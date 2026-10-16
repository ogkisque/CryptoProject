# Этап 2: глобальный контроль целостности состояния

**Статус:** ☐ не начат  ·  **Где:** CPU  ·  **ТЗ:** план → Этап 2, `crypto_project.md` §16–§24, §27, §52

## Цель

Сделать так, чтобы обнаруживалось любое изменение набора объектов или их содержимого на уровне всего хранилища, ещё до расшифрования:

`EncryptedFile → SHA3 leaf → Merkle → root → Manifest → ML-DSA-65 → Signature`

Формат `EncryptedFileV1`, AES-GCM, DEK, KEK и ML-KEM **не меняются**.

## Файлы

| Интерфейс | Реализация |
|---|---|
| `crypto/domain_hash.hpp` | `src/crypto/domain_hash.cpp` |
| `merkle/merkle.hpp` | `src/merkle/reference_merkle.cpp`, `src/merkle/proof.cpp` |
| `crypto/sig_backend.hpp` | `src/crypto/cpu/mldsa_liboqs.cpp` |
| `encoding/manifest.hpp` | `src/encoding/manifest.cpp` |
| `vault/state_verifier.hpp` | расширение: шаги 2–6 и 9–12 из `docs/format_v1.md` §11 |
| `storage/storage_backend.hpp` | FlatStorage: `manifest.bin`, `manifest.sig` через `put_manifest` |
| `storage/trusted_storage.hpp` | ключи `sig.pk`, `sig.sk` |
| `src/cli/commands.cpp` | `vault verify` |

## План работ

### 2.1 Domain-separated хеши
- [ ] Реализовать все функции из `domain_hash.hpp` через `IHashBackend::domain_hash`. Parent: буфер на стеке `L || R` (64 байта) + `domain_hash(0x01, ...)`.
- [ ] Тест: у каждой пары доменов результаты на одинаковых входах различаются. `EMPTY_ROOT` фиксируется как константа в тесте (значение вычислить один раз и записать в `format_v1_vectors.json`).

### 2.2 Merkle (reference)
- [ ] `compute_leaves` вызывает `domain_hash_batch(0x00, objects)`.
- [ ] `root_from_leaves` и `build_tree` реализуют алгоритм из `docs/format_v1.md` §6, включая решение M-1 (одиночный лист).
- [ ] `make_proof` / `verify_proof` с шагами `SiblingLeft`, `SiblingRight`, `Unpaired`.
- [ ] Тесты: N = 0…17 — `root_from_leaves == build_tree().root`, proof для каждого листа проходит и ломается при порче любого байта. Перестановка двух листьев меняет root. Сравнение с независимой реализацией на Python (скрипт `tests/vectors/gen_merkle.py`, через `hashlib.sha3_256`).

### 2.3 ML-DSA-65 (liboqs)
- [ ] `sign` через `OQS_SIG_sign_with_ctx_str`, `verify` через `OQS_SIG_verify_with_ctx_str`. Детерминированный режим и seed: если в liboqs нет публичного derand API для ML-DSA, взять `OQS_SIG_ml_dsa_65_keypair_derand`/internal или собрать нужное в тестах. Выбранный путь записать в журнал.
- [ ] Тесты: ACVP keyGen, sigGen (deterministic), sigVer. Подпись с другим ctx не проходит проверку.

### 2.4 Manifest и подпись
- [ ] `encode/decode_manifest` (ровно 168 байт).
- [ ] В `Vault`: после каждого изменения пересобирать дерево, собирать `ManifestV1{generation = 0, file_count, root, kem_ct_hash, kem_key_id, sig_key_id}`, подписывать с контекстом `label::kManifestSigContext` и писать `put_manifest`. Generation в M2 всегда 0, это нормально — rollback появится в M3.
- [ ] `vault init` создаёт ещё ключи ML-DSA, пустой Manifest (root = EMPTY_ROOT) и подпись.

### 2.5 Verifier
- [ ] Шаги строго по `docs/format_v1.md` §11 (без 7–8). Каждому соответствует свой `VerifyStep`.
- [ ] Сравнение хешей — через `constant_time_equal`.
- [ ] `recover_kek` вызывается **только** после успешного `verify_current()`.
- [ ] `vault verify` печатает `VALID` или `INVALID: <step>: <detail>` (код 2), с `--verbose` — шаги и PhaseProfile.

### 2.6 Тесты атак (§57)
- [ ] Порча ciphertext, tag, wrapped_DEK и nonce → `MerkleRoot`. Важно: ошибка должна возникать уже на verify, а не на extract.
- [ ] Удаление объекта → `FileCount` (или `MerkleRoot`).
- [ ] Вставка постороннего объекта (в том числе корректного объекта из другого vault того же владельца с изменённым uuid) → `ObjectBinding`, `FileCount` или `MerkleRoot`.
- [ ] Замена объекта другим объектом того же хранилища с переименованием файла → `ObjectNameMismatch` или `MerkleRoot`.
- [ ] Порча `manifest.bin` (каждый бит по очереди или выборочно) → `ManifestParse`, `FormatVersion`, `CryptoSuite`, `StorageUuidMismatch`, `KemKeyId`, `SigKeyId` или `Signature`.
- [ ] Порча `manifest.sig` или неверная длина → `Signature`.
- [ ] Порча `kem.ct` → `KemCtHash`, причём **до** вызова Decaps. Проверять мок-KEM backend'ом со счётчиком вызовов.
- [ ] Подмена Manifest и подписи парой, подписанной **другим** ключом → `SigKeyId` или `Signature`.

## Тонкие места

* Объекты при `verify` загружаются целиком. Для M2 это допустимо; оптимизации (streaming hash, Merkle cache) не делаем, пока не появится нужда.
* Без M3 атака «вернуть старую копию vault целиком» **не обнаруживается**. В отчёте это закрывает следующий этап.

## Критерии готовности

- [ ] Все тесты 2.6 проходят, каждый проверяет ожидаемый `VerifyStep`.
- [ ] `list`, `extract` и `remove` не работают на непроверенном состоянии (тест: порча → любая команда даёт код 2).

## Журнал прогресса

| Дата | Что сделано |
|---|---|
