# Этап 2: глобальный контроль целостности состояния

**Статус:** ✅ готово (2026-10-16)  ·  **Где:** CPU  ·  **ТЗ:** план → Этап 2, `crypto_project.md` §16–§24, §27, §52

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
- [x] Реализовать все функции из `domain_hash.hpp` через `IHashBackend::domain_hash`. Parent: буфер на стеке `L || R` (64 байта) + `domain_hash(0x01, ...)`.
- [x] Тест: у каждой пары доменов результаты на одинаковых входах различаются. `EMPTY_ROOT` фиксируется как константа в тесте (значение вычислить один раз и записать в `format_v1_vectors.json`).

### 2.2 Merkle (reference)
- [x] `compute_leaves` вызывает `domain_hash_batch(0x00, objects)`.
- [x] `root_from_leaves` и `build_tree` реализуют алгоритм из `docs/format_v1.md` §6, включая решение M-1 (одиночный лист).
- [x] `make_proof` / `verify_proof` с шагами `SiblingLeft`, `SiblingRight`, `Unpaired`.
- [x] Тесты: N = 0…17 — `root_from_leaves == build_tree().root`, proof для каждого листа проходит и ломается при порче любого байта. Перестановка двух листьев меняет root. Сравнение с независимой реализацией на Python (скрипт `tests/vectors/gen_merkle.py`, через `hashlib.sha3_256`).

### 2.3 ML-DSA-65 (liboqs)
- [x] `sign` через `OQS_SIG_sign_with_ctx_str`, `verify` через `OQS_SIG_verify_with_ctx_str`. Детерминированный режим и seed: если в liboqs нет публичного derand API для ML-DSA, взять `OQS_SIG_ml_dsa_65_keypair_derand`/internal или собрать нужное в тестах. Выбранный путь записать в журнал.
- [x] Тесты: ACVP keyGen, sigGen (deterministic), sigVer. Подпись с другим ctx не проходит проверку.

### 2.4 Manifest и подпись
- [x] `encode/decode_manifest` (ровно 168 байт).
- [x] В `Vault`: после каждого изменения пересобирать дерево, собирать `ManifestV1{generation = 0, file_count, root, kem_ct_hash, kem_key_id, sig_key_id}`, подписывать с контекстом `label::kManifestSigContext` и писать `put_manifest`. Generation в M2 всегда 0, это нормально — rollback появится в M3.
- [x] `vault init` создаёт ещё ключи ML-DSA, пустой Manifest (root = EMPTY_ROOT) и подпись.

### 2.5 Verifier
- [x] Шаги строго по `docs/format_v1.md` §11 (без 7–8). Каждому соответствует свой `VerifyStep`.
- [x] Сравнение хешей — через `constant_time_equal`.
- [x] `recover_kek` вызывается **только** после успешного `verify_current()`.
- [x] `vault verify` печатает `VALID` или `INVALID: <step>: <detail>` (код 2), с `--verbose` — шаги и PhaseProfile.

### 2.6 Тесты атак (§57)
- [x] Порча ciphertext, tag, wrapped_DEK и nonce → `MerkleRoot`. Важно: ошибка должна возникать уже на verify, а не на extract.
- [x] Удаление объекта → `FileCount` (или `MerkleRoot`).
- [x] Вставка постороннего объекта (в том числе корректного объекта из другого vault того же владельца с изменённым uuid) → `ObjectBinding`, `FileCount` или `MerkleRoot`.
- [x] Замена объекта другим объектом того же хранилища с переименованием файла → `ObjectNameMismatch` или `MerkleRoot`.
- [x] Порча `manifest.bin` (каждый бит по очереди или выборочно) → `ManifestParse`, `FormatVersion`, `CryptoSuite`, `StorageUuidMismatch`, `KemKeyId`, `SigKeyId` или `Signature`.
- [x] Порча `manifest.sig` или неверная длина → `Signature`.
- [x] Порча `kem.ct` → `KemCtHash`, причём **до** вызова Decaps. Проверять мок-KEM backend'ом со счётчиком вызовов.
- [x] Подмена Manifest и подписи парой, подписанной **другим** ключом → `SigKeyId` или `Signature`.

## Тонкие места

* Объекты при `verify` загружаются целиком. Для M2 это допустимо; оптимизации (streaming hash, Merkle cache) не делаем, пока не появится нужда.
* Без M3 атака «вернуть старую копию vault целиком» **не обнаруживается**. В отчёте это закрывает следующий этап.

## Критерии готовности

- [x] Все тесты 2.6 проходят, каждый проверяет ожидаемый `VerifyStep`.
- [x] `list`, `extract` и `remove` не работают на непроверенном состоянии (тест: порча → любая команда даёт код 2).

## Журнал прогресса

| Дата | Что сделано |
|---|---|
| 2026-10-16 | Этап 2 завершён: Merkle (reference + proofs), ML-DSA-65 backend, подпись Manifest, StateVerifier по шагам 1–6 и 9–12, `vault verify`. Все тесты (CPU и ASan/UBSan) проходят. Детали и отклонения ниже. |

### Заметки и отклонения

* **Детерминированный ML-DSA.** В публичном API liboqs 0.16.0 нет derand keygen/sign. `src/crypto/cpu/mldsa_liboqs.cpp` вызывает внутренние точки mldsa-native, экспортируемые из `liboqs.a`: `PQCP_MLDSA_NATIVE_MLDSA65_C_keypair_internal` и `..._C_signature_internal` (портативный C-вариант). Подпись с rnd собирается вручную: `pre = 0x00 || len(ctx) || ctx`. Эти точки нужны только при `seed`/`rnd != nullopt`. Производственный путь (hedged) идёт через `OQS_SIG_sign_with_ctx_str`. Совпадение подтверждено ACVP sigGen и проверкой детерминированной подписи через публичный `verify_with_ctx_str`. Если при обновлении liboqs символы переименуют, сломается линковка — тогда пересмотреть.
* **ACVP.** `tests/vectors/mldsa65_acvp.txt` создан скриптом `tests/vectors/gen_mldsa_acvp.py` из `internalProjection.json` (NIST ACVP-Server): keyGen, sigGen external/pure (deterministic и с rnd), sigVer — по 8 первых тестов каждой группы. Тест: `tests/unit/mldsa_test.cpp`.
* **Merkle-векторы.** `tests/vectors/merkle_vectors.txt` генерируется независимой Python-реализацией (`gen_merkle.py`, `hashlib.sha3_256`) для N = 0…17. `EMPTY_ROOT = 79cca31d…1ba8` зафиксирован в `tests/unit/merkle_test.cpp`. Отдельный `format_v1_vectors.json` пока не создавался.
* **`verify_proof` строгая:** форма пути выводится из `(leaf_index, leaf_count)`, поэтому лишние, недостающие и «не те» шаги отвергаются. Учтите: одинаковая форма пути у деревьев разного размера (напр. 5 и 6 листьев для листа 0) не считается ошибкой, привязка к размеру дерева идёт через `file_count` в Manifest.
* **Объекты хешируются по сырым байтам с диска.** Разбор `EncryptedFileV1` строгий (trailing data запрещены), поэтому они равны `CanonicalEncode(obj)`.
* **Порядок `VerifyStep`.** Неверный размер `manifest.bin` — `ManifestParse`; отвергнутая версия/suite внутри — `FormatVersion`/`CryptoSuite`; неверный размер `kem.ct` — по-прежнему `LoadSnapshot` (до Manifest); неверный размер `manifest.sig` — `Signature`.
* **`vault verify` не загружает секретные ключи:** `Vault::verify_state()` создаёт только `StateVerifier`, Decaps не вызывается. `Vault::open` вызывает `recover_kek` строго после `verify_current()`.
* **Запись в M2 не crash-safe:** `add`/`remove` пишут объект, затем Manifest и подпись по очереди (FlatStorage). Сбой между ними оставит хранилище невалидным (verify скажет `FileCount`/`MerkleRoot`). Atomic commit — этап 3.
* **Тесты stage 1 переписаны:** порча объекта теперь ловится при verify (`MerkleRoot`), а не при extract через GCM. Вместо GCM-ошибок на extract проверяется `VerifyStep`. Мок `CountingKem` доказывает, что при порче Decaps не вызывается.
* Без этапа 3 откат всего хранилища к старой (подписанной) копии не обнаруживается.
