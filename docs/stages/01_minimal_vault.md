# Этап 1: минимальное криптографически корректное хранилище

**Статус:** ☐ не начат  ·  **Где выполняется:** любая машина (CPU)  ·  **ТЗ:** `crypto_project_plan.md` → Этап 1, `crypto_project.md` §1–§15, §50–§55

## Цель

Получить работающий CLI (`init / add / list / extract / remove`). Без `SK_KEM` из доверенной области содержимое файлов должно оставаться недоступным, а любая порча объекта должна обнаруживаться при расшифровании. Глобального контроля состояния (Merkle/Manifest) пока нет.

После этого этапа **формат `EncryptedFileV1` и иерархия ключей считаются окончательными**.

## Не входит

Merkle, Manifest, ML-DSA, generation, rollback, crash-safe commit, GPU.

## Зависимости, которые нужно поставить

```bash
sudo apt install libssl-dev        # OpenSSL >= 3.0 (на этой машине 3.0.2)
# liboqs, CLI11, GoogleTest подтянутся через FetchContent (нужен git и интернет)
```

## Файлы

| Интерфейс | Реализация | Что делает |
|---|---|---|
| `common/bytes.hpp` | `src/common/bytes.cpp` | hex, constant_time_equal (через `CRYPTO_memcmp`) |
| `common/secure_buffer.hpp` | `src/common/secure_buffer.cpp` | `OPENSSL_cleanse`, move-семантика с обнулением источника |
| `common/error.hpp` | `src/common/error.cpp` | `to_string(VerifyStep)` |
| `encoding/canonical.hpp` | `src/encoding/canonical.cpp` | ByteWriter/ByteReader, require_supported |
| `encoding/file_plaintext.hpp` | `src/encoding/file_plaintext.cpp` | + валидация UTF-8 |
| `encoding/encrypted_file.hpp` | `src/encoding/encrypted_file.cpp` | + build_file_aad |
| `encoding/trusted_state.hpp` | `src/encoding/trusted_state.cpp` | |
| `crypto/symmetric.hpp` | `src/crypto/cpu/symmetric_openssl.cpp` | GCM, KW, HKDF через EVP |
| `crypto/random.hpp` | `src/crypto/cpu/random_openssl.cpp` | `RAND_bytes`; тестовый детерминированный RNG на SHAKE256 |
| `crypto/hash_backend.hpp`, `cpu_backends.hpp` | `src/crypto/cpu/sha3_openssl.cpp` | SHA3 понадобится уже здесь (kem_key_id), batch можно сделать простым циклом |
| `crypto/kem_backend.hpp` | `src/crypto/cpu/mlkem_liboqs.cpp` | |
| `crypto/backends.hpp` | `src/crypto/backends.cpp` | `make_backends(Cpu)`; sig/merkle пока `nullptr` |
| `storage/fs_util.hpp` | `src/storage/fs_util.cpp` | POSIX open/write/fsync/rename |
| `storage/storage_backend.hpp` | `src/storage/flat_storage.cpp` | FlatStorage |
| `storage/trusted_storage.hpp` | `src/storage/file_trusted_storage.cpp` | права 0700/0600 |
| `vault/key_hierarchy.hpp` | `src/vault/key_hierarchy.cpp` | |
| `vault/object_codec.hpp` | `src/vault/object_codec.cpp` | |
| `vault/state_verifier.hpp` | `src/vault/state_verifier.cpp` | только M1-шаги: разбор объектов, привязка, имена, дубликаты |
| `vault/vault.hpp` | `src/vault/vault.cpp` | фасад; в M1 `commit` = прямые записи через FlatStorage |
| `src/cli/commands.hpp` | `src/cli/main.cpp`, `src/cli/commands.cpp` | CLI11 |

## План работ

### 1.1 Сборка и инфраструктура
- [ ] Поставить `libssl-dev`, убедиться, что `cmake -S . -B build/cpu` подтягивает liboqs, CLI11 и GTest.
- [ ] Проверить, что в выбранной версии liboqs есть `OQS_KEM_ml_kem_768_keypair_derand`, `OQS_KEM_ml_kem_768_encaps_derand` и `OQS_SIG_sign_with_ctx_str` (для M2). Зафиксировать тег в `cmake/Dependencies.cmake`.
- [ ] `git init`, первый коммит каркаса.

### 1.2 Общие типы и кодирование
- [ ] `SecureBytes`: деструктор и `wipe()` вызывают `secure_zero`. Move обнуляет источник (`buf_.swap`, затем wipe чужого). Копирование запрещено.
- [ ] `ByteWriter` / `ByteReader` (BE). `ByteReader::var_*`: сначала `len <= remaining() && len <= max_len`, и только потом view.
- [ ] `encode/decode_file_plaintext`: проверять UTF-8 (простой автомат, отклонять overlong и суррогаты) и длину `<= kMaxFilenameLength`; пустое имя запрещено.
- [ ] `encode/decode_encrypted_file`: проверять `ciphertext_length == remaining - 16`, иначе FormatError.
- [ ] `build_file_aad`: формат из `docs/format_v1.md` §3.
- [ ] Юнит-тесты: round-trip, усечение на каждом байте, лишний байт в конце, неверная версия или suite → `UnsupportedVersion`, огромная длина → FormatError без попытки выделить память.

### 1.3 Симметричная криптография (OpenSSL EVP)
- [ ] AES-256-GCM: `EVP_aes_256_gcm`, `EVP_CTRL_GCM_SET_IVLEN = 12`, AAD через `EVP_EncryptUpdate(ctx, nullptr, ...)`, tag через `EVP_CTRL_GCM_GET_TAG/SET_TAG`. Decrypt пишет во временный `SecureBytes`. Если `EVP_DecryptFinal_ex` вернул ≤ 0, буфер обнуляется и бросается `AuthenticationFailed`.
- [ ] AES-256-KW: `EVP_aes_256_wrap` + `EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)`. Длина результата 40 байт. Ошибка unwrap → `AuthenticationFailed`.
- [ ] HKDF: `EVP_KDF_fetch(nullptr, "HKDF", nullptr)`, параметры `digest = "SHA3-256"`, `key`, `salt`, `info`.
- [ ] SHA3-256: `EVP_sha3_256`. `domain_hash` = `DigestUpdate(prefix)` + `DigestUpdate(data)`, без конкатенации буферов.
- [ ] Тесты на векторах (`tests/vectors/README.md`): GCM (CAVP), KW (RFC 3394 §4.6), SHA3 (CAVP), HKDF-SHA3 (сгенерировать через Python `cryptography`).

### 1.4 ML-KEM-768 (liboqs)
- [ ] `CpuKemBackend`: обёртки `OQS_KEM_ml_kem_768_*`, проверка размеров входов. `decaps` возвращает SecureBytes(32).
- [ ] Batch-методы: пока цикл; в M4 появится многопоточный вариант.
- [ ] Тесты: ACVP keyGen и encapDecap (через derand), `decaps(encaps)` совпадает с исходным секретом, неверный ct даёт другой секрет (implicit rejection).

### 1.5 Хранилища
- [ ] `fs_util`: `write_file_atomic_durable` = `open(tmp, O_CREAT|O_EXCL|O_WRONLY, mode)` → полный `write` в цикле → `fsync` → `close` → `rename` → `fsync(dir)`. При ошибке tmp удаляется.
- [ ] `FlatStorage`: `create_layout` создаёт `vault/` и `vault/objects/`, `kem.ct` пишется durable. `read_snapshot(0)` читает все файлы из `objects/` и **ничего не фильтрует**: посторонние файлы тоже передаются верификатору. `ISnapshotWriter::put_object` и `remove_object` сразу пишут/удаляют на диске (атомарно для отдельного файла), `publish()` и `sync()` в M1 — fsync каталога.
- [ ] `FileTrustedStorage`: `initialize` падает, если директория уже существует. Права `0700` на каталог и `0600` на файлы. `load_kem_secret_key` проверяет длину 2400.

### 1.6 Логика vault
- [ ] `derive_kek`, `establish_kek`, `recover_kek` (`docs/format_v1.md` §4). Секреты живут в SecureBytes.
- [ ] `encrypt_object`: DEK (32 байта) и nonce (12 байт) из RNG, затем `encode_file_plaintext`, AAD, GCM, `kw_wrap(KEK, DEK)`, wipe DEK.
- [ ] `decrypt_object`: `kw_unwrap`, затем GCM decrypt с AAD, собранным **из полей объекта**, затем `decode_file_plaintext`.
- [ ] `StateVerifier::verify_current` (M1): загрузить TrustedState и объекты. Каждый объект разобрать, проверить `storage_uuid`, version и suite, сверить имя файла с file_id, найти дубликаты, отсортировать.
- [ ] `Vault::init`: uuid из RNG, keygen, `establish_kek`, запись `kem.ct`, `TrustedStateV1{gen = 0, hash = 0}` и ключей, wipe KEK.
- [ ] `Vault::open`: verify, затем `recover_kek` (KEK держим в Impl до закрытия).
- [ ] `add`: сгенерировать `file_id`, повторять, пока он совпадает с существующим (вероятность ничтожна, но проверка обязательна). Затем `encrypt_object` и `put_object`.
- [ ] `extract`: найти объект в VerifiedState и вызвать `decrypt_object`.
- [ ] `remove`: если `file_id` нет, ошибка NotFound. Иначе `remove_object`.
- [ ] `list(decrypt_names)`: печатает file_id и размер ciphertext; имена показывает только после успешного GCM.

### 1.7 CLI
- [ ] `main.cpp`: CLI11, глобальные опции и подкоманды из `src/cli/commands.hpp`. Коды выхода 0/1/2. Все исключения перехватываются в main.
- [ ] `extract`: имя из plaintext санитизируется (берётся только `filename().filename()`, запрещены пустое имя, `.`, `..` и `/`). Существующий файл без `--force` не перезаписывается. `-o` задаёт путь явно.
- [ ] `list`: таблица `file_id (hex) | ciphertext_size | [name]`.

### 1.8 Тесты атак (tests/tamper/)
- [ ] Для каждого поля объекта — `ciphertext`, `nonce`, `gcm_tag`, `wrapped_DEK` — переворачивать один бит в нескольких позициях. `extract` должен бросать `AuthenticationFailed`, и plaintext не должен вернуться.
- [ ] Изменение `file_id`/`storage_uuid` внутри объекта ломает AAD; в M1 к этому добавляется ошибка привязки или имени файла.
- [ ] Изменение `kem.ct` в M1: Decaps возвращает «случайный» секрет из-за implicit rejection, KEK получается неверным, и unwrap падает. Тест фиксирует, что это ловится хотя бы на extract. В M2 то же самое будет ловиться раньше, через `kem_ct_hash`.
- [ ] Подмена объекта объектом из **другого** хранилища ловится по `storage_uuid`.

## Тонкие места

* **Implicit rejection в ML-KEM.** `decaps` никогда не сообщает об ошибке. Поэтому в M1 подмена `CT_KEM` проявляется только как сбой AES-KW unwrap. Это нормально для этапа, но в отчёте стоит про это написать.
* **Повторное использование DEK исключено конструкцией:** `encrypt_object` всегда генерирует DEK сам и не принимает его снаружи.
* **Секреты в `std::string` и в iostream-буферах.** plaintext читать и писать только через SecureBytes и `write(2)`, а не через `std::ofstream` (там лишняя копия).
* **Чтение файла для `add`:** прочитать файл целиком в SecureBytes заранее известного размера (`fstat`), без `resize` по ходу.

## Критерии готовности (DoD)

- [ ] `./scripts/build_cpu.sh` собирается без предупреждений, все тесты проходят (в том числе под ASan: `-DVAULT_SANITIZE=ON`).
- [ ] Сценарий из ТЗ работает: `vault init → add file.txt → list → extract <id> → remove <id>`.
- [ ] Тесты из 1.8 проходят.
- [ ] Обновлены `AGENTS.md` (статус) и журнал ниже.

## Журнал прогресса

| Дата | Что сделано |
|---|---|
| 2026-10-16 | Созданы интерфейсы (заголовки) и план этапа |
