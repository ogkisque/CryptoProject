# AGENTS.md — edu-vault

Файл описывает проект для людей и AI-агентов: что это, как устроено, что уже сделано и где что лежит. **Обновлять после каждой значимой работы**: таблицу статуса, журнал и при необходимости разделы ниже.

## Что это

Учебный проект по защите информации: прототип защищённого файлового хранилища (CLI `vault`).
- Файлы шифруются AES-256-GCM, у каждого объекта свой DEK. DEK оборачивается AES-256-KW ключом KEK.
- KEK выводится через HKDF-SHA3-256 из общего секрета ML-KEM-768.
- Состояние хранилища аутентифицируется деревом SHA3-256 Merkle, Manifest и подписью ML-DSA-65.
- Rollback и fork обнаруживаются по trusted state anchor. Изменения проходят через crash-safe commit.
- Исследовательская часть — сравнение CPU и GPU (CUDA/cuPQC, RTX 3050 SM 86) для SHA3/Merkle/ML-KEM/ML-DSA.

**Источники требований (не менять без согласования с автором):**
- `crypto_project.md` — полная спецификация (§1–§59). Ссылки вида `§N` в коде и документах ведут сюда.
- `crypto_project_plan.md` — разбиение на 7 этапов (milestones).
- `docs/format_v1.md` — байтовые форматы и **принятые решения** по неоднозначностям ТЗ (раздел «Открытые вопросы»).

## Статус

| Этап | Документ | Статус |
|---|---|---|
| 0. Каркас: структура, интерфейсы, CMake, планы | — | ✅ готово (2026-10-16) |
| 1. Минимальное хранилище (AES-GCM/KW, ML-KEM, HKDF, CLI) | `docs/stages/01_minimal_vault.md` | ✅ готово (2026-10-16) |
| 2. Merkle + Manifest + ML-DSA + `vault verify` | `docs/stages/02_integrity_state.md` | ✅ готово (2026-10-16) |
| 3. Generations, TrustedState anchor, crash-safe commit | `docs/stages/03_rollback_crash_safety.md` | ☐ |
| 4. Абстракция backend'ов, CPU-MT, benchmark framework | `docs/stages/04_backend_abstraction.md` | ☐ |
| 5. GPU SHA3 / Merkle (на GPU-машине) | `docs/stages/05_gpu_sha3_merkle.md` | ☐ |
| 6. GPU ML-KEM / ML-DSA через cuPQC (на GPU-машине) | `docs/stages/06_gpu_pqc.md` | ☐ |
| 7. Эксперименты и анализ | `docs/stages/07_experiments.md` | ☐ |

Подробный прогресс ведётся в чекбоксах и в «Журнале прогресса» каждого stage-документа.

## Технологии

- **C++20**, CMake ≥ 3.22, GCC 13 (локально). CUDA-код — C++17 (`nvcc`).
- **OpenSSL ≥ 3.0**: AES-GCM, AES-KW, HKDF(SHA3-256), SHA3, RAND. Локально нужно поставить `libssl-dev`.
- **liboqs 0.16.0** (FetchContent, tag в `cmake/Dependencies.cmake`): ML-KEM-768 и ML-DSA-65 на CPU.
- **CLI11** — CLI; **GoogleTest** — тесты; позже **nlohmann/json** — конфиги benchmark'а.
- **CUDA 12 + cuPQC SDK** — только на GPU-машине (`VAULT_ENABLE_CUDA=ON`).
- Python (pandas, matplotlib) — анализ результатов.

**Машины.** На машине разработки GPU нет: здесь собирается и тестируется только CPU-часть, GPU-код пишется «вслепую» и проверяется на GPU-машине (`docs/gpu_machine.md`).

## Архитектура

```
             CLI (src/cli)  ── vault init|add|extract|remove|list|verify|gc|benchmark
                  │
             vault::Vault (include/vault/vault/vault.hpp)          — фасад, кэш VerifiedState
             ├── core::StateVerifier   (state_verifier.hpp)        — §27/§52, VerificationError(step)
             ├── core::CommitProtocol  (commit.hpp)                — §28, crash points
             ├── core::key_hierarchy / object_codec                — KEK, encrypt/decrypt объекта
             │
   ┌─────────┼──────────────────────────────┬───────────────────────────────┐
   │ crypto::CryptoBackends (backends.hpp)  │ storage::IStorageBackend      │ storage::ITrustedStorage
   │  IHashBackend   SHA3                   │  FlatStorage (M1–M2)          │  trusted/ (ключи + TrustedState)
   │  IMerkleBackend Merkle                 │  GenerationStorage (M3+)      │
   │  IKemBackend    ML-KEM-768             │  — недоверенная директория    │
   │  ISigBackend    ML-DSA-65              │    vault/, только байты       │
   │  IRandom                               │                               │
   │  └ CPU (OpenSSL/liboqs) | CPU-MT | GPU (cuda/, cuPQC)                  │
   └────────────────────────────────────────┴───────────────────────────────┘
   crypto/symmetric.hpp — AES-GCM, AES-KW, HKDF: только CPU (§41)
   encoding/* — канонические форматы: FilePlaintext, EncryptedFileV1, ManifestV1, TrustedStateV1
```

Ключевые принципы:
1. **Формат не зависит от backend'а.** GPU подключается заменой реализации интерфейса, протокол при этом не меняется.
2. **Storage backend «тупой».** Он только перемещает байты, а все решения о доверии принимает `StateVerifier`.
3. **Сначала проверка, потом секреты.** `Decaps` и расшифрование выполняются только после полной верификации состояния.
4. **Ошибки — исключения** (`VaultError`, `VerificationError` с `VerifyStep`). Частичный результат и plaintext при ошибке не возвращаются.
5. **Секреты** хранятся в `SecureBytes` (обнуление при уничтожении); `std::string`/iostream для них не используются.

## Структура репозитория

```
AGENTS.md                  этот файл
crypto_project.md          спецификация (ТЗ)
crypto_project_plan.md     план этапов (ТЗ)
CMakeLists.txt             корневая сборка; цели появляются по мере появления src/*.cpp
cmake/                     CompilerFlags, Dependencies (OpenSSL/liboqs/CLI11/GTest), Cuda (cuPQC)
include/vault/             ПУБЛИЧНЫЕ ИНТЕРФЕЙСЫ (готовы, без реализаций)
  common/                  bytes, constants, error, secure_buffer, timing
  encoding/                canonical (ByteWriter/Reader), file_plaintext, encrypted_file, manifest, trusted_state
  crypto/                  hash/kem/sig backends, domain_hash, symmetric, random, backends, cpu_backends
  merkle/                  IMerkleBackend, MerkleTree, proofs
  storage/                 fs_util, storage_backend, trusted_storage, crash_injection
  vault/                   key_hierarchy, object_codec, state_verifier, commit, vault (фасад)
  bench/                   stats, system_info, benchmark
  gpu/                     фабрики GPU backend'ов
src/                       реализации, раскладка повторяет include/ (этап 1: common, encoding, crypto/cpu, storage, vault, cli; merkle/ добавлен на этапе 2; bench/ пока пуст)
cuda/                      GPU-реализации (.cu), только при VAULT_ENABLE_CUDA
tests/                     header_check.cpp; unit/ integration/ tamper/ (есть, 101 тест); crash/ gpu/ (пусто); vectors/
bench/                     configs/{quick,full}.json, analysis/analyze.py (заглушка), results/
scripts/                   build_cpu.sh, build_gpu.sh, check_gpu_env.sh, run_bench.sh
docs/                      format_v1.md, gpu_machine.md, stages/01..07
```

## Сборка

```bash
sudo apt install libssl-dev        # OpenSSL >= 3.0 (liboqs 0.16.0, CLI11, GoogleTest тянутся через FetchContent)
./scripts/build_cpu.sh             # сборка + ctest (первая сборка ~2 мин из-за liboqs)
cmake -S . -B build/asan -DVAULT_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug   # ASan+UBSan
CUPQC_ROOT=/path ./scripts/build_gpu.sh                   # на GPU-машине
```

## Соглашения

- Пространства имён: `vault` (общие типы и фасад), `vault::encoding`, `vault::crypto`, `vault::merkle`, `vault::storage`, `vault::core`, `vault::bench`, `vault::gpu`, `vault::cli`.
- Комментарии и документация — на русском, идентификаторы — на английском.
- Ссылаться на пункт ТЗ как `§N` (`crypto_project.md`).
- Новые решения по формату записываются сначала в `docs/format_v1.md`, потом в код.
- Каждый тест атаки проверяет **ожидаемый `VerifyStep`**, а не только факт ошибки.
- После работы над этапом: отметить чекбоксы и дописать журнал в `docs/stages/0N_*.md`, обновить таблицу статуса здесь.

## Журнал

| Дата | Что сделано |
|---|---|
| 2026-10-16 | Каркас проекта: структура каталогов, все публичные заголовки (`include/vault/**`, компилируются через `vault_header_check`), CMake с опциональной CUDA-частью, скрипты сборки и benchmark'а, конфиги benchmark'а, заглушка анализа, `docs/format_v1.md` с решениями по неоднозначностям, планы этапов 1–7. Реализаций нет. |
| 2026-10-16 | Этап 1 завершён: `vault init/add/list/extract/remove/verify` работают, 43 теста проходят (в т.ч. под ASan/UBSan). Подробности и отклонения — в `docs/stages/01_minimal_vault.md`. Репозиторий — `CryptoProject/` (коммиты только локально, без push). |
| 2026-10-16 | Ревью этапа 1: исправлено 8 проблем (tmp-файлы в objects/, длина kem.ct, частичный plaintext при ошибке записи в extract, GCM ≥ 2 GiB и др.), добавлены CLI-тесты, всего 49 тестов. Таблица — в `docs/stages/01_minimal_vault.md`. |
| 2026-10-16 | Этап 2 завершён: Merkle (reference, proofs), ML-DSA-65 (liboqs; derand через внутренние точки mldsa-native), подписанный Manifest, `StateVerifier` шаги 1–6 и 9–12, `vault verify` (VALID/INVALID, `-v`), тесты атак §57 с проверкой `VerifyStep`, ACVP-векторы. Подробности — `docs/stages/02_integrity_state.md`. |
| 2026-10-16 | Ревью этапа 2: криптографических дефектов нет. Добавлены NIST ACVP для ML-KEM-768 (долг этапа 1) и независимые Python-векторы всего формата v1; выбор storage-backend сведён в одну точку. 101 тест. Подробности — `docs/stages/02_integrity_state.md`, раздел «Ревью». |
