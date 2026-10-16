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
| 3. Generations, TrustedState anchor, crash-safe commit | `docs/stages/03_rollback_crash_safety.md` | ✅ готово (2026-10-16) |
| 4. Абстракция backend'ов, CPU-MT, benchmark framework | `docs/stages/04_backend_abstraction.md` | ✅ готово (2026-10-16) |
| 5. GPU SHA3 / Merkle — код (часть А, без компиляции CUDA) | `docs/stages/05_gpu_sha3_merkle.md` | ✅ часть А (2026-10-16) |
| 6. GPU ML-KEM / ML-DSA через cuPQC — код (часть А, без компиляции CUDA) | `docs/stages/06_gpu_pqc.md` | ☐ |
| 7. Анализ и сценарий запуска (часть А) | `docs/stages/07_experiments.md` | ☐ |
| Сборка и запуск на GPU-машине автором (`gpu_run_all.sh --quick`, затем полный) + исправления | `docs/gpu_workflow.md` | ☐ |
| Анализ результатов и выводы (этап 7, часть В) | `docs/stages/07_experiments.md` | ☐ |

Подробный прогресс ведётся в чекбоксах и в «Журнале прогресса» каждого stage-документа.

## Технологии

- **C++20**, CMake ≥ 3.22, GCC 13 (локально). CUDA-код — C++17 (`nvcc`).
- **OpenSSL ≥ 3.0**: AES-GCM, AES-KW, HKDF(SHA3-256), SHA3, RAND. Локально нужно поставить `libssl-dev`.
- **liboqs 0.16.0** (FetchContent, tag в `cmake/Dependencies.cmake`): ML-KEM-768 и ML-DSA-65 на CPU.
- **CLI11** — CLI; **GoogleTest** — тесты; **nlohmann/json** — конфиги и результаты benchmark'а.
- **CUDA 12 + cuPQC SDK** — только на GPU-машине (`VAULT_ENABLE_CUDA=ON`).
- Python (pandas, matplotlib) — анализ результатов.

**Машины и модель работы** (`docs/gpu_workflow.md`). На машине разработки нет GPU и **не ставится CUDA Toolkit**: `.cu`-код и вызовы cuPQC пишутся без компиляции, сборку не проверяем. Здесь проверяется только то, что собирает g++: kernel-логика как `VAULT_HD` (`__host__ __device__`) функции с тестами на CPU, host-часть GPU-backend'ов, `analyze.py` (в том числе на синтетических GPU-данных) и `scripts/gpu_run_all.sh` в CPU-режиме. Автор собирает и запускает на GPU-машине (сначала `--quick`, потом полный) и присылает ошибки или архив; по ним вносятся исправления. Цель — минимум таких итераций: ошибки через `CUDA_CHECK` с выражением и местом, неочевидные места API cuPQC помечены `// UNVERIFIED(cuPQC)`.

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
   │  IHashBackend   SHA3                   │  FlatStorage (M1–M2, не исп.) │  trusted/ (ключи + TrustedState)
   │  IMerkleBackend Merkle                 │  GenerationStorage (M3+)       │
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
src/                       реализации, раскладка повторяет include/ (этап 1: common, encoding, crypto/cpu, storage, vault, cli; merkle/ и bench/ добавлены на этапах 2 и 4; common/thread_pool для CPU-MT)
cuda/                      GPU: kernels/*.cuh (общий код device/CPU, VAULT_HD), host/ (планирование, шаблоны конвейеров — всегда собираются и тестируются), src/*.cu (только при VAULT_ENABLE_CUDA)
tools/fakecuda/            заглушки CUDA для scripts/check_cuda_syntax.sh (проверка .cu через clang без Toolkit)
tests/                     header_check.cpp; unit/ integration/ tamper/ crash/ (есть); gpu/ (CPU==GPU, пропускаются без устройства); vectors/
bench/                     configs/{quick,full}.json, analysis/analyze.py (заглушка), results/
scripts/                   build_cpu.sh, build_gpu.sh, check_gpu_env.sh, check_cuda_syntax.sh, run_bench.sh
docs/                      format_v1.md, gpu_workflow.md (работа с GPU без локальной CUDA), gpu_machine.md, stages/01..07
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
| 2026-10-16 | Этап 3 завершён: `GenerationStorage` (immutable поколения + hardlink), `CommitProtocol` с 6 crash-точками, шаги 7–8 verifier'а (rollback → `Generation`, fork → `ManifestHash`), `flock` на транзакцию, `vault gc`, предупреждения об orphan'ах. Тесты: rollback/fork, crash (CLI + `VAULT_CRASH_POINT`), параллельные `add`. Подробности — `docs/stages/03_rollback_crash_safety.md`. |
| 2026-10-16 | Ревью этапа 3: исправлена гонка «проверка N / trusted N+1», из-за которой параллельный commit мог удалить актуальное доверенное поколение (`VerifyReport::trusted_state` + проверка актуальности в `commit`); `init` больше не удаляет чужие каталоги при `AlreadyExists`. 128 тестов. Подробности — `docs/stages/03_rollback_crash_safety.md`, раздел «Ревью». |
| 2026-10-16 | Этап 4 завершён: `ThreadPool` и CPU-MT backend'ы (hash по байтам, Merkle по уровням, ML-KEM/ML-DSA batch), `--backend cpu|cpu-mt|gpu` и `--threads`, GPU-ветка `make_backends` (не компилировалась), плоские форматы batch (`format_v1.md` §15), профиль фаз (`-v`), benchmark framework + `vault benchmark --config --csv --json`, тест эквивалентности backend'ов. Подробности — `docs/stages/04_backend_abstraction.md`. |
| 2026-10-16 | Ревью этапа 4: benchmark теперь сверяет результаты каждого backend'а с reference (SHA3, Merkle root, ключи, encaps, подписи) — неверный GPU-backend не даст «быстрых» данных; `merkle_verify` не зависит от размера объектов; в JSON записываются потоки, а в `git_commit` — признак `-dirty`. Полная матрица на CPU: 10.5 мин, 1.6 GiB. **План этапов 5–7 переписан под модель «один запуск на GPU»** (`docs/gpu_single_run.md`, gate в таблице статуса). 154 теста. |
| 2026-10-16 | План работы с GPU пересмотрен по решению автора: CUDA Toolkit здесь не ставится, сборка GPU-кода здесь не проверяется; автор собирает и запускает на GPU-машине (`gpu_run_all.sh --quick`, затем полный) и присылает результат. `docs/gpu_single_run.md` → `docs/gpu_workflow.md`; убраны gate, офлайн-вендоринг и бюджет времени; этапы 5–7 обновлены. |
| 2026-10-16 | Этап 5, часть А: GPU SHA3/Merkle — код без компиляции CUDA. Kernel-логика (`cuda/kernels/*.cuh`, `VAULT_HD`) проверена на CPU против OpenSSL/reference; конвейер порций и подъём Merkle вынесены в шаблоны над «устройством» и проверены эмулированным устройством с отложенным исполнением (мутация конвейера ловится); `.cu` проверяются на синтаксис через clang (`scripts/check_cuda_syntax.sh`). Backend'ы: «поток на объект» и «warp на объект», pinned/pageable, double buffering, пулирование; benchmark-конфиги принимают GPU-опции и подписи, добавлены `gpu_*.json`. 193 теста. Подробности и список мест `UNVERIFIED` — `docs/stages/05_gpu_sha3_merkle.md`. |
