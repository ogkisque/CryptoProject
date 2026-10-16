# Этап 4: абстракция CPU/GPU backend и benchmark-инфраструктура

**Статус:** ✅ готово (2026-10-16)  ·  **Где:** CPU (вся GPU-часть пока в виде заглушек)  ·  **ТЗ:** план → Этап 4

## Цель

Сделать вычислительные backend'ы взаимозаменяемыми и подготовить воспроизводимый benchmark-каркас. Формат и протокол при этом не меняются.

> Интерфейсы backend'ов (`IHashBackend`, `IMerkleBackend`, `IKemBackend`, `ISigBackend`, `CryptoBackends`) заложены с самого начала, поэтому этот этап сводится в основном к batch/параллелизму, измерениям и проверке эквивалентности.

## Файлы

| Интерфейс | Реализация |
|---|---|
| `crypto/backends.hpp` | `src/crypto/backends.cpp` — `CpuParallel`, `Gpu` (сейчас `BackendUnavailable`, если `!VAULT_HAS_CUDA`) |
| `crypto/cpu_backends.hpp` | многопоточные batch через пул потоков (`src/common/thread_pool.{hpp,cpp}`) |
| `common/timing.hpp` | `PhaseProfile` в verifier/commit/vault |
| `bench/*.hpp` | `src/bench/stats.cpp`, `system_info.cpp`, `benchmark.cpp`, `bench_config.cpp` (JSON — nlohmann/json через FetchContent) |
| `src/cli/commands.cpp` | `vault benchmark --config --csv --json` |

## План работ

### 4.1 Backend'ы
- [x] `make_backends(cfg)`: Cpu — однопоточные, CpuParallel — с `cpu_threads`, Gpu — через `vault::gpu::make_*` под `#ifdef VAULT_HAS_CUDA`.
- [x] CLI-флаг `--backend` пробрасывается во все команды. `vault verify --backend gpu` должен давать тот же результат.
- [x] Batch-методы CPU-MT: разбить вход на равные чанки по потокам. Для SHA3 — балансировка по байтам, а не по количеству объектов.
- [x] Merkle CPU-MT: листья параллельно, уровни — параллельно внутри уровня, если узлов больше порога.

### 4.2 Единый бинарный API
- [x] Зафиксировать в `docs/format_v1.md` (или в комментариях заголовков) раскладку плоских буферов batch: `KemBatch`, `SigBatch`, массив `Hash256` (непрерывный, 32 байта на элемент, без padding — `static_assert(sizeof(Hash256) == 32)`).
- [x] Для SHA3 batch: на стороне backend'а `std::span<const ByteView>` упаковывается в «offsets + data». Этот же формат будет уходить на GPU.

### 4.3 Эквивалентность
- [x] `tests/unit/backend_equivalence_test.cpp` — параметризованный тест по всем доступным backend'ам: случайные входы с фиксированным seed, результат сравнивается с reference (Cpu) байт-в-байт для SHA3, leaves, root, proof и детерминированных KEM/DSA. GPU-вариант этого теста включится в M5/M6 автоматически.

### 4.4 Профилирование фаз vault
- [x] Расставить `ScopedPhase` в verifier, commit и object codec: Algorithm (крипто), Serialization (encode/decode), Filesystem (read/write/fsync), MemoryCopy (сборка буферов). `--verbose` печатает профиль.

### 4.5 Benchmark framework
- [x] `load_bench_config` — JSON из `bench/configs/*.json`.
- [x] Генерация входов заранее, вне измерения: объекты заданного размера (псевдослучайные байты), ключи и сообщения для PQC.
- [x] Цикл: `warmup_runs`, затем `measured_runs`; на каждый прогон — `TimingBreakdown` от backend'а. Total измеряется снаружи через `steady_clock`.
- [x] Пропуск комбинаций, где `size * count > max_total_bytes`, с записью `skipped`.
- [x] `write_csv` (одна строка на `BenchRecord`) и `write_json` (SystemInfo + конфиг + записи).
- [x] `collect_system_info`: `/proc/cpuinfo`, `uname`, `OpenSSL_version`, `OQS_version`, `__VERSION__`, `VAULT_COMPILE_FLAGS`, `git rev-parse` (передаётся при сборке через CMake), CUDA — под `#ifdef`.
- [x] Прогон `bench/configs/quick.json` на CPU (cpu, cpu-mt) — проверка, что CSV/JSON пишутся.

## Тонкие места

* Честное сравнение: в отчёте приводить GPU против **обоих** CPU-вариантов (single-thread и multi-thread).
* Перед замерами: `performance` governor, отсутствие фоновой нагрузки (`check_gpu_env.sh` выводит governor).

## Критерии готовности

- [x] `vault benchmark --config bench/configs/quick.json` работает на CPU и пишет CSV/JSON.
- [x] Тест эквивалентности проходит для `cpu` и `cpu-mt`.
- [x] Формат хранилища не изменился (регрессия на `format_v1_vectors.json`).

## Журнал прогресса

| Дата | Что сделано |
|---|---|
| 2026-10-16 | Этап 4 завершён: `ThreadPool`, CPU-MT backend'ы (hash/Merkle/ML-KEM/ML-DSA), `make_backends` для cpu/cpu-mt/gpu, плоские форматы batch, профиль фаз, benchmark framework и `vault benchmark`. 153 теста проходят (Release, ASan/UBSan). Детали ниже. |


### Ревью (2026-10-16)

Проверено: `ThreadPool` (синхронизация завершения через `completed == n` под мьютексом, вложенных `parallel_for` нет: внутри задач Merkle и proof'ов вызывается только одиночный `domain_hash`), балансировка SHA3 по байтам, независимость срезов выходных буферов в CPU-MT KEM/DSA, `make_backends` для трёх видов, статистика (`stddev` по n−1), разбор конфига. Дефектов корректности в CPU-MT не найдено.

| # | Находка | Исправление |
|---|---|---|
| R1 | **Benchmark не проверял результаты SHA3, Merkle root, ML-KEM keygen/encaps и ML-DSA keygen/sign.** Неверный GPU-backend дал бы правдоподобный «быстрый» замер, а при единственном запуске на GPU это не перепроверить | эталон считается на reference до замеров: SHA3 и листья/root сравниваются байт-в-байт; ключи KEM/DSA проверяются через reference encaps/decaps и sign/verify; ciphertext'ы backend'а — через reference decaps; подписи — через reference verify. Несовпадение роняет прогон (`benchmark self-check failed`). Тест `Benchmark.SelfCheckRejectsWrongBackendResults` (подменённый hash-backend) |
| R2 | `merkle_verify` гонялся для каждого `object_size`, хотя от размера объектов не зависит: 5 одинаковых серий, генерация до 4 GiB данных ради листьев, бессмысленный `throughput_gbps` | серия идёт только по `object_counts` (`object_size = 0`), листья — случайные хеши, throughput не считается |
| R3 | В JSON-результатах не записывалось число потоков `cpu-mt` | `config.cpu_threads` (фактическое, после `resolve_thread_count`) |
| R4 | `git_commit` в `SystemInfo` берётся при configure и не показывал незакоммиченные изменения | `git describe --always --dirty`; сценарий единственного запуска всегда делает свежий configure |
| R5 | `include_alloc_in_total`, `output_csv` и `output_json` не проверялись по типу: падение `nlohmann::type_error` вместо понятной ошибки конфига | проверка типов → `VaultError(InvalidArgument)` |
| R6 | Не было способа подставить в benchmark свой набор backend'ов (нужно для теста самопроверки) | перегрузка `run_benchmarks(cfg, std::vector<BenchBackend>)` |

**Замер полной матрицы на этой машине** (для плана единственного запуска): `full.json` для `cpu` и `cpu-mt`, 12 потоков — 10 мин 34 с, пиковая RSS 1.6 GiB, 24 комбинации пропущены по `max_total_bytes`. SHA3 1 MiB × 1000: 0.50 GB/s (cpu) и 2.42 GB/s (cpu-mt). Это проверка работоспособности и оценка времени, а не данные для отчёта.

**Изменение плана:** этапы 5–7 переписаны под модель «один запуск на GPU» — `docs/gpu_single_run.md`.

Итого тестов: 154 (было 153), Release и ASan/UBSan зелёные.

### Заметки и отклонения

* **`ThreadPool`** (`include/vault/common/thread_pool.hpp`, `src/common/thread_pool.cpp`): единственная операция `parallel_for(n, fn)`, вызывающий поток тоже работает, первое исключение из задач пробрасывается после завершения всех задач; одновременные вызовы сериализуются; не реентерабельный. Пул на заданное число потоков общий для всех backend'ов набора (`shared_thread_pool`), чтобы не плодить простаивающие потоки. Заголовок лежит в `include/`, а не в `src/common/`, как в плане, — так он виден тестам.
* **CPU-MT:** SHA3 batch делится на смежные диапазоны по **байтам** (`split_by_weight`, вес = размер + 1, диапазонов в 4 раза больше потоков, динамическая раздача). ML-KEM/ML-DSA batch — смежные диапазоны по 4 на поток; каждый элемент пишет только в свои срезы буферов. Merkle: листья идут через batch hash backend'а, уровни с числом родителей >= 2048 считаются параллельно, `verify_proofs_batch` — параллельно по proof'ам. Результаты побайтно равны reference (тест эквивалентности). Предположение, проверенное ThreadSanitizer (unit-тесты пула, Merkle, эквивалентности и benchmark: 0 предупреждений; сборка `-fsanitize=thread` вручную, в CMake-опцию не вынесена), ASan/UBSan и тестами: `OQS_KEM`/`OQS_SIG` после создания read-only, случайность берётся из OpenSSL RAND (потокобезопасен).
* **`make_backends`:** `cpu` — однопоточный, `cpu-mt` — `--threads`/`cpu_threads` (0 = все ядра), `gpu` — под `#ifdef VAULT_HAS_CUDA` собирает hash/merkle/kem/sig из `vault::gpu::make_*` (симметричная криптография и RNG остаются на CPU). **GPU-ветка написана «вслепую» и не компилировалась** — проверить на GPU-машине. Без CUDA `--backend gpu` даёт `BackendUnavailable` (код 1).
* **Плоские буферы** зафиксированы в `docs/format_v1.md` §15; `static_assert(sizeof(Hash256) == 32)`; добавлен `crypto/packed_batch.hpp` (`PackedBatch`: «offsets + data») с тестом round-trip.
* **Профиль фаз:** `ScopedPhase` в verifier, commit и object codec (`encrypt_object`/`decrypt_object` принимают необязательный `PhaseProfile*`). В commit `Filesystem` считается как остаток (wall минус Algorithm/Serialization/MemoryCopy), чтобы вложенные фазы не учитывались дважды. `Vault::open_profile()` и `Vault::last_profile()`; `-v` у `add`/`extract`/`remove`/`verify` печатает профили. `extract` по проверенному состоянию в памяти диск не трогает (Filesystem = 0).
* **Benchmark:** `src/bench/{stats,system_info,bench_config,benchmark}.cpp`, JSON через nlohmann/json (FetchContent, v3.11.3). Входы генерируются до измерений детерминированным ГПСЧ; для PQC и proof'ов подготовка идёт на reference CPU. Total меряется снаружи `steady_clock`; при `include_alloc_in_total = false` из него вычитается `alloc_ms` backend'а. `merkle_verify` — пакетная проверка proof'ов **всех** листьев (пересчёт root отдельно не измеряется, он входит в `merkle_build`). Бенчмарки сами проверяют корректность результата (proof'ы, подписи, decaps == encaps). Недоступный backend (gpu без CUDA) даёт записи `skipped`, комбинации `size * count > max_total_bytes` — `skipped: exceeds max_total_bytes` (проверка делением, без переполнения).
* **`vault benchmark --config <json> [--csv f] [--json f]`**; `--csv/--json` переопределяют ключи `output_csv`/`output_json`; `--config` обязателен. CSV: одна строка на запись, total — mean/median/min/max/stddev, остальные фазы — median и mean.
* **SystemInfo:** git commit определяется при конфигурации CMake (`VAULT_GIT_COMMIT`), версии OpenSSL/liboqs — в рантайме, CUDA-поля под `#ifdef`. Исправлено: `VAULT_COMPILE_FLAGS` раньше был пустым (`CMAKE_CXX_FLAGS_${BUILD_TYPE}` нужен в верхнем регистре).
* **Smoke-прогон `quick.json` на dev-машине** (i5-12450H, 12 потоков, Release): `mldsa_sign` batch 100 — cpu 10.2 мс, cpu-mt 2.3 мс; `mlkem_keygen` batch 100 — 1.09 против 0.28 мс; batch 1 ускорения не даёт (как и ожидалось). Это проверка работоспособности, не данные для отчёта: перед замерами нужен `performance` governor и отсутствие фоновой нагрузки.
* **Регрессия формата:** `tests/unit/format_vectors_test.cpp` (векторы этапа 2) проходит без изменений — формат хранилища не менялся.
