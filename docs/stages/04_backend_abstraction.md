# Этап 4: абстракция CPU/GPU backend и benchmark-инфраструктура

**Статус:** ☐ не начат  ·  **Где:** CPU (вся GPU-часть пока в виде заглушек)  ·  **ТЗ:** план → Этап 4

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
- [ ] `make_backends(cfg)`: Cpu — однопоточные, CpuParallel — с `cpu_threads`, Gpu — через `vault::gpu::make_*` под `#ifdef VAULT_HAS_CUDA`.
- [ ] CLI-флаг `--backend` пробрасывается во все команды. `vault verify --backend gpu` должен давать тот же результат.
- [ ] Batch-методы CPU-MT: разбить вход на равные чанки по потокам. Для SHA3 — балансировка по байтам, а не по количеству объектов.
- [ ] Merkle CPU-MT: листья параллельно, уровни — параллельно внутри уровня, если узлов больше порога.

### 4.2 Единый бинарный API
- [ ] Зафиксировать в `docs/format_v1.md` (или в комментариях заголовков) раскладку плоских буферов batch: `KemBatch`, `SigBatch`, массив `Hash256` (непрерывный, 32 байта на элемент, без padding — `static_assert(sizeof(Hash256) == 32)`).
- [ ] Для SHA3 batch: на стороне backend'а `std::span<const ByteView>` упаковывается в «offsets + data». Этот же формат будет уходить на GPU.

### 4.3 Эквивалентность
- [ ] `tests/unit/backend_equivalence_test.cpp` — параметризованный тест по всем доступным backend'ам: случайные входы с фиксированным seed, результат сравнивается с reference (Cpu) байт-в-байт для SHA3, leaves, root, proof и детерминированных KEM/DSA. GPU-вариант этого теста включится в M5/M6 автоматически.

### 4.4 Профилирование фаз vault
- [ ] Расставить `ScopedPhase` в verifier, commit и object codec: Algorithm (крипто), Serialization (encode/decode), Filesystem (read/write/fsync), MemoryCopy (сборка буферов). `--verbose` печатает профиль.

### 4.5 Benchmark framework
- [ ] `load_bench_config` — JSON из `bench/configs/*.json`.
- [ ] Генерация входов заранее, вне измерения: объекты заданного размера (псевдослучайные байты), ключи и сообщения для PQC.
- [ ] Цикл: `warmup_runs`, затем `measured_runs`; на каждый прогон — `TimingBreakdown` от backend'а. Total измеряется снаружи через `steady_clock`.
- [ ] Пропуск комбинаций, где `size * count > max_total_bytes`, с записью `skipped`.
- [ ] `write_csv` (одна строка на `BenchRecord`) и `write_json` (SystemInfo + конфиг + записи).
- [ ] `collect_system_info`: `/proc/cpuinfo`, `uname`, `OpenSSL_version`, `OQS_version`, `__VERSION__`, `VAULT_COMPILE_FLAGS`, `git rev-parse` (передаётся при сборке через CMake), CUDA — под `#ifdef`.
- [ ] Прогон `bench/configs/quick.json` на CPU (cpu, cpu-mt) — проверка, что CSV/JSON пишутся.

## Тонкие места

* Честное сравнение: в отчёте приводить GPU против **обоих** CPU-вариантов (single-thread и multi-thread).
* Перед замерами: `performance` governor, отсутствие фоновой нагрузки (`check_gpu_env.sh` выводит governor).

## Критерии готовности

- [ ] `vault benchmark --config bench/configs/quick.json` работает на CPU и пишет CSV/JSON.
- [ ] Тест эквивалентности проходит для `cpu` и `cpu-mt`.
- [ ] Формат хранилища не изменился (регрессия на `format_v1_vectors.json`).

## Журнал прогресса

| Дата | Что сделано |
|---|---|
