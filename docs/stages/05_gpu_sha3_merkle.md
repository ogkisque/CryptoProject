# Этап 5: GPU-ускорение SHA3-256 и Merkle Tree

**Статус:** часть А ✅ готова (2026-10-16); часть Б ☐ — сборка и запуск на GPU-машине автором  ·  **Где:** часть А — на этой машине (без CUDA, код не компилируется), часть Б — сборка и запуск на GPU-машине автором (`docs/gpu_workflow.md`)  ·  **ТЗ:** план → Этап 5, `crypto_project.md` §41–§42, §45, §48

## Цель

GPU-backend для `IHashBackend` и `IMerkleBackend`, байт-в-байт совпадающий с CPU, плюс замеры, где он выигрывает с учётом передачи данных. CUDA здесь нет: `.cu`-файлы пишутся без компиляции, а всё, что можно вынести в обычный C++ (логика kernel'ов, планирование запусков), выносится и тестируется g++.

## Файлы

```
cuda/kernels/hd.hpp              # VAULT_HD = __host__ __device__ под nvcc, пусто под g++
cuda/kernels/keccak.cuh          # VAULT_HD keccak_f1600, sha3_256 sponge (rate 136) с domain-префиксом
cuda/kernels/merkle_level.cuh    # VAULT_HD parent / unpaired / один шаг proof
cuda/host/launch_plan.{hpp,cpp}  # C++ без CUDA API: чанки по VRAM, grid/block, упаковка PackedBatch
cuda/src/device.cu               # query_device, cuda_device_available, GpuContext (stream, events, пулы pinned-буферов)
cuda/src/gpu_hash_backend.cu     # make_gpu_hash_backend
cuda/src/gpu_merkle_backend.cu   # make_gpu_merkle_backend
tests/unit/kernel_host_test.cpp  # VAULT_HD-функции на CPU против OpenSSL/reference (всегда)
tests/unit/launch_plan_test.cpp  # host-часть (всегда)
tests/gpu/gpu_equivalence_test.cpp  # на устройстве; GTEST_SKIP без GPU
bench/configs/gpu_*.json         # дополнительные серии (pinned/pageable, alloc, double buffering)
```

## Часть А — на этой машине (до запуска)

### 5.A0 CMake и заглушки
- [x] `cmake/Cuda.cmake`: поиск cuPQC по `CUPQC_ROOT` (имена пакета/целей — по документации SDK, помечены `UNVERIFIED`); без cuPQC GPU-backend собирается только с SHA3/Merkle.
- [x] Без устройства `cuda_device_available()` возвращает false, а `--backend gpu` даёт `BackendUnavailable`, а не падает.
- [x] `CUDA_CHECK(expr)` с выражением, файлом:строкой и `cudaGetErrorString` в тексте `VaultError(CryptoError)`.
- [x] Записать в журнал, на какие версии CUDA и cuPQC рассчитан код. Автор сверит с GPU-машиной.

### 5.A1 Kernel-логика как host-тестируемый код
- [x] `keccak.cuh`: `VAULT_HD` Keccak-f[1600] и sponge SHA3-256. Domain-префикс подаётся первым байтом, без копирования данных. Без глобальных таблиц, недоступных на device: round constants как `constexpr`, на device через `__constant__`.
- [x] `merkle_level.cuh`: `parent(L, R)`, `unpaired(x)`, шаг proof — поверх того же `sha3_256`.
- [x] `kernel_host_test.cpp` (собирается всегда, g++): CAVP-векторы и случайные длины 0…10000, в том числе ровно 135, 136, 137, 271, 272 байта — результат равен OpenSSL. Merkle для N = 0…1000 совпадает с reference.

### 5.A2 Host-часть GPU backend'а
- [x] `launch_plan`: порционирование входа по `max_chunk_bytes` (целые объекты; объект больше чанка обрабатывается отдельно), расчёт grid/block, смещения в `PackedBatch`. Тесты: граничные размеры, объект больше чанка, 0 объектов, 100000 объектов.
- [x] Стратегии параллелизма: **поток на объект** (основная — sponge последователен внутри сообщения) и **warp на объект** (25 lane'ов держат состояние, `__shfl_sync`) как опция. Выбор — параметр, оба варианта идут в benchmark.

### 5.A3 Device-код (пишется вслепую, здесь не компилируется)
- [x] `device.cu`: `GpuContext` (stream, events, переиспользуемые device- и pinned-буферы), `query_device`, `cudaMemGetInfo` → `max_chunk_bytes`.
- [x] `gpu_hash_backend.cu`: H2D (одна копия `PackedBatch`) → kernel → D2H. Тайминг через `cudaEvent` по фазам alloc/H2D/kernel/D2H/sync в `TimingBreakdown`. Double buffering на 2 stream'ах — опция.
- [x] `gpu_merkle_backend.cu`: листья тем же kernel'ом (домен 0x00), уровни — kernel на уровень (поток на родителя). Узкие уровни (< ~1024 узлов) досчитываются на CPU (порог — параметр). `verify_proofs_batch`: поток на proof.
- [x] Все вызовы CUDA — через `CUDA_CHECK`, чтобы по присланному логу было сразу видно, **что** упало.
- [x] Обнуление буферов не нужно: данные публичные (ciphertext). Отметить в отчёте, в отличие от этапа 6.

### 5.A4 Тесты и конфиги для запуска
- [x] `tests/gpu/gpu_equivalence_test.cpp`: CAVP на GPU, случайные длины (включая границы rate), Merkle N = 0…1000 и 100000, proof batch, `vault verify --backend gpu` на чистом и испорченном хранилище (тот же `VerifyStep`). Без устройства — `GTEST_SKIP`. Тест `BackendEquivalence` из этапа 4 подхватит gpu сам.
- [x] `bench/configs/gpu_pinned_vs_pageable.json`, `gpu_alloc_in_total.json`, `gpu_double_buffering.json`.
- [x] Сборка без CUDA здесь проходит, все тесты зелёные (GPU-тесты не собираются / skipped).

## Часть Б — на GPU-машине (собирает и запускает автор)

- `gpu_run_all.sh --quick`: сборка, `ctest -L gpu`, эквивалентность. Ошибки сборки и тестов присылаются и исправляются здесь, цикл повторяется.
- Когда быстрый прогон зелёный — полный: матрица SHA3/Merkle `full.json` (cpu, cpu-mt, gpu) и серии `gpu_*.json`.
- В архиве: модель GPU, VRAM, драйвер, CUDA, версия cuPQC (из `SystemInfo` и `nvidia-smi -q`).
- Исправления по результатам записываются в журнал этого файла (что упало → что поменяли).

## Тонкие места

* Первый CUDA-вызов создаёт контекст (≈ 100+ мс): он уходит в warm-up и в замеры не попадает (в отчёте указать отдельно).
* В speedup используется **GPU total**, а не kernel time (§45).
* Один большой объект (16 MiB × 10) GPU почти наверняка проигрывает: sponge последователен. Это ожидаемый и важный для отчёта результат.
* Интерфейс `IMerkleBackend` разделяет `compute_leaves` и `root_from_leaves`, поэтому листья проходят D2H → H2D. Это N·32 байт, мало по сравнению с данными. Влияние видно в разбивке фаз.

## Критерии готовности части А

- [x] `kernel_host_test` и `launch_plan_test` зелёные здесь; сборка без CUDA не сломана.
- [x] `.cu`-код написан, все вызовы CUDA — через `CUDA_CHECK`, места под вопросом помечены `UNVERIFIED`.

## Критерии готовности части Б

- [ ] На GPU-машине: сборка проходит, `ctest -L gpu` зелёный, данные `full.json` с GPU-точками получены.

## Журнал прогресса

| Дата | Что сделано |
|---|---|
| 2026-10-16 | План переписан под модель «один запуск на GPU» (ревью этапа 4) |
| 2026-10-16 | План пересмотрен: CUDA здесь не ставится, GPU-код пишется без компиляции, сборка и запуск — на GPU-машине автором с обратной связью (`docs/gpu_workflow.md`) |
| 2026-10-16 | **Часть А готова** (код без компиляции CUDA; host-часть и kernel-логика проверены здесь). Детали ниже. |

### Часть А: что сделано и принятые решения

**Версии, на которые рассчитан код (для сверки на GPU-машине):** CUDA Toolkit 12.x (`find_package(CUDAToolkit 12.0)`), SM 86, nvcc с C++20 (`CUDA_STANDARD 20`: публичные заголовки проекта используют `std::span`; для GCC 13 нужен CUDA ≥ 12.4, иначе `-DCMAKE_CUDA_HOST_COMPILER=g++-12`). cuPQC на этом этапе не используется (этап 6); без него собираются заглушки `cuda/src/gpu_pqc_stub.cpp`.

**Раскладка кода.**
* `cuda/kernels/` — общий код device/CPU (`VAULT_HD`): `keccak.cuh` (Keccak-f[1600], потоковый sponge SHA3-256 с domain-префиксом, байты XOR-ятся прямо в состояние, без буфера блока), `merkle_level.cuh` (parent/unpaired/узел уровня/строгая проверка proof — те же правила, что `merkle::verify_proof`), `keccak_warp.cuh` (вариант «warp на объект»: lane i держит лейн A[i], обмен `__shfl_sync`).
* `cuda/host/` — C++ без CUDA API: `launch_plan` (порции, grid/block, расписание уровней Merkle, диапазоны proof'ов, упаковка proof'ов в плоские массивы), `hash_pipeline.hpp` и `merkle_levels.hpp` — **шаблоны конвейера над абстрактным «устройством»**.
* `cuda/src/` — CUDA-часть: `gpu_runtime.hpp` (`CUDA_CHECK`, RAII-буферы, stream/event), `device.cu`, `gpu_hash_backend.cu`, `gpu_merkle_backend.cu` — тонкие реализации «устройства».
* `cmake/Cuda.cmake`: CUDA-исходники добавляются **прямо в `vault_core`** (функция `vault_attach_cuda`), а не в отдельную библиотеку `vault_gpu`: GPU-код использует `VaultError` и `cuda/host/*.cpp`, а `vault_core` вызывает GPU-фабрики, поэтому отдельная статическая библиотека дала бы циклическую зависимость при линковке.

**Как снижен риск «вслепую»:**
1. *Kernel-логика исполняется на CPU* тем же исходным текстом: `kernel_host_test` сверяет SHA3-256 с OpenSSL для всех длин 0…600 и границ rate (135/136/137/271/272/273…), для 8 доменов, при невыровненном входе и произвольном дроблении absorb; known answers (пустая строка, "abc", 200 байт 0xA3 из примеров NIST); Merkle для N = 0…1000 против reference (листья, все уровни, корень); proof'ы — согласованность с `merkle::verify_proof`, включая испорченные и неформатные.
2. *Warp-вариант*: индексная математика shuffle (`warp_*`, `keccak_pi_source`, `keccak_rho_offset`) вынесена в `VAULT_HD`-функции; тест эмулирует 32 lane'а массивами и сверяет перестановку со скалярным Keccak и полный sponge с OpenSSL. Сам `__shfl_sync`-код под g++ не собирается.
3. *Конвейеры на эмулированном устройстве* (`tests/unit/gpu_pipeline_test.cpp`): эмуляция исполняет **отложенно** (данные и kernel отрабатывают только в `finish`), staging заполняется «ядом» — поэтому перезапись staging слота до `finish`, чтение незаписанного уровня, выход за границы ping-pong буферов дают неверный результат или флаг. Проверено мутацией: если убрать ожидание занятого слота, тесты падают. Покрыто: размеры порций от одного объекта до 1 MiB, 1/2/3 слота, объект больше порции, пустые объекты, ошибка посреди конвейера (вызывается `drain`), все пороги `merkle_cpu_threshold`, N до 4097.
4. *Синтаксис `.cu`*: `scripts/check_cuda_syntax.sh` прогоняет `cuda/src/*.cu` через clang (`--cuda-host-only` и `--cuda-device-only`) с заглушками `tools/fakecuda/` — без CUDA Toolkit. Это поймало реальную ошибку (`merkle::MerkleSchedule` вместо `gpu::MerkleSchedule`) и отсутствующий guard `__CUDACC__`. Это не nvcc: PTX, ограничения конкретной версии, `Cuda.cmake` не проверяются.
5. *Ошибки информативны*: `CUDA_CHECK` кладёт в `VaultError(CryptoError)` выражение, `файл:строка` и имя/текст ошибки CUDA; запуск kernel'а проверяется `cudaGetLastError` с именем kernel'а. GPU-тесты на расхождении печатают первый несовпавший элемент (индекс, длину входа, оба хеша).

**Принятые решения.**
* **Одиночные хеши считаются на CPU** тем же кодом, что kernel (`sha3_256`, `domain_hash`): `kem_ct_hash`/key id по 1–2 КБ дешевле запуска kernel'а. GPU используют только batch-вызовы (`compute_leaves`, `*_batch`).
* **Вход собирается в смежный staging** (pinned или pageable): объекты разрознены в памяти, одна копия host→staging неизбежна. Поэтому «одна копия `PackedBatch`» из плана — это одна H2D-копия порции из staging. Время сборки входит в `h2d_ms`.
* **Буферы по умолчанию не пулируются** (`pool_buffers = false`): `cudaMalloc`/`cudaFree` на каждый вызов, их время — в `alloc_ms` и в total (§48: «GPU total включает аллокацию»). Для сравнения есть `pool_buffers = true`; серия `gpu_alloc_in_total.json` измеряет разницу.
* **Размер порции** (`max_chunk_bytes`, 0 = авто): не более 60 % свободной VRAM на все слоты и не более 1 GiB; порция считается как данные + смещения + выходы. Объект больше порции идёт отдельно (`oversized`) — при нехватке VRAM это даст `cudaMalloc` ошибку с понятным текстом.
* **Double buffering**: два слота (stream + события + буферы). Сумма фаз при перекрытии может превышать total — отмечено в комментарии и конфиге.
* **Merkle:** листья — тем же GPU-backend SHA3; уровни — kernel «поток на родителя»; уровни уже порога `merkle_cpu_threshold` (1024) и всё дерево, если оно не помещается в `max_chunk_bytes`, считаются на CPU. В режиме `build_tree` время D2H-копий уровней входит в `kernel_ms` (benchmark измеряет `root_from_leaves`, где этого нет).
* **GPU без cuPQC.** `make_backends(gpu)` собирает hash/Merkle на GPU, а ML-KEM/ML-DSA — на GPU, если cuPQC есть, иначе берёт CPU-реализацию (vault и `verify --backend gpu` работают). Benchmark по `name() != "gpu"` помечает такие точки как `skipped: no gpu implementation of this component`, а не выдаёт CPU-замер за GPU.
* **Benchmark-конфиг расширен:** backend можно задавать объектом `{"kind": "gpu", "label": "...", "pinned_host_memory", "double_buffering", "pool_buffers", "strategy": "thread"|"warp", "max_chunk_bytes", "merkle_cpu_threshold", "cuda_device", "threads"}`; неизвестные опции и повторяющиеся подписи — ошибка; `label` попадает в CSV/JSON (`backend`), опции — в JSON (`backend_options`). Добавлены `bench/configs/gpu_pinned_vs_pageable.json`, `gpu_alloc_in_total.json`, `gpu_double_buffering.json` и (сверх плана) `gpu_hash_strategy.json` — «поток на объект» против «warp на объект».
* **GPU-тесты собираются всегда** (`test_gpu`, метка `gpu`): без устройства — `GTEST_SKIP` с причиной; так компилятор проверяет их и здесь. `BackendEquivalence` из этапа 4 подхватывает gpu автоматически.
* **CAVP.** Вместо файлов NIST CAVP (`SHA3_256ShortMsg.rsp`) — известные ответы из примеров FIPS 202 плюс побайтное сравнение с OpenSSL на всех длинах; OpenSSL сам валидирован по CAVP.
* **Обнуление буферов не нужно** (данные публичные: ciphertext и хеши) — в отличие от этапа 6.

**Места, помеченные `UNVERIFIED`** (если сборка/запуск на GPU-машине упадёт, смотреть сюда):
1. `cmake/Cuda.cmake`: C++20 для `.cu`; device-link смешанной статической библиотеки (`CUDA_SEPARABLE_COMPILATION`); поиск cuPQC.
2. `kernels/keccak.cuh`: производительность `constexpr`-switch для round constants / rho / pi — nvcc должен свернуть их при развёртке.
3. `gpu_hash_backend.cu`: давление на регистры в варианте «поток на объект».
4. Не помечено, но не проверялось nvcc: `__shfl_sync` для 64-битных значений (поддерживается с CUDA 9), `-lineinfo --expt-relaxed-constexpr`.

**Что проверено здесь:** 193 теста (Release) и тесты под ASan/UBSan зелёные; `check_cuda_syntax.sh` чисто; GPU-тесты корректно пропускаются.
