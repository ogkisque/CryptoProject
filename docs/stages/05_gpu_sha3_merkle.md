# Этап 5: GPU-ускорение SHA3-256 и Merkle Tree

**Статус:** ☐ не начат  ·  **Где:** часть А — на этой машине (без GPU), часть Б — автоматически в единственном запуске (`docs/gpu_single_run.md`)  ·  **ТЗ:** план → Этап 5, `crypto_project.md` §41–§42, §45, §48

## Цель

GPU-backend для `IHashBackend` и `IMerkleBackend`, байт-в-байт совпадающий с CPU, плюс замеры, где он выигрывает с учётом передачи данных. Код пишется без GPU, поэтому всё, кроме исполнения на устройстве, должно быть проверено на CPU.

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

### 5.A0 Окружение для компиляции без GPU
- [ ] Поставить CUDA Toolkit (≥ 12.x, без драйвера) и скачать cuPQC SDK. Записать точные версии: GPU-машина должна получить те же.
- [ ] Проверить, есть ли в SDK **cuHash** (SHA3 и Merkle). Готовое Merkle из cuHash **не подходит**, потому что у нас свои domain-префиксы и правило непарного узла. Брать можно только SHA3-примитив и только как дополнительный вариант для сравнения.
- [ ] Поправить `cmake/Cuda.cmake` под реальные имена cuPQC. Цель — сборка `-DVAULT_ENABLE_CUDA=ON` **проходит здесь** без предупреждений.
- [ ] Сделать так, чтобы `cuda_device_available()` без устройства честно возвращал false, а `--backend gpu` давал `BackendUnavailable`, а не падал.

### 5.A1 Kernel-логика как host-тестируемый код
- [ ] `keccak.cuh`: `VAULT_HD` Keccak-f[1600] и sponge SHA3-256. Domain-префикс подаётся первым байтом, без копирования данных. Без глобальных таблиц, недоступных на device: round constants как `constexpr`, на device через `__constant__`.
- [ ] `merkle_level.cuh`: `parent(L, R)`, `unpaired(x)`, шаг proof — поверх того же `sha3_256`.
- [ ] `kernel_host_test.cpp` (собирается всегда, g++): CAVP-векторы и случайные длины 0…10000, в том числе ровно 135, 136, 137, 271, 272 байта — результат равен OpenSSL. Merkle для N = 0…1000 совпадает с reference.

### 5.A2 Host-часть GPU backend'а
- [ ] `launch_plan`: порционирование входа по `max_chunk_bytes` (целые объекты; объект больше чанка обрабатывается отдельно), расчёт grid/block, смещения в `PackedBatch`. Тесты: граничные размеры, объект больше чанка, 0 объектов, 100000 объектов.
- [ ] Стратегии параллелизма: **поток на объект** (основная — sponge последователен внутри сообщения) и **warp на объект** (25 lane'ов держат состояние, `__shfl_sync`) как опция. Выбор — параметр, оба варианта идут в benchmark.

### 5.A3 Device-код (пишется вслепую, проверяется компиляцией)
- [ ] `device.cu`: `GpuContext` (stream, events, переиспользуемые device- и pinned-буферы), `query_device`, `cudaMemGetInfo` → `max_chunk_bytes`.
- [ ] `gpu_hash_backend.cu`: H2D (одна копия `PackedBatch`) → kernel → D2H. Тайминг через `cudaEvent` по фазам alloc/H2D/kernel/D2H/sync в `TimingBreakdown`. Double buffering на 2 stream'ах — опция.
- [ ] `gpu_merkle_backend.cu`: листья тем же kernel'ом (домен 0x00), уровни — kernel на уровень (поток на родителя). Узкие уровни (< ~1024 узлов) досчитываются на CPU (порог — параметр). `verify_proofs_batch`: поток на proof.
- [ ] Каждая CUDA-ошибка превращается в `VaultError(CryptoError)` с именем вызова (макрос `CUDA_CHECK`): в логе единственного запуска должно быть видно, **что** упало.
- [ ] Обнуление буферов не нужно: данные публичные (ciphertext). Отметить в отчёте, в отличие от этапа 6.

### 5.A4 Тесты и конфиги для запуска
- [ ] `tests/gpu/gpu_equivalence_test.cpp`: CAVP на GPU, случайные длины (включая границы rate), Merkle N = 0…1000 и 100000, proof batch, `vault verify --backend gpu` на чистом и испорченном хранилище (тот же `VerifyStep`). Без устройства — `GTEST_SKIP`. Тест `BackendEquivalence` из этапа 4 подхватит gpu сам.
- [ ] `bench/configs/gpu_pinned_vs_pageable.json`, `gpu_alloc_in_total.json`, `gpu_double_buffering.json`.
- [ ] Сборка с CUDA здесь проходит, все тесты зелёные (GPU-тесты — skipped).

## Часть Б — в единственном запуске (делает скрипт, руками ничего)

- Сборка, `ctest -L gpu`, эквивалентность (шаг 2 `gpu_run_all.sh`). При провале эквивалентности GPU-hash/merkle исключаются из benchmark'а, остальные этапы продолжаются.
- Матрица SHA3/Merkle `full.json` (cpu, cpu-mt, gpu) и дополнительные серии `gpu_*.json`.
- В архив: модель GPU, VRAM, драйвер, CUDA, версия cuPQC (из `SystemInfo` и `nvidia-smi -q`).

## Тонкие места

* Первый CUDA-вызов создаёт контекст (≈ 100+ мс): он уходит в warm-up и в замеры не попадает (в отчёте указать отдельно).
* В speedup используется **GPU total**, а не kernel time (§45).
* Один большой объект (16 MiB × 10) GPU почти наверняка проигрывает: sponge последователен. Это ожидаемый и важный для отчёта результат.
* Интерфейс `IMerkleBackend` разделяет `compute_leaves` и `root_from_leaves`, поэтому листья проходят D2H → H2D. Это N·32 байт, мало по сравнению с данными. Влияние видно в разбивке фаз.

## Критерии готовности части А

- [ ] Сборка с CUDA и cuPQC проходит здесь; `kernel_host_test` и `launch_plan_test` зелёные.
- [ ] GPU-тесты корректно пропускаются без устройства.
- [ ] Отмечены соответствующие пункты gate в `docs/gpu_single_run.md`.

## Журнал прогресса

| Дата | Что сделано |
|---|---|
| 2026-10-16 | План переписан под модель «один запуск на GPU» (ревью этапа 4) |
