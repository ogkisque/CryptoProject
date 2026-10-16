# Этап 5: GPU-ускорение SHA3-256 и Merkle Tree

**Статус:** ☐ не начат  ·  **Где:** **GPU-машина** (RTX 3050, SM 86)  ·  **ТЗ:** план → Этап 5, `crypto_project.md` §41–§42, §45, §48

## Цель

Сделать GPU backend для `IHashBackend` и `IMerkleBackend`, результаты которого совпадают с CPU байт-в-байт, и измерить, где он выигрывает с учётом передачи данных.

## Файлы

```
cuda/kernels/keccak.cuh          # Keccak-f[1600], sponge SHA3-256 (rate 136), domain-префикс в первом блоке
cuda/kernels/merkle_level.cuh    # один уровень дерева: parent / unpaired
cuda/src/device.cu               # query_device, cuda_device_available, GpuContext (stream, events, pinned-пулы)
cuda/src/gpu_hash_backend.cu     # make_gpu_hash_backend
cuda/src/gpu_merkle_backend.cu   # make_gpu_merkle_backend
tests/gpu/gpu_equivalence_test.cpp
```

## План работ

### 5.0 Окружение (первым делом на GPU-машине)
- [ ] `./scripts/check_gpu_env.sh`: драйвер, `nvcc ≥ 12`, compute_cap 8.6, объём VRAM (в RTX 3050 бывает 4, 6 или 8 GiB — записать в журнал).
- [ ] Поставить cuPQC SDK и проверить, есть ли в нём **cuHash** (SHA3 / Merkle, в новых версиях SDK). Если есть — можно сравнить три варианта: свой kernel, cuHash и CPU. Готовое Merkle Tree из cuHash **не подходит** напрямую, потому что у нас свои domain-префиксы (0x00/0x01/0x02) и правило непарного узла. Использовать только его SHA3-примитив.
- [ ] Собрать проект с `VAULT_ENABLE_CUDA=ON` (`./scripts/build_gpu.sh`). Поправить `cmake/Cuda.cmake` под реальные имена cuPQC.

### 5.1 SHA3 batch kernel
- [ ] Упаковка входов: `offsets[count+1]` (u64) + непрерывный `data` в pinned memory, затем один H2D. Префикс домена передаётся параметром kernel'а и не копируется в data.
- [ ] Стратегия параллелизма: **один поток (или warp) на объект** — Keccak sponge последователен внутри одного сообщения, поэтому параллелизм есть только между объектами. Для 16 MiB × 10 объектов GPU почти наверняка проиграет; это ожидаемый и важный для отчёта результат.
- [ ] Вариант с warp на объект: 25 lane'ов держат состояние, θ/ρ/π/χ/ι через `__shfl_sync`. Сравнить с thread-per-object.
- [ ] Порционирование, если суммарный размер больше `max_chunk_bytes` (VRAM). Опционально — перекрытие H2D и вычислений через 2 stream'а (double buffering). Это отдельная точка в benchmark'е.
- [ ] Тайминг через `cudaEvent`: alloc (cudaMalloc/cudaMallocHost), H2D, kernel, D2H, sync → `TimingBreakdown`.
- [ ] Обнуление буферов на GPU не требуется: данные публичные (ciphertext). Это отметить в отчёте, в отличие от M6.

### 5.2 Merkle на GPU
- [ ] Листья — тот же SHA3 batch с доменом 0x00, результат остаётся на device.
- [ ] Уровни — kernel на уровень: поток i считает `parent(2i, 2i+1)` или `unpaired(2i)`. Число запусков = ⌈log2 N⌉. Для малых уровней (< ~1024 узлов) сравнить вариант «досчитать на CPU».
- [ ] `build_tree` копирует уровни на host только при запросе (для proof). `root_from_leaves` возвращает только корень.
- [ ] `verify_proofs_batch`: поток на proof (≤ 17 шагов при N ≤ 100000).

### 5.3 Эквивалентность (§42)
- [ ] `tests/gpu/`: SHA3 CAVP vectors на GPU. Случайные сообщения длиной 0…10000 байт, в том числе ровно 135, 136 и 137 (граница rate) — GPU == CPU. Merkle root для N = 0…1000 и для 100000 — GPU == CPU. Proof batch даёт тот же результат.
- [ ] `vault verify --backend gpu` возвращает VALID на тех же хранилищах, на испорченных — тот же `VerifyStep`.

### 5.4 Измерения
- [ ] Матрица: размеры {1, 4, 64 KiB, 1, 16 MiB} × количество {10 … 100000} с учётом `max_total_bytes` (VRAM). Бэкенды cpu, cpu-mt, gpu.
- [ ] Отдельные серии: с учётом и без учёта `cudaMalloc` (пул буферов, переиспользуемый между прогонами), pageable и pinned память.
- [ ] Предварительный crossover для SHA3 и Merkle (полный анализ — в M7).

## Тонкие места

* Первый CUDA-вызов создаёт контекст (≈ 100+ мс). Его делают в warm-up, и в замеры он не попадает (в отчёте указать отдельно).
* Не смешивать «GPU kernel time» и «GPU total»: в speedup используется total (§45).
* Для `verify` на реальном хранилище узким местом может оказаться чтение с диска — это измеряется через PhaseProfile из M4.

## Критерии готовности

- [ ] Тесты эквивалентности проходят на GPU-машине.
- [ ] CSV с полной матрицей SHA3/Merkle сохранён в `bench/results/`.

## Журнал прогресса

| Дата | Что сделано |
|---|---|
