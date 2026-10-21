# Результаты benchmark'а

Файл сформирован `bench/analysis/analyze.py` из сырых CSV; числа не правились вручную. speedup = total(CPU) / total(кандидат) по медианам; total GPU включает аллокации, передачу данных и синхронизацию (§45, §48).

Входные файлы (1): `results_gpu_alloc_in_total.csv`

## Покрытие

| backend | измерено (строк) | пропущено (строк) |
|---|---|---|
| cpu | 16 | 2 |
| gpu-alloc-per-call | 16 | 2 |
| gpu-pooled | 16 | 2 |

Причины пропусков:

| backend | причина | строк |
|---|---|---|
| cpu | exceeds max_total_bytes | 2 |
| gpu-alloc-per-call | exceeds max_total_bytes | 2 |
| gpu-pooled | exceeds max_total_bytes | 2 |

## Точки пересечения (speedup = 1)

Интерполяция линейная по log(speedup) от log(x) между соседними точками сетки. «Кандидат» — GPU-backend (kind = gpu) либо `cpu-mt` (kind = threads, против `cpu`).

### GPU против CPU

| операция | ось | фиксировано | кандидат | baseline | результат |
|---|---|---|---|---|---|
| merkle_build | по числу (batch) | размер 1 KiB | gpu-alloc-per-call | cpu | быстрее начиная с ≈ 305 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 1 KiB | gpu-pooled | cpu | быстрее начиная с ≈ 274 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 64 KiB | gpu-alloc-per-call | cpu | быстрее начиная с ≈ 256 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 64 KiB | gpu-pooled | cpu | быстрее начиная с ≈ 60 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 1 MiB | gpu-alloc-per-call | cpu | быстрее начиная с ≈ 273 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 1 MiB | gpu-pooled | cpu | быстрее начиная с ≈ 58 (число объектов/листьев/batch) |
| merkle_build | по размеру объекта | 10 объектов | gpu-alloc-per-call | cpu | нет пересечения в диапазоне (1 KiB…1 MiB): кандидат не быстрее |
| merkle_build | по размеру объекта | 10 объектов | gpu-pooled | cpu | нет пересечения в диапазоне (1 KiB…1 MiB): кандидат не быстрее |
| merkle_build | по размеру объекта | 1 000 объектов | gpu-alloc-per-call | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| merkle_build | по размеру объекта | 1 000 объектов | gpu-pooled | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| merkle_build | по размеру объекта | 10 000 объектов | gpu-alloc-per-call | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| merkle_build | по размеру объекта | 10 000 объектов | gpu-pooled | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| sha3 | по числу (batch) | размер 1 KiB | gpu-alloc-per-call | cpu | быстрее начиная с ≈ 244 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 1 KiB | gpu-pooled | cpu | быстрее начиная с ≈ 66 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 64 KiB | gpu-alloc-per-call | cpu | быстрее начиная с ≈ 275 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 64 KiB | gpu-pooled | cpu | быстрее начиная с ≈ 61 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 1 MiB | gpu-alloc-per-call | cpu | быстрее начиная с ≈ 269 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 1 MiB | gpu-pooled | cpu | быстрее начиная с ≈ 57 (число объектов/листьев/batch) |
| sha3 | по размеру объекта | 10 объектов | gpu-alloc-per-call | cpu | нет пересечения в диапазоне (1 KiB…1 MiB): кандидат не быстрее |
| sha3 | по размеру объекта | 10 объектов | gpu-pooled | cpu | нет пересечения в диапазоне (1 KiB…1 MiB): кандидат не быстрее |
| sha3 | по размеру объекта | 1 000 объектов | gpu-alloc-per-call | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| sha3 | по размеру объекта | 1 000 объектов | gpu-pooled | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| sha3 | по размеру объекта | 10 000 объектов | gpu-alloc-per-call | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| sha3 | по размеру объекта | 10 000 объектов | gpu-pooled | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |

## Максимальный и минимальный speedup

| операция | кандидат | baseline | максимум (точка) | минимум (точка) |
|---|---|---|---|---|
| merkle_build | gpu-alloc-per-call | cpu | 2.17× (1 KiB × 10000) | 0.234× (1 KiB × 10) |
| merkle_build | gpu-pooled | cpu | 6.51× (64 KiB × 10000) | 0.269× (1 KiB × 10) |
| sha3 | gpu-alloc-per-call | cpu | 7.24× (1 KiB × 1000) | 0.0112× (1 KiB × 10) |
| sha3 | gpu-pooled | cpu | 7.75× (1 KiB × 10000) | 0.245× (1 KiB × 10) |

## Эффективная ширина H2D (sha3, merkle_build)

Байты входа / h2d_ms. Время h2d включает сборку staging-буфера на CPU, поэтому значения — нижняя оценка ширины PCIe; «крупные» — объём ≥ 16 MiB.

| операция | backend | GB/s, медиана по всем | GB/s, медиана по крупным | GB/s, максимум |
|---|---|---|---|---|
| merkle_build | gpu-alloc-per-call | 3.60 | 3.60 | 5.27 |
| merkle_build | gpu-pooled | 3.57 | 3.58 | 5.23 |
| sha3 | gpu-alloc-per-call | 3.58 | 3.58 | 5.39 |
| sha3 | gpu-pooled | 3.58 | 3.58 | 5.39 |

## Стабильность медиан между прогонами

Прогонов: 1. Для оценки стабильности нужно ≥ 2 полных прогона одной матрицы.

## Графики

- `plots/gpu_phases_merkle_build.png`
- `plots/gpu_phases_sha3.png`
- `plots/heatmap_merkle_build_gpu-alloc-per-call_vs_cpu.png`
- `plots/heatmap_merkle_build_gpu-pooled_vs_cpu.png`
- `plots/heatmap_sha3_gpu-alloc-per-call_vs_cpu.png`
- `plots/heatmap_sha3_gpu-pooled_vs_cpu.png`
- `plots/throughput_merkle_build.png`
- `plots/throughput_sha3.png`

