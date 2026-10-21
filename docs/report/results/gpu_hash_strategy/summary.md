# Результаты benchmark'а

Файл сформирован `bench/analysis/analyze.py` из сырых CSV; числа не правились вручную. speedup = total(CPU) / total(кандидат) по медианам; total GPU включает аллокации, передачу данных и синхронизацию (§45, §48).

Входные файлы (1): `results_gpu_hash_strategy.csv`

## Покрытие

| backend | измерено (строк) | пропущено (строк) |
|---|---|---|
| cpu-mt | 13 | 3 |
| gpu-thread-per-object | 13 | 3 |
| gpu-warp-per-object | 13 | 3 |

Причины пропусков:

| backend | причина | строк |
|---|---|---|
| cpu-mt | exceeds max_total_bytes | 3 |
| gpu-thread-per-object | exceeds max_total_bytes | 3 |
| gpu-warp-per-object | exceeds max_total_bytes | 3 |

## Точки пересечения (speedup = 1)

Интерполяция линейная по log(speedup) от log(x) между соседними точками сетки. «Кандидат» — GPU-backend (kind = gpu) либо `cpu-mt` (kind = threads, против `cpu`).

### GPU против CPU

| операция | ось | фиксировано | кандидат | baseline | результат |
|---|---|---|---|---|---|
| sha3 | по числу (batch) | размер 1 KiB | gpu-thread-per-object | cpu-mt | быстрее начиная с ≈ 406 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 1 KiB | gpu-warp-per-object | cpu-mt | быстрее начиная с ≈ 323 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 64 KiB | gpu-thread-per-object | cpu-mt | быстрее начиная с ≈ 2 876 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 64 KiB | gpu-warp-per-object | cpu-mt | нет пересечения в диапазоне (10…10 000): кандидат не быстрее |
| sha3 | по числу (batch) | размер 1 MiB | gpu-thread-per-object | cpu-mt | нет пересечения в диапазоне (10…1 000): кандидат не быстрее |
| sha3 | по числу (batch) | размер 1 MiB | gpu-warp-per-object | cpu-mt | нет пересечения в диапазоне (10…1 000): кандидат не быстрее |
| sha3 | по числу (batch) | размер 16 MiB | gpu-thread-per-object | cpu-mt | нет пересечения в диапазоне (10…100): кандидат не быстрее |
| sha3 | по числу (batch) | размер 16 MiB | gpu-warp-per-object | cpu-mt | нет пересечения в диапазоне (10…100): кандидат не быстрее |
| sha3 | по размеру объекта | 10 объектов | gpu-thread-per-object | cpu-mt | нет пересечения в диапазоне (1 KiB…16 MiB): кандидат не быстрее |
| sha3 | по размеру объекта | 10 объектов | gpu-warp-per-object | cpu-mt | нет пересечения в диапазоне (1 KiB…16 MiB): кандидат не быстрее |
| sha3 | по размеру объекта | 100 объектов | gpu-thread-per-object | cpu-mt | нет пересечения в диапазоне (1 KiB…16 MiB): кандидат не быстрее |
| sha3 | по размеру объекта | 100 объектов | gpu-warp-per-object | cpu-mt | нет пересечения в диапазоне (1 KiB…16 MiB): кандидат не быстрее |
| sha3 | по размеру объекта | 1 000 объектов | gpu-thread-per-object | cpu-mt | быстрее только до ≈ 37116 B (размер объекта), дальше медленнее |
| sha3 | по размеру объекта | 1 000 объектов | gpu-warp-per-object | cpu-mt | быстрее только до ≈ 5947 B (размер объекта), дальше медленнее |
| sha3 | по размеру объекта | 10 000 объектов | gpu-thread-per-object | cpu-mt | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| sha3 | по размеру объекта | 10 000 объектов | gpu-warp-per-object | cpu-mt | быстрее только до ≈ 2057 B (размер объекта), дальше медленнее |

## Максимальный и минимальный speedup

| операция | кандидат | baseline | максимум (точка) | минимум (точка) |
|---|---|---|---|---|
| sha3 | gpu-thread-per-object | cpu-mt | 1.5× (1 KiB × 1000) | 0.066× (16 MiB × 10) |
| sha3 | gpu-warp-per-object | cpu-mt | 1.21× (1 KiB × 1000) | 0.106× (16 MiB × 10) |

## Эффективная ширина H2D (sha3, merkle_build)

Байты входа / h2d_ms. Время h2d включает сборку staging-буфера на CPU, поэтому значения — нижняя оценка ширины PCIe; «крупные» — объём ≥ 16 MiB.

| операция | backend | GB/s, медиана по всем | GB/s, медиана по крупным | GB/s, максимум |
|---|---|---|---|---|
| sha3 | gpu-thread-per-object | 3.55 | 3.57 | 5.30 |
| sha3 | gpu-warp-per-object | 3.60 | 3.59 | 5.34 |

## Стабильность медиан между прогонами

Прогонов: 1. Для оценки стабильности нужно ≥ 2 полных прогона одной матрицы.

## Графики

- `plots/gpu_phases_sha3.png`
- `plots/heatmap_sha3_gpu-thread-per-object_vs_cpu-mt.png`
- `plots/heatmap_sha3_gpu-warp-per-object_vs_cpu-mt.png`
- `plots/throughput_sha3.png`

