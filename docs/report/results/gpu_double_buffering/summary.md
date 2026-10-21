# Результаты benchmark'а

Файл сформирован `bench/analysis/analyze.py` из сырых CSV; числа не правились вручную. speedup = total(CPU) / total(кандидат) по медианам; total GPU включает аллокации, передачу данных и синхронизацию (§45, §48).

Входные файлы (1): `results_gpu_double_buffering.csv`

## Покрытие

| backend | измерено (строк) | пропущено (строк) |
|---|---|---|
| cpu-mt | 4 | 0 |
| gpu-double-buffer | 4 | 0 |
| gpu-single-buffer | 4 | 0 |

## Точки пересечения (speedup = 1)

Интерполяция линейная по log(speedup) от log(x) между соседними точками сетки. «Кандидат» — GPU-backend (kind = gpu) либо `cpu-mt` (kind = threads, против `cpu`).

### GPU против CPU

| операция | ось | фиксировано | кандидат | baseline | результат |
|---|---|---|---|---|---|
| sha3 | по числу (batch) | размер 4 KiB | gpu-double-buffer | cpu-mt | кандидат быстрее на всём диапазоне (20 000…50 000) |
| sha3 | по числу (batch) | размер 4 KiB | gpu-single-buffer | cpu-mt | кандидат быстрее на всём диапазоне (20 000…50 000) |
| sha3 | по числу (batch) | размер 64 KiB | gpu-double-buffer | cpu-mt | кандидат быстрее на всём диапазоне (20 000…50 000) |
| sha3 | по числу (batch) | размер 64 KiB | gpu-single-buffer | cpu-mt | нет пересечения в диапазоне (20 000…50 000): кандидат не быстрее |
| sha3 | по размеру объекта | 20 000 объектов | gpu-double-buffer | cpu-mt | кандидат быстрее на всём диапазоне (4 KiB…64 KiB) |
| sha3 | по размеру объекта | 20 000 объектов | gpu-single-buffer | cpu-mt | быстрее только до ≈ 18546 B (размер объекта), дальше медленнее |
| sha3 | по размеру объекта | 50 000 объектов | gpu-double-buffer | cpu-mt | кандидат быстрее на всём диапазоне (4 KiB…64 KiB) |
| sha3 | по размеру объекта | 50 000 объектов | gpu-single-buffer | cpu-mt | быстрее только до ≈ 22752 B (размер объекта), дальше медленнее |

## Максимальный и минимальный speedup

| операция | кандидат | baseline | максимум (точка) | минимум (точка) |
|---|---|---|---|---|
| sha3 | gpu-double-buffer | cpu-mt | 1.77× (4 KiB × 50000) | 1.31× (4 KiB × 20000) |
| sha3 | gpu-single-buffer | cpu-mt | 1.17× (4 KiB × 50000) | 0.893× (64 KiB × 20000) |

## Эффективная ширина H2D (sha3, merkle_build)

Байты входа / h2d_ms. Время h2d включает сборку staging-буфера на CPU, поэтому значения — нижняя оценка ширины PCIe; «крупные» — объём ≥ 16 MiB.

| операция | backend | GB/s, медиана по всем | GB/s, медиана по крупным | GB/s, максимум |
|---|---|---|---|---|
| sha3 | gpu-double-buffer | 3.17 | 3.17 | 3.43 |
| sha3 | gpu-single-buffer | 3.52 | 3.52 | 3.55 |

## Стабильность медиан между прогонами

Прогонов: 1. Для оценки стабильности нужно ≥ 2 полных прогона одной матрицы.

## Графики

- `plots/gpu_phases_sha3.png`
- `plots/heatmap_sha3_gpu-double-buffer_vs_cpu-mt.png`
- `plots/heatmap_sha3_gpu-single-buffer_vs_cpu-mt.png`
- `plots/throughput_sha3.png`

