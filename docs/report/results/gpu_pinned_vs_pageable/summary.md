# Результаты benchmark'а

Файл сформирован `bench/analysis/analyze.py` из сырых CSV; числа не правились вручную. speedup = total(CPU) / total(кандидат) по медианам; total GPU включает аллокации, передачу данных и синхронизацию (§45, §48).

Входные файлы (1): `results_gpu_pinned_vs_pageable.csv`

## Покрытие

| backend | измерено (строк) | пропущено (строк) |
|---|---|---|
| cpu | 16 | 2 |
| cpu-mt | 16 | 2 |
| gpu-pageable | 16 | 2 |
| gpu-pinned | 16 | 2 |

Причины пропусков:

| backend | причина | строк |
|---|---|---|
| cpu | exceeds max_total_bytes | 2 |
| cpu-mt | exceeds max_total_bytes | 2 |
| gpu-pageable | exceeds max_total_bytes | 2 |
| gpu-pinned | exceeds max_total_bytes | 2 |

## Точки пересечения (speedup = 1)

Интерполяция линейная по log(speedup) от log(x) между соседними точками сетки. «Кандидат» — GPU-backend (kind = gpu) либо `cpu-mt` (kind = threads, против `cpu`).

### GPU против CPU

| операция | ось | фиксировано | кандидат | baseline | результат |
|---|---|---|---|---|---|
| merkle_build | по числу (batch) | размер 1 KiB | gpu-pageable | cpu | кандидат быстрее на всём диапазоне (100…10 000) |
| merkle_build | по числу (batch) | размер 1 KiB | gpu-pageable | cpu-mt | быстрее начиная с ≈ 3 001 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 1 KiB | gpu-pinned | cpu | кандидат быстрее на всём диапазоне (100…10 000) |
| merkle_build | по числу (batch) | размер 1 KiB | gpu-pinned | cpu-mt | быстрее начиная с ≈ 2 864 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 64 KiB | gpu-pageable | cpu | кандидат быстрее на всём диапазоне (100…10 000) |
| merkle_build | по числу (batch) | размер 64 KiB | gpu-pageable | cpu-mt | быстрее начиная с ≈ 5 171 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 64 KiB | gpu-pinned | cpu | кандидат быстрее на всём диапазоне (100…10 000) |
| merkle_build | по числу (batch) | размер 64 KiB | gpu-pinned | cpu-mt | быстрее начиная с ≈ 4 185 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 1 MiB | gpu-pageable | cpu | кандидат быстрее на всём диапазоне (100…1 000) |
| merkle_build | по числу (batch) | размер 1 MiB | gpu-pageable | cpu-mt | нет пересечения в диапазоне (100…1 000): кандидат не быстрее |
| merkle_build | по числу (batch) | размер 1 MiB | gpu-pinned | cpu | кандидат быстрее на всём диапазоне (100…1 000) |
| merkle_build | по числу (batch) | размер 1 MiB | gpu-pinned | cpu-mt | нет пересечения в диапазоне (100…1 000): кандидат не быстрее |
| merkle_build | по размеру объекта | 100 объектов | gpu-pageable | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| merkle_build | по размеру объекта | 100 объектов | gpu-pageable | cpu-mt | нет пересечения в диапазоне (1 KiB…1 MiB): кандидат не быстрее |
| merkle_build | по размеру объекта | 100 объектов | gpu-pinned | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| merkle_build | по размеру объекта | 100 объектов | gpu-pinned | cpu-mt | нет пересечения в диапазоне (1 KiB…1 MiB): кандидат не быстрее |
| merkle_build | по размеру объекта | 1 000 объектов | gpu-pageable | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| merkle_build | по размеру объекта | 1 000 объектов | gpu-pageable | cpu-mt | нет пересечения в диапазоне (1 KiB…1 MiB): кандидат не быстрее |
| merkle_build | по размеру объекта | 1 000 объектов | gpu-pinned | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| merkle_build | по размеру объекта | 1 000 объектов | gpu-pinned | cpu-mt | нет пересечения в диапазоне (1 KiB…1 MiB): кандидат не быстрее |
| merkle_build | по размеру объекта | 10 000 объектов | gpu-pageable | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| merkle_build | по размеру объекта | 10 000 объектов | gpu-pageable | cpu-mt | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| merkle_build | по размеру объекта | 10 000 объектов | gpu-pinned | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| merkle_build | по размеру объекта | 10 000 объектов | gpu-pinned | cpu-mt | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| sha3 | по числу (batch) | размер 1 KiB | gpu-pageable | cpu | кандидат быстрее на всём диапазоне (100…10 000) |
| sha3 | по числу (batch) | размер 1 KiB | gpu-pageable | cpu-mt | быстрее начиная с ≈ 494 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 1 KiB | gpu-pinned | cpu | кандидат быстрее на всём диапазоне (100…10 000) |
| sha3 | по числу (batch) | размер 1 KiB | gpu-pinned | cpu-mt | быстрее начиная с ≈ 399 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 64 KiB | gpu-pageable | cpu | кандидат быстрее на всём диапазоне (100…10 000) |
| sha3 | по числу (batch) | размер 64 KiB | gpu-pageable | cpu-mt | быстрее начиная с ≈ 5 644 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 64 KiB | gpu-pinned | cpu | кандидат быстрее на всём диапазоне (100…10 000) |
| sha3 | по числу (batch) | размер 64 KiB | gpu-pinned | cpu-mt | быстрее начиная с ≈ 3 958 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 1 MiB | gpu-pageable | cpu | кандидат быстрее на всём диапазоне (100…1 000) |
| sha3 | по числу (batch) | размер 1 MiB | gpu-pageable | cpu-mt | нет пересечения в диапазоне (100…1 000): кандидат не быстрее |
| sha3 | по числу (batch) | размер 1 MiB | gpu-pinned | cpu | кандидат быстрее на всём диапазоне (100…1 000) |
| sha3 | по числу (batch) | размер 1 MiB | gpu-pinned | cpu-mt | нет пересечения в диапазоне (100…1 000): кандидат не быстрее |
| sha3 | по размеру объекта | 100 объектов | gpu-pageable | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| sha3 | по размеру объекта | 100 объектов | gpu-pageable | cpu-mt | нет пересечения в диапазоне (1 KiB…1 MiB): кандидат не быстрее |
| sha3 | по размеру объекта | 100 объектов | gpu-pinned | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| sha3 | по размеру объекта | 100 объектов | gpu-pinned | cpu-mt | нет пересечения в диапазоне (1 KiB…1 MiB): кандидат не быстрее |
| sha3 | по размеру объекта | 1 000 объектов | gpu-pageable | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| sha3 | по размеру объекта | 1 000 объектов | gpu-pageable | cpu-mt | быстрее только до ≈ 18983 B (размер объекта), дальше медленнее |
| sha3 | по размеру объекта | 1 000 объектов | gpu-pinned | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| sha3 | по размеру объекта | 1 000 объектов | gpu-pinned | cpu-mt | быстрее только до ≈ 25533 B (размер объекта), дальше медленнее |
| sha3 | по размеру объекта | 10 000 объектов | gpu-pageable | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| sha3 | по размеру объекта | 10 000 объектов | gpu-pageable | cpu-mt | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| sha3 | по размеру объекта | 10 000 объектов | gpu-pinned | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| sha3 | по размеру объекта | 10 000 объектов | gpu-pinned | cpu-mt | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |

### cpu-mt против cpu

| операция | ось | фиксировано | кандидат | baseline | результат |
|---|---|---|---|---|---|
| merkle_build | по числу (batch) | размер 1 KiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (100…10 000) |
| merkle_build | по числу (batch) | размер 64 KiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (100…10 000) |
| merkle_build | по числу (batch) | размер 1 MiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (100…1 000) |
| merkle_build | по размеру объекта | 100 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| merkle_build | по размеру объекта | 1 000 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| merkle_build | по размеру объекта | 10 000 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| sha3 | по числу (batch) | размер 1 KiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (100…10 000) |
| sha3 | по числу (batch) | размер 64 KiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (100…10 000) |
| sha3 | по числу (batch) | размер 1 MiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (100…1 000) |
| sha3 | по размеру объекта | 100 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| sha3 | по размеру объекта | 1 000 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| sha3 | по размеру объекта | 10 000 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |

## Максимальный и минимальный speedup

| операция | кандидат | baseline | максимум (точка) | минимум (точка) |
|---|---|---|---|---|
| merkle_build | cpu-mt | cpu | 6.01× (1 MiB × 1000) | 1.96× (1 KiB × 100) |
| merkle_build | gpu-pageable | cpu | 6.38× (64 KiB × 10000) | 1.01× (1 KiB × 100) |
| merkle_build | gpu-pageable | cpu-mt | 1.65× (1 KiB × 10000) | 0.33× (1 MiB × 100) |
| merkle_build | gpu-pinned | cpu | 6.54× (64 KiB × 10000) | 1.02× (1 KiB × 100) |
| merkle_build | gpu-pinned | cpu-mt | 1.68× (1 KiB × 10000) | 0.336× (1 MiB × 100) |
| sha3 | cpu-mt | cpu | 6.05× (64 KiB × 1000) | 3.24× (1 KiB × 100) |
| sha3 | gpu-pageable | cpu | 6.96× (1 KiB × 10000) | 1.67× (1 KiB × 100) |
| sha3 | gpu-pageable | cpu-mt | 1.34× (1 KiB × 1000) | 0.328× (1 MiB × 100) |
| sha3 | gpu-pinned | cpu | 7.81× (1 KiB × 10000) | 1.76× (1 KiB × 100) |
| sha3 | gpu-pinned | cpu-mt | 1.5× (1 KiB × 1000) | 0.333× (1 MiB × 100) |

## Эффективная ширина H2D (sha3, merkle_build)

Байты входа / h2d_ms. Время h2d включает сборку staging-буфера на CPU, поэтому значения — нижняя оценка ширины PCIe; «крупные» — объём ≥ 16 MiB.

| операция | backend | GB/s, медиана по всем | GB/s, медиана по крупным | GB/s, максимум |
|---|---|---|---|---|
| merkle_build | gpu-pageable | 3.46 | 3.46 | 4.61 |
| merkle_build | gpu-pinned | 3.57 | 3.57 | 5.26 |
| sha3 | gpu-pageable | 3.36 | 3.44 | 4.33 |
| sha3 | gpu-pinned | 3.57 | 3.55 | 5.36 |

## Стабильность медиан между прогонами

Прогонов: 1. Для оценки стабильности нужно ≥ 2 полных прогона одной матрицы.

## Графики

- `plots/gpu_phases_merkle_build.png`
- `plots/gpu_phases_sha3.png`
- `plots/heatmap_merkle_build_gpu-pageable_vs_cpu-mt.png`
- `plots/heatmap_merkle_build_gpu-pageable_vs_cpu.png`
- `plots/heatmap_merkle_build_gpu-pinned_vs_cpu-mt.png`
- `plots/heatmap_merkle_build_gpu-pinned_vs_cpu.png`
- `plots/heatmap_sha3_gpu-pageable_vs_cpu-mt.png`
- `plots/heatmap_sha3_gpu-pageable_vs_cpu.png`
- `plots/heatmap_sha3_gpu-pinned_vs_cpu-mt.png`
- `plots/heatmap_sha3_gpu-pinned_vs_cpu.png`
- `plots/throughput_merkle_build.png`
- `plots/throughput_sha3.png`

