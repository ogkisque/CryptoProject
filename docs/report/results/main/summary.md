# Результаты benchmark'а

Файл сформирован `bench/analysis/analyze.py` из сырых CSV; числа не правились вручную. speedup = total(CPU) / total(кандидат) по медианам; total GPU включает аллокации, передачу данных и синхронизацию (§45, §48).

Входные файлы (2): `results_full_run1.csv`, `results_full_run2.csv`

**Окружение:** 2026-10-21T20:40:36Z, baikalai-agl-ada-dev-c54620ab
- CPU: AMD Ryzen 5 PRO 4650G with Radeon Graphics
- ОС: Linux 6.8.0-71-generic x86_64
- GPU: NVIDIA GeForce RTX 4060
- Архитектура GPU: sm_89
- VRAM: 7803 MiB
- CUDA runtime: 12090
- Драйвер CUDA: 12090
- OpenSSL: OpenSSL 3.0.13 30 Jan 2024
- liboqs: 0.16.0
- Компилятор: 11.5.0
- Тип сборки: Release
- Коммит: 192e2f3a9374
- Флаги: `-O3 -DNDEBUG`
- Конфиг: warmup 3, прогонов 10, потоков cpu-mt 12, alloc в total: True, ctx ML-DSA: manifest

## Покрытие

| backend | измерено (строк) | пропущено (строк) |
|---|---|---|
| cpu | 146 | 24 |
| cpu-mt | 146 | 24 |
| gpu | 126 | 44 |

Причины пропусков:

| backend | причина | строк |
|---|---|---|
| cpu | exceeds max_total_bytes | 24 |
| cpu-mt | exceeds max_total_bytes | 24 |
| gpu | exceeds max_total_bytes | 24 |
| gpu | not supported by backend: gpu ML-DSA: this cuPQC build signs only with an empty context string (use the cpu backend for the vault manifest context) | 20 |

## Точки пересечения (speedup = 1)

Интерполяция линейная по log(speedup) от log(x) между соседними точками сетки. «Кандидат» — GPU-backend (kind = gpu) либо `cpu-mt` (kind = threads, против `cpu`).

### GPU против CPU

| операция | ось | фиксировано | кандидат | baseline | результат |
|---|---|---|---|---|---|
| merkle_build | по числу (batch) | размер 1 KiB | gpu | cpu | быстрее начиная с ≈ 2 076 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 1 KiB | gpu | cpu-mt | нет пересечения в диапазоне (10…100 000): кандидат не быстрее |
| merkle_build | по числу (batch) | размер 4 KiB | gpu | cpu | быстрее начиная с ≈ 1 231 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 4 KiB | gpu | cpu-mt | нет пересечения в диапазоне (10…100 000): кандидат не быстрее |
| merkle_build | по числу (batch) | размер 64 KiB | gpu | cpu | быстрее начиная с ≈ 230 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 64 KiB | gpu | cpu-mt | нет пересечения в диапазоне (10…10 000): кандидат не быстрее |
| merkle_build | по числу (batch) | размер 1 MiB | gpu | cpu | быстрее начиная с ≈ 104 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 1 MiB | gpu | cpu-mt | нет пересечения в диапазоне (10…1 000): кандидат не быстрее |
| merkle_build | по числу (batch) | размер 16 MiB | gpu | cpu | нет пересечения в диапазоне (10…100): кандидат не быстрее |
| merkle_build | по числу (batch) | размер 16 MiB | gpu | cpu-mt | нет пересечения в диапазоне (10…100): кандидат не быстрее |
| merkle_build | по размеру объекта | 10 объектов | gpu | cpu | нет пересечения в диапазоне (1 KiB…16 MiB): кандидат не быстрее |
| merkle_build | по размеру объекта | 10 объектов | gpu | cpu-mt | нет пересечения в диапазоне (1 KiB…16 MiB): кандидат не быстрее |
| merkle_build | по размеру объекта | 100 объектов | gpu | cpu | нет пересечения в диапазоне (1 KiB…16 MiB): кандидат не быстрее |
| merkle_build | по размеру объекта | 100 объектов | gpu | cpu-mt | нет пересечения в диапазоне (1 KiB…16 MiB): кандидат не быстрее |
| merkle_build | по размеру объекта | 1 000 объектов | gpu | cpu | быстрее начиная с ≈ 5705 B (размер объекта) |
| merkle_build | по размеру объекта | 1 000 объектов | gpu | cpu-mt | нет пересечения в диапазоне (1 KiB…1 MiB): кандидат не быстрее |
| merkle_build | по размеру объекта | 10 000 объектов | gpu | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| merkle_build | по размеру объекта | 10 000 объектов | gpu | cpu-mt | нет пересечения в диапазоне (1 KiB…64 KiB): кандидат не быстрее |
| merkle_build | по размеру объекта | 100 000 объектов | gpu | cpu | кандидат быстрее на всём диапазоне (1 KiB…4 KiB) |
| merkle_build | по размеру объекта | 100 000 объектов | gpu | cpu-mt | нет пересечения в диапазоне (1 KiB…4 KiB): кандидат не быстрее |
| merkle_verify | по числу (batch) | — | gpu | cpu | быстрее начиная с ≈ 59 (число объектов/листьев/batch) |
| merkle_verify | по числу (batch) | — | gpu | cpu-mt | быстрее начиная с ≈ 133 (число объектов/листьев/batch) |
| mldsa_keygen | по числу (batch) | — | gpu | cpu | быстрее начиная с ≈ 24 (число объектов/листьев/batch) |
| mldsa_keygen | по числу (batch) | — | gpu | cpu-mt | быстрее начиная с ≈ 273 (число объектов/листьев/batch) |
| mlkem_decaps | по числу (batch) | — | gpu | cpu | быстрее начиная с ≈ 51 (число объектов/листьев/batch) |
| mlkem_decaps | по числу (batch) | — | gpu | cpu-mt | быстрее начиная с ≈ 797 (число объектов/листьев/batch) |
| mlkem_encaps | по числу (batch) | — | gpu | cpu | быстрее начиная с ≈ 61 (число объектов/листьев/batch) |
| mlkem_encaps | по числу (batch) | — | gpu | cpu-mt | быстрее начиная с ≈ 952 (число объектов/листьев/batch) |
| mlkem_keygen | по числу (batch) | — | gpu | cpu | быстрее начиная с ≈ 69 (число объектов/листьев/batch) |
| mlkem_keygen | по числу (batch) | — | gpu | cpu-mt | быстрее начиная с ≈ 1 991 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 1 KiB | gpu | cpu | быстрее начиная с ≈ 1 073 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 1 KiB | gpu | cpu-mt | нет пересечения в диапазоне (10…100 000): кандидат не быстрее |
| sha3 | по числу (batch) | размер 4 KiB | gpu | cpu | быстрее начиная с ≈ 854 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 4 KiB | gpu | cpu-mt | нет пересечения в диапазоне (10…100 000): кандидат не быстрее |
| sha3 | по числу (batch) | размер 64 KiB | gpu | cpu | быстрее начиная с ≈ 211 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 64 KiB | gpu | cpu-mt | нет пересечения в диапазоне (10…10 000): кандидат не быстрее |
| sha3 | по числу (batch) | размер 1 MiB | gpu | cpu | быстрее начиная с ≈ 100 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 1 MiB | gpu | cpu-mt | нет пересечения в диапазоне (10…1 000): кандидат не быстрее |
| sha3 | по числу (batch) | размер 16 MiB | gpu | cpu | нет пересечения в диапазоне (10…100): кандидат не быстрее |
| sha3 | по числу (batch) | размер 16 MiB | gpu | cpu-mt | нет пересечения в диапазоне (10…100): кандидат не быстрее |
| sha3 | по размеру объекта | 10 объектов | gpu | cpu | нет пересечения в диапазоне (1 KiB…16 MiB): кандидат не быстрее |
| sha3 | по размеру объекта | 10 объектов | gpu | cpu-mt | нет пересечения в диапазоне (1 KiB…16 MiB): кандидат не быстрее |
| sha3 | по размеру объекта | 100 объектов | gpu | cpu | неоднозначно (несколько смен знака), первое пересечение ≈ 1024186 B |
| sha3 | по размеру объекта | 100 объектов | gpu | cpu-mt | нет пересечения в диапазоне (1 KiB…16 MiB): кандидат не быстрее |
| sha3 | по размеру объекта | 1 000 объектов | gpu | cpu | быстрее начиная с ≈ 1288 B (размер объекта) |
| sha3 | по размеру объекта | 1 000 объектов | gpu | cpu-mt | нет пересечения в диапазоне (1 KiB…1 MiB): кандидат не быстрее |
| sha3 | по размеру объекта | 10 000 объектов | gpu | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| sha3 | по размеру объекта | 10 000 объектов | gpu | cpu-mt | нет пересечения в диапазоне (1 KiB…64 KiB): кандидат не быстрее |
| sha3 | по размеру объекта | 100 000 объектов | gpu | cpu | кандидат быстрее на всём диапазоне (1 KiB…4 KiB) |
| sha3 | по размеру объекта | 100 000 объектов | gpu | cpu-mt | нет пересечения в диапазоне (1 KiB…4 KiB): кандидат не быстрее |

### cpu-mt против cpu

| операция | ось | фиксировано | кандидат | baseline | результат |
|---|---|---|---|---|---|
| merkle_build | по числу (batch) | размер 1 KiB | cpu-mt | cpu | быстрее начиная с ≈ 13 (число объектов/листьев/batch) |
| merkle_build | по числу (batch) | размер 4 KiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (10…100 000) |
| merkle_build | по числу (batch) | размер 64 KiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (10…10 000) |
| merkle_build | по числу (batch) | размер 1 MiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (10…1 000) |
| merkle_build | по числу (batch) | размер 16 MiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (10…100) |
| merkle_build | по размеру объекта | 10 объектов | cpu-mt | cpu | быстрее начиная с ≈ 1216 B (размер объекта) |
| merkle_build | по размеру объекта | 100 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…16 MiB) |
| merkle_build | по размеру объекта | 1 000 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| merkle_build | по размеру объекта | 10 000 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| merkle_build | по размеру объекта | 100 000 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…4 KiB) |
| merkle_verify | по числу (batch) | — | cpu-mt | cpu | быстрее начиная с ≈ 14 (число объектов/листьев/batch) |
| mldsa_keygen | по числу (batch) | — | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1…10 000) |
| mldsa_sign | по числу (batch) | размер 168 B | cpu-mt | cpu | быстрее начиная с ≈ 1 (число объектов/листьев/batch) |
| mldsa_verify | по числу (batch) | размер 168 B | cpu-mt | cpu | быстрее начиная с ≈ 1 (число объектов/листьев/batch) |
| mlkem_decaps | по числу (batch) | — | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1…10 000) |
| mlkem_encaps | по числу (batch) | — | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1…10 000) |
| mlkem_keygen | по числу (batch) | — | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1…10 000) |
| sha3 | по числу (batch) | размер 1 KiB | cpu-mt | cpu | быстрее начиная с ≈ 10 (число объектов/листьев/batch) |
| sha3 | по числу (batch) | размер 4 KiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (10…100 000) |
| sha3 | по числу (batch) | размер 64 KiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (10…10 000) |
| sha3 | по числу (batch) | размер 1 MiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (10…1 000) |
| sha3 | по числу (batch) | размер 16 MiB | cpu-mt | cpu | кандидат быстрее на всём диапазоне (10…100) |
| sha3 | по размеру объекта | 10 объектов | cpu-mt | cpu | быстрее начиная с ≈ 1060 B (размер объекта) |
| sha3 | по размеру объекта | 100 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…16 MiB) |
| sha3 | по размеру объекта | 1 000 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…1 MiB) |
| sha3 | по размеру объекта | 10 000 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…64 KiB) |
| sha3 | по размеру объекта | 100 000 объектов | cpu-mt | cpu | кандидат быстрее на всём диапазоне (1 KiB…4 KiB) |

## Максимальный и минимальный speedup

| операция | кандидат | baseline | максимум (точка) | минимум (точка) |
|---|---|---|---|---|
| merkle_build | cpu-mt | cpu | 6.05× (1 MiB × 1000) | 0.921× (1 KiB × 10) |
| merkle_build | gpu | cpu | 2.4× (1 KiB × 100000) | 0.0149× (1 KiB × 10) |
| merkle_build | gpu | cpu-mt | 0.545× (1 KiB × 100000) | 0.0162× (1 KiB × 10) |
| merkle_verify | cpu-mt | cpu | 3× (1000) | 0.866× (10) |
| merkle_verify | gpu | cpu | 33.4× (10000) | 0.118× (10) |
| merkle_verify | gpu | cpu-mt | 11.2× (10000) | 0.136× (10) |
| mldsa_keygen | cpu-mt | cpu | 6.22× (1000) | 1× (1) |
| mldsa_keygen | gpu | cpu | 11.7× (10000) | 0.0447× (1) |
| mldsa_keygen | gpu | cpu-mt | 2.05× (10000) | 0.0446× (1) |
| mldsa_sign | cpu-mt | cpu | 6.95× (168 B × 10000) | 0.944× (168 B × 1) |
| mldsa_verify | cpu-mt | cpu | 7.02× (168 B × 10000) | 1× (168 B × 1) |
| mlkem_decaps | cpu-mt | cpu | 7.63× (10000) | 1× (1) |
| mlkem_decaps | gpu | cpu | 14.2× (10000) | 0.0209× (1) |
| mlkem_decaps | gpu | cpu-mt | 1.87× (10000) | 0.0209× (1) |
| mlkem_encaps | cpu-mt | cpu | 7.42× (10000) | 1× (1) |
| mlkem_encaps | gpu | cpu | 13.4× (10000) | 0.0172× (1) |
| mlkem_encaps | gpu | cpu-mt | 1.8× (10000) | 0.0172× (1) |
| mlkem_keygen | cpu-mt | cpu | 6.5× (1000) | 1× (1) |
| mlkem_keygen | gpu | cpu | 9.06× (10000) | 0.0168× (1) |
| mlkem_keygen | gpu | cpu-mt | 1.46× (10000) | 0.0167× (1) |
| sha3 | cpu-mt | cpu | 6.16× (64 KiB × 10000) | 0.983× (1 KiB × 10) |
| sha3 | gpu | cpu | 1.97× (1 KiB × 100000) | 0.0112× (1 KiB × 10) |
| sha3 | gpu | cpu-mt | 0.365× (1 KiB × 100000) | 0.0114× (1 KiB × 10) |

## Эффективная ширина H2D (sha3, merkle_build)

Байты входа / h2d_ms. Время h2d включает сборку staging-буфера на CPU, поэтому значения — нижняя оценка ширины PCIe; «крупные» — объём ≥ 16 MiB.

| операция | backend | GB/s, медиана по всем | GB/s, медиана по крупным | GB/s, максимум |
|---|---|---|---|---|
| merkle_build | gpu | 3.57 | 3.59 | 4.38 |
| sha3 | gpu | 3.57 | 3.59 | 4.38 |

## Стабильность медиан между прогонами

Прогонов: 2; точек, измеренных не менее чем в двух прогонах: 209 из 209. Разброс = (max − min) / медиана медиан total.

| статистика | значение |
|---|---|
| медиана разброса | 0.8 % |
| 90-й процентиль | 5.0 % |
| максимум | 24.1 % |
| точек с разбросом > 10 % | 10 (5 %) |

Самые нестабильные точки:

| операция | backend | размер | число | разброс |
|---|---|---|---|---|
| mldsa_keygen | gpu | — | 10000 | 24.1 % |
| merkle_verify | cpu-mt | — | 10000 | 22.1 % |
| merkle_verify | cpu-mt | — | 1000 | 22.1 % |
| merkle_verify | cpu-mt | — | 100000 | 21.9 % |
| mldsa_sign | cpu | 168 B | 1 | 21.5 % |
| mldsa_sign | cpu-mt | 168 B | 1 | 13.3 % |
| mldsa_verify | cpu-mt | 168 B | 1000 | 13.2 % |
| sha3 | cpu-mt | 1 KiB | 10 | 12.9 % |
| merkle_build | cpu-mt | 4 KiB | 10 | 10.2 % |
| merkle_build | cpu-mt | 1 KiB | 10000 | 10.1 % |

## Графики

- `plots/gpu_phases_merkle_build.png`
- `plots/gpu_phases_merkle_verify.png`
- `plots/gpu_phases_mldsa_keygen.png`
- `plots/gpu_phases_mlkem_decaps.png`
- `plots/gpu_phases_mlkem_encaps.png`
- `plots/gpu_phases_mlkem_keygen.png`
- `plots/gpu_phases_sha3.png`
- `plots/heatmap_merkle_build_gpu_vs_cpu-mt.png`
- `plots/heatmap_merkle_build_gpu_vs_cpu.png`
- `plots/heatmap_sha3_gpu_vs_cpu-mt.png`
- `plots/heatmap_sha3_gpu_vs_cpu.png`
- `plots/ops_per_sec_merkle_verify.png`
- `plots/ops_per_sec_pqc.png`
- `plots/throughput_merkle_build.png`
- `plots/throughput_sha3.png`

