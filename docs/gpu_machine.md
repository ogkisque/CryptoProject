# Работа на GPU-машине

Машина разработки (без GPU) собирает и тестирует только CPU-часть. Всё, что связано с CUDA/cuPQC, собирается и запускается на отдельной машине с NVIDIA RTX 3050 (SM 86).

## Требования

| Компонент | Версия |
|---|---|
| NVIDIA driver | совместимый с CUDA 12.x |
| CUDA Toolkit | ≥ 12.0 (`nvcc`) |
| cuPQC SDK | последняя доступная; путь задаётся в `CUPQC_ROOT` |
| CMake | ≥ 3.22 |
| GCC | ≥ 12, поддерживаемый установленным nvcc как host compiler |
| OpenSSL | ≥ 3.0 + headers (`libssl-dev`) |
| Python | 3.10+, `pip install -r bench/analysis/requirements.txt` |

## Перенос кода

Через git (предпочтительно) или `rsync -a --exclude build ./ gpu-host:~/crypto/`.

## Сборка и проверка

```bash
./scripts/check_gpu_env.sh                 # драйвер, nvcc, compute_cap 8.6, cuPQC
CUPQC_ROOT=/opt/cupqc ./scripts/build_gpu.sh   # сборка + ctest (включая tests/gpu)
ctest --test-dir build/gpu -L gpu --output-on-failure
```

## Benchmark

```bash
./scripts/run_bench.sh bench/configs/quick.json   # smoke
./scripts/run_bench.sh bench/configs/full.json    # полная матрица (долго)
```
Результаты попадают в `bench/results/<timestamp>_<host>/`. Эту папку затем копируют обратно (или коммитят только `summary.md` и графики).

## Что записать в журнал этапа после первого запуска

- модель GPU, объём VRAM, драйвер, CUDA, версия cuPQC;
- реальные имена CMake-целей и заголовков cuPQC (поправить `cmake/Cuda.cmake`);
- ответы на вопросы из `docs/stages/06_gpu_pqc.md` §6.0.
