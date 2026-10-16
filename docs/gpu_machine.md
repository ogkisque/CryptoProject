# GPU-машина

GPU-код пишется на машине разработки без CUDA и здесь не компилируется (модель — `docs/gpu_workflow.md`). Сборка и запуск — на GPU-машине: сначала `--quick`, присылаем результат, после исправлений — полный прогон.

## Требования

| Компонент | Версия |
|---|---|
| NVIDIA driver | поддерживающий выбранную версию CUDA |
| CUDA Toolkit | ≥ 12.0 (версия, на которую рассчитан код, — в журнале этапа 5) |
| cuPQC SDK | путь — `CUPQC_ROOT` (без него соберётся только SHA3/Merkle на GPU) |
| CMake | ≥ 3.22 |
| GCC | поддерживаемый этим nvcc как host compiler |
| OpenSSL | ≥ 3.0 + headers (`libssl-dev`) |
| Python | 3.10+, `pip install -r bench/analysis/requirements.txt` |
| RAM | ≥ 4 GiB свободной (пик полной матрицы — 1.6 GiB) |

Нужен доступ в интернет: liboqs, CLI11, GoogleTest и nlohmann/json тянутся через FetchContent при первой сборке.

## Запуск

```bash
CUPQC_ROOT=/opt/cupqc ./scripts/gpu_run_all.sh --quick   # сборка, тесты, smoke, quick-benchmark
CUPQC_ROOT=/opt/cupqc ./scripts/gpu_run_all.sh           # полный прогон, когда --quick зелёный
```

Прислать `RUN_SUMMARY.txt` и `bench/results/<timestamp>_<host>.tar.gz` (там логи, результаты ctest, окружение, CSV/JSON, графики). Если не собралось — `build.log` из архива.

## Ручные команды (для отладки)

```bash
./scripts/check_gpu_env.sh
CUPQC_ROOT=/opt/cupqc ./scripts/build_gpu.sh
ctest --test-dir build/gpu -L gpu --output-on-failure
./scripts/run_bench.sh bench/configs/quick.json
```
