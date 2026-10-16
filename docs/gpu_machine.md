# GPU-машина

На GPU-машину мы выходим **один раз** (модель — `docs/gpu_single_run.md`). Весь код к этому моменту написан и проверен на машине разработки, в том числе компилируется с CUDA и cuPQC. На GPU-машине только подготавливается окружение и запускается один скрипт.

## Требования (подготовить заранее, до прихода с кодом)

| Компонент | Версия |
|---|---|
| NVIDIA driver | поддерживающий выбранную версию CUDA |
| CUDA Toolkit | **та же major.minor**, с которой код собирался на машине разработки (записана в gate) |
| cuPQC SDK | **та же версия**; путь — `CUPQC_ROOT` |
| CMake | ≥ 3.22 |
| GCC | поддерживаемый этим nvcc как host compiler |
| OpenSSL | ≥ 3.0 + headers (`libssl-dev`) |
| Python | 3.10+, `pip install -r bench/analysis/requirements.txt` |
| RAM | ≥ 4 GiB свободной (пик полной матрицы — 1.6 GiB, см. `docs/gpu_single_run.md`) |

Сеть не нужна: зависимости FetchContent приносятся архивом (`scripts/vendor_deps.sh`).

## Запуск

```bash
CUPQC_ROOT=/opt/cupqc ./scripts/gpu_run_all.sh --time-budget 120
```

Перед уходом прочитать `RUN_SUMMARY.txt`. Унести `bench/results/<timestamp>_<host>.tar.gz`: там логи, CSV/JSON, результаты ctest, окружение и графики. Анализ делается дома (`docs/stages/07_experiments.md`, часть В).

## Ручные команды (только для отладки, если что-то пошло не так)

```bash
./scripts/check_gpu_env.sh
CUPQC_ROOT=/opt/cupqc ./scripts/build_gpu.sh
ctest --test-dir build/gpu -L gpu --output-on-failure
./scripts/run_bench.sh bench/configs/quick.json
```
