# Работа с GPU-частью

**Решение (2026-10-16, пересмотрено):** CUDA Toolkit на машине разработки **не ставится**, сборка GPU-кода здесь не проверяется. GPU-код этапов 5–6 пишется «вслепую». Автор проекта собирает и запускает его на GPU-машине, когда удобно, и присылает результат: ошибки сборки, упавшие тесты, логи или архив с замерами. По ним код правится, цикл повторяется. Запусков может быть несколько, но цель — обойтись **минимумом заходов**: код должен быть максимально готов, а ошибки — максимально информативны.

## Что проверяется здесь (без CUDA)

Всё, что может скомпилировать обычный g++:

| Что | Как |
|---|---|
| Логика kernel'ов | Keccak-f[1600], sponge SHA3-256 с domain-префиксом, шаг уровня Merkle и шаг proof пишутся как функции с макросом `VAULT_HD` в `cuda/kernels/*.cuh`: под nvcc это `__host__ __device__`, под g++ — пусто. Эти же заголовки подключаются в `tests/unit/kernel_host_test.cpp` и проверяются на CPU против OpenSSL и reference Merkle. На GPU исполняется тот же исходный код |
| Host-часть GPU-backend'ов | Упаковка `PackedBatch`, порционирование по VRAM, расчёт grid/block, разбиение batch'а PQC — обычный C++ без CUDA API (`cuda/host/`), с юнит-тестами |
| Анализ результатов | `bench/analysis/analyze.py` тестируется на реальных CPU-данных и на синтетическом CSV с gpu-строками |
| Синтаксис `.cu` | `scripts/check_cuda_syntax.sh`: clang с заглушками `tools/fakecuda/` (host- и device-проход) ловит опечатки и вызовы host-функций из device-кода, но это не nvcc |
| Сценарий запуска | `scripts/gpu_run_all.sh` прогоняется здесь в CPU-режиме: GPU-шаги дают «skipped», архив собирается |

**Не проверяется здесь:** файлы `.cu`, вызовы CUDA runtime и cuPQC, `cmake/Cuda.cmake`. Это первое, что может сломаться при сборке на GPU-машине. API cuPQC берётся из публичной документации NVIDIA; места, где документация неоднозначна, помечаются в коде `// UNVERIFIED(cuPQC): ...` и перечисляются в журнале этапа 6, чтобы при ошибке было сразу видно, куда смотреть.

## cuPQC (этап 6): что нужно на GPU-машине

CUDA Toolkit и nvcc **≥ 12.8** (требование cuPQC-PK; SHA3/Merkle собираются и с CUDA ≥ 12.0), cuPQC SDK (`CUPQC_ROOT` — каталог SDK с `include/cupqc`, `include`, `lib/libcupqc-pk.a`, `cmake/`). Если CUDA старше 12.8 или SDK не найден, `Cuda.cmake` отключает только GPU ML-KEM/ML-DSA, а SHA3/Merkle остаются. Три предположения о cuPQC определяются прогоном (режим context string ML-DSA — калибровка, раскладка entropy — ACVP-тесты, `-dlto`/архитектура — сборка); результат смотреть в `RUN_SUMMARY`, выводе `ctest -L gpu` (`[cuPQC] ...`) и свойствах тестов — они описаны в `docs/stages/06_gpu_pqc.md`.

## Как сделать, чтобы заходов на GPU было меньше

1. **Ошибки говорят сами за себя.** Каждый вызов CUDA и cuPQC обёрнут в `CUDA_CHECK(expr)`: в исключении будут выражение, файл:строка и `cudaGetErrorString`. Тесты эквивалентности печатают первый несовпавший элемент (индекс, длину входа, оба хеша).
2. **GPU-backend'ы независимы.** Ошибка в ML-DSA на GPU не должна мешать SHA3/Merkle. Если cuPQC не найден, CMake собирает GPU-backend без PQC (`VAULT_HAS_CUPQC` не определён → `make_gpu_kem_backend`/`make_gpu_sig_backend` дают `BackendUnavailable`).
3. **Сначала быстрый прогон.** `gpu_run_all.sh --quick`: сборка, `ctest`, smoke vault и `quick.json` — за минуты. Полную матрицу имеет смысл гонять, только когда быстрый прогон зелёный.
4. **Всё в один архив.** Скрипт складывает лог сборки, вывод ctest (JUnit XML), окружение (`nvidia-smi -q`, версии CUDA и cuPQC, `lscpu`, `free`), CSV/JSON и графики в `bench/results/<ts>_<host>.tar.gz`. Достаточно прислать архив или, если сломалась сборка, `build.log`.

## `scripts/gpu_run_all.sh`

```bash
CUPQC_ROOT=/opt/cupqc-sdk ./scripts/gpu_run_all.sh --quick    # сборка, ctest, smoke, quick.json, анализ
./scripts/gpu_run_all.sh                                      # полный: full.json и gpu_*.json
./scripts/gpu_run_all.sh --runs 3                             # полный с 3 повторами full.json (оценка стабильности)
```

| Шаг | Что делает | Если не получилось |
|---|---|---|
| `00_env` | `check_gpu_env.sh`: nvidia-smi (в т.ч. `-q`), nvcc, cmake, компилятор, cuPQC, python/pandas, lscpu, governor, free, df | — |
| `01_build_*` | Каскад: **CUDA + cuPQC** (`build/gpu`, нужен `CUPQC_ROOT`) → **CUDA + cuPQC с `-arch=native`** (`build/gpu_native`, как в примерах NVIDIA — на случай сбоя device-link с LTO) → **CUDA без cuPQC** (`build/gpu_nopqc`) → **только CPU** (`build/cpu`). Без `nvcc` сразу CPU-режим | следующий вариант каскада; в сводке видно, какая сборка использована; весь вывод — в `build.log` в корне архива |
| `01a_flags` | сборка должна быть `Release`, и `-march=native` в флагах запрещён (воспроизводимость) | `fail` |
| `02_ctest`, `02a_ctest_gpu` | весь `ctest` (JUnit — `ctest.xml`), затем `-L gpu -V`; строки `[cuPQC] ...` → `cupqc_report.txt` | шаг `fail`, дальше идёт |
| `03a/b/c_smoke_*` | `init/add/list/verify/extract`, кросс-открытие хранилищ cpu↔cpu-mt и (при GPU) gpu↔cpu в обе стороны, порча подписи → код 2 на обоих backend'ах | `fail`/`skipped` (нет GPU) |
| `04_bench_quick` | `bench/configs/quick.json` → `results_quick.csv/json` | `fail`, анализ без CSV пропускается |
| `05_bench_full_runN` | *(без `--quick`)* `full.json`, N раз; `nvidia-smi` clocks/temperature/power до и после | `fail` |
| `05a_bench_gpu_*` | серии `gpu_*.json` (pinned/pageable, alloc, double buffering, стратегия SHA3) | `skipped` без GPU |
| `06_analyze`, `06a_*` | `analyze.py` по всем full-прогонам (или quick) и отдельно по каждой серии `gpu_*` | `skipped` без CSV |

Сбой шага пишется в `RUN_SUMMARY.txt` (`ok`/`fail`/`skipped`) и **не останавливает** следующие. Архив
`bench/results/<время>_<хост>.tar.gz` собирается всегда (`trap EXIT`), даже после сбоя сборки; код возврата ненулевой, если
был хоть один `fail`. В архиве: `RUN_SUMMARY.txt`, `build.log`, `env.txt`, `ptxas_kernels.txt` (регистры и spill'ы kernel'ов,
если сборка была с CUDA), `cupqc_report.txt`, `gpu_clocks_*.txt`, `results_*.csv/json`, `logs/<шаг>.log`, `analysis*/`.
Backend, не прошедший эквивалентность CPU==GPU, исключается из benchmark'а: benchmark сам сверяет каждый результат с reference
и не даст «быстрых» неверных данных (ревью этапа 4).

**CPU-режим** (без nvcc): собирается CPU-часть, все GPU-шаги `skipped`, архив и анализ формируются — так сценарий
проверялся на машине разработки (`bench/analysis/test_run_all.py`).

## Стенд и воспроизводимость

* Release-флаги проекта: `-O3 -DNDEBUG` для C++ и стандартные `-O3` для CUDA, **без `-march=native`** (с ним бинарник привязан к
  CPU сборочной машины). CMake предупреждает о `-march=native`, а `gpu_run_all.sh` помечает шаг `01a_flags` как `fail`.
* Флаги, версии, коммит (с `-dirty`), число потоков cpu-mt и параметры конфига пишутся в `results.json` и в начало `summary.md`.
* Перед замерами: governor `performance`, отсутствие фоновой нагрузки, один пользователь GPU; `env.txt` показывает governor и
  нагрузку, `gpu_clocks_before/after.txt` — частоты, температуру и мощность до и после полного прогона.
* Первый CUDA-вызов создаёт контекст (≈ 100+ мс): он уходит в warm-up (`GpuContext` создаётся при создании backend'а), в замеры не попадает.

## Анализ результатов

`bench/analysis/analyze.py run1.csv [run2.csv ...] --out DIR` (зависимости — `bench/analysis/requirements.txt`; сообщения
`numexpr/bottleneck ... _ARRAY_API` от системных пакетов при импорте pandas безвредны). Выход: `summary.md`, `speedup.csv`,
`crossover.csv`, `transfer_bw.csv`, `plots/*.png`. speedup считается против `cpu` и против `cpu-mt`; точки пересечения —
по числу объектов, по размеру объекта и по batch, с интерполяцией в log-шкале и явными результатами «GPU быстрее везде» /
«нет пересечения в диапазоне». Несколько прогонов → медианы и разброс между прогонами. Тесты: `python3 -m pytest bench/analysis`
(или `ctest -L analysis`).

## Время и ресурсы

Замер на машине разработки (12 потоков): полная матрица `full.json` для `cpu` и `cpu-mt` — **10 мин 34 с**, пиковая RSS **1.6 GiB** (самая большая точка — 16 MiB × 100). На GPU-машине с GPU-точками полный прогон займёт ориентировочно 20–40 минут, `--quick` — несколько минут плюс сборка. Свободной RAM нужно ≥ 4 GiB.

## Порядок работы

1. Здесь: этапы 5, 6 и часть А этапа 7 — код, host-тесты, анализ, скрипт. Всё, что собирается g++, зелёное.
2. На GPU: `CUPQC_ROOT=... ./scripts/gpu_run_all.sh --quick` → прислать результат.
3. Здесь: исправления по присланному. Повторять п. 2, пока быстрый прогон не станет зелёным.
4. На GPU: `./scripts/gpu_run_all.sh` (полный) → прислать архив.
5. Здесь: анализ и выводы (этап 7, часть В).
