#!/usr/bin/env bash
# Сборка, тесты, smoke vault, benchmark, анализ и архив — одним запуском (docs/gpu_workflow.md).
#
#   CUPQC_ROOT=/opt/cupqc-sdk ./scripts/gpu_run_all.sh --quick     # быстрый прогон (минуты + сборка)
#   ./scripts/gpu_run_all.sh                                       # полный: full.json + gpu_*.json
#   ./scripts/gpu_run_all.sh --runs 3                              # полный, 3 повтора full.json (оценка стабильности)
#
# Результат: bench/results/<время>_<хост>/ и одноимённый .tar.gz (архив собирается ВСЕГДА, даже после сбоев).
# Итог по шагам — RUN_SUMMARY.txt (ok / fail / skipped); сбой шага не останавливает следующие.
# Без nvcc (машина без CUDA) скрипт работает в CPU-режиме: собирает CPU-часть, GPU-шаги помечаются skipped.
#
# Тестовые хуки (для tests/test_run_all.py): SKIP_BUILD=1 — не собирать, использовать готовый BUILD_DIR;
# SKIP_CTEST=1 — не запускать ctest; RESULTS_ROOT=<каталог> — куда складывать результаты.
set -uo pipefail
# CUPQC_ROOT задаётся относительно каталога, ИЗ КОТОРОГО запущен скрипт: приводим к абсолютному пути до cd.
# (Первый запуск на GPU-машине: относительный CUPQC_ROOT после cd указывал в никуда, и сборка молча прошла без cuPQC.)
if [ -n "${CUPQC_ROOT:-}" ]; then CUPQC_ROOT="$(realpath -m -- "$CUPQC_ROOT")"; export CUPQC_ROOT; fi
cd "$(dirname "$0")/.."
ROOT="$PWD"

QUICK=0
RUNS=1
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) QUICK=1 ;;
    --runs) shift; RUNS="${1:-1}" ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 64 ;;
  esac
  shift
done
case "$RUNS" in ''|*[!0-9]*|0) echo "--runs должен быть положительным числом" >&2; exit 64 ;; esac

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="${STAMP}_$(hostname)"
RESULTS_ROOT="${RESULTS_ROOT:-$ROOT/bench/results}"
OUT="$RESULTS_ROOT/$NAME"
LOGS="$OUT/logs"
mkdir -p "$LOGS"
SUMMARY="$OUT/RUN_SUMMARY.txt"
START_TS=$SECONDS
FAILED=0
declare -a STEP_LINES=()

record() {  # имя статус [детали]
  local line
  line=$(printf '%-28s %-8s %s' "$1" "$2" "${3:-}")
  STEP_LINES+=("$line")
  echo ">>> $line"
  [ "$2" = "fail" ] && FAILED=1
  return 0
}

# run_step имя команда...: лог в logs/<имя>.log, статус в сводку; возвращает код команды
run_step() {
  local name="$1"; shift
  local t0=$SECONDS rc
  "$@" >"$LOGS/$name.log" 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then record "$name" ok "$((SECONDS - t0)) s"; else record "$name" fail "код $rc, $((SECONDS - t0)) s, см. logs/$name.log"; fi
  return $rc
}

finish() {
  local rc=$?
  set +e
  {
    echo "gpu_run_all.sh: $(date -u +%Y-%m-%dT%H:%M:%SZ)  хост $(hostname)  режим $([ $QUICK = 1 ] && echo quick || echo full)  runs=$RUNS"
    echo "коммит: $(git log -1 --format=%h 2>/dev/null)$(git diff --quiet 2>/dev/null || echo ' (+ незакоммиченные изменения)')"
    echo "режим сборки: ${BUILD_MODE:-не определён}   GPU-устройство: ${HAVE_GPU:-0}   cuPQC: ${HAVE_CUPQC:-0}"
    echo "время: $((SECONDS - START_TS)) s"
    echo
    printf '%-28s %-8s %s\n' "шаг" "статус" "детали"
    printf '%s\n' "${STEP_LINES[@]}"
  } >"$SUMMARY"
  # build.log в корне архива — первое, что нужно при сбое сборки
  cat "$LOGS"/build*.log >"$OUT/build.log" 2>/dev/null
  tar -czf "$RESULTS_ROOT/$NAME.tar.gz" -C "$RESULTS_ROOT" "$NAME" 2>/dev/null \
    && echo "архив: $RESULTS_ROOT/$NAME.tar.gz" || echo "не удалось создать архив" >&2
  echo; cat "$SUMMARY"
  exit $(( rc != 0 ? rc : FAILED ))
}
trap finish EXIT

# ---------------------------------------------------------------------------------------------- 0. окружение
CUPQC_ROOT="${CUPQC_ROOT:-}"
run_step 00_env bash -c "CUPQC_ROOT='$CUPQC_ROOT' ./scripts/check_gpu_env.sh | tee '$OUT/env.txt'"
{ nvidia-smi -q >"$OUT/nvidia-smi-q.txt" 2>&1; lscpu >"$OUT/lscpu.txt" 2>&1; free -h >"$OUT/free.txt" 2>&1; } || true

HAVE_NVCC=0; command -v nvcc >/dev/null 2>&1 && HAVE_NVCC=1
HAVE_GPU=0; nvidia-smi -L >/dev/null 2>&1 && HAVE_GPU=1
if [ -n "$CUPQC_ROOT" ] && [ ! -d "$CUPQC_ROOT" ]; then
  record 00a_cupqc_root fail "CUPQC_ROOT=$CUPQC_ROOT не существует: GPU ML-KEM/ML-DSA не соберутся"
fi
# Архитектура по умолчанию — с самого устройства (compute_cap 8.9 -> 89): ТЗ называет RTX 3050 (86), но на
# GPU-машине может стоять другая карта (первый запуск: RTX 4060, SM 89). VAULT_CUDA_ARCH из окружения важнее.
if [ -z "${VAULT_CUDA_ARCH:-}" ] && [ "$HAVE_GPU" = 1 ]; then
  VAULT_CUDA_ARCH="$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -1 | tr -d ' .')"
fi
VAULT_CUDA_ARCH="${VAULT_CUDA_ARCH:-86}"
HAVE_CUPQC=0
BUILD_MODE="cpu"
BUILD_DIR="${BUILD_DIR:-}"

# ---------------------------------------------------------------------------------------------- 1. сборка
build_in() {  # каталог аргументы-cmake...
  local dir="$1"; shift
  cmake -S . -B "$dir" -DCMAKE_BUILD_TYPE=Release "$@" && cmake --build "$dir" -j"$(nproc)"
}

if [ "${SKIP_BUILD:-0}" = 1 ]; then
  BUILD_DIR="${BUILD_DIR:-build/cpu}"
  [ "$HAVE_NVCC" = 1 ] && [ "$HAVE_GPU" = 1 ] && BUILD_MODE="cuda (готовая сборка)"
  record 01_build skipped "SKIP_BUILD=1, используется $BUILD_DIR"
elif [ "$HAVE_NVCC" = 1 ]; then
  # Каскад: CUDA + cuPQC -> CUDA без cuPQC -> только CPU. Любой сбой всё равно даёт данные и build.log.
  built=0
  if [ -n "$CUPQC_ROOT" ]; then
    if run_step 01_build_cuda_cupqc build_in build/gpu -DVAULT_ENABLE_CUDA=ON -DVAULT_CUDA_ARCH="$VAULT_CUDA_ARCH" -DCUPQC_ROOT="$CUPQC_ROOT" -DVAULT_CUDA_PTXAS_VERBOSE=ON; then
      built=1; BUILD_DIR=build/gpu; BUILD_MODE="cuda + cuPQC"; HAVE_CUPQC=1
    elif [ "$VAULT_CUDA_ARCH" != native ]; then
      # Самый вероятный сбой с cuPQC — device-link с LTO (ревью этапа 6). Официальные примеры NVIDIA собираются с
      # -arch=native: пробуем так, прежде чем отказываться от cuPQC (лог первой попытки остаётся в архиве).
      if run_step 01_build_cuda_cupqc_native build_in build/gpu_native -DVAULT_ENABLE_CUDA=ON -DVAULT_CUDA_ARCH=native -DCUPQC_ROOT="$CUPQC_ROOT" -DVAULT_CUDA_PTXAS_VERBOSE=ON; then
        built=1; BUILD_DIR=build/gpu_native; BUILD_MODE="cuda + cuPQC (-arch=native)"; HAVE_CUPQC=1
      fi
    fi
  else
    record 01_build_cuda_cupqc skipped "CUPQC_ROOT не задан"
  fi
  if [ $built = 0 ]; then
    if run_step 01_build_cuda_nopqc build_in build/gpu_nopqc -DVAULT_ENABLE_CUDA=ON -DVAULT_CUDA_ARCH="$VAULT_CUDA_ARCH" -DCUPQC_ROOT= -DVAULT_CUDA_PTXAS_VERBOSE=ON; then
      built=1; BUILD_DIR=build/gpu_nopqc; BUILD_MODE="cuda без cuPQC"
    fi
  else
    record 01_build_cuda_nopqc skipped "не нужна: сборка с cuPQC прошла"
  fi
  if [ $built = 0 ]; then
    if run_step 01_build_cpu_fallback build_in build/cpu -DVAULT_ENABLE_CUDA=OFF; then
      built=1; BUILD_DIR=build/cpu; BUILD_MODE="cpu (CUDA-сборка не удалась)"
    fi
  fi
  [ $built = 0 ] && { BUILD_DIR=""; BUILD_MODE="сборка не удалась"; }
  # Успешная сборка ещё не значит, что cuPQC подключён: CMake при ненайденном SDK собирает заглушки.
  # Истину сообщает маркер VAULT_CUPQC=ON|OFF из cmake/Cuda.cmake.
  if [ "$HAVE_CUPQC" = 1 ]; then
    if grep -q "VAULT_CUPQC=ON" "$LOGS"/01_build_cuda_cupqc*.log 2>/dev/null; then
      record 01b_cupqc ok "cuPQC подключён (VAULT_CUPQC=ON)"
    else
      HAVE_CUPQC=0
      BUILD_MODE="cuda без cuPQC (CMake не нашёл SDK)"
      record 01b_cupqc fail "CUPQC_ROOT=$CUPQC_ROOT, но CMake не нашёл cuPQC: GPU ML-KEM/ML-DSA не измерены; см. 'cuPQC не найден' в build.log"
    fi
  fi
else
  BUILD_DIR=build/cpu
  run_step 01_build_cpu build_in build/cpu -DVAULT_ENABLE_CUDA=OFF && BUILD_MODE="cpu (nvcc не найден)" || { BUILD_DIR=""; BUILD_MODE="сборка не удалась"; }
fi

case "$BUILD_DIR" in /*) BUILD_ABS="$BUILD_DIR" ;; *) BUILD_ABS="$ROOT/$BUILD_DIR" ;; esac
VAULT="$BUILD_ABS/vault"
if [ -z "$BUILD_DIR" ] || [ ! -x "$VAULT" ]; then
  for s in 02_ctest 03_smoke_vault 04_bench_quick 05_bench_full 06_analyze; do record "$s" skipped "нет собранного vault"; done
  exit 1
fi
# GPU реально используем, только если CUDA вошла в сборку и есть устройство
USE_GPU=0
case "$BUILD_MODE" in cuda*) [ "$HAVE_GPU" = 1 ] && USE_GPU=1 ;; esac
[ "$USE_GPU" = 0 ] && echo "GPU-режим выключен (сборка: $BUILD_MODE, устройство: $HAVE_GPU)"

# Флаги для воспроизводимости: замеры только в Release и без -march=native (§49, docs/gpu_workflow.md).
# Тип сборки проверяется явно: флаги CMAKE_CXX_FLAGS_RELEASE лежат в кэше и у Debug-сборки.
BUILD_TYPE="$(grep -E '^CMAKE_BUILD_TYPE:' "$BUILD_DIR/CMakeCache.txt" 2>/dev/null | cut -d= -f2)"
if grep -qE 'CMAKE_CXX_FLAGS[^=]*=.*-march=native' "$BUILD_DIR/CMakeCache.txt" 2>/dev/null; then
  record 01a_flags fail "в CMAKE_CXX_FLAGS стоит -march=native: результаты не воспроизводимы на другой машине"
elif [ "$BUILD_TYPE" != Release ]; then
  record 01a_flags fail "тип сборки '${BUILD_TYPE:-не задан}', а не Release: замеры не годятся для отчёта"
else
  record 01a_flags ok "Release: $(grep -E '^CMAKE_CXX_FLAGS_RELEASE:' "$BUILD_DIR/CMakeCache.txt" 2>/dev/null | cut -d= -f2)"
fi
# Регистры/spill'ы kernel'ов (ptxas -v) отдельным файлом — главный риск производительности
[ -f "$LOGS/01_build_cuda_cupqc.log" ] || [ -f "$LOGS/01_build_cuda_nopqc.log" ] && \
  grep -hE "ptxas info|Used [0-9]+ registers|spill" "$LOGS"/01_build_cuda_*.log >"$OUT/ptxas_kernels.txt" 2>/dev/null

# ---------------------------------------------------------------------------------------------- 2. ctest
if [ "${SKIP_CTEST:-0}" = 1 ]; then
  record 02_ctest skipped "SKIP_CTEST=1"
else
  run_step 02_ctest ctest --test-dir "$BUILD_DIR" --output-on-failure --timeout 900 -j"$(nproc)" --output-junit "$OUT/ctest.xml"
  # GPU-тесты отдельно и подробно: строки [cuPQC] ... (режим context string и т.п.) нужны для журнала этапа 6
  if [ "$USE_GPU" = 1 ]; then
    run_step 02a_ctest_gpu ctest --test-dir "$BUILD_DIR" -L gpu -V --timeout 900
    grep -hE "^\[cuPQC\]|ASSUMPTION|RecordProperty|entropy_layout|mldsa_context_mode" "$LOGS/02a_ctest_gpu.log" >"$OUT/cupqc_report.txt" 2>/dev/null
  else
    record 02a_ctest_gpu skipped "нет GPU"
  fi
fi

# ---------------------------------------------------------------------------------------------- 3. smoke vault
smoke() {
  local backend="$1" other="$2" d
  d="$(mktemp -d)"
  trap 'rm -rf "$d"' RETURN
  local V=("$VAULT" --vault "$d/v" --trusted "$d/t")
  head -c 300000 /dev/urandom >"$d/in.bin"
  set -e
  "${V[@]}" --backend "$backend" init
  id=$("${V[@]}" --backend "$backend" add "$d/in.bin" | head -1 | cut -c1-32)
  "${V[@]}" --backend "$backend" list
  "${V[@]}" --backend "$backend" verify
  "${V[@]}" --backend "$backend" extract "$id" -o "$d/out.bin"
  cmp "$d/in.bin" "$d/out.bin"
  # кросс-открытие: хранилище, созданное одним backend'ом, читает и дополняет другой
  "${V[@]}" --backend "$other" verify
  "${V[@]}" --backend "$other" add "$d/in.bin" >/dev/null
  "${V[@]}" --backend "$backend" verify
  # порча подписи -> код 2 на обоих. Байт инвертируется (а не затирается константой): запись 0x00 поверх
  # байта, который уже равен 0, не меняла бы подпись, и шаг падал бы ложно примерно в 1 из 256 запусков.
  sig=$(ls "$d"/v/generations/*/manifest.sig | tail -1)
  b=$(od -An -tu1 -j100 -N1 "$sig" | tr -d ' ')
  printf "$(printf '\\%03o' $(( b ^ 255 )))" | dd of="$sig" bs=1 seek=100 conv=notrunc 2>/dev/null
  set +e
  "${V[@]}" --backend "$backend" verify; [ $? -eq 2 ]
  local r1=$?
  "${V[@]}" --backend "$other" verify; [ $? -eq 2 ]
  local r2=$?
  return $((r1 + r2))
}
run_step 03a_smoke_cpu bash -c "$(declare -f smoke); VAULT='$VAULT'; smoke cpu cpu-mt"
if [ "$USE_GPU" = 1 ]; then
  run_step 03b_smoke_gpu bash -c "$(declare -f smoke); VAULT='$VAULT'; smoke gpu cpu"
  run_step 03c_smoke_gpu_to_cpu bash -c "$(declare -f smoke); VAULT='$VAULT'; smoke cpu gpu"
else
  record 03b_smoke_gpu skipped "нет GPU"
  record 03c_smoke_gpu_to_cpu skipped "нет GPU"
fi

# ---------------------------------------------------------------------------------------------- 4. benchmark
bench() {  # имя конфиг -> results_<имя>.csv/json
  "$VAULT" benchmark --config "$2" --csv "$OUT/results_$1.csv" --json "$OUT/results_$1.json"
}
gpu_clocks() { nvidia-smi --query-gpu=timestamp,clocks.sm,clocks.max.sm,temperature.gpu,power.draw,pstate --format=csv 2>&1; }

run_step 04_bench_quick bench quick bench/configs/quick.json
CSV_QUICK="$OUT/results_quick.csv"

ANALYZE_CSVS=()
if [ $QUICK = 1 ]; then
  record 05_bench_full skipped "--quick"
  record 05a_bench_gpu_series skipped "--quick"
  [ -f "$CSV_QUICK" ] && ANALYZE_CSVS=("$CSV_QUICK")
else
  [ "$USE_GPU" = 1 ] && gpu_clocks >"$OUT/gpu_clocks_before.txt"
  for i in $(seq 1 "$RUNS"); do
    if run_step "05_bench_full_run$i" bench "full_run$i" bench/configs/full.json; then ANALYZE_CSVS+=("$OUT/results_full_run$i.csv"); fi
  done
  [ "$USE_GPU" = 1 ] && gpu_clocks >"$OUT/gpu_clocks_after.txt"
  if [ "$USE_GPU" = 1 ]; then
    for cfg in bench/configs/gpu_*.json; do
      n="$(basename "$cfg" .json)"
      run_step "05a_bench_$n" bench "$n" "$cfg"
    done
  else
    record 05a_bench_gpu_series skipped "нет GPU"
  fi
fi

# ---------------------------------------------------------------------------------------------- 6. анализ
# Python: .venv проекта, если есть (системные pandas и pip-numpy бывают бинарно несовместимы — первый запуск
# на GPU-машине: "numpy.dtype size changed"), иначе python3.
PY=python3
[ -x "$ROOT/.venv/bin/python" ] && PY="$ROOT/.venv/bin/python"
if [ ${#ANALYZE_CSVS[@]} -gt 0 ] && ! "$PY" -W ignore -c "import pandas, matplotlib" >"$LOGS/06_python_check.log" 2>&1; then
  record 06_analyze fail "$PY не импортирует pandas/matplotlib (см. logs/06_python_check.log); исправить: python3 -m venv .venv && .venv/bin/pip install -r bench/analysis/requirements.txt. Сырые CSV в архиве"
elif [ ${#ANALYZE_CSVS[@]} -gt 0 ]; then
  run_step 06_analyze "$PY" -W ignore bench/analysis/analyze.py "${ANALYZE_CSVS[@]}" --out "$OUT/analysis"
  for csv in "$OUT"/results_gpu_*.csv; do
    [ -f "$csv" ] || continue
    n="$(basename "$csv" .csv)"
    run_step "06a_analyze_${n#results_}" "$PY" -W ignore bench/analysis/analyze.py "$csv" --out "$OUT/analysis_${n#results_}"
  done
else
  record 06_analyze skipped "нет CSV с результатами"
fi
