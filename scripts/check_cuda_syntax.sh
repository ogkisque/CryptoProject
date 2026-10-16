#!/usr/bin/env bash
# Синтаксическая проверка cuda/src/*.cu без CUDA Toolkit: clang + заглушки из tools/fakecuda.
#   ./scripts/check_cuda_syntax.sh [файл.cu ...]
# Код возврата 0 — ошибок нет (кроме известной помехи <chrono>), 1 — есть ошибки, 2 — нет clang.
set -uo pipefail
cd "$(dirname "$0")/.."
CLANG="${CLANG:-clang++}"
command -v "$CLANG" >/dev/null || { echo "clang++ не найден: проверка пропущена" >&2; exit 2; }

FAKE=tools/fakecuda
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/nvvm/libdevice" && echo "CUDA Version 12.0.0" > "$TMP/version.txt" && touch "$TMP/nvvm/libdevice/libdevice.10.bc"

FILES=("$@")
[ ${#FILES[@]} -eq 0 ] && FILES=(cuda/src/*.cu)
rc=0
for f in "${FILES[@]}"; do
  for mode in host device; do
    out="$("$CLANG" -x cuda --cuda-path="$TMP" --cuda-gpu-arch=sm_86 --cuda-$mode-only -nocudainc -nocudalib \
        -std=c++20 -fsyntax-only -Wno-unknown-cuda-version -D__CUDACC__ -include "$FAKE/cuda_macros.h" \
        -Icuda -Iinclude -I"$FAKE" -DVAULT_HAS_CUDA=1 "$f" 2>&1)"
    # clang 14 + libstdc++ 13: <chrono> не собирается (не наш код) — отфильтровать
    real="$(echo "$out" | grep -E "error:" | grep -v "chrono:2360\|hh_mm_ss" || true)"
    if [ -n "$real" ]; then
      echo "== $f ($mode): ОШИБКИ"; echo "$out" | grep -E "error:|warning:" -A3 | grep -v "chrono:2360\|hh_mm_ss"; rc=1
    else
      echo "== $f ($mode): ok"
    fi
  done
done
exit $rc
