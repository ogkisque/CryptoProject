#!/usr/bin/env bash
# GPU-сборка (машина с RTX 3050 / SM 86, CUDA Toolkit >= 12, cuPQC SDK).
#   CUPQC_ROOT=/opt/cupqc ./scripts/build_gpu.sh
set -euo pipefail
cd "$(dirname "$0")/.."
: "${CUPQC_ROOT:?укажите CUPQC_ROOT — путь к cuPQC SDK}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
cmake -S . -B build/gpu -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
  -DVAULT_ENABLE_CUDA=ON -DVAULT_CUDA_ARCH=86 -DCUPQC_ROOT="$CUPQC_ROOT" "$@"
cmake --build build/gpu -j"$(nproc)"
if [ -f build/gpu/CTestTestfile.cmake ]; then
  ctest --test-dir build/gpu --output-on-failure
fi
