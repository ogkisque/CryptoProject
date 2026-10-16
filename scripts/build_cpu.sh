#!/usr/bin/env bash
# CPU-сборка (локальная машина, без GPU).
# Зависимости: cmake >= 3.22, g++ >= 12, libssl-dev (OpenSSL >= 3.0), git (для FetchContent).
set -euo pipefail
cd "$(dirname "$0")/.."
BUILD_TYPE="${BUILD_TYPE:-Release}"
cmake -S . -B build/cpu -DCMAKE_BUILD_TYPE="$BUILD_TYPE" -DVAULT_ENABLE_CUDA=OFF "$@"
cmake --build build/cpu -j"$(nproc)"
if [ -f build/cpu/CTestTestfile.cmake ]; then
  ctest --test-dir build/cpu --output-on-failure
fi
