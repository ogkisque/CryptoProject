#!/usr/bin/env bash
# Полный прогон benchmark на GPU-машине и анализ.
#   ./scripts/run_bench.sh [bench/configs/full.json]
set -euo pipefail
cd "$(dirname "$0")/.."
CONFIG="${1:-bench/configs/full.json}"
OUT="bench/results/$(date -u +%Y%m%dT%H%M%SZ)_$(hostname)"
mkdir -p "$OUT"
./scripts/check_gpu_env.sh > "$OUT/env.txt" 2>&1
./build/gpu/vault benchmark --config "$CONFIG" --csv "$OUT/results.csv" --json "$OUT/results.json"
python3 bench/analysis/analyze.py "$OUT/results.csv" --out "$OUT"
echo "Результаты: $OUT"
