#!/usr/bin/env bash
# Диагностика окружения GPU-машины перед сборкой/benchmark.
set -uo pipefail
echo "== nvidia-smi";  nvidia-smi --query-gpu=name,compute_cap,memory.total,driver_version --format=csv 2>&1 || echo "nvidia-smi недоступен"
echo "== nvcc";        nvcc --version 2>&1 | tail -2 || echo "nvcc не найден"
echo "== cmake";       cmake --version | head -1
echo "== compiler";    "${CXX:-g++}" --version | head -1
echo "== openssl";     openssl version
echo "== cuPQC";       if [ -n "${CUPQC_ROOT:-}" ]; then ls "$CUPQC_ROOT" "$CUPQC_ROOT/include" 2>&1 | head -20; else echo "CUPQC_ROOT не задан"; fi
echo "== CPU";         grep -m1 'model name' /proc/cpuinfo; nproc
echo "== governor";    cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "n/a"
