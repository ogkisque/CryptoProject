#!/usr/bin/env bash
# Снимок окружения машины перед сборкой/benchmark. Всё идёт в stdout; ошибки команд не прерывают скрипт.
set -uo pipefail
sec() { echo; echo "== $*"; }
sec "date";       date -u +%Y-%m-%dT%H:%M:%SZ; hostname
sec "git";        git -C "$(dirname "$0")/.." log -1 --format='%H %s' 2>&1; git -C "$(dirname "$0")/.." status --short 2>&1 | head -5
sec "nvidia-smi"; nvidia-smi --query-gpu=name,compute_cap,memory.total,driver_version,clocks.max.sm,power.limit --format=csv 2>&1 || echo "nvidia-smi недоступен"
sec "nvidia-smi -q"; nvidia-smi -q 2>&1 | head -150 || true
sec "nvcc";       nvcc --version 2>&1 | tail -3 || echo "nvcc не найден"
sec "cmake";      cmake --version | head -1
sec "compiler";   "${CXX:-g++}" --version | head -1
sec "openssl";    openssl version
sec "cuPQC";      if [ -n "${CUPQC_ROOT:-}" ]; then echo "CUPQC_ROOT=$CUPQC_ROOT"; ls "$CUPQC_ROOT" "$CUPQC_ROOT/include" "$CUPQC_ROOT/lib" 2>&1 | head -40; else echo "CUPQC_ROOT не задан"; fi
sec "python";     python3 --version 2>&1; python3 -c "import pandas, matplotlib; print('pandas', pandas.__version__, 'matplotlib', matplotlib.__version__)" 2>&1 | tail -1
sec "CPU";        lscpu 2>&1 | head -30; nproc
sec "governor";   gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a); echo "$gov"
[ "$gov" != "performance" ] && [ "$gov" != "n/a" ] && echo "ВНИМАНИЕ: governor = $gov; для замеров нужен performance (sudo cpupower frequency-set -g performance)"
sec "memory";     free -h
sec "disk";       df -h . 2>&1 | head -3
sec "load";       uptime
