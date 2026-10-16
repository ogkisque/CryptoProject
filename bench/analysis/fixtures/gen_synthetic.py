#!/usr/bin/env python3
"""Синтетические результаты benchmark'а со строками GPU — для тестов анализа (на CPU-машине настоящих GPU-данных нет).

Время GPU задаётся как CPU_total / speedup(x), где speedup(x) — кривая сценария, поэтому точка пересечения известна
аналитически: для кривой s(x) = x / x_cross log-интерполяция в analyze.py восстанавливает x_cross точно.
Формат строк — тот же, что у `vault benchmark` (столбцы write_csv).

  gen_synthetic.py [--scenario normal] [--runs 1] [--seed 0] > synthetic.csv
"""
from __future__ import annotations

import argparse
import math
import random
import sys

import pandas as pd

COLUMNS = ["op", "backend", "object_size", "count", "skipped", "skip_reason", "n", "total_mean_ms", "total_median_ms",
           "total_min_ms", "total_max_ms", "total_stddev_ms", "kernel_median_ms", "alloc_median_ms", "h2d_median_ms",
           "d2h_median_ms", "sync_median_ms", "entropy_median_ms", "kernel_mean_ms", "alloc_mean_ms", "h2d_mean_ms",
           "d2h_mean_ms", "sync_mean_ms", "entropy_mean_ms", "throughput_gbps", "ops_per_sec", "latency_ms"]

SIZES = [1024, 4096, 65536, 1048576, 16777216]
COUNTS = [10, 100, 1000, 10000, 100000]
BATCHES = [1, 10, 100, 1000, 10000]
HASH_OPS = ["sha3", "merkle_build"]
PQC_OPS = ["mlkem_keygen", "mlkem_encaps", "mlkem_decaps", "mldsa_keygen", "mldsa_sign", "mldsa_verify"]
X_CROSS = 1000.0  # точка пересечения кривой «crossover» по числу объектов/листьев/batch
X_CROSS_BYTES = 4.0e6  # ... и по общему объёму для sha3/merkle_build по размеру объекта


def cpu_ms(op: str, size: int, count: int) -> float:
    if op in HASH_OPS:
        return 0.002 + size * count / 0.5e9 * 1e3  # ~0.5 GB/s на один поток
    if op == "merkle_verify":
        return 0.001 + count * 0.0009
    per = {"mlkem_keygen": 0.013, "mlkem_encaps": 0.011, "mlkem_decaps": 0.0125, "mldsa_keygen": 0.044, "mldsa_sign": 0.085, "mldsa_verify": 0.047}[op]
    return per * count


def cpu_mt_ms(op: str, size: int, count: int) -> float:
    return cpu_ms(op, size, count) / max(1.0, min(8.0, count / 2)) + 0.03


def curve(scenario: str, op: str, size: int, count: int) -> float:
    """speedup GPU относительно cpu."""
    x = size * count if op in HASH_OPS else count
    xc = X_CROSS_BYTES if op in HASH_OPS else X_CROSS
    if scenario == "gpu_faster":
        return 4.0
    if scenario == "gpu_slower":
        return 0.2
    if scenario == "crossover":
        return x / xc  # < 1 слева, > 1 справа от xc
    if scenario == "crossover_above_range":
        return 0.5 * x / 1e12  # GPU так и не обгоняет CPU в диапазоне
    if scenario == "crossover_below_range":
        return 2.0 + x / 1e6  # GPU быстрее уже на минимальной точке
    if scenario == "nonmonotone":
        return 2.0 if (count in (100, 1000, 10)) else 0.4  # быстрее на середине, медленнее на краях
    return (x / xc) ** 0.9 * 1.2  # normal: пересечение чуть левее xc


def build(scenario: str = "normal", runs: int = 1, seed: int = 0, gpu_labels=("gpu",), failed_gpu: bool = False,
          skip_big: bool = True, legacy: bool = False, noise: float = 0.03) -> list[pd.DataFrame]:
    rnd = random.Random(seed)
    frames = []
    for run in range(runs):
        rows = []
        points = []
        for op in HASH_OPS:
            points += [(op, s, c) for s in SIZES for c in COUNTS]
        points += [("merkle_verify", 0, c) for c in COUNTS]
        for op in PQC_OPS:
            size = 168 if op == "mldsa_sign" or op == "mldsa_verify" else 0
            points += [(op, size, b) for b in BATCHES]
        for op, size, count in points:
            big = op in HASH_OPS and size * count > 4 * 2**30
            for backend in ("cpu", "cpu-mt") + tuple(gpu_labels):
                gpu = backend.startswith("gpu")
                skip_reason = ""
                if big and skip_big:
                    skip_reason = "exceeds max_total_bytes"
                elif gpu and failed_gpu:
                    skip_reason = "backend unavailable: gpu backend: not compiled in (build with VAULT_ENABLE_CUDA=ON)"
                elif gpu and op in PQC_OPS and op.startswith("mldsa") and scenario == "no_ctx":
                    skip_reason = "not supported by backend: gpu ML-DSA: this cuPQC build signs only with an empty context string"
                if skip_reason:
                    rows.append(_row(op, backend, size, count, None, skipped=skip_reason))
                    continue
                base = cpu_ms(op, size, count)
                if backend == "cpu":
                    t = base
                elif backend == "cpu-mt":
                    t = cpu_mt_ms(op, size, count)
                else:
                    factor = 1.0 + 0.15 * gpu_labels.index(backend)  # разные GPU-конфигурации чуть отличаются
                    t = base / curve(scenario, op, size, count) * factor
                t *= 1.0 + rnd.uniform(-noise, noise)
                rows.append(_row(op, backend, size, count, t, gpu=gpu))
        df = pd.DataFrame(rows, columns=COLUMNS)
        if legacy:  # CSV до появления entropy_ms
            df = df[[c for c in df.columns if "entropy" not in c]]
        frames.append(df)
    return frames


def _row(op, backend, size, count, t, skipped="", gpu=False):
    if skipped:
        return [op, backend, size, count, 1, skipped] + [0] * (len(COLUMNS) - 6)
    nbytes = size * count if op in HASH_OPS else 0
    sec = t / 1e3
    thr = nbytes / sec / 1e9 if nbytes else 0.0
    ops = count / sec
    if gpu:  # разбивка фаз: сумма меньше total (остаток — staging на CPU)
        alloc, h2d, kernel, d2h, sync = 0.12 * t, 0.25 * t, 0.30 * t, 0.10 * t, 0.05 * t
        entropy = 0.08 * t if op in PQC_OPS and "keygen" in op else 0.0
    else:
        alloc = h2d = d2h = sync = entropy = 0.0
        kernel = t
    return [op, backend, size, count, 0, "", 10, t, t, t * 0.97, t * 1.04, t * 0.02, kernel, alloc, h2d, d2h, sync, entropy,
            kernel, alloc, h2d, d2h, sync, entropy, thr, ops, t / max(count, 1)]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="normal")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    build(a.scenario, a.runs, a.seed)[0].to_csv(sys.stdout, index=False, float_format="%.9g")


if __name__ == "__main__":
    main()
