#!/usr/bin/env python3
"""Анализ результатов benchmark (Milestone 7).

Вход: results.csv, который пишет `vault benchmark` (столбцы — см. BenchRecord
в include/vault/bench/benchmark.hpp).
Выход (в --out):
  * speedup.csv           — speedup = CPU_total / GPU_total для каждой точки
                            (отдельно относительно cpu и cpu-mt);
  * crossover.csv         — минимальный размер задачи / batch, где GPU_total < CPU_total (§48);
  * plots/*.png           — throughput vs size, ops/s vs batch, stacked bar
                            alloc/H2D/kernel/D2H/sync для GPU;
  * summary.md            — таблицы для отчёта.

Зависимости: pandas, matplotlib (pip install -r bench/analysis/requirements.txt).
"""
from __future__ import annotations

import argparse
from pathlib import Path


def load_results(csv_path: Path):
    """Прочитать CSV в DataFrame, отфильтровать skipped."""
    raise NotImplementedError("Milestone 7")


def compute_speedup(df):
    """speedup = median(total_ms CPU) / median(total_ms GPU) по (op, object_size, count)."""
    raise NotImplementedError("Milestone 7")


def find_crossover(df):
    """Для каждого op — минимальный count (и object_size для SHA3/Merkle), где GPU быстрее.
    Интерполяция между соседними точками сетки (лог-шкала)."""
    raise NotImplementedError("Milestone 7")


def make_plots(df, out_dir: Path) -> None:
    raise NotImplementedError("Milestone 7")


def write_summary(df, speedup, crossover, out_dir: Path) -> None:
    raise NotImplementedError("Milestone 7")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    df = load_results(args.csv)
    sp = compute_speedup(df)
    co = find_crossover(df)
    make_plots(df, args.out)
    write_summary(df, sp, co, args.out)


if __name__ == "__main__":
    main()
