#!/usr/bin/env python3
"""Анализ результатов benchmark'а (этап 7): speedup, точки пересечения, графики, summary.md.

Вход: один или несколько results.csv, которые пишет `vault benchmark` (столбцы — write_csv в
src/bench/benchmark.cpp). Несколько файлов — это повторные прогоны одной и той же матрицы: по ним считается
медиана и оценивается стабильность. Рядом с CSV может лежать results.json (SystemInfo и конфиг) — его
данные попадают в summary.md.

Выход (в --out), только из скрипта, без ручной правки чисел:
  speedup.csv    — speedup = CPU_total / candidate_total для каждой точки сетки (медианы)
  transfer_bw.csv — эффективная ширина H2D по GPU-точкам sha3/merkle_build
  crossover.csv  — точка пересечения по каждой оси задачи (интерполяция в log-шкале) или явный результат
                   «GPU быстрее везде» / «нет пересечения в диапазоне» / «пересечения выше/ниже диапазона»
  summary.md     — таблицы для отчёта
  plots/*.png    — throughput от размера, ops/s от batch, разбивка фаз GPU, heatmap speedup

Зависимости: pandas, matplotlib (pip install -r bench/analysis/requirements.txt).
Использование: analyze.py run1.csv [run2.csv ...] --out DIR [--json results.json ...]
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import numpy as np
import pandas as pd

HASH_OPS = ["sha3", "merkle_build"]
PQC_OPS = ["mlkem_keygen", "mlkem_encaps", "mlkem_decaps", "mldsa_keygen", "mldsa_sign", "mldsa_verify"]
ALL_OPS = HASH_OPS + ["merkle_verify"] + PQC_OPS
CPU_BASELINES = ("cpu", "cpu-mt")
PHASES = ["alloc", "h2d", "kernel", "d2h", "sync", "entropy"]  # столбцы <phase>_median_ms

REQUIRED = ["op", "backend", "object_size", "count", "skipped", "skip_reason", "n", "total_median_ms",
            "throughput_gbps", "ops_per_sec"]
OPTIONAL_ZERO = [f"{p}_median_ms" for p in PHASES]  # старые CSV (до entropy_ms) читаются: отсутствующее = 0
KEY = ["op", "object_size", "count", "backend"]
SPREAD_WARN = 0.10  # разброс медиан между прогонами > 10 % считается нестабильным


class AnalysisError(Exception):
    """Ошибка входных данных (понятное сообщение пользователю, а не traceback)."""


def is_gpu(label: str) -> bool:
    return label == "gpu" or label.startswith("gpu")


# ---------------------------------------------------------------------------------------------------------
# Загрузка
# ---------------------------------------------------------------------------------------------------------
def load_results(paths) -> pd.DataFrame:
    """Читает один или несколько CSV; добавляет столбец run (номер файла). Пустые/испорченные входы — AnalysisError."""
    if isinstance(paths, (str, Path)):
        paths = [paths]
    frames = []
    for i, p in enumerate(paths):
        p = Path(p)
        if not p.is_file():
            raise AnalysisError(f"файл не найден: {p}")
        try:
            df = pd.read_csv(p, keep_default_na=False)
        except Exception as e:  # pandas бросает разные исключения на пустой/битый файл
            raise AnalysisError(f"не удалось прочитать {p}: {e}") from e
        missing = [c for c in REQUIRED if c not in df.columns]
        if missing:
            raise AnalysisError(f"{p}: нет столбцов {missing} (ожидается CSV от `vault benchmark`)")
        for c in OPTIONAL_ZERO:
            if c not in df.columns:
                df[c] = 0.0
        df["run"] = i
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    num = ["object_size", "count", "n", "total_median_ms", "throughput_gbps", "ops_per_sec"] + OPTIONAL_ZERO
    for c in num:
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df["skipped"] = pd.to_numeric(df["skipped"], errors="coerce").fillna(0).astype(int) == 1
    df["op"] = df["op"].astype(str)
    df["backend"] = df["backend"].astype(str)
    df["skip_reason"] = df["skip_reason"].astype(str)
    return df


def split_measured(df: pd.DataFrame):
    """(измеренные, пропущенные). Измеренной считается строка с конечным положительным total."""
    ok = ~df["skipped"] & np.isfinite(df["total_median_ms"]) & (df["total_median_ms"] > 0)
    return df[ok].copy(), df[~ok].copy()


def aggregate(measured: pd.DataFrame) -> pd.DataFrame:
    """Медиана по прогонам для каждой точки сетки + разброс медиан между прогонами."""
    if measured.empty:
        return pd.DataFrame(columns=KEY + ["total_ms", "throughput_gbps", "ops_per_sec", "n_runs", "spread"] + [f"{p}_ms" for p in PHASES])
    g = measured.groupby(KEY, sort=True)
    agg = g.agg(
        total_ms=("total_median_ms", "median"),
        throughput_gbps=("throughput_gbps", "median"),
        ops_per_sec=("ops_per_sec", "median"),
        n_runs=("run", "nunique"),
        tmin=("total_median_ms", "min"),
        tmax=("total_median_ms", "max"),
        **{f"{p}_ms": (f"{p}_median_ms", "median") for p in PHASES},
    ).reset_index()
    agg["spread"] = np.where(agg["n_runs"] > 1, (agg["tmax"] - agg["tmin"]) / agg["total_ms"], 0.0)
    return agg.drop(columns=["tmin", "tmax"])


# ---------------------------------------------------------------------------------------------------------
# speedup
# ---------------------------------------------------------------------------------------------------------
def compute_speedup(agg: pd.DataFrame) -> pd.DataFrame:
    """speedup = total(baseline) / total(candidate), медианы, одна и та же точка сетки.

    Кандидаты: каждая GPU-подпись против cpu И против cpu-mt; плюс cpu-mt против cpu (эффект потоков)."""
    cols = ["op", "object_size", "count", "candidate", "baseline", "kind", "baseline_ms", "candidate_ms", "speedup"]
    if agg.empty:
        return pd.DataFrame(columns=cols)
    by_backend = {b: d.set_index(["op", "object_size", "count"])["total_ms"] for b, d in agg.groupby("backend")}
    rows = []
    pairs = []
    for cand in by_backend:
        if is_gpu(cand):
            pairs += [(cand, base, "gpu") for base in CPU_BASELINES if base in by_backend]
    if "cpu-mt" in by_backend and "cpu" in by_backend:
        pairs.append(("cpu-mt", "cpu", "threads"))
    for cand, base, kind in pairs:
        joined = pd.concat([by_backend[base].rename("b"), by_backend[cand].rename("c")], axis=1, join="inner").reset_index()
        for r in joined.itertuples(index=False):
            rows.append((r.op, r.object_size, r.count, cand, base, kind, r.b, r.c, r.b / r.c))
    return pd.DataFrame(rows, columns=cols)


# ---------------------------------------------------------------------------------------------------------
# Эффективная пропускная способность передачи (для объяснения границ: PCIe vs вычисления)
# ---------------------------------------------------------------------------------------------------------
TRANSFER_MIN_BYTES = 16 << 20  # на малых объёмах время передачи определяется задержкой, а не шириной канала


def transfer_bandwidth(agg: pd.DataFrame) -> pd.DataFrame:
    """H2D GB/s = байты входа / h2d_ms для GPU-точек sha3 и merkle_build (объём известен: size * count).

    Время h2d в backend'е включает сборку staging-буфера на CPU, поэтому это нижняя оценка ширины PCIe.
    Столбец large = объём >= 16 MiB (там задержка не доминирует)."""
    cols = ["op", "backend", "object_size", "count", "bytes", "h2d_ms", "h2d_gbps", "d2h_ms", "kernel_ms", "large"]
    if agg.empty:
        return pd.DataFrame(columns=cols)
    d = agg[agg["backend"].map(is_gpu) & agg["op"].isin(HASH_OPS) & (agg["h2d_ms"] > 0)].copy()
    if d.empty:
        return pd.DataFrame(columns=cols)
    d["bytes"] = d["object_size"] * d["count"]
    d["h2d_gbps"] = d["bytes"] / (d["h2d_ms"] / 1e3) / 1e9
    d["large"] = d["bytes"] >= TRANSFER_MIN_BYTES
    return d[cols].sort_values(["op", "backend", "object_size", "count"]).reset_index(drop=True)


# ---------------------------------------------------------------------------------------------------------
# crossover
# ---------------------------------------------------------------------------------------------------------
def crossover_1d(xs, speedups) -> dict:
    """Точка пересечения speedup = 1 по оси x (log-интерполяция log(speedup) от log(x)).

    Результат (поле result):
      always          — кандидат быстрее во всех точках диапазона
      never           — нет пересечения: кандидат не быстрее ни в одной точке
      crossover       — один переход «медленнее -> быстрее», x_cross — точка пересечения
      crossover_down  — один переход «быстрее -> медленнее» (выигрыш только на малых x)
      mixed           — несколько смен знака; x_cross — первое пересечение вверх
      insufficient    — меньше двух точек
    x_first_win — наименьшая точка сетки, где кандидат быстрее (или пусто)."""
    pts = sorted((float(x), float(s)) for x, s in zip(xs, speedups) if x > 0 and s > 0 and math.isfinite(s))
    out = {"result": "insufficient", "x_cross": None, "x_first_win": None, "x_min": None, "x_max": None, "changes": 0}
    if len(pts) < 2:
        return out
    x = [p[0] for p in pts]
    s = [p[1] for p in pts]
    out["x_min"], out["x_max"] = x[0], x[-1]
    wins = [v > 1.0 for v in s]
    out["x_first_win"] = next((xi for xi, w in zip(x, wins) if w), None)
    changes = [i for i in range(1, len(wins)) if wins[i] != wins[i - 1]]
    out["changes"] = len(changes)

    def interp(i: int) -> float:  # между точками i-1 и i
        lx0, lx1 = math.log(x[i - 1]), math.log(x[i])
        ls0, ls1 = math.log(s[i - 1]), math.log(s[i])
        if ls1 == ls0:
            return x[i]
        return math.exp(lx0 + (0.0 - ls0) * (lx1 - lx0) / (ls1 - ls0))

    if all(wins):
        out["result"] = "always"
    elif not any(wins):
        out["result"] = "never"
    else:
        up = [i for i in changes if wins[i]]
        down = [i for i in changes if not wins[i]]
        if len(changes) == 1 and up:
            out["result"], out["x_cross"] = "crossover", interp(up[0])
        elif len(changes) == 1 and down:
            out["result"], out["x_cross"] = "crossover_down", interp(down[0])
        else:
            out["result"] = "mixed"
            if up:
                out["x_cross"] = interp(up[0])
            else:
                out["x_cross"] = interp(down[0])
    return out


def _axes_for(op: str):
    """Оси задачи: (имя оси, столбец x, столбец фиксируемого параметра)."""
    if op in HASH_OPS:
        return [("count", "count", "object_size"), ("size", "object_size", "count")]
    return [("count", "count", "object_size")]  # merkle_verify и PQC: по числу листьев / batch


def find_crossover(speedup: pd.DataFrame) -> pd.DataFrame:
    cols = ["op", "axis", "fixed", "fixed_value", "candidate", "baseline", "kind", "result", "x_cross", "x_first_win",
            "x_min", "x_max", "points"]
    rows = []
    if speedup.empty:
        return pd.DataFrame(columns=cols)
    for (op, cand, base, kind), d in speedup.groupby(["op", "candidate", "baseline", "kind"], sort=True):
        for axis, xcol, fcol in _axes_for(op):
            for fv, dd in d.groupby(fcol, sort=True):
                r = crossover_1d(dd[xcol], dd["speedup"])
                rows.append((op, axis, fcol, fv, cand, base, kind, r["result"], r["x_cross"], r["x_first_win"],
                             r["x_min"], r["x_max"], len(dd)))
    return pd.DataFrame(rows, columns=cols)


# ---------------------------------------------------------------------------------------------------------
# Вспомогательное: форматирование и стиль
# ---------------------------------------------------------------------------------------------------------
def fmt_size(n: float) -> str:
    n = float(n)
    for unit, div in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= div and n % div == 0:
            return f"{int(n // div)} {unit}"
    return f"{int(n)} B" if n == int(n) else f"{n:.0f} B"


def fmt_x(v: float) -> str:
    """Speedup в виде «280×», «3.4×», «0.044×» (без научной нотации)."""
    if v >= 100:
        return f"{v:.0f}×"
    if v >= 10:
        return f"{v:.0f}×"
    if v >= 1:
        return f"{v:.2g}×" if v < 10 else f"{v:.0f}×"
    return f"{v:.2g}×"


def fmt_num(x: float) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "—"
    if x >= 100:
        return f"{x:,.0f}".replace(",", " ")
    if x >= 10:
        return f"{x:.1f}"
    return f"{x:.2f}"


def describe_x(axis: str, x: float) -> str:
    return fmt_size(x) if axis == "size" else f"{x:,.0f}".replace(",", " ")


def describe_crossover(row) -> str:
    axis = row["axis"]
    unit = "размер объекта" if axis == "size" else ("число объектов/листьев/batch")
    res = row["result"]
    if res == "always":
        return f"кандидат быстрее на всём диапазоне ({describe_x(axis, row['x_min'])}…{describe_x(axis, row['x_max'])})"
    if res == "never":
        return f"нет пересечения в диапазоне ({describe_x(axis, row['x_min'])}…{describe_x(axis, row['x_max'])}): кандидат не быстрее"
    if res == "crossover":
        return f"быстрее начиная с ≈ {describe_x(axis, row['x_cross'])} ({unit})"
    if res == "crossover_down":
        return f"быстрее только до ≈ {describe_x(axis, row['x_cross'])} ({unit}), дальше медленнее"
    if res == "mixed":
        return f"неоднозначно (несколько смен знака), первое пересечение ≈ {describe_x(axis, row['x_cross'])}"
    return "мало точек (< 2)"


# Категориальная палитра (проверена scripts/validate_palette.js дата-viz skill, light, fixed order): цвет закреплён
# за сущностью (backend), а не за порядком в данных. Часть слотов ниже 3:1 по контрасту -> маркеры разной формы,
# подписи линий и таблицы в summary.md (relief rule).
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
INK3 = "#8a8985"
GRID = "#e6e5e1"
SLOTS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
MARKERS = ["o", "s", "^", "D", "v", "P", "X", "h"]
FIXED = {"cpu": 0, "cpu-mt": 1, "gpu": 2}


def backend_styles(labels):
    styles, nxt = {}, 3
    used = set(FIXED[b] for b in labels if b in FIXED)
    for b in sorted(labels, key=lambda s: (s not in FIXED, s)):
        if b in FIXED:
            slot = FIXED[b]
        else:
            while nxt in used:
                nxt += 1
            slot = nxt
            used.add(slot)
        if slot >= len(SLOTS):
            styles[b] = ("#8a8985", "o")  # больше 8 серий — нейтральный серый (не новый оттенок)
        else:
            styles[b] = (SLOTS[slot], MARKERS[slot])
    return styles


def _mpl():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "text.color": INK, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
        "axes.edgecolor": GRID, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
        "axes.spines.top": False, "axes.spines.right": False, "font.size": 10, "axes.titlesize": 11,
        "axes.titlelocation": "left", "legend.frameon": False, "font.family": "DejaVu Sans",
    })
    return plt


# ---------------------------------------------------------------------------------------------------------
# Графики
# ---------------------------------------------------------------------------------------------------------
def _log_axis_labels(ax):
    """Десятичные подписи на log-оси (0.1, 0.2, 0.5, 1, 2, 5, 10 …) вместо степеней, которых при малом диапазоне одна-две."""
    from matplotlib.ticker import FuncFormatter, LogLocator

    ax.yaxis.set_major_locator(LogLocator(base=10, subs=(1.0, 2.0, 5.0), numticks=12))
    ax.yaxis.set_minor_locator(LogLocator(base=10, subs=(), numticks=12))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}".replace(",", " ") if v >= 10 else f"{v:g}"))


def _line_panel(ax, d, xcol, ycol, styles, xlog=True):
    series = list(d.groupby("backend"))
    for b, dd in series:
        dd = dd.sort_values(xcol)
        color, marker = styles[b]
        ax.plot(dd[xcol], dd[ycol], color=color, marker=marker, markersize=6, linewidth=2,
                markeredgecolor=SURFACE, markeredgewidth=1.2, label=b)
        if len(series) <= 4:  # прямые подписи на конце линии (при ≤ 4 сериях), не цветом текста, а ink
            ax.annotate(b, (dd[xcol].iloc[-1], dd[ycol].iloc[-1]), xytext=(6, 0), textcoords="offset points",
                        fontsize=8, color=INK2, va="center", annotation_clip=False)
    ax.set_yscale("log")
    if xlog:
        ax.set_xscale("log", base=2 if xcol == "object_size" else 10)
    ax.margins(x=0.18)
    _log_axis_labels(ax)
    if xcol != "object_size":  # число объектов / batch: «1, 10, 100» вместо 10^0, 10^1, 10^2
        from matplotlib.ticker import FuncFormatter, NullLocator

        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}".replace(",", " ")))
        ax.xaxis.set_minor_locator(NullLocator())


def _legend_and_labels(fig, axes, styles, labels):
    handles = []
    import matplotlib.lines as mlines

    for b in labels:
        c, m = styles[b]
        handles.append(mlines.Line2D([], [], color=c, marker=m, linewidth=2, markersize=6, markeredgecolor=SURFACE, label=b))
    fig.legend(handles=handles, loc="lower center", ncol=min(len(handles), 6), fontsize=9, labelcolor=INK2)


def _size_ticks(ax):
    from matplotlib.ticker import FixedLocator, FuncFormatter

    xs = sorted({x for line in ax.lines for x in line.get_xdata()})
    ax.xaxis.set_major_locator(FixedLocator(xs))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: fmt_size(v)))
    ax.minorticks_off()
    for t in ax.get_xticklabels():
        t.set_rotation(35)
        t.set_ha("right")


def plot_throughput(agg, out_dir: Path, styles) -> list[Path]:
    plt = _mpl()
    files = []
    for op in HASH_OPS:
        d = agg[(agg["op"] == op) & (agg["object_size"] > 0)]
        if d.empty:
            continue
        counts = sorted(d["count"].unique())
        ncols = min(3, len(counts))
        nrows = math.ceil(len(counts) / ncols)
        fig, axes = plt.subplots(nrows, ncols, figsize=(4.6 * ncols, 3.4 * nrows + 0.7), squeeze=False, sharey=True)
        for ax, c in zip(axes.flat, counts):
            _line_panel(ax, d[d["count"] == c], "object_size", "throughput_gbps", styles)
            ax.set_title(f"{c:,} объектов".replace(",", " "), color=INK)
            _size_ticks(ax)
        for ax in list(axes.flat)[len(counts):]:
            ax.set_visible(False)
        for ax in axes[:, 0]:
            ax.set_ylabel("пропускная способность, GB/s (log)")
        for ax in axes[-1]:
            ax.set_xlabel("размер объекта")
        fig.suptitle(f"{op}: пропускная способность от размера объекта (по медиане total, GPU — с учётом передачи и аллокаций)",
                     x=0.01, ha="left", fontsize=11, color=INK)
        _legend_and_labels(fig, axes, styles, sorted(d["backend"].unique(), key=lambda s: (s not in FIXED, s)))
        fig.tight_layout(rect=(0, 0.06, 1, 0.95))
        p = out_dir / f"throughput_{op}.png"
        fig.savefig(p, dpi=140)
        plt.close(fig)
        files.append(p)
    return files


def plot_ops_per_sec(agg, out_dir: Path, styles) -> list[Path]:
    plt = _mpl()
    files = []
    for name, ops in (("pqc", PQC_OPS), ("merkle_verify", ["merkle_verify"])):
        ops = [o for o in ops if not agg[agg["op"] == o].empty]
        if not ops:
            continue
        ncols = min(3, len(ops))
        nrows = math.ceil(len(ops) / ncols)
        fig, axes = plt.subplots(nrows, ncols, figsize=(4.6 * ncols, 3.3 * nrows + 0.7), squeeze=False)
        for ax, op in zip(axes.flat, ops):
            d = agg[agg["op"] == op]
            _line_panel(ax, d, "count", "ops_per_sec", styles)
            ax.set_title(op, color=INK)
            ax.set_xlabel("число листьев" if op == "merkle_verify" else "batch")
            ax.set_ylabel("операций/с (log)")
        for ax in list(axes.flat)[len(ops):]:
            ax.set_visible(False)
        fig.suptitle("Операций в секунду от размера задачи (медиана total)", x=0.01, ha="left", fontsize=11, color=INK)
        _legend_and_labels(fig, axes, styles, sorted(agg[agg["op"].isin(ops)]["backend"].unique(), key=lambda s: (s not in FIXED, s)))
        fig.tight_layout(rect=(0, 0.06, 1, 0.95))
        p = out_dir / f"ops_per_sec_{name}.png"
        fig.savefig(p, dpi=140)
        plt.close(fig)
        files.append(p)
    return files


PHASE_COLORS = {"alloc": SLOTS[0], "h2d": SLOTS[1], "kernel": SLOTS[2], "d2h": SLOTS[3], "sync": SLOTS[4],
                "entropy": SLOTS[5], "other": "#c9c8c3"}


# Фазы, которые складываются в total. sync в стопку не входит: это время, пока CPU ЖДЁТ GPU, и оно перекрывается
# с kernel и копированиями — в стопке оно считалось бы дважды (первый полный прогон: столбец 16 MiB × 100 был
# ~6500 мс при total 3787 мс).
STACK_PHASES = ["alloc", "h2d", "kernel", "d2h", "entropy"]


def phase_shares(dd: pd.DataFrame) -> dict:
    """Доли фаз от total (в %), по строкам dd. other = total − сумма фаз (сборка staging, запуск, прочее CPU-время).
    Если фазы перекрываются (double buffering) и их сумма больше total, доли нормируются на эту сумму."""
    total = dd["total_ms"].to_numpy(dtype=float)
    phases = {p: dd[f"{p}_ms"].to_numpy(dtype=float) for p in STACK_PHASES}
    s = sum(phases.values())
    other = np.maximum(total - s, 0.0)
    denom = np.maximum(total, s)
    denom = np.where(denom > 0, denom, 1.0)
    out = {p: 100.0 * v / denom for p, v in phases.items()}
    out["other"] = 100.0 * other / denom
    return out


def plot_gpu_phases(agg, out_dir: Path) -> list[Path]:
    """Stacked bar долей фаз в total GPU (каждый столбец = 100 %); над столбцом — total в мс."""
    plt = _mpl()
    files = []
    gpu = agg[agg["backend"].map(is_gpu)]
    for op in ALL_OPS:
        d = gpu[gpu["op"] == op]
        if d.empty:
            continue
        backs = sorted(d["backend"].unique())
        fig, axes = plt.subplots(len(backs), 1, figsize=(max(7.0, 0.42 * d.groupby(["object_size", "count"]).ngroups + 3), 3.4 * len(backs) + 0.9), squeeze=False)
        for ax, b in zip(axes[:, 0], backs):
            dd = d[d["backend"] == b].sort_values(["object_size", "count"]).reset_index(drop=True)
            shares = phase_shares(dd)
            bottom = np.zeros(len(dd))
            x = np.arange(len(dd))
            for p in STACK_PHASES + ["other"]:
                vals = shares[p]
                if not np.any(vals > 0):
                    continue
                ax.bar(x, vals, bottom=bottom, width=0.72, color=PHASE_COLORS[p], edgecolor=SURFACE, linewidth=1.5, label=p)
                bottom += vals
            for xi, t in zip(x, dd["total_ms"].to_numpy(dtype=float)):
                ax.text(xi, 101.5, fmt_num(t), ha="center", va="bottom", fontsize=7, color=INK2, rotation=90)
            ax.set_ylim(0, 125)
            ax.set_yticks([0, 25, 50, 75, 100])
            if op in ("merkle_verify",) or op in PQC_OPS:
                ax.set_xticks(x, [f"{int(c)}" for c in dd["count"]])
                ax.set_xlabel("число листьев" if op == "merkle_verify" else "batch")
            else:
                ax.set_xticks(x, [f"{fmt_size(s)}×{int(c)}" for s, c in zip(dd["object_size"], dd["count"])], rotation=60, ha="right")
                ax.set_xlabel("размер объекта × число объектов")
            ax.set_ylabel("доля total, %")
            ax.set_title(f"{op} — {b}", color=INK)
            ax.grid(axis="x", visible=False)
            ax.legend(ncol=7, fontsize=8, labelcolor=INK2, loc="upper left")
        fig.suptitle("Доли фаз в total GPU (над столбцом — total, мс); other = total − сумма фаз; sync (ожидание CPU) не входит — оно перекрывается с kernel",
                     x=0.01, ha="left", fontsize=10, color=INK)
        fig.tight_layout(rect=(0, 0, 1, 0.96))
        p = out_dir / f"gpu_phases_{op}.png"
        fig.savefig(p, dpi=140)
        plt.close(fig)
        files.append(p)
    return files


def plot_heatmaps(speedup, out_dir: Path) -> list[Path]:
    """Heatmap speedup (размер × число объектов) для SHA3 и Merkle build, по каждой паре GPU/baseline."""
    plt = _mpl()
    from matplotlib.colors import LinearSegmentedColormap, TwoSlopeNorm

    cmap = LinearSegmentedColormap.from_list("div", ["#184f95", "#6da7ec", "#f0efec", "#ee8a85", "#a8201f"])  # blue <-> red, нейтральная середина
    files = []
    for op in HASH_OPS:
        for (cand, base), d in speedup[(speedup["op"] == op) & (speedup["kind"] == "gpu") & (speedup["object_size"] > 0)].groupby(["candidate", "baseline"]):
            piv = d.pivot_table(index="object_size", columns="count", values="speedup", aggfunc="median").sort_index().sort_index(axis=1)
            if piv.size == 0:
                continue
            lg = np.log2(piv.to_numpy())
            lim = max(1.0, float(np.nanmax(np.abs(lg))))
            fig, ax = plt.subplots(figsize=(1.0 * piv.shape[1] + 3.2, 0.6 * piv.shape[0] + 2.4))
            im = ax.imshow(lg, cmap=cmap, norm=TwoSlopeNorm(vcenter=0.0, vmin=-lim, vmax=lim), aspect="auto", origin="lower")
            ax.set_xticks(range(piv.shape[1]), [f"{int(c):,}".replace(",", " ") for c in piv.columns])
            ax.set_yticks(range(piv.shape[0]), [fmt_size(s) for s in piv.index])
            ax.set_xlabel("число объектов")
            ax.set_ylabel("размер объекта")
            ax.grid(False)
            for i in range(piv.shape[0]):
                for j in range(piv.shape[1]):
                    v = piv.iat[i, j]
                    if np.isfinite(v):
                        dark = abs(lg[i, j]) > 0.6 * lim
                        ax.text(j, i, fmt_x(v), ha="center", va="center", fontsize=8, color="#ffffff" if dark else INK)
            cb = fig.colorbar(im, ax=ax)
            ticks = [-lim, 0, lim]
            cb.set_ticks(ticks, labels=[fmt_x(2 ** t) for t in ticks])
            cb.set_label("speedup (log): <1 CPU быстрее, >1 GPU быстрее", color=INK2)
            ax.set_title(f"{op}: speedup {cand} против {base}", color=INK)
            fig.tight_layout()
            p = out_dir / f"heatmap_{op}_{cand}_vs_{base}.png"
            fig.savefig(p, dpi=140)
            plt.close(fig)
            files.append(p)
    return files


def make_plots(agg: pd.DataFrame, speedup: pd.DataFrame, out_dir: Path) -> list[Path]:
    plots = out_dir / "plots"
    plots.mkdir(parents=True, exist_ok=True)
    if agg.empty:
        return []
    styles = backend_styles(sorted(agg["backend"].unique()))
    files = plot_throughput(agg, plots, styles) + plot_ops_per_sec(agg, plots, styles)
    files += plot_gpu_phases(agg, plots) + plot_heatmaps(speedup, plots)
    return files


# ---------------------------------------------------------------------------------------------------------
# summary.md
# ---------------------------------------------------------------------------------------------------------
def md_table(headers, rows) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def _system_section(infos) -> list[str]:
    lines = []
    for i, info in enumerate(infos):
        s = info.get("system", {})
        c = info.get("config", {})
        if not s:
            continue
        title = f"Прогон {i + 1}" if len(infos) > 1 else "Окружение"
        lines.append(f"**{title}:** {s.get('timestamp_utc', '?')}, {s.get('hostname', '?')}")
        for k, label in (("cpu_model", "CPU"), ("os", "ОС"), ("gpu_model", "GPU"), ("gpu_arch", "Архитектура GPU"),
                         ("gpu_memory", "VRAM"), ("cuda_runtime_version", "CUDA runtime"), ("cuda_driver_version", "Драйвер CUDA"),
                         ("cupqc_version", "cuPQC"), ("openssl_version", "OpenSSL"), ("liboqs_version", "liboqs"),
                         ("compiler", "Компилятор"), ("build_type", "Тип сборки"), ("git_commit", "Коммит")):
            if s.get(k):
                lines.append(f"- {label}: {s[k]}")
        if s.get("compiler_flags", "").strip():
            lines.append(f"- Флаги: `{s['compiler_flags'].strip()}`")
        if c:
            lines.append(f"- Конфиг: warmup {c.get('warmup_runs')}, прогонов {c.get('measured_runs')}, потоков cpu-mt {c.get('cpu_threads')}, "
                         f"alloc в total: {c.get('include_alloc_in_total')}, ctx ML-DSA: {c.get('mldsa_context', 'manifest')}")
        lines.append("")
    return lines


def write_summary(df, agg, speedup, crossover, out_dir: Path, plot_files, infos=(), inputs=()) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    measured, skipped = split_measured(df)
    L = ["# Результаты benchmark'а", "",
         "Файл сформирован `bench/analysis/analyze.py` из сырых CSV; числа не правились вручную. "
         "speedup = total(CPU) / total(кандидат) по медианам; total GPU включает аллокации, передачу данных и синхронизацию (§45, §48).", ""]
    L.append(f"Входные файлы ({len(inputs)}): " + ", ".join(f"`{Path(p).name}`" for p in inputs))
    L.append("")
    L += _system_section(list(infos))

    # --- покрытие
    L += ["## Покрытие", ""]
    backs = sorted(df["backend"].unique(), key=lambda s: (s not in FIXED, s))
    rows = []
    for b in backs:
        m = int((measured["backend"] == b).sum()) if not measured.empty else 0
        sk = int((skipped["backend"] == b).sum()) if not skipped.empty else 0
        rows.append((b, m, sk))
    L.append(md_table(["backend", "измерено (строк)", "пропущено (строк)"], rows))
    L.append("")
    if not skipped.empty:
        grp = skipped.groupby(["backend", "skip_reason"]).size().reset_index(name="n")
        L.append("Причины пропусков:")
        L.append("")
        L.append(md_table(["backend", "причина", "строк"], [(r.backend, r.skip_reason or "(не указана)", r.n) for r in grp.itertuples()]))
        L.append("")
    gpu_present = any(is_gpu(b) for b in agg["backend"].unique()) if not agg.empty else False
    if not gpu_present:
        L += ["> **GPU-данных в этом наборе нет** (GPU-backend пропущен или не запускался): speedup и пересечения ниже — только "
              "`cpu-mt` против `cpu`.", ""]
    failed = [b for b in backs if is_gpu(b) and (measured.empty or (measured["backend"] == b).sum() == 0)]
    if failed:
        L += ["> **Backend без единой измеренной точки:** " + ", ".join(f"`{b}`" for b in failed) +
              " — см. причины пропусков выше (backend недоступен, нет реализации компонента или отказ операции).", ""]

    # --- пересечения
    L += ["## Точки пересечения (speedup = 1)", "",
          "Интерполяция линейная по log(speedup) от log(x) между соседними точками сетки. «Кандидат» — GPU-backend (kind = gpu) "
          "либо `cpu-mt` (kind = threads, против `cpu`).", ""]
    if crossover.empty:
        L += ["Нет пар «кандидат/baseline» для сравнения.", ""]
    else:
        for kind, title in (("gpu", "GPU против CPU"), ("threads", "cpu-mt против cpu")):
            c = crossover[crossover["kind"] == kind]
            if c.empty:
                continue
            L += [f"### {title}", ""]
            rows = []
            for r in c.sort_values(["op", "axis", "fixed_value", "candidate", "baseline"]).to_dict("records"):
                fixed = "—"
                if r["fixed"] == "object_size":
                    fixed = f"размер {fmt_size(r['fixed_value'])}" if r["fixed_value"] else "—"
                elif r["fixed"] == "count":
                    fixed = f"{int(r['fixed_value']):,} объектов".replace(",", " ")
                axis = {"count": "по числу (batch)", "size": "по размеру объекта"}[r["axis"]]
                rows.append((r["op"], axis, fixed, r["candidate"], r["baseline"], describe_crossover(r)))
            L.append(md_table(["операция", "ось", "фиксировано", "кандидат", "baseline", "результат"], rows))
            L.append("")

    # --- экстремумы speedup
    L += ["## Максимальный и минимальный speedup", ""]
    if speedup.empty:
        L += ["Нет данных.", ""]
    else:
        rows = []
        for (op, cand, base, kind), d in speedup.groupby(["op", "candidate", "baseline", "kind"], sort=True):
            hi, lo = d.loc[d["speedup"].idxmax()], d.loc[d["speedup"].idxmin()]

            def where(r):
                if r["object_size"]:
                    return f"{fmt_size(r['object_size'])} × {int(r['count'])}"
                return f"{int(r['count'])}"

            rows.append((op, cand, base, f"{hi['speedup']:.3g}× ({where(hi)})", f"{lo['speedup']:.3g}× ({where(lo)})"))
        L.append(md_table(["операция", "кандидат", "baseline", "максимум (точка)", "минимум (точка)"], rows))
        L.append("")

    # --- передача данных
    bw = transfer_bandwidth(agg)
    L += ["## Эффективная ширина H2D (sha3, merkle_build)", ""]
    if bw.empty:
        L += ["Нет GPU-точек с разбивкой фаз.", ""]
    else:
        big = bw[bw["large"]]
        rows = []
        for (op, b), d in bw.groupby(["op", "backend"]):
            dl = d[d["large"]]
            rows.append((op, b, f"{d['h2d_gbps'].median():.2f}", f"{dl['h2d_gbps'].median():.2f}" if len(dl) else "—",
                         f"{d['h2d_gbps'].max():.2f}"))
        L += ["Байты входа / h2d_ms. Время h2d включает сборку staging-буфера на CPU, поэтому значения — нижняя оценка ширины PCIe; "
              f"«крупные» — объём ≥ {fmt_size(TRANSFER_MIN_BYTES)}.", ""]
        L.append(md_table(["операция", "backend", "GB/s, медиана по всем", "GB/s, медиана по крупным", "GB/s, максимум"], rows))
        L.append("")

    # --- стабильность
    n_runs = int(df["run"].nunique())
    L += ["## Стабильность медиан между прогонами", ""]
    if n_runs < 2 or agg.empty:
        L += [f"Прогонов: {n_runs}. Для оценки стабильности нужно ≥ 2 полных прогона одной матрицы.", ""]
    else:
        multi = agg[agg["n_runs"] > 1]
        sp = multi["spread"]
        L += [f"Прогонов: {n_runs}; точек, измеренных не менее чем в двух прогонах: {len(multi)} из {len(agg)}. "
              f"Разброс = (max − min) / медиана медиан total.", ""]
        if len(multi):
            L.append(md_table(["статистика", "значение"], [
                ("медиана разброса", f"{sp.median() * 100:.1f} %"),
                ("90-й процентиль", f"{sp.quantile(0.9) * 100:.1f} %"),
                ("максимум", f"{sp.max() * 100:.1f} %"),
                (f"точек с разбросом > {SPREAD_WARN * 100:.0f} %", f"{int((sp > SPREAD_WARN).sum())} ({(sp > SPREAD_WARN).mean() * 100:.0f} %)"),
            ]))
            L.append("")
            worst = multi.sort_values("spread", ascending=False).head(10)
            L += ["Самые нестабильные точки:", ""]
            L.append(md_table(["операция", "backend", "размер", "число", "разброс"], [
                (r.op, r.backend, fmt_size(r.object_size) if r.object_size else "—", int(r.count), f"{r.spread * 100:.1f} %") for r in worst.itertuples()]))
            L.append("")

    # --- сырая таблица CPU/GPU по операциям (кратко): медианы
    L += ["## Графики", ""]
    if plot_files:
        L += [f"- `plots/{p.name}`" for p in sorted(plot_files)]
    else:
        L.append("Графики не построены (нет измеренных точек).")
    L.append("")
    path = out_dir / "summary.md"
    path.write_text("\n".join(L) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------------------------------------
def load_infos(csv_paths, json_paths):
    """results.json для каждого CSV: явный список или файл рядом (results.json / <имя>.json)."""
    infos = []
    paths = list(json_paths) if json_paths else []
    if not paths:
        for p in csv_paths:
            for cand in (Path(p).with_suffix(".json"), Path(p).parent / "results.json"):
                if cand.is_file():
                    paths.append(cand)
                    break
    for p in paths:
        try:
            infos.append(json.loads(Path(p).read_text(encoding="utf-8")))
        except Exception:
            continue  # метаданные необязательны
    return infos


def analyze(csv_paths, out_dir: Path, json_paths=(), plots: bool = True) -> dict:
    """Полный анализ: пишет speedup.csv, crossover.csv, summary.md, plots/. Возвращает пути и таблицы."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    df = load_results(csv_paths)
    measured, _ = split_measured(df)
    agg = aggregate(measured)
    sp = compute_speedup(agg)
    co = find_crossover(sp)
    sp.to_csv(out_dir / "speedup.csv", index=False)
    transfer_bandwidth(agg).to_csv(out_dir / "transfer_bw.csv", index=False)
    co.to_csv(out_dir / "crossover.csv", index=False)
    plot_files = make_plots(agg, sp, out_dir) if plots else []
    summary = write_summary(df, agg, sp, co, out_dir, plot_files, load_infos(csv_paths, json_paths), csv_paths)
    return {"df": df, "agg": agg, "speedup": sp, "crossover": co, "plots": plot_files, "summary": summary}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", type=Path, nargs="+", help="results.csv от `vault benchmark` (несколько — повторные прогоны)")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--json", type=Path, nargs="*", default=[], help="results.json (SystemInfo/конфиг); по умолчанию рядом с CSV")
    ap.add_argument("--no-plots", action="store_true", help="только таблицы (быстро)")
    args = ap.parse_args(argv)
    try:
        r = analyze(args.csv, args.out, args.json, plots=not args.no_plots)
    except AnalysisError as e:
        print(f"analyze.py: {e}", file=sys.stderr)
        return 2
    print(f"summary: {r['summary']}")
    print(f"speedup: {args.out / 'speedup.csv'}  crossover: {args.out / 'crossover.csv'}  plots: {len(r['plots'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
