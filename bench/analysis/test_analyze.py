"""Тесты analyze.py (этап 7.A1): реальный CPU-прогон, синтетические GPU-данные, граничные случаи.

Запуск: python3 -m pytest bench/analysis -q
Анализ не должен падать ни на одном варианте данных: GPU быстрее/медленнее, пересечение внутри и вне диапазона,
skipped-точки, упавший backend, несколько прогонов, старый CSV без entropy_ms.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import pandas as pd
import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "fixtures"))

import analyze as A  # noqa: E402
import gen_synthetic as G  # noqa: E402

REAL_CSV = HERE / "fixtures" / "cpu_quick.csv"
SYNTH_CSV = HERE / "fixtures" / "synthetic_gpu.csv"


def write(tmp_path: Path, frames, name="run") -> list[Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    paths = []
    for i, df in enumerate(frames):
        p = tmp_path / f"{name}{i}.csv"
        df.to_csv(p, index=False, float_format="%.9g")
        paths.append(p)
    return paths


def run(tmp_path: Path, csvs, plots: bool = False, **kw):
    """plots=False по умолчанию: построение ~17 графиков занимает секунды; графики проверяют отдельные тесты."""
    out = tmp_path / "out"
    r = A.analyze(csvs, out, plots=plots, **kw)
    assert (out / "summary.md").is_file()
    assert (out / "speedup.csv").is_file()
    assert (out / "crossover.csv").is_file()
    return r, out


# ----------------------------------------------------------------------------------------------- crossover_1d
def test_crossover_log_interpolation_is_exact_for_power_law():
    xc = 1000.0
    xs = [10, 100, 1000, 10000, 100000]
    # s(x) = x / xc : ln s линейно по ln x, интерполяция обязана попасть в xc точно (между 100 и 10000)
    r = A.crossover_1d([10, 100, 10000, 100000], [x / xc for x in (10, 100, 10000, 100000)])
    assert r["result"] == "crossover"
    assert r["x_cross"] == pytest.approx(xc, rel=1e-9)
    assert r["x_first_win"] == 10000
    assert A.crossover_1d(xs, [x / xc for x in xs])["x_cross"] == pytest.approx(xc, rel=1e-9)


def test_crossover_results_always_never_down_mixed_insufficient():
    assert A.crossover_1d([1, 10, 100], [2, 3, 4])["result"] == "always"
    assert A.crossover_1d([1, 10, 100], [0.5, 0.3, 0.1])["result"] == "never"
    assert A.crossover_1d([1, 10, 100], [0.5, 0.3, 0.1])["x_cross"] is None
    down = A.crossover_1d([1, 10, 100], [3.0, 2.0, 0.5])
    assert down["result"] == "crossover_down" and 10 < down["x_cross"] < 100
    mixed = A.crossover_1d([1, 10, 100, 1000], [0.5, 2.0, 0.5, 2.0])
    assert mixed["result"] == "mixed" and mixed["changes"] == 3 and 1 < mixed["x_cross"] < 10
    assert A.crossover_1d([5], [2.0])["result"] == "insufficient"
    assert A.crossover_1d([], [])["result"] == "insufficient"


def test_crossover_ignores_unsorted_and_invalid_points():
    r = A.crossover_1d([100, 10, 0, 1000, -5], [2.0, 0.5, 9.0, 4.0, 3.0])  # x <= 0 отбрасываются, порядок не важен
    assert r["result"] == "crossover" and 10 < r["x_cross"] < 100
    assert A.crossover_1d([1, 10], [float("nan"), 2.0])["result"] == "insufficient"
    assert A.crossover_1d([1, 10], [1.0, 1.0])["result"] == "never"  # speedup ровно 1 — не выигрыш


# ----------------------------------------------------------------------------------------------- реальные данные
def test_real_cpu_run_without_gpu():
    df = A.load_results([REAL_CSV])
    measured, skipped = A.split_measured(df)
    assert (skipped["backend"] == "gpu").all() and len(skipped) > 0  # gpu в quick.json без CUDA пропущен
    assert set(measured["backend"]) == {"cpu", "cpu-mt"}


def test_real_cpu_run_end_to_end(tmp_path):
    r, out = run(tmp_path, [REAL_CSV], plots=True)
    sp = r["speedup"]
    assert set(sp["kind"]) == {"threads"}  # GPU-данных нет: только cpu-mt против cpu
    assert (sp["baseline"] == "cpu").all()
    text = (out / "summary.md").read_text(encoding="utf-8")
    assert "GPU-данных в этом наборе нет" in text
    assert "not compiled in" in text  # причина пропуска GPU попала в summary
    assert "Окружение" in text and "Release" in text  # SystemInfo из cpu_quick.json рядом с CSV
    assert list((out / "plots").glob("throughput_*.png")) and list((out / "plots").glob("ops_per_sec_*.png"))
    assert not list((out / "plots").glob("gpu_phases_*"))  # без GPU нет разбивки GPU-фаз


# ----------------------------------------------------------------------------------------------- синтетические GPU-данные
def test_committed_synthetic_fixture_is_current(tmp_path):
    """Файл fixtures/synthetic_gpu.csv — выход gen_synthetic.py (сценарий normal); не правится вручную."""
    fresh = G.build("normal")[0]
    committed = pd.read_csv(SYNTH_CSV, keep_default_na=False)
    pd.testing.assert_frame_equal(committed.reset_index(drop=True), pd.read_csv(write(tmp_path, [fresh])[0], keep_default_na=False).reset_index(drop=True))


def cross_for(co, op, axis, fixed_value, cand="gpu", base="cpu"):
    d = co[(co["op"] == op) & (co["axis"] == axis) & (co["fixed_value"] == fixed_value) & (co["candidate"] == cand) & (co["baseline"] == base)]
    assert len(d) == 1, d
    return d.iloc[0]


def test_gpu_always_faster(tmp_path):
    r, _ = run(tmp_path, write(tmp_path, G.build("gpu_faster")))
    g = r["crossover"].query("kind == 'gpu' and baseline == 'cpu'")  # против cpu-mt «всегда быстрее» не обязано выполняться
    assert (g["result"] == "always").all()
    assert (r["speedup"][r["speedup"]["kind"] == "gpu"].query("baseline == 'cpu'")["speedup"] > 3.5).all()


def test_gpu_always_slower(tmp_path):
    r, out = run(tmp_path, write(tmp_path, G.build("gpu_slower")))
    g = r["crossover"][r["crossover"]["kind"] == "gpu"]
    assert (g["result"] == "never").all()
    assert "нет пересечения в диапазоне" in (out / "summary.md").read_text(encoding="utf-8")


def test_crossover_inside_range_matches_analytic_point(tmp_path):
    r, out = run(tmp_path, write(tmp_path, G.build("crossover", noise=0.0)))  # без шума: интерполяция точна
    # merkle_verify и PQC: ось count, speedup = count / 1000 -> пересечение ровно в 1000
    for op in ["merkle_verify", "mlkem_keygen", "mldsa_sign"]:
        fixed = 168 if op == "mldsa_sign" else 0
        row = cross_for(r["crossover"], op, "count", fixed)
        assert row["result"] == "crossover"
        assert row["x_cross"] == pytest.approx(1000.0, rel=1e-6), op
    # sha3 по размеру при 1000 объектов: speedup = size * 1000 / 4e6 -> size = 4000
    row = cross_for(r["crossover"], "sha3", "size", 1000)
    assert row["result"] == "crossover" and row["x_cross"] == pytest.approx(4000.0, rel=1e-6)
    # sha3 по числу при размере 1 MiB: count * 1048576 / 4e6 = 1 -> count ≈ 3.81 (ниже диапазона 10…100000)
    row = cross_for(r["crossover"], "sha3", "count", 1048576)
    assert row["result"] == "always"


def test_crossover_outside_range(tmp_path):
    r, _ = run(tmp_path, write(tmp_path, G.build("crossover_above_range")))
    assert (r["crossover"].query("kind == 'gpu'")["result"] == "never").all()
    r2, _ = run(tmp_path / "b", write(tmp_path / "b", G.build("crossover_below_range")))
    assert (r2["crossover"].query("kind == 'gpu' and baseline == 'cpu'")["result"] == "always").all()


def test_nonmonotone_scenario_does_not_crash_and_is_reported(tmp_path):
    r, out = run(tmp_path, write(tmp_path, G.build("nonmonotone")))
    res = set(r["crossover"].query("kind == 'gpu'")["result"])
    assert res & {"mixed", "crossover", "crossover_down"}
    assert "неоднозначно" in (out / "summary.md").read_text(encoding="utf-8") or "быстрее только до" in (out / "summary.md").read_text(encoding="utf-8")


def test_speedup_is_cpu_over_gpu_for_both_baselines(tmp_path):
    r, _ = run(tmp_path, write(tmp_path, G.build("gpu_faster")))
    sp = r["speedup"]
    row = sp[(sp["op"] == "sha3") & (sp["object_size"] == 65536) & (sp["count"] == 1000) & (sp["candidate"] == "gpu")]
    assert set(row["baseline"]) == {"cpu", "cpu-mt"}  # против обоих CPU-вариантов (§45)
    for x in row.itertuples():
        assert x.speedup == pytest.approx(x.baseline_ms / x.candidate_ms)
    assert row[row["baseline"] == "cpu"]["speedup"].iloc[0] == pytest.approx(4.0, rel=0.1)  # шум ±3 % у двух строк


def test_skipped_points_and_exceeds_max_total_bytes(tmp_path):
    r, out = run(tmp_path, write(tmp_path, G.build("normal")))
    text = (out / "summary.md").read_text(encoding="utf-8")
    assert "exceeds max_total_bytes" in text
    # 16 MiB × 10000/100000 пропущены -> этих точек в speedup нет, остальные посчитаны
    sp = r["speedup"]
    assert sp[(sp["op"] == "sha3") & (sp["object_size"] == 16777216) & (sp["count"] == 100000)].empty
    assert not sp[(sp["op"] == "sha3") & (sp["object_size"] == 16777216) & (sp["count"] == 100)].empty


def test_failed_backend_all_points_skipped(tmp_path):
    r, out = run(tmp_path, write(tmp_path, G.build("normal", failed_gpu=True)), plots=True)
    assert r["speedup"].query("kind == 'gpu'").empty
    text = (out / "summary.md").read_text(encoding="utf-8")
    assert "Backend без единой измеренной точки" in text and "`gpu`" in text
    assert "backend unavailable" in text
    assert not list((out / "plots").glob("gpu_phases_*"))


def test_backend_that_rejects_an_operation(tmp_path):
    """GPU ML-DSA без поддержки context string: те строки skipped, остальные операции GPU есть."""
    r, out = run(tmp_path, write(tmp_path, G.build("no_ctx")))
    gpu_ops = set(r["speedup"].query("kind == 'gpu'")["op"])
    assert "sha3" in gpu_ops and "mlkem_keygen" in gpu_ops
    assert not gpu_ops & {"mldsa_keygen", "mldsa_sign", "mldsa_verify"}
    assert "empty context string" in (out / "summary.md").read_text(encoding="utf-8")


def test_multiple_gpu_configurations_get_own_series_and_styles(tmp_path):
    labels = ("gpu-pinned", "gpu-pageable", "gpu-warp", "gpu-db")
    r, out = run(tmp_path, write(tmp_path, G.build("normal", gpu_labels=labels)), plots=True)
    assert set(r["speedup"].query("kind == 'gpu'")["candidate"]) == set(labels)
    assert list((out / "plots").glob("gpu_phases_sha3.png"))
    styles = A.backend_styles(["cpu", "cpu-mt", *labels])
    assert styles["cpu"][0] == A.SLOTS[0] and styles["cpu-mt"][0] == A.SLOTS[1]  # цвет закреплён за сущностью
    assert len({v[0] for v in styles.values()}) == len(styles)
    # цвет не зависит от того, какие backend'ы присутствуют вместе
    assert A.backend_styles(["cpu", "gpu-warp"])["cpu"] == styles["cpu"]


def test_more_than_eight_series_fall_back_to_neutral_color():
    labels = ["cpu", "cpu-mt"] + [f"gpu-x{i}" for i in range(9)]
    styles = A.backend_styles(labels)
    assert len(styles) == len(labels)
    assert sum(1 for c, _ in styles.values() if c == "#8a8985") >= 3


def test_transfer_bandwidth_from_phase_breakdown(tmp_path):
    r, out = run(tmp_path, write(tmp_path, G.build("normal")))
    bw = pd.read_csv(out / "transfer_bw.csv")
    assert set(bw["op"]) == {"sha3", "merkle_build"} and set(bw["backend"]) == {"gpu"}
    row = bw[(bw["op"] == "sha3") & (bw["object_size"] == 1048576) & (bw["count"] == 100)].iloc[0]
    assert row["bytes"] == 1048576 * 100
    assert row["h2d_gbps"] == pytest.approx(row["bytes"] / (row["h2d_ms"] / 1e3) / 1e9)
    assert bool(row["large"]) is True
    assert not bw[bw["bytes"] < (16 << 20)]["large"].any()
    assert "Эффективная ширина H2D" in (out / "summary.md").read_text(encoding="utf-8")
    # без GPU — пустая таблица и пояснение
    r2, out2 = run(tmp_path / "c", [REAL_CSV])
    assert pd.read_csv(out2 / "transfer_bw.csv").empty
    assert "Нет GPU-точек с разбивкой фаз" in (out2 / "summary.md").read_text(encoding="utf-8")


# ----------------------------------------------------------------------------------------------- стабильность
def test_stability_two_runs_spread_formula(tmp_path):
    base = G.build("normal")[0]
    other = base.copy()
    mask = (other["op"] == "sha3") & (other["backend"] == "cpu") & (other["object_size"] == 1024) & (other["count"] == 10)
    other.loc[mask, ["total_median_ms"]] = base.loc[mask, "total_median_ms"] * 1.5
    r, out = run(tmp_path, write(tmp_path, [base, other]))
    agg = r["agg"]
    pt = agg[(agg["op"] == "sha3") & (agg["backend"] == "cpu") & (agg["object_size"] == 1024) & (agg["count"] == 10)].iloc[0]
    t1 = float(base.loc[mask, "total_median_ms"].iloc[0])
    t2 = 1.5 * t1
    assert pt["n_runs"] == 2
    assert pt["total_ms"] == pytest.approx((t1 + t2) / 2)  # медиана двух значений
    assert pt["spread"] == pytest.approx((t2 - t1) / ((t1 + t2) / 2))
    text = (out / "summary.md").read_text(encoding="utf-8")
    assert "Стабильность медиан" in text and "90-й процентиль" in text
    assert "sha3" in text.split("Самые нестабильные точки")[1][:600]


def test_single_run_has_zero_spread_and_explanatory_note(tmp_path):
    r, out = run(tmp_path, write(tmp_path, G.build("normal")))
    assert (r["agg"]["spread"] == 0).all()
    assert "нужно ≥ 2 полных прогона" in (out / "summary.md").read_text(encoding="utf-8")


# ----------------------------------------------------------------------------------------------- устойчивость
def test_legacy_csv_without_entropy_columns(tmp_path):
    df = G.build("normal", legacy=True)[0]
    assert not any("entropy" in c for c in df.columns)
    r, _ = run(tmp_path, write(tmp_path, [df]))
    assert not r["speedup"].empty


def test_only_skipped_rows(tmp_path):
    df = G.build("normal", failed_gpu=True)[0]
    df = df[df["backend"] == "gpu"]
    r, out = run(tmp_path, write(tmp_path, [df]))
    assert r["speedup"].empty and r["crossover"].empty
    text = (out / "summary.md").read_text(encoding="utf-8")
    assert "GPU-данных в этом наборе нет" in text and "Нет пар" in text


def test_summary_and_tables_are_deterministic(tmp_path):
    csvs = write(tmp_path, G.build("normal", runs=2))
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    A.analyze(csvs, tmp_path / "a", plots=False)
    A.analyze(csvs, tmp_path / "b", plots=False)
    for name in ("summary.md", "speedup.csv", "crossover.csv"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes(), name


@pytest.mark.parametrize("scenario", ["normal", "gpu_slower", "nonmonotone", "no_ctx"])
def test_scenarios_produce_all_artifacts_and_valid_images(tmp_path, scenario):
    r, out = run(tmp_path, write(tmp_path, G.build(scenario, runs=2)), plots=True)
    pngs = list((out / "plots").glob("*.png"))
    assert len(pngs) >= 8
    for p in pngs:
        assert p.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n" and p.stat().st_size > 2000, p
    co = pd.read_csv(out / "crossover.csv")
    assert set(co["result"]) <= {"always", "never", "crossover", "crossover_down", "mixed", "insufficient"}
    for row in co.itertuples():
        if row.result in ("crossover", "crossover_down", "mixed"):
            assert math.isfinite(row.x_cross) and row.x_min <= row.x_cross <= row.x_max


@pytest.mark.parametrize("scenario", ["gpu_faster", "crossover", "crossover_above_range", "crossover_below_range"])
def test_remaining_scenarios_tables_only(tmp_path, scenario):
    r, out = run(tmp_path, write(tmp_path, G.build(scenario, runs=2)))
    co = pd.read_csv(out / "crossover.csv")
    assert set(co["result"]) <= {"always", "never", "crossover", "crossover_down", "mixed", "insufficient"}
    assert not co.empty


# ----------------------------------------------------------------------------------------------- ошибки входа
def test_bad_inputs_give_clear_errors(tmp_path):
    with pytest.raises(A.AnalysisError, match="не найден"):
        A.load_results([tmp_path / "nope.csv"])
    bad = tmp_path / "bad.csv"
    bad.write_text("a,b\n1,2\n")
    with pytest.raises(A.AnalysisError, match="нет столбцов"):
        A.load_results([bad])
    empty = tmp_path / "empty.csv"
    empty.write_text("")
    with pytest.raises(A.AnalysisError):
        A.load_results([empty])
    assert A.main([str(bad), "--out", str(tmp_path / "o")]) == 2
    assert A.main([str(REAL_CSV), "--out", str(tmp_path / "o2"), "--no-plots"]) == 0
    assert not (tmp_path / "o2" / "plots").exists() or not list((tmp_path / "o2" / "plots").glob("*.png"))
