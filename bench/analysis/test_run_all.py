"""Тесты scripts/gpu_run_all.sh в CPU-режиме (без nvcc/GPU): сценарий доходит до конца, GPU-шаги skipped,
сбой шага не останавливает следующие, архив собирается всегда, итог — RUN_SUMMARY.txt."""
from __future__ import annotations

import os
import re
import subprocess
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "gpu_run_all.sh"
DEFAULT_BUILD = os.environ.get("BUILD_DIR", str(ROOT / "build" / "cpu"))  # из ctest: каталог текущей сборки
REAL_VAULT = Path(DEFAULT_BUILD) / "vault"


def run_script(tmp_path: Path, *args, build_dir: str = DEFAULT_BUILD, **env):
    results = tmp_path / "results"
    e = dict(os.environ, SKIP_BUILD="1", SKIP_CTEST="1", RESULTS_ROOT=str(results), BUILD_DIR=build_dir, PYTHONWARNINGS="ignore")
    e.update({k: str(v) for k, v in env.items()})
    p = subprocess.run(["bash", str(SCRIPT), *args], cwd=ROOT, env=e, capture_output=True, text=True, timeout=600)
    runs = sorted(d for d in results.glob("*") if d.is_dir()) if results.exists() else []
    return p, (runs[-1] if runs else None), results


def statuses(run_dir: Path) -> dict[str, str]:
    out = {}
    for line in (run_dir / "RUN_SUMMARY.txt").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^(\d\w+)\s+(ok|fail|skipped)\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def build_type(build_dir: str) -> str:
    cache = Path(build_dir) / "CMakeCache.txt"
    if not cache.is_file():
        return ""
    for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("CMAKE_BUILD_TYPE:"):
            return line.split("=", 1)[1].strip()
    return ""


@pytest.mark.skipif(not REAL_VAULT.exists(), reason="нужна CPU-сборка build/cpu (scripts/build_cpu.sh)")
def test_cpu_mode_quick_run_reaches_the_end(tmp_path):
    p, run, results = run_script(tmp_path, "--quick")
    st = statuses(run)
    # Замеры годятся только из Release: на Debug-сборке (например, ASan) шаг 01a_flags обязан быть fail,
    # и тогда код возврата 1 — это правильное поведение, а не сбой сценария.
    release = build_type(DEFAULT_BUILD) == "Release"
    assert st["01a_flags"] == ("ok" if release else "fail")
    assert p.returncode == (0 if release else 1), p.stdout + p.stderr
    assert st["03a_smoke_cpu"] == "ok"
    assert st["03b_smoke_gpu"] == "skipped" and st["03c_smoke_gpu_to_cpu"] == "skipped"
    assert st["04_bench_quick"] == "ok" and st["06_analyze"] == "ok"
    assert st["05_bench_full"] == "skipped"
    # архив с результатами и анализом
    tars = list(results.glob("*.tar.gz"))
    assert len(tars) == 1
    names = tarfile.open(tars[0]).getnames()
    for part in ("RUN_SUMMARY.txt", "build.log", "env.txt", "results_quick.csv", "analysis/summary.md", "analysis/crossover.csv"):
        assert any(n.endswith(part) for n in names), part
    assert "GPU-данных в этом наборе нет" in (run / "analysis" / "summary.md").read_text(encoding="utf-8")


@pytest.mark.skipif(not REAL_VAULT.exists(), reason="нужна CPU-сборка build/cpu")
def test_repeated_runs_feed_stability_analysis(tmp_path):
    # --runs 2 без --quick запускает полный full.json (10 минут) — здесь проверяется только разбор аргументов
    p, run, _ = run_script(tmp_path, "--runs", "0")
    assert p.returncode == 64 and run is None


def test_bad_arguments(tmp_path):
    p, run, _ = run_script(tmp_path, "--nope")
    assert p.returncode == 64 and "неизвестный аргумент" in p.stderr


def test_missing_build_still_produces_summary_and_archive(tmp_path):
    p, run, results = run_script(tmp_path, "--quick", build_dir="build/does_not_exist")
    assert p.returncode != 0
    st = statuses(run)
    assert st["04_bench_quick"] == "skipped" and st["06_analyze"] == "skipped"
    assert len(list(results.glob("*.tar.gz"))) == 1  # архив — всегда




def test_failing_step_does_not_stop_later_steps(tmp_path):
    fake = tmp_path / "fake_build"
    fake.mkdir()
    (fake / "vault").write_text('#!/usr/bin/env bash\ncase "$*" in *benchmark*) echo "boom" >&2; exit 5;; esac\nexit 0\n')
    (fake / "vault").chmod(0o755)
    (fake / "CMakeCache.txt").write_text("")
    p, run, results = run_script(tmp_path, "--quick", build_dir=str(fake))
    assert p.returncode != 0
    st = statuses(run)
    assert st["04_bench_quick"] == "fail"       # benchmark упал
    assert st["06_analyze"] == "skipped"        # а анализ без CSV честно пропущен, а не упал
    assert "03a_smoke_cpu" in st                # шаги до и после сбоя выполнены
    assert "boom" in (run / "logs" / "04_bench_quick.log").read_text()
    assert len(list(results.glob("*.tar.gz"))) == 1


def test_march_native_is_flagged(tmp_path):
    fake = tmp_path / "fake_build"
    fake.mkdir()
    (fake / "vault").write_text("#!/usr/bin/env bash\nexit 0\n")
    (fake / "vault").chmod(0o755)
    (fake / "CMakeCache.txt").write_text("CMAKE_CXX_FLAGS:STRING=-O3 -march=native\n")
    p, run, _ = run_script(tmp_path, "--quick", build_dir=str(fake))
    assert statuses(run)["01a_flags"] == "fail"
    assert "march=native" in (run / "RUN_SUMMARY.txt").read_text(encoding="utf-8")
