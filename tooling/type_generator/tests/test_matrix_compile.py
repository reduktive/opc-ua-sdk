# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Unit tests for tooling.type_generator.matrix_compile (codegen-matrix P2).

Harness coverage - compile environments, bounded child execution, worker phases,
checkpoints and allowlist gating - without invoking a real compiler or generator.
One controlled Python child exercises bounded process-tree cleanup.

Standalone - no pytest dependency.  Invoke via:

    python -m tooling.type_generator.tests.test_matrix_compile
"""

from __future__ import annotations

import inspect
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

from .. import matrix_compile as matrix
from ..manifest import NS0_URI
from ..matrix_compile import (
    SpecResult,
    build_manifest,
    default_jobs,
    extract_compile_env,
    _include_dirs,
    load_allowlist,
    write_reports,
)

UA = "http://opcfoundation.org/UA/"


def _spec(slug: str, uri: str, *, sources, csv=None, lookups=()):
    return {
        "uri": uri,
        "slug": slug,
        "cpp_namespace": f"ua::{slug}",
        "include_prefix": f"ua_{slug}_",
        "target": f"ua_{slug}_types",
        "sources": list(sources),
        "nodeids_csv": csv,
        "lookup_specs": list(lookups),
    }


# -- worker budget -----------------------------------------------------------


def test_default_jobs_inherits_cmake_build_budget():
    assert default_jobs({"CMAKE_BUILD_PARALLEL_LEVEL": "8"}, cpu_count=32) == 8


def test_default_jobs_uses_all_local_cpus_without_build_budget():
    assert default_jobs({}, cpu_count=32) == 32


def test_default_jobs_rejects_non_positive_or_invalid_build_budget():
    assert default_jobs({"CMAKE_BUILD_PARALLEL_LEVEL": "0"}, cpu_count=12) == 12
    assert default_jobs({"CMAKE_BUILD_PARALLEL_LEVEL": "many"}, cpu_count=12) == 12


# -- extract_compile_env -----------------------------------------------------


def _write_cc(path: Path, entries) -> Path:
    path.write_text(json.dumps(entries), encoding="utf-8")
    return path


def test_extract_keeps_sdk_flags_drops_gen_and_noise(tmp_path: Path):
    cc = _write_cc(
        tmp_path / "compile_commands.json",
        [{
            "file": "/repo/build/tests/.../gen/di/data_types/ua_di_x.cpp",
            "arguments": [
                "/usr/bin/c++", "-std=gnu++20", "-DNDEBUG", "-Wall", "-Werror",
                "-I/repo/sdk/interface/core/types",
                "-I/repo/build/tests/.../gen/di/data_types",   # gen -> dropped
                "-isystem", "/opt/boost/include",
                "-isystem", "/repo/build/.../gen/di/object_types",  # gen -> dropped
                "-c", "-o", "x.o", "/repo/build/tests/.../gen/di/data_types/ua_di_x.cpp",
            ],
        }],
    )
    env = extract_compile_env(cc)
    assert env.compiler == "/usr/bin/c++"
    assert "-std=gnu++20" in env.base_flags
    assert "-DNDEBUG" in env.base_flags
    assert "-I/repo/sdk/interface/core/types" in env.base_flags
    # gen includes, warnings, output and source are all dropped.
    assert all("/gen/" not in f for f in env.base_flags)
    assert "-Wall" not in env.base_flags and "-Werror" not in env.base_flags
    assert "-c" not in env.base_flags and "-o" not in env.base_flags
    # -isystem pair to a non-gen dir is preserved together.
    assert "-isystem" in env.base_flags
    assert "/opt/boost/include" in env.base_flags


def test_extract_prefers_di_tu(tmp_path: Path):
    cc = _write_cc(
        tmp_path / "cc.json",
        [
            {"file": "/b/gen/pn/x.cpp", "arguments": ["c++", "-DPN", "-c", "/b/gen/pn/x.cpp"]},
            {"file": "/b/gen/di/y.cpp", "arguments": ["c++", "-DDI", "-c", "/b/gen/di/y.cpp"]},
        ],
    )
    env = extract_compile_env(cc)
    assert "-DDI" in env.base_flags  # the di TU was chosen


def test_extract_parses_command_string(tmp_path: Path):
    cc = _write_cc(
        tmp_path / "cc.json",
        [{"file": "/b/gen/di/z.cpp",
          "command": "/usr/bin/c++ -std=c++20 -I/sdk/inc -c /b/gen/di/z.cpp"}],
    )
    env = extract_compile_env(cc)
    assert env.compiler == "/usr/bin/c++"
    assert "-I/sdk/inc" in env.base_flags


def test_extract_errors_without_gen_tu(tmp_path: Path):
    cc = _write_cc(tmp_path / "cc.json",
                   [{"file": "/repo/sdk/foo.cpp", "arguments": ["c++", "-c"]}])
    try:
        extract_compile_env(cc)
        assert False, "expected SystemExit"
    except SystemExit:
        pass


# -- build_manifest ----------------------------------------------------------


def test_build_manifest_structure(tmp_path: Path):
    spec = _spec("ia", UA + "IA/", sources=["IA/Opc.Ua.IA.NodeSet2.xml"],
                 csv="IA/Opc.Ua.IA.NodeIds.csv",
                 lookups=[{
                     "uri": UA + "DI/", "slug": "di",
                     "cpp_namespace": "ua::di", "include_prefix": "ua_di_",
                     "nodeids_csv": "DI/Opc.Ua.Di.NodeIds.csv",
                     "sources": ["DI/Opc.Ua.Di.NodeSet2.xml"],
                 }])
    m = build_manifest(spec, tmp_path, instance_categories=["all"],
                       emit_event_types=False)
    ns = m["nodesets"]
    # NS0 first (emit=false), then the di lookup (emit=false), then ia (emit=true).
    assert ns[0]["uri"] == NS0_URI and ns[0]["emit"] is False
    assert ns[0]["nodeids_csv"].endswith("Schema/NodeIds.csv")
    assert ns[1]["uri"] == UA + "DI/" and ns[1]["emit"] is False
    assert ns[1]["target"] == "ua_di_lookup"
    assert ns[1]["sources"][0] == str(tmp_path / "DI/Opc.Ua.Di.NodeSet2.xml")
    emit = ns[-1]
    assert emit["uri"] == UA + "IA/" and emit["emit"] is True
    assert emit["instance_type_categories"] == ["all"]
    assert emit["emit_event_types"] is False
    assert emit["nodeids_csv"].endswith("IA/Opc.Ua.IA.NodeIds.csv")


def test_build_manifest_omits_absent_csv(tmp_path: Path):
    spec = _spec("nocsv", UA + "NoCsv/", sources=["x.NodeSet2.xml"], csv=None)
    emit = build_manifest(spec, tmp_path, instance_categories=[],
                          emit_event_types=True)["nodesets"][-1]
    assert "nodeids_csv" not in emit
    assert emit["emit_event_types"] is True
    assert emit["instance_type_categories"] == []


# -- _include_dirs -----------------------------------------------------------


def test_include_dirs_covers_subdirs(tmp_path: Path):
    (tmp_path / "data_types").mkdir()
    (tmp_path / "object_types").mkdir()
    flags = _include_dirs(tmp_path)
    assert f"-I{tmp_path}" in flags
    assert f"-I{tmp_path / 'data_types'}" in flags
    assert f"-I{tmp_path / 'object_types'}" in flags


# -- load_allowlist ----------------------------------------------------------


def test_load_allowlist(tmp_path: Path):
    f = tmp_path / "allow.txt"
    f.write_text("# header\n di \nmachinery\n\n  # comment\nia # inline\n",
                 encoding="utf-8")
    assert load_allowlist(f) == {"di", "machinery", "ia"}


def test_load_allowlist_missing_is_empty(tmp_path: Path):
    assert load_allowlist(tmp_path / "nope.txt") == set()
    assert load_allowlist(None) == set()


# -- write_reports / gating --------------------------------------------------


def _results():
    return [
        SpecResult("di", UA + "DI/", True, True, 28, ""),
        SpecResult("ia", UA + "IA/", True, False, 5, "ua_ia_x.cpp:\nerror: boom"),
        SpecResult("bad", UA + "B/", False, False, 0, "generation failed:\nx"),
    ]


def test_write_reports_counts_and_files(tmp_path: Path):
    passed, failed, regr = write_reports(_results(), tmp_path / "rep", set())
    assert (passed, failed, regr) == (1, 2, 0)
    data = json.loads((tmp_path / "rep.json").read_text())
    assert data["stats"]["passed"] == 1 and data["stats"]["failed"] == 2
    md = (tmp_path / "rep.md").read_text()
    assert "1/3 specs compile" in md
    assert "| di " in md


def test_write_reports_allowlist_regression_gates(tmp_path: Path):
    # ia is on the allowlist but failed -> counts as a regression.
    passed, failed, regr = write_reports(_results(), tmp_path / "r", {"di", "ia"})
    assert regr == 1
    data = json.loads((tmp_path / "r.json").read_text())
    assert data["regressions"] == ["ia"]


def test_write_reports_no_regression_when_failing_spec_not_listed(tmp_path: Path):
    _p, _f, regr = write_reports(_results(), tmp_path / "r", {"di"})
    assert regr == 0  # only di is gated, and di passed


def test_specresult_passed():
    assert SpecResult("a", "u", True, True, 1, "").passed is True
    assert SpecResult("a", "u", True, False, 1, "x").passed is False
    assert SpecResult("a", "u", False, False, 0, "x").passed is False


def test_incomplete_result_cannot_report_a_pass():
    result = SpecResult("a", "u", True, True, 1, "", incomplete=True)
    assert result.passed is False


def test_unlisted_incomplete_model_keeps_the_scan_incomplete(tmp_path: Path):
    results = [SpecResult("known", "u", True, True, 1, ""),
               SpecResult("unlisted", "v", True, False, 1, "timeout", incomplete=True)]
    passed, failed, regressions = write_reports(results, tmp_path / "partial", {"known"})
    data = json.loads((tmp_path / "partial.json").read_text())
    assert (passed, failed, regressions) == (1, 1, 0)
    assert data["scan_complete"] is False
    assert data["incomplete"] == ["unlisted"]


# -- bounded execution fixtures ----------------------------------------------


def _model(slug: str, *, lookups=()):
    return _spec(slug, UA + slug + "/", sources=[f"{slug}.NodeSet2.xml"],
                 lookups=lookups)


def _stage_result(spec, stage="compile", *, error="", incomplete=False):
    return SpecResult(spec["slug"], spec["uri"], stage != "generate" or not error,
                      stage == "compile" and not error, 1 if stage == "compile" else 0,
                      error, incomplete=incomplete, stage=stage)


def _matrix_run(tmp_path: Path, specs, *, jobs=2, only=None, **kwargs):
    return matrix.run_matrix(
        {"generatable": specs}, tmp_path / "nodesets",
        matrix.CompileEnv("never-run-c++", ["-std=c++20"], directory=str(tmp_path)),
        tmp_path / "output", tmp_path,
        instance_categories=["all"], emit_event_types=False, syntax_only=True,
        jobs=jobs, only=only, **kwargs,
    )


def _generate(tmp_path: Path, spec, **kwargs):
    return matrix.generate_spec(
        spec, tmp_path / "nodesets", tmp_path / "output",
        instance_categories=["all"], emit_event_types=False, repo_root=tmp_path,
        deadline=time.monotonic() + 5, stop=threading.Event(),
        logs_root=tmp_path / "logs", **kwargs,
    )


def _compile(tmp_path: Path, spec, *, env=None, **kwargs):
    if env is None:
        env = matrix.CompileEnv("never-run-c++", ["-std=c++20"], directory=str(tmp_path))
    return matrix.compile_spec(
        spec, tmp_path / "output", env, deadline=time.monotonic() + 5,
        stop=threading.Event(), logs_root=tmp_path / "logs", **kwargs,
    )


def _tu(tmp_path: Path, slug="di", name="model.cpp"):
    path = tmp_path / "output" / slug / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("int generated_value;\n", encoding="utf-8")
    return path


def _cli_args(tmp_path: Path, specs):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"generatable": specs}), encoding="utf-8")
    cc = _write_cc(tmp_path / "cc.json", [{
        "directory": str(tmp_path), "file": "/build/gen/di/model.cpp",
        "arguments": ["never-run-c++", "-std=c++20", "-c", "/build/gen/di/model.cpp"],
    }])
    return ["--plan", str(plan), "--root", str(tmp_path / "nodesets"),
            "--compile-commands", str(cc), "--out-dir", str(tmp_path / "output"),
            "--report", str(tmp_path / "report"), "--repo-root", str(tmp_path)]


def _main_status(argv):
    try:
        return matrix.main(argv)
    except SystemExit as ex:
        return ex.code if isinstance(ex.code, int) else 1


def _assert_rejected(action):
    try:
        action()
    except (SystemExit, ValueError, RuntimeError):
        return
    raise AssertionError("invalid configuration was accepted")


# -- compile-environment fidelity --------------------------------------------


def test_extract_preserves_split_options_and_define_undefine_order(tmp_path: Path):
    flags = ["-std=c++20", "-I", "/sdk/split include", "-D", "FEATURE=1",
             "-U", "FEATURE", "-DFEATURE=2", "-UOLD_FEATURE",
             "-isystem", "/deps/split", "-isystem/deps/joined"]
    cc = _write_cc(tmp_path / "cc.json", [{
        "file": "/build/gen/di/model.cpp", "directory": str(tmp_path),
        "arguments": ["c++", *flags, "-I", "/build/gen/di/data_types",
                      "-c", "/build/gen/di/model.cpp", "-o", "model.o"],
    }])
    env = extract_compile_env(cc)
    assert env.base_flags == flags


def test_extract_preserves_directory_provenance_and_relative_paths(tmp_path: Path):
    directory = tmp_path / "build"
    directory.mkdir()
    entry = {
        "directory": str(directory), "file": "gen/di/model.cpp",
        "arguments": ["../tools/c++", "-std=c++20", "-I../sdk/include",
                      "-I", "gen/di/data_types", "-isystem", "../deps/include",
                      "-c", "gen/di/model.cpp", "-o", "model.o"],
    }
    env = extract_compile_env(_write_cc(tmp_path / "cc.json", [entry]))
    assert Path(env.directory).resolve() == directory.resolve()
    assert env.source_entry == entry
    spec = _model("di")
    _tu(tmp_path)
    calls = []

    def child(command, *, cwd, log, deadline, stop):
        calls.append((command, Path(cwd)))
        return subprocess.CompletedProcess(command, 0, stdout="")

    with mock.patch.object(matrix, "_run_child", side_effect=child):
        result = _compile(tmp_path, spec, env=env)
    assert result.passed and len(calls) == 1
    command, cwd = calls[0]
    assert cwd.resolve() == directory.resolve()
    compiler = Path(command[0])
    assert (compiler if compiler.is_absolute() else cwd / compiler).resolve() == (
        tmp_path / "tools/c++").resolve()
    assert not any("gen/di/data_types" in token for token in command)
    assert any("sdk/include" in token for token in command)
    assert any("deps/include" in token for token in command)


def test_extract_keeps_semantic_flags_drops_only_compile_artifacts(tmp_path: Path):
    semantics = ["-std=c++20", "--target=aarch64-linux-gnu",
                 "--sysroot=/toolchain/sysroot", "-pthread", "-fno-exceptions",
                 "-fno-rtti", "-m32", "-fshort-wchar", "-fPIC",
                 "-include", "config.hpp", "-imacros", "macros.hpp"]
    cc = _write_cc(tmp_path / "cc.json", [{
        "file": "/build/gen/di/model.cpp", "directory": str(tmp_path),
        "arguments": ["c++", *semantics, "-O2", "-g", "-Wall", "-Werror",
                      "-MMD", "-MF", "model.d", "-MT", "model.o",
                      "-include", "/build/CMakeFiles/types.dir/cmake_pch.hxx",
                      "-c", "/build/gen/di/model.cpp", "-o", "model.o"],
    }])
    env = extract_compile_env(cc)
    assert env.base_flags == semantics


def test_extract_rejects_launchers_response_files_and_missing_operands(tmp_path: Path):
    for index, arguments in enumerate([
        ["ccache", "/usr/bin/c++", "-c", "/build/gen/di/model.cpp"],
        ["/usr/bin/c++", "@flags.rsp", "-c", "/build/gen/di/model.cpp"],
        ["/usr/bin/c++", "-I"],
        ["/usr/bin/c++", "-D"],
        ["/usr/bin/c++", "-c", "/different/source.cpp"],
    ]):
        cc = _write_cc(tmp_path / f"cc-{index}.json", [{
            "file": "/build/gen/di/model.cpp", "arguments": arguments,
        }])
        _assert_rejected(lambda: extract_compile_env(cc))


def test_include_dirs_is_complete_and_deterministic(tmp_path: Path):
    for relative in ["zeta/nested", "alpha", "middle/inner"]:
        (tmp_path / relative).mkdir(parents=True)
    first = _include_dirs(tmp_path)
    second = _include_dirs(tmp_path)
    expected = {f"-I{tmp_path}", *(f"-I{path}" for path in tmp_path.rglob("*") if path.is_dir())}
    assert set(first) == expected and len(first) == len(expected)
    assert second == first == [f"-I{tmp_path}", *sorted(expected - {f"-I{tmp_path}"})]


# -- completed diagnostics versus incomplete workers -------------------------


def test_specresult_new_fields_keep_existing_constructor_compatible():
    result = SpecResult("di", "uri", True, True, 2, "")
    assert result.passed and not result.incomplete
    assert result.stage == "" and result.duration_seconds == 0.0


def test_generation_success_and_completed_diagnostic_failure(tmp_path: Path):
    spec = _model("di")
    with mock.patch.object(matrix, "_run_child", return_value=subprocess.CompletedProcess(
            ["python"], 0, stdout="generation complete")):
        success = _generate(tmp_path, spec)
    assert success.generated and not success.incomplete
    assert "generat" in success.stage and success.duration_seconds >= 0
    with mock.patch.object(matrix, "_run_child", return_value=subprocess.CompletedProcess(
            ["python"], 1, stdout="unknown node model diagnostic")):
        failed = _generate(tmp_path, spec)
    assert not failed.generated and not failed.compiled and not failed.incomplete
    assert "unknown node model diagnostic" in failed.error


def test_compile_diagnostic_is_a_completed_model_failure(tmp_path: Path):
    spec = _model("di")
    _tu(tmp_path)
    with mock.patch.object(matrix, "_run_child", return_value=subprocess.CompletedProcess(
            ["c++"], 1, stdout="model.cpp: error: missing generated declaration")):
        result = _compile(tmp_path, spec)
    assert result.generated and not result.compiled and not result.incomplete
    assert result.tus == 1 and "missing generated declaration" in result.error
    assert "model.cpp" in result.error and "compil" in result.stage


def test_signal_timeout_spawn_and_unexpected_errors_are_incomplete(tmp_path: Path):
    spec = _model("di")
    cases = [subprocess.CompletedProcess(["tool"], -signal.SIGTERM, stdout="signal terminated"),
             subprocess.TimeoutExpired(["tool"], 1, output="deadline expired"),
             FileNotFoundError("tool is not installed"),
             RuntimeError("unexpected worker failure")]
    for index, outcome in enumerate(cases):
        for stage in ("generate", "compile"):
            if stage == "compile":
                _tu(tmp_path)
            patch = (mock.patch.object(matrix, "_run_child", side_effect=outcome)
                     if isinstance(outcome, Exception) else
                     mock.patch.object(matrix, "_run_child", return_value=outcome))
            with patch as supervisor:
                result = (_generate(tmp_path, spec) if stage == "generate" else
                          _compile(tmp_path, spec))
            assert supervisor.call_count == 1, (index, stage)
            assert result.incomplete and not result.passed, (index, stage, result)
            assert result.error and stage[:5] in result.stage
            assert result.duration_seconds >= 0


def test_positive_driver_resource_and_internal_failures_are_incomplete(tmp_path: Path):
    spec = _model("di")
    _tu(tmp_path)
    for diagnostic in [
        "c++: fatal error: Killed signal terminated program cc1plus",
        "clang: error: clang frontend command failed due to signal",
        "internal compiler error: Segmentation fault",
        "LLVM ERROR: out of memory",
    ]:
        with mock.patch.object(matrix, "_run_child", return_value=subprocess.CompletedProcess(
                ["c++"], 1, stdout=diagnostic)):
            result = _compile(tmp_path, spec)
        assert result.incomplete and not result.passed, diagnostic
        assert diagnostic in result.error


def test_phase_tu_commands_cwd_and_logs_are_retained(tmp_path: Path):
    spec = _model("di")
    calls = []

    def child(command, *, cwd, log, deadline, stop):
        log = Path(log)
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(json.dumps(command) + "\nretained successful output\n", encoding="utf-8")
        calls.append((command, Path(cwd), log, deadline, stop))
        return subprocess.CompletedProcess(command, 0, stdout="retained successful output")

    with mock.patch.object(matrix, "_run_child", side_effect=child):
        generated = _generate(tmp_path, spec)
        first = _tu(tmp_path, name="a.cpp")
        second = _tu(tmp_path, name="nested/z.cpp")
        compiled = _compile(tmp_path, spec, syntax_only=False)
    assert generated.generated and compiled.passed and compiled.tus == 2
    assert len(calls) == 3 and len({call[2] for call in calls}) == 3
    assert calls[0][0][:4] == [sys.executable, "-u", "-m", matrix._GENERATOR_MODULE]
    assert "--manifest" in calls[0][0] and "--output" in calls[0][0]
    assert [Path(call[0][-1]) for call in calls[1:]] == [first, second]
    for command, cwd, log, deadline, stop in calls:
        assert cwd == tmp_path
        assert tmp_path / "logs" in log.parents and "di" in str(log)
        assert "retained successful output" in log.read_text()
        assert isinstance(stop, threading.Event) and deadline > 0
    for command, *_rest in calls[1:]:
        assert "-c" in command and command[command.index("-o") + 1] == os.devnull
        assert "-fsyntax-only" not in command


# -- coordinator progress and bounded shutdown -------------------------------


def test_initial_and_completion_checkpoints_do_not_wait_for_first_input(tmp_path: Path):
    specs = [_model("slow"), _model("fast")]
    first_waiting = threading.Event()
    release_first = threading.Event()
    initial_written = threading.Event()
    fast_checkpointed = threading.Event()
    coordinator = threading.get_ident()
    snapshots = []
    real_write = matrix.write_reports

    def checkpoint(results, report_stem, allowlist, **kwargs):
        assert threading.get_ident() == coordinator, "workers must not write shared reports"
        answer = real_write(results, report_stem, allowlist, **kwargs)
        data = json.loads(report_stem.with_suffix(".json").read_text())
        rows = {row["slug"]: row for row in data["results"]}
        assert set(rows) == {"slow", "fast"} and len(data["results"]) == 2
        snapshots.append(data)
        if len(snapshots) == 1:
            assert not data["scan_complete"] and data["stats"]["incomplete"] == 2
            initial_written.set()
        if rows["fast"]["generated"] and not rows["slow"]["generated"]:
            assert not data["scan_complete"]
            fast_checkpointed.set()
            release_first.set()
        return answer

    def generate(spec, *_args, **_kwargs):
        assert initial_written.is_set(), "initial coverage checkpoint must precede child work"
        if spec["slug"] == "slow":
            first_waiting.set()
            assert release_first.wait(2), "later completion was hidden behind the first input"
        else:
            assert first_waiting.wait(2)
        return _stage_result(spec, "generate")

    try:
        with mock.patch.object(matrix, "generate_spec", side_effect=generate), \
                mock.patch.object(matrix, "compile_spec", side_effect=lambda spec, *_a, **_kw:
                                  _stage_result(spec)), \
                mock.patch.object(matrix, "write_reports", side_effect=checkpoint):
            results = _matrix_run(tmp_path, specs, report_stem=tmp_path / "progress",
                                  allowlist=set(), deadline=time.monotonic() + 5)
    finally:
        release_first.set()
    assert fast_checkpointed.is_set()
    assert len(results) == 2 and all(result.passed for result in results)
    assert len(snapshots) >= 4 and snapshots[-1]["scan_complete"]


def test_generation_barrier_precedes_every_compilation(tmp_path: Path):
    specs = [_model("first"), _model("second"), _model("third")]
    generated = set()
    lock = threading.Lock()
    compiled = []

    def generate(spec, *_args, **_kwargs):
        with lock:
            generated.add(spec["slug"])
        return _stage_result(spec, "generate")

    def compile_model(spec, *_args, **_kwargs):
        with lock:
            assert generated == {"first", "second", "third"}
            compiled.append(spec["slug"])
        return _stage_result(spec)

    with mock.patch.object(matrix, "generate_spec", side_effect=generate), \
            mock.patch.object(matrix, "compile_spec", side_effect=compile_model):
        results = _matrix_run(tmp_path, specs)
    assert set(compiled) == generated and len(compiled) == 3
    assert all(result.passed for result in results)


def test_worker_budget_caps_both_phases_including_worker_failure(tmp_path: Path):
    specs = [_model(f"spec{index}") for index in range(5)]
    lock = threading.Lock()
    first_pair = threading.Event()
    active = 0
    peak = 0
    generation_entries = 0

    def work(spec, *_args, stage, **_kwargs):
        nonlocal active, peak, generation_entries
        with lock:
            active += 1
            peak = max(peak, active)
            if stage == "generate":
                generation_entries += 1
                wait_for_pair = generation_entries <= 2
                if generation_entries == 2:
                    first_pair.set()
            else:
                wait_for_pair = False
        try:
            if wait_for_pair:
                assert first_pair.wait(2), "configured second worker did not start"
            if stage == "generate" and spec["slug"] == "spec0":
                raise OSError("controlled worker infrastructure failure")
            return _stage_result(spec, stage)
        finally:
            with lock:
                active -= 1

    with mock.patch.object(matrix, "generate_spec", side_effect=lambda *a, **kw:
                           work(*a, stage="generate", **kw)), \
            mock.patch.object(matrix, "compile_spec", side_effect=lambda *a, **kw:
                              work(*a, stage="compile", **kw)):
        results = _matrix_run(tmp_path, specs, jobs=2)
    assert active == 0 and peak == 2
    assert len(results) == 5 and len({result.slug for result in results}) == 5
    by_slug = {result.slug: result for result in results}
    assert by_slug["spec0"].incomplete and all(by_slug[f"spec{i}"].passed for i in range(1, 5))


def test_global_deadline_keeps_queued_rows_and_prevents_late_passes(tmp_path: Path):
    specs = [_model("first"), _model("queued"), _model("last")]
    clock = [1.0]
    entries = []
    stops = []

    def generate(spec, *_args, **kwargs):
        entries.append(spec["slug"])
        stops.append(kwargs["stop"])
        clock[0] = 20.0
        return _stage_result(spec, "generate")

    with mock.patch.object(matrix.time, "monotonic", side_effect=lambda: clock[0]), \
            mock.patch.object(matrix, "generate_spec", side_effect=generate), \
            mock.patch.object(matrix, "compile_spec") as compile_model:
        results = _matrix_run(tmp_path, specs, jobs=1, deadline=10.0,
                              report_stem=tmp_path / "expired", allowlist=set())
    assert entries == ["first"], "queued work started after the global deadline"
    assert stops and all(stop.is_set() for stop in stops)
    compile_model.assert_not_called()
    assert {result.slug for result in results} == {"first", "queued", "last"}
    assert all(result.incomplete and not result.passed for result in results)
    data = json.loads((tmp_path / "expired.json").read_text())
    assert not data["scan_complete"] and data["stats"]["incomplete"] == 3


def test_deadline_collects_active_compile_details_after_workers_stop(tmp_path: Path):
    specs = [_model("first"), _model("second"), _model("queued")]
    clock = [1.0]
    entries = []
    stops = []
    lock = threading.Lock()
    real_wait = matrix.concurrent.futures.wait

    def generate(spec, *_args, **_kwargs):
        return SpecResult(spec["slug"], spec["uri"], True, False, 0, "",
                          stage="generation", duration_seconds=2.0)

    def compile_model(spec, *_args, **kwargs):
        with lock:
            entries.append(spec["slug"])
            stops.append(kwargs["stop"])
        assert kwargs["stop"].wait(2), "active worker was not signalled at deadline"
        index = 0 if spec["slug"] == "first" else 1
        return SpecResult(spec["slug"], spec["uri"], True, False, 7 + index,
                          f"TimeoutExpired: {spec['slug']}; child cleanup also failed",
                          incomplete=True, stage="compilation", duration_seconds=4.0 + index)

    def wait(active, **kwargs):
        answer = real_wait(active, timeout=0.01,
                           return_when=kwargs["return_when"])
        with lock:
            if len(entries) == 2 and not answer[0]:
                clock[0] = 20.0
                stops[0].set()
        return answer

    with mock.patch.object(matrix.time, "monotonic", side_effect=lambda: clock[0]), \
            mock.patch.object(matrix, "generate_spec", side_effect=generate), \
            mock.patch.object(matrix, "compile_spec", side_effect=compile_model), \
            mock.patch.object(matrix.concurrent.futures, "wait", side_effect=wait):
        results = _matrix_run(tmp_path, specs, jobs=2, deadline=10.0,
                              report_stem=tmp_path / "drained", allowlist={"first", "second", "queued"})
    assert set(entries) == {"first", "second"}, "queued compilation started after stop"
    assert all(stop.is_set() for stop in stops)
    rows = {result.slug: result for result in results}
    for index, slug in enumerate(("first", "second")):
        result = rows[slug]
        assert result.incomplete and not result.passed
        assert result.generated and not result.compiled
        assert result.stage == "compilation", "active compilation receipt was discarded"
        assert result.tus == 7 + index
        assert result.duration_seconds == 6.0 + index
        assert "global deadline or interruption" in result.error
        assert f"TimeoutExpired: {slug}; child cleanup also failed" in result.error
    assert rows["queued"].stage == "awaiting compilation" and rows["queued"].tus == 0
    data = json.loads((tmp_path / "drained.json").read_text())
    assert not data["scan_complete"] and data["stats"]["incomplete"] == 3
    assert data["stats"]["regressions"] == 3
    assert {row["slug"]: row["error"] for row in data["results"]} == {
        slug: result.error for slug, result in rows.items()}


def test_unexpected_worker_exception_retains_all_rows_and_reports(tmp_path: Path):
    specs = [_model("broken"), _model("healthy")]

    for broken_phase in ("generation", "compilation"):
        def work(spec, *, phase):
            if spec["slug"] == "broken" and phase == broken_phase:
                error = RuntimeError("controlled unexpected worker exception")
                error.add_note("controlled cleanup failure")
                raise error
            return SpecResult(spec["slug"], spec["uri"], True, phase == "compilation", 0, "",
                              stage=phase, duration_seconds=2.0)

        report = tmp_path / broken_phase
        with mock.patch.object(matrix, "generate_spec", side_effect=lambda spec, *_a, **_kw:
                               work(spec, phase="generation")), \
                mock.patch.object(matrix, "compile_spec", side_effect=lambda spec, *_a, **_kw:
                                  work(spec, phase="compilation")):
            results = _matrix_run(tmp_path, specs, report_stem=report, allowlist=set())
        rows = {result.slug: result for result in results}
        assert len(results) == 2 and rows["healthy"].passed
        assert rows["broken"].incomplete and "controlled unexpected worker exception" in rows["broken"].error
        assert "controlled cleanup failure" in rows["broken"].error
        assert rows["broken"].stage == broken_phase
        assert rows["broken"].duration_seconds == (2.0 if broken_phase == "compilation" else 0.0)
        assert not json.loads(report.with_suffix(".json").read_text())["scan_complete"]


def test_interruption_signals_active_workers_and_writes_incomplete_report(tmp_path: Path):
    specs = [_model("interrupt"), _model("waiting"), _model("queued")]
    waiting = threading.Event()
    stopped = threading.Event()

    def generate(spec, *_args, **kwargs):
        if spec["slug"] == "interrupt":
            assert waiting.wait(2)
            raise KeyboardInterrupt("controlled interrupt")
        if spec["slug"] == "waiting":
            waiting.set()
            assert kwargs["stop"].wait(2), "coordinator waited without signalling the active worker"
            stopped.set()
            return SpecResult(spec["slug"], spec["uri"], True, False, 0,
                              "interrupted child; child cleanup also failed", incomplete=True,
                              stage="generation", duration_seconds=7.0)
        return _stage_result(spec, "generate", error="interrupted", incomplete=True)

    started = time.monotonic()
    with mock.patch.object(matrix, "generate_spec", side_effect=generate), \
            mock.patch.object(matrix, "compile_spec") as compile_model:
        status = _main_status(_cli_args(tmp_path, specs) + ["--jobs", "2", "--timeout-seconds", "5"])
    assert status != 0 and stopped.is_set()
    assert time.monotonic() - started < 5
    compile_model.assert_not_called()
    data = json.loads((tmp_path / "report.json").read_text())
    assert not data["scan_complete"] and len(data["results"]) == 3
    assert {row["slug"] for row in data["results"]} == {"interrupt", "waiting", "queued"}
    assert data["stats"]["incomplete"] == 3
    rows = {row["slug"]: row for row in data["results"]}
    assert rows["waiting"]["stage"] == "generation"
    assert rows["waiting"]["duration_seconds"] == 7.0
    assert "interrupted child; child cleanup also failed" in rows["waiting"]["error"]
    assert "KeyboardInterrupt: controlled interrupt" in rows["interrupt"]["error"]


def test_checkpoint_failure_does_not_collect_a_completed_worker_twice(tmp_path: Path):
    specs = [_model("finished"), _model("queued")]
    failed = False
    real_write = matrix.write_reports

    def checkpoint(results, report_stem, allowlist, **kwargs):
        nonlocal failed
        if any(result.compiled for result in results) and not failed:
            failed = True
            raise OSError("controlled report write failure")
        return real_write(results, report_stem, allowlist, **kwargs)

    with mock.patch.object(matrix, "generate_spec", side_effect=lambda spec, *_a, **_kw:
                           SpecResult(spec["slug"], spec["uri"], True, False, 0, "",
                                      stage="generation", duration_seconds=2.0)), \
            mock.patch.object(matrix, "compile_spec", side_effect=lambda spec, *_a, **_kw:
                              SpecResult(spec["slug"], spec["uri"], True, True, 7, "",
                                         stage="compilation", duration_seconds=4.0)) as compile_model, \
            mock.patch.object(matrix, "write_reports", side_effect=checkpoint):
        results = _matrix_run(tmp_path, specs, jobs=1, report_stem=tmp_path / "report-error")
    assert failed and compile_model.call_count == 1
    rows = {result.slug: result for result in results}
    assert rows["finished"].passed and rows["finished"].duration_seconds == 6.0
    assert rows["queued"].incomplete and not rows["queued"].passed
    data = json.loads((tmp_path / "report-error.json").read_text())
    assert not data["scan_complete"]
    assert "controlled report write failure" in data["metadata"]["error"]


def test_run_matrix_rejects_invalid_worker_budget_before_starting(tmp_path: Path):
    with mock.patch.object(matrix, "generate_spec") as generate, \
            mock.patch.object(matrix, "compile_spec") as compile_model:
        for jobs in (0, -1):
            _assert_rejected(lambda: _matrix_run(tmp_path, [_model("di")], jobs=jobs))
    generate.assert_not_called()
    compile_model.assert_not_called()


# -- output freshness and diagnostic subsets ---------------------------------


def test_regeneration_removes_stale_outputs_and_preserves_other_models(tmp_path: Path):
    spec = _model("di")
    old_cpp = _tu(tmp_path, name="obsolete.cpp")
    old_header = old_cpp.with_suffix(".h")
    old_header.write_text("obsolete declaration", encoding="utf-8")
    (old_cpp.parent / "_manifest.json").write_text(json.dumps(build_manifest(
        spec, tmp_path / "nodesets", instance_categories=["all"], emit_event_types=False)),
        encoding="utf-8")
    neighbour = _tu(tmp_path, slug="other", name="keep.cpp")
    compiled_commands = []

    def child(command, **_kwargs):
        if "--manifest" in command:
            assert not old_cpp.exists() and not old_header.exists()
            _tu(tmp_path, name="fresh.cpp")
        else:
            compiled_commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="")

    with mock.patch.object(matrix, "_run_child", side_effect=child):
        generated = _generate(tmp_path, spec)
        compiled = _compile(tmp_path, spec)
    assert generated.generated and compiled.passed
    assert neighbour.exists() and not old_cpp.exists() and not old_header.exists()
    assert len(compiled_commands) == 1 and Path(compiled_commands[0][-1]).name == "fresh.cpp"


def test_regeneration_rejects_paths_outside_owned_model_output(tmp_path: Path):
    outside = tmp_path / "precious"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("must survive", encoding="utf-8")
    for slug in ("../precious", str(outside.resolve())):
        with mock.patch.object(matrix, "_run_child") as child:
            try:
                result = _generate(tmp_path, _model(slug))
            except (SystemExit, ValueError, RuntimeError):
                pass
            else:
                assert result.incomplete and not result.passed
            child.assert_not_called()
        assert sentinel.read_text() == "must survive"


def test_only_dependent_generates_transitive_planned_lookup_closure(tmp_path: Path):
    base = _model("base")
    middle = _model("middle", lookups=[base])
    leaf = _model("leaf", lookups=[middle])
    other = _model("other")
    generated = []
    compiled = []

    def generate(spec, *_args, **_kwargs):
        generated.append(spec["slug"])
        _tu(tmp_path, slug=spec["slug"], name="support.cpp")
        return _stage_result(spec, "generate")

    def compile_model(spec, *_args, **_kwargs):
        assert set(generated) == {"base", "middle", "leaf"}
        assert (tmp_path / "output/base/support.cpp").is_file()
        assert (tmp_path / "output/middle/support.cpp").is_file()
        compiled.append(spec["slug"])
        return _stage_result(spec)

    with mock.patch.object(matrix, "generate_spec", side_effect=generate), \
            mock.patch.object(matrix, "compile_spec", side_effect=compile_model):
        results = _matrix_run(tmp_path, [leaf, other, middle, base], only={"leaf"},
                              report_stem=tmp_path / "subset", allowlist=set())
    assert set(generated) == {"base", "middle", "leaf"} and len(generated) == 3
    assert set(compiled) == {"base", "middle", "leaf"} and len(compiled) == 3
    assert {row.slug for row in results} == {"base", "middle", "leaf"}
    data = json.loads((tmp_path / "subset.json").read_text())
    assert not data["scan_complete"] and data["metadata"]["partial"]


def test_stale_unplanned_lookup_never_enters_current_compile_flags(tmp_path: Path):
    planned = _model("planned")
    unplanned = _model("unplanned")
    leaf = _model("leaf", lookups=[planned, unplanned])
    stale_root = tmp_path / "output/unplanned"
    stale_header = stale_root / "data_types/stale.h"
    stale_header.parent.mkdir(parents=True)
    stale_header.write_text("stale declaration from an earlier plan\n", encoding="utf-8")
    generation_lookups = {}
    compile_commands = []

    def child(command, **_kwargs):
        if "--manifest" in command:
            manifest_path = Path(command[command.index("--manifest") + 1])
            output = Path(command[command.index("--output") + 1])
            manifest = json.loads(manifest_path.read_text())
            generation_lookups[output.name] = [entry["uri"] for entry in manifest["nodesets"]
                                                if not entry["emit"]]
            _tu(tmp_path, slug=output.name, name="generated.cpp")
            if output.name == "planned":
                current_header = output / "data_types/current.h"
                current_header.parent.mkdir()
                current_header.write_text("fresh planned declaration\n", encoding="utf-8")
        else:
            compile_commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="")

    # Exercise the actual generation, coordinator and compilation functions. Only child execution is
    # replaced, so the assertion observes the compiler command rather than a copied filtering rule.
    with mock.patch.object(matrix, "_run_child", side_effect=child) as supervisor:
        results = _matrix_run(tmp_path, [planned, leaf], only={"leaf"})
    assert supervisor.call_count == 4
    assert set(generation_lookups) == {"planned", "leaf"}
    assert generation_lookups["leaf"] == [NS0_URI, planned["uri"], unplanned["uri"]]
    assert [dep["slug"] for dep in leaf["lookup_specs"]] == ["planned", "unplanned"]
    assert {result.slug for result in results} == {"planned", "leaf"}
    assert all(result.passed and not result.incomplete for result in results)
    assert len(compile_commands) == 2
    leaf_command = next(command for command in compile_commands if Path(command[-1]).parent.name == "leaf")
    assert f"-I{tmp_path / 'output/planned'}" in leaf_command
    assert f"-I{tmp_path / 'output/planned/data_types'}" in leaf_command
    for command in compile_commands:
        assert f"-I{stale_root}" not in command
        assert f"-I{stale_header.parent}" not in command
    assert stale_header.read_text() == "stale declaration from an earlier plan\n"


def test_subset_does_not_generate_unplanned_lookup_or_unknown_slug(tmp_path: Path):
    missing = _model("skipped_dependency")
    leaf = _model("leaf", lookups=[missing])
    with mock.patch.object(matrix, "generate_spec") as generate:
        for specs, only in [([_model("di")], {"typo"}), ([_model("di")], set())]:
            try:
                results = _matrix_run(tmp_path, specs, only=only)
            except (SystemExit, ValueError, RuntimeError):
                pass
            else:
                assert results and all(row.incomplete for row in results)
    generate.assert_not_called()
    with mock.patch.object(matrix, "generate_spec", side_effect=lambda spec, *_a, **_kw:
                           _stage_result(spec, "generate")) as generate, \
            mock.patch.object(matrix, "compile_spec", side_effect=lambda spec, *_a, **_kw:
                              _stage_result(spec)):
        results = _matrix_run(tmp_path, [leaf], only={"leaf"})
    assert [call.args[0]["slug"] for call in generate.call_args_list] == ["leaf"]
    assert [row.slug for row in results] == ["leaf"]


# -- complete reports and CLI qualification ----------------------------------


def test_reports_require_exact_coverage_and_a_finished_scan(tmp_path: Path):
    good = SpecResult("di", "uri", True, True, 1, "")
    extra = SpecResult("extra", "uri:extra", True, True, 1, "")
    cases = [([good], ["di", "missing"], True, {}),
             ([good, good], ["di"], True, {}),
             ([good, extra], ["di"], True, {}),
             ([good], ["di", "di"], True, {}),
             ([good], ["di"], False, {}),
             ([good], ["di"], True, {"partial": True}),
             ([good], ["di"], True, {"error": "interrupted coordinator"})]
    for index, (rows, expected, finished, metadata) in enumerate(cases):
        stem = tmp_path / f"coverage-{index}"
        write_reports(rows, stem, set(), expected_slugs=expected,
                      scan_finished=finished, metadata=metadata)
        data = json.loads(stem.with_suffix(".json").read_text())
        assert data["scan_complete"] is False, (index, data)
        assert "incomplete" in data and "incomplete" in data["stats"]
        assert data["expected_slugs"] == expected
        for key, value in metadata.items():
            assert data["metadata"][key] == value
    write_reports([good], tmp_path / "complete", {"di"}, expected_slugs=["di"],
                  metadata={"compiler": "retained-c++", "jobs": 2})
    complete = json.loads((tmp_path / "complete.json").read_text())
    assert complete["scan_complete"] and complete["stats"]["incomplete"] == 0
    assert complete["metadata"] == {"compiler": "retained-c++", "jobs": 2}


def test_incomplete_report_retains_stage_duration_and_diagnostics(tmp_path: Path):
    rows = [SpecResult("unlisted", "uri", True, False, 3, "b.cpp: deadline; logs/unlisted/b.log",
                       incomplete=True, stage="compile", duration_seconds=1.25)]
    counts = write_reports(rows, tmp_path / "incomplete", set(), expected_slugs=["unlisted"])
    data = json.loads((tmp_path / "incomplete.json").read_text())
    assert counts == (0, 1, 0) and data["stats"]["incomplete"] == 1
    assert data["incomplete"] == ["unlisted"] and not data["scan_complete"]
    assert data["results"][0]["duration_seconds"] == 1.25
    assert data["results"][0]["stage"] == "compile"
    assert data["results"][0]["error"] == rows[0].error
    assert "unlisted" in (tmp_path / "incomplete.md").read_text()


def test_report_atomic_replacement_preserves_last_valid_json_on_error(tmp_path: Path):
    stem = tmp_path / "atomic"
    old = SpecResult("di", "uri", True, False, 1, "original diagnostic")
    write_reports([old], stem, set(), expected_slugs=["di"])
    previous = stem.with_suffix(".json").read_bytes()
    with mock.patch.object(matrix.os, "replace", side_effect=OSError("controlled replace failure")):
        try:
            write_reports([SpecResult("di", "uri", True, True, 1, "")], stem, set(),
                          expected_slugs=["di"])
        except OSError:
            pass
        else:
            raise AssertionError("report replacement failure was silently accepted")
    assert stem.with_suffix(".json").read_bytes() == previous
    assert json.loads(previous)["results"][0]["error"] == "original diagnostic"


def test_cli_completed_unlisted_failure_remains_allow_fail(tmp_path: Path):
    specs = [_model("known"), _model("unlisted")]
    rows = [_stage_result(specs[0]), _stage_result(specs[1], error="ordinary completed model diagnostic")]
    allowlist = tmp_path / "allow.txt"
    allowlist.write_text("known\n", encoding="utf-8")
    with mock.patch.object(matrix, "run_matrix", return_value=rows) as run:
        status = _main_status(_cli_args(tmp_path, specs) + ["--allowlist", str(allowlist)])
    assert status == 0 and run.call_count == 1
    data = json.loads((tmp_path / "report.json").read_text())
    assert data["scan_complete"] and data["regressions"] == []
    assert data["stats"]["failed"] == 1 and data["stats"]["incomplete"] == 0


def test_cli_unlisted_timeout_and_allowlisted_completed_failure_both_fail(tmp_path: Path):
    specs = [_model("known"), _model("unlisted")]
    allowlist = tmp_path / "allow.txt"
    allowlist.write_text("known\n", encoding="utf-8")
    cases = [[_stage_result(specs[0]),
              _stage_result(specs[1], error="unlisted deadline expired", incomplete=True)],
             [_stage_result(specs[0], error="known model compile diagnostic"),
              _stage_result(specs[1])]]
    for rows in cases:
        with mock.patch.object(matrix, "run_matrix", return_value=rows):
            status = _main_status(_cli_args(tmp_path, specs) + ["--allowlist", str(allowlist)])
        assert status != 0
        data = json.loads((tmp_path / "report.json").read_text())
        if rows[1].incomplete:
            assert not data["scan_complete"] and data["regressions"] == []
            assert data["incomplete"] == ["unlisted"]
        else:
            assert data["scan_complete"] and data["regressions"] == ["known"]


def test_cli_deadline_after_final_completion_preserves_coordinator_failure(tmp_path: Path):
    spec = _model("di")
    clock = [100.0]
    real_write = matrix.write_reports

    def checkpoint(rows, *args, **kwargs):
        counts = real_write(rows, *args, **kwargs)
        if rows and all(row.passed for row in rows):
            clock[0] = 200.0
        return counts

    with mock.patch.object(matrix.time, "monotonic", side_effect=lambda: clock[0]), \
            mock.patch.object(matrix, "generate_spec", side_effect=lambda model, *_a, **_kw:
                              _stage_result(model, "generate")), \
            mock.patch.object(matrix, "compile_spec", side_effect=lambda model, *_a, **_kw:
                              _stage_result(model)), \
            mock.patch.object(matrix, "write_reports", side_effect=checkpoint):
        status = _main_status(_cli_args(tmp_path, [spec]) + ["--timeout-seconds", "5"])
    data = json.loads((tmp_path / "report.json").read_text())
    assert status != 0 and not data["scan_complete"]
    assert data["metadata"]["error"]
    assert len(data["results"]) == 1 and data["results"][0]["compiled"]
    assert data["stats"]["incomplete"] == 0


def test_cli_rejects_nonpositive_nonfinite_and_invalid_budgets(tmp_path: Path):
    base = _cli_args(tmp_path, [_model("di")])
    invalid = [["--jobs", "0"], ["--jobs", "-2"], ["--jobs", "1.5"],
               ["--timeout-seconds=0"], ["--timeout-seconds=-1"],
               ["--timeout-seconds=nan"], ["--timeout-seconds=inf"],
               ["--timeout-seconds=-inf"], ["--timeout-seconds=invalid"]]
    with mock.patch.object(matrix, "run_matrix") as run:
        for arguments in invalid:
            assert _main_status(base + arguments) != 0, arguments
    run.assert_not_called()


def test_cli_accepts_positive_budget_and_passes_a_finite_deadline(tmp_path: Path):
    spec = _model("di")
    now = time.monotonic()
    with mock.patch.object(matrix, "run_matrix", return_value=[_stage_result(spec)]) as run:
        status = _main_status(_cli_args(tmp_path, [spec]) +
                              ["--jobs", "3", "--timeout-seconds", "12.5"])
    assert status == 0 and run.call_count == 1
    assert run.call_args.kwargs["jobs"] == 3
    assert now + 12 <= run.call_args.kwargs["deadline"] <= time.monotonic() + 12.5


def test_cli_missing_allowlist_and_uncovered_promises_cannot_start_workers(tmp_path: Path):
    base = _cli_args(tmp_path, [_model("di")])
    allowlist = tmp_path / "allow.txt"
    allowlist.write_text("di\nnot_in_plan\n", encoding="utf-8")
    with mock.patch.object(matrix, "generate_spec") as generate, \
            mock.patch.object(matrix, "compile_spec") as compile_model:
        assert _main_status(base + ["--allowlist", str(tmp_path / "missing.txt")]) != 0
        assert _main_status(base + ["--allowlist", str(allowlist)]) != 0
    generate.assert_not_called()
    compile_model.assert_not_called()


def test_cli_unknown_only_duplicate_plan_and_partial_selection_cannot_qualify(tmp_path: Path):
    specs = [_model("di"), _model("other")]
    base = _cli_args(tmp_path, specs)
    with mock.patch.object(matrix, "generate_spec") as generate:
        assert _main_status(base + ["--only", "typo"]) != 0
        assert _main_status(base + ["--only", ", ,"]) != 0
    generate.assert_not_called()
    with mock.patch.object(matrix, "run_matrix", return_value=[_stage_result(specs[0])]):
        assert _main_status(base + ["--only", "di"]) != 0
    data = json.loads((tmp_path / "report.json").read_text())
    assert not data["scan_complete"] and data["metadata"]["partial"]
    duplicate_args = _cli_args(tmp_path, [specs[0], specs[0]])
    with mock.patch.object(matrix, "generate_spec") as generate:
        assert _main_status(duplicate_args) != 0
    generate.assert_not_called()


# -- owned child-process lifecycle -------------------------------------------


def test_nonposix_supervision_rejects_before_spawning(tmp_path: Path):
    command = [sys.executable, "-c", "raise AssertionError('must not run')"]
    log = tmp_path / "unsupported-platform.log"
    stop = threading.Event()
    with mock.patch.object(matrix.os, "name", "nt"), \
            mock.patch.object(matrix.subprocess, "Popen") as spawn:
        try:
            result = matrix._run_child(command, cwd=tmp_path, log=log,
                                       deadline=time.monotonic() + 2, stop=stop)
        except RuntimeError as error:
            assert "supervision" in str(error) and "POSIX" in str(error)
        else:
            assert result.returncode < 0, "unsupported supervision cannot report completed work"
    spawn.assert_not_called()


def test_term_cleanup_failure_still_kills_reaps_and_preserves_both_errors(tmp_path: Path):
    command = ["controlled-child"]
    log = tmp_path / "cleanup-errors.log"
    process = mock.Mock()
    process.pid = 987654321  # Cannot identify an unrelated process group on the Linux test host.
    process.returncode = None
    calls = []
    reaped = False

    def wait(*, timeout):
        nonlocal reaped
        calls.append(("wait", timeout))
        if len(calls) == 1:
            raise OSError("controlled original wait failure")
        if process.returncode is None:
            raise subprocess.TimeoutExpired(command, timeout)
        reaped = True
        return process.returncode

    def signal_group(pid, value):
        assert pid == process.pid
        calls.append(("signal", value))
        if value == signal.SIGTERM:
            raise PermissionError("controlled TERM cleanup failure")
        if value == signal.SIGKILL:
            process.returncode = -signal.SIGKILL
        else:
            raise AssertionError(f"unexpected group signal {value}")

    process.poll.side_effect = lambda: process.returncode
    process.wait.side_effect = wait
    caught = None
    with mock.patch.object(matrix.subprocess, "Popen", return_value=process) as spawn, \
            mock.patch.object(matrix.os, "killpg", side_effect=signal_group):
        try:
            matrix._run_child(command, cwd=tmp_path, log=log,
                              deadline=time.monotonic() + 2, stop=threading.Event())
        except OSError as error:
            caught = error
    assert spawn.call_count == 1 and caught is not None
    assert [value for operation, value in calls if operation == "signal"] == [
        signal.SIGTERM, signal.SIGKILL]
    assert reaped and calls[-1][0] == "wait", "KILL must be followed by a reap attempt"
    assert process.returncode == -signal.SIGKILL
    diagnostic = str(caught) + "\n" + "\n".join(getattr(caught, "__notes__", []))
    assert "controlled original wait failure" in diagnostic
    assert "controlled TERM cleanup failure" in diagnostic
    retained = log.read_text()
    assert "controlled TERM cleanup failure" in retained
    assert json.loads(retained.splitlines()[0])["command"] == command


def test_expired_deadline_or_existing_stop_never_spawns_a_child(tmp_path: Path):
    for expired in (False, True):
        stop = threading.Event()
        if not expired:
            stop.set()
        with mock.patch.object(matrix.subprocess, "Popen") as spawn:
            try:
                result = matrix._run_child(
                    [sys.executable, "-c", "raise AssertionError('must not run')"],
                    cwd=tmp_path, log=tmp_path / f"not-started-{expired}.log",
                    deadline=time.monotonic() - 1 if expired else time.monotonic() + 2,
                    stop=stop,
                )
            except Exception as ex:  # The private supervisor's exception class is not an API.
                assert str(ex)
            else:
                assert result.returncode < 0, "a stopped child must remain an infrastructure outcome"
        spawn.assert_not_called()


def test_controlled_python_child_and_descendant_stop_and_timeout_are_bounded(tmp_path: Path):
    # This module's execution gate is the Linux Hetzner container. The child owns/reaps its descendant;
    # neither a real generator/compiler nor an unbounded test sleep is involved.
    assert os.name == "posix", "controlled process-group check requires the Linux execution gate"
    program = """
import json, os, pathlib, signal, subprocess, sys, time
descendant = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(8)'])
def stop(signum, frame):
    try:
        descendant.terminate()
    except ProcessLookupError:
        pass
    descendant.wait(timeout=1)
    if sys.argv[2] == 'force':
        time.sleep(8)
    raise SystemExit(23)
signal.signal(signal.SIGTERM, stop)
pathlib.Path(sys.argv[1]).write_text(json.dumps([os.getpid(), descendant.pid]))
print('controlled-child-ready', flush=True)
if sys.argv[2] == 'orphan':
    raise SystemExit(0)
try:
    descendant.wait(timeout=8)
finally:
    if descendant.poll() is None:
        descendant.kill()
    descendant.wait(timeout=1)
"""
    for mode in ("deadline", "stop", "orphan"):
        pid_file = tmp_path / f"{mode}.pids"
        log = tmp_path / f"{mode}.log"
        stop = threading.Event()

        def request_stop():
            ready_by = time.monotonic() + 2
            while time.monotonic() < ready_by:
                if (pid_file.exists() and log.exists()
                        and "controlled-child-ready" in log.read_text()):
                    break
                if stop.wait(0.01):
                    return
            stop.set()

        watcher = threading.Thread(target=request_stop, daemon=False) if mode == "stop" else None
        started = time.monotonic()
        if watcher:
            watcher.start()
        try:
            try:
                result = matrix._run_child(
                    [sys.executable, "-u", "-c", program, str(pid_file),
                     "force" if mode == "stop" else mode],
                    cwd=tmp_path, log=log, deadline=started + 2,
                    stop=stop,
                )
            except Exception as ex:  # Assert the public lifecycle outcome, not a private exception type.
                assert str(ex)
            else:
                assert result.returncode < 0, "deadline/stop/orphan must be an infrastructure outcome"
            assert time.monotonic() - started < 6, "cleanup did not respect the bounded deadline"
            assert pid_file.is_file(), "controlled child never established descendant ownership"
            parent_pid, descendant_pid = json.loads(pid_file.read_text())
            assert not Path(f"/proc/{parent_pid}").exists(), "direct child was not reaped"
            descendant_stat = Path(f"/proc/{descendant_pid}/stat")
            if descendant_stat.exists():
                assert descendant_stat.read_text().split()[2] == "Z", "descendant remained running"
            retained = log.read_text()
            assert "controlled-child-ready" in retained and sys.executable in retained
        finally:
            stop.set()
            if watcher:
                watcher.join(timeout=3)
                assert not watcher.is_alive()
            if pid_file.exists():
                for pid in json.loads(pid_file.read_text()):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    full_log = tmp_path / "bounded-output.log"
    result = matrix._run_child(
        [sys.executable, "-u", "-c",
         "print('first-output-marker'); print('x' * 100000); print('last-output-marker')"],
        cwd=tmp_path, log=full_log, deadline=time.monotonic() + 2, stop=threading.Event(),
    )
    assert result.returncode == 0 and len(result.stdout) < 20000
    assert "last-output-marker" in result.stdout and "first-output-marker" not in result.stdout
    retained = full_log.read_text()
    assert "first-output-marker\n" in retained and "last-output-marker\n" in retained


# -- runner ------------------------------------------------------------------


def _run() -> int:
    failed = 0
    tests = [
        (name, fn)
        for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
    ]
    for name, fn in tests:
        try:
            if "tmp_path" in inspect.signature(fn).parameters:
                with tempfile.TemporaryDirectory() as td:
                    fn(tmp_path=Path(td))
            else:
                fn()
            print(f"OK   {name}")
        except AssertionError as ex:
            failed += 1
            print(f"FAIL {name}: {ex}", file=sys.stderr)
        except Exception as ex:  # noqa: BLE001
            failed += 1
            print(f"ERR  {name}: {type(ex).__name__}: {ex}", file=sys.stderr)
    if failed:
        print(f"\n{failed} test(s) failed", file=sys.stderr)
    else:
        print(f"\n{len(tests)} test(s) passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
