# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Codegen matrix compile harness (phase 2).

For every spec in the discovery plan (see ``companion_matrix.py``): synthesise a
manifest, run the type generator, then compile the emitted translation units in
the *real* SDK compile environment - the flags are lifted verbatim from a
``ua_*_types`` entry in ``compile_commands.json``, so no fragile hand-replication
of include paths or defines. Each spec's pass/fail (generate + compile) is
recorded to a JSON + Markdown report.

Completed model failures outside the **allowlist** are dashboard data. An
incomplete scan, infrastructure failure or allowlist regression fails the run.
Every planned model remains visible in incremental JSON and Markdown reports.

Generation of a spec is self-contained (it resolves cross-spec refs from its
lookup specs' NodeSet XML, not from generated C++), so all specs are generated
first; compilation then runs concurrently with each dependency's emitted headers
on the include path.

Invoke via::

    python -m tooling.type_generator.matrix_compile \\
        --plan plan.json --root <uanodeset-src> \\
        --compile-commands <build>/compile_commands.json \\
        --out-dir /tmp/codegen_matrix --report report
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
from collections.abc import Mapping
from pathlib import Path

from .manifest import NS0_URI

# NS0 base inputs, relative to the UA-Nodeset checkout root (the always-present
# emit=false dependency every companion spec resolves against).
_NS0_SOURCES = ("Schema/Opc.Ua.NodeSet2.xml", "Schema/Opc.Ua.NodeSet2.Services.xml")
_NS0_NODEIDS_CSV = "Schema/NodeIds.csv"
_NS0_STATUSCODE_CSV = "Schema/StatusCode.csv"
_NS0_ATTRIBUTE_IDS_CSV = "Schema/AttributeIds.csv"

_GENERATOR_MODULE = "tooling.type_generator"


def default_jobs(
    environ: Mapping[str, str] | None = None,
    cpu_count: int | None = None,
) -> int:
    """Select a worker budget that composes with the surrounding build."""

    environment = os.environ if environ is None else environ
    configured = environment.get("CMAKE_BUILD_PARALLEL_LEVEL", "").strip()
    if configured:
        try:
            parsed = int(configured)
        except ValueError:
            parsed = 0
        if parsed > 0:
            return parsed

    available = os.cpu_count() if cpu_count is None else cpu_count
    return max(1, available or 4)


# ---- compile environment ---------------------------------------------------


@dataclasses.dataclass
class CompileEnv:
    compiler: str
    base_flags: list[str]  # -std / -D / -I (SDK + vcpkg), gen dirs excluded
    directory: str | None = None
    source_entry: dict | None = None


def _command_args(entry: dict) -> list[str]:
    if "arguments" in entry:
        return list(entry["arguments"])
    return shlex.split(entry["command"])


def extract_compile_env(
    compile_commands: Path, gen_marker: str = "/gen/"
) -> CompileEnv:
    """Lift the SDK compile flags from a generated-companion TU command.

    Keeps ``-std``, every ``-D`` define and every ``-I``/``-isystem`` include
    that does NOT point into a generated tree (those are per-spec and added
    later). Drops outputs, source, dep-file and warning flags so the dashboard
    measures "compiles", not "compiles warning-free".
    """

    entries = json.loads(compile_commands.read_text(encoding="utf-8"))
    chosen: dict | None = None
    for entry in entries:
        f = entry.get("file", "")
        entry_directory = Path(entry.get("directory", str(compile_commands.parent)))
        if not entry_directory.is_absolute():
            entry_directory = compile_commands.parent / entry_directory
        full_file = str((entry_directory / f).resolve())
        if f.endswith(".cpp") and gen_marker in full_file:
            chosen = entry
            if "/gen/di/" in full_file:
                break
    if chosen is None:
        raise SystemExit(
            "matrix_compile: no generated-companion TU found in "
            f"{compile_commands}; build the companion_spec tier first so its "
            "ua_*_types compile commands are present."
        )

    args = _command_args(chosen)
    if not args:
        raise ValueError("empty compile command")
    compiler = args[0]
    if Path(compiler).name.lower() in {"ccache", "sccache", "env", "cmake", "cl.exe"}:
        raise ValueError(f"unsupported compiler launcher or command: {compiler}")
    directory = Path(chosen.get("directory", str(compile_commands.parent)))
    if not directory.is_absolute():
        directory = compile_commands.parent / directory
    directory = directory.resolve()
    if "/" in compiler and not Path(compiler).is_absolute():
        compiler = str((directory / compiler).resolve())
    base: list[str] = []
    i = 1
    source = Path(chosen["file"])
    if not source.is_absolute():
        source = directory / source
    paired_options = {"-I", "-isystem", "-iquote", "-idirafter", "-D", "-U", "-include",
                      "-imacros", "--sysroot", "-isysroot", "-target", "--target", "-Xclang",
                      "-gcc-toolchain", "--gcc-toolchain", "-B", "-isystem-after"}
    output_options = {"-o", "-MF", "-MT", "-MQ", "-MJ", "-include-pch"}
    while i < len(args):
        a = args[i]
        if a.startswith("@"):
            raise ValueError(f"unsupported response file: {a}")
        if a in output_options or a in paired_options:
            if i + 1 == len(args):
                raise ValueError(f"missing operand for {a}")
            operand = args[i + 1]
            i += 2
            if a in output_options:
                continue
            if a in {"-I", "-isystem", "-iquote", "-idirafter"}:
                include = Path(operand)
                if not include.is_absolute():
                    include = directory / include
                if gen_marker in str(include.resolve()) + "/":
                    continue
            if a == "-include" and "cmake_pch" in Path(operand).name:
                continue
            base.extend([a, operand])
            continue
        if a in {"-c", "-MD", "-MMD", "-MP", "-M", "-MM", "-MG"}:
            i += 1
            continue
        if (a.startswith(("-W", "-O", "-fdiagnostics", "-fcolor-diagnostics"))
                or re.fullmatch(r"-g(?:[0-3]|gdb[0-3]?|dwarf(?:-\d+)?|line-tables-only)?", a)):
            i += 1
            continue
        if a.startswith(("-MF", "-MT", "-MQ", "-MJ")) or (a.startswith("-o") and len(a) > 2):
            i += 1
            continue
        if a.startswith(("-I", "-isystem", "-iquote", "-idirafter")):
            option = next(prefix for prefix in ("-isystem", "-iquote", "-idirafter", "-I")
                          if a.startswith(prefix))
            include = Path(a[len(option):])
            if not include.is_absolute():
                include = directory / include
            if gen_marker not in str(include.resolve()) + "/":
                base.append(a)
        elif a.startswith("-"):
            base.append(a)
        else:
            candidate = Path(a)
            if not candidate.is_absolute():
                candidate = directory / candidate
            if candidate.resolve() != source.resolve():
                raise ValueError(f"unsupported bare compile argument: {a}")
        i += 1
    return CompileEnv(compiler, base, str(directory), chosen)


def _include_dirs(root: Path) -> list[str]:
    """``-I`` for ``root`` and every subdirectory beneath it."""
    flags = [f"-I{root}"]
    for dirpath, directories, _files in os.walk(root):
        directories.sort()
        if Path(dirpath) != root:
            flags.append(f"-I{dirpath}")
    return [flags[0], *sorted(flags[1:])]


# ---- generation ------------------------------------------------------------


def _abs_sources(rel_sources: list[str], root: Path) -> list[str]:
    return [str(root / s) for s in rel_sources]


def build_manifest(spec: dict, root: Path, *, instance_categories: list[str],
                   emit_event_types: bool) -> dict:
    """Synthesise the generator manifest for one spec (+ NS0 + lookups)."""

    nodesets: list[dict] = []
    nodesets.append(
        {
            "uri": NS0_URI,
            "sources": _abs_sources(list(_NS0_SOURCES), root),
            "include_prefix": "ua_",
            "cpp_namespace": "ua",
            "target": "sdk",
            "emit": False,
            "nodeids_csv": str(root / _NS0_NODEIDS_CSV),
            "statuscode_csv": str(root / _NS0_STATUSCODE_CSV),
            "attribute_ids_csv": str(root / _NS0_ATTRIBUTE_IDS_CSV),
        }
    )
    for dep in spec["lookup_specs"]:
        entry = {
            "uri": dep["uri"],
            "sources": _abs_sources(dep["sources"], root),
            "include_prefix": dep["include_prefix"],
            "cpp_namespace": dep["cpp_namespace"],
            "target": dep["include_prefix"].rstrip("_") + "_lookup",
            "emit": False,
        }
        if dep.get("nodeids_csv"):
            entry["nodeids_csv"] = str(root / dep["nodeids_csv"])
        nodesets.append(entry)

    emit = {
        "uri": spec["uri"],
        "sources": _abs_sources(spec["sources"], root),
        "include_prefix": spec["include_prefix"],
        "cpp_namespace": spec["cpp_namespace"],
        "target": spec["target"],
        "emit": True,
        "instance_type_categories": instance_categories,
        "instance_type_browse_names": [],
        "emit_event_types": emit_event_types,
    }
    if spec.get("nodeids_csv"):
        emit["nodeids_csv"] = str(root / spec["nodeids_csv"])
    nodesets.append(emit)
    return {"nodesets": nodesets}


def _run_child(command: list[str], *, cwd: Path, log: Path,
               deadline: float, stop: threading.Event) -> subprocess.CompletedProcess:
    """Run one bounded child, retaining its output and stopping its process tree."""

    if os.name != "posix":
        raise RuntimeError("bounded matrix child supervision requires POSIX process groups")
    if stop.is_set():
        raise InterruptedError("matrix execution stopped before child launch")
    if time.monotonic() >= deadline:
        stop.set()
        raise subprocess.TimeoutExpired(command, 0)
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with log.open("wb") as output:
        output.write((json.dumps({"command": command, "cwd": str(cwd)}) + "\n").encode())
        output.flush()
        process = subprocess.Popen(
            command, cwd=str(cwd), stdout=output, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        primary: BaseException | None = None
        descendants = False
        try:
            while process.poll() is None:
                if stop.is_set():
                    raise InterruptedError("matrix execution stopped while child was running")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    stop.set()
                    raise subprocess.TimeoutExpired(command, time.monotonic() - started)
                try:
                    process.wait(timeout=min(0.2, remaining))
                except subprocess.TimeoutExpired:
                    pass
            try:
                os.killpg(process.pid, 0)
                descendants = True
            except ProcessLookupError:
                pass
            if descendants:
                raise RuntimeError("child exited while descendants were still running")
        except BaseException as error:
            primary = error
            raise
        finally:
            if process.poll() is None or descendants or primary is not None:
                cleanup_errors: list[BaseException] = []
                # Every termination and reap attempt runs even if an earlier one failed.
                for termination, grace in ((signal.SIGTERM, 1), (signal.SIGKILL, 2)):
                    try:
                        os.killpg(process.pid, termination)
                    except ProcessLookupError:
                        pass
                    except BaseException as cleanup_error:
                        cleanup_errors.append(cleanup_error)
                    try:
                        process.wait(timeout=grace)
                    except subprocess.TimeoutExpired as cleanup_error:
                        if termination == signal.SIGKILL:
                            cleanup_errors.append(cleanup_error)
                    except BaseException as cleanup_error:
                        cleanup_errors.append(cleanup_error)
                try:
                    # killpg is asynchronous. Wait for every group member to stop,
                    # including descendants whose parent already exited. Linux /proc
                    # distinguishes exited, unreaped orphans from running processes.
                    stopped_by = time.monotonic() + 1
                    while True:
                        if Path("/proc").is_dir():
                            running = False
                            for stat in Path("/proc").glob("[0-9]*/stat"):
                                try:
                                    fields = stat.read_text().rsplit(")", 1)[1].split()
                                    if int(fields[2]) == process.pid and fields[0] not in {"Z", "X"}:
                                        running = True
                                        break
                                except (OSError, ValueError, IndexError):
                                    continue  # An exiting process can disappear during this read.
                        else:
                            try:
                                os.killpg(process.pid, 0)
                                running = True
                            except ProcessLookupError:
                                running = False
                        if not running:
                            break
                        if time.monotonic() >= stopped_by:
                            raise RuntimeError("child process group did not stop after SIGKILL")
                        time.sleep(0.01)
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
                if cleanup_errors:
                    note = "child cleanup also failed: " + "; ".join(
                        f"{type(error).__name__}: {error}" for error in cleanup_errors)
                    if primary is not None:
                        primary.add_note(note)
                    try:
                        output.write(("\n" + note + "\n").encode())
                        output.flush()
                    except OSError as log_error:
                        if primary is None:
                            raise
                        primary.add_note(f"cleanup log write failed: {log_error}")
                    if primary is None:
                        raise RuntimeError(note) from cleanup_errors[0]

    with log.open("rb") as output:
        output.seek(0, os.SEEK_END)
        output.seek(max(0, output.tell() - 16384))
        tail = output.read().decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(command, process.returncode, stdout=tail, stderr="")


def generate_spec(spec: dict, root: Path, out_root: Path, *,
                  instance_categories: list[str], emit_event_types: bool,
                  repo_root: Path, deadline: float, stop: threading.Event,
                  logs_root: Path) -> SpecResult:
    started = time.monotonic()
    result = SpecResult(spec["slug"], spec["uri"], False, False, 0, "", stage="generation")
    try:
        slug = spec["slug"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", slug):
            raise ValueError(f"invalid output slug: {slug!r}")
        out_dir = out_root / slug
        if out_dir.is_symlink() or out_dir.resolve().parent != out_root.resolve():
            raise ValueError(f"output directory is not an owned model directory: {out_dir}")
        manifest = build_manifest(
            spec, root, instance_categories=instance_categories,
            emit_event_types=emit_event_types,
        )
        manifest_path = out_dir / "_manifest.json"
        if out_dir.exists() and any(out_dir.iterdir()):
            # Rebuild an earlier model output only when its own manifest proves identity.
            previous = json.loads(manifest_path.read_text(encoding="utf-8"))
            previous_emit = [entry for entry in previous["nodesets"] if entry.get("emit")]
            if (len(previous_emit) != 1
                    or any(previous_emit[0].get(key) != spec[key]
                           for key in ("uri", "target", "include_prefix", "cpp_namespace"))):
                raise ValueError(f"refusing to clear unrelated output directory: {out_dir}")
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        process = _run_child(
            [sys.executable, "-u", "-m", _GENERATOR_MODULE,
             "--manifest", str(manifest_path), "--output", str(out_dir)],
            cwd=repo_root, log=logs_root / slug / "generate.log", deadline=deadline, stop=stop,
        )
        result.generated = process.returncode == 0
        if not result.generated:
            result.error = f"generation exited {process.returncode}:\n{process.stdout.strip()}"
            result.incomplete = process.returncode < 0 or bool(re.search(
                r"MemoryError|cannot allocate memory|no space left on device|out of memory",
                process.stdout, re.IGNORECASE,
            ))
    except Exception as error:
        result.incomplete = True
        result.error = "".join(traceback.format_exception_only(error)).strip()
    result.duration_seconds = time.monotonic() - started
    return result


# ---- compilation -----------------------------------------------------------


def compile_spec(spec: dict, out_root: Path, env: CompileEnv,
                 *, syntax_only: bool = True, deadline: float,
                 stop: threading.Event, logs_root: Path) -> SpecResult:
    """Compile every emitted TU; stop at the first failure (which marks RED)."""

    started = time.monotonic()
    result = SpecResult(spec["slug"], spec["uri"], True, False, 0, "", stage="compilation")
    try:
        spec_out = out_root / spec["slug"]
        tus = sorted(spec_out.rglob("*.cpp"))
        result.tus = len(tus)
        if not tus:
            result.error = "no .cpp emitted"
            return result
        inc = _include_dirs(spec_out)
        for dep in spec["lookup_specs"]:
            dep_out = out_root / dep["slug"]
            if dep_out.is_dir():
                inc.extend(_include_dirs(dep_out))
        mode = ["-fsyntax-only"] if syntax_only else ["-c", "-o", os.devnull]
        for index, tu in enumerate(tus):
            log = logs_root / spec["slug"] / f"compile-{index:04d}-{tu.name}.log"
            command = [env.compiler, *env.base_flags, *inc, *mode, str(tu)]
            process = _run_child(command, cwd=Path(env.directory or Path.cwd()),
                                 log=log, deadline=deadline, stop=stop)
            if process.returncode != 0:
                result.error = f"{tu.name}: exit {process.returncode}\n{process.stdout.strip()}"
                result.incomplete = process.returncode < 0 or bool(re.search(
                    r"internal compiler error|killed signal|cannot allocate memory|"
                    r"no space left on device|segmentation fault|llvm error|"
                    r"collect2: fatal error|failed due to signal|out of memory",
                    process.stdout, re.IGNORECASE,
                ))
                return result
        result.compiled = True
    except Exception as error:
        result.incomplete = True
        result.error = "".join(traceback.format_exception_only(error)).strip()
    finally:
        result.duration_seconds = time.monotonic() - started
    return result


# ---- orchestration ---------------------------------------------------------


@dataclasses.dataclass
class SpecResult:
    slug: str
    uri: str
    generated: bool
    compiled: bool
    tus: int
    error: str
    incomplete: bool = False
    stage: str = ""
    duration_seconds: float = 0.0

    @property
    def passed(self) -> bool:
        return self.generated and self.compiled and not self.incomplete


def run_matrix(plan: dict, root: Path, env: CompileEnv, out_root: Path,
               repo_root: Path, *, instance_categories: list[str],
               emit_event_types: bool, syntax_only: bool, jobs: int,
               only: set[str] | None, deadline: float | None = None,
               report_stem: Path | None = None, allowlist: set[str] | None = None,
               metadata: dict | None = None) -> list[SpecResult]:
    if jobs <= 0:
        raise ValueError("jobs must be positive")
    deadline = time.monotonic() + 3540 if deadline is None else deadline
    if not math.isfinite(deadline):
        raise ValueError("deadline must be finite")
    by_slug = {spec["slug"]: spec for spec in plan["generatable"]}
    if not by_slug or len(by_slug) != len(plan["generatable"]):
        raise ValueError("matrix plan is empty or contains duplicate slugs")
    selected = set(by_slug) if only is None else set(only)
    if not selected or selected - by_slug.keys():
        raise ValueError(f"unknown or empty model selection: {sorted(selected - by_slug.keys())}")
    # A diagnostic subset still needs the generated headers of all planned dependencies.
    while True:
        expanded = selected | {
            dep["slug"] for slug in selected for dep in by_slug[slug]["lookup_specs"]
            if dep["slug"] in by_slug
        }
        if expanded == selected:
            break
        selected = expanded
    specs = [spec for spec in plan["generatable"] if spec["slug"] in selected]
    expected = [spec["slug"] for spec in specs]
    rows = {spec["slug"]: SpecResult(
        spec["slug"], spec["uri"], False, False, 0, "not started", incomplete=True,
        stage="pending",
    ) for spec in specs}
    information = metadata if metadata is not None else {}
    information["partial"] = only is not None or bool(information.get("partial"))
    logs_root = (report_stem.parent / (report_stem.name + "_logs")
                 if report_stem is not None else out_root.parent / (out_root.name + "_logs"))
    stop = threading.Event()

    def checkpoint(*, finished=False):
        if report_stem is not None:
            write_reports(list(rows.values()), report_stem, allowlist or set(),
                          expected_slugs=expected, scan_finished=finished, metadata=information)

    def work(spec, phase):
        if stop.is_set() or time.monotonic() >= deadline:
            stop.set()
            return dataclasses.replace(rows[spec["slug"]], incomplete=True,
                                       error="global deadline or interruption", stage=phase)
        if phase == "generation":
            return generate_spec(
                spec, root, out_root, instance_categories=instance_categories,
                emit_event_types=emit_event_types, repo_root=repo_root,
                deadline=deadline, stop=stop, logs_root=logs_root,
            )
        compile_input = {**spec, "lookup_specs": [
            dep for dep in spec["lookup_specs"]
            if dep["slug"] in rows and rows[dep["slug"]].generated
        ]}
        return compile_spec(compile_input, out_root, env, syntax_only=syntax_only,
                            deadline=deadline, stop=stop, logs_root=logs_root)

    def collect(future, spec, phase, *, interrupted=False):
        try:
            result = future.result()
            if result.slug != spec["slug"] or result.uri != spec["uri"]:
                raise ValueError("worker returned a different model identity")
        except BaseException as error:
            if not isinstance(error, Exception) and not interrupted:
                raise
            result = dataclasses.replace(
                rows[spec["slug"]], incomplete=True, stage=phase,
                error="".join(traceback.format_exception_only(error)).strip(),
                duration_seconds=0.0,
            )
        if interrupted or time.monotonic() >= deadline or stop.is_set():
            stop.set()
            reason = "global deadline or interruption"
            result = dataclasses.replace(
                result, incomplete=True,
                error=f"{reason}\n{result.error}" if result.error else reason,
            )
        if phase == "generation" and result.generated and not result.incomplete:
            result = dataclasses.replace(result, incomplete=True,
                                         stage="awaiting compilation",
                                         error="compilation not started")
        elif phase == "compilation":
            result = dataclasses.replace(
                result, duration_seconds=result.duration_seconds + rows[spec["slug"]].duration_seconds)
        rows[spec["slug"]] = result
        del active[future]
        print(f"codegen matrix: {phase} finish {result.slug}; "
              f"{result.duration_seconds:.2f}s; {result.tus} TUs; "
              f"{'incomplete' if result.incomplete else 'complete'}", flush=True)
        if not interrupted:
            checkpoint()

    checkpoint()
    try:
        for phase in ("generation", "compilation"):
            candidates = [spec for spec in specs if phase == "generation"
                          or (rows[spec["slug"]].generated
                              and rows[spec["slug"]].stage == "awaiting compilation")]
            remaining_specs = iter(candidates)
            active: dict[concurrent.futures.Future, dict] = {}
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=jobs)
            try:
                while True:
                    if time.monotonic() >= deadline:
                        stop.set()
                    if stop.is_set():
                        information["error"] = "global deadline or interruption"
                        break
                    while len(active) < jobs:
                        spec = next(remaining_specs, None)
                        if spec is None:
                            break
                        print(f"codegen matrix: {phase} start {spec['slug']}", flush=True)
                        active[pool.submit(work, spec, phase)] = spec
                    if not active:
                        break
                    completed, _pending = concurrent.futures.wait(
                        active, timeout=min(15.0, max(0.0, deadline - time.monotonic())),
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    if not completed:
                        print(f"codegen matrix: {phase} active "
                              f"{','.join(sorted(spec['slug'] for spec in active.values()))}; "
                              f"{max(0, deadline - time.monotonic()):.0f}s remaining", flush=True)
                        continue
                    for future in completed:
                        collect(future, active[future], phase)
            except BaseException:
                stop.set()
                raise
            finally:
                if stop.is_set():
                    for future in active:
                        future.cancel()
                pool.shutdown(wait=True, cancel_futures=True)
                # Stopped workers still return their stage, TU count and diagnostics.
                # Collect only terminal work after shutdown; cancelled work never ran.
                for future, spec in list(active.items()):
                    if not future.cancelled():
                        collect(future, spec, phase, interrupted=True)
            if stop.is_set():
                break
    except BaseException as error:
        stop.set()
        information["error"] = f"{type(error).__name__}: {error}"
        # Preserve the actual rows and failure metadata across the CLI boundary.
        checkpoint()
    finally:
        for slug, result in rows.items():
            if result.incomplete and result.stage in {"pending", "awaiting compilation"}:
                rows[slug] = dataclasses.replace(
                    result, error=information.get("error", result.error),
                )
        checkpoint(finished=True)
    return list(rows.values())


# ---- reporting -------------------------------------------------------------


def write_reports(results: list[SpecResult], report_stem: Path,
                  allowlist: set[str], *, expected_slugs: list[str] | None = None,
                  scan_finished: bool = True, metadata: dict | None = None) -> tuple[int, int, int]:
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    regressions = [r for r in results if r.slug in allowlist and not r.passed]
    expected = [r.slug for r in results] if expected_slugs is None else list(expected_slugs)
    actual = [r.slug for r in results]
    incomplete = sorted({r.slug for r in results if r.incomplete} | (set(expected) - set(actual)))
    information = dict(metadata or {})
    scan_complete = (scan_finished and not incomplete and len(actual) == len(set(actual))
                     and len(expected) == len(set(expected)) and set(actual) == set(expected)
                     and not information.get("error") and not information.get("partial"))

    data = {
        "stats": {
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "allowlist_size": len(allowlist),
            "regressions": len(regressions),
            "incomplete": len(incomplete),
        },
        "scan_complete": scan_complete,
        "expected_slugs": expected,
        "incomplete": incomplete,
        "metadata": information,
        "results": [dataclasses.asdict(r) for r in results],
        "regressions": [r.slug for r in regressions],
    }
    report_stem.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Codegen matrix report",
        "",
        f"**{passed}/{len(results)} specs compile** "
        f"(allowlist: {len(allowlist)}, regressions: {len(regressions)})",
        f"Scan complete: {scan_complete}; incomplete models: {len(incomplete)}.",
        "",
        "| spec | gen | compile | TUs | note |",
        "|------|-----|---------|-----|------|",
    ]
    for r in sorted(results, key=lambda r: (r.passed, r.slug)):
        gen = "ok" if r.generated else "FAIL"
        comp = "incomplete" if r.incomplete else ("ok" if r.compiled else ("FAIL" if r.generated else "-"))
        note = "" if r.passed else r.error.splitlines()[0][:80] if r.error else ""
        gate = " [STOP]" if r.slug in allowlist and not r.passed else ""
        lines.append(f"| {r.slug}{gate} | {gen} | {comp} | {r.tus} | {note.replace('|', '/')} |")
    # JSON is the authoritative checkpoint and is replaced last. A killed writer leaves
    # either the preceding complete JSON object or the next one, never truncated JSON.
    for suffix, contents in ((".md", "\n".join(lines) + "\n"),
                             (".json", json.dumps(data, indent=2) + "\n")):
        target = report_stem.with_suffix(suffix)
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_text(contents, encoding="utf-8")
        os.replace(temporary, target)
    return passed, failed, len(regressions)


def load_allowlist(path: Path | None) -> set[str]:
    if path is None or not path.is_file():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


# ---- CLI -------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path,
                        help="UA-Nodeset checkout root.")
    parser.add_argument("--compile-commands", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path,
                        help="Scratch dir for generated trees.")
    parser.add_argument("--report", required=True, type=Path,
                        help="Report path stem (.json + .md written).")
    parser.add_argument("--allowlist", type=Path, default=None)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--only", default=None,
                        help="Comma-separated slugs to limit the run.")
    parser.add_argument("--instance-categories", default="all",
                        help="Comma-separated instance categories, or 'none'.")
    parser.add_argument("--emit-event-types", action="store_true")
    parser.add_argument("--full-compile", action="store_true",
                        help="Use -c instead of -fsyntax-only.")
    parser.add_argument("--jobs", type=int, default=default_jobs())
    parser.add_argument("--timeout-seconds", type=float, default=3540,
                        help="Whole-scan deadline; leaves cleanup time before CTest's 3600s limit.")
    args = parser.parse_args(argv)
    if args.jobs <= 0:
        parser.error("--jobs must be positive")
    if not math.isfinite(args.timeout_seconds) or args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be finite and positive")
    deadline = time.monotonic() + args.timeout_seconds
    cats = [] if args.instance_categories.strip().lower() in ("", "none") \
        else [c.strip() for c in args.instance_categories.split(",") if c.strip()]
    only = (
        {s.strip() for s in args.only.split(",") if s.strip()}
        if args.only is not None else None
    )
    information = {
        "revision": os.environ.get("CI_COMMIT_SHA"), "jobs": args.jobs,
        "timeout_seconds": args.timeout_seconds, "partial": only is not None,
        "module_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    results: list[SpecResult] = []
    expected: list[str] = []
    allowlist: set[str] = set()
    try:
        plan_bytes = args.plan.read_bytes()
        information["plan_sha256"] = hashlib.sha256(plan_bytes).hexdigest()
        plan = json.loads(plan_bytes)
        expected = [spec["slug"] for spec in plan["generatable"]]
        results = [SpecResult(spec["slug"], spec["uri"], False, False, 0, "not started",
                              incomplete=True, stage="pending") for spec in plan["generatable"]]
        write_reports(results, args.report, allowlist, expected_slugs=expected,
                      scan_finished=False, metadata=information)
        if not expected or len(expected) != len(set(expected)):
            raise ValueError("matrix plan is empty or contains duplicate model slugs")
        if only is not None and (not only or only - set(expected)):
            raise ValueError("--only must name existing planned model slugs")
        if args.allowlist is not None:
            if not args.allowlist.is_file():
                raise FileNotFoundError(f"allowlist not found: {args.allowlist}")
            information["allowlist_sha256"] = hashlib.sha256(args.allowlist.read_bytes()).hexdigest()
            allowlist = load_allowlist(args.allowlist)
        if allowlist - set(expected):
            raise ValueError(f"allowlisted models missing from plan: {sorted(allowlist - set(expected))}")
        env = extract_compile_env(args.compile_commands.resolve())
        information["compile_environment"] = dataclasses.asdict(env)
        results = run_matrix(
            plan, args.root.resolve(), env, args.out_dir.resolve(), args.repo_root.resolve(),
            instance_categories=cats, emit_event_types=args.emit_event_types,
            syntax_only=not args.full_compile, jobs=args.jobs, only=only,
            deadline=deadline, report_stem=args.report, allowlist=allowlist, metadata=information,
        )
    except (Exception, SystemExit, KeyboardInterrupt) as error:
        information["error"] = f"{type(error).__name__}: {error}"
        write_reports(results, args.report, allowlist, expected_slugs=expected,
                      scan_finished=False, metadata=information)
        print(f"codegen matrix: incomplete: {information['error']}", file=sys.stderr, flush=True)
        return 130 if isinstance(error, KeyboardInterrupt) else 1

    passed, failed, regressions = write_reports(
        results, args.report, allowlist, expected_slugs=expected, metadata=information,
    )
    complete = (not information["partial"] and not information.get("error")
                and {r.slug for r in results} == set(expected)
                and len(results) == len(expected) and not any(r.incomplete for r in results))
    print(f"codegen matrix: {passed}/{len(results)} compile, "
          f"{failed} failed, {regressions} allowlist regression(s)")
    if regressions:
        for r in results:
            if r.slug in allowlist and not r.passed:
                print(f"  REGRESSION {r.slug}: {r.error.splitlines()[0][:100]}",
                      file=sys.stderr)
    return 1 if regressions or not complete else 0


if __name__ == "__main__":
    sys.exit(main())
