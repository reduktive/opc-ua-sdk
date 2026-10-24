# Codegen matrix (`tests/codegen`)

Generates **every** companion spec the UA-Nodeset checkout provides and compiles
the emitted C++ in the real SDK compile environment — a coverage dashboard for
the type generator. Opt-in: configure with `-DUASDK_BUILD_CODEGEN_MATRIX=ON`.

## Why it exists

The hand-written `tests/integration/companion_spec` suite proves a *curated*
slice (DI + PROFINET + BACnet + synthetic fixtures). This tier proves the
generator against the *whole* set (≈124 models once sub-specs and cross-spec
dependency chains are resolved), so generator gaps surface as data, not as a
surprise when someone points the tool at a new spec.

## How it works

Two Python drivers in `tooling/type_generator/`:

- **`companion_matrix.py`** — scans the checkout, builds a registry keyed by
  parsed `<Model ModelUri>` (not directory name), resolves each spec's
  `<RequiredModel>` chain transitively, topo-sorts, derives `ua::<slug>` names,
  and writes an ordered build plan (`codegen_plan.json`). Specs whose
  dependencies are absent from the checkout are recorded as skipped, with the
  missing URI.
- **`matrix_compile.py`** — for each spec: synthesise a manifest, run the
  generator, then compile each emitted TU. Compile flags are lifted verbatim
  from a `ua_*_types` entry in `compile_commands.json`, so no include path or
  define is hand-replicated. Preserves the compile command's working directory
  and records its provenance. Writes an initial report containing every planned
  model, then atomically updates `codegen_matrix_report.{json,md}` as workers
  finish. Per-model generation and per-TU compilation logs are retained under
  `codegen_matrix_report_logs/` with command lines and working directories.

## Allow-fail + the allowlist

The `codegen_matrix` CTest test fails if a spec in
[`allowlist.txt`](allowlist.txt) regresses, or if execution is incomplete.
Completed model diagnostics outside the allowlist remain non-fatal. A timeout,
interruption, missing tool, compiler resource failure or unexpected worker
exception is incomplete execution, even for an unlisted model. A successful scan
requires exactly one completed result for every planned model.

The supervisor uses a shared 3540-second deadline, reserving cleanup and report
time before CTest's unchanged 3600-second limit. It stops active child process
groups on POSIX. Other hosts report unsupported supervision as incomplete before
launching a child. CTest invokes
the Python environment provisioned during configure directly. A test run does
not repeat dependency installation. `--timeout-seconds` accepts a finite positive
budget for a measured diagnostic run.

`--only` includes the transitive dependencies that are also planned for generation.
Lookup XML outside that plan remains a lookup input. Subset reports are marked
partial and exit non-zero; they cannot qualify the full matrix.

## Running

The `codegen-matrix` CI job configures with `UASDK_BUILD_CODEGEN_MATRIX=ON`, runs
the harness unit tests, builds and runs `companion_spec_integration_tests`, then
runs CTest with label `codegen_matrix`. Its artifacts include the discovery plan,
incremental reports, per-model logs and CTest log on success or failure.
