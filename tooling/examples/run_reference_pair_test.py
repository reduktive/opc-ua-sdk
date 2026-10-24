#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Behaviour test for the reference server and client, which are one deliverable in two programs.

Performs the provisioning workflow the applications actually document - each side exports its own
public certificate, each side imports the other's - then starts the server, runs the client, and
compares both programs' whole normalised output to their golden files.

This replaces an earlier shell harness that grepped nine literal phrases out of the logs. Comparing
the whole stream also catches missing lines, extra lines, and reordering, and it leaves the wording
of the output free to improve.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_example_test import normalise  # noqa: E402

KEY_CREDENTIAL_VARIABLE = "REDUKTIVE_REFERENCE_KEY_PASSWORD"
SERVER_READY_MARKER = "Press Ctrl+C to stop"


def provision(server: Path, client: Path, root: Path, listen: str, environment: dict[str, str]) -> None:
    """Runs the four provisioning commands the applications' READMEs document.

    Both peers and both certificate files live inside one private temporary directory here, so
    their direct exchange is part of the fixture. A real provisioning step verifies the printed
    fingerprint over an independent channel first.
    """
    server_certificate = root / "server.der"
    client_certificate = root / "client.der"
    steps = (
        [server, "--pki", root / "server-pki", "--listen", listen, "--export-certificate", server_certificate],
        [client, "--pki", root / "client-pki", "--export-certificate", client_certificate],
        [server, "--pki", root / "server-pki", "--listen", listen, "--trust-certificate", client_certificate],
        [client, "--pki", root / "client-pki", "--trust-certificate", server_certificate],
    )
    for step in steps:
        subprocess.run(
            [str(part) for part in step] + ["--provision-only"],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )


def compare(name: str, actual: str, expected_path: Path, update: bool, masks: list[str]) -> bool:
    normalised = normalise(actual, masks)
    if update:
        expected_path.write_text(normalised, encoding="utf-8")
        print(f"updated {expected_path}")
        return True
    if not expected_path.is_file():
        print(f"FAILED: no golden output at {expected_path}", file=sys.stderr)
        return False
    expected = normalise(expected_path.read_text(encoding="utf-8"), masks)
    if normalised == expected:
        return True
    import difflib

    print(f"FAILED: {name} output does not match {expected_path.name}", file=sys.stderr)
    sys.stderr.writelines(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            normalised.splitlines(keepends=True),
            fromfile="expected",
            tofile="actual",
        )
    )
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--server-expected", type=Path, required=True)
    parser.add_argument("--client-expected", type=Path, required=True)
    parser.add_argument(
        "--listen",
        # Below the ephemeral range (32768 upwards on Linux), which the kernel hands out as
        # source ports: a fixed bind inside it fails intermittently and reproduces nowhere.
        # Fixed rather than port 0 because the pair is provisioned against this address
        # before either program is started for real.
        default="127.0.0.1:24840")
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--update-golden", action="store_true")
    parser.add_argument("--mask", action="append", default=[])
    arguments = parser.parse_args()

    environment = dict(os.environ)
    # The applications refuse to run without a key credential, and never accept one on the command
    # line. A test fixture supplies a throwaway value the same way a deployment supplies a real one.
    environment[KEY_CREDENTIAL_VARIABLE] = "reference-pair-test"

    with tempfile.TemporaryDirectory(prefix="uasdk-reference-pair-") as directory:
        root = Path(directory)
        try:
            provision(arguments.server, arguments.client, root, arguments.listen, environment)
        except subprocess.CalledProcessError as failure:
            print("FAILED: provisioning did not complete", file=sys.stderr)
            print(failure.stdout, file=sys.stderr)
            print(failure.stderr, file=sys.stderr)
            return 1

        server = subprocess.Popen(
            [str(arguments.server), "--pki", str(root / "server-pki"), "--listen", arguments.listen,
             "--model", str(arguments.model)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=environment,
        )
        server_output: list[str] = []
        ready = threading.Event()

        def read_server() -> None:
            assert server.stdout is not None
            for line in server.stdout:
                server_output.append(line)
                if SERVER_READY_MARKER in line:
                    ready.set()

        reader = threading.Thread(target=read_server, daemon=True)
        reader.start()

        try:
            if not ready.wait(timeout=arguments.timeout):
                print(f"FAILED: the reference server was not ready within {arguments.timeout}s", file=sys.stderr)
                print("".join(server_output), file=sys.stderr)
                return 1

            client = subprocess.run(
                [str(arguments.client), "--pki", str(root / "client-pki"),
                 "--endpoint", f"opc.tcp://{arguments.listen}"],
                capture_output=True, text=True, timeout=arguments.timeout, env=environment,
            )
            if client.returncode != 0:
                print(f"FAILED: the reference client exited {client.returncode}", file=sys.stderr)
                print(client.stdout, file=sys.stderr)
                print(client.stderr, file=sys.stderr)
                return 1
        finally:
            if server.poll() is None:
                server.send_signal(signal.SIGINT)
                try:
                    server.wait(timeout=arguments.timeout)
                except subprocess.TimeoutExpired:
                    server.kill()
            reader.join(timeout=5)

        if server.returncode != 0:
            print(f"FAILED: the reference server exited {server.returncode} after SIGINT", file=sys.stderr)
            print("".join(server_output), file=sys.stderr)
            return 1

        client_ok = compare("reference_client", client.stdout, arguments.client_expected, arguments.update_golden,
                              arguments.mask)
        server_ok = compare("reference_server", "".join(server_output), arguments.server_expected,
                            arguments.update_golden, arguments.mask)
        return 0 if client_ok and server_ok else 1


if __name__ == "__main__":
    sys.exit(main())
