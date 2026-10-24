#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Gate 5 of the reference-project process: the behaviour test for one example.

Runs an example binary under a timeout, then compares its whole normalised stdout to the example's
expected_output.txt. Comparing the whole stream rather than grepping for phrases catches missing
lines, extra lines, and reordering, and it leaves the wording of the output free to improve without
breaking the build.

Usage:
  run_example_test.py --binary <path> --expected <path> [--timeout 60] [--arg ...] [--update-golden]
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

# Everything that legitimately differs between two correct runs. Each pattern replaces a varying
# value with a stable placeholder; anything not listed here is compared verbatim.
NORMALISERS = (
    (re.compile(r"(opc\.tcp://[^\s:]+):\d{1,5}"), r"\1:<port>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?Z?"), "<timestamp>"),
    (re.compile(r"\b[0-9A-Fa-f]{32,}\b"), "<fingerprint>"),
    (re.compile(r"\b\d+(\.\d+)? ms\b"), "<duration> ms"),
    (re.compile(r"\b\d+(\.\d+)? s\b"), "<duration> s"),
    (re.compile(r"/tmp/[^\s\"']+"), "<tmp>"),
    # A NodeId's numeric identifier is the server's to choose and can move when a model changes.
    (re.compile(r"\bns=\d+;i=\d+"), "<nodeid>"),
)


def normalise(text: str, masks: "list[str] | None" = None) -> str:
    """Replaces everything that legitimately differs between two correct runs.

    `masks` are extra patterns an individual example declares for values only it produces - an
    uptime counter, say - so that the shared list stays general.
    """
    for pattern, replacement in NORMALISERS:
        text = pattern.sub(replacement, text)
    for mask in masks or []:
        text = re.sub(mask, "<masked>", text)
    # Windows line endings and a trailing blank line are not differences worth failing over.
    return text.replace("\r\n", "\n").rstrip() + "\n"


ENDPOINT_URL = re.compile(r"opc\.tcp://[^\s]+")

# Port 0 asks the operating system for any free port. Binding a fixed high port instead would sit
# inside the ephemeral range on most Linux hosts, where the kernel may already have handed the same
# number to an outgoing connection - an intermittent bind failure that reproduces nowhere.
EPHEMERAL_BIND = "127.0.0.1:0"


class ExampleServer:
    """An example server started for the duration of a client example's test.

    It is stopped with SIGINT rather than SIGKILL so that a server left broken by the client under
    test still fails visibly, and so that nothing is left listening afterwards.
    """

    def __init__(self, binary: Path, ready_marker: str, timeout: float,
                 arguments: "list[str] | None" = None) -> None:
        self._binary = binary
        self._arguments = list(arguments or [])
        self._ready_marker = ready_marker
        self._timeout = timeout
        self._process: subprocess.Popen[str] | None = None
        self._output: list[str] = []

    def endpoint_url(self) -> "str | None":
        """The URL the server actually bound, read from the line it prints when it starts.

        Every server example prints its advertised URL under its "Listening" step, so a test does
        not have to be told a port in advance: the server is asked to bind port 0, the operating
        system picks a free one, and the client is given whatever came back. Restarting reuses the
        same URL, because the server is restarted with the same arguments.
        """
        for line in self._output:
            found = ENDPOINT_URL.search(line)
            if found:
                return found.group(0)
        return None

    def start(self) -> bool:
        self._process = subprocess.Popen(
            [str(self._binary), *self._arguments],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        ready = threading.Event()

        def read() -> None:
            assert self._process is not None and self._process.stdout is not None
            for line in self._process.stdout:
                self._output.append(line)
                if self._ready_marker in line:
                    ready.set()

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        if ready.wait(timeout=self._timeout):
            self._pin_bound_port()
            return True
        print(f"FAILED: {self._binary.name} was not ready within {self._timeout}s", file=sys.stderr)
        print("".join(self._output), file=sys.stderr)
        self.stop()
        return False

    def _pin_bound_port(self) -> None:
        """Rewrites a `:0` bind argument to the port the operating system actually chose.

        Only matters for a restart: the client under test is connected to the first port, so the
        server has to come back on it rather than being given a second arbitrary one.
        """
        url = self.endpoint_url()
        if url is None:
            return
        authority = url.split("//", 1)[-1].rstrip("/")
        self._arguments = [
            authority if argument.endswith(":0") else argument for argument in self._arguments
        ]

    def stop(self) -> None:
        if self._process is None or self._process.poll() is not None:
            return
        self._process.send_signal(signal.SIGINT)
        try:
            self._process.wait(timeout=self._timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()

    def restart(self) -> bool:
        """Stops the server and starts it again, so a client can be seen surviving the outage.

        The recorded output is kept rather than cleared: it carries the URL the first start bound,
        and the client under test is already connected to it.
        """
        self.stop()
        return self.start()


def run_with_server_restart(arguments: argparse.Namespace, server: "ExampleServer") -> str | None:
    """Runs an example, restarting its server the moment the example says it is ready for that.

    Triggering on a line the example prints, rather than on a timer, keeps the outage in the same
    place on every machine.
    """
    process = subprocess.Popen(
        [str(arguments.binary), *arguments.arg],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    collected: list[str] = []
    restarted = threading.Event()

    def watch() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            collected.append(line)
            if not restarted.is_set() and arguments.restart_server_when in line:
                restarted.set()
                server.restart()

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        process.wait(timeout=arguments.timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        print(f"FAILED: {arguments.binary.name} did not finish within {arguments.timeout}s", file=sys.stderr)
        print("".join(collected), file=sys.stderr)
        return None
    watcher.join(timeout=5)
    if not restarted.is_set():
        print(f"FAILED: {arguments.binary.name} never printed {arguments.restart_server_when!r}, "
              "so the server was never restarted", file=sys.stderr)
        print("".join(collected), file=sys.stderr)
        return None
    if process.returncode != 0:
        print(f"FAILED: {arguments.binary.name} exited {process.returncode}", file=sys.stderr)
        print("".join(collected), file=sys.stderr)
        print(process.stderr.read() if process.stderr else "", file=sys.stderr)
        return None
    return "".join(collected)


def run_to_completion(arguments: argparse.Namespace) -> str | None:
    """Runs an example that finishes on its own and returns its stdout."""
    try:
        completed = subprocess.run(
            [str(arguments.binary), *arguments.arg],
            capture_output=True,
            text=True,
            timeout=arguments.timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"FAILED: {arguments.binary.name} did not finish within {arguments.timeout}s", file=sys.stderr)
        return None
    if completed.returncode != 0:
        print(f"FAILED: {arguments.binary.name} exited {completed.returncode}", file=sys.stderr)
        print(completed.stdout, file=sys.stderr)
        print(completed.stderr, file=sys.stderr)
        return None
    return completed.stdout


def run_and_interrupt(arguments: argparse.Namespace) -> str | None:
    """Runs an example that waits for Ctrl+C, interrupts it once it is ready, and returns stdout.

    Interrupting rather than killing means the example's own signal handling and orderly shutdown
    are part of what the golden output covers. The interrupt is triggered by the example saying it
    is ready, not by a timer, so a slow or loaded machine does not change the result.
    """
    process = subprocess.Popen(
        [str(arguments.binary), *arguments.arg],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    collected: list[str] = []

    def read_until_ready() -> bool:
        assert process.stdout is not None
        for line in process.stdout:
            collected.append(line)
            if arguments.interrupt_when in line:
                return True
        return False

    reader = threading.Thread(target=lambda: ready.set() if read_until_ready() else finished.set())
    ready = threading.Event()
    finished = threading.Event()
    reader.daemon = True
    reader.start()

    if not ready.wait(timeout=arguments.timeout):
        process.kill()
        reader.join(timeout=5)
        print(f"FAILED: {arguments.binary.name} never printed a line containing "
              f"{arguments.interrupt_when!r} within {arguments.timeout}s", file=sys.stderr)
        print("".join(collected), file=sys.stderr)
        return None

    process.send_signal(signal.SIGINT)
    assert process.stdout is not None
    remaining = process.stdout.read()
    process.wait(timeout=arguments.timeout)
    reader.join(timeout=5)
    if process.returncode != 0:
        print(f"FAILED: {arguments.binary.name} exited {process.returncode} after SIGINT", file=sys.stderr)
        print("".join(collected) + remaining, file=sys.stderr)
        return None
    return "".join(collected) + remaining


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--arg", action="append", default=[])
    parser.add_argument("--update-golden", action="store_true")
    parser.add_argument(
        "--mask",
        action="append",
        default=[],
        help="A regular expression for a value only this example produces and that varies between "
        "correct runs. Each match is replaced before comparison.",
    )
    parser.add_argument(
        "--server",
        default="",
        help="An example server to start first and stop afterwards, for a client example that "
        "needs something to talk to.",
    )
    parser.add_argument(
        "--server-arg",
        action="append",
        default=[],
        help="An argument passed to the example server, beyond the bind address the runner supplies.",
    )
    parser.add_argument(
        "--fixed-ports",
        action="store_true",
        help="Do not manage ports. The test names them itself, in --arg and --server-arg. Needed "
        "where a URL is an identity rather than a socket - a reverse-connect server advertises a "
        "URL its certificate must cover, and both sides have to agree on it in advance.",
    )
    parser.add_argument(
        "--server-ready",
        default="Press Ctrl+C to stop",
        help="The line the server prints when it is accepting connections.",
    )
    parser.add_argument(
        "--restart-server-when",
        default="",
        help="Restart the server once the example prints a line containing this text. Lets a client "
        "example demonstrate what it does when its server goes away and comes back.",
    )
    parser.add_argument(
        "--interrupt-when",
        default="",
        help="For an example that waits for Ctrl+C: send SIGINT once a line containing this text "
        "has been printed, then compare its whole output including the shutdown it prints. "
        "Waiting for the example to say it is ready is deterministic; waiting a fixed number of "
        "seconds is not, and fails on a slow or loaded machine.",
    )
    arguments = parser.parse_args()

    # The PKI is the runner's business too, for the same reason the ports below are. The examples
    # keep their development certificates under the system temp directory at a FIXED name
    # (examples/support/example_pki.cpp: temp_directory_path()/"uasdk-examples-pki") and CREATE
    # them on first use, reusing whatever is already there. ctest runs these tests concurrently, so
    # two examples race to initialise that one directory: the loser ends up presenting a
    # certificate the peer's trust list no longer holds, and the connect is refused
    # BadSecurityChecksFailed. Measured on a cleared PKI at -j 4, the failing SET varies run to run
    # - 2 tests, then a different 5 - while -j 1 passes all 29, which is the signature of a race
    # rather than a broken example.
    #
    # Giving each test its own temp directory gives it its own PKI. TMP and TEMP are set alongside
    # TMPDIR because temp_directory_path() reads TMPDIR on POSIX and TMP/TEMP on Windows, and the
    # example tests run on both. The directory lives as long as this function.
    private_temp = tempfile.TemporaryDirectory(prefix="uasdk-example-test-")
    for variable in ("TMPDIR", "TMP", "TEMP"):
        os.environ[variable] = private_temp.name

    # Ports are the runner's business, not the test's. Every listener is asked for port 0 and the
    # operating system picks a free one, so no test has to reserve a number, two runs on one machine
    # cannot collide, and a new example needs no port allocated to it. The goldens already mask the
    # port, so nothing downstream can tell the difference.
    server_arguments = list(arguments.server_arg)
    example_arguments = list(arguments.arg)
    if not arguments.fixed_ports:
        if arguments.server:
            server_arguments += ["--listen", EPHEMERAL_BIND]
        elif arguments.interrupt_when:
            example_arguments += ["--listen", EPHEMERAL_BIND]

    server = None
    if arguments.server:
        server = ExampleServer(Path(arguments.server), arguments.server_ready, arguments.timeout,
                               server_arguments)
        if not server.start():
            return 1
        if not arguments.fixed_ports:
            url = server.endpoint_url()
            if url is None:
                print(f"FAILED: {Path(arguments.server).name} started but printed no opc.tcp:// URL, "
                      "so the client cannot be told where to connect", file=sys.stderr)
                server.stop()
                return 1
            example_arguments += ["--endpoint", url]
    arguments.arg = example_arguments

    try:
        if arguments.restart_server_when:
            if server is None:
                print("FAILED: --restart-server-when needs --server", file=sys.stderr)
                return 1
            outcome = run_with_server_restart(arguments, server)
            if outcome is None:
                return 1
            return report(normalise(outcome, arguments.mask), arguments)
        return compare(arguments)
    finally:
        if server is not None:
            server.stop()


def compare(arguments: argparse.Namespace) -> int:
    if arguments.interrupt_when:
        outcome = run_and_interrupt(arguments)
    else:
        outcome = run_to_completion(arguments)
    if outcome is None:
        return 1
    return report(normalise(outcome, arguments.mask), arguments)


def report(actual: str, arguments: argparse.Namespace) -> int:
    if arguments.update_golden:
        arguments.expected.write_text(actual, encoding="utf-8")
        print(f"updated {arguments.expected}")
        return 0

    if not arguments.expected.is_file():
        print(f"FAILED: no golden output at {arguments.expected}", file=sys.stderr)
        print("Re-run with --update-golden once the output is correct.", file=sys.stderr)
        return 1

    expected = normalise(arguments.expected.read_text(encoding="utf-8"), arguments.mask)
    if actual == expected:
        return 0

    print(f"FAILED: {arguments.binary.name} output does not match {arguments.expected.name}", file=sys.stderr)
    for line in difflib.unified_diff(
        expected.splitlines(keepends=True),
        actual.splitlines(keepends=True),
        fromfile="expected",
        tofile="actual",
    ):
        sys.stderr.write(line)
    return 1


if __name__ == "__main__":
    sys.exit(main())
