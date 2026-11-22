#!/usr/bin/env python3
"""Opt-in helper-engine integration. Never accepts an existing prefix or discovers applications.

Run after helper/build-helper.sh --fixtures:
  python3 tests/helper_integration.py --wine /absolute/path/to/wine64 --fixtures build/helper
This tests the unchanged fixture-only C++ helper, not Rust runtime-route discovery.
"""

import argparse
import json
import os
from pathlib import Path
import selectors
import shutil
import stat
import subprocess
import struct
import tempfile
import time
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def bounded(command, environment, directory, payload=b"", seconds=20):
    """Bound both streams and always reap this one owned helper, including timeout."""
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(
        command,
        env=environment,
        cwd=directory,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    selector = selectors.DefaultSelector()
    output = bytearray()
    stderr_size = 0
    try:
        require(len(payload) < 4096, "Harness request unexpectedly large")
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        if payload:
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
        written = 0
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            require(
                time.monotonic() < deadline, "Owned fixture/helper transport timeout"
            )
            for key, _ in selector.select(max(0, deadline - time.monotonic())):
                if key.data == "stdin":
                    written += os.write(key.fd, payload[written:])
                    if written == len(payload):
                        selector.unregister(key.fileobj)
                        process.stdin.close()
                    continue
                data = os.read(key.fd, 8192)
                if not data:
                    selector.unregister(key.fileobj)
                elif key.data == "stdout":
                    output.extend(data)
                    require(len(output) <= 2 * 1024 * 1024, "Fixture stdout limit")
                else:
                    stderr_size += len(data)
                    require(stderr_size <= 65536, "Fixture stderr limit")
        return process.wait(timeout=max(0, deadline - time.monotonic())), bytes(output)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        if not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()
        process.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wine", required=True, type=Path)
    parser.add_argument("--fixtures", required=True, type=Path)
    args = parser.parse_args()
    require(os.geteuid() != 0, "Never run fixture integration as root")
    require(args.wine.is_absolute(), "Wine path must be explicit and absolute")
    wine = args.wine.resolve(strict=True)
    require(
        wine.name in ("wine", "wine64", "wine64-preloader"),
        "Only an explicit native Wine loader is accepted",
    )
    require(
        not any(
            word in str(wine).lower() for word in ("proton", "steam", "flatpak", "snap")
        ),
        "Do not use packaged/game runtimes",
    )
    server = (wine.parent / "wineserver").resolve(strict=True)
    require(
        os.access(wine, os.X_OK) and os.access(server, os.X_OK),
        "Native Wine and adjacent wineserver required",
    )
    artifacts = args.fixtures.resolve(strict=True)
    names = (
        "proton_needle_fixture_helper_x64.exe",
        "proton_needle_test_target.exe",
        "proton_needle_test.dll",
        "proton_needle_reject_test.dll",
        "proton_needle_timeout_test.dll",
        "proton_needle_exit_test.dll",
    )
    for name in names:
        require(
            (artifacts / name).is_file(), "Build all opted-in fixtures first: " + name
        )
    root = Path(tempfile.mkdtemp(prefix="proton-needle-helper-", dir="/tmp")).resolve()
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "WINEARCH": "win64",
        "WINEDEBUG": "-all",
        "WINEDLLOVERRIDES": "mscoree,mshtml=",
    }
    for key in (
        "HOME",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
    ):
        directory = root / key.lower()
        directory.mkdir(mode=0o700)
        environment[key] = str(directory)
    prefix = root / "prefix"
    prefix.mkdir(mode=0o700)
    environment["WINEPREFIX"] = str(prefix)
    fixture_dir = root / "fixtures"
    fixture_dir.mkdir(mode=0o700)
    for name in names:
        shutil.copyfile(artifacts / name, fixture_dir / name)
    unicode_name = "proton_needle_測試_🧪.dll"
    shutil.copyfile(fixture_dir / "proton_needle_test.dll", fixture_dir / unicode_name)
    # Malformed images are copies of our own DLL, never arbitrary external payloads.
    original_dll = (fixture_dir / "proton_needle_test.dll").read_bytes()
    nt_offset = struct.unpack_from("<I", original_dll, 60)[0]
    optional_offset = nt_offset + 24
    section_offset = (
        optional_offset + struct.unpack_from("<H", original_dll, nt_offset + 20)[0]
    )
    malformed_names = []
    for suffix, offset, value in (
        ("alignment", optional_offset + 32, 3),
        ("section", section_offset + 20, 0xFFFFFE00),
        ("managed", optional_offset + 112 + 14 * 8, 4096),
    ):
        name = "proton_needle_bad_" + suffix + ".dll"
        malformed = bytearray(original_dll)
        struct.pack_into("<I", malformed, offset, value)
        (fixture_dir / name).write_bytes(malformed)
        malformed_names.append(name)
    truncated_name = "proton_needle_bad_truncated.dll"
    (fixture_dir / truncated_name).write_bytes(original_dll[: optional_offset + 1])
    malformed_names.append(truncated_name)
    session, instance = uuid.uuid4().hex, uuid.uuid4().hex
    environment.update(
        PROTON_NEEDLE_FIXTURE_SESSION=session,
        PROTON_NEEDLE_TEST_INSTANCE=instance,
        PROTON_NEEDLE_TEST_READY=str(root / "target.ready"),
        PROTON_NEEDLE_TEST_MARKER=str(root / "target.marker"),
        PROTON_NEEDLE_TEST_STOP=str(root / "target.stop"),
        PROTON_NEEDLE_TEST_INTERRUPT=str(root / "INTERRUPTED"),
        PROTON_NEEDLE_TEST_GATE_EVENT="Local\\ProtonNeedleGate_" + session,
        PROTON_NEEDLE_TEST_GATE_RELEASE=str(root / "gate.release"),
        PROTON_NEEDLE_TEST_GATE_ENTERED=str(root / "gate.entered"),
    )
    # Pin every local executable/file/directory used to authorize launches and cleanup.
    pinned = {
        path: (path.stat().st_dev, path.stat().st_ino)
        for path in [
            root,
            prefix,
            wine,
            server,
            fixture_dir,
            *[fixture_dir / name for name in (*names, unicode_name, *malformed_names)],
        ]
    }
    bus = target = None
    clean = False
    bus_log = root / "bus.log"
    target_log = root / "target.log"

    def live_paths():
        for path, identity in pinned.items():
            metadata = path.lstat()
            require(
                not stat.S_ISLNK(metadata.st_mode),
                "Pinned fixture path became a symlink",
            )
            if path.is_relative_to(root):
                require(
                    metadata.st_uid == os.geteuid(),
                    "Pinned fixture path ownership changed",
                )
            require(
                (metadata.st_dev, metadata.st_ino) == identity,
                "Pinned fixture path identity changed",
            )
        require(
            stat.S_IMODE(root.stat().st_mode) == 0o700,
            "Private root permissions changed",
        )

    try:
        bus_socket = Path(environment["XDG_RUNTIME_DIR"]) / "bus"
        bus_address = "unix:path=" + str(bus_socket)
        environment["DBUS_SESSION_BUS_ADDRESS"] = bus_address
        with bus_log.open("wb") as log:
            bus = subprocess.Popen(
                [
                    "/usr/bin/dbus-daemon",
                    "--session",
                    "--nofork",
                    "--nopidfile",
                    "--address=" + bus_address,
                ],
                env=environment,
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
            )
        deadline = time.monotonic() + 5
        while not bus_socket.exists():
            require(
                bus.poll() is None and time.monotonic() < deadline,
                "Private fixture bus did not become ready",
            )
            time.sleep(0.02)
        pinned[bus_socket] = (bus_socket.stat().st_dev, bus_socket.stat().st_ino)
        live_paths()
        executable = fixture_dir / "proton_needle_test_target.exe"
        with target_log.open("wb") as log:
            target = subprocess.Popen(
                [str(wine), str(executable)],
                env=environment,
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
            )
        ready = root / "target.ready"
        deadline = time.monotonic() + 90
        while not ready.exists() or not ready.read_bytes().endswith(b"\n"):
            require(
                target.poll() is None and time.monotonic() < deadline,
                "Owned fixture did not become ready. See " + str(target_log),
            )
            time.sleep(0.05)
        fields = ready.read_text(encoding="utf-8").splitlines()
        require(
            len(fields) == 5 and fields[1] == session and fields[4] == instance,
            "Readiness token/instance mismatch",
        )
        pid, creation, image = int(fields[0]), int(fields[2]), fields[3]
        require(
            0 < pid <= 0xFFFFFFFF
            and str(pid) == fields[0]
            and 0 < creation <= 0xFFFFFFFFFFFFFFFF
            and str(creation) == fields[2],
            "Invalid fixture PID/creation",
        )
        mapped = image.replace("\\", "/")
        require(
            len(mapped) > 3 and mapped[1:3] == ":/", "Unexpected fixture Windows path"
        )
        drive = (prefix / "dosdevices" / (mapped[0].lower() + ":")).resolve(strict=True)
        require(
            (drive / mapped[3:]).resolve(strict=True) == executable,
            "Readiness image is not our copied fixture",
        )
        require(target.poll() is None, "Owned target exited before registration")
        proc = Path("/proc") / str(target.pid)
        ticks = proc.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19]
        expected_environment = proc.joinpath("environ").read_bytes()
        for key in (
            "WINEPREFIX",
            "PROTON_NEEDLE_FIXTURE_SESSION",
            "PROTON_NEEDLE_TEST_INSTANCE",
        ):
            require(
                (key + "=" + environment[key]).encode() + b"\0" in expected_environment,
                "Owned fixture environment mismatch",
            )
        registry = [
            {
                "windows_pid": pid,
                "image_path": image,
                "creation_time": str(creation),
                "fixture_instance": instance,
            }
        ]

        def helper(operation, extra=None, argument=False):
            live_paths()
            require(
                bus.poll() is None and target.poll() is None,
                "Owned fixture/bus lifetime ended",
            )
            require(
                proc.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19]
                == ticks,
                "Owned target start identity changed",
            )
            require(
                proc.joinpath("environ").read_bytes() == expected_environment,
                "Owned target environment changed",
            )
            request_id = uuid.uuid4().hex
            request = dict(
                protocol_version=1,
                request_id=request_id,
                operation=operation,
                fixture_session=session,
                fixture_targets=registry,
            )
            request.update(extra or {})
            payload = json.dumps(request, separators=(",", ":")).encode()
            command = [str(wine), str(fixture_dir / names[0])]
            if argument:
                command += ["--request-json", payload.decode()]
            code, output = bounded(
                command, environment, root, b"" if argument else payload + b"\n"
            )
            require(
                output.endswith(b"\n") and output.count(b"\n") == 1,
                "Expected one helper JSON line",
            )
            response = json.loads(output)
            require(
                response.get("request_id") == request_id
                and response.get("operation") == operation
                and response.get("protocol_version") == 1,
                "Uncorrelated helper response",
            )
            require(
                (code == 0) == (response.get("status") == "success"),
                "Helper status/exit mismatch",
            )
            return response

        for argument in (False, True):
            probe = helper("probe", argument=argument)
            require(
                probe["status"] == "success" and probe["methods"] == ["load_library_w"],
                "Fixture probe/method failed",
            )
        listing = helper("list_processes")
        require(
            listing.get("wine_detected") is True
            and isinstance(listing.get("wine_version"), str)
            and listing["wine_version"],
            "Enumeration runtime metadata missing",
        )
        require(
            any(
                row["windows_pid"] == pid
                and row["image_path"] == image
                and row["creation_time"] == str(creation)
                and row["architecture"] == "x64"
                for row in listing.get("processes", [])
            ),
            "Fresh enumeration omitted owned fixture",
        )
        bad_registry = [dict(registry[0], fixture_instance=uuid.uuid4().hex)]
        refused = helper("list_processes", {"fixture_targets": bad_registry})
        require(
            refused.get("error_code") == "fixture_safety",
            "Missing readiness proof was accepted",
        )

        def inject(name, **changes):
            request = dict(
                target_windows_pid=pid,
                expected_image_path=image,
                expected_creation_time=str(creation),
                dll_path=str(fixture_dir / name),
                method="load_library_w",
                timeout_ms=10000,
            )
            request.update(changes)
            return helper("inject", request)

        obsolete = inject("proton_needle_test.dll", method="load_library_a")
        require(
            obsolete.get("error_code") == "unsupported_method"
            and obsolete.get("inconclusive") is False,
            "Obsolete ANSI method was accepted",
        )
        wrong = inject(
            "proton_needle_test.dll", expected_creation_time=str(creation + 1)
        )
        require(
            wrong.get("error_code") == "identity_mismatch"
            and wrong.get("inconclusive") is False,
            "Stale creation identity was accepted",
        )
        for name in malformed_names:
            invalid = inject(name)
            require(
                invalid.get("error_code") == "invalid_dll"
                and not invalid.get("inconclusive"),
                "Malformed fixture PE was not rejected: " + name,
            )
        require(
            not (root / "target.marker").exists(),
            "Rejected preflight unexpectedly loaded a DLL",
        )
        rejected = inject("proton_needle_reject_test.dll")
        require(
            rejected.get("error_code") == "load_library_failed"
            and rejected.get("inconclusive") is True,
            "Initialization rejection did not preserve the unknown execution outcome",
        )
        require(
            (root / "target.marker").read_text().strip() == str(pid),
            "Rejected DLL did not leave its code-executed PID marker",
        )
        (root / "target.marker").unlink()
        timeout = inject("proton_needle_timeout_test.dll", timeout_ms=500)
        require(
            timeout.get("error_code") == "injection_timeout"
            and timeout.get("inconclusive") is True,
            "Loader timeout was not inconclusive",
        )
        require(
            (root / "gate.entered").exists(), "Timeout fixture never entered its gate"
        )
        (root / "gate.release").touch()
        deadline = time.monotonic() + 5
        while not (root / "target.marker").exists():
            require(
                time.monotonic() < deadline and target.poll() is None,
                "Timed-out fixture did not complete after gate release",
            )
            time.sleep(0.02)
        (root / "target.marker").unlink()
        loaded = inject("proton_needle_test.dll")
        require(
            loaded.get("verified") is True
            and loaded.get("target_windows_pid") == pid
            and int(loaded.get("module_base", "0")) > 0
            and loaded.get("loaded_module_path"),
            "Verified loading evidence missing",
        )
        require(
            loaded.get("target_image_path") == image
            and loaded.get("target_creation_time") == str(creation)
            and loaded.get("file_identity_verified") is True
            and loaded.get("method") == "load_library_w",
            "Target/file/method evidence missing",
        )
        require(
            (root / "target.marker").read_text().strip() == str(pid),
            "DLL marker PID mismatch",
        )
        duplicate = inject("proton_needle_test.dll")
        require(
            duplicate.get("error_code") == "dll_already_loaded"
            and duplicate.get("inconclusive") is False,
            "Duplicate load was not rejected",
        )
        (root / "target.marker").unlink()
        unicode = inject(unicode_name)
        require(
            unicode.get("status") == "success"
            and unicode.get("file_identity_verified") is True
            and unicode.get("loaded_module_path", "").endswith(unicode_name),
            "Real Unicode DLL path was not verified",
        )
        require(
            (root / "target.marker").read_text().strip() == str(pid),
            "Unicode DLL marker PID mismatch",
        )
        exited = inject("proton_needle_exit_test.dll")
        require(
            exited.get("status") == "error" and exited.get("inconclusive") is True,
            "Target exit after starting the loader was reported conclusive",
        )
        print(
            "PASS: private fixture probe/stdin/argv, enumeration metadata, readiness proof, stale identity, ANSI-method rejection, code-executed rejection with unknown outcome, timeout/completion, verified ASCII/Unicode load, duplicate load, unknown target-exit outcome"
        )
    finally:
        try:
            live_paths()
            (root / "gate.release").touch()
            (root / "target.stop").touch()
            if target is not None:
                try:
                    target.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            # Exact adjacent wineserver, with the same newly created pinned private prefix only.
            wait_code, _ = bounded([str(server), "-w"], environment, root, seconds=5)
            clean = wait_code == 0
        finally:
            # Reap our one owned fixture even if a pinned-path or server check failed.
            if target is not None:
                if target.poll() is None:
                    target.kill()
                target.wait(timeout=5)
            if bus is not None:
                if bus.poll() is None:
                    bus.terminate()
                try:
                    bus.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    bus.kill()
                    bus.wait()
            if clean:
                shutil.rmtree(root)
            else:
                print(
                    "Cleanup could not prove private fixture shutdown. Retained:", root
                )


if __name__ == "__main__":
    main()
