#!/usr/bin/env python3
"""Opt in to the ignored Rust backend fixture, with a private headless session bus.

Build fixtures separately: helper/build-helper.sh --fixtures
Run: python3 tests/helper_backend.py --wine /absolute/path/to/wine64 --fixtures build/helper
No existing prefix, Steam service, or application PID is accepted. The Rust test owns
its independently launched fixture Child and gates all helper calls to that registry.
"""

import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wine", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("Never run runtime integration as root")
    if not args.wine.is_absolute():
        parser.error("Wine path must be explicit and absolute")
    wine = args.wine.resolve(strict=True)
    fixtures = args.fixtures.resolve(strict=True)
    cargo = shutil.which("cargo")
    if cargo is None:
        parser.error("Cargo is required")
    root = Path(tempfile.mkdtemp(prefix="proton-needle-backend-", dir="/tmp")).resolve()
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    address = "unix:path=" + str(runtime / "bus")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        not in (
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "WINEPREFIX",
            "WINELOADER",
            "WINESERVER",
            "WINELOADERNOEXEC",
            "FLATPAK_ID",
        )
        and not key.upper().startswith(
            ("STEAM", "PROTON_", "PRESSURE_VESSEL_", "SNAP", "SRT_")
        )
    }
    environment.update(
        DBUS_SESSION_BUS_ADDRESS=address,
        PROTON_NEEDLE_PRIVATE_TEST_BUS="1",
        PROTON_NEEDLE_TEST_ROOT=str(root),
        PROTON_NEEDLE_TEST_WINE=str(wine),
        PROTON_NEEDLE_TEST_FIXTURES=str(fixtures),
    )
    bus = test = None
    try:
        with (root / "bus.log").open("wb") as log:
            bus = subprocess.Popen(
                [
                    "/usr/bin/dbus-daemon",
                    "--session",
                    "--nofork",
                    "--nopidfile",
                    "--address=" + address,
                ],
                env=environment,
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
            )
        deadline = time.monotonic() + 5
        while not (runtime / "bus").exists():
            if bus.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Private test bus did not become ready")
            time.sleep(0.02)
        if not stat.S_ISSOCK((runtime / "bus").stat().st_mode):
            raise RuntimeError("Private bus path is not a socket")
        project = Path(__file__).resolve().parent.parent
        test = subprocess.Popen(
            [
                cargo,
                "test",
                "helper::tests::backend::controlled_backend_fixture",
                "--",
                "--ignored",
                "--exact",
                "--nocapture",
            ],
            env=environment,
            cwd=project,
        )
        try:
            return test.wait(timeout=180)
        except subprocess.TimeoutExpired:
            (root / "INTERRUPTED").touch()
            test.terminate()
            try:
                test.wait(timeout=10)
            except subprocess.TimeoutExpired:
                test.kill()
                test.wait()
            raise RuntimeError(
                "Backend test deadline exceeded. Fixture has a five-minute lifetime cap"
            )
    finally:
        if test is not None and test.poll() is None:
            (root / "INTERRUPTED").touch()
            test.terminate()
            try:
                test.wait(timeout=10)
            except subprocess.TimeoutExpired:
                test.kill()
                test.wait()
        if bus is not None:
            if bus.poll() is None:
                bus.terminate()
            try:
                bus.wait(timeout=3)
            except subprocess.TimeoutExpired:
                bus.kill()
                bus.wait()
        if list(root.glob("session-*")):
            print("Retained private fixture state after unproven teardown:", root)
        else:
            shutil.rmtree(root)


if __name__ == "__main__":
    raise SystemExit(main())
