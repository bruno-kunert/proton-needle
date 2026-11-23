#!/usr/bin/env python3
"""Checks for the standalone Steam/Proton manual-test fixtures. Never touches Steam or Proton.

Run after helper/build-helper.sh --fixtures:
  python3 tests/steam_fixtures.py --fixtures build/helper
  python3 tests/steam_fixtures.py --fixtures build/helper --wine /absolute/path/to/native/wine

Static checks parse the PE files only. --wine additionally runs the target's non-interactive
--self-test in a private, temporary native Wine prefix. Passing proves the fixture pair builds and
works under native Wine; it is not evidence of Steam/Proton compatibility.
"""

import argparse
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

TARGET = "proton_needle_steam_target.exe"
PROBE = "proton_needle_steam_probe.dll"
PROBE_EXPORTS = {"proton_needle_steam_probe_pid", "proton_needle_steam_probe_version"}
FORBIDDEN_IMPORTS = {
    "libstdc++-6.dll",
    "libgcc_s_seh-1.dll",
    "libwinpthread-1.dll",
    "ws2_32.dll",
    "wsock32.dll",
    "wininet.dll",
    "winhttp.dll",
    "urlmon.dll",
}
IMAGE_FILE_DLL = 0x2000
SUBSYSTEM_GUI = 2


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Image:
    """Minimal PE32+ reader: headers, imports and export names."""

    def __init__(self, path):
        self.data = path.read_bytes()
        data = self.data
        require(data[:2] == b"MZ", f"{path.name}: not a PE image")
        nt = struct.unpack_from("<I", data, 0x3C)[0]
        require(data[nt : nt + 4] == b"PE\0\0", f"{path.name}: missing PE signature")
        machine, sections, _, _, _, optional_size, self.characteristics = (
            struct.unpack_from("<HHIIIHH", data, nt + 4)
        )
        require(machine == 0x8664, f"{path.name}: not x64")
        optional = nt + 24
        require(
            struct.unpack_from("<H", data, optional)[0] == 0x20B,
            f"{path.name}: not PE32+",
        )
        self.subsystem = struct.unpack_from("<H", data, optional + 68)[0]
        directories = optional + 112
        self.directories = [
            struct.unpack_from("<II", data, directories + 8 * index)
            for index in range(16)
        ]
        table = optional + optional_size
        self.sections = [
            struct.unpack_from("<IIII", data, table + 40 * index + 8)
            for index in range(sections)
        ]

    def offset(self, rva):
        for virtual_size, address, raw_size, raw in self.sections:
            if address <= rva < address + max(virtual_size, raw_size):
                return raw + rva - address
        raise RuntimeError(f"RVA {rva:#x} is outside every section")

    def string(self, rva):
        start = self.offset(rva)
        return self.data[start : self.data.index(b"\0", start)].decode("ascii")

    def imports(self):
        rva, _ = self.directories[1]
        names = set()
        cursor = self.offset(rva) if rva else None
        while cursor is not None:
            descriptor = struct.unpack_from("<IIIII", self.data, cursor)
            if not any(descriptor):
                break
            names.add(self.string(descriptor[3]).lower())
            cursor += 20
        return names

    def exports(self):
        rva, _ = self.directories[0]
        if not rva:
            return set()
        base = self.offset(rva)
        count = struct.unpack_from("<I", self.data, base + 24)[0]
        names = struct.unpack_from("<I", self.data, base + 32)[0]
        return {
            self.string(
                struct.unpack_from("<I", self.data, self.offset(names) + 4 * i)[0]
            )
            for i in range(count)
        }


def static_checks(directory):
    target = Image(directory / TARGET)
    probe = Image(directory / PROBE)
    require(not target.characteristics & IMAGE_FILE_DLL, f"{TARGET}: built as DLL")
    require(
        target.subsystem == SUBSYSTEM_GUI, f"{TARGET}: not a GUI-subsystem executable"
    )
    require(probe.characteristics & IMAGE_FILE_DLL, f"{PROBE}: not a DLL")
    missing = PROBE_EXPORTS - probe.exports()
    require(not missing, f"{PROBE}: missing exports {sorted(missing)}")
    for name, image in ((TARGET, target), (PROBE, probe)):
        forbidden = image.imports() & FORBIDDEN_IMPORTS
        require(not forbidden, f"{name}: forbidden imports {sorted(forbidden)}")
    require("user32.dll" not in probe.imports(), f"{PROBE}: must not import user32")


def wine_self_test(wine, directory):
    """Run --self-test in a throwaway prefix with a minimal, private environment."""
    require(os.geteuid() != 0, "Never run fixture tests as root")
    require(wine.is_absolute(), "Wine path must be explicit and absolute")
    wine = wine.resolve(strict=True)
    require(
        wine.name in ("wine", "wine64"),
        "Only an explicit native Wine loader is accepted",
    )
    require(
        not any(
            word in str(wine).lower() for word in ("proton", "steam", "flatpak", "snap")
        ),
        "Do not use packaged/game runtimes",
    )
    root = Path(tempfile.mkdtemp(prefix="proton-needle-steam-", dir="/tmp")).resolve()
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "WINEARCH": "win64",
        "WINEDEBUG": "-all",
        "WINEDLLOVERRIDES": "mscoree,mshtml=",
        "WINEPREFIX": str(root / "prefix"),
    }
    for key in (
        "HOME",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
    ):
        path = root / key.lower()
        path.mkdir(mode=0o700)
        environment[key] = str(path)
    work = root / "fixtures"
    work.mkdir()
    for name in (TARGET, PROBE):
        shutil.copy2(directory / name, work / name)
    server = wine.parent / "wineserver"
    try:
        result = subprocess.run(
            [str(wine), str(work / TARGET), "--self-test"],
            env=environment,
            cwd=work,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=180,
        )
        require(
            result.returncode == 0,
            f"Self-test failed with exit code {result.returncode}: "
            + result.stderr.decode(errors="replace")[-2000:],
        )
    finally:
        if server.is_file():
            subprocess.run(
                [str(server), "-k"], env=environment, timeout=30, capture_output=True
            )
            subprocess.run(
                [str(server), "-w"], env=environment, timeout=60, capture_output=True
            )
        shutil.rmtree(root, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--wine", type=Path)
    args = parser.parse_args()
    directory = args.fixtures.resolve(strict=True) / "steam-proton"
    for name in (TARGET, PROBE):
        require(
            (directory / name).is_file(), f"Build fixtures first: {directory / name}"
        )
    static_checks(directory)
    print("Steam fixture static checks passed")
    if args.wine:
        wine_self_test(args.wine, directory)
        print("Steam fixture native Wine self-test passed (not a Proton result)")


if __name__ == "__main__":
    main()
