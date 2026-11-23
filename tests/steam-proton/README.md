# Steam/Proton Compatibility Tests

This guide describes how to verify ProtonNeedle with a controlled Windows test application launched through Steam/Proton. **Do not use real games for these tests.**

## Test Fixtures

Both files are built into `build/helper/steam-proton/`.

| File | Description |
|---|---|
| `proton_needle_steam_target.exe` | x64 Win32 application displaying its PID, creation time, executable path, Wine version, and DLL status. |
| `proton_needle_steam_probe.dll` | x64 test DLL that only accepts the designated test executable and exposes its loaded state and PID. |

The fixtures require no elevated privileges, network access, or additional services.

## Automated Tests

Build and validate the fixtures:

```bash
cargo build --release
./helper/build-helper.sh --fixtures
python3 tests/steam_fixtures.py --fixtures build/helper
```

Optional native Wine self-test:

```bash
python3 tests/steam_fixtures.py \
  --fixtures build/helper \
  --wine /absolute/path/to/native/wine
```

Automated tests verify PE architecture, required exports, dependencies, and basic DLL loading.

**These tests use native Wine, not Steam/Proton.** Real Proton compatibility must be verified manually.

## Manual Testing

### 1. Prepare the Fixtures

```bash
mkdir -p ~/ProtonNeedleTest

cp build/helper/steam-proton/proton_needle_steam_{target.exe,probe.dll} \
  ~/ProtonNeedleTest/
```

### 2. Configure Steam

1. Add `proton_needle_steam_target.exe` as a non-Steam game.
2. Open **Properties -> Compatibility**.
3. Enable a specific Proton version.
4. Leave launch options empty.
5. Launch the application.

The test window should display the Windows PID, Wine version, and `Probe DLL: not loaded`.

### 3. Verify ProtonNeedle Detection

Launch ProtonNeedle separately:

```bash
./target/release/proton-needle --list
./target/release/proton-needle --passive
./target/release/proton-needle
```

Verify that:

- The test process appears exactly once.
- Windows PID and executable path match the target window.
- The correct Proton version and Wine prefix are detected.
- Runtime packaging is identified correctly (`native_proton`, `flatpak`, or `steam_snap`).
- Runtime diagnostics show a valid execution route.

Use `d` for process details and `l` for diagnostics.

### 4. Test DLL Loading

Select the test process in ProtonNeedle:

1. Press `p` and enter the absolute path to `proton_needle_steam_probe.dll`.
2. Confirm validation and review the operation.
3. Press `y` to proceed.

**Success criteria:**

- ProtonNeedle reports a verified module load.
- The test window displays `Probe DLL: LOADED`.
- The reported PID matches the target process.
- A second load is rejected or recognized as already loaded.
- Closing the test window terminates the application normally.

Do not automatically retry uncertain operations.

## Compatibility Matrix

**Verified** means the complete manual procedure passed. Native Wine tests alone do not qualify.

| Steam Installation | Proton Version | Status |
|---|---|---|
| Native | Stable | Untested |
| Native | Experimental | Untested |
| Native | GE-Proton | Untested |
| Flatpak | Any | Untested |
| Snap | Stable | **Verified** |
| Snap | Experimental | **Verified** |

### Verified Environment: Snap Steam

| Property | Value |
|---|---|
| Distribution | Ubuntu |
| Steam package | Snap |
| Steam version | 1.0.0.87 |
| Snap revision | 289 |
| Channel | `latest/stable` |
| Publisher | Canonical |
| Proton Stable | **PASS** |
| Proton Experimental | **PASS** |

Both configurations passed the manual test procedure using the dedicated test fixtures.