#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build="$root/build/helper"
fixtures=OFF
while (($#)); do
    case "$1" in
    --fixtures)
        fixtures=ON
        shift
        ;;
    --build-dir)
        if (($# < 2)) || [[ -z $2 || $2 == -* ]]; then
            printf '%s\n' 'Missing build directory after --build-dir' >&2
            exit 2
        fi
        build=$2
        shift 2
        ;;
    --help)
        printf '%s\n' 'Usage: helper/build-helper.sh [--fixtures] [--build-dir DIR]' 'Requires CMake, x86_64-w64-mingw32-g++ and nlohmann-json3-dev.' 'Set NLOHMANN_INCLUDE_DIR to an alternate include root. Fixtures are never run.'
        exit 0
        ;;
    *)
        printf 'Unknown option: %s\n' "$1" >&2
        exit 2
        ;;
    esac
done
args=(-S "$root/helper" -B "$build" "-DCMAKE_TOOLCHAIN_FILE=$root/helper/cmake/mingw_toolchain.cmake" -DCMAKE_BUILD_TYPE=Release "-DBUILD_TESTING=$fixtures")
if [[ -n ${NLOHMANN_INCLUDE_DIR:-} ]]; then
    args+=("-DNLOHMANN_INCLUDE_DIR=$NLOHMANN_INCLUDE_DIR")
fi
cmake "${args[@]}"
cmake --build "$build" --parallel
target=${CARGO_TARGET_DIR:-"$root/target"}
install -d "$target/debug/helpers" "$target/release/helpers"
for destination in "$target/debug/helpers" "$target/release/helpers"; do
    install -m 0644 "$build/proton_needle_helper_x64.exe" "$destination/"
done
printf 'Production helper installed beside Cargo binaries. Build artifacts: %s\n' "$build"
if [[ $fixtures == ON ]]; then
    printf '%s\n' 'Fixture-only helper and DLLs remain in the build directory. None are installed or run.'
fi
