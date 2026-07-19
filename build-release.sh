#!/usr/bin/env bash
# Reproducible, privacy-hardened release build.
#
# Rewrites machine-specific absolute paths (CARGO_HOME and this checkout's
# location — both of which embed the OS user name) out of the binary, strips
# symbols, and removes the side-car PDB. Run from the crate root:
#
#   ./build-release.sh
#
# The resulting binary is at target/release/sni-gate.exe (or sni-gate
# on Unix) and contains no local filesystem paths.
set -euo pipefail

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
workspace="$(pwd)"

# --remap-path-prefix rewrites the leading path component in every embedded
# Rust source reference. Longest / most-specific prefixes first.
export RUSTFLAGS="\
--remap-path-prefix=${cargo_home}=cargo \
--remap-path-prefix=${workspace}=. \
-Cstrip=symbols"

# C dependencies (aws-lc-sys) embed their own absolute __FILE__ paths that
# RUSTFLAGS cannot reach. MSVC's cl.exe has no path-remap flag, so we build the
# C code with clang (which does) and remap with -ffile-prefix-map. clang-cl
# keeps MSVC ABI compatibility for the msvc target. Applied to both the registry
# (where aws-lc-sys lives) and the workspace.
c_remap="-ffile-prefix-map=${cargo_home}=cargo -ffile-prefix-map=${workspace}=."
export CC="clang"
export CXX="clang++"
export CFLAGS="${CFLAGS:-} ${c_remap}"
export CXXFLAGS="${CXXFLAGS:-} ${c_remap}"
# Tell aws-lc-sys's CMake build to use clang for both languages.
export CMAKE_C_COMPILER="clang"
export CMAKE_CXX_COMPILER="clang++"

# A clean build is required: cached dependency artifacts were compiled without
# the remaps and would otherwise keep their absolute paths.
cargo clean --release
cargo build --release

# The PDB (Windows) embeds the build path; never ship it.
rm -f target/release/*.pdb

# Report the produced binary (sni-gate on Unix, sni-gate.exe on Windows).
if [ -f target/release/sni-gate.exe ]; then
  echo "Release binary: target/release/sni-gate.exe"
else
  echo "Release binary: target/release/sni-gate"
fi
