# Blutter Setup And libapp.so Reconstruction

This note records how the Dart AOT snapshot in `libapp.so` was reconstructed, so the environment can
be rebuilt. It supports the analysis approach chosen in `Summary.md`.

## Tool

blutter by worawit reconstructs Flutter AOT snapshots into symbolized arm64 assembly plus an object
pool dump, a Frida hook template, and an IDA naming script. Source is
`https://github.com/worawit/blutter`.

## Build Environment

The build host is Debian 12 (bookworm). blutter's own executable uses the C++20 `<format>` library,
which needs g++>=13 or clang>=16. bookworm ships g++ 12 and has no installable g++ 13 (the trixie
build would mismatch glibc), so the build uses clang 19 with libc++ instead. The Dart runtime static
library and the blutter executable are both compiled with clang plus libc++ so their C++ standard
library ABI matches when they are linked together.

Packages installed with apt:

```
clang-19 libc++-19-dev libc++abi-19-dev lld-19 cmake ninja-build pkg-config \
libicu-dev libcapstone-dev python3-pyelftools python3-requests build-essential git
```

## Source Patch

blutter's `blutter/CMakeLists.txt` adds macOS only linker flags on the Clang path, including
`-dead_strip` and an Apple libc++ search path. Those break the GNU or lld linker on Linux. The fix
gates that block behind `if (APPLE)`. On Linux the libc++ standard library is selected through the
environment variables below instead.

```cmake
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if (APPLE)
        cmake_path(GET CMAKE_CXX_COMPILER PARENT_PATH LLVM_BIN_DIR)
        add_compile_options(-fexperimental-library)
        add_link_options(-fexperimental-library -L${LLVM_BIN_DIR}/../lib/c++ -dead_strip)
    endif()
endif()
```

## Run Command

The environment variables force clang plus libc++ for both the Dart runtime build and the blutter
build. The input is the arm64-v8a library directory that holds `libapp.so` and `libflutter.so`. The
output directory is separate and no project files are modified.

```
CC=clang-19 CXX=clang++-19 CXXFLAGS="-stdlib=libc++" LDFLAGS="-stdlib=libc++" \
  python3 blutter.py \
    apk/com.oceanwing.soundcore-423/resources/lib/arm64-v8a \
    <output_dir>
```

blutter auto-detects the target. It reported Dart `3.4.4`, snapshot
`d20a1be77c3d3c41b2a5accaee1ce549`, target `android arm64`, `compressed-pointers`. It then sparse
clones the Dart `3.4.4` source, builds the Dart runtime static library, builds the blutter
executable, and runs it against `libapp.so`.

## Output

The run produced the following in the output directory:

- `asm/`: 2367 files of symbolized arm64 assembly, grouped into 131 package directories. Dart class,
  method, and library names are present because the snapshot is not obfuscated.
- `pp.txt`: 7.5 MB dump of all objects in the object pool, including string literals.
- `objs.txt`: nested dump of objects from the object pool.
- `blutter_frida.js`: Frida script template for hooking the target.
- `ida_script/addNames.py` and `ida_script/ida_dart_struct.h`: IDA naming script and struct header.

Only 80 analysis errors were logged across the whole snapshot, so coverage is high. blutter emits an
IDA script rather than a Ghidra script. If Ghidra is used later, the symbol names still come from
the `asm/` listings and `pp.txt`.

## Reproduction Notes

- The output currently lives in the session scratchpad, which is not committed and may be cleared.
  Regenerate with the command above, or relocate it into the project if it should persist.
- The `dartsdk/`, `build/`, and `packages/` directories that blutter creates can be deleted after
  the build. The compiled blutter executable is cached under `bin/`, so re-running against another
  Dart 3.4.4 app skips the runtime build.
