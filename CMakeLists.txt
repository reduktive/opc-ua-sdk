# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

cmake_minimum_required(VERSION 3.21)

project(SDK VERSION 1.0.0)

# Full version of the deliberately approved release. CMake's project(VERSION)
# accepts only the numeric core, while public tags and package metadata retain
# the SemVer prerelease component.
set(UASDK_RELEASE_VERSION "1.0.0-rc.1")

# Expose our own helpers (UAGenerateTypes etc.) on CMAKE_MODULE_PATH so
# downstream consumers that `add_subdirectory(sdk)` can simply
# `include(UAGenerateTypes)` to access ua_generate_types().
list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# Compiler floors (GCC 13 / Clang 19 / MSVC 19.50), refused here with one sentence rather than
# discovered later as template errors inside <coroutine> - or not discovered at all. The numbers,
# their rationale and the escape hatch live in cmake/UaCompilerFloor.cmake, which the installed
# package config runs as well. First thing after project(), so nothing below configures on a
# compiler that is known to miscompile the SDK.
include(UaCompilerFloor)
ua_check_compiler_floor()

include(GNUInstallDirs)

# -- Link and compile concurrency ---------------------------------------------
# Ninja schedules compiles and links at the full -j width, so peak memory scales
# with core count rather than with available RAM, and a host with many cores
# relative to its memory is driven into swap or killed outright. Two dedicated job
# pools bound each phase independently of -j. Both defaults may be overridden from
# the environment: a builder that has already sized its own concurrency - a CI
# container with a memory cap, a dedicated build machine - can then set the bound
# once for a whole pipeline instead of repeating a -D on every configure line, which
# is the kind of flag that gets forgotten in exactly the job that needed it.
#
# Both pools are confined to a top-level build of the SDK, for the same reason the
# ccache/mold/PCH block below is: when the SDK is consumed through add_subdirectory()
# or FetchContent, the concurrency of the build belongs to the parent project, and a
# dependency has no business narrowing it. A consumer that wants the bound sets it.
#
# Linking is the cheaper phase wherever mold is in use (see UASDK_USE_MOLD below):
# mold streams its output instead of holding the whole image resident, so a link of
# even a multi-gigabyte debug binary costs well under a hundred megabytes. The bound
# is retained for the hosts that fall back to GNU ld, where the same link holds the
# symbol table, relocations and debug info in memory and is orders of magnitude
# more expensive. 0 restores Ninja's default.
if (DEFINED ENV{UASDK_LINK_JOBS})
    set(_uasdk_link_jobs_default "$ENV{UASDK_LINK_JOBS}")
else ()
    set(_uasdk_link_jobs_default "2")
endif ()
set(UASDK_LINK_JOBS "${_uasdk_link_jobs_default}" CACHE STRING
        "Maximum concurrent link steps (Ninja only; 0 = unbounded)")

if (PROJECT_IS_TOP_LEVEL AND CMAKE_GENERATOR MATCHES "Ninja" AND NOT UASDK_LINK_JOBS STREQUAL "0")
    set_property(GLOBAL APPEND PROPERTY JOB_POOLS uasdk_link=${UASDK_LINK_JOBS})
    set(CMAKE_JOB_POOL_LINK uasdk_link)
endif ()

# Compiling is the dominant term. The heaviest test translation units of this SDK
# cost around 2 GB resident each, and they also compile several times slower than an
# ordinary one, so they accumulate: at any instant the running set skews towards the
# expensive end rather than towards the average translation unit. The bound has to be
# sized against the heavy TU, not the mean, or it under-counts the peak by more than
# a factor of two.
#
# The default is conservative rather than unbounded because getting this wrong does
# not fail loudly. An unbounded build on a developer machine exhausts the host and is
# killed by the OOM daemon, which takes the whole terminal session with it and leaves
# no failing build to read. A builder with memory to spare raises the bound.
if (DEFINED ENV{UASDK_COMPILE_JOBS})
    set(_uasdk_compile_jobs_default "$ENV{UASDK_COMPILE_JOBS}")
else ()
    set(_uasdk_compile_jobs_default "6")
endif ()
set(UASDK_COMPILE_JOBS "${_uasdk_compile_jobs_default}" CACHE STRING
        "Maximum concurrent compile steps (Ninja only; 0 = unbounded)")

if (PROJECT_IS_TOP_LEVEL AND CMAKE_GENERATOR MATCHES "Ninja" AND NOT UASDK_COMPILE_JOBS STREQUAL "0")
    set_property(GLOBAL APPEND PROPERTY JOB_POOLS uasdk_compile=${UASDK_COMPILE_JOBS})
    set(CMAKE_JOB_POOL_COMPILE uasdk_compile)
endif ()

# -- Consumer vs developer build profile --------------------------------------
# The SDK's own test, documentation and generator targets build or verify the SDK itself, and every
# one of them reads a tree that only a development checkout carries. Whether to build them is not
# the same question as PROJECT_IS_TOP_LEVEL: a standalone build of the published source-available
# tree is the top-level project without being a development checkout, and defaulting these options
# from PROJECT_IS_TOP_LEVEL conflated the two - it turned them on and then failed on directories the
# published tree does not have.
#
# It is not a flag either. A flag has to be remembered - in every preset, and in every CI job that
# configures without one - and forgetting it yields a build that contains no test targets and still
# reports success. That failure is silent, which is the dangerous kind.
#
# The fact is observable instead. A development checkout carries the private material; a published
# tree says it is not one by not carrying it. One marker answers the question for every option
# below, and it answers it the same way from any build directory, with or without a preset.
# Every private path below is expressed relative to this one directory, so the published tree
# carries a single name it does not have rather than a scattering of them.
set(_uasdk_private_dir "${CMAKE_CURRENT_LIST_DIR}/internal")
set(_uasdk_private_tree FALSE)
if (IS_DIRECTORY "${_uasdk_private_dir}")
    set(_uasdk_private_tree TRUE)
endif ()

set(_uasdk_development FALSE)
if (PROJECT_IS_TOP_LEVEL AND _uasdk_private_tree)
    set(_uasdk_development TRUE)
endif ()

# A standalone build - this repository as the top-level project, published or private - builds the
# examples and the optional Historical Access tier. A consumer embedding the SDK through
# add_subdirectory() or FetchContent gets a libraries-only build and adds what it wants.
set(_uasdk_standalone_default ${PROJECT_IS_TOP_LEVEL})

option(UASDK_BUILD_TESTS         "Build the SDK test suites"                  ${_uasdk_development})
option(UASDK_BUILD_EXAMPLES      "Build the example projects under examples/" ${_uasdk_standalone_default})
option(UASDK_BUILD_EXAMPLE_TESTS "Register the examples' behaviour tests (needs Python3)" ${_uasdk_development})
option(UASDK_BUILD_DOCS_EXAMPLES "Build the documentation example snippets"   ${_uasdk_development})
option(UASDK_REGENERATE_TYPES    "Enable the type-generator target (needs Python3 + UA-Nodeset clone)" ${_uasdk_development})
option(UASDK_BUILD_HISTORY       "Build the optional Historical Access component (uasdk-history[-sqlite])" ${_uasdk_standalone_default})

# Each development option is guarded on the input it actually consumes, and the guard is on the
# OPTION rather than on the directory. A tree that cannot satisfy an option the caller explicitly
# asked for has to say so here, by name - the alternative is a failure deep inside add_subdirectory()
# that names a path rather than the switch that reached for it. The directory-guarded form is right
# where absence is expected and silent skipping is correct (see the private development applications below); it is wrong here,
# where absence means the caller asked for something this tree cannot do.
if (UASDK_BUILD_TESTS AND NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/tests/CMakeLists.txt")
    message(FATAL_ERROR "UASDK_BUILD_TESTS is ON but this tree carries no tests/ directory.")
endif ()
if (UASDK_BUILD_EXAMPLE_TESTS AND NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/tooling/examples/run_example_test.py")
    message(FATAL_ERROR
            "UASDK_BUILD_EXAMPLE_TESTS is ON but this tree carries no example-test harness "
            "(tooling/examples/run_example_test.py).")
endif ()
if (UASDK_BUILD_DOCS_EXAMPLES AND NOT EXISTS "${_uasdk_private_dir}/documentation/examples/CMakeLists.txt")
    message(FATAL_ERROR
            "UASDK_BUILD_DOCS_EXAMPLES is ON but this tree carries no documentation examples.")
endif ()
if (UASDK_REGENERATE_TYPES)
    if (NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/tooling/type_generator/run_type_generator.py")
        message(FATAL_ERROR
                "UASDK_REGENERATE_TYPES is ON but this tree carries no tooling/type_generator/.")
    endif ()
    # cmake/UAGenerateTypes.cmake degrades to a no-op without an interpreter, which is right for a
    # consumer including the module and wrong for a build that asked to regenerate: the generator
    # would produce nothing and the build would succeed against whatever is committed.
    find_package(Python3 QUIET COMPONENTS Interpreter)
    if (NOT Python3_FOUND)
        message(FATAL_ERROR
                "UASDK_REGENERATE_TYPES is ON but no Python3 interpreter was found; the type "
                "generator cannot run and would silently produce nothing.")
    endif ()
endif ()

# The dangerous direction is the quiet one: a development checkout that builds no test binaries and
# reports success. option() writes its value to the cache on the FIRST configure, so no default -
# this marker included - reaches an existing build directory. This check does, because it
# re-evaluates the cached value on every reconfigure.
if (_uasdk_development AND NOT UASDK_BUILD_TESTS)
    message(WARNING
            "UASDK_BUILD_TESTS is OFF in a development checkout: this build produces no test "
            "binaries. Pass -DUASDK_BUILD_TESTS=ON, or delete the build directory if the value was "
            "cached by an earlier configure.")
endif ()

# Exact revision embedded in release documentation. Release/archive builders may
# provide this explicitly; a Git worktree derives it from HEAD. The cache entry
# intentionally remains empty for auto-detection so a later checkout is picked
# up on the next configure instead of retaining a stale revision.
set(UASDK_SOURCE_REVISION "" CACHE STRING
        "Exact source revision to embed in installed SDK release documentation")
if (NOT UASDK_SOURCE_REVISION)
    execute_process(
            COMMAND git -C "${PROJECT_SOURCE_DIR}" rev-parse HEAD
            RESULT_VARIABLE _uasdk_git_revision_result
            OUTPUT_VARIABLE _uasdk_git_revision
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET)
    if (_uasdk_git_revision_result EQUAL 0 AND _uasdk_git_revision)
        set(UASDK_SOURCE_REVISION "${_uasdk_git_revision}")
    else ()
        set(UASDK_SOURCE_REVISION "unqualified-source-tree")
        message(WARNING
                "No UASDK_SOURCE_REVISION override or Git revision is available; "
                "installed capacity documentation will be marked unqualified")
    endif ()
endif ()

# The capacity manifest and the capability matrix are internal artefacts. The release drift tests
# parse the RENDERED manifest - tests/unit/client/standard_client_capacity_manifest_tests.cpp and its
# integration counterpart both open standard_client_2025_capacities.md by name beside the binary, and
# fail rather than skip when it is absent - and nothing installs either document. They therefore
# render with the tests that read them, and only when the documentation sources they render from are
# present. Rendering them behind their own option made it possible to build the tests against a
# manifest that was never rendered, which failed at link time on an empty copy_if_different argument.
if (UASDK_BUILD_TESTS AND EXISTS "${_uasdk_private_dir}/documentation/standard_client_2025_capacities.md")
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/tests")
    set(UASDK_RENDERED_CAPACITY_MANIFEST
            "${CMAKE_BINARY_DIR}/tests/standard_client_2025_capacities.md")
    configure_file(
            "${_uasdk_private_dir}/documentation/standard_client_2025_capacities.md"
            "${UASDK_RENDERED_CAPACITY_MANIFEST}"
            @ONLY)

    set(UASDK_RENDERED_CAPABILITY_MATRIX
            "${CMAKE_BINARY_DIR}/tests/sdk_capability_matrix.md")
    configure_file(
            "${_uasdk_private_dir}/documentation/sdk_capability_matrix.md"
            "${UASDK_RENDERED_CAPABILITY_MATRIX}"
            @ONLY)
endif ()

# The codegen matrix (tests/codegen) generates + compiles EVERY companion spec
# the UA-Nodeset checkout provides as an allow-fail coverage dashboard. It is
# heavy (~124 specs) and intended for a dedicated nightly job, so it is opt-in
# and OFF even for developer builds - enable explicitly with -DUASDK_BUILD_CODEGEN_MATRIX=ON.
option(UASDK_BUILD_CODEGEN_MATRIX "Build the companion-spec codegen matrix (heavy; nightly)" OFF)
if (UASDK_BUILD_CODEGEN_MATRIX)
    # The matrix harness lifts the real SDK compile flags from compile_commands.json,
    # so the database must be exported. (Must be set before any target is defined.)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE BOOL "" FORCE)
endif ()

# -- Build-speed tooling: ccache, mold, PCH -----------------------------------
# All three auto-enable when the tool/flag is available, and default ON for a
# developer or package/CI build of the SDK itself (PROJECT_IS_TOP_LEVEL) but OFF
# when the SDK is consumed via add_subdirectory()/FetchContent - a parent project's
# build is then never silently pushed onto ccache/mold. None hardcode a core count.
# The compiler launcher must be set before any target is created, so this block
# sits ahead of the add_subdirectory() calls.
option(UASDK_USE_CCACHE "Cache compilation with ccache when available" ${_uasdk_standalone_default})
option(UASDK_USE_MOLD   "Link with the mold linker when available"     ${_uasdk_standalone_default})
option(UASDK_USE_PCH    "Precompile stable third-party/std headers"    ${_uasdk_standalone_default})

# The codegen matrix lifts raw compiler invocations from compile_commands.json; the
# PCH's `-include <cmake_pch>` argument is emitted there and would break that harness,
# so force PCH off when the matrix is on. (The ccache launcher and mold are NOT
# emitted into compile_commands.json, so they are left alone.)
if (UASDK_BUILD_CODEGEN_MATRIX)
    set(UASDK_USE_PCH OFF)
    message(VERBOSE "Codegen matrix on: PCH disabled (its -include arg would pollute compile_commands.json)")
endif ()

# ccache: prepend it as the compiler launcher. The `cmake -E env CCACHE_SLOPPINESS=...`
# wrapper lets ccache cache PCH-using TUs - without pch_defines,time_macros ccache
# refuses to cache them, which would defeat ccache wherever PCH is enabled. MSVC uses
# /MP instead and is excluded; a launcher the parent project or CI already set is left
# untouched.
if (UASDK_USE_CCACHE AND NOT MSVC AND NOT CMAKE_CXX_COMPILER_LAUNCHER)
    find_program(CCACHE_PROGRAM ccache)
    if (CCACHE_PROGRAM)
        set(_uasdk_ccache_launcher
                "${CMAKE_COMMAND}" -E env CCACHE_SLOPPINESS=pch_defines,time_macros
                "${CCACHE_PROGRAM}")
        set(CMAKE_C_COMPILER_LAUNCHER   ${_uasdk_ccache_launcher})
        set(CMAKE_CXX_COMPILER_LAUNCHER ${_uasdk_ccache_launcher})
        message(VERBOSE "ccache enabled: ${CCACHE_PROGRAM}")
    endif ()
endif ()

# mold: a much faster linker than GNU ld. Gate on a REAL link probe rather than
# find_program - the compiler resolves -fuse-ld=mold by looking for `ld.mold`, so a
# find_program(mold) test both false-negatives (only ld.mold present) and is
# redundant: check_linker_flag actually links a test program and so also fails closed
# on a gcc<12.1 / clang<12 that cannot drive mold. Applied as a global link option so
# the role libs, the two big test binaries, the SUT and the examples all benefit.
# (mold speeds the link step only; under LTO the lto1 worker RAM stays governed by
# LTO_LINK_JOBS, orthogonally.)
if (UASDK_USE_MOLD AND NOT MSVC AND NOT WIN32)
    include(CheckLinkerFlag)
    check_linker_flag(CXX "-fuse-ld=mold" UASDK_LINKER_ACCEPTS_MOLD)
    if (UASDK_LINKER_ACCEPTS_MOLD)
        add_link_options(-fuse-ld=mold)
        message(VERBOSE "mold linker enabled (-fuse-ld=mold)")
    endif ()
endif ()

# Linux/ELF shared-library option (default OFF -> static, the initial prerelease default). When ON, the role libraries
# and the history component build as versioned shared objects. This is a CMake-only switch - no source
# annotation is needed because ELF exports default-visibility symbols. Caveats: the dependencies
# (OpenSSL/Boost/SQLite3) must be position-independent (a vcpkg *-dynamic triplet or PIC static libs);
# and the shared API is ABI-stable only for a consumer using the same toolchain. Windows DLLs (data
# symbol exports) are deliberately not covered here.
option(UASDK_BUILD_SHARED "Build the SDK as shared libraries instead of static (Linux/ELF)" OFF)
if (UASDK_BUILD_SHARED)
    set(UASDK_LIBRARY_TYPE SHARED)
else ()
    set(UASDK_LIBRARY_TYPE STATIC)
endif ()

# CTest has to be switched on for either suite, because add_test() only reaches CTestTestfile.cmake
# once enable_testing() has run. The examples' behaviour tests are gated separately from the SDK's
# own suites so that a build can take the examples without building GTest and the unit tests; that
# case calls enable_testing() alone, because it wants none of what include(CTest) brings with it
# (a BUILD_TESTING cache entry and the CDash submission targets).
if (UASDK_BUILD_TESTS)
    include(CTest)
    enable_testing()
elseif (UASDK_BUILD_EXAMPLES AND UASDK_BUILD_EXAMPLE_TESTS)
    enable_testing()
endif ()

# Default to Debug for single-config generators when no build type is given.
# Without this, an unset CMAKE_BUILD_TYPE falls through the LTO check below
# and enables LTO, which OOM-kills the linker on CI runners.
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type" FORCE)
endif ()

# Declared here rather than beside the install rules in sdk/CMakeLists.txt because the LTO
# default immediately below depends on it, and sdk/ is added at the bottom of this file.
# Default ON for a top-level build (developer or Conan/vcpkg recipe); OFF when the SDK is
# add_subdirectory()'d into a parent that manages its own install.
option(UASDK_INSTALL "Generate the SDK install/export rules" ${PROJECT_IS_TOP_LEVEL})

# Default LTO on for non-Debug builds. Forced off for sanitizer builds: LTO
# destroys UBSan's source-line attribution and aggressive inlining produces
# diagnostics that point at "<unknown>:?" - useless for triage. The non-
# sanitizer RWDI jobs cover the LTO codegen path. Can be overridden by
# explicitly passing -DENABLE_LTO=ON / OFF.
#
# Also off by default whenever this build produces an install tree. A -flto object file holds
# GCC's serialised internal representation rather than finished machine code, which makes an
# installed static library both enormous and tied to the exact compiler that produced it: the
# format is not stable across GCC major versions, and a licensee who builds the SDK with one
# compiler and their application with another gets a link failure that reads as a corrupt
# archive. An installed library is redistributed to a compiler we do not control, so it must be
# ordinary object code; a vendored or in-tree build keeps LTO, because there one compiler builds
# everything.
if (${CMAKE_BUILD_TYPE} MATCHES "Debug" OR ENABLE_ASAN OR ENABLE_TSAN OR UASDK_INSTALL)
    option(ENABLE_LTO "Enable link-time optimisation" OFF)
else ()
    option(ENABLE_LTO "Enable link-time optimisation" ON)
endif ()

# LTO_LINK_JOBS caps GCC's -flto=N at link time. Empty (the default) keeps
# -flto=auto so local builds use all cores. CI sets it explicitly to bound peak
# RAM during LTO: -flto=auto spawns up to nproc parallel lto1 workers per link,
# which OOM-kills the 24 GB runner on the largest test binary.
set(LTO_LINK_JOBS "" CACHE STRING "Cap GCC -flto=N at link time (empty = auto)")

if (ENABLE_LTO)
    if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
        add_compile_options(-flto)
        if (LTO_LINK_JOBS)
            add_link_options(-flto=${LTO_LINK_JOBS})
        else ()
            add_link_options(-flto=auto)
        endif ()
    endif ()
endif ()

# Dead-strip unreferenced functions/data from optimised builds. -ffunction-sections /
# -fdata-sections emit each function and datum in its own section; --gc-sections then lets the
# linker drop every section the final binary never references - e.g. the generated NS0 accessor
# classes for type families a given application does not use. This makes "compile out unused code"
# a pure link-time decision: every TU is still compiled (full type-check coverage, no per-feature
# build matrix), and only the unreferenced result is removed. Gated to optimised builds - in Debug
# the extra sections bloat objects and keeping all symbols aids debugging. (MSVC applies the
# equivalent /OPT:REF automatically in release, so this targets the GCC/Clang toolchains.)
if (NOT ${CMAKE_BUILD_TYPE} MATCHES "Debug")
    if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_compile_options(-ffunction-sections -fdata-sections)
        add_link_options(-Wl,--gc-sections)
    endif ()
endif ()

# Define the minimum Windows target for boost.asio and the Win32 SDK.
# Without this, boost.asio warns on every TU and falls back to Windows 7.
if (WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0A00 WINVER=0x0A00)
endif ()

if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    # Enable libstdc++ hardening assertions (bounds-checking on operator[], etc.).
    # GCC 15+ enables these by default; this ensures consistent behavior on older versions.
    #
    # Disabled under ASAN: ASAN already provides bounds checking, and the
    # combination triggers a known false positive `-Wstringop-overflow` in
    # boost::json::storage_ptr::release() under -O2 without LTO. Re-enable it
    # if/when boost.json fixes the warning, or once we drop -Werror for the
    # sanitizer build.
    if (NOT ENABLE_ASAN)
        add_compile_definitions(_GLIBCXX_ASSERTIONS)
    endif ()
endif ()

# --- Binary hardening / exploit mitigations ----------------------------------------------------------
# Make the shipped binaries' mitigations EXPLICIT instead of relying on distro/toolchain defaults, which
# differ across base images and GCC versions and can regress silently. Release verification checks these
# properties on every shipped binary; these flags make the intended build properties explicit. Default ON
# for optimised non-sanitizer builds; OFF in Debug (fortify no-ops + warns at -O0) and under sanitizers,
# which own the memory model (_FORTIFY_SOURCE fights ASan - mirrors the _GLIBCXX_ASSERTIONS exclusion).
if (${CMAKE_BUILD_TYPE} MATCHES "Debug" OR ENABLE_ASAN OR ENABLE_TSAN)
    option(UASDK_ENABLE_HARDENING "Set binary exploit-mitigation flags (RELRO/now, PIE, stack-protector, stack-clash, fortify, CET)" OFF)
else ()
    option(UASDK_ENABLE_HARDENING "Set binary exploit-mitigation flags (RELRO/now, PIE, stack-protector, stack-clash, fortify, CET)" ON)
endif ()

if (UASDK_ENABLE_HARDENING AND (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang"))
    include(CheckCXXCompilerFlag)
    include(CheckLinkerFlag)

    # PIE: let CMake emit -fPIE/-pie for executables and -fPIC for shared libs per target type (CMP0083
    # NEW, default under cmake_minimum_required 3.21). A blanket -pie would break shared-library links.
    # CMP0083 NEW only makes CMake honour POSITION_INDEPENDENT_CODE at *link* time for executables if
    # check_pie_supported() has populated CMAKE_<LANG>_LINK_PIE_SUPPORTED first; without it CMake compiles
    # objects with -fPIE but silently omits -pie at link, yielding an ET_EXEC that checksec flags "not a
    # PIE". Probe once so the -pie link flag is actually emitted for the shipped executables.
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    include(CheckPIESupported)
    check_pie_supported(OUTPUT_VARIABLE UASDK_PIE_CHECK LANGUAGES CXX)
    if (NOT CMAKE_CXX_LINK_PIE_SUPPORTED)
        message(WARNING "PIE link not supported by this toolchain; shipped executables will not be PIE. "
                        "check_pie_supported: ${UASDK_PIE_CHECK}")
    endif ()

    # _FORTIFY_SOURCE=3 (strongest; > the distro default of 2). -U first so redefining the distro's
    # predefined =2 does not trip -Werror with a "macro redefined" warning.
    add_compile_options(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
    add_compile_options(-fstack-protector-strong)

    # Non-universal flags are probed (check_*_flag links/compiles a test program) so a toolchain/arch
    # lacking one degrades gracefully rather than failing the configure.
    check_cxx_compiler_flag("-fstack-clash-protection" UASDK_CC_STACK_CLASH)  # not ELF-verifiable; flag-guaranteed
    if (UASDK_CC_STACK_CLASH)
        add_compile_options(-fstack-clash-protection)
    endif ()
    check_cxx_compiler_flag("-fcf-protection=full" UASDK_CC_CF_PROTECTION)    # Intel CET (IBT+SHSTK), x86-only
    if (UASDK_CC_CF_PROTECTION)
        add_compile_options(-fcf-protection=full)
        # Every object WE compile then carries the CET GNU-property note, but the linker sets IBT/SHSTK on
        # the OUTPUT only if EVERY input object has it -- and Debian's glibc (the official gcc:N build image,
        # glibc 2.41) ships a PIE startup stub Scrt1.o with NO CET note, which silently strips CET from every
        # PIE we link there (checksec then reports "no CET") even though all our code is instrumented. Force
        # the note back on with -z ibt / -z shstk: safe here because the only un-annotated input is _start
        # (entered directly by the kernel, never via an indirect branch, so IBT never faults on it, and it
        # never returns, so SHSTK is moot) while every reachable indirect-branch target in our code has
        # endbr64. On CET-enabled toolchains (Fedora/Ubuntu glibc) the note is already present so the force
        # is a no-op. Probed so a linker/arch without -z ibt degrades gracefully.
        check_linker_flag(CXX "-Wl,-z,ibt"   UASDK_LD_IBT)
        check_linker_flag(CXX "-Wl,-z,shstk" UASDK_LD_SHSTK)
        if (UASDK_LD_IBT)
            add_link_options(-Wl,-z,ibt)
        endif ()
        if (UASDK_LD_SHSTK)
            add_link_options(-Wl,-z,shstk)
        endif ()
    endif ()

    # Full RELRO (relro + BIND_NOW) + non-executable stack. Safe for both executables and shared objects.
    check_linker_flag(CXX "-Wl,-z,relro"       UASDK_LD_RELRO)
    check_linker_flag(CXX "-Wl,-z,now"         UASDK_LD_NOW)
    check_linker_flag(CXX "-Wl,-z,noexecstack" UASDK_LD_NOEXECSTACK)
    if (UASDK_LD_RELRO)
        add_link_options(-Wl,-z,relro)
    endif ()
    if (UASDK_LD_NOW)
        add_link_options(-Wl,-z,now)
    endif ()
    if (UASDK_LD_NOEXECSTACK)
        add_link_options(-Wl,-z,noexecstack)
    endif ()
endif ()

# The UA-Nodeset checkout feeds the type generator and the tests' NodeSet2.xml
# data files only. A consumer/package build (both options OFF) skips the git clone,
# so the SDK's own configure performs no network access.
if (UASDK_BUILD_TESTS OR UASDK_REGENERATE_TYPES)
    include(FetchContent)
    FetchContent_Declare(
            UaNodeset
            GIT_REPOSITORY https://github.com/OPCFoundation/UA-Nodeset.git
            GIT_TAG UA-1.05.06-2025-11-08
    )
    # MakeAvailable (not the deprecated single-arg FetchContent_Populate, CMP0169) -
    # UA-Nodeset is data-only (no CMakeLists.txt), so this just clones + populates it to
    # ${CMAKE_BINARY_DIR}/_deps/uanodeset-src with no add_subdirectory(). Consumers
    # reference that path directly (type generator, tests' NodeSet2.xml).
    FetchContent_MakeAvailable(UaNodeset)
endif ()

# Fuzz targets (tooling/fuzzer's opcua-fuzzer + tests/fuzz's fuzzer_tests) link the
# whole SDK and are the heaviest links in the tree. They are never run in the
# regular per-push pipeline (fuzz is excluded by default), so keep them OUT of
# normal builds - this also removes the link-time memory spike that OOM-killed the
# 32-bit build. The nightly sanitizer jobs pass -DBUILD_FUZZER=ON to build and run
# them under ASan/TSan.
option(BUILD_FUZZER "Build fuzz targets (heavy links; on for nightly sanitizer runs)" OFF)

# Coverage-guided libFuzzer decode targets (Phase 2 robustness). Clang-only
# (libFuzzer is not in GCC); pairs with ENABLE_ASAN. When ON, the SDK is built
# with -fsanitize=fuzzer-no-link (coverage feedback) and the fuzz_* executables
# under tooling/fuzzer/libfuzzer add -fsanitize=fuzzer for the driver. Requires
# BUILD_FUZZER. Off by default - it is a dedicated heavy build.
option(ENABLE_LIBFUZZER "Build coverage-guided libFuzzer decode targets (Clang only)" OFF)

add_subdirectory(tooling)
add_subdirectory(sdk)
# The optional Historical Access tier (uasdk-history[-sqlite], gated by UASDK_BUILD_HISTORY) now lives
# inside the SDK layer trees - sdk/{interface,implementation}/history - added by sdk's own aggregators.

if (UASDK_BUILD_EXAMPLES)
    # Public example programs, published to the source-available mirror.
    add_subdirectory(examples)
    # Private development applications (compliance harnesses, the history development server). These
    # are not published, so the guard is on the directory rather than on the option: the examples and
    # these are not the same audience, and a published tree must not fail for want of them.
    if (EXISTS "${_uasdk_private_dir}/projects/CMakeLists.txt")
        add_subdirectory("${_uasdk_private_dir}/projects")
    endif ()
endif ()

# Execution evidence for the requirements corpus. Included ahead of
# every tree that declares a GoogleTest suite - tests/ and the private documentation examples both
# do - so
# uasdk_add_test_report() is defined where the suites are declared. It also declares
# UASDK_TEST_REPORT_DIR, which tests/test_main.cpp bakes in as its default destination.
if (UASDK_BUILD_TESTS OR UASDK_BUILD_DOCS_EXAMPLES)
    include(UaTestReports)
endif ()

if (UASDK_BUILD_TESTS)
    add_subdirectory(tests)
endif ()

# Documentation example code. Built with the SDK so every doc snippet (pulled
# from named //! [label] regions by the docs site) is compile-checked under
# -Werror in every build, not just docs builds.
if (UASDK_BUILD_DOCS_EXAMPLES)
    add_subdirectory("${_uasdk_private_dir}/documentation/examples")
endif ()

# After running the generate_types target, re-run CMake configure so that any
# new/removed generated source files are picked up by the build system.
set(_TYPEGEN_STAMP "${CMAKE_BINARY_DIR}/generated/type_generator.stamp")
if(EXISTS "${_TYPEGEN_STAMP}")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_TYPEGEN_STAMP}")
endif()
