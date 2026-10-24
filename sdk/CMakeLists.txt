# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# -----------------------------------------------------------------------------
# Library layering
#
# The SDK is split into role-separated link units instead of one monolithic
# library, so size-sensitive / embedded builds can link only what they need:
#
#   uasdk-core           role-agnostic kernel (types, codecs, async, security,
#                        transport, dynamic-type core + interfaces, generated
#                        data_types/status/id-enums). Depends on nothing.
#   uasdk-address-space  the server information model (Node graph, instantiation,
#                        NodeSet import, conditions, instance-handle generated
#                        categories + ns0). Depends on core.
#   uasdk-client         tier-0/1/2 client. Depends on core only.
#   uasdk-server         secure-channel/session/services/subscriptions. Depends
#                        on core + address-space.
#
# `uasdk` is the INTERFACE umbrella linking all four - the "just give me the
# whole SDK" entry point that the private development applications, tests/, and external
# consumers link.
# In-tree consumers link `uasdk::uasdk`, the same name an installed package
# exports, so a call site reads identically however the SDK was obtained.
#
# The enforced layering is the LINK GRAPH below: uasdk-core links nothing, so a
# core TU that includes an address-space/server/client header fails to compile;
# uasdk-client links only uasdk-core, so it cannot see server/address-space.
#
# All common compiler/linker options live on two shared INTERFACE config targets
# (uasdk-build-private / uasdk-build-public) defined ONCE below and linked by
# every layer lib, so the options are applied to all four libraries without
# duplication and can never drift between them.
# -----------------------------------------------------------------------------

add_library(uasdk-core ${UASDK_LIBRARY_TYPE})
add_library(uasdk-address-space ${UASDK_LIBRARY_TYPE})
add_library(uasdk-client ${UASDK_LIBRARY_TYPE})
add_library(uasdk-server ${UASDK_LIBRARY_TYPE})
# Application-composition tier: hosts helpers that legitimately need MORE than one role
# (e.g. ProcessConfigurationFile, which bridges client + server config; and, later,
# LDS DiscoveryRegistration, which drives a client to RegisterServer2 a server with an LDS).
# It sits ABOVE the role libs (depends on core + client + server) so the roles stay peers -
# a server never gains a client dependency. Size-sensitive builds link only the layers they
# need and never pull this tier.
add_library(uasdk-app ${UASDK_LIBRARY_TYPE})

set(UASDK_LAYER_LIBS uasdk-core uasdk-address-space uasdk-client uasdk-server uasdk-app)

add_library(uasdk INTERFACE)

# In-tree uasdk:: aliases so add_subdirectory()/FetchContent consumers link the SAME target names
# as installed find_package() consumers (link uasdk::uasdk however you consumed the SDK). Without
# these the uasdk:: names would exist only in the installed export (install(EXPORT ... NAMESPACE
# uasdk::) below), forcing source consumers onto the bare target names.
add_library(uasdk::core ALIAS uasdk-core)
add_library(uasdk::address-space ALIAS uasdk-address-space)
add_library(uasdk::client ALIAS uasdk-client)
add_library(uasdk::server ALIAS uasdk-server)
add_library(uasdk::app ALIAS uasdk-app)
add_library(uasdk::uasdk ALIAS uasdk)

option(ENABLE_CODE_COVERAGE "Build SDK with code coverage" OFF)
option(ENABLE_ASAN "Build SDK with ASan + UBSan" OFF)
option(ENABLE_TSAN "Build SDK with ThreadSanitizer (mutually exclusive with ENABLE_ASAN)" OFF)
option(ENABLE_BUILD_SPEED_ANALYSIS_FOR_CLANG "Build SDK with build speed analysis (clang only)" OFF)
option(ENABLE_ASIO_HANDLER_TRACKING "Compile the SDK with BOOST_ASIO_ENABLE_HANDLER_TRACKING for asio handler tracing" OFF)

if (ENABLE_ASAN AND ENABLE_TSAN)
    message(FATAL_ERROR "ENABLE_ASAN (ASan) and ENABLE_TSAN cannot be used together")
endif ()

# -- Optional Historical Access tier (uasdk-history[-sqlite]) ------------------
# A first-class-but-optional tier ABOVE the role libs (depends on core + address-space + server),
# folded into the SDK trees like uasdk-app but kept independently selectable: it carries the only
# SQLite dependency in the SDK and ships as a SEPARATE export set (uasdkHistoryTargets) so consumers
# opt in via find_package(uasdk COMPONENTS history sqlite-store). Declared here, before the
# add_subdirectory() calls below, so sdk/{interface,implementation}/history can target_sources onto
# it exactly as the role folders do for the role libs. UASDK_BUILD_HISTORY is defined at the repo root.
if (UASDK_BUILD_HISTORY)
    add_library(uasdk-history ${UASDK_LIBRARY_TYPE})
    add_library(uasdk::history ALIAS uasdk-history)

    # The bundled SQLite-backed HistoryStore is independently optional so a consumer plugging their
    # own backend builds uasdk-history alone and never needs SQLite3.
    option(UASDK_BUILD_HISTORY_SQLITE "Build the bundled SQLite-backed history store (uasdk-history-sqlite)" ON)
    if (UASDK_BUILD_HISTORY_SQLITE)
        # Canonical SQLite target from CMake's built-in FindSQLite3 (system / Conan / vcpkg) - no
        # vendor-specific target name leaks into the tree.
        find_package(SQLite3 REQUIRED)

        # CMake 4.3 made SQLite3::SQLite3 canonical and marked SQLite::SQLite3 deprecated, so linking
        # the old name prints a configure-time warning in every consumer's build. Link the new name and
        # alias it in on older CMake - this project supports 3.21+, and the shim is the one FindSQLite3's
        # own documentation prescribes. ALIAS of a non-GLOBAL imported target needs CMake >= 3.18, which
        # the 3.21 floor guarantees. The alias must be recreated consumer-side too: the exported target
        # carries $<LINK_ONLY:SQLite3::SQLite3> into the install tree, so see cmake/uasdkConfig.cmake.in.
        if (NOT TARGET SQLite3::SQLite3)  # CMake < 4.3
            add_library(SQLite3::SQLite3 ALIAS SQLite::SQLite3)
        endif ()
        add_library(uasdk-history-sqlite ${UASDK_LIBRARY_TYPE})
        add_library(uasdk::history-sqlite ALIAS uasdk-history-sqlite)
    endif ()
endif ()

# uasdk-internal - the SDK's private include directories, collected from every sdk/implementation folder by
# uasdk_private_include_directory(). The SDK's libraries, tests and fuzzers and the book's sample programs
# link it PRIVATE; examples never do, so an example or a public header that includes a private header does
# not compile (public API review 2026-10, item 1, API-1.1). Build tree only: an installed SDK has no private
# headers.
add_library(uasdk-internal INTERFACE)
add_library(uasdk::internal ALIAS uasdk-internal)

# Makes the calling folder a private include directory of <lib>, shared with the other SDK libraries,
# the tests and the fuzzers through uasdk-internal.
function(uasdk_private_include_directory lib)
    target_include_directories(${lib} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_include_directories(uasdk-internal INTERFACE "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>")
endfunction()

# Folder CMakeLists call target_sources(<layer-lib> ...); the layer libs must
# already exist above before these add_subdirectory() calls.
add_subdirectory(interface)
add_subdirectory(implementation)

# Generated types are committed to the repo. Developers can manually run the
# `generate_types` target to regenerate them when the generator or spec inputs
# change.  CI verifies that committed files are up-to-date.

find_package(fmt REQUIRED)
# Minimum supported Boost. Pinned at 1.88 for vcpkg consumers via the
# builtin-baseline; 1.83 is the floor for Conan / system Boost / plain-CMake
# consumers. 1.83 is the oldest Boost the SDK is verified against
# (weekly-system-deps-boost, ubuntu:24.04) and the Boost of every distribution
# whose stock GCC meets the SDK's GCC 13 floor: Ubuntu 24.04, Debian 13 and
# RHEL 10 ship 1.83. Boost 1.75 (RHEL 9) does not compile the SDK: ClientId's
# std::hash needs asio::ip::address hashing, and Boost.JSON 1.75 takes no
# std::string_view. RHEL 9 consumers use vcpkg/Conan for a newer Boost.
#
# `url` is deliberately NOT requested. Nothing in the SDK, the tests, or the
# examples includes `boost/url` or names `boost::urls`; the component was once
# requested and linked without ever being used. Do not re-add it without a
# source file that needs it.
find_package(Boost 1.83 CONFIG REQUIRED COMPONENTS json)
# 1.1.1 is supported for embedded and industrial targets that must build against their platform's
# vendor-maintained OpenSSL (RHEL 8, older Yocto BSPs); the weekly-openssl-1.1.1 CI lane gates it
# (owner decision 12). Upstream 1.1.1 has been out of support since September 2023, so it is
# supported only where the platform vendor still patches it.
find_package(OpenSSL 1.1.1 REQUIRED)
# PKCS#1 v1.5 decryption (the deprecated RSA policies, RSA user-token secrets) relies on OpenSSL's
# implicit rejection, which arrived in 3.2 (B2-4). The documented system-dependency path still
# builds against a distribution 3.0 (and the supported floor is 1.1.1), so this is a warning rather
# than a floor (owner decision 6).
if (OPENSSL_VERSION VERSION_LESS 3.2)
  message(WARNING "OpenSSL ${OPENSSL_VERSION}: PKCS#1 v1.5 decryption has no implicit rejection before 3.2; "
                  "keep the deprecated RSA security policies and RSA-1.5 user-token policies disabled, or build against 3.2+")
endif()

# Release metadata records the packages this configuration actually selected. Distribution-package
# consumers have no vcpkg inventory, so the SBOM generator needs these found versions too.
include(UaDependencyVersions)
set(_uasdk_dependency_sqlite FALSE)
if (TARGET uasdk-history-sqlite)
    set(_uasdk_dependency_sqlite TRUE)
endif ()
ua_write_dependency_versions("${PROJECT_BINARY_DIR}/uasdk-dependency-versions.json"
        "${Boost_VERSION}" "${OPENSSL_VERSION}" "${fmt_VERSION}"
        "${_uasdk_dependency_sqlite}" "${SQLite3_VERSION}")

# rapidxml is vendored under third_party/rapidxml (Boost/MIT, redistribution OK).
# It is a PRIVATE, build-only dependency - only the SDK's own XML codec compiles
# against it, so consumers never include it and it is NOT a find_dependency in the
# installed package config. The include dir is build-tree-only (see below).

# -- Shared build configuration (defined once, linked by every layer lib) ------
#
#  uasdk-build-public  - usage requirements that MUST also reach SDK consumers
#                        (propagated through the umbrella): public link deps,
#                        sanitizer instrumentation, optional asio tracing,
#                        coverage link flags, the C++20 requirement.
#  uasdk-build-private - SDK-internal-only options that must NOT be forced on
#                        consumers: warnings-as-errors, private link deps, the
#                        rapidxml include dir, coverage compile flags.
add_library(uasdk-build-public INTERFACE)
add_library(uasdk-build-private INTERFACE)

target_compile_features(uasdk-build-public INTERFACE cxx_std_20)
target_link_libraries(uasdk-build-public INTERFACE Boost::boost fmt::fmt)
target_link_libraries(uasdk-build-private INTERFACE OpenSSL::Crypto OpenSSL::SSL Boost::json)
# PROJECT_SOURCE_DIR (the SDK's own project(SDK) root), NOT CMAKE_SOURCE_DIR - the latter is
# the top-level project, which for an add_subdirectory()/FetchContent consumer is the CONSUMER,
# so CMAKE_SOURCE_DIR/third_party would not exist and the SDK's XML codec would fail to compile.
target_include_directories(uasdk-build-private SYSTEM INTERFACE
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/third_party>")

if (ENABLE_ASIO_HANDLER_TRACKING)
    target_compile_definitions(uasdk-build-public INTERFACE BOOST_ASIO_ENABLE_HANDLER_TRACKING)
endif ()

if (MSVC)
    target_compile_options(uasdk-build-private INTERFACE /W4 /WX /MP /bigobj)
    target_compile_definitions(uasdk-build-private INTERFACE
            _SILENCE_CXX20_OLD_SHARED_PTR_ATOMIC_SUPPORT_DEPRECATION_WARNING
            BOOST_UUID_FORCE_AUTO_LINK)
elseif (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
    target_compile_options(uasdk-build-private INTERFACE -Wall -Wextra -Wpedantic -Werror -Wnull-dereference)
    #Avoid false positives in Guid conversion
    target_compile_options(uasdk-build-private INTERFACE -Wno-stringop-overread)
    # These extra-warning classes have all been driven to ZERO across
    # the hand-written SDK tree, so they are promoted to HARD GATES - a new C-style cast, cast-away-const,
    # variable/parameter shadow, or value/sign-changing implicit conversion now fails the build.
    #  - -Wold-style-cast / -Wcast-qual: censused at zero (cpp_style "no C-style casts").
    #  - -Wshadow: 2026-07 shadow campaign (295 hand-written sites -> 0 via idiom-preserving renames); the
    #    sole residual was a GCC scoped-enum false positive in generated id headers, suppressed narrowly at
    #    the generator (emit_identifiers.py).
    #  - -Wconversion / -Wsign-conversion: 2026-07 campaign (29 sites in 9 crypto/codec/config TUs -> 0 via
    #    documented static_cast under a proven guard / numeric_cast / added bound checks). Each fix was
    #    security-reviewed (these sit on the pre-auth attack surface).
    target_compile_options(uasdk-build-private INTERFACE
            -Wshadow -Wold-style-cast -Wcast-qual -Wconversion -Wsign-conversion)

    if (ENABLE_CODE_COVERAGE)
        target_compile_options(uasdk-build-private INTERFACE --coverage -O0)
        target_link_options(uasdk-build-public INTERFACE --coverage -lgcov)
    endif ()

elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if (ENABLE_BUILD_SPEED_ANALYSIS_FOR_CLANG)
        target_compile_options(uasdk-build-private INTERFACE -ftime-trace)
    endif ()
endif ()

# The UASDK_EXTRA_WARNINGS census staging mechanism. All of the classes
# it staged (-Wshadow / -Wold-style-cast / -Wcast-qual / -Wconversion / -Wsign-conversion) have now been
# driven to zero and PROMOTED to always-on hard gates above, so the advisory body is empty. The option and
# the -Wno-error explicit override are retained for the NEXT warning class to be censused: add it here as an
# advisory (`-Wfoo -Wno-error=foo`), drive it to zero, then promote it to the always-on gate line above.
option(UASDK_EXTRA_WARNINGS "Enable a staged extra warning class for a P7 census + drive-to-zero (advisory)" OFF)
if (UASDK_EXTRA_WARNINGS AND (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang"))
    # (no class currently staged - all promoted to the always-on gates above)
endif ()

# Sanitizer flags - applied for any build type (Debug or RelWithDebInfo) so CI
# can run sanitizers against the optimised build for speed. Both compile and
# link must carry the flag for the SDK code to be instrumented; on the PUBLIC
# config so the flags propagate to consumers (tests, sample apps) via the
# umbrella.
if (NOT MSVC AND (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang"))
    if (ENABLE_ASAN)
        if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
            set(_ua_bounds_flag -fsanitize=bounds)
        else ()
            set(_ua_bounds_flag -fsanitize=bounds-strict)
        endif ()
        target_compile_options(uasdk-build-public INTERFACE
                -fsanitize=address -fsanitize=undefined ${_ua_bounds_flag}
                -fno-omit-frame-pointer)
        target_link_options(uasdk-build-public INTERFACE
                -fsanitize=address -fsanitize=undefined ${_ua_bounds_flag})
        # GCC at -O2 without LTO produces false-positive warnings inside
        # inlined libstdc++ / boost templates that we cannot fix at our
        # source. Demote only the specific flags that have actually fired:
        #   -Wstringop-overflow:  std::atomic::fetch_sub inlined through
        #                         boost::json::storage_ptr::release()
        #                         (libstdc++ atomic_base.h:641, "destination
        #                         object is likely at address zero")
        #   -Wmaybe-uninitialized: libstdc++ template instantiations seen
        #                          in earlier sanitizer runs
        #   -Wnull-dereference:   boost::asio::any_executor::equal_ex
        #                         target_ comparison (per-TU IPA cannot
        #                         prove non-null without whole-program info)
        # Other -Werror gates remain in effect, so a *new* warning class
        # will still break the sanitizer build.
        if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
            target_compile_options(uasdk-build-public INTERFACE
                    -Wno-error=stringop-overflow
                    -Wno-error=maybe-uninitialized
                    -Wno-error=null-dereference)
        endif ()
    elseif (ENABLE_TSAN)
        target_compile_options(uasdk-build-public INTERFACE -fsanitize=thread -fno-omit-frame-pointer)
        target_link_options(uasdk-build-public INTERFACE -fsanitize=thread)
        # See the ASAN block above for rationale. Under TSan we additionally
        # suppress -Wtsan entirely: boost::asio's std_fenced_block uses
        # std::atomic_thread_fence which GCC TSan can't model, producing one
        # warning per inlined fence. The warnings have huge inlining stacks
        # and overflow GitLab's 4 MB job log limit, hiding the actual test
        # output. The fence is a documented false positive.
        if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
            target_compile_options(uasdk-build-public INTERFACE
                    -Wno-error=stringop-overflow
                    -Wno-error=maybe-uninitialized
                    -Wno-error=null-dereference
                    -Wno-tsan)
        endif ()
    endif ()
endif ()

# Coverage-guided libFuzzer (Phase 2 robustness): instrument the SDK with
# -fsanitize=fuzzer-no-link so the decode fuzz targets get coverage feedback.
# Clang-only; the fuzz_* executables (tooling/fuzzer/libfuzzer) add
# -fsanitize=fuzzer for the driver. Pair with ENABLE_ASAN for per-input memory
# error detection. On the PUBLIC umbrella so the flag reaches every SDK TU.
if (ENABLE_LIBFUZZER)
    if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "ENABLE_LIBFUZZER requires Clang (libFuzzer is clang-only)")
    endif ()
    target_compile_options(uasdk-build-public INTERFACE -fsanitize=fuzzer-no-link)
    target_link_options(uasdk-build-public INTERFACE -fsanitize=fuzzer-no-link)
endif ()

# Non-sanitizer optimised GCC builds with LTO disabled hit the SAME inlined
# boost.asio / libstdc++ false positives the sanitizer blocks above demote
# (-Wnull-dereference in boost::asio scheduler / shared_ptr internals,
# -Wstringop-overflow, -Wmaybe-uninitialized). These only surface at -O2
# without LTO: per-TU IPA cannot prove non-null, whereas an LTO build's WPA
# can - which is why the LTO-on RelWithDebInfo builds stay clean and only the
# LTO-off integration-test builds (ENABLE_LTO=OFF, kept off to bound the test
# binary's link-time RAM) trip them. Demote the same three flags here so a
# *real* new warning class still breaks the build.
if ((CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
        AND NOT ENABLE_LTO AND NOT ENABLE_ASAN AND NOT ENABLE_TSAN
        AND NOT CMAKE_BUILD_TYPE MATCHES "Debug")
    target_compile_options(uasdk-build-public INTERFACE
            -Wno-error=stringop-overflow
            -Wno-error=maybe-uninitialized
            -Wno-error=null-dereference)
    # GCC 15 adds -Wfree-nonheap-object on the temporary std::variant that NodeId's copy assignment inlines
    # (libstdc++ new_allocator.h, "called on unallocated object '<anonymous>'"): the variant's ByteString
    # alternative owns heap storage, so the warning is false.
    if (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 15)
        target_compile_options(uasdk-build-public INTERFACE -Wno-error=free-nonheap-object)
    endif ()
endif ()

# -- Apply shared config + layer dependency edges to each real layer lib -------
foreach (lib IN LISTS UASDK_LAYER_LIBS)
    target_link_libraries(${lib} PUBLIC uasdk-build-public)
    target_link_libraries(${lib} PRIVATE uasdk-build-private uasdk-internal)
endforeach ()

target_link_libraries(uasdk-address-space PUBLIC uasdk-core)
target_link_libraries(uasdk-client PUBLIC uasdk-core)
target_link_libraries(uasdk-server PUBLIC uasdk-core uasdk-address-space)
target_link_libraries(uasdk-app PUBLIC uasdk-core uasdk-client uasdk-server)

# History tier: depends on server (which brings core + address-space + the public build config
# transitively). The SQLite store links the engine plus SQLite3 (PRIVATE -> a static-link requirement).
if (UASDK_BUILD_HISTORY)
    target_link_libraries(uasdk-history PUBLIC uasdk-server PRIVATE uasdk-build-private uasdk-internal)
    if (UASDK_BUILD_HISTORY_SQLITE)
        # SQLite3::SQLite3 - canonical from CMake 4.3, aliased in beside find_package(SQLite3) above for
        # older CMake. Getting this name wrong is a trap: an unknown Foo::Bar is assumed to be an imported
        # target and configures without complaint, failing only at the generate step, so a build tree
        # configured before the name changed keeps working and only a fresh configure reports it.
        target_link_libraries(uasdk-history-sqlite PUBLIC uasdk-history PRIVATE SQLite3::SQLite3 uasdk-build-private uasdk-internal)
    endif ()
endif ()

# -- Umbrella: link every layer ------------------------------------------------
target_link_libraries(uasdk INTERFACE
        uasdk-core uasdk-address-space uasdk-client uasdk-server uasdk-app)

# -- Precompiled headers (opt-in; PRIVATE so never propagated nor exported) ----
# In the static build, uasdk-core compiles the PCH and the other four role libs
# REUSE_FROM it. In a shared build, each target receives a distinct
# `<target>_EXPORTS` definition, so GCC correctly rejects a PCH compiled for a
# sibling target; give every role library its own private PCH in that mode.
# PRIVATE keeps PCHs out of the install/export set and away from consumers.
if (UASDK_USE_PCH)
    if (UASDK_BUILD_SHARED)
        foreach (lib ${UASDK_LAYER_LIBS})
            target_precompile_headers(${lib} PRIVATE "${PROJECT_SOURCE_DIR}/cmake/uasdk_pch.h")
        endforeach ()
    else ()
        target_precompile_headers(uasdk-core PRIVATE "${PROJECT_SOURCE_DIR}/cmake/uasdk_pch.h")
        foreach (lib uasdk-address-space uasdk-client uasdk-server uasdk-app)
            target_precompile_headers(${lib} REUSE_FROM uasdk-core)
        endforeach ()
    endif ()
endif ()

# Shared-library versioning (ELF SONAME -> libuasdk-core.so.1, etc.). No-op for the static default.
if (UASDK_BUILD_SHARED)
    set_target_properties(${UASDK_LAYER_LIBS} PROPERTIES
            VERSION "${PROJECT_VERSION}"
            SOVERSION "${PROJECT_VERSION_MAJOR}"
            POSITION_INDEPENDENT_CODE ON)
    if (UASDK_BUILD_HISTORY)
        set_target_properties(uasdk-history PROPERTIES
                VERSION "${PROJECT_VERSION}" SOVERSION "${PROJECT_VERSION_MAJOR}" POSITION_INDEPENDENT_CODE ON)
        if (UASDK_BUILD_HISTORY_SQLITE)
            set_target_properties(uasdk-history-sqlite PROPERTIES
                    VERSION "${PROJECT_VERSION}" SOVERSION "${PROJECT_VERSION_MAJOR}" POSITION_INDEPENDENT_CODE ON)
        endif ()
    endif ()
endif ()

# -----------------------------------------------------------------------------
# Install / export / package-config  ->  find_package(uasdk CONFIG)
#
# Produces a relocatable install tree:
#   <prefix>/lib/                the five static archives
#   <prefix>/include/uasdk/      all public headers, flat (the include
#                                convention; header names are globally unique)
#   <prefix>/lib/cmake/uasdk/    uasdkTargets + uasdkConfig + version file
#
# Targets export under the uasdk:: namespace with friendly EXPORT_NAMEs
# (uasdk::core, uasdk::address-space, uasdk::client, uasdk::server, uasdk::app;
# uasdk::uasdk is the umbrella). The two uasdk-build-{public,private} INTERFACE
# config carriers are exported too: a STATIC lib's PRIVATE deps still propagate as
# link requirements, so CMake requires them in the export set.
#
# UASDK_INSTALL is declared in the top-level CMakeLists.txt, not here: it decides the
# default for ENABLE_LTO, which is settled before this directory is added.
# -----------------------------------------------------------------------------

if (UASDK_INSTALL)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    # Friendly exported names: uasdk::core instead of uasdk::uasdk-core.
    set_target_properties(uasdk-core PROPERTIES EXPORT_NAME core)
    set_target_properties(uasdk-address-space PROPERTIES EXPORT_NAME address-space)
    set_target_properties(uasdk-client PROPERTIES EXPORT_NAME client)
    set_target_properties(uasdk-server PROPERTIES EXPORT_NAME server)
    set_target_properties(uasdk-app PROPERTIES EXPORT_NAME app)
    set_target_properties(uasdk PROPERTIES EXPORT_NAME uasdk)
    set_target_properties(uasdk-build-public PROPERTIES EXPORT_NAME build-public)
    set_target_properties(uasdk-build-private PROPERTIES EXPORT_NAME build-private)
    set_target_properties(uasdk-internal PROPERTIES EXPORT_NAME internal)

    # The interface folders add their source dirs as `target_include_directories(
    # <lib> PUBLIC .)` and their headers as `target_sources(<lib> PUBLIC <h>)` for
    # the flat-include convention. Both are correct for the build tree, but
    # install(EXPORT) rejects raw source paths in INTERFACE_INCLUDE_DIRECTORIES and
    # INTERFACE_SOURCES - so wrap each entry in $<BUILD_INTERFACE:> here, CENTRALLY,
    # so the leaf folders need no install knowledge and keep using `PUBLIC .` /
    # `PUBLIC <header>`. The headers are delivered to consumers as installed files
    # (install(FILES) below), not as interface sources. Installed consumers are
    # routed at the single flat include/uasdk dir via $<INSTALL_INTERFACE:> on the
    # public config target, so `#include "ua_foo.h"` stays prefix-free post-install.
    # The role libs plus the optional history libs (which also use `PUBLIC .` + PUBLIC headers).
    set(_uasdk_export_wrap_libs ${UASDK_LAYER_LIBS})
    if (UASDK_BUILD_HISTORY)
        list(APPEND _uasdk_export_wrap_libs uasdk-history)
        if (UASDK_BUILD_HISTORY_SQLITE)
            list(APPEND _uasdk_export_wrap_libs uasdk-history-sqlite)
        endif ()
    endif ()
    foreach (lib IN LISTS _uasdk_export_wrap_libs)
        foreach (prop IN ITEMS INTERFACE_INCLUDE_DIRECTORIES INTERFACE_SOURCES)
            get_target_property(_vals ${lib} ${prop})
            if (_vals)
                list(TRANSFORM _vals REPLACE "(.+)" "$<BUILD_INTERFACE:\\1>")
                set_target_properties(${lib} PROPERTIES ${prop} "${_vals}")
            endif ()
        endforeach ()
    endforeach ()
    target_include_directories(uasdk-build-public INTERFACE
            "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/uasdk>")

    # Archives + the INTERFACE umbrella/config carriers, recorded in one export set.
    install(TARGETS
            uasdk-core uasdk-address-space uasdk-client uasdk-server uasdk-app
            uasdk uasdk-build-public uasdk-build-private uasdk-internal
            EXPORT uasdkTargets
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT uasdk_runtime
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT uasdk_runtime
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT uasdk_runtime
            INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/uasdk")

    # All public headers, installed flat (verified: 0 name collisions across the
    # interface tree, so a single directory faithfully represents the convention).
    # interface/history is EXCLUDED here (this glob is filesystem-based, so it would otherwise ship
    # history headers even when UASDK_BUILD_HISTORY is OFF); they install via the guarded history
    # export block below under their own component gating.
    file(GLOB_RECURSE _uasdk_public_headers CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/interface/*.h")
    list(FILTER _uasdk_public_headers EXCLUDE REGEX "/interface/history/")
    install(FILES ${_uasdk_public_headers}
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/uasdk"
            COMPONENT uasdk_development)

    install(EXPORT uasdkTargets
            NAMESPACE uasdk::
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/uasdk"
            FILE uasdkTargets.cmake
            COMPONENT uasdk_development)

    # -- Optional Historical Access component - its OWN export set -------------
    # A separate uasdkHistoryTargets.cmake (loaded by uasdkConfig only when a history component is
    # requested) is the correct shape for an optional component: uasdkTargets above is already
    # finalized, and the history export references uasdk::server / uasdk::build-private from it (which
    # uasdkConfig loads first). Target names, component selection, and flat headers are unchanged from
    # when this lived in the top-level history/ directory.
    if (UASDK_BUILD_HISTORY)
        set(_uasdk_history_targets uasdk-history)
        set_target_properties(uasdk-history PROPERTIES EXPORT_NAME history)

        set(_uasdk_history_headers
                "${CMAKE_CURRENT_SOURCE_DIR}/interface/history/ua_history_store.h"
                "${CMAKE_CURRENT_SOURCE_DIR}/interface/history/ua_history_engine.h"
                "${CMAKE_CURRENT_SOURCE_DIR}/interface/history/ua_history_engine_delegate.h"
                "${CMAKE_CURRENT_SOURCE_DIR}/interface/history/ua_history_namespace.h"
                "${CMAKE_CURRENT_SOURCE_DIR}/interface/history/ua_history_annotations_property.h")

        if (UASDK_BUILD_HISTORY_SQLITE)
            set_target_properties(uasdk-history-sqlite PROPERTIES EXPORT_NAME history-sqlite)
            list(APPEND _uasdk_history_targets uasdk-history-sqlite)
            # The bundled store's public headers ship only when that library does.
            list(APPEND _uasdk_history_headers
                    "${CMAKE_CURRENT_SOURCE_DIR}/interface/history/ua_history_sqlite_store.h"
                    "${CMAKE_CURRENT_SOURCE_DIR}/interface/history/ua_history_sqlite_connection.h"
                    "${CMAKE_CURRENT_SOURCE_DIR}/interface/history/ua_history_sqlite_statement.h")
        endif ()

        install(TARGETS ${_uasdk_history_targets}
                EXPORT uasdkHistoryTargets
                ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT uasdk_runtime
                LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT uasdk_runtime
                RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT uasdk_runtime
                INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/uasdk")

        # Public headers, installed flat into the same include/uasdk dir (ua_history_*.h - globally
        # unique, no collision with the core ua_*.h set).
        install(FILES ${_uasdk_history_headers}
                DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/uasdk"
                COMPONENT uasdk_development)

        install(EXPORT uasdkHistoryTargets
                NAMESPACE uasdk::
                DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/uasdk"
                FILE uasdkHistoryTargets.cmake
                COMPONENT uasdk_development)
    endif ()

    configure_package_config_file(
            # PROJECT_SOURCE_DIR, not CMAKE_SOURCE_DIR: correct even if a consumer installs the
            # SDK from an add_subdirectory()/FetchContent subtree (where the top level differs).
            "${PROJECT_SOURCE_DIR}/cmake/uasdkConfig.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/uasdkConfig.cmake"
            INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/uasdk")

    write_basic_package_version_file(
            "${CMAKE_CURRENT_BINARY_DIR}/uasdkConfigVersion.cmake"
            VERSION "${PROJECT_VERSION}"
            COMPATIBILITY SameMajorVersion)

    install(FILES
            "${CMAKE_CURRENT_BINARY_DIR}/uasdkConfig.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/uasdkConfigVersion.cmake"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/uasdk"
            COMPONENT uasdk_development)

    # The capacity manifest and capability matrix are NOT installed. They are internal artefacts:
    # the release drift tests parse them, and they render from documentation sources that the
    # published tree does not carry, so a consumer could never obtain the documents this rule used
    # to install. Publishing them, and installing them again, is a decision to take deliberately
    # rather than a side effect of a build option being on.
endif ()
