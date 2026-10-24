# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""Conan 2.x recipe for the reduktive OPC UA SDK.

Drives the same CMake install/export foundation as the raw find_package and vcpkg channels. Conan
provides the dependencies and toolchain, the SDK's own CMake produces the relocatable install tree,
and package_info() re-exposes the exported uasdk:: targets.

Static-only for the initial prerelease. History ships as optional components gated by the
with_history / with_sqlite_store options (with_sqlite_store implies with_history and adds the sqlite3
requirement).

NOTE: verified by the CI consume gate (a downstream `conan install` + build), not in the dev tree -
Conan is not part of the local toolchain.
"""

import os

from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps, cmake_layout
from conan.tools.build import check_min_cppstd
from conan.tools.files import rmdir


class ReduktiveOpcUaSdkConan(ConanFile):
    name = "reduktive-opcua-sdk"
    version = "1.0.0-rc.2"
    license = "LicenseRef-Reduktive-Source-Available-1.0"  # see LICENSE
    description = "Modern C++ OPC UA SDK (client + server)"
    homepage = "https://github.com/reduktive/opc-ua-sdk"
    topics = ("opc-ua", "opcua", "iiot", "industrial")
    package_type = "static-library"
    settings = "os", "arch", "compiler", "build_type"

    options = {
        "with_history": [True, False],
        "with_sqlite_store": [True, False],
    }
    default_options = {
        "with_history": True,
        "with_sqlite_store": True,
    }

    # The generated NS0 type sources are committed, so no Python/network is needed to build from source.
    exports_sources = (
        "CMakeLists.txt",
        "cmake/*",
        "sdk/*",
        "history/*",
        "third_party/*",
        "tooling/type_generator/*",
        "tooling/CMakeLists.txt",
        "vcpkg.json",
        "LICENSE",
    )

    # Boost reaches Conan as ONE package that builds every compiled sublibrary by default -
    # 33 of them in 1.88. The SDK compiles against Boost headers plus exactly one built
    # library, Boost.JSON (see find_package(Boost ... COMPONENTS json) in sdk/CMakeLists.txt),
    # and Boost.JSON in turn needs Boost.Container and Boost.System. Everything else is dead
    # weight a licensee pays for on their first `conan create`, because requiring C++20 changes
    # the package id and so misses ConanCenter's prebuilt binaries. Asking for three libraries
    # instead of thirty-three is the difference between a short first build and a long one.
    # The vcpkg channel needs no equivalent: its Boost ports are per-library, and the
    # header-only ones install in under a second each.
    # Listed explicitly rather than derived from the Boost recipe's own options, which are not
    # introspectable this early. A Boost release that adds a library simply builds it until this
    # list is extended, which is the safe direction to be wrong in.
    _unused_boost_libraries = (
        "atomic", "charconv", "chrono", "cobalt", "context", "contract", "coroutine",
        "date_time", "exception", "fiber", "filesystem", "graph", "graph_parallel",
        "iostreams", "locale", "log", "math", "mpi", "nowide", "process", "program_options",
        "python", "random", "regex", "serialization", "stacktrace", "test", "thread",
        "timer", "type_erasure", "url", "wave",
    )

    def configure(self):
        # The sqlite store cannot exist without the agnostic history library.
        if self.options.with_sqlite_store:
            self.options.with_history = True

        for library in self._unused_boost_libraries:
            setattr(self.options["boost"], f"without_{library}", True)

    def validate(self):
        check_min_cppstd(self, 20)

    def requirements(self):
        # Versions are pinned to EXACTLY match the vcpkg channel (vcpkg.json overrides + builtin
        # baseline), so all three consumption channels build the SDK against an identical dependency
        # set. Open-ended ranges previously resolved to bleeding-edge (boost 1.91 / openssl 4.x /
        # fmt 12.x), an untested combination. Bump these in lockstep with vcpkg.json.
        #
        # PUBLIC (header-leaking) deps. Boost is header-only for the SDK except Boost.JSON.
        self.requires("boost/1.88.0", transitive_headers=True)
        self.requires("fmt/10.2.1", transitive_headers=True)
        # OpenSSL + Boost.JSON are PRIVATE at build time but, as static-lib link requirements, must be
        # available to the final consumer - Conan propagates them via the package_info() requires below.
        self.requires("openssl/3.5.9")
        if self.options.with_sqlite_store:
            self.requires("sqlite3/3.50.4")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        # Libraries only: no tests, examples, doc snippets, type regeneration, or UA-Nodeset clone.
        tc.cache_variables["UASDK_BUILD_TESTS"] = False
        tc.cache_variables["UASDK_BUILD_EXAMPLES"] = False
        tc.cache_variables["UASDK_BUILD_DOCS_EXAMPLES"] = False
        tc.cache_variables["UASDK_REGENERATE_TYPES"] = False
        tc.cache_variables["UASDK_BUILD_HISTORY"] = bool(self.options.with_history)
        tc.cache_variables["UASDK_INSTALL"] = True
        # Disable the precompiled header in the Conan package build. PCH defaults ON for a top-level SDK
        # build, but this channel - uniquely among the three consume gates - persists its build tree in a
        # cross-pipeline Conan cache. A cmake_pch.hxx.gch produced by one pipeline's gcc then survives into
        # the next; gcc rejects a PCH "created by a different GCC executable" (-Werror=invalid-pch) the
        # moment any single TU is a compiler (rather than ccache) miss. PCH is a build-speed optimisation
        # with no bearing on this from-source correctness gate, so we drop the fragile artifact outright
        # rather than chase ccache compiler-identity determinism across cached build trees.
        tc.cache_variables["UASDK_USE_PCH"] = False
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
        # Drop the SDK's own exported CMake package config from the Conan package. The Conan channel
        # consumes through the uasdk-config.cmake that CMakeDeps generates from package_info() below;
        # keeping the shipped lib/cmake/uasdk would let find_package(uasdk) resolve to it ambiguously.
        # (The raw find_package and vcpkg channels install the same tree and DO use the shipped config.)
        rmdir(self, os.path.join(self.package_folder, "lib", "cmake"))

    def package_info(self):
        # The Conan channel consumes via a uasdk-config.cmake that Conan's CMakeDeps GENERATES from the
        # component graph below (the raw find_package and vcpkg channels instead use the SDK's own
        # exported uasdkConfig.cmake - see package(), which removes that shipped config from the Conan
        # package so the two cannot collide). package_info() must therefore fully describe the package:
        # the flat include dir, the per-role libraries, the uasdk:: target names, and the inter-component
        # + external dependency edges (CMakeDeps emits fmt/Boost/OpenSSL/SQLite3 configs whose standard
        # upstream target names the link edges below reference).
        #
        # Public headers install flat under include/uasdk (so consumers write #include "ua_node_id.h").
        # Every component shares that one include dir; setting it on core is enough because every other
        # component requires core transitively, but it is set on each for clarity.
        self.cpp_info.set_property("cmake_file_name", "uasdk")
        self.cpp_info.set_property("cmake_target_name", "uasdk::uasdk")

        flat_include = ["include/uasdk"]

        core = self.cpp_info.components["core"]
        core.set_property("cmake_target_name", "uasdk::core")
        core.libs = ["uasdk-core"]
        core.includedirs = flat_include
        core.requires = ["boost::boost", "fmt::fmt", "openssl::openssl"]

        addr = self.cpp_info.components["address-space"]
        addr.set_property("cmake_target_name", "uasdk::address-space")
        addr.libs = ["uasdk-address-space"]
        addr.includedirs = flat_include
        addr.requires = ["core"]

        client = self.cpp_info.components["client"]
        client.set_property("cmake_target_name", "uasdk::client")
        client.libs = ["uasdk-client"]
        client.includedirs = flat_include
        client.requires = ["core"]

        server = self.cpp_info.components["server"]
        server.set_property("cmake_target_name", "uasdk::server")
        server.libs = ["uasdk-server"]
        server.includedirs = flat_include
        server.requires = ["core", "address-space"]

        app = self.cpp_info.components["app"]
        app.set_property("cmake_target_name", "uasdk::app")
        app.libs = ["uasdk-app"]
        app.includedirs = flat_include
        app.requires = ["core", "client", "server"]

        umbrella = self.cpp_info.components["uasdk"]
        umbrella.set_property("cmake_target_name", "uasdk::uasdk")
        umbrella.requires = ["core", "address-space", "client", "server", "app"]

        if self.options.with_history:
            history = self.cpp_info.components["history"]
            history.set_property("cmake_target_name", "uasdk::history")
            history.libs = ["uasdk-history"]
            history.includedirs = flat_include
            history.requires = ["server"]
            if self.options.with_sqlite_store:
                sqlite_store = self.cpp_info.components["history-sqlite"]
                sqlite_store.set_property("cmake_target_name", "uasdk::history-sqlite")
                sqlite_store.libs = ["uasdk-history-sqlite"]
                sqlite_store.includedirs = flat_include
                sqlite_store.requires = ["history", "sqlite3::sqlite3"]
