# SPDX-License-Identifier: 0BSD
# Copyright (c) 2026 Reduktive Limited.

"""Conan consume gate for the reduktive OPC UA SDK.

Run automatically by `conan create` after the package is built. Proves a downstream Conan consumer
can find_package(uasdk CONFIG) and link the exported uasdk:: targets - i.e. that package_info()
(cmake_find_mode="none" + the exported uasdkConfig.cmake) actually works end to end. Mirrors the raw
find_package gate (tests/packaging/find_package) and the vcpkg gate (tests/packaging/vcpkg).
"""

import os

from conan import ConanFile
from conan.tools.cmake import CMake, cmake_layout
from conan.tools.build import can_run


class UasdkTestPackageConan(ConanFile):
    settings = "os", "arch", "compiler", "build_type"
    generators = "CMakeDeps", "CMakeToolchain"
    test_type = "explicit"

    def requirements(self):
        # Consume the package under test with its default options (with_sqlite_store=True), so the
        # optional uasdk::history-sqlite component is exercised alongside the core libraries.
        self.requires(self.tested_reference_str)

    def layout(self):
        cmake_layout(self)

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def test(self):
        if can_run(self):
            self.run(os.path.join(self.cpp.build.bindir, "uasdk_test_package"), env="conanrun")
