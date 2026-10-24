# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# vcpkg overlay port for the reduktive OPC UA SDK. Drives the same CMake install/export foundation as
# the raw find_package and Conan channels: vcpkg supplies the dependencies + toolchain, the SDK's own
# CMake produces the relocatable install tree, and vcpkg_cmake_config_fixup relocates the package config.
#
# Static-only for the initial prerelease (the port is a static library). History ships as optional
# features; sqlite-store pulls in sqlite3 and the agnostic history feature.
#
# Use as an overlay port (`--overlay-ports=ports`) or via a future Reduktive vcpkg registry.

# Source acquisition, in the order a consumer is most likely to want it.
#
# 1. UASDK_SOURCE_DIR names a checkout explicitly, for a tree that is not the one this port
#    was loaded from - e.g.
#      UASDK_SOURCE_DIR=/path/to/sdk vcpkg install uasdk[sqlite-store] --overlay-ports=/path/to/sdk/ports
# 2. This port file ships INSIDE the SDK source tree, at <sdk>/ports/uasdk. When it is used as an
#    overlay port from there, the tree two directories up is the SDK the consumer means, so build
#    that and touch the network for nothing. Detected by a file only the SDK root carries, not by
#    the directory name.
# 3. Otherwise the port came from a registry with no source beside it, so fetch the release tag.
if(DEFINED ENV{UASDK_SOURCE_DIR})
    set(SOURCE_PATH "$ENV{UASDK_SOURCE_DIR}")
    message(STATUS "uasdk: building the source tree named by UASDK_SOURCE_DIR (${SOURCE_PATH})")
else()
    get_filename_component(_uasdk_in_tree_root "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
    if(EXISTS "${_uasdk_in_tree_root}/sdk/CMakeLists.txt" AND EXISTS "${_uasdk_in_tree_root}/vcpkg.json")
        set(SOURCE_PATH "${_uasdk_in_tree_root}")
        message(STATUS "uasdk: building the source tree this overlay port ships in (${SOURCE_PATH})")
    else()
        # The public source is published on GitHub, which carries each release's tag.
        vcpkg_from_git(
            OUT_SOURCE_PATH SOURCE_PATH
            URL "https://github.com/reduktive/opc-ua-sdk.git"
            # Registry entries pin a full commit SHA here for reproducibility; "v${VERSION}" is the release tag.
            REF "v${VERSION}"
        )
    endif()
    unset(_uasdk_in_tree_root)
endif()

# Map port features to the SDK's CMake options. The agnostic history library is independent of the
# SQLite store (UASDK_BUILD_HISTORY_SQLITE), so a "history"-only install never needs SQLite3.
vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
    FEATURES
        history       UASDK_BUILD_HISTORY
        sqlite-store  UASDK_BUILD_HISTORY_SQLITE
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        # Libraries only - no tests, examples, doc snippets, type regeneration, or UA-Nodeset clone.
        -DUASDK_BUILD_TESTS=OFF
        -DUASDK_BUILD_EXAMPLES=OFF
        -DUASDK_BUILD_DOCS_EXAMPLES=OFF
        -DUASDK_REGENERATE_TYPES=OFF
        -DUASDK_INSTALL=ON
        # Explicit OFF defaults: the SDK builds as the top-level project here, where history would
        # otherwise default ON. ${FEATURE_OPTIONS} (appended last) re-enables what the consumer selected.
        -DUASDK_BUILD_HISTORY=OFF
        -DUASDK_BUILD_HISTORY_SQLITE=OFF
        ${FEATURE_OPTIONS}
)

vcpkg_cmake_install()
# The SDK installs its package config under <libdir>/cmake/uasdk; vcpkg always normalises the package
# layout to "lib" (never lib64), so the path is literally lib/cmake/uasdk here. (CMAKE_INSTALL_LIBDIR
# is a configure-time variable and is NOT defined in portfile scope - using it collapsed CONFIG_PATH
# to "/cmake/uasdk" and the fixup failed to find the config.)
vcpkg_cmake_config_fixup(PACKAGE_NAME uasdk CONFIG_PATH "lib/cmake/uasdk")

# A static-library port has no headers or tools in the debug tree.
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
