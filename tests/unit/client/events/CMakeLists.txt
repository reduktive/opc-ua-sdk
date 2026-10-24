# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        alarm_condition_tracker_impl_tests.cpp
        event_demux_tests.cpp
        event_subscriber_impl_tests.cpp
)

# The A&C tracker's data-integrity observer-fire tests build a real ConnectionImpl + ObserverSink with the
# shared FakeSessionOps / FakeReopen stubs, which live in the sibling connection/ test directory.
target_include_directories(tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../connection)
