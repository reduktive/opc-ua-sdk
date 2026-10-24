# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-server PRIVATE
        ua_aggregate_types.h
        ua_aggregate_types.cpp
        ua_aggregate_intervals.h
        ua_aggregate_intervals.cpp
        ua_aggregate_bounds.h
        ua_aggregate_bounds.cpp
        ua_aggregator.h
        ua_aggregator.cpp
        ua_aggregate_support.h
        ua_aggregate_support.cpp
        ua_aggregate_engine.h
        ua_aggregate_engine.cpp
        ua_aggregate_regions.h
        ua_aggregate_regions.cpp
        ua_aggregator_factories.h
        ua_aggregators_basic.cpp
        ua_aggregators_variation.cpp
        ua_aggregators_statistical.cpp
        ua_aggregators_bounds.cpp
        ua_aggregators_duration.cpp
        ua_aggregators_timeaverage.cpp
        ua_aggregators_minmax2.cpp
        ua_aggregators_counting.cpp
        ua_aggregators_quality.cpp
        ua_aggregate_registry.h
        ua_aggregate_registry.cpp
        ua_aggregate_descriptions.h
        ua_aggregate_descriptions.cpp
)

target_include_directories(uasdk-server PRIVATE .)
