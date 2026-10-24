# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-server PRIVATE
        ua_monitored_item.h
        ua_monitored_item.cpp
        ua_monitored_item_factory.h
        ua_monitored_item_factory.cpp
        ua_monitoring_release.h
        ua_monitoring_release.cpp
        ua_compiled_event_filter.h
        ua_compiled_event_filter.cpp
        ua_eu_range_resolver.h
        ua_eu_range_resolver.cpp
        ua_numeric_data_type_facts.h
        ua_numeric_data_type_facts.cpp
        ua_retained_notification_authorization.h
        ua_sample_sink_impl.h
        ua_subscription.h
        ua_subscription.cpp
        ua_subscriptions_pipeline.h
        ua_subscriptions_pipeline.cpp
        ua_subscriptions_pipeline_test_access.h
        ua_subscription_test_access.h
        ua_subscription_router.h
        ua_subscription_router.cpp
        ua_subscription_transfer_authorization.h
        ua_subscription_transfer_authorization.cpp
        ua_orphaned_subscription_store.h
        ua_orphaned_subscription_store.cpp
)

uasdk_private_include_directory(uasdk-server)
