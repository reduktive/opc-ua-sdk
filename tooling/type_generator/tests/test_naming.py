# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

"""The generator's public field names are camelBack (cpp_style.md section Naming)."""

from __future__ import annotations

from ..naming import to_camel_back


def test_a_browse_name_becomes_camel_back():
    assert to_camel_back("EventId") == "eventId"
    assert to_camel_back("SubscriptionId") == "subscriptionId"


def test_an_acronym_reads_as_one_word():
    assert to_camel_back("EURange") == "euRange"
    assert to_camel_back("ServerURI") == "serverUri"


def test_a_snake_case_name_and_an_embedded_underscore_join():
    assert to_camel_back("event_id") == "eventId"
    assert to_camel_back("PriorityValue_PCP") == "priorityValuePcp"


def test_a_keyword_takes_a_suffix():
    assert to_camel_back("Namespace") == "namespaceValue"
    assert to_camel_back("Default") == "defaultValue"
