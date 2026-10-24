// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef TESTS_HISTORY_TEST_SUPPORT_H
#define TESTS_HISTORY_TEST_SUPPORT_H

#include "ua_binary_data_value_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_encoding_limits.h"
#include "ua_node_id.h"
#include "ua_structure.h"

#include <memory>

namespace ua::history::test
{

/// A scalar-only DataValue codec for the history_reference tests. The engine and store are exercised
/// against SqliteHistoryStore(":memory:") - an in-memory SQLite database - so there is a single store
/// implementation under test (the real backend), not a separate test double. No structured DataTypes
/// are used, so the structure resolver returns nullptr.
inline std::shared_ptr<const ua::UaBinaryDataValueCodec> make_codec()
{
  return ua::UaBinaryDataValueCodec::create([](const ua::NodeId&) -> std::unique_ptr<ua::Structure>
    { return nullptr; },
    ua::CodecNamespaceContext{},
    ua::EncodingLimits{});
}

}  // namespace ua::history::test

#endif  // !TESTS_HISTORY_TEST_SUPPORT_H
