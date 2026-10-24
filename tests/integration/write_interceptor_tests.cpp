// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// Integration tests for an application's own write rule for particular Variables, carried by a value source
/// (ua::make_value_source) attached to those Variables.
///
/// The source's write function runs for every Value write to its Variable, after built-in type checks. It
/// may approve, replace (e.g. clamp, answering Good_Clamped), or refuse the write. These tests attach such
/// sources and exercise all three outcomes end-to-end through the real Write service.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_attribute_id.h"
#include "ua_default_variable_node.h"
#include "ua_numeric_range_parser.h"
#include "ua_read_value_id.h"
#include "ua_value_source.h"
#include "ua_write_value.h"
#include "ua_data_value.h"
#include "ua_node_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_server.h"
#include "ua_session_attribute_services.h"
#include "ua_status_code.h"
#include "ua_variant.h"

#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>

using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;

namespace
{

DataValue read_value_of(Session& session, const NodeId& node)
{
  return session.attributes().read_sync(read_value(node)).results()[0];
}

/// Holds the Value of one Variable; `rule` judges each incoming write and may replace its value.
struct RuleSourceState
{
  std::mutex mutex;
  DataValue value;
};

/// Attaches to @p nodeId a value source that keeps the Value (starting at @p initial) and applies @p rule to
/// each write: a bad status refuses it, a good one stores the (possibly replaced) value and answers it.
void attach_rule_source(default_ns::Namespace& ns, const NodeId& nodeId, int32_t initial,
  std::function<StatusCode(DataValue&)> rule)
{
  auto state = std::make_shared<RuleSourceState>();
  state->value = DataValue{Variant{initial}};
  auto node = std::dynamic_pointer_cast<default_ns::VariableNode>(ns.find_node<Node>(nodeId));
  ASSERT_NE(node, nullptr);
  ASSERT_TRUE(node->external_value_source()
                ->set_value_source(make_value_source(
                  [state](const ValueSource::ReadContext& /*context*/,
                    const Node& /*node*/,
                    const ReadValueId& read,
                    std::function<void(DataValueResult)>
                      callback)
                  {
                    DataValue current;
                    {
                      std::lock_guard lock(state->mutex);
                      current = state->value;
                    }
                    index_range_utils::apply_to_value(current, read.index_range());
                    callback(DataValueResult{std::move(current)});
                  },
                  [state, rule = std::move(rule)](const ValueSource::WriteContext& /*context*/,
                    const Node& /*node*/,
                    const WriteValue& write,
                    std::function<void(ValueSource::WriteResult)>
                      callback)
                  {
                    DataValue proposed = write.value();
                    const StatusCode verdict = rule(proposed);
                    if (verdict.is_bad())
                    {
                      callback(ValueSource::WriteResult{verdict});
                      return;
                    }
                    {
                      std::lock_guard lock(state->mutex);
                      state->value = std::move(proposed);
                    }
                    if (verdict == StatusCode{Status::GoodClamped})
                      callback(ValueSource::WriteResult{ValueSource::Written{}, verdict});
                    else
                      callback(ValueSource::Written{});
                  }))
                .is_good());
}

}  // namespace

class WriteInterceptorTest : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();
    // Refuses every write to the full-access Variable with Bad_UserAccessDenied.
    attach_rule_source(*mTestNamespace,
      mFullAccessVariableId,
      0,
      [](DataValue&) { return StatusCode{Status::BadUserAccessDenied}; });
    // Clamps Int32 writes to the writable Variable at 100 and approves the rest unchanged.
    attach_rule_source(*mTestNamespace,
      mWritableVariableId,
      42,
      [](DataValue& proposed)
      {
        if (const auto* current = proposed.value().try_as<int32_t>(); current && *current > 100)
        {
          proposed.value() = Variant{int32_t{100}};
          return StatusCode{Status::GoodClamped};
        }
        return StatusCode{Status::Good};
      });
  }
};

// A value source can reject a write; the value is not stored.
TEST_F(WriteInterceptorTest, RejectsTargetedWrite)
{
  auto resp = mSession->attributes().write_sync(
    WriteRequestBuilder().write(mFullAccessVariableId, Variant{int32_t{777}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Bad(Status::BadUserAccessDenied));
  // Unchanged from its configured initial value (0).
  EXPECT_THAT(read_value_of(*mSession, mFullAccessVariableId), good_value_of<int32_t>(0));
}

// A value source can replace (clamp) the value; the clamped value is what gets stored.
TEST_F(WriteInterceptorTest, ClampsTransformedWrite)
{
  auto resp = mSession->attributes().write_sync(
    WriteRequestBuilder().write(mWritableVariableId, Variant{int32_t{999}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], HasStatus(Status::GoodClamped));
  EXPECT_THAT(read_value_of(*mSession, mWritableVariableId), good_value_of<int32_t>(100));
}

// In-range writes pass through unchanged.
TEST_F(WriteInterceptorTest, ApprovesInRangeWrite)
{
  auto resp =
    mSession->attributes().write_sync(WriteRequestBuilder().write(mWritableVariableId, Variant{int32_t{42}}));
  ASSERT_EQ(resp.results().size(), 1u);
  EXPECT_THAT(resp.results()[0], Good());
  EXPECT_THAT(read_value_of(*mSession, mWritableVariableId), good_value_of<int32_t>(42));
}
