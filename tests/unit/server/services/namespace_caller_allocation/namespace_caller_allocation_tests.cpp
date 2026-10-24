// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "allocation_controller.h"
#include "batch_recording_namespace.h"
#include "scripted_node.h"
#include "test_log_sink.h"
#include "ua_address_space.h"
#include "ua_allow_nulls_batch.h"
#include "ua_attribute_id.h"
#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_eu_range_resolver.h"
#include "ua_event_type_model.h"
#include "ua_external_guard_linker.h"
#include "ua_localized_text.h"
#include "ua_node_class.h"
#include "ua_node_utilities.h"
#include "ua_objecttype_id.h"
#include "ua_numeric_data_type_facts.h"
#include "ua_qualified_name.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_subtype_facts.h"
#include "ua_utilities.h"
#include "ua_variant.h"

#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>
#include <unistd.h>

using namespace ua;
using namespace ua::server;

namespace
{

TEST(AllocationSymbolizerParser, PreservesEveryInlineScopeInProducerOrder)
{
  const std::array<std::uintptr_t, 2> addresses{0x10, 0x20};
  const auto decoded = test::allocation::parse_symbolizer_output(
    "0x0000000000000010\nstd::allocator::allocate()\n/usr/include/allocator.h:5\n"
    "ua::NamespaceRoute::finish_one()\n/work/src/sdk/implementation/ua_namespace_route.h:241 (discriminator "
    "2)\n"
    "ua::NamespaceRoute::run_part()\n/work/src/sdk/implementation/ua_namespace_route.h:364\n"
    "0x0000000000000020\n??\n??:0\n",
    addresses);
  ASSERT_EQ(decoded.size(), 2U);
  ASSERT_EQ(decoded[0].size(), 3U);
  EXPECT_EQ(decoded[0][0].function, "std::allocator::allocate()");
  EXPECT_EQ(decoded[0][1].function, "ua::NamespaceRoute::finish_one()");
  EXPECT_EQ(decoded[0][1].file, "/work/src/sdk/implementation/ua_namespace_route.h");
  EXPECT_EQ(decoded[0][1].line, 241U);
  EXPECT_EQ(
    decoded[0][1].sourceLocation, "/work/src/sdk/implementation/ua_namespace_route.h:241 (discriminator 2)");
  EXPECT_EQ(decoded[0][2].function, "ua::NamespaceRoute::run_part()");
  for (const auto& frame : decoded[0])
    EXPECT_EQ(frame.address, 0x10U);
  ASSERT_EQ(decoded[1].size(), 1U);
  EXPECT_EQ(decoded[1][0].address, 0x20U);
  EXPECT_EQ(decoded[1][0].function, "??");
  EXPECT_EQ(decoded[1][0].file, "??");
  EXPECT_EQ(decoded[1][0].line, 0U);
}

TEST(AllocationSymbolizerParser, RetainsNamesAndPathsLongerThanFourKiB)
{
  const std::array<std::uintptr_t, 1> addresses{0x10};
  const std::string function = "ua::" + std::string(9000, 'n') + "()";
  const std::string file =
    "/work/src/sdk/implementation/directory:with-colon/" + std::string(5000, 'f') + ".h";
  const auto decoded =
    test::allocation::parse_symbolizer_output("0x10\n" + function + '\n' + file + ":42\n", addresses);
  ASSERT_EQ(decoded.size(), 1U);
  ASSERT_EQ(decoded[0].size(), 1U);
  EXPECT_EQ(decoded[0][0].function, function);
  EXPECT_EQ(decoded[0][0].file, file);
  EXPECT_EQ(decoded[0][0].line, 42U);
}

TEST(AllocationSymbolizerParser, RetainsUnknownExternalSymbolsWithoutClaimingSdkEvidence)
{
  const std::array<std::uintptr_t, 1> addresses{0x10};
  const auto decoded = test::allocation::parse_symbolizer_output("0x10\n??\n??:?\n", addresses);
  ASSERT_EQ(decoded.size(), 1U);
  ASSERT_EQ(decoded[0].size(), 1U);
  EXPECT_EQ(decoded[0][0].sourceLocation, "??:?");
  EXPECT_EQ(decoded[0][0].line, 0U);
}

TEST(AllocationSymbolizerParser, EmptyRequestsRequireEmptyOutput)
{
  EXPECT_TRUE(test::allocation::parse_symbolizer_output("", {}).empty());
  EXPECT_THROW(test::allocation::parse_symbolizer_output("0x10\n??\n??:0\n", {}), std::runtime_error);
}

TEST(AllocationSymbolizerParser, RetainsObservedEmptyExternalLocationWithoutInventingSource)
{
  // Original GNU records, plus the 32-bit size_t spelling of the same external growth method.
  constexpr std::array<std::string_view, 6> externalFunctions{
    "fmt::v10::vformat[abi:cxx11](fmt::v10::basic_string_view<char>, "
    "fmt::v10::basic_format_args<fmt::v10::basic_format_context<fmt::v10::appender, char> >)",
    "fmt::v10::basic_memory_buffer<char, 500ul, std::allocator<char> >::grow(unsigned long)",
    "fmt::v10::basic_memory_buffer<char, 500u, std::allocator<char> >::grow(unsigned int)",
    "fmt::v10::appender fmt::v10::detail::copy_str_noinline<char, char const*, fmt::v10::appender>(char "
    "const*, char const*, fmt::v10::appender)",
    "char const* fmt::v10::detail::parse_replacement_field<char, "
    "fmt::v10::detail::vformat_to<char>(fmt::v10::detail::buffer<char>&, fmt::v10::basic_string_view<char>, "
    "fmt::v10::detail::vformat_args<char>::type, fmt::v10::detail::locale_ref)::format_handler&>(char "
    "const*, char const*, fmt::v10::detail::vformat_to<char>(fmt::v10::detail::buffer<char>&, "
    "fmt::v10::basic_string_view<char>, fmt::v10::detail::vformat_args<char>::type, "
    "fmt::v10::detail::locale_ref)::format_handler&)",
    "void fmt::v10::detail::vformat_to<char>(fmt::v10::detail::buffer<char>&, "
    "fmt::v10::basic_string_view<char>, fmt::v10::detail::vformat_args<char>::type, "
    "fmt::v10::detail::locale_ref)"};
  const std::array<std::uintptr_t, 1> addresses{0x482b11};
  for (const auto function : externalFunctions)
  {
    SCOPED_TRACE(function);
    const auto decoded = test::allocation::parse_symbolizer_output(
      "0x482b11\n" + std::string{function} +
        "\n:?\n"
        "ua::NamespaceRoute::finish_one()\n/work/src/sdk/implementation/ua_namespace_route.h:241\n",
      addresses);
    ASSERT_EQ(decoded.size(), 1U);
    ASSERT_EQ(decoded[0].size(), 2U);
    EXPECT_EQ(decoded[0][0].function, function);
    EXPECT_EQ(decoded[0][0].sourceLocation, ":?");
    EXPECT_TRUE(decoded[0][0].file.empty());
    EXPECT_EQ(decoded[0][0].line, 0U);
    EXPECT_EQ(decoded[0][1].function, "ua::NamespaceRoute::finish_one()");
    EXPECT_EQ(decoded[0][1].line, 241U);
  }
}

TEST(AllocationSymbolizerParser, RejectsEmptySdkLocationsAndOtherEmptyFilenameForms)
{
  const std::array<std::uintptr_t, 1> addresses{0x10};
  for (const std::string_view output : {"0x10\nua::NamespaceRoute::finish_one()\n:?\n",
         "0x10\nstart\n:?\nua::NamespaceRoute::finish_one()\n/work/src/sdk/implementation/file.h:241\n",
         "0x10\nExternalGuardVariableLinkOperation\n:?\nua::NamespaceRoute::finish_one()\n/work/src/sdk/"
         "implementation/file.h:241\n",
         "0x10\nvoid "
         "ua::NamespaceRoute::finish_one()\n:?\nua::NamespaceRoute::run_part()\n/work/src/sdk/implementation/"
         "file.h:364\n",
         "0x10\nfmt::v10::formatter<ua::Fixture>::format(arguments)\n:?\n",
         "0x10\nfmt::v10::basic_memory_buffer<char, 500ul, std::allocator<char> >::grow(unsigned "
         "long)::{lambda()}\n:?\n",
         "0x10\nfmt::v11::vformat[abi:cxx11](arguments)\n:?\n",
         "0x10\ngrow\n:?\n",
         "0x10\nexternal\n:0\n",
         "0x10\nexternal\n:1\n",
         "0x10\nexternal\n:?extra\n",
         "0x10\nexternal\n:\n"})
  {
    SCOPED_TRACE(output);
    EXPECT_THROW(test::allocation::parse_symbolizer_output(output, addresses), std::runtime_error);
  }
}

TEST(AllocationSymbolizerParser, RejectsMissingMalformedAndMismatchedAddresses)
{
  const std::array<std::uintptr_t, 1> addresses{0x10};
  for (const std::string_view output : {"",
         "10\nfunction\nfile:1\n",
         "0xzz\nfunction\nfile:1\n",
         "0x20\nfunction\nfile:1\n",
         "0x\nfunction\nfile:1\n"})
  {
    SCOPED_TRACE(output);
    EXPECT_THROW(test::allocation::parse_symbolizer_output(output, addresses), std::runtime_error);
  }
  const std::array<std::uintptr_t, 2> twoAddresses{0x10, 0x20};
  EXPECT_THROW(
    test::allocation::parse_symbolizer_output("0x10\nfunction\nfile:1\n", twoAddresses), std::runtime_error);
}

TEST(AllocationSymbolizerParser, RejectsMissingAndTruncatedInlinePairs)
{
  const std::array<std::uintptr_t, 1> addresses{0x10};
  for (const std::string_view output :
    {"0x10\n", "0x10\nfunction\n", "0x10\nfunction\nfile:1", "0x10\n\nfile:1\n", "0x10\nfunction\n0x20\n"})
  {
    SCOPED_TRACE(output);
    EXPECT_THROW(test::allocation::parse_symbolizer_output(output, addresses), std::runtime_error);
  }
}

TEST(AllocationSymbolizerParser, RejectsInvalidSourceFieldsAndNumericOverflow)
{
  const std::array<std::uintptr_t, 1> addresses{0x10};
  for (const std::string_view location : {"file",
         ":1",
         "file:",
         "file:garbage",
         "file:1tail",
         "file:184467440737095516160",
         "file:?extra",
         "file:1 (discriminator )",
         "file:1 (discriminator x)",
         "file:1 (discriminator 2) extra",
         "file:1 (discriminator 2"})
  {
    SCOPED_TRACE(location);
    EXPECT_THROW(
      test::allocation::parse_symbolizer_output("0x10\nfunction\n" + std::string{location} + '\n', addresses),
      std::runtime_error);
  }
}

TEST(AllocationSymbolizerParser, RejectsMissingSdkSymbolsAndSourceLines)
{
  const std::array<std::uintptr_t, 1> addresses{0x10};
  for (const std::string_view output : {"0x10\n??\n/work/src/sdk/implementation/file.cpp:1\n",
         "0x10\nfunction\n/work/src/sdk/implementation/file.cpp:0\n",
         "0x10\nfunction\n/work/src/sdk/implementation/file.cpp:?\n"})
  {
    SCOPED_TRACE(output);
    EXPECT_THROW(test::allocation::parse_symbolizer_output(output, addresses), std::runtime_error);
  }
}

TEST(AllocationSymbolizerParser, RejectedSourceRetainsQueryAndCompleteProducerRecord)
{
  const std::array<std::uintptr_t, 3> addresses{0x10, 0x20, 0x30};
  constexpr std::string_view rejectedRecord{
    "0x0000000000000020\nstart\ninvalid location\nouter raw function\nfile:17\n"};
  try
  {
    static_cast<void>(test::allocation::parse_symbolizer_output(
      "0x10\nfirst\nfile:1\n" + std::string{rejectedRecord} + "0x30\nlast\nfile:3\n", addresses));
    FAIL() << "The malformed location must be rejected";
  }
  catch (const std::runtime_error& error)
  {
    const std::string_view diagnostic{error.what()};
    EXPECT_NE(diagnostic.find("query[1] expected=0x20"), std::string_view::npos);
    EXPECT_NE(diagnostic.find("function: start\nlocation: invalid location\n"), std::string_view::npos);
    EXPECT_NE(diagnostic.find(rejectedRecord), std::string_view::npos);
    EXPECT_EQ(diagnostic.find("first\n"), std::string_view::npos);
    EXPECT_EQ(diagnostic.find("last\n"), std::string_view::npos);
  }
}

TEST(AllocationSymbolizerParser, RejectsUnexpectedTrailingRecords)
{
  const std::array<std::uintptr_t, 1> addresses{0x10};
  for (const std::string_view trailing : {"0x20\n??\n??:0\n", "extra\n", "extra\ninvalid location\n"})
  {
    SCOPED_TRACE(trailing);
    EXPECT_THROW(test::allocation::parse_symbolizer_output(
                   "0x10\nfunction\nfile:1\n" + std::string{trailing}, addresses),
      std::runtime_error);
  }
}

TEST(AllocationSymbolizerParser, RepeatedNormalizedAddressesKeepTheirOrderedReplies)
{
  const std::array<std::uintptr_t, 2> addresses{0x10, 0x10};
  const auto decoded = test::allocation::parse_symbolizer_output(
    "0x10\nfirst alias\nfile:1\n0x10\nsecond alias\nfile:2\n", addresses);
  ASSERT_EQ(decoded.size(), 2U);
  ASSERT_EQ(decoded[0].size(), 1U);
  ASSERT_EQ(decoded[1].size(), 1U);
  EXPECT_EQ(decoded[0][0].function, "first alias");
  EXPECT_EQ(decoded[1][0].function, "second alias");
}

TEST(AllocationSymbolizerParser, RefusesToAllocateEvidenceWhileInterceptionIsArmed)
{
  test::allocation::record();
  bool refused = false;
  try
  {
    static_cast<void>(test::allocation::parse_symbolizer_output("", {}));
  }
  catch (const std::logic_error&)
  {
    refused = true;
  }
  catch (...)
  {
    test::allocation::disarm();
    throw;
  }
  test::allocation::disarm();
  EXPECT_TRUE(refused);
}

enum class Caller
{
  AllowNulls,
  EuRange,
  Walking
};

enum class Stage
{
  References,
  Lookup,
  Value
};

struct Scenario
{
  Caller caller;
  Stage stage;
  bool uncertainValue{false};
  bool embeddedValueFailure{false};
};

std::string name(Scenario scenario)
{
  const std::array<std::string_view, 3> callers{"AllowNulls", "EURange", "Walking"};
  std::string result{callers[static_cast<std::size_t>(scenario.caller)]};
  if (scenario.stage == Stage::References)
  {
    return result + "/References";
  }
  if (scenario.stage == Stage::Value)
  {
    result += "/Value";
    if (scenario.uncertainValue)
      result += "/Uncertain";
    else
      result += "/TypeMismatch";
    if (scenario.embeddedValueFailure)
      return result + "/EmbeddedFailure";
    return result + "/OuterFailure";
  }
  return result + "/Lookup";
}

// Extends ScriptedNode only for the already-established absent-Property control.
class FakeScriptedNode final : public test::ScriptedNode
{
public:
  explicit FakeScriptedNode(bool deleted = false) : mDeleted(deleted)
  {}

  bool deleted() const noexcept override
  {
    return mDeleted;
  }

private:
  bool mDeleted;
};

struct ContinuationDelivery
{
  std::function<void()> answer;
  std::function<void()> duplicate;
};

// BatchRecordingNamespace records every call and shapes every answer; this extension retains a completed
// namespace answer at the external callback boundary, so routing can finish before the selected SDK
// continuation is reached. Copies for duplicate delivery are made before interception.
//
// Lookups answer the handed-out ScriptedNodes. Each has an in-memory shadow with its NodeId, NodeClass and
// the References it answered when handed out, which the recorder's reference reads (scripted answers, hints,
// pages and their tokens) read in its place; a handed-out Node's Value is its scripted Value.
class FakeParkedNamespace final : public test::BatchRecordingNamespace
{
public:
  explicit FakeParkedNamespace(boost::asio::any_io_executor executor)
    : BatchRecordingNamespace("urn:test:continuation-allocation", std::move(executor))
  {
    decline_single_lookups();
    apply_reference_hints();
  }

  void hand_out(std::shared_ptr<test::ScriptedNode> node)
  {
    const NodeDescription description = node->attributes();
    const NodeId nodeId = description.node_id();
    auto shadow =
      std::static_pointer_cast<default_ns::BaseNode>(create_node(nodeId, description.node_class()));
    // The in-memory Node changes its own References inline.
    VoidResult copied{StatusCode{Status::BadInternalError}};
    shadow->add_references_async(
      node->references(), [&copied](VoidResult result) { copied = std::move(result); });
    if (copied.is_bad())
    {
      throw std::runtime_error{"The allocation fixture could not copy a handed-out Node's References"};
    }
    mShadows.emplace(nodeId, std::move(shadow));
    mNodes.emplace(nodeId, std::move(node));
  }

  void park() noexcept
  {
    mPark = true;
  }

  /// While set, lookups are answered at once although the namespace is parked: a fixture's own lookup of a
  /// Node it hands out after parking.
  void answer_lookups(bool answer) noexcept
  {
    mAnswerLookups = answer;
  }

  std::optional<NodeResult> find_node(const NodeId& nodeId, std::optional<Duration> maxAge) override
  {
    auto answer = BatchRecordingNamespace::find_node(nodeId, maxAge);
    // While parked, every lookup, a scripted one included, reaches the batched member, which retains it.
    if (mPark && !mAnswerLookups)
      return std::nullopt;
    return answer;
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> complete) override
  {
    BatchRecordingNamespace::find_nodes_async(
      request, nodeIds, maxAge, mAnswerLookups ? std::move(complete) : retain(mLookups, std::move(complete)));
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    std::vector<ReferenceQuery> shadowed;
    shadowed.reserve(queries.size());
    for (const auto& query : queries)
    {
      shadowed.push_back(ReferenceQuery{.node = shadow_of(query.node, query.nodeId),
        .nodeId = query.nodeId,
        .direction = query.direction,
        .referenceTypeHint = query.referenceTypeHint,
        .maxReferences = query.maxReferences,
        .resumeToken = query.resumeToken});
    }
    BatchRecordingNamespace::read_references_async(
      request, shadowed, retain(mReferences, std::move(complete)));
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    std::vector<std::optional<DataValueResult>> scripted;
    scripted.reserve(items.size());
    for (const auto& item : items)
    {
      const auto* node = dynamic_cast<const test::ScriptedNode*>(&item.node);
      scripted.push_back(node != nullptr ? std::optional<DataValueResult>{node->read_value()} : std::nullopt);
    }
    BatchRecordingNamespace::read_values_async(request,
      caller,
      items,
      maxAge,
      setSourceTimestamp,
      [scripted = std::move(scripted), complete = retain(mValues, std::move(complete))](
        BatchResult<DataValueResult> read)
      {
        if (read.items.size() == scripted.size())
        {
          for (std::size_t i = 0; i < scripted.size(); ++i)
          {
            if (scripted[i])
              read.items[i] = *scripted[i];
          }
        }
        complete(std::move(read));
      });
  }

  ContinuationDelivery take(Stage stage)
  {
    std::optional<ContinuationDelivery> delivery;
    if (stage == Stage::References)
    {
      delivery = take_ready(mReferences);
    }
    else if (stage == Stage::Value)
    {
      delivery = take_ready(mValues);
    }
    else
    {
      delivery = take_ready(mLookups);
    }
    if (!delivery)
    {
      throw std::runtime_error{"The selected namespace answer is not ready"};
    }
    return std::move(*delivery);
  }

  std::optional<ContinuationDelivery> take_next()
  {
    if (auto delivery = take_ready(mReferences))
      return delivery;
    if (auto delivery = take_ready(mLookups))
      return delivery;
    return take_ready(mValues);
  }

protected:
  NodeResult resolve_here(const NodeId& nodeId) override
  {
    if (const auto found = mNodes.find(nodeId); found != mNodes.end())
    {
      return NodeResult{std::shared_ptr<Node>{found->second}};
    }
    return BatchRecordingNamespace::resolve_here(nodeId);
  }

private:
  template<typename Answer>
  struct Pending
  {
    std::function<void(Answer)> complete;
    std::optional<Answer> answer;
    bool delivered{false};
  };

  /// The in-memory shadow of the handed-out @p node, or @p node itself when it is not one handed out.
  const Node& shadow_of(const Node& node, const NodeId& nodeId) const
  {
    const auto handed = mNodes.find(nodeId);
    const auto shadow = mShadows.find(nodeId);
    if (handed == mNodes.end() || handed->second.get() != &node || shadow == mShadows.end())
      return node;
    return *shadow->second;
  }

  template<typename Answer>
  std::function<void(Answer)> retain(
    std::vector<std::shared_ptr<Pending<Answer>>>& pending, std::function<void(Answer)> complete)
  {
    if (!mPark)
      return complete;
    auto held = std::make_shared<Pending<Answer>>();
    held->complete = std::move(complete);
    pending.push_back(held);
    return [held](Answer answer)
    {
      held->answer = std::move(answer);
    };
  }

  template<typename Answer>
  static std::optional<ContinuationDelivery> take_ready(
    std::vector<std::shared_ptr<Pending<Answer>>>& pending)
  {
    for (const auto& held : pending)
    {
      if (held->delivered || !held->answer)
        continue;
      held->delivered = true;
      const auto complete = held->complete;
      const Answer answer = *held->answer;
      const auto deliver = [complete, answer]()
      {
        complete(answer);
      };
      return ContinuationDelivery{deliver, deliver};
    }
    return std::nullopt;
  }

  bool mPark{false};
  bool mAnswerLookups{false};
  std::map<NodeId, std::shared_ptr<test::ScriptedNode>> mNodes;
  std::map<NodeId, std::shared_ptr<default_ns::BaseNode>> mShadows;
  std::vector<std::shared_ptr<Pending<BatchResult<NodeResult>>>> mLookups;
  std::vector<std::shared_ptr<Pending<BatchResult<NodeReferencesResult>>>> mReferences;
  std::vector<std::shared_ptr<Pending<BatchResult<DataValueResult>>>> mValues;
};

struct Answers
{
  std::size_t completions{0};
  std::vector<AllowNullsOutcome> allowNulls;
  std::vector<EuRangeProperty> euRanges;
  std::vector<SupertypeWalkEnd> walks;
  std::vector<bool> nonNumeric;
  bool throwNumericCompletion{false};
  std::optional<event_type_model::DeclarationsResult> declarations;
  std::optional<std::size_t> tokenReleasesAtCompletion;
  std::vector<event_type_model::SelectClauseModelsResult> models;
  std::optional<node_utils::OptionalNodeAccessorResult> supertype;
  std::optional<BoolResult> referenceMatch;
  std::optional<VoidResult> externalGuard;
};

class AllocationRun
{
public:
  explicit AllocationRun(Scenario scenario, Status sentinelStatus = Status::BadResourceUnavailable)
    : scenario(scenario),
      addressSpace(AddressSpace::create("urn:test:allocation-owner", context.get_executor())),
      nameSpace(std::make_shared<FakeParkedNamespace>(context.get_executor())),
      answers(std::make_shared<Answers>()),
      sentinel(sentinelStatus, ErrorDetail::build("LaterNamespaceRefusal", "The later item was refused",
                                 "NamespaceCallerAllocation"))
  {
    std::optional<Result<uint16_t>> registered;
    addressSpace.add_namespace_async(
      nameSpace, [&registered](Result<uint16_t> result) { registered = std::move(result); });
    drain();
    if (!registered || !registered->is_good())
    {
      throw std::runtime_error{"The allocation fixture namespace registration failed"};
    }
    const auto index = registered->value();
    subjects.resize(3);
    if (scenario.stage == Stage::Value)
    {
      subjects.resize(4);
    }
    for (std::size_t item = 0; item < subjects.size(); ++item)
    {
      subjects[item] = NodeId{index, static_cast<uint32_t>(100 + item)};
    }
    // Long identifiers force genuine NodeId copy allocations, independent of a library's small-string size.
    continuing = NodeId{index, String{std::string(512, 'p')}};
    refused = NodeId{index, uint32_t{200}};
    terminal = NodeId{index, uint32_t{201}};
    const bool walking = scenario.caller == Caller::Walking;
    NodeClass subjectClass{NodeClass::Variable};
    ReferenceTypeId referenceType{ReferenceTypeId::HasProperty};
    if (walking)
    {
      subjectClass = NodeClass::DataType;
      referenceType = ReferenceTypeId::HasSubtype;
    }
    for (std::size_t item = 0; item < subjects.size(); ++item)
    {
      bool absent = !walking && item == 2;
      if (scenario.stage == Stage::Value)
        absent = item == 3;
      auto node = make_node(subjects[item], subjectClass, "Subject", absent);
      if (item < 2 || (scenario.stage == Stage::Value && item == 2))
      {
        NodeId target{refused};
        if (item == 0)
        {
          target = continuing;
        }
        else if (item == 2)
        {
          target = terminal;
        }
        node->answer_references({Reference{NodeId{referenceType}, ExpandedNodeId{target}, !walking}});
      }
      nameSpace->hand_out(std::move(node));
    }
    std::string_view propertyName{"EURange"};
    if (scenario.caller == Caller::AllowNulls)
    {
      propertyName = "AllowNulls";
    }
    auto next = make_node(continuing, subjectClass, propertyName);
    if (walking)
    {
      next->answer_references(
        {Reference{NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{terminal}, false}});
    }
    else if (scenario.stage == Stage::Value && scenario.uncertainValue)
    {
      firstValueRefusal = StatusCode{Status::UncertainNoCommunicationLastUsableValue,
        ErrorDetail::build(
          "FirstValueUncertain", "The first Value answer has no payload", "NamespaceCallerAllocation")};
      next->answer_read_value(DataValueResult{firstValueRefusal});
    }
    else
    {
      DataValue value;
      if (scenario.stage == Stage::Value)
      {
        value.value() = Variant{int32_t{42}};
      }
      else if (scenario.caller == Caller::AllowNulls)
      {
        value.value() = Variant{true};
      }
      else
      {
        value.value() = Variant{42.5};
      }
      next->answer_read_value(DataValueResult{std::move(value)});
    }
    nameSpace->hand_out(std::move(next));
    if (scenario.stage == Stage::Value)
    {
      // This final read has three selected Properties and a separately established absent Property.
      auto later = make_node(refused, NodeClass::Variable, "AllowNulls");
      if (scenario.embeddedValueFailure)
      {
        later->answer_read_value(DataValueResult{DataValue{Variant{false}, sentinel}});
      }
      else
      {
        later->answer_read_value(DataValueResult{sentinel});
      }
      nameSpace->hand_out(std::move(later));
      auto usable = make_node(terminal, NodeClass::Variable, "AllowNulls");
      usable->answer_read_value(DataValueResult{DataValue{Variant{false}}});
      nameSpace->hand_out(std::move(usable));
    }
    else
    {
      nameSpace->hand_out(make_node(refused, subjectClass, "Refused"));
    }
    if (scenario.stage == Stage::References)
    {
      nameSpace->answer_reference_query_of(subjects[1], 1, sentinel);
    }
    else if (scenario.stage == Stage::Lookup)
    {
      nameSpace->answer_lookup_of(refused, sentinel);
    }
    for (const auto& subject : subjects)
    {
      std::optional<NodeAccessorResult> found;
      addressSpace.find_node_async(
        subject, [&found](NodeAccessorResult answer) { found = std::move(answer); });
      drain();
      if (!found || !found->is_good())
        throw std::runtime_error{"The allocation fixture lookup failed"};
      starts.push_back(std::move(*found).value());
    }
    nameSpace->reset();
    nameSpace->park();
  }

  void start()
  {
    if (scenario.caller == Caller::AllowNulls)
    {
      AllowNullsBatch::resolve_async(addressSpace,
        {},
        starts,
        {},
        {},
        [answers = answers](std::vector<AllowNullsOutcome> result)
        {
          ++answers->completions;
          answers->allowNulls = std::move(result);
        });
    }
    else if (scenario.caller == Caller::EuRange)
    {
      EuRangeResolver::resolve_async(addressSpace,
        {},
        starts,
        {},
        [answers = answers](std::vector<EuRangeProperty> result)
        {
          ++answers->completions;
          answers->euRanges = std::move(result);
        });
    }
    else
    {
      std::vector<std::pair<NodeAccessor, NodeId>> chains;
      for (std::size_t item = 0; item < starts.size(); ++item)
        chains.emplace_back(starts[item], subjects[item]);
      walk_supertypes(
        addressSpace,
        {},
        std::move(chains),
        8,
        [terminal = terminal](std::size_t chain, const NodeId& type) -> std::optional<int>
        {
          if (chain == 2)
            return 73;
          if (type == terminal)
            return 11;
          return std::nullopt;
        },
        [answers = answers](std::vector<SupertypeWalkEnd> result)
        {
          ++answers->completions;
          answers->walks = std::move(result);
        });
    }
    drain();
    if (scenario.stage == Stage::Lookup || scenario.stage == Stage::Value)
    {
      auto references = nameSpace->take(Stage::References);
      duplicates.push_back(references.duplicate);
      references.answer();
      drain();
    }
    if (scenario.stage == Stage::Value)
    {
      auto lookup = nameSpace->take(Stage::Lookup);
      duplicates.push_back(lookup.duplicate);
      lookup.answer();
      drain();
    }
  }

  void drain()
  {
    context.restart();
    context.run();
  }

  std::size_t drain_bounded()
  {
    context.restart();
    std::size_t dispatched{0};
    for (std::size_t step = 0; step < 32; ++step)
    {
      if (context.poll_one() == 0)
        return dispatched;
      ++dispatched;
    }
    throw std::runtime_error{"The allocation fixture executor exceeded its fixed drain bound"};
  }

  ContinuationDelivery external_guard_delivery(bool nonapplicable)
  {
    auto instantiation = std::make_shared<instantiation_detail::InstantiationContext>();
    if (nonapplicable)
    {
      const auto index = subjects[0].namespace_index();
      instantiation->record_node(
        instantiation_detail::InstantiatedNodeBinding{.declarationId = NodeId{index, uint32_t{700}},
          .instanceId = NodeId{index, uint32_t{701}},
          .parentInstanceId = NodeId{index, uint32_t{702}},
          .parentReferenceType = NodeId{ReferenceTypeId::HasProperty},
          .browseName = QualifiedName{index, "Value"},
          .nodeClass = NodeClass::Variable,
          .typeDefinitionId = NodeId{index, uint32_t{703}}});
    }
    // Context and initiation storage are ready before arming. The consumer owns no SDK handle;
    // AllocationRun retains its observation and the only mutable context alias is discarded here.
    std::shared_ptr<const instantiation_detail::InstantiationContext> immutable = std::move(instantiation);
    std::function<void(VoidResult)> completion = [observation = answers.get()](VoidResult result)
    {
      ++observation->completions;
      observation->externalGuard = std::move(result);
    };
    return {[addressSpace = addressSpace,
              immutable = std::move(immutable),
              completion = std::move(completion)]() mutable
      {
        instantiation_detail::wire_external_guard_variables_async(
          addressSpace, DepthBudget{128}, immutable, std::move(completion));
      },
      {}};
  }

  std::pair<NodeAccessor, NodeId> nested_type(bool hasParent)
  {
    const auto index = subjects[0].namespace_index();
    const NodeId child{index, uint32_t{600}};
    const NodeId parent{index, uint32_t{601}};
    auto node = make_node(child, NodeClass::ReferenceType, "Nested child");
    if (hasParent)
    {
      node->answer_references(
        {Reference{NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{parent}, false}});
    }
    nameSpace->hand_out(std::move(node));
    nameSpace->hand_out(make_node(parent, NodeClass::ReferenceType, "Nested parent"));
    std::optional<NodeAccessorResult> found;
    nameSpace->answer_lookups(true);
    addressSpace.find_node_async(child, [&found](NodeAccessorResult answer) { found = std::move(answer); });
    drain();
    nameSpace->answer_lookups(false);
    if (!found || !found->is_good())
      throw std::runtime_error{"The nested allocation fixture type lookup failed: " +
                               (found ? to_string(found->status_code()) : std::string{"no answer"})};
    nameSpace->reset();
    return {std::move(*found).value(), parent};
  }

  ContinuationDelivery supertype_delivery(NodeAccessor type)
  {
    // AllocationRun retains Answers through all deliveries; the caller completion owns no SDK handle.
    return {[addressSpace = addressSpace, type = std::move(type), observation = answers.get()]()
      {
        node_utils::get_super_type_async(addressSpace,
          type,
          [observation](node_utils::OptionalNodeAccessorResult result)
          {
            ++observation->completions;
            observation->supertype = std::move(result);
          });
      },
      {}};
  }

  void start_nested_reference(
    const NodeId& child, bool cached, const std::shared_ptr<node_utils::RefTypeCache>& cache)
  {
    const auto complete = [observation = answers.get()](BoolResult result)
    {
      ++observation->completions;
      observation->referenceMatch = std::move(result);
    };
    if (cached)
    {
      node_utils::is_ref_of_type_cached_async(
        EncodingLimits{}, addressSpace, true, child, NodeId{ReferenceTypeId::References}, cache, complete);
    }
    else
    {
      node_utils::is_ref_of_type_async(
        EncodingLimits{}, addressSpace, true, child, NodeId{ReferenceTypeId::References}, complete);
    }
    drain();
    auto lookup = nameSpace->take(Stage::Lookup);
    duplicates.push_back(lookup.duplicate);
    lookup.answer();
    drain();
  }

  std::vector<NodeId> numeric_types()
  {
    const auto index = subjects[0].namespace_index();
    const NodeId numeric{index, uint32_t{300}};
    const NodeId nonNumeric{index, uint32_t{301}};
    const NodeId undecided{index, uint32_t{302}};
    auto numericNode = make_node(numeric, NodeClass::DataType, "Custom numeric");
    numericNode->answer_references(
      {Reference{NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{NodeId{DataTypeId::Double}}, false}});
    nameSpace->hand_out(std::move(numericNode));
    auto nonNumericNode = make_node(nonNumeric, NodeClass::DataType, "Custom nonnumeric");
    nonNumericNode->answer_references(
      {Reference{NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{NodeId{DataTypeId::String}}, false}});
    nameSpace->hand_out(std::move(nonNumericNode));
    nameSpace->hand_out(make_node(undecided, NodeClass::DataType, "Custom undecided"));
    return {NodeId{DataTypeId::Double},
      NodeId{DataTypeId::String},
      NodeId{DataTypeId::BaseDataType},
      NodeId{},
      numeric,
      nonNumeric,
      undecided};
  }

  void start_numeric(
    std::vector<NodeId> types, bool throwing, std::function<void(std::vector<bool>)> complete = {})
  {
    if (complete)
    {
      numeric_data_type_facts(addressSpace, {}, std::move(types), std::move(complete));
      return;
    }
    numeric_data_type_facts(addressSpace,
      {},
      std::move(types),
      [answers = answers, throwing](std::vector<bool> result)
      {
        ++answers->completions;
        answers->nonNumeric = std::move(result);
        if (throwing)
        {
          throw std::runtime_error{"Numeric facts caller completion refusal"};
        }
      });
  }

  std::pair<std::vector<NodeId>, NodeId> event_nodes(std::size_t typeCount = 1)
  {
    std::optional<NodeAccessorResult> base;
    addressSpace.create_node_async(NodeId{ObjectTypeId::BaseEventType},
      NodeClass::ObjectType,
      [&base](NodeAccessorResult answer) { base = std::move(answer); });
    drain();
    if (!base || !base->is_good())
      throw std::runtime_error{"The allocation fixture BaseEventType creation failed"};
    const auto index = subjects[0].namespace_index();
    const NodeId declaration{index, uint32_t{501}};
    std::vector<NodeId> types;
    for (std::size_t item = 0; item < typeCount; ++item)
    {
      const NodeId type{index, numeric_cast<uint32_t>(500 + 2 * item)};
      types.push_back(type);
      auto event = make_node(type, NodeClass::ObjectType, "Allocation event");
      event->answer_references(
        {Reference{
           NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{NodeId{ObjectTypeId::BaseEventType}}, false},
          Reference{NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{declaration}, true}});
      nameSpace->hand_out(std::move(event));
    }
    nameSpace->hand_out(make_node(declaration, NodeClass::Object, "Entry"));
    nameSpace->page_references(1);
    nameSpace->reset();
    return {std::move(types), declaration};
  }

  void start_event(NodeId type)
  {
    event_type_model::collect_declarations_async(addressSpace,
      std::move(type),
      [answers = answers, issuer = std::weak_ptr<FakeParkedNamespace>{nameSpace}](
        event_type_model::DeclarationsResult result)
      {
        ++answers->completions;
        if (const auto nameSpace = issuer.lock())
          answers->tokenReleasesAtCompletion =
            nameSpace->count(test::BatchRecordingNamespace::Member::ReleaseResumeToken);
        answers->declarations = std::move(result);
      });
    drain();
    auto lookup = nameSpace->take(Stage::Lookup);
    duplicates.push_back(lookup.duplicate);
    lookup.answer();
    drain();
  }

  ContinuationDelivery event_models_delivery(const std::vector<NodeId>& types)
  {
    std::vector<EventFilter> filters;
    for (const auto& type : types)
    {
      SimpleAttributeOperand clause;
      clause.type_definition_id() = type;
      clause.attribute_id() = utils::to_underlying(AttributeId::NodeId);
      EventFilter filter;
      filter.select_clauses() = Array<SimpleAttributeOperand>{std::move(clause)};
      filters.push_back(std::move(filter));
    }
    return {[addressSpace = addressSpace, filters = std::move(filters), answers = answers]() mutable
      {
        event_type_model::resolve_select_clause_models_async(std::move(addressSpace),
          {},
          std::move(filters),
          [answers](std::vector<event_type_model::SelectClauseModelsResult> result)
          {
            ++answers->completions;
            answers->models = std::move(result);
          });
      },
      {}};
  }

  // No assertions, logging or evidence processing inside this interval. The one-shot allocator disarms
  // itself before throwing; the normal path and exception path are disarmed before returning as well.
  std::exception_ptr deliver(ContinuationDelivery delivery)
  {
    std::exception_ptr escaped;
    try
    {
      delivery.answer();
      drain();
    }
    catch (...)
    {
      escaped = std::current_exception();
    }
    test::allocation::disarm();
    return escaped;
  }

  std::exception_ptr deliver_bounded(ContinuationDelivery delivery, std::size_t& dispatched)
  {
    std::exception_ptr escaped;
    try
    {
      delivery.answer();
      dispatched = drain_bounded();
    }
    catch (...)
    {
      escaped = std::current_exception();
    }
    test::allocation::disarm();
    return escaped;
  }

  void finish()
  {
    for (std::size_t round = 0; round < 32; ++round)
    {
      drain();
      auto delivery = nameSpace->take_next();
      if (!delivery)
        return;
      duplicates.push_back(delivery->duplicate);
      delivery->answer();
    }
    throw std::runtime_error{"The allocation fixture did not reach a terminal result"};
  }

  Scenario scenario;
  boost::asio::io_context context;
  AddressSpace addressSpace;
  std::shared_ptr<FakeParkedNamespace> nameSpace;
  std::shared_ptr<Answers> answers;
  StatusCode sentinel;
  StatusCode firstValueRefusal;
  std::vector<NodeId> subjects;
  NodeId continuing;
  NodeId refused;
  NodeId terminal;
  std::vector<NodeAccessor> starts;
  std::vector<std::function<void()>> duplicates;

private:
  static std::shared_ptr<FakeScriptedNode> make_node(
    const NodeId& id, NodeClass nodeClass, std::string_view browseName, bool deleted = false)
  {
    auto node = std::make_shared<FakeScriptedNode>(deleted);
    node->answer_attribute(AttributeId::NodeId, Variant{id});
    node->answer_attribute(AttributeId::NodeClass, Variant{static_cast<int32_t>(nodeClass)});
    node->answer_attribute(AttributeId::BrowseName, Variant{QualifiedName{0, String{browseName}}});
    node->answer_attribute(
      AttributeId::DisplayName, Variant{LocalizedText{LocaleId{"en"}, String{browseName}}});
    return node;
  }
};

bool continuation_allocation(Scenario scenario, const test::allocation::Evidence& evidence)
{
  // Header-based routing/result assembly stays in the inventory and cannot be selected by treating a
  // continuation farther up its stack as the allocation's nearest SDK boundary.
  if (!evidence.nearestSdkFrame.file.ends_with(".cpp"))
  {
    return false;
  }
  const std::array<std::string_view, 3> files{
    "ua_allow_nulls_batch.cpp", "ua_eu_range_resolver.cpp", "ua_subtype_facts.cpp"};
  if (!evidence.nearestSdkFrame.file.ends_with(files[static_cast<std::size_t>(scenario.caller)]))
    return false;
  // namespace_calls and Walking share a source file: the function, not that file alone, distinguishes them.
  return scenario.caller != Caller::Walking ||
         evidence.nearestSdkFrame.function.find("walk_level(") != std::string::npos ||
         evidence.nearestSdkFrame.function.find("next_level(") != std::string::npos;
}

bool staging_allocation(Scenario scenario, const test::allocation::Evidence& evidence)
{
  if (!continuation_allocation(scenario, evidence))
    return false;
  const auto& statement = evidence.nearestSdkFrame.statement;
  // These source expressions select a fault stimulus, never the expected outcomes. Selection is recalibrated
  // for the running binary; it does not depend on a production line number, allocation count or fixed PC.
  std::vector<std::string_view> references;
  std::vector<std::string_view> lookup;
  if (scenario.caller == Caller::Walking)
  {
    references = {"const auto target", "climbing.", "supertypes."};
    lookup = {"walking->currentId[chain] = supertypes[k]", "active.push_back", "reads.reserve"};
  }
  else
  {
    references = {"candidateOwner.",
      "candidateSlot.",
      "candidates.",
      "distinct.",
      "slotOf.try_emplace",
      "const NodeId target"};
    lookup = {"std::vector<bool> decided",
      "unresolved(count",
      "unresolved(resolving",
      "property(count",
      "property(resolving",
      "owners.reserve",
      "properties.reserve",
      "propertyIds[k] =",
      "id.node_id() = property.get_node_id()",
      "make_shared<Reading>"};
  }
  auto selected = references;
  if (scenario.stage == Stage::Lookup)
  {
    selected = lookup;
  }
  return std::ranges::any_of(
    selected, [&statement](std::string_view token) { return statement.find(token) != std::string::npos; });
}

void expect_exact(const StatusCode& actual, const StatusCode& expected)
{
  EXPECT_EQ(actual.value(), expected.value());
  EXPECT_EQ(actual.shared_detail(), expected.shared_detail());
}

void expect_memory_failure(const StatusCode& status)
{
  EXPECT_EQ(status.value(), StatusCode{Status::BadOutOfMemory}.value());
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->code, "BadAlloc");
}

void expect_uncertain_references_refusal(const StatusCode& status, const StatusCode& sentinel)
{
  EXPECT_EQ(status.value(), StatusCode{Status::BadInternalError}.value());
  ASSERT_NE(status.shared_detail(), nullptr);
  EXPECT_EQ(status.shared_detail()->code, "ReferencesAnswerUncertain");
  EXPECT_EQ(status.shared_detail()->innerStatus, sentinel.value());
  EXPECT_EQ(status.shared_detail()->cause, sentinel.shared_detail());
}

// The refusal of an Uncertain Value read is built by the server's shared refusal builder, so the nearest SDK
// frame of its allocations is that builder in ua_status_routing.h, not read_properties. The Value delivery of
// an AllowNulls/Value/Uncertain scenario builds no other refusal, so the builder's frame identifies this one.
bool uncertain_value_refusal_allocation(const test::allocation::Evidence& evidence)
{
  const auto& frame = evidence.nearestSdkFrame;
  return frame.file.ends_with("ua_status_routing.h") &&
         frame.function.find("uncertain_answer_refused(") != std::string::npos;
}

bool value_interpretation_allocation(Scenario scenario, const test::allocation::Evidence& evidence)
{
  if (scenario.stage != Stage::Value || scenario.caller != Caller::AllowNulls)
    return false;
  if (scenario.uncertainValue)
    return uncertain_value_refusal_allocation(evidence);
  if (!continuation_allocation(scenario, evidence))
    return false;
  if (evidence.nearestSdkFrame.function.find("read_properties(") == std::string::npos)
    return false;
  constexpr std::string_view code{"AllowNullsTypeMismatch"};
  if (evidence.nearestSdkFrame.statement.find(code) != std::string::npos)
    return true;
  // The nearest allocating builder call can place its first argument on the next physical line.
  // Inspect only that argument at this same call site; context construction and ancestors do not qualify.
  constexpr std::string_view builder{"ErrorDetail::build("};
  const auto call = evidence.nearestSdkFrame.statement.find(builder);
  if (call == std::string::npos ||
      evidence.nearestSdkFrame.statement.find_first_not_of(" \t", call + builder.size()) != std::string::npos)
    return false;
  std::ifstream source{evidence.nearestSdkFrame.file};
  if (!source)
    throw std::runtime_error{"The nearest refusal-builder source is unavailable"};
  std::string argument;
  for (std::size_t line = 0; line <= evidence.nearestSdkFrame.line; ++line)
  {
    if (!std::getline(source, argument))
      throw std::runtime_error{"The nearest refusal-builder argument source is unavailable"};
  }
  const auto first = argument.find_first_not_of(" \t");
  return first != std::string::npos &&
         std::string_view{argument}.substr(first).starts_with('"' + std::string{code} + '"');
}

void expect_value_interpretation_results(const AllocationRun& run, bool fault)
{
  ASSERT_EQ(run.answers->completions, 1U);
  ASSERT_EQ(run.answers->allowNulls.size(), 4U);
  const auto& outcomes = run.answers->allowNulls;
  if (fault)
  {
    expect_memory_failure(outcomes[0].status);
  }
  else if (run.scenario.uncertainValue)
  {
    EXPECT_EQ(outcomes[0].status.value(), StatusCode{Status::BadInternalError}.value());
    ASSERT_NE(outcomes[0].status.shared_detail(), nullptr);
    EXPECT_EQ(outcomes[0].status.shared_detail()->code, "ReadAnswerUncertain");
    EXPECT_EQ(outcomes[0].status.shared_detail()->innerStatus, run.firstValueRefusal.value());
    EXPECT_EQ(outcomes[0].status.shared_detail()->cause, run.firstValueRefusal.shared_detail());
  }
  else
  {
    EXPECT_EQ(outcomes[0].status.value(), StatusCode{Status::BadTypeMismatch}.value());
    ASSERT_NE(outcomes[0].status.shared_detail(), nullptr);
    EXPECT_EQ(outcomes[0].status.shared_detail()->code, "AllowNullsTypeMismatch");
  }
  EXPECT_FALSE(outcomes[0].allowed.has_value());
  expect_exact(outcomes[1].status, run.sentinel);
  EXPECT_FALSE(outcomes[1].allowed.has_value());
  expect_exact(outcomes[2].status, StatusCode{});
  EXPECT_EQ(outcomes[2].allowed, std::optional<bool>{false});
  expect_exact(outcomes[3].status, StatusCode{});
  EXPECT_FALSE(outcomes[3].allowed.has_value());
}

bool reference_query_allocation(const test::allocation::Evidence& evidence)
{
  // The query is still unissued here. Page/result assembly and executor dispatch are not query staging.
  if (!evidence.nearestSdkFrame.file.ends_with("ua_node_accessor_route.cpp"))
    return false;
  const auto& statement = evidence.nearestSdkFrame.statement;
  return statement.find("queries.reserve(") != std::string::npos ||
         statement.find("queries.push_back(") != std::string::npos;
}

bool reference_setup_allocation(std::string_view statement, const test::allocation::Evidence& evidence)
{
  return evidence.nearestSdkFrame.file.ends_with("ua_node_accessor_route.cpp") &&
         evidence.nearestSdkFrame.function.find("NodeAccessorRoute::read_references(") != std::string::npos &&
         evidence.nearestSdkFrame.statement.find(statement) != std::string::npos;
}

bool event_walk_initialization_allocation(const test::allocation::Evidence& evidence)
{
  // Select the first vector storage allocation at this expression, before TypeWalk construction.
  return evidence.nearestSdkFrame.file.ends_with("ua_event_type_model.cpp") &&
         evidence.nearestSdkFrame.statement.find("mWalks.emplace_back(") != std::string::npos;
}

void expect_reference_query_failure(const StatusCode& status)
{
  EXPECT_EQ(status.value(), StatusCode{Status::BadInternalError}.value());
  auto detail = status.shared_detail();
  ASSERT_NE(detail, nullptr);
  while (detail && detail->code != "NamespaceCallThrew")
    detail = detail->cause;
  ASSERT_NE(detail, nullptr);
  EXPECT_EQ(detail->innerStatus, StatusCode{Status::BadOutOfMemory}.value());
  ASSERT_NE(detail->cause, nullptr);
  EXPECT_EQ(detail->cause->code, "BadAlloc");
}

void expect_results(const AllocationRun& run, bool fault)
{
  ASSERT_EQ(run.answers->completions, 1U);
  if (run.scenario.caller == Caller::AllowNulls)
  {
    ASSERT_EQ(run.answers->allowNulls.size(), 3U);
    const auto& answers = run.answers->allowNulls;
    if (fault)
    {
      expect_memory_failure(answers[0].status);
      EXPECT_FALSE(answers[0].allowed.has_value());
    }
    else
    {
      expect_exact(answers[0].status, StatusCode{});
      EXPECT_EQ(answers[0].allowed, std::optional<bool>{true});
    }
    expect_exact(answers[1].status, run.sentinel);
    EXPECT_FALSE(answers[1].allowed.has_value());
    expect_exact(answers[2].status, StatusCode{});
    EXPECT_FALSE(answers[2].allowed.has_value());
  }
  else if (run.scenario.caller == Caller::EuRange)
  {
    ASSERT_EQ(run.answers->euRanges.size(), 3U);
    const auto& answers = run.answers->euRanges;
    if (fault)
    {
      expect_memory_failure(answers[0].value.status_code());
      EXPECT_FALSE(answers[0].value.is_good());
    }
    else
    {
      ASSERT_TRUE(answers[0].value.is_good());
      EXPECT_EQ(answers[0].property, run.continuing);
      EXPECT_EQ(answers[0].value.value().value(), Variant{42.5});
    }
    expect_exact(answers[1].value.status_code(), run.sentinel);
    EXPECT_EQ(answers[1].property, NodeId{});
    // The deleted Variable has none: its References read is answered Bad_NodeIdUnknown, with that answer's
    // detail.
    EXPECT_EQ(answers[2].property, NodeId{});
    EXPECT_EQ(answers[2].value.status_code().value(), StatusCode{Status::BadNodeIdUnknown}.value());
    ASSERT_NE(answers[2].value.status_code().shared_detail(), nullptr);
    EXPECT_EQ(answers[2].value.status_code().shared_detail()->code, "NodeDeleted");
  }
  else
  {
    ASSERT_EQ(run.answers->walks.size(), 3U);
    const auto& answers = run.answers->walks;
    if (fault)
    {
      EXPECT_EQ(answers[0].how, SupertypeWalkEnd::How::Failed);
      expect_memory_failure(answers[0].failure);
    }
    else
    {
      EXPECT_EQ(answers[0].how, SupertypeWalkEnd::How::Decided);
      EXPECT_EQ(answers[0].value, 11);
      expect_exact(answers[0].failure, StatusCode{});
    }
    EXPECT_EQ(answers[1].how, SupertypeWalkEnd::How::Failed);
    expect_exact(answers[1].failure, run.sentinel);
    EXPECT_EQ(answers[2].how, SupertypeWalkEnd::How::Decided);
    EXPECT_EQ(answers[2].value, 73);
    expect_exact(answers[2].failure, StatusCode{});
  }
}

void expect_duplicates_do_nothing(AllocationRun& run)
{
  const auto calls = run.nameSpace->calls().size();
  for (const auto& duplicate : run.duplicates)
  {
    EXPECT_NO_THROW(duplicate());
    run.drain();
    EXPECT_EQ(run.answers->completions, 1U);
    EXPECT_EQ(run.nameSpace->calls().size(), calls);
  }
}

bool numeric_setup_allocation(const test::allocation::Evidence& evidence)
{
  return evidence.nearestSdkFrame.file.ends_with("ua_numeric_data_type_facts.cpp") &&
         evidence.nearestSdkFrame.function.starts_with("ua::server::numeric_data_type_facts(") &&
         evidence.nearestSdkFrame.statement.find("nonNumeric.assign(") != std::string::npos;
}

bool numeric_staging_allocation(const test::allocation::Evidence& evidence)
{
  return evidence.nearestSdkFrame.file.ends_with("ua_numeric_data_type_facts.cpp") &&
         evidence.nearestSdkFrame.function.starts_with("ua::server::numeric_data_type_facts(") &&
         evidence.nearestSdkFrame.statement.find("asked.push_back(") != std::string::npos;
}

// An allocation get_super_type_async makes in its own body, before it invokes the References reader. Its
// completions are lambdas named after it, which run only after the reader answers, so they are not setup.
bool supertype_setup_allocation(const test::allocation::Evidence& evidence)
{
  const auto& frame = evidence.nearestSdkFrame;
  return frame.file.ends_with("ua_node_utilities.cpp") &&
         frame.function.starts_with("ua::node_utils::get_super_type_async(") &&
         frame.function.find("{lambda") == std::string::npos;
}

bool nested_diagnostic_allocation(const test::allocation::Evidence& evidence)
{
  const auto& frame = evidence.nearestSdkFrame;
  if (!frame.file.ends_with("ua_node_utilities.cpp"))
    return false;
  if (frame.function.find("IsRefOfTypeOperation::run(") == std::string::npos)
    return false;
  // A multiline call can be attributed to its last argument. Only the source expression containing
  // this nearest SDK frame qualifies; a diagnostic in an ancestor frame never selects an allocation.
  std::ifstream source{frame.file};
  if (!source)
    throw std::runtime_error{"The nested diagnostic allocation source is unavailable"};
  std::optional<std::size_t> callLine;
  std::string statement;
  for (std::size_t line = 1; line <= frame.line; ++line)
  {
    if (!std::getline(source, statement))
      throw std::runtime_error{"The nested diagnostic allocation source line is unavailable"};
    if (statement.find("make_error_detail(\"DanglingHasSubtype\"") != std::string::npos)
      callLine = line;
    if (line == frame.line)
      return callLine.has_value() && line - *callLine <= 8;
    if (callLine && statement.find(';') != std::string::npos)
      callLine.reset();
  }
  return false;
}

// The return addresses of @p evidence's allocation stack, from the allocation up to and including its nearest
// SDK frame.
std::vector<std::uintptr_t> stack_prefix(const test::allocation::Evidence& evidence)
{
  const auto end = std::find(evidence.allocation.addresses.begin(),
    evidence.allocation.addresses.begin() + evidence.allocation.depth,
    evidence.nearestSdkFrame.address);
  return std::vector<std::uintptr_t>(evidence.allocation.addresses.begin(), end + 1);
}

// Expects the injected allocation @p observed to be the calibrated allocation @p calibrated: the same nearest
// SDK frame (address, file, function, line and statement), the same copy wrappers, and the same stack up to
// that frame. Equal addresses imply equal symbolization; each field is still compared so that a failure names
// what differs.
void expect_same_location(
  const test::allocation::Evidence& observed, const test::allocation::Evidence& calibrated)
{
  ASSERT_EQ(observed.nearestSdkFrame.address, calibrated.nearestSdkFrame.address);
  ASSERT_EQ(observed.nearestSdkFrame.file, calibrated.nearestSdkFrame.file);
  ASSERT_EQ(observed.nearestSdkFrame.function, calibrated.nearestSdkFrame.function);
  ASSERT_EQ(observed.nearestSdkFrame.line, calibrated.nearestSdkFrame.line);
  ASSERT_EQ(observed.nearestSdkFrame.statement, calibrated.nearestSdkFrame.statement);
  ASSERT_EQ(observed.nearestSdkFrame.sourceLocation, calibrated.nearestSdkFrame.sourceLocation);
  ASSERT_EQ(observed.copyWrappers.size(), calibrated.copyWrappers.size());
  for (std::size_t wrapper = 0; wrapper < calibrated.copyWrappers.size(); ++wrapper)
  {
    ASSERT_EQ(observed.copyWrappers[wrapper].address, calibrated.copyWrappers[wrapper].address);
    ASSERT_EQ(observed.copyWrappers[wrapper].file, calibrated.copyWrappers[wrapper].file);
    ASSERT_EQ(observed.copyWrappers[wrapper].function, calibrated.copyWrappers[wrapper].function);
    ASSERT_EQ(observed.copyWrappers[wrapper].line, calibrated.copyWrappers[wrapper].line);
    ASSERT_EQ(observed.copyWrappers[wrapper].statement, calibrated.copyWrappers[wrapper].statement);
    ASSERT_EQ(observed.copyWrappers[wrapper].sourceLocation, calibrated.copyWrappers[wrapper].sourceLocation);
  }
  ASSERT_EQ(observed.inlineFrames.size(), calibrated.inlineFrames.size());
  for (std::size_t index = 0; index < calibrated.inlineFrames.size(); ++index)
  {
    ASSERT_EQ(observed.inlineFrames[index].address, calibrated.inlineFrames[index].address);
    ASSERT_EQ(observed.inlineFrames[index].file, calibrated.inlineFrames[index].file);
    ASSERT_EQ(observed.inlineFrames[index].function, calibrated.inlineFrames[index].function);
    ASSERT_EQ(observed.inlineFrames[index].line, calibrated.inlineFrames[index].line);
    ASSERT_EQ(observed.inlineFrames[index].statement, calibrated.inlineFrames[index].statement);
    ASSERT_EQ(observed.inlineFrames[index].sourceLocation, calibrated.inlineFrames[index].sourceLocation);
  }
  ASSERT_EQ(stack_prefix(observed), stack_prefix(calibrated))
    << "the allocation stacks differ below the nearest SDK frame";
}

// As expect_same_location, and the allocations are of the same size.
void expect_nested_allocation_site(
  const test::allocation::Evidence& observed, const test::allocation::Evidence& calibrated)
{
  ASSERT_NO_FATAL_FAILURE(expect_same_location(observed, calibrated));
  ASSERT_EQ(observed.allocation.bytes, calibrated.allocation.bytes);
}

void event_walk_initialization_child()
{
  AllocationRun control{{Caller::AllowNulls, Stage::References}};
  const auto controlTypes = control.event_nodes(2).first;
  ASSERT_EQ(controlTypes.size(), 2U);
  ASSERT_NE(controlTypes[0], controlTypes[1]);
  auto permitted = control.event_models_delivery(controlTypes);
  ASSERT_TRUE(control.nameSpace->calls().empty());
  test::allocation::record();
  const auto controlEscape = control.deliver(std::move(permitted));
  ASSERT_FALSE(test::allocation::armed());
  ASSERT_FALSE(controlEscape);
  ASSERT_FALSE(test::allocation::overflowed());
  ASSERT_EQ(test::allocation::injections(), 0U);
  const auto allocations = test::allocation::recorded_sdk_allocations();
  const auto selected = std::ranges::find_if(allocations, event_walk_initialization_allocation);
  std::string locationDiagnostics;
  if (selected == allocations.end())
  {
    for (const auto& allocation : allocations)
      locationDiagnostics += test::allocation::describe(allocation) + '\n';
  }
  ASSERT_NE(selected, allocations.end()) << "No real first TypeWalk storage allocation was identified\n"
                                         << locationDiagnostics;
  const auto location = *selected;
  const auto calibration = test::allocation::describe(location);
  std::fprintf(stdout, "EventWalkInitialization allocation calibration:\n%s\n", calibration.c_str());
  std::fflush(stdout);
  std::fprintf(stderr, "EventWalkInitialization allocation calibration:\n%s\n", calibration.c_str());
  std::fflush(stderr);
  ASSERT_EQ(control.answers->completions, 0U);
  ASSERT_NO_THROW(control.finish());
  ASSERT_EQ(control.answers->completions, 1U);
  ASSERT_EQ(control.answers->models.size(), 2U);
  for (std::size_t filter = 0; filter < controlTypes.size(); ++filter)
  {
    const auto& answer = control.answers->models[filter];
    ASSERT_TRUE(answer.is_good());
    expect_exact(answer.status_code(), StatusCode{});
    ASSERT_EQ(answer.value().size(), 1U);
    const auto& clause = answer.value().front();
    expect_exact(clause.status, StatusCode{});
    ASSERT_TRUE(clause.declarationAccessor.has_value());
    EXPECT_EQ(clause.declarationAccessor->get_node_id(), controlTypes[filter]);
  }
  ASSERT_FALSE(control.nameSpace->calls().empty());
  ASSERT_FALSE(control.duplicates.empty());
  expect_duplicates_do_nothing(control);
  if (::testing::Test::HasFailure())
    return;
  std::fprintf(stderr, "EventWalkInitialization allocation permitted two-type control passed\n");
  std::fflush(stderr);

  AllocationRun fault{{Caller::AllowNulls, Stage::References}};
  const auto faultTypes = fault.event_nodes(2).first;
  ASSERT_EQ(faultTypes.size(), 2U);
  ASSERT_NE(faultTypes[0], faultTypes[1]);
  auto failing = fault.event_models_delivery(faultTypes);
  ASSERT_TRUE(fault.nameSpace->calls().empty());
  std::fprintf(stderr,
    "EventWalkInitialization allocation armed at calibrated nearest SDK PC 0x%llx:\n%s\n",
    static_cast<unsigned long long>(location.nearestSdkFrame.address),
    calibration.c_str());
  std::fflush(stderr);
  test::allocation::fail_at(location.nearestSdkFrame.address);
  const auto faultEscape = fault.deliver(std::move(failing));
  // A defective process may crash before returning. These injection/trace assertions discharge the
  // corrected return path; a crash report must not claim that they executed.
  ASSERT_FALSE(test::allocation::armed());
  ASSERT_FALSE(faultEscape);
  ASSERT_EQ(test::allocation::injections(), 1U);
  const auto observed = test::allocation::identify(test::allocation::failed_allocation());
  ASSERT_TRUE(observed.has_value());
  ASSERT_TRUE(event_walk_initialization_allocation(*observed));
  ASSERT_NO_FATAL_FAILURE(expect_same_location(*observed, location));
  const auto injection = test::allocation::describe(*observed);
  std::fprintf(stdout, "EventWalkInitialization allocation injected:\n%s\n", injection.c_str());
  std::fflush(stdout);
  std::fprintf(stderr, "EventWalkInitialization allocation injected:\n%s\n", injection.c_str());
  std::fflush(stderr);
  ASSERT_EQ(fault.answers->completions, 1U);
  ASSERT_EQ(fault.answers->models.size(), 2U);
  for (const auto& answer : fault.answers->models)
  {
    EXPECT_FALSE(answer.is_good());
    expect_memory_failure(answer.status_code());
  }
  EXPECT_EQ(fault.answers->models[0].status_code().shared_detail(),
    fault.answers->models[1].status_code().shared_detail());
  EXPECT_TRUE(fault.nameSpace->calls().empty());
  EXPECT_TRUE(fault.duplicates.empty());
  ASSERT_NO_THROW(fault.finish());
  EXPECT_EQ(fault.answers->completions, 1U);
  EXPECT_TRUE(fault.nameSpace->calls().empty());
}

// An allocation of ExternalGuardVariableLinkOperation's setup: its construction in start(), the operation's
// storage and what its constructor allocates, before launch() posts its body. The entry before start(), the
// body and launch() itself are not setup.
bool external_guard_setup_allocation(const test::allocation::Evidence& evidence)
{
  const auto& frame = evidence.nearestSdkFrame;
  std::string_view statement{frame.statement};
  const auto first = statement.find_first_not_of(" \t\r\n");
  if (first == std::string_view::npos)
  {
    statement = {};
  }
  else
  {
    statement = statement.substr(first, statement.find_last_not_of(" \t\r\n") - first + 1);
  }
  // The observed optimized record names this scope only 'start'. Require the same nearest
  // frame's exact relative source path and typed storage expression for that additional case.
  const bool typedStorage =
    frame.file.ends_with("/sdk/implementation/address_space/instantiation/ua_external_guard_linker.cpp") &&
    frame.function == "start" && statement == "launch(std::make_shared<ExternalGuardVariableLinkOperation>(";
  return frame.file.ends_with("ua_external_guard_linker.cpp") &&
         (frame.function.find("ExternalGuardVariableLinkOperation::start(") != std::string::npos ||
           frame.function.find("ExternalGuardVariableLinkOperation::ExternalGuardVariableLinkOperation(") !=
             std::string::npos ||
           typedStorage) &&
         frame.function.find("{lambda") == std::string::npos;
}

TEST(AllocationSetupSelector, AcceptsBareStartOnlyAtTheTypedOperationStorageExpression)
{
  test::allocation::Evidence evidence;
  evidence.nearestSdkFrame.file =
    "/work/src/sdk/implementation/address_space/instantiation/ua_external_guard_linker.cpp";
  evidence.nearestSdkFrame.function = "start";
  evidence.nearestSdkFrame.statement =
    "  \tlaunch(std::make_shared<ExternalGuardVariableLinkOperation>( \r\n";
  EXPECT_TRUE(external_guard_setup_allocation(evidence));
}

TEST(AllocationSetupSelector, RetainsTheExistingQualifiedSetupScopes)
{
  test::allocation::Evidence evidence;
  evidence.nearestSdkFrame.file =
    "/work/src/sdk/implementation/address_space/instantiation/ua_external_guard_linker.cpp";
  for (const std::string_view function : {"ua::ExternalGuardVariableLinkOperation::start(arguments)",
         "ua::ExternalGuardVariableLinkOperation::ExternalGuardVariableLinkOperation(arguments)"})
  {
    evidence.nearestSdkFrame.function = function;
    EXPECT_TRUE(external_guard_setup_allocation(evidence));
  }
}

TEST(AllocationSetupSelector, RejectsOtherNearestFilesFunctionsAndExpressions)
{
  test::allocation::Evidence evidence;
  auto& frame = evidence.nearestSdkFrame;
  frame.file = "/work/src/sdk/implementation/address_space/instantiation/ua_external_guard_linker.cpp";
  frame.function = "start";
  frame.statement = "launch(std::make_shared<ExternalGuardVariableLinkOperation>(";
  const auto valid = frame;
  for (const std::string_view file : {"/work/src/tests/ua_external_guard_linker.cpp",
         "/work/src/sdk/implementation/other/ua_external_guard_linker.cpp",
         "ua_external_guard_linker.cpp"})
  {
    frame = valid;
    frame.file = file;
    EXPECT_FALSE(external_guard_setup_allocation(evidence)) << file;
  }
  for (const std::string_view function : {"start_helper",
         "ExternalGuardVariableLinkOperation",
         "launch",
         "run",
         "start::{lambda()}",
         "ua::ExternalGuardVariableLinkOperation::start(arguments)::{lambda()}"})
  {
    frame = valid;
    frame.function = function;
    EXPECT_FALSE(external_guard_setup_allocation(evidence)) << function;
  }
  for (const std::string_view statement : {"launch(std::make_shared<OtherOperation>(",
         "launch(operation);",
         "other(launch(std::make_shared<ExternalGuardVariableLinkOperation>(",
         "launch(std::make_shared<ExternalGuardVariableLinkOperation>(trailing",
         ""})
  {
    frame = valid;
    frame.statement = statement;
    EXPECT_FALSE(external_guard_setup_allocation(evidence)) << statement;
  }
}

TEST(AllocationSetupSelector, DoesNotSelectAMatchingOuterFrame)
{
  test::allocation::Evidence evidence;
  test::allocation::Frame outer;
  outer.file = "/work/src/sdk/implementation/address_space/instantiation/ua_external_guard_linker.cpp";
  outer.function = "start";
  outer.statement = "launch(std::make_shared<ExternalGuardVariableLinkOperation>(";
  evidence.inlineFrames.push_back(outer);
  evidence.nearestSdkFrame = outer;
  evidence.nearestSdkFrame.function = "launch";
  EXPECT_FALSE(external_guard_setup_allocation(evidence));
  evidence.nearestSdkFrame.function = "run";
  EXPECT_FALSE(external_guard_setup_allocation(evidence));
  evidence.nearestSdkFrame.function = "start";
  evidence.nearestSdkFrame.statement = "launch(std::make_shared<OtherOperation>(";
  EXPECT_FALSE(external_guard_setup_allocation(evidence));
}

void external_guard_setup_child(bool nonapplicable)
{
  std::string_view mode;
  if (nonapplicable)
  {
    mode = "nonapplicable";
  }
  else
  {
    mode = "empty";
  }
  SCOPED_TRACE(mode);
  AllocationRun control{{Caller::AllowNulls, Stage::References}};
  auto permitted = control.external_guard_delivery(nonapplicable);
  ASSERT_TRUE(control.nameSpace->calls().empty());
  std::size_t controlDispatched{0};
  test::allocation::record();
  const auto controlEscape = control.deliver_bounded(std::move(permitted), controlDispatched);
  ASSERT_FALSE(test::allocation::armed());
  ASSERT_FALSE(controlEscape);
  ASSERT_FALSE(test::allocation::overflowed());
  ASSERT_EQ(test::allocation::injections(), 0U);
  // Disarmed debug-symbol processing gets a separate bound; initiation and executor execution
  // retain the 45-second bound before and immediately after this metadata-only call.
  ::alarm(180);
  const auto allocations = test::allocation::recorded_sdk_allocations();
  ::alarm(45);
  const auto selected = std::ranges::find_if(allocations, external_guard_setup_allocation);
  std::string locationDiagnostics;
  if (selected == allocations.end())
  {
    for (const auto& allocation : allocations)
      locationDiagnostics += test::allocation::describe(allocation) + '\n';
  }
  ASSERT_NE(selected, allocations.end())
    << "ExternalGuardVariableLinkOperation's setup made no allocation before posting its body\n"
    << locationDiagnostics;
  const auto location = *selected;
  const auto calibration = test::allocation::describe(location);
  std::fprintf(stdout,
    "ExternalGuardSetup allocation %.*s calibration:\n%s\n",
    static_cast<int>(mode.size()),
    mode.data(),
    calibration.c_str());
  std::fflush(stdout);
  std::fprintf(stderr,
    "ExternalGuardSetup allocation %.*s calibration:\n%s\n",
    static_cast<int>(mode.size()),
    mode.data(),
    calibration.c_str());
  std::fflush(stderr);
  ASSERT_GT(controlDispatched, 0U);
  ASSERT_EQ(control.answers->completions, 1U);
  ASSERT_TRUE(control.answers->externalGuard.has_value());
  ASSERT_TRUE(control.answers->externalGuard->is_good());
  expect_exact(control.answers->externalGuard->status_code(), StatusCode{});
  ASSERT_TRUE(control.nameSpace->calls().empty());
  ASSERT_TRUE(control.duplicates.empty());
  for (std::size_t round = 0; round < 8; ++round)
  {
    std::size_t dispatched{0};
    ASSERT_NO_THROW(dispatched = control.drain_bounded());
    EXPECT_EQ(dispatched, 0U);
    EXPECT_EQ(control.answers->completions, 1U);
    EXPECT_TRUE(control.nameSpace->calls().empty());
  }
  if (::testing::Test::HasFailure())
    return;
  std::fprintf(stderr,
    "ExternalGuardSetup allocation %.*s permitted control passed\n",
    static_cast<int>(mode.size()),
    mode.data());
  std::fflush(stderr);

  AllocationRun fault{{Caller::AllowNulls, Stage::References}};
  auto failing = fault.external_guard_delivery(nonapplicable);
  ASSERT_TRUE(fault.nameSpace->calls().empty());
  std::size_t faultDispatched{0};
  std::fprintf(stderr,
    "ExternalGuardSetup allocation %.*s armed at calibrated nearest SDK PC 0x%llx:\n%s\n",
    static_cast<int>(mode.size()),
    mode.data(),
    static_cast<unsigned long long>(location.nearestSdkFrame.address),
    calibration.c_str());
  std::fflush(stderr);
  test::allocation::fail_at(location.nearestSdkFrame.address);
  const auto faultEscape = fault.deliver_bounded(std::move(failing), faultDispatched);
  // A defective process can terminate before returning. These assertions prove only the return
  // path on which they execute; a termination report must not claim post-injection evidence.
  ASSERT_FALSE(test::allocation::armed());
  ASSERT_FALSE(faultEscape);
  ASSERT_EQ(test::allocation::injections(), 1U);
  // Fault initiation and its fixed-bound drain have returned and interception is disarmed.
  // Only injected-trace symbolization gets the separate metadata budget.
  ::alarm(180);
  const auto observed = test::allocation::identify(test::allocation::failed_allocation());
  ::alarm(45);
  ASSERT_TRUE(observed.has_value());
  ASSERT_TRUE(external_guard_setup_allocation(*observed));
  expect_nested_allocation_site(*observed, location);
  const auto injection = test::allocation::describe(*observed);
  std::fprintf(stdout,
    "ExternalGuardSetup allocation %.*s injected:\n%s\n",
    static_cast<int>(mode.size()),
    mode.data(),
    injection.c_str());
  std::fflush(stdout);
  std::fprintf(stderr,
    "ExternalGuardSetup allocation %.*s injected:\n%s\n",
    static_cast<int>(mode.size()),
    mode.data(),
    injection.c_str());
  std::fflush(stderr);
  ASSERT_EQ(faultDispatched, 0U);
  ASSERT_EQ(fault.answers->completions, 1U);
  ASSERT_TRUE(fault.answers->externalGuard.has_value());
  EXPECT_FALSE(fault.answers->externalGuard->is_good());
  expect_memory_failure(fault.answers->externalGuard->status_code());
  EXPECT_TRUE(fault.nameSpace->calls().empty());
  EXPECT_TRUE(fault.duplicates.empty());
  for (std::size_t round = 0; round < 8; ++round)
  {
    std::size_t dispatched{0};
    ASSERT_NO_THROW(dispatched = fault.drain_bounded());
    EXPECT_EQ(dispatched, 0U);
    EXPECT_EQ(fault.answers->completions, 1U);
    EXPECT_TRUE(fault.nameSpace->calls().empty());
  }
}

}  // namespace

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-CONTINUATION-ALLOCATION-PRESERVES-RECEIVED-ANSWERS, scope=function)
TEST(NamespaceCallerAllocation, ContinuationAllocationPreservesReceivedAnswers)
{
  for (const Caller caller : {Caller::AllowNulls, Caller::EuRange, Caller::Walking})
  {
    for (const Stage stage : {Stage::References, Stage::Lookup})
    {
      const Scenario scenario{caller, stage};
      SCOPED_TRACE(name(scenario));
      AllocationRun control{scenario};
      ASSERT_NO_THROW(control.start());
      ASSERT_EQ(control.answers->completions, 0U);
      auto permitted = control.nameSpace->take(stage);
      control.duplicates.push_back(permitted.duplicate);
      test::allocation::record();
      const auto controlEscape = control.deliver(std::move(permitted));
      ASSERT_FALSE(test::allocation::armed());
      ASSERT_FALSE(controlEscape);
      ASSERT_FALSE(test::allocation::overflowed()) << "The fixed-capacity allocation evidence overflowed";
      const auto allocations = test::allocation::recorded_sdk_allocations();
      const auto selected = std::ranges::find_if(
        allocations, [scenario](const auto& allocation) { return staging_allocation(scenario, allocation); });
      ASSERT_NO_THROW(control.finish());
      expect_results(control, false);
      expect_duplicates_do_nothing(control);
      if (selected == allocations.end())
      {
        // A future actually allocation-free continuation needs no artificial allocation. Unknown staging
        // allocations are a coverage failure; missing SDK symbols are an infrastructure failure, not a skip.
        ASSERT_FALSE(allocations.empty()) << "No SDK symbol/source evidence was obtained";
        const auto unclassified = std::ranges::find_if(allocations,
          [scenario](const auto& allocation) { return continuation_allocation(scenario, allocation); });
        ASSERT_EQ(unclassified, allocations.end())
          << "An allocation in this continuation lacks staging proof";
        RecordProperty(name(scenario) + " allocation-free",
          "No allocation has this continuation as its nearest SDK staging frame; complete control and "
          "duplicate checks passed");
        continue;
      }
      const auto location = *selected;
      RecordProperty(name(scenario) + " allocation", test::allocation::describe(location));

      AllocationRun fault{scenario};
      ASSERT_NO_THROW(fault.start());
      ASSERT_EQ(fault.answers->completions, 0U);
      auto failing = fault.nameSpace->take(stage);
      fault.duplicates.push_back(failing.duplicate);
      test::allocation::fail_at(location.nearestSdkFrame.address);
      const auto faultEscape = fault.deliver(std::move(failing));
      ASSERT_FALSE(test::allocation::armed());
      ASSERT_FALSE(faultEscape);
      ASSERT_EQ(test::allocation::injections(), 1U) << test::allocation::describe(location);
      const auto observed = test::allocation::identify(test::allocation::failed_allocation());
      ASSERT_TRUE(observed.has_value());
      ASSERT_TRUE(staging_allocation(scenario, *observed));
      ASSERT_NO_FATAL_FAILURE(expect_same_location(*observed, location))
        << "The injected allocation is not the calibrated staging allocation";
      RecordProperty(name(scenario) + " injected allocation", test::allocation::describe(*observed));
      ASSERT_NO_THROW(fault.finish());
      expect_results(fault, true);
      expect_duplicates_do_nothing(fault);
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-REFERENCE-QUERY-ALLOCATION-RELEASES-UNCONSUMED-TOKENS, scope=function)
TEST(NamespaceCallerAllocation, ReferenceQueryAllocationReleasesUnconsumedTokens)
{
  AllocationRun control{{Caller::AllowNulls, Stage::References}};
  const auto [controlTypes, controlDeclaration] = control.event_nodes();
  ASSERT_EQ(controlTypes.size(), 1U);
  const auto controlType = controlTypes.front();
  ASSERT_NO_THROW(control.start_event(controlType));
  ASSERT_EQ(control.answers->completions, 0U);
  const auto initialControl = control.nameSpace->calls(test::BatchRecordingNamespace::Member::ReadReferences);
  ASSERT_EQ(initialControl.size(), 1U);
  ASSERT_EQ(initialControl[0].nodeIds, (std::vector<NodeId>{controlType}));
  ASSERT_EQ(initialControl[0].referenceQueries.size(), 1U);
  ASSERT_TRUE(initialControl[0].referenceQueries[0].resumeToken.empty());
  const auto controlToken = initialControl[0].referenceQueries[0].answeredToken;
  ASSERT_FALSE(controlToken.empty());
  ASSERT_EQ(control.nameSpace->count(test::BatchRecordingNamespace::Member::ReleaseResumeToken), 0U);
  auto permitted = control.nameSpace->take(Stage::References);
  control.duplicates.push_back(permitted.duplicate);
  test::allocation::record();
  const auto controlEscape = control.deliver(std::move(permitted));
  ASSERT_FALSE(test::allocation::armed());
  ASSERT_FALSE(controlEscape);
  ASSERT_FALSE(test::allocation::overflowed());
  ASSERT_EQ(test::allocation::injections(), 0U);
  const auto allocations = test::allocation::recorded_sdk_allocations();
  const auto selected = std::ranges::find_if(allocations, reference_query_allocation);
  std::string locationDiagnostics;
  if (selected == allocations.end())
  {
    for (const auto& allocation : allocations)
      locationDiagnostics += test::allocation::describe(allocation) + '\n';
    RecordProperty("References query nearest SDK allocation inventory", locationDiagnostics);
  }
  ASSERT_NE(selected, allocations.end()) << "No real continuation query-staging allocation was identified\n"
                                         << locationDiagnostics;
  const auto location = *selected;
  RecordProperty("References query allocation", test::allocation::describe(location));
  ASSERT_EQ(control.answers->completions, 0U);
  const auto resumedControl = control.nameSpace->calls(test::BatchRecordingNamespace::Member::ReadReferences);
  ASSERT_EQ(resumedControl.size(), 2U);
  ASSERT_EQ(resumedControl[1].referenceQueries.size(), 1U);
  EXPECT_EQ(resumedControl[1].referenceQueries[0].nodeId, controlType);
  EXPECT_EQ(resumedControl[1].referenceQueries[0].resumeToken, controlToken);
  ASSERT_NO_THROW(control.finish());
  ASSERT_EQ(control.answers->completions, 1U);
  ASSERT_TRUE(control.answers->declarations.has_value());
  ASSERT_TRUE(control.answers->declarations->is_good());
  expect_exact(control.answers->declarations->status_code(), StatusCode{});
  const auto& declarations = control.answers->declarations->value();
  ASSERT_EQ(declarations.size(), 1U);
  EXPECT_EQ(declarations[0].nodeId, controlDeclaration);
  EXPECT_EQ(declarations[0].browsePath, (std::vector<QualifiedName>{QualifiedName{0, "Entry"}}));
  ASSERT_TRUE(declarations[0].accessor.has_value());
  EXPECT_EQ(declarations[0].accessor->get_node_id(), controlDeclaration);
  EXPECT_EQ(declarations[0].nodeClass, NodeClass::Object);
  EXPECT_FALSE(declarations[0].mandatory);
  EXPECT_TRUE(declarations[0].dataType.is_null());
  EXPECT_EQ(control.answers->tokenReleasesAtCompletion, std::optional<std::size_t>{0});
  EXPECT_EQ(control.nameSpace->count(test::BatchRecordingNamespace::Member::ReleaseResumeToken), 0U);
  std::size_t consumed = 0;
  for (const auto& call : control.nameSpace->calls(test::BatchRecordingNamespace::Member::ReadReferences))
  {
    for (const auto& query : call.referenceQueries)
      if (query.resumeToken == controlToken)
        ++consumed;
  }
  EXPECT_EQ(consumed, 1U);
  expect_duplicates_do_nothing(control);
  EXPECT_EQ(control.nameSpace->count(test::BatchRecordingNamespace::Member::ReleaseResumeToken), 0U);

  AllocationRun fault{{Caller::AllowNulls, Stage::References}};
  const auto faultTypes = fault.event_nodes().first;
  ASSERT_EQ(faultTypes.size(), 1U);
  const auto faultType = faultTypes.front();
  ASSERT_NO_THROW(fault.start_event(faultType));
  ASSERT_EQ(fault.answers->completions, 0U);
  const auto initialFault = fault.nameSpace->calls(test::BatchRecordingNamespace::Member::ReadReferences);
  ASSERT_EQ(initialFault.size(), 1U);
  ASSERT_EQ(initialFault[0].nodeIds, (std::vector<NodeId>{faultType}));
  ASSERT_EQ(initialFault[0].referenceQueries.size(), 1U);
  ASSERT_TRUE(initialFault[0].referenceQueries[0].resumeToken.empty());
  const auto faultToken = initialFault[0].referenceQueries[0].answeredToken;
  ASSERT_FALSE(faultToken.empty());
  ASSERT_EQ(fault.nameSpace->count(test::BatchRecordingNamespace::Member::ReleaseResumeToken), 0U);
  auto failing = fault.nameSpace->take(Stage::References);
  fault.duplicates.push_back(failing.duplicate);
  test::allocation::fail_at(location.nearestSdkFrame.address);
  const auto faultEscape = fault.deliver(std::move(failing));
  ASSERT_FALSE(test::allocation::armed());
  ASSERT_FALSE(faultEscape);
  ASSERT_EQ(test::allocation::injections(), 1U);
  const auto observed = test::allocation::identify(test::allocation::failed_allocation());
  ASSERT_TRUE(observed.has_value());
  ASSERT_TRUE(reference_query_allocation(*observed));
  ASSERT_NO_FATAL_FAILURE(expect_same_location(*observed, location));
  RecordProperty("References query injected allocation", test::allocation::describe(*observed));
  ASSERT_NO_THROW(fault.finish());
  ASSERT_EQ(fault.answers->completions, 1U);
  ASSERT_TRUE(fault.answers->declarations.has_value());
  expect_reference_query_failure(fault.answers->declarations->status_code());
  EXPECT_EQ(fault.nameSpace->count(test::BatchRecordingNamespace::Member::ReadReferences), 1U);
  EXPECT_EQ(fault.answers->tokenReleasesAtCompletion, std::optional<std::size_t>{1});
  const auto released = fault.nameSpace->calls(test::BatchRecordingNamespace::Member::ReleaseResumeToken);
  EXPECT_EQ(released.size(), 1U);
  if (released.size() == 1U)
    EXPECT_EQ(released[0].token, faultToken);
  ASSERT_FALSE(fault.duplicates.empty());
  expect_duplicates_do_nothing(fault);
  EXPECT_EQ(fault.nameSpace->count(test::BatchRecordingNamespace::Member::ReleaseResumeToken), 1U);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-EVENT-WALK-INITIALIZATION-ALLOCATION-ANSWERS-ONCE, scope=function)
TEST(NamespaceCallerAllocationDeathTest, EventWalkInitializationAllocationAnswersOnce)
{
  ASSERT_EXIT(
    {
      event_walk_initialization_child();
      if (::testing::Test::HasFailure())
      {
        const auto* testResult = ::testing::UnitTest::GetInstance()->current_test_info()->result();
        for (int partIndex = 0; partIndex < testResult->total_part_count(); ++partIndex)
        {
          const auto& partResult = testResult->GetTestPartResult(partIndex);
          if (partResult.failed())
          {
            const char* file = partResult.file_name();
            if (file == nullptr)
              file = "(unknown source)";
            std::fprintf(
              stderr, "stored assertion %s:%d\n%s\n", file, partResult.line_number(), partResult.message());
          }
        }
        std::fflush(stderr);
        std::_Exit(1);
      }
      std::_Exit(0);
    },
    ::testing::ExitedWithCode(0),
    "EventWalkInitialization allocation");
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-EXTERNAL-GUARD-SETUP-ALLOCATION-ANSWERS-ONCE, scope=function)
TEST(NamespaceCallerAllocationDeathTest, ExternalGuardSetupAllocationAnswersOnce)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  for (const bool nonapplicable : {false, true})
  {
    std::string_view mode;
    if (nonapplicable)
    {
      mode = "nonapplicable";
    }
    else
    {
      mode = "empty";
    }
    SCOPED_TRACE(mode);
    EXPECT_EXIT(
      {
        ::alarm(45);
        external_guard_setup_child(nonapplicable);
        if (::testing::Test::HasFailure())
        {
          const auto* testResult = ::testing::UnitTest::GetInstance()->current_test_info()->result();
          for (int partIndex = 0; partIndex < testResult->total_part_count(); ++partIndex)
          {
            const auto& partResult = testResult->GetTestPartResult(partIndex);
            if (partResult.failed())
            {
              const char* file = partResult.file_name();
              if (file == nullptr)
                file = "(unknown source)";
              std::fprintf(
                stderr, "stored assertion %s:%d\n%s\n", file, partResult.line_number(), partResult.message());
            }
          }
          std::fflush(stderr);
          std::_Exit(1);
        }
        std::_Exit(0);
      },
      ::testing::ExitedWithCode(0),
      "ExternalGuardSetup allocation");
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-23-NUMERIC-SETUP-ALLOCATION-COMPLETES-ONCE, scope=function)
TEST(NamespaceCallerAllocation, NumericSetupAllocationStillCompletesOnce)
{
  for (const bool throwing : {false, true})
  {
    std::string mode{"nonthrowing"};
    std::size_t expectedWarnings{0};
    if (throwing)
    {
      mode = "throwing";
      expectedWarnings = 1;
    }
    SCOPED_TRACE(mode);
    test::TestLogSink controlLog;
    AllocationRun control{{Caller::Walking, Stage::Lookup}};
    control.addressSpace.set_logger(controlLog.logger());
    auto types = control.numeric_types();
    const auto count = types.size();
    ASSERT_GT(count, 0U);
    ContinuationDelivery permitted;
    permitted.answer = [&control, types = std::move(types), throwing]() mutable
    {
      control.start_numeric(std::move(types), throwing);
    };
    test::allocation::record();
    const auto controlEscape = control.deliver(std::move(permitted));
    ASSERT_FALSE(test::allocation::armed());
    ASSERT_FALSE(controlEscape);
    ASSERT_FALSE(test::allocation::overflowed());
    ASSERT_EQ(test::allocation::injections(), 0U);
    const auto allocations = test::allocation::recorded_sdk_allocations();
    const auto selected = std::ranges::find_if(allocations, numeric_setup_allocation);
    ASSERT_NE(selected, allocations.end())
      << "The initial numeric answer-vector allocation was not independently identified";
    const auto location = *selected;
    RecordProperty(mode + " numeric setup allocation", test::allocation::describe(location));
    ASSERT_NO_THROW(control.finish());
    EXPECT_EQ(control.answers->completions, 1U);
    EXPECT_EQ(
      control.answers->nonNumeric, (std::vector<bool>{false, true, false, false, false, true, false}));
    EXPECT_GT(control.nameSpace->count(test::BatchRecordingNamespace::Member::BatchedLookup), 0U);
    EXPECT_EQ(controlLog.count(LogLevel::Warning), expectedWarnings);
    expect_duplicates_do_nothing(control);
    EXPECT_EQ(controlLog.count(LogLevel::Warning), expectedWarnings);

    test::TestLogSink faultLog;
    AllocationRun fault{{Caller::Walking, Stage::Lookup}};
    fault.addressSpace.set_logger(faultLog.logger());
    auto faultTypes = fault.numeric_types();
    ASSERT_EQ(faultTypes.size(), count);
    ContinuationDelivery failing;
    failing.answer = [&fault, types = std::move(faultTypes), throwing]() mutable
    {
      fault.start_numeric(std::move(types), throwing);
    };
    test::allocation::fail_at(location.nearestSdkFrame.address);
    const auto faultEscape = fault.deliver(std::move(failing));
    ASSERT_FALSE(test::allocation::armed());
    ASSERT_FALSE(faultEscape);
    ASSERT_EQ(test::allocation::injections(), 1U);
    const auto observed = test::allocation::identify(test::allocation::failed_allocation());
    ASSERT_TRUE(observed.has_value());
    ASSERT_TRUE(numeric_setup_allocation(*observed));
    ASSERT_TRUE(observed->copyWrappers.empty());
    ASSERT_NO_FATAL_FAILURE(expect_same_location(*observed, location));
    RecordProperty(mode + " numeric setup injected allocation", test::allocation::describe(*observed));
    EXPECT_NO_THROW(fault.finish());
    EXPECT_EQ(fault.answers->completions, 1U);
    EXPECT_EQ(fault.answers->nonNumeric, std::vector<bool>(count, false));
    EXPECT_TRUE(fault.nameSpace->calls().empty()) << "Setup failure must not start namespace work";
    EXPECT_EQ(faultLog.count(LogLevel::Warning), expectedWarnings);
    fault.drain();
    EXPECT_EQ(fault.answers->completions, 1U);
    EXPECT_EQ(faultLog.count(LogLevel::Warning), expectedWarnings);
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-23-NUMERIC-STAGING-FAILURE-RETAINS-ESTABLISHED-FACTS, scope=function)
TEST(NamespaceCallerAllocation, NumericStagingFailureRetainsEstablishedFacts)
{
  for (const bool throwing : {false, true})
  {
    std::string mode{"nonthrowing"};
    std::size_t expectedWarnings{0};
    if (throwing)
    {
      mode = "throwing";
      expectedWarnings = 1;
    }
    SCOPED_TRACE(mode);
    test::TestLogSink controlLog;
    AllocationRun control{{Caller::Walking, Stage::Lookup}};
    control.addressSpace.set_logger(controlLog.logger());
    control.answers->throwNumericCompletion = throwing;
    const auto allTypes = control.numeric_types();
    std::vector<NodeId> types{NodeId{DataTypeId::String}, allTypes[5]};
    // The actual standard-library function receives a trivially copyable target containing only one raw
    // observation pointer. AllocationRun externally retains Answers until every delivery has completed.
    const auto controlCallback = [observation = control.answers.get()](std::vector<bool> facts)
    {
      ++observation->completions;
      observation->nonNumeric = std::move(facts);
      if (observation->throwNumericCompletion)
      {
        throw std::runtime_error{"Numeric staging caller completion refusal"};
      }
    };
    static_assert(std::is_trivially_copyable_v<decltype(controlCallback)>);
    std::function<void(std::vector<bool>)> controlComplete{controlCallback};
    ContinuationDelivery permitted;
    permitted.answer = [&control, types = std::move(types), complete = std::move(controlComplete)]() mutable
    {
      control.start_numeric(std::move(types), false, std::move(complete));
    };
    test::allocation::record();
    const auto controlEscape = control.deliver(std::move(permitted));
    ASSERT_FALSE(test::allocation::armed());
    ASSERT_FALSE(controlEscape);
    ASSERT_FALSE(test::allocation::overflowed());
    ASSERT_EQ(test::allocation::injections(), 0U);
    const auto allocations = test::allocation::recorded_sdk_allocations();
    const auto selected = std::ranges::find_if(allocations, numeric_staging_allocation);
    ASSERT_NE(selected, allocations.end())
      << "The unresolved lookup-staging allocation was not independently identified";
    const auto location = *selected;
    RecordProperty(mode + " numeric staging allocation", test::allocation::describe(location));
    ASSERT_NO_THROW(control.finish());
    EXPECT_EQ(control.answers->completions, 1U);
    EXPECT_EQ(control.answers->nonNumeric, (std::vector<bool>{true, true}));
    EXPECT_GT(control.nameSpace->count(test::BatchRecordingNamespace::Member::BatchedLookup), 0U);
    EXPECT_EQ(controlLog.count(LogLevel::Warning), expectedWarnings);
    expect_duplicates_do_nothing(control);
    EXPECT_EQ(controlLog.count(LogLevel::Warning), expectedWarnings);

    test::TestLogSink faultLog;
    AllocationRun fault{{Caller::Walking, Stage::Lookup}};
    fault.addressSpace.set_logger(faultLog.logger());
    fault.answers->throwNumericCompletion = throwing;
    const auto allFaultTypes = fault.numeric_types();
    std::vector<NodeId> faultTypes{NodeId{DataTypeId::String}, allFaultTypes[5]};
    const auto faultCallback = [observation = fault.answers.get()](std::vector<bool> facts)
    {
      ++observation->completions;
      observation->nonNumeric = std::move(facts);
      if (observation->throwNumericCompletion)
      {
        throw std::runtime_error{"Numeric staging caller completion refusal"};
      }
    };
    static_assert(std::is_trivially_copyable_v<decltype(faultCallback)>);
    std::function<void(std::vector<bool>)> faultComplete{faultCallback};
    ContinuationDelivery failing;
    failing.answer = [&fault, types = std::move(faultTypes), complete = std::move(faultComplete)]() mutable
    {
      fault.start_numeric(std::move(types), false, std::move(complete));
    };
    test::allocation::fail_at(location.nearestSdkFrame.address);
    const auto faultEscape = fault.deliver(std::move(failing));
    ASSERT_FALSE(test::allocation::armed());
    ASSERT_FALSE(faultEscape);
    ASSERT_EQ(test::allocation::injections(), 1U);
    const auto observed = test::allocation::identify(test::allocation::failed_allocation());
    ASSERT_TRUE(observed.has_value());
    ASSERT_TRUE(numeric_staging_allocation(*observed));
    ASSERT_TRUE(observed->copyWrappers.empty());
    ASSERT_NO_FATAL_FAILURE(expect_same_location(*observed, location));
    RecordProperty(mode + " numeric staging injected allocation", test::allocation::describe(*observed));
    EXPECT_NO_THROW(fault.finish());
    EXPECT_EQ(fault.answers->completions, 1U);
    EXPECT_EQ(fault.answers->nonNumeric, (std::vector<bool>{true, false}));
    EXPECT_TRUE(fault.nameSpace->calls().empty()) << "Staging failure must precede namespace work";
    EXPECT_EQ(faultLog.count(LogLevel::Warning), expectedWarnings);
    expect_duplicates_do_nothing(fault);
    fault.drain();
    EXPECT_EQ(fault.answers->completions, 1U);
    EXPECT_EQ(fault.answers->nonNumeric, (std::vector<bool>{true, false}));
    EXPECT_EQ(faultLog.count(LogLevel::Warning), expectedWarnings);
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-22-UNCERTAIN-REFERENCES-SURVIVES-SIBLING-ALLOCATION, scope=function)
TEST(NamespaceCallerAllocation, UncertainReferencesSurvivesSiblingAllocation)
{
  const Scenario scenario{Caller::AllowNulls, Stage::References};
  const Status uncertain{Status::UncertainNoCommunicationLastUsableValue};
  AllocationRun control{scenario, uncertain};
  ASSERT_TRUE(control.sentinel.is_uncertain());
  ASSERT_NE(control.sentinel.shared_detail(), nullptr);
  ASSERT_NO_THROW(control.start());
  ASSERT_EQ(control.answers->completions, 0U);
  auto permitted = control.nameSpace->take(Stage::References);
  control.duplicates.push_back(permitted.duplicate);
  test::allocation::record();
  const auto controlEscape = control.deliver(std::move(permitted));
  ASSERT_FALSE(test::allocation::armed());
  ASSERT_FALSE(controlEscape);
  ASSERT_FALSE(test::allocation::overflowed());
  ASSERT_EQ(test::allocation::injections(), 0U);
  const auto allocations = test::allocation::recorded_sdk_allocations();
  const auto selected = std::ranges::find_if(
    allocations, [scenario](const auto& allocation) { return staging_allocation(scenario, allocation); });
  ASSERT_NE(selected, allocations.end())
    << "The earlier successful item's candidate-staging allocation was not independently identified";
  const auto location = *selected;
  RecordProperty("Uncertain References control allocation", test::allocation::describe(location));
  ASSERT_NO_THROW(control.finish());
  ASSERT_EQ(control.answers->completions, 1U);
  ASSERT_EQ(control.answers->allowNulls.size(), 3U);
  expect_exact(control.answers->allowNulls[0].status, StatusCode{});
  EXPECT_EQ(control.answers->allowNulls[0].allowed, std::optional<bool>{true});
  expect_uncertain_references_refusal(control.answers->allowNulls[1].status, control.sentinel);
  EXPECT_FALSE(control.answers->allowNulls[1].allowed.has_value());
  expect_exact(control.answers->allowNulls[2].status, StatusCode{});
  EXPECT_FALSE(control.answers->allowNulls[2].allowed.has_value());
  expect_duplicates_do_nothing(control);

  AllocationRun fault{scenario, uncertain};
  ASSERT_TRUE(fault.sentinel.is_uncertain());
  ASSERT_NE(fault.sentinel.shared_detail(), nullptr);
  ASSERT_NO_THROW(fault.start());
  ASSERT_EQ(fault.answers->completions, 0U);
  auto failing = fault.nameSpace->take(Stage::References);
  fault.duplicates.push_back(failing.duplicate);
  test::allocation::fail_at(location.nearestSdkFrame.address);
  const auto faultEscape = fault.deliver(std::move(failing));
  ASSERT_FALSE(test::allocation::armed());
  ASSERT_FALSE(faultEscape);
  ASSERT_EQ(test::allocation::injections(), 1U);
  const auto observed = test::allocation::identify(test::allocation::failed_allocation());
  ASSERT_TRUE(observed.has_value());
  ASSERT_TRUE(staging_allocation(scenario, *observed));
  ASSERT_NO_FATAL_FAILURE(expect_same_location(*observed, location));
  RecordProperty("Uncertain References injected allocation", test::allocation::describe(*observed));
  ASSERT_NO_THROW(fault.finish());
  ASSERT_EQ(fault.answers->completions, 1U);
  ASSERT_EQ(fault.answers->allowNulls.size(), 3U);
  expect_memory_failure(fault.answers->allowNulls[0].status);
  EXPECT_FALSE(fault.answers->allowNulls[0].allowed.has_value());
  expect_uncertain_references_refusal(fault.answers->allowNulls[1].status, fault.sentinel);
  EXPECT_FALSE(fault.answers->allowNulls[1].allowed.has_value());
  expect_exact(fault.answers->allowNulls[2].status, StatusCode{});
  EXPECT_FALSE(fault.answers->allowNulls[2].allowed.has_value());
  expect_duplicates_do_nothing(fault);
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-ALLOW-NULLS-VALUE-INTERPRETATION-PRESERVES-RECEIVED-ANSWERS, scope=function)
TEST(NamespaceCallerAllocation, AllowNullsValueInterpretationPreservesReceivedFailures)
{
  for (const bool uncertain : {false, true})
  {
    for (const bool embedded : {false, true})
    {
      const Scenario scenario{Caller::AllowNulls, Stage::Value, uncertain, embedded};
      SCOPED_TRACE(name(scenario));
      Status laterStatus{Status::BadResourceUnavailable};
      if (embedded)
        laterStatus = Status::BadCommunicationError;
      AllocationRun control{scenario, laterStatus};
      ASSERT_NE(control.sentinel.shared_detail(), nullptr);
      if (uncertain)
      {
        ASSERT_EQ(control.firstValueRefusal.value(),
          StatusCode{Status::UncertainNoCommunicationLastUsableValue}.value());
        ASSERT_NE(control.firstValueRefusal.shared_detail(), nullptr);
        ASSERT_NE(control.firstValueRefusal.shared_detail(), control.sentinel.shared_detail());
      }
      ASSERT_NO_THROW(control.start());
      ASSERT_EQ(control.answers->completions, 0U);
      const auto controlReads = control.nameSpace->calls(test::BatchRecordingNamespace::Member::ReadValues);
      ASSERT_EQ(controlReads.size(), 1U);
      ASSERT_EQ(controlReads[0].nodeIds,
        (std::vector<NodeId>{control.continuing, control.refused, control.terminal}));
      const auto controlCalls = control.nameSpace->calls().size();
      auto permitted = control.nameSpace->take(Stage::Value);
      control.duplicates.push_back(permitted.duplicate);
      test::allocation::record();
      const auto controlEscape = control.deliver(std::move(permitted));
      ASSERT_FALSE(test::allocation::armed());
      ASSERT_FALSE(controlEscape);
      ASSERT_FALSE(test::allocation::overflowed());
      ASSERT_EQ(test::allocation::injections(), 0U);
      const auto allocations = test::allocation::recorded_sdk_allocations();
      const auto selected = std::ranges::find_if(allocations,
        [scenario](const auto& allocation) { return value_interpretation_allocation(scenario, allocation); });
      std::string locationDiagnostics;
      if (selected == allocations.end())
      {
        for (const auto& allocation : allocations)
        {
          locationDiagnostics += test::allocation::describe(allocation) + '\n';
        }
        RecordProperty(name(scenario) + " nearest SDK allocation inventory", locationDiagnostics);
      }
      ASSERT_NE(selected, allocations.end())
        << "No real allocation in the first Value's declared refusal construction was identified\n"
        << locationDiagnostics;
      const auto location = *selected;
      RecordProperty(name(scenario) + " allocation", test::allocation::describe(location));
      ASSERT_NO_THROW(control.finish());
      expect_value_interpretation_results(control, false);
      EXPECT_EQ(control.nameSpace->calls().size(), controlCalls);
      expect_duplicates_do_nothing(control);

      AllocationRun fault{scenario, laterStatus};
      ASSERT_NE(fault.sentinel.shared_detail(), nullptr);
      if (uncertain)
      {
        ASSERT_EQ(fault.firstValueRefusal.value(),
          StatusCode{Status::UncertainNoCommunicationLastUsableValue}.value());
        ASSERT_NE(fault.firstValueRefusal.shared_detail(), nullptr);
        ASSERT_NE(fault.firstValueRefusal.shared_detail(), fault.sentinel.shared_detail());
      }
      ASSERT_NO_THROW(fault.start());
      ASSERT_EQ(fault.answers->completions, 0U);
      const auto faultReads = fault.nameSpace->calls(test::BatchRecordingNamespace::Member::ReadValues);
      ASSERT_EQ(faultReads.size(), 1U);
      ASSERT_EQ(
        faultReads[0].nodeIds, (std::vector<NodeId>{fault.continuing, fault.refused, fault.terminal}));
      const auto faultCalls = fault.nameSpace->calls().size();
      auto failing = fault.nameSpace->take(Stage::Value);
      fault.duplicates.push_back(failing.duplicate);
      test::allocation::fail_at(location.nearestSdkFrame.address);
      const auto faultEscape = fault.deliver(std::move(failing));
      ASSERT_FALSE(test::allocation::armed());
      ASSERT_FALSE(faultEscape);
      ASSERT_EQ(test::allocation::injections(), 1U);
      const auto observed = test::allocation::identify(test::allocation::failed_allocation());
      ASSERT_TRUE(observed.has_value());
      ASSERT_TRUE(value_interpretation_allocation(scenario, *observed));
      ASSERT_NO_FATAL_FAILURE(expect_same_location(*observed, location));
      RecordProperty(name(scenario) + " injected allocation", test::allocation::describe(*observed));
      ASSERT_NO_THROW(fault.finish());
      expect_value_interpretation_results(fault, true);
      EXPECT_EQ(fault.nameSpace->calls().size(), faultCalls);
      expect_duplicates_do_nothing(fault);
    }
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-REFERENCE-SETUP-ALLOCATION-RETAINS-TOKEN-OWNERSHIP, scope=function)
TEST(NamespaceCallerAllocation, ReferenceSetupAllocationRetainsTokenOwnership)
{
  const std::array<std::string_view, 3> setupSites{
    "complete = std::make_shared<", "state = std::make_shared<State>", "state->owners.resize("};
  for (const auto site : setupSites)
  {
    SCOPED_TRACE(site);
    AllocationRun control{{Caller::AllowNulls, Stage::References}};
    const auto [controlTypes, controlDeclaration] = control.event_nodes();
    ASSERT_EQ(controlTypes.size(), 1U);
    const auto controlType = controlTypes.front();
    ASSERT_NO_THROW(control.start_event(controlType));
    ASSERT_EQ(control.answers->completions, 0U);
    const auto initialControl =
      control.nameSpace->calls(test::BatchRecordingNamespace::Member::ReadReferences);
    ASSERT_EQ(initialControl.size(), 1U);
    ASSERT_EQ(initialControl[0].nodeIds, (std::vector<NodeId>{controlType}));
    ASSERT_EQ(initialControl[0].referenceQueries.size(), 1U);
    ASSERT_TRUE(initialControl[0].referenceQueries[0].resumeToken.empty());
    const auto controlToken = initialControl[0].referenceQueries[0].answeredToken;
    ASSERT_FALSE(controlToken.empty());
    ASSERT_EQ(control.nameSpace->count(test::BatchRecordingNamespace::Member::ReleaseResumeToken), 0U);
    auto permitted = control.nameSpace->take(Stage::References);
    control.duplicates.push_back(permitted.duplicate);
    test::allocation::record();
    const auto controlEscape = control.deliver(std::move(permitted));
    ASSERT_FALSE(test::allocation::armed());
    ASSERT_FALSE(controlEscape);
    ASSERT_FALSE(test::allocation::overflowed());
    ASSERT_EQ(test::allocation::injections(), 0U);
    const auto allocations = test::allocation::recorded_sdk_allocations();
    const auto selected = std::ranges::find_if(
      allocations, [site](const auto& allocation) { return reference_setup_allocation(site, allocation); });
    std::string locationDiagnostics;
    if (selected == allocations.end())
    {
      for (const auto& allocation : allocations)
        locationDiagnostics += test::allocation::describe(allocation) + '\n';
      RecordProperty(std::string{site} + " nearest SDK allocation inventory", locationDiagnostics);
    }
    ASSERT_NE(selected, allocations.end()) << "No real References setup allocation was identified\n"
                                           << locationDiagnostics;
    const auto location = *selected;
    RecordProperty(std::string{site} + " allocation", test::allocation::describe(location));
    ASSERT_EQ(control.answers->completions, 0U);
    const auto resumedControl =
      control.nameSpace->calls(test::BatchRecordingNamespace::Member::ReadReferences);
    ASSERT_EQ(resumedControl.size(), 2U);
    ASSERT_EQ(resumedControl[1].referenceQueries.size(), 1U);
    EXPECT_EQ(resumedControl[1].referenceQueries[0].nodeId, controlType);
    EXPECT_EQ(resumedControl[1].referenceQueries[0].resumeToken, controlToken);
    ASSERT_NO_THROW(control.finish());
    ASSERT_EQ(control.answers->completions, 1U);
    ASSERT_TRUE(control.answers->declarations.has_value());
    ASSERT_TRUE(control.answers->declarations->is_good());
    expect_exact(control.answers->declarations->status_code(), StatusCode{});
    const auto& declarations = control.answers->declarations->value();
    ASSERT_EQ(declarations.size(), 1U);
    EXPECT_EQ(declarations[0].nodeId, controlDeclaration);
    EXPECT_EQ(declarations[0].browsePath, (std::vector<QualifiedName>{QualifiedName{0, "Entry"}}));
    ASSERT_TRUE(declarations[0].accessor.has_value());
    EXPECT_EQ(declarations[0].accessor->get_node_id(), controlDeclaration);
    EXPECT_EQ(declarations[0].nodeClass, NodeClass::Object);
    EXPECT_FALSE(declarations[0].mandatory);
    EXPECT_TRUE(declarations[0].dataType.is_null());
    EXPECT_EQ(control.answers->tokenReleasesAtCompletion, std::optional<std::size_t>{0});
    EXPECT_EQ(control.nameSpace->count(test::BatchRecordingNamespace::Member::ReleaseResumeToken), 0U);
    std::size_t consumed = 0;
    for (const auto& call : control.nameSpace->calls(test::BatchRecordingNamespace::Member::ReadReferences))
    {
      for (const auto& query : call.referenceQueries)
        if (query.resumeToken == controlToken)
          ++consumed;
    }
    EXPECT_EQ(consumed, 1U);
    expect_duplicates_do_nothing(control);
    EXPECT_EQ(control.nameSpace->count(test::BatchRecordingNamespace::Member::ReleaseResumeToken), 0U);

    AllocationRun fault{{Caller::AllowNulls, Stage::References}};
    const auto faultTypes = fault.event_nodes().first;
    ASSERT_EQ(faultTypes.size(), 1U);
    const auto faultType = faultTypes.front();
    ASSERT_NO_THROW(fault.start_event(faultType));
    ASSERT_EQ(fault.answers->completions, 0U);
    const auto initialFault = fault.nameSpace->calls(test::BatchRecordingNamespace::Member::ReadReferences);
    ASSERT_EQ(initialFault.size(), 1U);
    ASSERT_EQ(initialFault[0].nodeIds, (std::vector<NodeId>{faultType}));
    ASSERT_EQ(initialFault[0].referenceQueries.size(), 1U);
    ASSERT_TRUE(initialFault[0].referenceQueries[0].resumeToken.empty());
    const auto faultToken = initialFault[0].referenceQueries[0].answeredToken;
    ASSERT_FALSE(faultToken.empty());
    ASSERT_EQ(fault.nameSpace->count(test::BatchRecordingNamespace::Member::ReleaseResumeToken), 0U);
    const auto initialCalls = fault.nameSpace->calls().size();
    auto failing = fault.nameSpace->take(Stage::References);
    fault.duplicates.push_back(failing.duplicate);
    test::allocation::fail_at(location.nearestSdkFrame.address);
    const auto faultEscape = fault.deliver(std::move(failing));
    ASSERT_FALSE(test::allocation::armed());
    ASSERT_FALSE(faultEscape);
    ASSERT_EQ(test::allocation::injections(), 1U);
    const auto observed = test::allocation::identify(test::allocation::failed_allocation());
    ASSERT_TRUE(observed.has_value());
    ASSERT_TRUE(reference_setup_allocation(site, *observed));
    ASSERT_NO_FATAL_FAILURE(expect_same_location(*observed, location));
    RecordProperty(std::string{site} + " injected allocation", test::allocation::describe(*observed));
    ASSERT_NO_THROW(fault.finish());
    ASSERT_EQ(fault.answers->completions, 1U);
    ASSERT_TRUE(fault.answers->declarations.has_value());
    const auto& failure = fault.answers->declarations->status_code();
    EXPECT_EQ(failure.value(), StatusCode{Status::BadOutOfMemory}.value());
    const auto detail = failure.shared_detail();
    ASSERT_NE(detail, nullptr);
    EXPECT_EQ(detail->code, "EventTypeReferencesUnavailable");
    EXPECT_EQ(detail->innerStatus, StatusCode{Status::BadOutOfMemory}.value());
    ASSERT_NE(detail->cause, nullptr);
    EXPECT_EQ(detail->cause->code, "BadAlloc");
    EXPECT_EQ(fault.nameSpace->count(test::BatchRecordingNamespace::Member::ReadReferences), 1U);
    EXPECT_EQ(fault.answers->tokenReleasesAtCompletion, std::optional<std::size_t>{1});
    const auto released = fault.nameSpace->calls(test::BatchRecordingNamespace::Member::ReleaseResumeToken);
    EXPECT_EQ(released.size(), 1U);
    if (released.size() == 1U)
      EXPECT_EQ(released[0].token, faultToken);
    EXPECT_EQ(fault.nameSpace->calls().size(), initialCalls + 1);
    ASSERT_FALSE(fault.duplicates.empty());
    expect_duplicates_do_nothing(fault);
    EXPECT_EQ(fault.nameSpace->count(test::BatchRecordingNamespace::Member::ReleaseResumeToken), 1U);
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-NESTED-SUPERTYPE-SETUP-ALLOCATION-ANSWERS-ONCE, scope=function)
TEST(NamespaceCallerAllocation, NestedSupertypeSetupAllocationAnswersOnce)
{
  for (const bool hasParent : {false, true})
  {
    SCOPED_TRACE(hasParent);
    AllocationRun control{{Caller::Walking, Stage::References}};
    const auto [controlType, controlParent] = control.nested_type(hasParent);
    ASSERT_TRUE(controlType.is_type());
    auto permitted = control.supertype_delivery(controlType);
    test::allocation::record();
    const auto controlEscape = control.deliver(std::move(permitted));
    ASSERT_FALSE(test::allocation::armed());
    ASSERT_FALSE(controlEscape);
    ASSERT_FALSE(test::allocation::overflowed());
    ASSERT_EQ(test::allocation::injections(), 0U);
    const auto allocations = test::allocation::recorded_sdk_allocations();
    const auto selected = std::ranges::find_if(allocations, supertype_setup_allocation);
    std::string locationDiagnostics;
    if (selected == allocations.end())
    {
      for (const auto& allocation : allocations)
        locationDiagnostics += test::allocation::describe(allocation) + '\n';
      RecordProperty("Nested supertype setup nearest SDK allocation inventory", locationDiagnostics);
    }
    ASSERT_NE(selected, allocations.end())
      << "get_super_type_async made no allocation before invoking the References reader\n"
      << locationDiagnostics;
    const auto location = *selected;
    ASSERT_TRUE(location.copyWrappers.empty());
    RecordProperty("Nested supertype setup allocation", test::allocation::describe(location));
    ASSERT_EQ(control.answers->completions, 0U);
    ASSERT_EQ(control.nameSpace->count(test::BatchRecordingNamespace::Member::ReadReferences), 1U);
    ASSERT_EQ(control.nameSpace->count(test::BatchRecordingNamespace::Member::BatchedLookup), 0U);
    ASSERT_NO_THROW(control.finish());
    ASSERT_EQ(control.answers->completions, 1U);
    ASSERT_TRUE(control.answers->supertype.has_value());
    const auto& result = *control.answers->supertype;
    ASSERT_TRUE(result.is_good());
    expect_exact(result.status_code(), StatusCode{});
    EXPECT_EQ(result.value().has_value(), hasParent);
    std::size_t expectedLookups{0};
    if (hasParent)
    {
      expectedLookups = 1;
      ASSERT_TRUE(result.value().has_value());
      EXPECT_EQ(result.value()->get_node_id(), controlParent);
      const auto lookups = control.nameSpace->calls(test::BatchRecordingNamespace::Member::BatchedLookup);
      ASSERT_EQ(lookups.size(), 1U);
      EXPECT_EQ(lookups.front().nodeIds, (std::vector<NodeId>{controlParent}));
    }
    EXPECT_EQ(control.nameSpace->count(test::BatchRecordingNamespace::Member::ReadReferences), 1U);
    EXPECT_EQ(
      control.nameSpace->count(test::BatchRecordingNamespace::Member::BatchedLookup), expectedLookups);
    ASSERT_FALSE(control.duplicates.empty());
    expect_duplicates_do_nothing(control);

    AllocationRun fault{{Caller::Walking, Stage::References}};
    const auto [faultType, faultParent] = fault.nested_type(hasParent);
    ASSERT_EQ(faultType.get_node_id(), controlType.get_node_id());
    ASSERT_EQ(faultParent, controlParent);
    auto failing = fault.supertype_delivery(faultType);
    test::allocation::fail_at(location.nearestSdkFrame.address);
    const auto faultEscape = fault.deliver(std::move(failing));
    ASSERT_FALSE(test::allocation::armed());
    ASSERT_EQ(test::allocation::injections(), 1U);
    const auto observed = test::allocation::identify(test::allocation::failed_allocation());
    ASSERT_TRUE(observed.has_value());
    ASSERT_TRUE(supertype_setup_allocation(*observed));
    expect_nested_allocation_site(*observed, location);
    RecordProperty("Nested supertype setup injected allocation", test::allocation::describe(*observed));
    EXPECT_FALSE(faultEscape)
      << "The public async invocation or executor drain allowed an exception to escape";
    EXPECT_NO_THROW(fault.finish());
    EXPECT_TRUE(fault.nameSpace->calls().empty()) << "Setup failure must not issue namespace work";
    EXPECT_EQ(fault.nameSpace->count(test::BatchRecordingNamespace::Member::ReadReferences), 0U);
    EXPECT_EQ(fault.nameSpace->count(test::BatchRecordingNamespace::Member::BatchedLookup), 0U);
    ASSERT_EQ(fault.answers->completions, 1U);
    ASSERT_TRUE(fault.answers->supertype.has_value());
    EXPECT_FALSE(fault.answers->supertype->is_good());
    expect_memory_failure(fault.answers->supertype->status_code());
    EXPECT_NO_THROW(fault.drain());
    EXPECT_EQ(fault.answers->completions, 1U);
    EXPECT_TRUE(fault.nameSpace->calls().empty());
  }
}

// @relation(AC-COMP-SVR-NAMESPACE-CALLS-21-NESTED-REFERENCE-WRAPPER-ALLOCATION-PRESERVES-REFUSAL, scope=function)
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(NamespaceCallerAllocation, NestedReferenceWrapperAllocationPreservesRefusal)
{
  for (const bool cached : {false, true})
  {
    for (const Stage stage : {Stage::References, Stage::Lookup})
    {
      for (const Status refusalStatus :
        {Status::BadResourceUnavailable, Status::UncertainNoCommunicationLastUsableValue})
      {
        SCOPED_TRACE(cached);
        SCOPED_TRACE(utils::to_underlying(stage));
        SCOPED_TRACE(StatusCode{refusalStatus}.value());
        AllocationRun control{{Caller::Walking, Stage::References}, refusalStatus};
        const auto [controlType, controlParent] = control.nested_type(true);
        const auto controlId = controlType.get_node_id();
        const auto key = std::make_pair(controlId, NodeId{ReferenceTypeId::References});
        const auto controlCache = std::make_shared<node_utils::RefTypeCache>();
        ASSERT_EQ(control.sentinel.value(), StatusCode{refusalStatus}.value());
        if (stage == Stage::References)
          control.nameSpace->answer_reference_query_of(controlId, 1, control.sentinel);
        else
          control.nameSpace->answer_lookup_of(controlParent, control.sentinel);
        ASSERT_NO_THROW(control.start_nested_reference(controlId, cached, controlCache));
        ASSERT_EQ(control.nameSpace->count(test::BatchRecordingNamespace::Member::BatchedLookup), 1U);
        ASSERT_EQ(control.nameSpace->count(test::BatchRecordingNamespace::Member::ReadReferences), 1U);
        if (stage == Stage::Lookup)
        {
          auto references = control.nameSpace->take(Stage::References);
          control.duplicates.push_back(references.duplicate);
          ASSERT_NO_THROW(references.answer());
          ASSERT_NO_THROW(control.drain());
          ASSERT_EQ(control.nameSpace->count(test::BatchRecordingNamespace::Member::BatchedLookup), 2U);
        }
        ASSERT_EQ(control.answers->completions, 0U);
        ASSERT_FALSE(controlCache->lookup(key).has_value());
        const auto controlCalls = control.nameSpace->calls().size();
        if (StatusCode{refusalStatus}.is_uncertain())
        {
          // The walk decides a rule, so an Uncertain supertype answer is refused before any wrapper is built:
          // there is no wrapper allocation to fail, and the walk answers the refusal.
          auto uncertain = control.nameSpace->take(stage);
          control.duplicates.push_back(uncertain.duplicate);
          ASSERT_FALSE(control.deliver(std::move(uncertain)));
          ASSERT_NO_THROW(control.finish());
          ASSERT_EQ(control.answers->completions, 1U);
          ASSERT_TRUE(control.answers->referenceMatch.has_value());
          const auto& refused = *control.answers->referenceMatch;
          EXPECT_EQ(refused.status_code().as_status(), Status::BadInternalError);
          const auto refusal = refused.shared_detail();
          ASSERT_NE(refusal, nullptr);
          EXPECT_EQ(refusal->code, "LookupAnswerUncertain");
          EXPECT_EQ(refusal->innerStatus, control.sentinel.value());
          EXPECT_EQ(control.nameSpace->calls().size(), controlCalls);
          EXPECT_FALSE(controlCache->lookup(key).has_value());
          expect_duplicates_do_nothing(control);
          continue;
        }
        auto permitted = control.nameSpace->take(stage);
        control.duplicates.push_back(permitted.duplicate);
        test::allocation::record();
        const auto controlEscape = control.deliver(std::move(permitted));
        ASSERT_FALSE(test::allocation::armed());
        ASSERT_FALSE(controlEscape);
        ASSERT_FALSE(test::allocation::overflowed());
        ASSERT_EQ(test::allocation::injections(), 0U);
        const auto allocations = test::allocation::recorded_sdk_allocations();
        const auto selected = std::ranges::find_if(allocations, nested_diagnostic_allocation);
        std::string locationDiagnostics;
        if (selected == allocations.end())
        {
          for (const auto& allocation : allocations)
            locationDiagnostics += test::allocation::describe(allocation) + '\n';
          RecordProperty("Nested reference wrapper nearest SDK allocation inventory", locationDiagnostics);
        }
        ASSERT_NE(selected, allocations.end())
          << "No actual DanglingHasSubtype construction allocation was identified\n"
          << locationDiagnostics;
        const auto location = *selected;
        ASSERT_TRUE(location.copyWrappers.empty());
        RecordProperty("Nested reference wrapper allocation", test::allocation::describe(location));
        ASSERT_NO_THROW(control.finish());
        ASSERT_EQ(control.answers->completions, 1U);
        ASSERT_TRUE(control.answers->referenceMatch.has_value());
        const auto& controlResult = *control.answers->referenceMatch;
        EXPECT_FALSE(controlResult.is_good());
        EXPECT_EQ(controlResult.status_code().value(), control.sentinel.value());
        const auto wrapper = controlResult.shared_detail();
        ASSERT_NE(wrapper, nullptr);
        EXPECT_EQ(wrapper->code, "DanglingHasSubtype");
        EXPECT_EQ(wrapper->innerStatus, control.sentinel.value());
        EXPECT_EQ(wrapper->cause, control.sentinel.shared_detail());
        EXPECT_EQ(control.nameSpace->calls().size(), controlCalls);
        EXPECT_FALSE(controlCache->lookup(key).has_value());
        expect_duplicates_do_nothing(control);
        EXPECT_FALSE(controlCache->lookup(key).has_value());

        AllocationRun fault{{Caller::Walking, Stage::References}, refusalStatus};
        const auto [faultType, faultParent] = fault.nested_type(true);
        const auto faultId = faultType.get_node_id();
        ASSERT_EQ(faultId, controlId);
        ASSERT_EQ(faultParent, controlParent);
        const auto faultCache = std::make_shared<node_utils::RefTypeCache>();
        ASSERT_EQ(fault.sentinel.value(), control.sentinel.value());
        if (stage == Stage::References)
          fault.nameSpace->answer_reference_query_of(faultId, 1, fault.sentinel);
        else
          fault.nameSpace->answer_lookup_of(faultParent, fault.sentinel);
        ASSERT_NO_THROW(fault.start_nested_reference(faultId, cached, faultCache));
        ASSERT_EQ(fault.nameSpace->count(test::BatchRecordingNamespace::Member::BatchedLookup), 1U);
        ASSERT_EQ(fault.nameSpace->count(test::BatchRecordingNamespace::Member::ReadReferences), 1U);
        if (stage == Stage::Lookup)
        {
          auto references = fault.nameSpace->take(Stage::References);
          fault.duplicates.push_back(references.duplicate);
          ASSERT_NO_THROW(references.answer());
          ASSERT_NO_THROW(fault.drain());
          ASSERT_EQ(fault.nameSpace->count(test::BatchRecordingNamespace::Member::BatchedLookup), 2U);
        }
        ASSERT_EQ(fault.answers->completions, 0U);
        ASSERT_FALSE(faultCache->lookup(key).has_value());
        const auto faultCalls = fault.nameSpace->calls().size();
        auto failing = fault.nameSpace->take(stage);
        fault.duplicates.push_back(failing.duplicate);
        test::allocation::fail_at(location.nearestSdkFrame.address);
        const auto faultEscape = fault.deliver(std::move(failing));
        ASSERT_FALSE(test::allocation::armed());
        ASSERT_FALSE(faultEscape);
        ASSERT_EQ(test::allocation::injections(), 1U);
        const auto observed = test::allocation::identify(test::allocation::failed_allocation());
        ASSERT_TRUE(observed.has_value());
        ASSERT_TRUE(nested_diagnostic_allocation(*observed));
        expect_nested_allocation_site(*observed, location);
        RecordProperty("Nested reference wrapper injected allocation", test::allocation::describe(*observed));
        ASSERT_NO_THROW(fault.finish());
        ASSERT_EQ(fault.answers->completions, 1U);
        ASSERT_TRUE(fault.answers->referenceMatch.has_value());
        EXPECT_FALSE(fault.answers->referenceMatch->is_good());
        expect_exact(fault.answers->referenceMatch->status_code(), fault.sentinel);
        EXPECT_EQ(fault.nameSpace->calls().size(), faultCalls);
        EXPECT_FALSE(faultCache->lookup(key).has_value());
        expect_duplicates_do_nothing(fault);
        EXPECT_FALSE(faultCache->lookup(key).has_value());
      }
    }
  }
}
