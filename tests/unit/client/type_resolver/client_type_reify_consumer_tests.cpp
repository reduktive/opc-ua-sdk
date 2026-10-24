// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the gated-lazy application-data reify consumer (ua::client::detail::reify_and_deliver,
// client design section 9.2 / Slice T1 Phase A2). The consumer upgrades UnknownStructure placeholders left by
// the wire decoder to their concrete typed Structure using the per-Connection TypeRegistry, gated by the
// decode-and-defer policy. These tests drive the orchestration free function directly over a fake
// ReifySupport interface (no live wire, no io_context), plus the production ResolverReifySupport adapter over
// a real TypeResolver, so every branch of the algorithm is exercised in isolation.
//
// Falsifiability:
//   - A consumer that never reifies fails ReifiesRegisteredType.
//   - A consumer that touched the resolver on the no-placeholder common case fails FastPathNoSupportAccess.
//   - A consumer that reified over budget fails OverBudgetGateDeliversPlaceholdersUnreified.
//   - A consumer that never drives resolution fails ResolveDrivenForUnknownEncoding.
//   - A consumer that failed the whole read when a type could not be reified fails
//     ResolveFailureIsNonFatalAndDelivers (the highest-priority ErrorDetail rule).
//
// @verifies CL-BASE-008 - type pre-knowledge (user-registered) reifies an application-data placeholder.
// @relation(CL-BASE-008, scope=file)
// @verifies CL-ATTR-012 - resolve_async is the production consumer's resolution entry (adapter path).
// @relation(CL-ATTR-012, scope=file)
// @verifies CL-ADDRSP-011 - the resolve path is exercised for an unknown encoding.
// @relation(CL-ADDRSP-011, scope=file)
// @verifies CL-ADDRSP-012 - the in-Connection registry snapshot is used via the resolve/registry path.
// @relation(CL-ADDRSP-012, scope=file)

#include "ua_type_reify_consumer.h"

#include "fake_connection_ops.h"

#include "ua_application_configuration.h"
#include "ua_argument.h"
#include "ua_array.h"
#include "ua_binary_codec.h"
#include "ua_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_dynamic_structure.h"
#include "ua_dynamic_type_registry.h"
#include "ua_encoding_limits.h"
#include "ua_expanded_node_id.h"
#include "ua_log_level.h"
#include "ua_logger.h"
#include "ua_memory_stream.h"
#include "ua_namespace_table.h"
#include "ua_node_id.h"
#include "ua_read_response.h"
#include "ua_ref_structure.h"
#include "ua_reference_description.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_structure.h"
#include "ua_structure_definition.h"
#include "ua_structure_field.h"
#include "ua_type_registry.h"
#include "ua_type_resolution_policy.h"
#include "ua_type_resolver.h"
#include "ua_type_resolver_test_access.h"
#include "ua_unknown_structure.h"
#include "ua_variant.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <gtest/gtest.h>
#include "ua_object_id.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace
{

using ua::client::detail::DeferDecision;
using ua::client::detail::ReifySupport;
using ua::client::detail::ResolverReifySupport;
using ua::client::detail::StructureFactory;
using ua::client::detail::StructureType;
using ua::client::detail::TypeRegistry;
using ua::client::detail::TypeResolver;
using ua::client::detail::TypeSource;

ua::NodeId node(std::uint16_t ns, std::uint32_t identifier)
{
  return ua::NodeId{ns, identifier};
}

ua::EncodingLimits limits()
{
  return ua::make_encoding_limits(ua::ApplicationConfig::load_default());
}

ua::NodeId argument_binary_encoding()
{
  return ua::NodeId{ua::Argument::defaultBinaryEncodingId};
}

// Encode then decode an Argument with NO resolver so the decoder leaves it as an opaque UnknownStructure -
// exactly what the client secure-channel decoder produces for an unresolved encoding.
ua::unique_ptr<ua::Structure> make_argument_opaque()
{
  ua::Argument argument;
  argument.name() = "Speed";
  argument.data_type() = node(0, 11u);
  argument.value_rank() = -1;

  ua::memory_stream_device::Dynamic device;
  ua::MemoryStream stream{device};
  ua::UaBinaryEncoder encoder{ua::CodecNamespaceContext{}, stream};
  const auto depth = limits().stack_depth();
  encoder.encode(depth, &argument);
  stream.seek_from_start(0);
  ua::UaBinaryDecoder decoder{ua::StructureResolver{}, stream, limits()};
  ua::unique_ptr<ua::Structure> opaque;
  decoder.decode(limits().stack_depth(), opaque);
  return opaque;
}

// A registry that resolves the Argument binary encoding to an Argument decode prototype (models a
// user-registered / built-in known type).
std::shared_ptr<const TypeRegistry> registry_with_argument()
{
  StructureFactory factory;
  factory.register_structure_type(argument_binary_encoding(), node(0, 296), std::make_shared<ua::Argument>());
  return TypeRegistry::create(std::move(factory), 1);
}

// A ReifySupport interface whose behaviour each test scripts: the gate decision, the registry snapshot
// returned after resolution, and whether resolve_async completes Good. Records every classify / resolve
// interaction so the fast-path and gate tests can assert the resolver was never consulted.
class FakeReifySupport : public ReifySupport
{
public:
  DeferDecision decision = DeferDecision::Defer;
  std::shared_ptr<const TypeRegistry> snapshot = TypeRegistry::create(StructureFactory{}, 1);
  bool resolveGood = true;
  bool waitForResolution = true;
  std::size_t redecodeBudget = 1;

  mutable int classifyCalls = 0;
  mutable std::size_t lastDistinctCount = 0;
  std::vector<ua::NodeId> resolveRequests;

  DeferDecision classify(std::size_t distinctUnresolvedCount) const noexcept override
  {
    ++classifyCalls;
    lastDistinctCount = distinctUnresolvedCount;
    return decision;
  }

  void resolve_async(ua::NodeId encodingId, std::function<void(ua::VoidResult)> done) override
  {
    resolveRequests.push_back(encodingId);
    // Fire the completion inline: the barrier pre-sets its counter, so an inline completion is safe and
    // keeps the orchestration test synchronous (the real adapter posts to the resolver strand).
    done(resolveGood ? ua::VoidResult{} : ua::VoidResult{ua::StatusCode{ua::Status::BadDataTypeIdUnknown}});
  }

  bool wait_for_resolution() const noexcept override
  {
    return waitForResolution;
  }

  bool may_redecode(std::size_t passIndex) const noexcept override
  {
    return passIndex < redecodeBudget;
  }

  std::shared_ptr<const TypeRegistry> registry() const override
  {
    return snapshot;
  }
};

bool is_unknown(const ua::Variant& value)
{
  return value.is_structure() &&
         dynamic_cast<const ua::UnknownStructure*>(&value.as<ua::Structure>()) != nullptr;
}

bool is_argument(const ua::Variant& value)
{
  return value.is_structure() && dynamic_cast<const ua::Argument*>(&value.as<ua::Structure>()) != nullptr;
}

// --- server-discovered end-to-end helpers (Slice T1(b) / CL-ADDRSP-013) -------------------------

// A StructureDefinition of one scalar Int32 field "Payload" - what a server publishes as the
// DataTypeDefinition for a simple custom Structure.
ua::StructureDefinition server_struct_definition()
{
  ua::StructureDefinition definition;
  definition.structure_type() = ua::StructureType::Structure;
  definition.base_data_type() = ua::NodeId{0, static_cast<std::uint32_t>(ua::DataTypeId::Structure)};
  ua::StructureField field;
  field.name() = ua::String{"Payload"};
  field.data_type() = ua::NodeId{0, static_cast<std::uint32_t>(ua::DataTypeId::Int32)};
  field.value_rank() = -1;
  definition.fields().push_back(std::move(field));
  return definition;
}

// A ReadResponse whose DataValue carries `definition` - the DataTypeDefinition Read the resolver issues.
ua::Result<ua::ReadResponse> definition_read_response(ua::StructureDefinition definition)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::move(definition)}});
  return ua::Result<ua::ReadResponse>{std::move(response)};
}

// A Browse page whose single reference names `dataType` as the DataType behind the browsed encoding.
ua::test_helpers::FakeWireOps::BrowsePage encoding_to_data_type_page(ua::NodeId dataType)
{
  ua::test_helpers::FakeWireOps::BrowsePage page;
  ua::ReferenceDescription reference;
  reference.node_id().node_id() = std::move(dataType);
  page.references.push_back(std::move(reference));
  return page;
}

// Produces an opaque UnknownStructure for `encodingId` carrying a `payload`-valued single-Int32 body -
// exactly what the client secure-channel decoder yields for an ExtensionObject of an as-yet-unresolved
// SERVER-discovered type (its encoding id + raw body preserved). Built by encoding a matching
// DynamicStructure through the binary codec then decoding it with NO resolver.
ua::unique_ptr<ua::Structure> make_server_struct_opaque(
  const ua::NodeId& encodingId, const ua::NodeId& dataTypeId, std::int32_t payload)
{
  ua::DynamicTypeRegistry registry;
  registry.register_type(server_struct_definition(),
    ua::ExpandedNodeId{dataTypeId},
    ua::ExpandedNodeId{encodingId},
    ua::String{"ServerType"});
  ua::unique_ptr<ua::Structure> instance;
  registry.register_all_with(
    [&](const ua::NodeId& enc, std::function<ua::unique_ptr<ua::Structure>()> factory)
    {
      if (enc == encodingId)
      {
        instance = factory();
      }
    });
  auto* dynamic = dynamic_cast<ua::DynamicStructure*>(instance.get());
  dynamic->field(0) = ua::Variant{payload};

  ua::memory_stream_device::Dynamic device;
  ua::MemoryStream stream{device};
  ua::UaBinaryEncoder encoder{ua::CodecNamespaceContext{}, stream};
  encoder.encode(limits().stack_depth(), instance.get());
  stream.seek_from_start(0);
  ua::UaBinaryDecoder decoder{ua::StructureResolver{}, stream, limits()};
  ua::unique_ptr<ua::Structure> opaque;
  decoder.decode(limits().stack_depth(), opaque);
  return opaque;
}

}  // namespace

// (1) A response whose value is an UnknownStructure for a KNOWN encoding is upgraded to the concrete type.
// RED without the consumer: the caller only ever sees the UnknownStructure.
// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeReifyConsumer, ReifiesRegisteredType)
{
  std::vector<ua::Variant> storage;
  storage.emplace_back(make_argument_opaque());
  ASSERT_TRUE(is_unknown(storage[0]));

  auto support = std::make_shared<FakeReifySupport>();
  support->snapshot = registry_with_argument();

  bool delivered = false;
  ua::client::detail::reify_and_deliver({&storage[0]}, support, limits(), [&delivered] { delivered = true; });

  EXPECT_TRUE(delivered);
  EXPECT_FALSE(is_unknown(storage[0])) << "the placeholder must be reified away";
  ASSERT_TRUE(is_argument(storage[0])) << "the value must be the concrete Argument";
  EXPECT_EQ(storage[0].as<ua::Structure>().type_name(), ua::String{"Argument"});
  EXPECT_EQ(support->resolveRequests.size(), 1u);
}

// (2) FAST PATH: a response with NO placeholder is delivered with ZERO support interaction (no classify, no
// resolve) - the allocation-free common path. RED if the consumer classifies/resolves unconditionally.
TEST(TypeReifyConsumer, FastPathNoSupportAccess)
{
  std::vector<ua::Variant> storage;
  storage.emplace_back(std::int32_t{42});

  auto support = std::make_shared<FakeReifySupport>();

  bool delivered = false;
  ua::client::detail::reify_and_deliver({&storage[0]}, support, limits(), [&delivered] { delivered = true; });

  EXPECT_TRUE(delivered);
  EXPECT_EQ(support->classifyCalls, 0) << "the fast path must not consult the gate";
  EXPECT_TRUE(support->resolveRequests.empty()) << "the fast path must not drive resolution";
  EXPECT_EQ(storage[0].to<std::int32_t>().value(), 42) << "the value is delivered unchanged";
}

// (3) GATE: an over-budget message (classify -> Placeholder) is delivered WITHOUT reify - placeholders
// preserved, no resolution. RED if the consumer ignores the gate and reifies anyway.
TEST(TypeReifyConsumer, OverBudgetGateDeliversPlaceholdersUnreified)
{
  std::vector<ua::Variant> storage;
  storage.emplace_back(make_argument_opaque());

  auto support = std::make_shared<FakeReifySupport>();
  support->snapshot = registry_with_argument();  // resolvable, but the gate must veto
  support->decision = DeferDecision::Placeholder;

  bool delivered = false;
  ua::client::detail::reify_and_deliver({&storage[0]}, support, limits(), [&delivered] { delivered = true; });

  EXPECT_TRUE(delivered);
  EXPECT_EQ(support->classifyCalls, 1) << "the gate must be consulted exactly once";
  EXPECT_TRUE(support->resolveRequests.empty()) << "an over-budget message must not drive resolution";
  EXPECT_TRUE(is_unknown(storage[0])) << "over budget: the placeholder is preserved";
}

// (4) The resolve path is driven exactly once per DISTINCT unknown encoding (deduped across values). RED if
// the consumer never resolves, or resolves per-value rather than per-distinct-encoding.
// @verifies CL-ADDRSP-011
// @verifies CL-ATTR-012
// @relation(CL-ADDRSP-011, CL-ATTR-012, scope=function)
TEST(TypeReifyConsumer, ResolveDrivenForUnknownEncoding)
{
  std::vector<ua::Variant> storage;
  storage.emplace_back(make_argument_opaque());
  storage.emplace_back(make_argument_opaque());  // same encoding: must coalesce to one resolve

  auto support = std::make_shared<FakeReifySupport>();
  support->snapshot = registry_with_argument();

  bool delivered = false;
  ua::client::detail::reify_and_deliver(
    {&storage[0], &storage[1]}, support, limits(), [&delivered] { delivered = true; });

  EXPECT_TRUE(delivered);
  EXPECT_EQ(support->lastDistinctCount, 1u) << "the two identical encodings collapse to one distinct type";
  ASSERT_EQ(support->resolveRequests.size(), 1u) << "resolve_async is driven once per distinct encoding";
  EXPECT_EQ(support->resolveRequests[0], argument_binary_encoding());
  EXPECT_TRUE(is_argument(storage[0]));
  EXPECT_TRUE(is_argument(storage[1]));
}

// (5) NON-FATAL resolve failure: a type that cannot be resolved stays opaque, but the value set is STILL
// delivered (never a dropped ErrorDetail turning into a failed read). RED if the consumer fails / drops on
// a resolve failure.
// @verifies CL-ADDRSP-011
// @relation(CL-ADDRSP-011, scope=function)
TEST(TypeReifyConsumer, ResolveFailureIsNonFatalAndDelivers)
{
  std::vector<ua::Variant> storage;
  storage.emplace_back(make_argument_opaque());

  auto support = std::make_shared<FakeReifySupport>();
  support->resolveGood = false;  // resolution fails ...
  support->snapshot = TypeRegistry::create(StructureFactory{}, 1);  // ... and the type stays unknown

  bool delivered = false;
  ua::client::detail::reify_and_deliver({&storage[0]}, support, limits(), [&delivered] { delivered = true; });

  EXPECT_TRUE(delivered) << "a failed resolve must never fail / drop the whole delivery";
  EXPECT_EQ(support->resolveRequests.size(), 1u);
  EXPECT_TRUE(is_unknown(storage[0])) << "an unresolved type is left opaque, not lost";
}

// (6) DoS guard (section 3.1): a hostile server can answer a legitimate Read/Call with an ARRAY of up to
// MaxArrayLength ExtensionObjects each carrying a DISTINCT, unresolvable encoding id. The distinct-encoding
// collection that precedes the budget gate must be LINEAR - an O(1) (hash-set) dedup, not an O(N) linear scan
// of a growing vector (which is O(N^2) overall and burns seconds of CPU on the shared executor thread before
// the gate even rejects). This pins that the PRE-GATE collection is bounded; the over-budget gate then
// delivers as-is. The array carries distinct encodings so dedup does no collapsing.
// @verifies CL-ADDRSP-011
// @relation(CL-ADDRSP-011, scope=function)
TEST(TypeReifyConsumer, LargeDistinctEncodingArrayCollectsInLinearTime)
{
  constexpr std::uint32_t count = 40000;
  ua::Array<ua::RefStructure<ua::Structure>> array;
  array.reserve(count);
  for (std::uint32_t identifier = 0; identifier < count; ++identifier)
  {
    ua::RefStructure<ua::Structure> reference;
    reference.inner_unique_ptr() = std::make_unique<ua::UnknownStructure>(node(1, identifier));
    array.push_back(std::move(reference));
  }
  std::vector<ua::Variant> storage;
  storage.emplace_back(std::move(array));

  auto support = std::make_shared<FakeReifySupport>();
  support->decision = DeferDecision::Placeholder;  // over budget -> deliver as-is (the realistic DoS path)

  bool delivered = false;
  const auto start = std::chrono::steady_clock::now();
  ua::client::detail::reify_and_deliver({&storage[0]}, support, limits(), [&delivered] { delivered = true; });
  const auto elapsed =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

  EXPECT_TRUE(delivered);
  EXPECT_EQ(support->lastDistinctCount, count) << "every distinct encoding is counted for the gate";
  EXPECT_TRUE(support->resolveRequests.empty()) << "an over-budget message drives no resolution";
  // Linear collection is sub-millisecond; the O(N^2) scan took ~seconds for N=40000. The 2 s ceiling stays
  // RED for a regression to the linear-scan dedup yet is robust against CI/sharding CPU contention.
  EXPECT_LT(elapsed.count(), 2000) << "distinct-encoding collection must be linear, not quadratic (took "
                                   << elapsed.count() << " ms)";
}

// Resolver gone (null support): the values are delivered un-reified - never dropped, never a crash.
TEST(TypeReifyConsumer, NullSupportDeliversUnreified)
{
  std::vector<ua::Variant> storage;
  storage.emplace_back(make_argument_opaque());

  bool delivered = false;
  ua::client::detail::reify_and_deliver({&storage[0]}, nullptr, limits(), [&delivered] { delivered = true; });

  EXPECT_TRUE(delivered);
  EXPECT_TRUE(is_unknown(storage[0]));
}

// The production ResolverReifySupport adapter drives a REAL TypeResolver end-to-end: a user-registered
// Argument prototype reifies an application-data placeholder through resolve_async's already-resolved fast
// path (no wire Browse needed). Proves the adapter's classify / resolve_async / registry forwarding.
// @verifies CL-ATTR-012
// @verifies CL-ADDRSP-012
// @relation(CL-ADDRSP-012, CL-ATTR-012, scope=function)
TEST(TypeReifyConsumer, ProductionAdapterReifiesUserRegisteredType)
{
  boost::asio::io_context ctx;
  auto strand = boost::asio::make_strand(ctx.get_executor());
  auto wireOps = std::make_shared<ua::test_helpers::FakeWireOps>();
  auto supportOps = std::make_shared<ua::test_helpers::FakeSupportOps>();
  auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
  ua::Logger logger{nullptr, level, "reify_adapter_test"};

  auto resolver =
    TypeResolver::create(strand, wireOps, supportOps, ua::client::TypeResolutionPolicy{}, nullptr, logger);

  auto namespaces =
    ua::client::NamespaceTable::create({"http://opcfoundation.org/UA/"}, std::nullopt, 1).value();
  resolver->on_namespace_table_replaced_async(namespaces, [] {});
  ctx.run();
  ctx.restart();

  // Register the Argument type (URI = standard UA -> index 0), carrying a real decode prototype.
  ua::client::detail::UserTypeRegistration registration;
  registration.namespaceUri = "http://opcfoundation.org/UA/";
  registration.dataTypeIdentifier = node(0, 296);
  registration.binaryEncodingIdentifier = argument_binary_encoding();
  registration.decoder = std::make_shared<ua::Argument>();
  resolver->register_types_async(
    std::vector<ua::client::detail::UserTypeRegistration>{registration}, [](auto) {});
  ctx.run();
  ctx.restart();
  ASSERT_EQ(ua::client::detail::TypeResolverTestAccess::source_of(*resolver, argument_binary_encoding()),
    TypeSource::UserRegistered);

  std::vector<ua::Variant> storage;
  storage.emplace_back(make_argument_opaque());

  auto support = std::make_shared<ResolverReifySupport>(resolver, namespaces, /*waitForResolution=*/true);
  bool delivered = false;
  ua::client::detail::reify_and_deliver({&storage[0]}, support, limits(), [&delivered] { delivered = true; });
  ctx.run();  // drain the resolve_async strand hop + completion

  EXPECT_TRUE(delivered);
  ASSERT_TRUE(is_argument(storage[0])) << "the production adapter reifies the user-registered type";
  EXPECT_EQ(storage[0].as<ua::Structure>().type_name(), ua::String{"Argument"});
}

// END-TO-END (Slice T1(b) / CL-ADDRSP-013): a SERVER-DISCOVERED structure - one the client learns ONLY from
// the server's DataTypeDefinition over the wire - reifies from an opaque UnknownStructure to a concrete
// DynamicStructure through the production consumer. The real TypeResolver runs a genuine Browse HasEncoding
// + Read DataTypeDefinition (scripted on FakeWireOps), builds a DynamicStructure decoder from the wire
// definition, and the consumer clones it to decode the placeholder's preserved body. RED before the slice:
// finish_resolution installed a nullptr decoder, so the placeholder stayed opaque forever.
// @verifies CL-ADDRSP-013
// @verifies CL-ATTR-012
// @relation(CL-ADDRSP-013, CL-ATTR-012, scope=function)
TEST(TypeReifyConsumer, ProductionAdapterReifiesServerDiscoveredTypeThroughWire)
{
  const ua::NodeId encodingId{1, 100u};
  const ua::NodeId dataTypeId{1, 200u};

  boost::asio::io_context ctx;
  auto strand = boost::asio::make_strand(ctx.get_executor());
  auto wireOps = std::make_shared<ua::test_helpers::FakeWireOps>();
  auto supportOps = std::make_shared<ua::test_helpers::FakeSupportOps>();
  auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
  ua::Logger logger{nullptr, level, "reify_server_type_test"};

  // Script the resolver's wire discovery: Browse HasEncoding -> DataType, then Read -> DataTypeDefinition.
  wireOps->browsePages.push_back(encoding_to_data_type_page(dataTypeId));
  wireOps->scriptedReadResponses.push_back(definition_read_response(server_struct_definition()));

  auto resolver =
    TypeResolver::create(strand, wireOps, supportOps, ua::client::TypeResolutionPolicy{}, nullptr, logger);
  auto namespaces =
    ua::client::NamespaceTable::create({"http://opcfoundation.org/UA/", "urn:server"}, std::nullopt, 1)
      .value();
  resolver->on_namespace_table_replaced_async(namespaces, [] {});
  ctx.run();
  ctx.restart();

  // The placeholder the wire decoder produced for the unresolved server type (encoding + body preserved).
  std::vector<ua::Variant> storage;
  storage.emplace_back(make_server_struct_opaque(encodingId, dataTypeId, 4242));
  ASSERT_TRUE(is_unknown(storage[0])) << "precondition: the value starts opaque";

  auto support = std::make_shared<ResolverReifySupport>(resolver, namespaces, /*waitForResolution=*/true);
  bool delivered = false;
  ua::client::detail::reify_and_deliver({&storage[0]}, support, limits(), [&delivered] { delivered = true; });
  ctx.run();  // drain the wire resolve (Browse + Read) + the reify finalize

  EXPECT_TRUE(delivered);
  EXPECT_FALSE(is_unknown(storage[0])) << "the server-discovered placeholder must be reified away";
  auto* dynamic = dynamic_cast<ua::DynamicStructure*>(&storage[0].as<ua::Structure>());
  ASSERT_NE(dynamic, nullptr)
    << "the reified value must be a DynamicStructure built from the wire definition";
  EXPECT_EQ(dynamic->field(0).to<std::int32_t>().value(), 4242)
    << "the preserved body must decode faithfully";
}

// ============================================================================================
// Security review 2026-09-28: a malformed body from the server never loses the delivery.
// ============================================================================================

namespace
{

std::shared_ptr<const TypeRegistry> registry_with_argument_xml()
{
  StructureFactory factory;
  factory.register_structure_type(
    node(0, static_cast<std::uint32_t>(ua::ObjectId::Argument_Encoding_DefaultXml)),
    node(0, 296),
    std::make_shared<ua::Argument>());
  return TypeRegistry::create(std::move(factory), 1);
}

ua::Variant malformed_xml_argument_opaque()
{
  const std::string body{"x"};
  std::vector<std::uint8_t> bytes(body.begin(), body.end());
  return ua::Variant{ua::make_unique<ua::UnknownStructure>(
    node(0, static_cast<std::uint32_t>(ua::ObjectId::Argument_Encoding_DefaultXml)),
    ua::UnknownStructure::BodyEncoding::Xml,
    ua::ByteString{std::move(bytes)})};
}

}  // namespace

// @relation(AC-CL-ADDRSP-013-A-BODY-THAT-CANNOT-BE-REIFIED-IS-A-DECODING-ERROR, scope=function)
TEST(TypeReifyConsumer, MalformedXmlBodyStillDeliversExactlyOnce)
{
  std::vector<ua::Variant> storage;
  storage.emplace_back(malformed_xml_argument_opaque());
  ASSERT_TRUE(is_unknown(storage[0]));

  auto support = std::make_shared<FakeReifySupport>();
  support->snapshot = registry_with_argument_xml();

  int delivered = 0;
  ua::client::detail::reify_and_deliver({&storage[0]}, support, limits(), [&delivered] { ++delivered; });

  EXPECT_EQ(delivered, 1) << "the read is delivered exactly once whatever the body holds";
  EXPECT_TRUE(is_unknown(storage[0])) << "the value that could not be reified stays opaque";
}
