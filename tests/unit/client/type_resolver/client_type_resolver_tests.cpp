// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for ua::client::detail::TypeResolver (client design section 8.6): the per-Connection
// type-resolution component. Covers the resolution modes (Lazy defers connect-time discovery; Eager
// pre-resolves via Browse HasEncoding + Read DataTypeDefinition), the dictionary fallback path and its
// provenance, the dictionary-disabled fail-closed path, waiter coalescing, register-types attach-or-defer,
// the no-private-strand structural contract, and the section 9.8.3 weak-owner lifetime bail (an async
// resolution completion after the resolver is gone must not dereference it).
//
// Falsifiability: a resolver that scans under Lazy fails LazyModeIssuesNoWireOpsAtBootstrap; one that never
// scans under Eager fails EagerModePreResolvesViaBrowseAndRead; one that mis-provenances the dictionary
// path fails ResolveViaDictionaryTagsServerDictionary; one that derefs a gone owner crashes
// DeferredReadAfterResolverGoneDoesNotDeref.

#include "ua_type_resolver.h"

#include "fake_connection_ops.h"

#include "ua_application_configuration.h"
#include "ua_binary_codec.h"
#include "ua_codec.h"
#include "ua_browse_direction.h"
#include "ua_codec_namespace_context.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_dynamic_structure.h"
#include "ua_encoding_limits.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_memory_stream.h"
#include "ua_namespace_table.h"
#include "ua_node_id.h"
#include "ua_read_response.h"
#include "ua_reference_description.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_structure_definition.h"
#include "ua_structure_field.h"
#include "ua_type_registry.h"
#include "ua_type_resolver_test_access.h"
#include "ua_variant.h"

#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace
{

using ua::client::TypeResolutionMode;
using ua::client::TypeResolutionPolicy;
using ua::client::detail::RegistrationOutcome;
using ua::client::detail::TypeResolver;
using ua::client::detail::TypeResolverTestAccess;
using ua::client::detail::TypeSource;
using ua::client::detail::UserTypeRegistration;
using ua::test_helpers::FakeSupportOps;
using ua::test_helpers::FakeWireOps;

ua::NodeId node(std::uint16_t ns, std::uint32_t identifier)
{
  return ua::NodeId{ns, identifier};
}

// A scripted Browse page whose single reference names @p dataType as the DataType behind the encoding.
FakeWireOps::BrowsePage encoding_to_data_type_page(ua::NodeId dataType)
{
  FakeWireOps::BrowsePage page;
  ua::ReferenceDescription reference;
  reference.node_id().node_id() = std::move(dataType);
  page.references.push_back(std::move(reference));
  return page;
}

// A Read response with one Good, non-empty DataValue (models "DataTypeDefinition present").
ua::Result<ua::ReadResponse> definition_present()
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::int32_t{7}}});
  return ua::Result<ua::ReadResponse>{std::move(response)};
}

// A Read response with one bad, empty DataValue (models "DataTypeDefinition absent").
ua::Result<ua::ReadResponse> definition_absent()
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::StatusCode{ua::Status::BadAttributeIdInvalid}});
  return ua::Result<ua::ReadResponse>{std::move(response)};
}

// A transport-Good Read response whose ResponseHeader.serviceResult is Bad and whose results[] is EMPTY (a
// legal service-fault shape). This is the case the per-item DataValue.status() checks never inspect, so
// without the facade flatten it is masked as "definition/dictionary absent".
ua::Result<ua::ReadResponse> read_service_fault(ua::Status status)
{
  ua::ReadResponse response;
  response.response_header().service_result() = ua::StatusCode{status};
  return ua::Result<ua::ReadResponse>{std::move(response)};
}

std::shared_ptr<const ua::client::NamespaceTable> namespaces_with(const std::string& customUri)
{
  auto result =
    ua::client::NamespaceTable::create({"http://opcfoundation.org/UA/", customUri}, std::nullopt, 1);
  return result.value();
}

// --- server-discovered DataTypeDefinition helpers (Slice T1(b) / CL-ADDRSP-013) -----------------

// A StructureDefinition of `fieldCount` scalar Int32 fields named "F0".."F<n-1>". Used to model the
// DataTypeDefinition a server publishes for a custom Structure.
ua::StructureDefinition make_structure_definition(std::size_t fieldCount)
{
  ua::StructureDefinition definition;
  definition.structure_type() = ua::StructureType::Structure;
  definition.base_data_type() = ua::NodeId{0, static_cast<std::uint32_t>(ua::DataTypeId::Structure)};
  ua::Array<ua::StructureField> fields;
  fields.reserve(fieldCount);
  for (std::size_t i = 0; i < fieldCount; ++i)
  {
    ua::StructureField field;
    field.name() = ua::String{"F" + std::to_string(i)};
    field.data_type() = ua::NodeId{0, static_cast<std::uint32_t>(ua::DataTypeId::Int32)};
    field.value_rank() = -1;
    fields.push_back(std::move(field));
  }
  definition.fields() = std::move(fields);
  return definition;
}

// A StructureWithOptionalFields definition with `optionalCount` OPTIONAL scalar Int32 fields - models a
// server publishing a type whose optional-field presence mask would exceed the 32-bit encoding-mask width.
ua::StructureDefinition make_optional_fields_definition(std::size_t optionalCount)
{
  ua::StructureDefinition definition;
  definition.structure_type() = ua::StructureType::StructureWithOptionalFields;
  definition.base_data_type() = ua::NodeId{0, static_cast<std::uint32_t>(ua::DataTypeId::Structure)};
  ua::Array<ua::StructureField> fields;
  fields.reserve(optionalCount);
  for (std::size_t i = 0; i < optionalCount; ++i)
  {
    ua::StructureField field;
    field.name() = ua::String{"O" + std::to_string(i)};
    field.data_type() = ua::NodeId{0, static_cast<std::uint32_t>(ua::DataTypeId::Int32)};
    field.value_rank() = -1;
    field.is_optional() = true;
    fields.push_back(std::move(field));
  }
  definition.fields() = std::move(fields);
  return definition;
}

// A Read response whose single DataValue carries `definition` as its Value (a DataTypeDefinition
// ExtensionObject the client decoder materialises to a concrete StructureDefinition / EnumDefinition).
template<class Definition>
ua::Result<ua::ReadResponse> definition_response(Definition definition)
{
  ua::ReadResponse response;
  response.results().push_back(ua::DataValue{ua::Variant{std::move(definition)}});
  return ua::Result<ua::ReadResponse>{std::move(response)};
}

ua::EncodingLimits codec_limits()
{
  return ua::make_encoding_limits(ua::ApplicationConfig::load_default());
}

// Round-trips the field payload of `prototype` (a DynamicStructure decoder installed by the resolver):
// clones it, decodes the given int32 into its first field via the binary codec, and returns the value.
// Proves the installed decoder actually decodes a body, not merely that it is non-null.
std::int32_t decode_first_int32_field(const ua::Structure& prototype, std::int32_t value)
{
  // Encode a matching instance's field payload.
  auto source = prototype.clone();
  auto* sourceStruct = dynamic_cast<ua::DynamicStructure*>(source.get());
  EXPECT_NE(sourceStruct, nullptr);
  sourceStruct->field(0) = ua::Variant{value};

  ua::memory_stream_device::Dynamic device;
  ua::MemoryStream stream{device};
  ua::UaBinaryEncoder binaryEncoder{ua::CodecNamespaceContext{}, stream};
  ua::Encoder encoder{binaryEncoder};
  const auto depth = codec_limits().stack_depth();
  sourceStruct->encode(depth, encoder);

  // Decode it back into a FRESH clone of the installed prototype.
  stream.seek_from_start(0);
  ua::UaBinaryDecoder binaryDecoder{ua::StructureResolver{}, stream, codec_limits()};
  ua::Decoder decoder{binaryDecoder};
  auto sink = prototype.clone();
  auto* sinkStruct = dynamic_cast<ua::DynamicStructure*>(sink.get());
  EXPECT_NE(sinkStruct, nullptr);
  sinkStruct->decode(codec_limits().stack_depth(), decoder);
  return sinkStruct->field(0).to<std::int32_t>().value();
}

// Captures the messages the resolver logs, so the DoS test can assert the source-tagged ErrorDetail is
// surfaced (not silently dropped) on a fail-closed build.
struct RecordingLogSink : public ua::LogSink
{
  std::vector<std::string> messages;

  void log(const ua::LogEntry& entry) override
  {
    messages.push_back(entry.message);
  }

  [[nodiscard]] bool has_message_containing(std::string_view needle) const
  {
    for (const auto& message : messages)
    {
      if (message.find(needle) != std::string::npos)
      {
        return true;
      }
    }
    return false;
  }
};

struct Fixture
{
  boost::asio::io_context ctx;
  boost::asio::strand<boost::asio::any_io_executor> strand = boost::asio::make_strand(ctx.get_executor());
  std::shared_ptr<FakeWireOps> wireOps = std::make_shared<FakeWireOps>();
  std::shared_ptr<FakeSupportOps> supportOps = std::make_shared<FakeSupportOps>();
  std::shared_ptr<RecordingLogSink> logSink = std::make_shared<RecordingLogSink>();

  ua::Logger logger()
  {
    auto level = std::make_shared<std::atomic<ua::LogLevel>>(ua::LogLevel::Trace);
    return ua::Logger{logSink, level, "type_resolver_test"};
  }

  std::shared_ptr<TypeResolver> make(TypeResolutionPolicy policy,
    std::shared_ptr<const ua::client::detail::StructureFactory> overlay = nullptr)
  {
    return TypeResolver::create(strand, wireOps, supportOps, std::move(policy), std::move(overlay), logger());
  }

  // Drains all posted work, then restarts so a later pump() (this test reuses the io_context across
  // several async steps) processes the next batch - io_context::run() returning out-of-work requires a
  // restart() before a subsequent run().
  void pump()
  {
    ctx.run();
    ctx.restart();
  }
};

// ---- construction / structural ----

// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST(TypeResolver, RegistryNeverNullAfterConstruction)
{
  Fixture f;
  auto resolver = f.make(TypeResolutionPolicy{});
  ASSERT_NE(resolver->registry(), nullptr);
  EXPECT_GE(resolver->registry()->generation(), 1U);
}

// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST(TypeResolver, PostsOntoInjectedStrandNotAPrivateOne)
{
  Fixture f;
  auto resolver = f.make(TypeResolutionPolicy{});
  EXPECT_EQ(TypeResolverTestAccess::post_strand(*resolver), f.strand);  // section 8.6: no fabricated strand
}

// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST(TypeResolver, ClientWideOverlayIsConsultedAndReStamped)
{
  Fixture f;
  auto overlay = std::make_shared<ua::client::detail::StructureFactory>();
  overlay->install(
    ua::client::detail::StructureType{node(1, 200), node(1, 100), nullptr, TypeSource::UserRegistered});
  auto resolver = f.make(TypeResolutionPolicy{}, overlay);
  // The overlay entry is folded in (consultation point) and re-stamped ClientOverlay precedence
  // (section 9.8.3).
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), TypeSource::ClientOverlay);
}

// ---- modes (Lazy defers; Eager pre-resolves) ----

// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, scope=function)
TEST(TypeResolver, LazyModeIssuesNoWireOpsAtBootstrap)
{
  Fixture f;
  TypeResolutionPolicy policy;
  policy.mode = TypeResolutionMode::Lazy;
  policy.eagerTypes = {node(1, 100)};  // present but must be ignored under Lazy
  auto resolver = f.make(policy);
  bool done = false;
  resolver->on_namespace_table_replaced_async(namespaces_with("urn:vendor"), [&done] { done = true; });
  f.pump();
  EXPECT_TRUE(done);
  EXPECT_TRUE(f.wireOps->browseRequests.empty());  // no eager scan under Lazy (decode-and-defer)
  EXPECT_EQ(f.wireOps->readCalls, 0U);
}

// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, scope=function)
TEST(TypeResolver, EagerModePreResolvesViaBrowseAndRead)
{
  Fixture f;
  TypeResolutionPolicy policy;
  policy.mode = TypeResolutionMode::Eager;
  policy.eagerTypes = {node(1, 100)};
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_present());
  auto resolver = f.make(policy);
  resolver->on_namespace_table_replaced_async(namespaces_with("urn:vendor"), [] {});
  f.pump();
  EXPECT_FALSE(f.wireOps->browseRequests.empty());  // eager scan issued the Browse
  EXPECT_GE(f.wireOps->readCalls, 1U);  // ...and the DataTypeDefinition Read
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), TypeSource::ServerDataTypeDefinition);
}

// ---- decode-and-defer resolution paths ----

// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, scope=function)
TEST(TypeResolver, ResolveViaDataTypeDefinitionTagsServerDefinition)
{
  Fixture f;
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_present());
  auto resolver = f.make(TypeResolutionPolicy{});
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  EXPECT_TRUE(outcome->is_good());
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), TypeSource::ServerDataTypeDefinition);
}

// @verifies CL-ADDRSP-011
// @relation(CL-ADDRSP-011, scope=function)
TEST(TypeResolver, ResolveViaDictionaryTagsServerDictionary)
{
  Fixture f;
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_absent());  // DataTypeDefinition absent
  f.wireOps->scriptedReadResponses.push_back(definition_present());  // dictionary has it
  TypeResolutionPolicy policy;
  policy.allowDictionaryFallback = true;
  auto resolver = f.make(policy);
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  EXPECT_TRUE(outcome->is_good());
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), TypeSource::ServerDataTypeDictionary);
}

// @verifies CL-ADDRSP-011
// (This is the fallback-disabled rejection contract: Bad_DataTypeIdUnknown chained
//  ...datatype_definition_absent_dictionary_disabled. CL-ADDRSP-013 is a DIFFERENT contract
//  - Bad_TypeMismatch for a structure-subtyped Variable missing its mandatory Definition -
//  which is a tier-2 typed-read concern and stays genuinely uncovered until that slice.)
// @relation(CL-ADDRSP-011, scope=function)
TEST(TypeResolver, DictionaryDisabledFailsClosedWhenDefinitionAbsent)
{
  Fixture f;
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_absent());
  TypeResolutionPolicy policy;
  policy.allowDictionaryFallback = false;
  auto resolver = f.make(policy);
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  EXPECT_TRUE(outcome->is_bad());
  EXPECT_EQ(outcome->status_code().value(), ua::StatusCode{ua::Status::BadDataTypeIdUnknown}.value());
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), std::nullopt);  // nothing installed
}

// A transport-Good Browse HasEncoding whose ResponseHeader.serviceResult is Bad with an empty results[]
// MUST surface the true serviceResult to the waiters, not the masked Bad_NodeIdUnknown the no-DataType
// branch would otherwise fabricate (on_browse_done serviceResult FLATTEN).
// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, scope=function)
TEST(TypeResolver, BrowseServiceFaultSurfacesServiceResultNotMasked)
{
  Fixture f;
  f.wireOps->browseHeaderServiceResult = ua::StatusCode{ua::Status::BadTooManyOperations};
  f.wireOps->browseOmitResults = true;  // empty results[]: the service-fault shape
  auto resolver = f.make(TypeResolutionPolicy{});
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  ASSERT_TRUE(outcome->is_bad());
  EXPECT_EQ(outcome->status_code().value(), ua::StatusCode{ua::Status::BadTooManyOperations}.value());
  EXPECT_NE(outcome->status_code().value(), ua::StatusCode{ua::Status::BadNodeIdUnknown}.value());
  ASSERT_NE(outcome->shared_detail(), nullptr);
  EXPECT_EQ(outcome->shared_detail()->source, "client.tier1.type_resolver.resolve");
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), std::nullopt);  // nothing installed
}

// A transport-Good DataTypeDefinition Read whose ResponseHeader.serviceResult is Bad with an empty
// results[] MUST surface the true serviceResult, NOT be masked as "definition absent -> dictionary
// fallback" (which - with a default-Good dictionary read - would fabricate a Good resolution). Dictionary
// fallback is ENABLED here precisely to prove the fault short-circuits it (on_definition_read FLATTEN).
// @verifies CL-ADDRSP-011
// @relation(CL-ADDRSP-011, scope=function)
TEST(TypeResolver, DefinitionReadServiceFaultSurfacesServiceResultNotMasked)
{
  Fixture f;
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(read_service_fault(ua::Status::BadSessionIdInvalid));
  TypeResolutionPolicy policy;
  policy.allowDictionaryFallback = true;
  auto resolver = f.make(policy);
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  ASSERT_TRUE(outcome->is_bad());
  EXPECT_EQ(outcome->status_code().value(), ua::StatusCode{ua::Status::BadSessionIdInvalid}.value());
  EXPECT_EQ(f.wireOps->readCalls, 1U);  // the fault short-circuited BEFORE any dictionary read
  ASSERT_NE(outcome->shared_detail(), nullptr);
  EXPECT_EQ(outcome->shared_detail()->source, "client.tier1.type_resolver.resolve");
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), std::nullopt);  // nothing installed
}

// A transport-Good dictionary Read whose ResponseHeader.serviceResult is Bad with an empty results[] MUST
// surface the true serviceResult, NOT the masked Bad_DataTypeIdUnknown the dictionary-absent tail would
// otherwise fabricate (on_dictionary_read FLATTEN).
// @verifies CL-ADDRSP-011
// @relation(CL-ADDRSP-011, scope=function)
TEST(TypeResolver, DictionaryReadServiceFaultSurfacesServiceResultNotMasked)
{
  Fixture f;
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_absent());  // DataTypeDefinition absent -> fallback
  f.wireOps->scriptedReadResponses.push_back(
    read_service_fault(ua::Status::BadSessionClosed));  // dict faults
  TypeResolutionPolicy policy;
  policy.allowDictionaryFallback = true;
  auto resolver = f.make(policy);
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  ASSERT_TRUE(outcome->is_bad());
  EXPECT_EQ(outcome->status_code().value(), ua::StatusCode{ua::Status::BadSessionClosed}.value());
  EXPECT_NE(outcome->status_code().value(), ua::StatusCode{ua::Status::BadDataTypeIdUnknown}.value());
  ASSERT_NE(outcome->shared_detail(), nullptr);
  EXPECT_EQ(outcome->shared_detail()->source, "client.tier1.type_resolver.dictionary_read_service_fault");
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), std::nullopt);  // nothing installed
}

// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, scope=function)
TEST(TypeResolver, AlreadyResolvedEncodingTakesFastPath)
{
  Fixture f;
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_present());
  auto resolver = f.make(TypeResolutionPolicy{});
  resolver->resolve_async(node(1, 100), nullptr, [](ua::VoidResult) {});
  f.pump();
  const std::size_t browsesAfterFirst = f.wireOps->browseRequests.size();
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  EXPECT_TRUE(outcome->is_good());
  EXPECT_EQ(f.wireOps->browseRequests.size(), browsesAfterFirst);  // no new Browse (fast path)
}

// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, scope=function)
TEST(TypeResolver, ConcurrentWaitersForSameEncodingCoalesce)
{
  Fixture f;
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_present());
  f.wireOps->deferReads = true;  // hold the DataTypeDefinition Read so the resolution stays in flight
  // No resolution deadline: this test parks a resolution deliberately, and pump() drains the io_context
  // until it is out of work - an armed deadline is work, so the default 10 s would be waited out and would
  // then settle the very waiters whose coalescing is under test. The deadline has its own coverage
  // (TypeResolver.ResolutionDeadlineSettlesParkedWaitersBadTimeout).
  auto resolver = f.make(TypeResolutionPolicy{.resolutionTimeout = std::chrono::milliseconds::zero()});
  int completions = 0;
  resolver->resolve_async(node(1, 100), nullptr, [&completions](ua::VoidResult) { ++completions; });
  f.pump();  // Browse completes; Read is deferred -> in flight
  ASSERT_EQ(TypeResolverTestAccess::in_flight_count(*resolver), 1U);
  resolver->resolve_async(node(1, 100), nullptr, [&completions](ua::VoidResult) { ++completions; });
  f.pump();
  EXPECT_EQ(TypeResolverTestAccess::waiter_count(*resolver, node(1, 100)), 2U);  // coalesced
  EXPECT_EQ(f.wireOps->browseRequests.size(), 1U);  // only one Browse for both waiters
  f.wireOps->fire_deferred_reads();
  f.pump();
  EXPECT_EQ(completions, 2);  // both waiters notified
}

// The `resolutionTimeout` deadline settles every waiter parked on one encoding rather than letting a
// server that never answers the discovery Read hold a typed read open forever (section 9.8.3). The Read is
// deferred and never fired, so the deadline is the ONLY thing that can settle the waiter: the outcome is
// not a race between the timer and a wire round trip.
// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, scope=function)
TEST(TypeResolver, ResolutionDeadlineSettlesParkedWaitersBadTimeout)
{
  Fixture f;
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_present());
  f.wireOps->deferReads = true;  // the DataTypeDefinition Read is never answered
  auto resolver = f.make(TypeResolutionPolicy{.resolutionTimeout = std::chrono::milliseconds{5}});
  std::optional<ua::VoidResult> first;
  std::optional<ua::VoidResult> second;
  resolver->resolve_async(node(1, 100), nullptr, [&first](ua::VoidResult r) { first = std::move(r); });
  resolver->resolve_async(node(1, 100), nullptr, [&second](ua::VoidResult r) { second = std::move(r); });
  // pump() drains the io_context until it is out of work; the armed deadline IS work, so this returns only
  // once the timer has fired and its handler has run.
  f.pump();

  ASSERT_TRUE(first.has_value()) << "the deadline must fail the waiter, not leave it parked";
  ASSERT_TRUE(second.has_value()) << "every coalesced waiter settles, not just the first";
  EXPECT_TRUE(first->is_bad());
  EXPECT_EQ(first->status_code().as_status(), ua::Status::BadTimeout);
  EXPECT_EQ(second->status_code().as_status(), ua::Status::BadTimeout);
  ASSERT_NE(first->shared_detail(), nullptr) << "the timeout must carry an ErrorDetail";
  EXPECT_EQ(first->shared_detail()->code, "TypeResolutionTimedOut");
  EXPECT_EQ(first->shared_detail()->source, "client.tier1.type_resolver.resolve");
  EXPECT_EQ(TypeResolverTestAccess::in_flight_count(*resolver), 0U)
    << "the timed-out resolution must be retired, so a later resolve starts afresh";
}

// A non-positive `resolutionTimeout` disables the deadline: the resolution then lives as long as the wire
// operations behind it. Without this row the disabling branch is only ever exercised incidentally by the
// tests that park a resolution on purpose, and nothing asserts that parking is what it produces.
// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, scope=function)
TEST(TypeResolver, NonPositiveResolutionTimeoutDisablesTheDeadline)
{
  Fixture f;
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_present());
  f.wireOps->deferReads = true;
  auto resolver = f.make(TypeResolutionPolicy{.resolutionTimeout = std::chrono::milliseconds::zero()});
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();  // returns out-of-work: with no deadline armed there is no timer keeping the context alive
  EXPECT_FALSE(outcome.has_value()) << "with the deadline disabled the waiter stays parked on the wire";
  EXPECT_EQ(TypeResolverTestAccess::in_flight_count(*resolver), 1U);

  f.wireOps->fire_deferred_reads();  // the wire, not a deadline, is what settles this resolution
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  EXPECT_TRUE(outcome->is_good());
}

// ---- gone-Connection / lifetime ----

// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST(TypeResolver, ResolveWhenWireInterfaceGoneFailsConnectionClosed)
{
  Fixture f;
  f.wireOps.reset();  // the Connection (wire interface) is already gone
  auto resolver = f.make(TypeResolutionPolicy{});
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  EXPECT_TRUE(outcome->is_bad());
  EXPECT_EQ(outcome->status_code().value(), ua::StatusCode{ua::Status::BadConnectionClosed}.value());
}

// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST(TypeResolver, DeferredReadAfterResolverGoneDoesNotDeref)
{
  Fixture f;
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_present());
  f.wireOps->deferReads = true;
  // No resolution deadline - see ConcurrentWaitersForSameEncodingCoalesce; this test parks a resolution too.
  auto resolver = f.make(TypeResolutionPolicy{.resolutionTimeout = std::chrono::milliseconds::zero()});
  resolver->resolve_async(node(1, 100), nullptr, [](ua::VoidResult) {});
  f.pump();  // Browse done; Read deferred (in flight)
  resolver.reset();  // section 9.8.3: destroy the resolver while a completion is pending
  f.wireOps->fire_deferred_reads();  // the Read completion lands AFTER the owner is gone
  f.pump();  // must weak-lock, find the resolver gone, and no-op - no crash / no deref
  SUCCEED();
}

// @verifies CL-ATTR-012
// @relation(CL-ATTR-012, scope=function)
TEST(TypeResolver, ResolvePostedThenResolverDestroyedBailsOnGonePath)
{
  Fixture f;
  auto resolver = f.make(TypeResolutionPolicy{});
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  resolver.reset();  // destroy BEFORE the strand turn runs
  f.pump();
  ASSERT_TRUE(outcome.has_value());  // completion-owning post fires the gone result exactly once
  EXPECT_TRUE(outcome->is_bad());
  EXPECT_EQ(outcome->status_code().value(), ua::StatusCode{ua::Status::BadConnectionClosed}.value());
}

// ---- register_types attach-or-defer (section 8.6.3) ----

// @verifies CL-ADDRSP-012
// @relation(CL-ADDRSP-012, scope=function)
TEST(TypeResolver, RegisterTypesResolvesUriToIndexAndInstalls)
{
  Fixture f;
  auto resolver = f.make(TypeResolutionPolicy{});
  resolver->on_namespace_table_replaced_async(namespaces_with("urn:vendor"), [] {});
  f.pump();
  std::optional<std::vector<RegistrationOutcome>> outcomes;
  UserTypeRegistration registration;
  registration.namespaceUri = "urn:vendor";
  registration.dataTypeIdentifier = node(0, 200);  // ns overwritten by the resolved index
  registration.binaryEncodingIdentifier = node(0, 100);
  resolver->register_types_async(
    {registration}, [&outcomes](ua::Result<std::vector<RegistrationOutcome>> r) { outcomes = r.value(); });
  f.pump();
  ASSERT_TRUE(outcomes.has_value());
  ASSERT_EQ(outcomes->size(), 1U);
  EXPECT_TRUE((*outcomes)[0].status.is_good());
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), TypeSource::UserRegistered);
}

// @verifies CL-ADDRSP-012
// @relation(CL-ADDRSP-012, scope=function)
TEST(TypeResolver, RegisterTypesParksUnknownUriAndAttachesOnNamespaceReplace)
{
  Fixture f;
  auto resolver = f.make(TypeResolutionPolicy{});  // no namespace snapshot yet
  std::optional<std::vector<RegistrationOutcome>> outcomes;
  UserTypeRegistration registration;
  registration.namespaceUri = "urn:vendor";
  registration.dataTypeIdentifier = node(0, 200);
  registration.binaryEncodingIdentifier = node(0, 100);
  resolver->register_types_async(
    {registration}, [&outcomes](ua::Result<std::vector<RegistrationOutcome>> r) { outcomes = r.value(); });
  f.pump();
  ASSERT_TRUE(outcomes.has_value());
  EXPECT_TRUE((*outcomes)[0].retainedForLaterAttach);  // parked, not lost
  EXPECT_EQ(TypeResolverTestAccess::pending_registration_count(*resolver), 1U);
  // The URI later lands: the parked registration attaches automatically.
  resolver->on_namespace_table_replaced_async(namespaces_with("urn:vendor"), [] {});
  f.pump();
  EXPECT_EQ(TypeResolverTestAccess::pending_registration_count(*resolver), 0U);
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), TypeSource::UserRegistered);
}

// ---- server-discovered decoder construction (Slice T1(b) / CL-ADDRSP-013) ----

// A server-discovered Structure (DataTypeDefinition = StructureDefinition of built-in fields) resolves to a
// NON-null decoder prototype that is a DynamicStructure and actually decodes a wire body. RED before the
// slice: finish_resolution installs a nullptr decoder, so find_by_encoding(...)->decoder stays null.
// @verifies CL-ADDRSP-013
// @relation(CL-ADDRSP-013, scope=function)
TEST(TypeResolver, ServerDiscoveredStructDefinitionInstallsNonNullDecoder)
{
  Fixture f;
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_response(make_structure_definition(2)));
  auto resolver = f.make(TypeResolutionPolicy{});
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  EXPECT_TRUE(outcome->is_good());
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), TypeSource::ServerDataTypeDefinition);

  auto registry = resolver->registry();
  ASSERT_NE(registry, nullptr);
  const auto* entry = registry->find_by_encoding(node(1, 100));
  ASSERT_NE(entry, nullptr);
  ASSERT_NE(entry->decoder, nullptr) << "a server-discovered StructureDefinition must install a decoder";
  const auto* dynamic = dynamic_cast<const ua::DynamicStructure*>(entry->decoder.get());
  ASSERT_NE(dynamic, nullptr) << "the decoder must be a DynamicStructure built from the definition";
  EXPECT_EQ(dynamic->field_count(), 2U) << "the prototype must carry the definition's field layout";
  EXPECT_EQ(decode_first_int32_field(*entry->decoder, 4242), 4242)
    << "a clone of the installed decoder must decode a field payload";
}

// A server-discovered Enumeration (DataTypeDefinition = EnumDefinition) resolves Good and provenance-tags
// ServerDataTypeDefinition, but installs NO structure decoder: enum values are plain integers that already
// decode, so there is no ExtensionObject to reify. RED-adjacent: a naive impl that tried to build a struct
// decoder from an EnumDefinition (or crashed on the dynamic_cast) fails here.
// @verifies CL-ADDRSP-013
// @relation(CL-ADDRSP-013, scope=function)
TEST(TypeResolver, ServerDiscoveredEnumDefinitionResolvesProvenanceOnly)
{
  Fixture f;
  ua::EnumDefinition enumDefinition;
  for (std::int64_t value : {std::int64_t{0}, std::int64_t{1}, std::int64_t{2}})
  {
    ua::EnumField field;
    field.name() = ua::String{"E" + std::to_string(value)};
    field.value() = value;
    enumDefinition.fields().push_back(std::move(field));
  }
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_response(std::move(enumDefinition)));
  auto resolver = f.make(TypeResolutionPolicy{});
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  EXPECT_TRUE(outcome->is_good());
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), TypeSource::ServerDataTypeDefinition);
  const auto* entry = resolver->registry()->find_by_encoding(node(1, 100));
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->decoder, nullptr) << "an enum is not an ExtensionObject-bodied structure: no decoder";
}

// A hostile / oversized StructureDefinition (field count over the DoS cap) must NOT drive unbounded
// allocation: the build fails closed (decoder stays null, type opaque), the resolution stays NON-fatal
// (Good), provenance is still installed, and a source-tagged ErrorDetail is surfaced to the log. This is
// the section 3.1-critical guard: a malicious server must not crash / hang / OOM the client via a huge
// definition.
// @verifies CL-ADDRSP-013
// @relation(CL-ADDRSP-013, scope=function)
TEST(TypeResolver, OversizedStructDefinitionStaysOpaqueNonFatal)
{
  Fixture f;
  // One field over the resolver's field-count cap (maxServerDefinitionFieldCount == 1024).
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_response(make_structure_definition(1025)));
  auto resolver = f.make(TypeResolutionPolicy{});
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  EXPECT_TRUE(outcome->is_good()) << "an over-budget definition is non-fatal - the type just stays opaque";
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), TypeSource::ServerDataTypeDefinition);
  const auto* entry = resolver->registry()->find_by_encoding(node(1, 100));
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->decoder, nullptr) << "the over-cap definition must NOT build a decoder (fail closed)";
  EXPECT_TRUE(f.logSink->has_message_containing("client.tier1.type_resolver.build_server_decoder"))
    << "the fail-closed build must surface a source-tagged ErrorDetail, never silently drop it";
}

// A hostile StructureWithOptionalFields carrying MORE than 32 optional fields must stay opaque (section 3.1):
// OPC UA Part 6 section 5.2.7 encodes optional-field presence in a SINGLE 32-bit mask, so the built
// DynamicStructure decoder would compute `1u << bit` with bit >= 32 - shift-count UB / bit-aliasing ->
// silently mis-decoded typed data from a malicious server. The build fails closed (decoder null, opaque),
// NON-fatal, with a source-tagged log.
// @verifies CL-ADDRSP-013
// @relation(CL-ADDRSP-013, scope=function)
TEST(TypeResolver, OptionalFieldsOver32StayOpaqueNonFatal)
{
  Fixture f;
  // 33 optional fields - one over the 32-bit encoding-mask width, but well under the 1024 field-count cap, so
  // it is the optional-field guard (not the field-count cap) that must reject it.
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_response(make_optional_fields_definition(33)));
  auto resolver = f.make(TypeResolutionPolicy{});
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  EXPECT_TRUE(outcome->is_good())
    << "a >32-optional-field definition is non-fatal - the type just stays opaque";
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), TypeSource::ServerDataTypeDefinition);
  const auto* entry = resolver->registry()->find_by_encoding(node(1, 100));
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->decoder, nullptr)
    << "a StructureWithOptionalFields with >32 optional fields must NOT build a decoder (fail closed): the "
       "32-bit encoding mask cannot address >32 optional fields (1u << bit, bit>=32 is shift-count UB)";
  EXPECT_TRUE(f.logSink->has_message_containing("client.tier1.type_resolver.build_server_decoder"));
}

// A server Structure whose field references ANOTHER (unresolved) custom/ExtensionObject type stays opaque:
// the nested dependency-chase is DEFERRED this slice (MVP = built-in/NS0 fields only). The whole type is
// left opaque (decoder null) rather than half-decoded, and the resolution stays Good. Pins the boundary so
// a future nested-chase change is a deliberate, test-visible decision - not a silent mis-decode.
// @verifies CL-ADDRSP-013
// @relation(CL-ADDRSP-013, scope=function)
TEST(TypeResolver, NestedCustomFieldStructStaysOpaqueDeferred)
{
  Fixture f;
  ua::StructureDefinition definition;
  definition.structure_type() = ua::StructureType::Structure;
  ua::StructureField nested;
  nested.name() = ua::String{"Inner"};
  nested.data_type() = node(1, 300);  // a custom (non-NS0) DataType - unresolved in this slice
  nested.value_rank() = -1;
  definition.fields().push_back(std::move(nested));
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  f.wireOps->scriptedReadResponses.push_back(definition_response(std::move(definition)));
  auto resolver = f.make(TypeResolutionPolicy{});
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  EXPECT_TRUE(outcome->is_good()) << "an unresolved nested field is non-fatal - the type just stays opaque";
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), TypeSource::ServerDataTypeDefinition);
  const auto* entry = resolver->registry()->find_by_encoding(node(1, 100));
  ASSERT_NE(entry, nullptr);
  EXPECT_EQ(entry->decoder, nullptr) << "the nested dependency-chase is deferred: the type stays opaque";
}

// ---- CL-ADDRSP-009 DataType subtype discovery (resolve_subtype_async) ----

ua::NodeId base_data_type()
{
  return ua::NodeId{ua::DataTypeId::BaseDataType};
}

// The resolver seeds the fixed NS0 built-in DataType hierarchy at construction, so is_subtype_of over
// built-in types is decidable SYNCHRONOUSLY (no Browse). Falsifiable: without the seed these are all nullopt.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeResolver, SeedsNs0BuiltInDataTypeHierarchy)
{
  Fixture f;
  auto resolver = f.make(TypeResolutionPolicy{});
  auto registry = resolver->registry();
  ASSERT_NE(registry, nullptr);

  EXPECT_EQ(registry->is_subtype_of(ua::NodeId{ua::DataTypeId::Int32}, ua::NodeId{ua::DataTypeId::Number}),
    std::optional<bool>{true})
    << "Int32 <: Number is decidable from the seed";
  EXPECT_EQ(registry->is_subtype_of(ua::NodeId{ua::DataTypeId::UInt32}, ua::NodeId{ua::DataTypeId::Number}),
    std::optional<bool>{true});
  EXPECT_EQ(registry->is_subtype_of(ua::NodeId{ua::DataTypeId::Double}, ua::NodeId{ua::DataTypeId::Number}),
    std::optional<bool>{true});
  EXPECT_EQ(registry->is_subtype_of(ua::NodeId{ua::DataTypeId::String}, ua::NodeId{ua::DataTypeId::Number}),
    std::optional<bool>{false})
    << "String is NOT a subtype of Number (decidable, not nullopt)";
  EXPECT_EQ(registry->is_subtype_of(
              ua::NodeId{ua::DataTypeId::Enumeration}, ua::NodeId{ua::DataTypeId::BaseDataType}),
    std::optional<bool>{true});
}

// resolve_subtype_async Browses HasSubtype (inverse) for the DataType's immediate supertype and records the
// edge, so a subsequent is_subtype_of over the published registry is decidable. Falsifiable: without the edge
// record is_subtype_of stays nullopt.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeResolver, ResolveSubtypeRecordsImmediateSupertypeEdge)
{
  Fixture f;
  auto resolver = f.make(TypeResolutionPolicy{});
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));  // supertype = ns1:200

  ua::VoidResult outcome{ua::Status::BadInternalError};
  resolver->resolve_subtype_async(
    node(1, 300), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();

  EXPECT_TRUE(outcome.is_good()) << "recording the immediate supertype must settle Good";
  EXPECT_EQ(resolver->registry()->is_subtype_of(node(1, 300), node(1, 200)), std::optional<bool>{true})
    << "the discovered edge makes ns1:300 <: ns1:200 decidable";

  ASSERT_FALSE(f.wireOps->browseRequests.empty());
  const auto& browsed = f.wireOps->browseRequests.back().nodes_to_browse();
  ASSERT_EQ(browsed.size(), 1U);
  EXPECT_EQ(browsed[0].node_id(), node(1, 300));
  EXPECT_EQ(browsed[0].browse_direction(), ua::BrowseDirection::Inverse)
    << "the supertype is the INVERSE target";
  EXPECT_EQ(browsed[0].reference_type_id(), (ua::NodeId{0, 45U})) << "HasSubtype (NS0 i=45)";
}

// BaseDataType is the hierarchy root: it has no supertype, so resolve_subtype_async settles Good WITHOUT a
// Browse (no I/O for the root).
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeResolver, ResolveSubtypeBaseDataTypeTakesFastPathNoBrowse)
{
  Fixture f;
  auto resolver = f.make(TypeResolutionPolicy{});

  ua::VoidResult outcome{ua::Status::BadInternalError};
  resolver->resolve_subtype_async(
    base_data_type(), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();

  EXPECT_TRUE(outcome.is_good());
  EXPECT_TRUE(f.wireOps->browseRequests.empty()) << "the root DataType needs no supertype Browse";
}

// A second resolution for a DataType whose edge is already recorded takes the fast path - no repeat Browse.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeResolver, ResolveSubtypeAlreadyKnownTakesFastPath)
{
  Fixture f;
  auto resolver = f.make(TypeResolutionPolicy{});
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  resolver->resolve_subtype_async(node(1, 300), nullptr, [](ua::VoidResult) {});
  f.pump();
  const std::size_t browsesAfterFirst = f.wireOps->browseRequests.size();

  ua::VoidResult outcome{ua::Status::BadInternalError};
  resolver->resolve_subtype_async(
    node(1, 300), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();

  EXPECT_TRUE(outcome.is_good());
  EXPECT_EQ(f.wireOps->browseRequests.size(), browsesAfterFirst)
    << "no repeat Browse for a known supertype edge";
}

// Two concurrent resolutions for the same DataType coalesce onto ONE Browse; both waiters settle.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeResolver, ResolveSubtypeCoalescesConcurrentWaiters)
{
  Fixture f;
  auto resolver = f.make(TypeResolutionPolicy{});
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));

  bool firstDone = false;
  bool secondDone = false;
  resolver->resolve_subtype_async(node(1, 300), nullptr, [&firstDone](ua::VoidResult) { firstDone = true; });
  resolver->resolve_subtype_async(
    node(1, 300), nullptr, [&secondDone](ua::VoidResult) { secondDone = true; });
  f.pump();

  EXPECT_TRUE(firstDone);
  EXPECT_TRUE(secondDone);
  EXPECT_EQ(f.wireOps->browseRequests.size(), 1U) << "concurrent waiters share one HasSubtype Browse";
}

// A service-level Browse fault surfaces as a bad outcome (the service status preserved, not masked) and
// records no edge.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeResolver, ResolveSubtypeBrowseServiceFaultSurfacesBad)
{
  Fixture f;
  auto resolver = f.make(TypeResolutionPolicy{});
  f.wireOps->browseHeaderServiceResult = ua::StatusCode{ua::Status::BadTooManyOperations};
  f.wireOps->browseOmitResults = true;

  ua::VoidResult outcome{};  // default Good; the fault must flip it bad
  resolver->resolve_subtype_async(
    node(1, 300), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();

  EXPECT_TRUE(outcome.is_bad());
  EXPECT_EQ(outcome.status_code().value(), ua::StatusCode{ua::Status::BadTooManyOperations}.value());
  EXPECT_EQ(resolver->registry()->is_subtype_of(node(1, 300), node(1, 200)), std::nullopt)
    << "a failed Browse records no edge";
}

// A DataType the server exposes no supertype for (empty Browse) settles Good WITHOUT an edge - the relation
// stays undecidable so the caller stops rather than looping on a supertype the server will not reveal.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeResolver, ResolveSubtypeNoSupertypeSettlesGoodWithoutEdge)
{
  Fixture f;
  auto resolver = f.make(TypeResolutionPolicy{});
  // No scripted page -> the fake returns an empty Good Browse (no references).

  ua::VoidResult outcome{ua::Status::BadInternalError};
  resolver->resolve_subtype_async(
    node(1, 300), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();

  EXPECT_TRUE(outcome.is_good()) << "no supertype is not an error - the walk simply stops";
  EXPECT_EQ(resolver->registry()->is_subtype_of(node(1, 300), node(1, 400)), std::nullopt)
    << "no edge was recorded (undecidable)";
}

// The resolver acts on the DataTypeDefinition it reads, so an Uncertain DataValue is refused
// (Bad_InternalError, ReadAnswerUncertain) rather than read as an absent definition: the dictionary fallback
// is enabled to prove no further read is issued and nothing is installed.
// @relation(AC-CL-STATUS-ROUTING-02-A-HELPER-THAT-DECODES-A-VALUE-CHECKS-ITS-STATUS, scope=function)
TEST(TypeResolver, AnUncertainDefinitionReadIsRefusedNotReadAsAbsent)
{
  Fixture f;
  f.wireOps->browsePages.push_back(encoding_to_data_type_page(node(1, 200)));
  ua::ReadResponse response;
  response.results().push_back(
    ua::DataValue{ua::Variant{std::int32_t{7}}, ua::StatusCode{ua::Status::UncertainLastUsableValue}});
  f.wireOps->scriptedReadResponses.push_back(ua::Result<ua::ReadResponse>{std::move(response)});
  f.wireOps->scriptedReadResponses.push_back(definition_present());  // the dictionary would answer
  TypeResolutionPolicy policy;
  policy.allowDictionaryFallback = true;
  auto resolver = f.make(policy);
  std::optional<ua::VoidResult> outcome;
  resolver->resolve_async(node(1, 100), nullptr, [&outcome](ua::VoidResult r) { outcome = std::move(r); });
  f.pump();
  ASSERT_TRUE(outcome.has_value());
  ASSERT_TRUE(outcome->is_bad());
  EXPECT_EQ(outcome->status_code().value(), ua::StatusCode{ua::Status::BadInternalError}.value());
  ASSERT_NE(outcome->shared_detail(), nullptr);
  EXPECT_EQ(outcome->shared_detail()->code, "ReadAnswerUncertain");
  EXPECT_EQ(
    outcome->shared_detail()->innerStatus, ua::StatusCode{ua::Status::UncertainLastUsableValue}.value());
  EXPECT_EQ(f.wireOps->readCalls, 1U) << "no dictionary read follows a refused definition read";
  EXPECT_EQ(TypeResolverTestAccess::source_of(*resolver, node(1, 100)), std::nullopt);  // nothing installed
}

}  // namespace
