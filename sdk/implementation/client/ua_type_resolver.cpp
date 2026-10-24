// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_type_resolver.h"

#include "ua_attribute_id.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_client_answer_status.h"
#include "ua_connection_ops.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_dynamic_type_registry.h"
#include "ua_enum_definition.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_exceptions.h"
#include "ua_namespace_table.h"
#include "ua_on_strand.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_to_string.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_structure.h"
#include "ua_structure_definition.h"
#include "ua_variant.h"

#include <boost/asio/post.hpp>

#include <functional>
#include <utility>

namespace ua::client::detail
{
namespace
{
// HasEncoding (NS0 i=38): the reference from a DataType to its DataTypeEncoding node.
constexpr std::uint32_t hasEncodingReferenceType = 38U;

// HasSubtype (NS0 i=45): the reference from a supertype to its subtype. Browsed INVERSE from a DataType to
// find its (single, per Part 3 section 5.8.3) immediate supertype for the client-side subtype graph
// (CL-ADDRSP-009).
constexpr std::uint32_t hasSubtypeReferenceType = 45U;

// CL-ADDRSP-009: seed the FIXED NS0 built-in DataType hierarchy (Part 6 built-in types + the abstract
// Number/Integer/UInteger/Enumeration roots) so `is_subtype_of` / `check_value_subtype` are decidable
// SYNCHRONOUSLY for the built-in types  -  no Browse round-trip for the overwhelmingly common case. Vendor /
// non-built-in DataTypes are discovered lazily via `resolve_subtype_async`. This hierarchy is invariant per
// the spec (a candidate for generation from the NS0 NodeSet later; hand-authored here as the bounded core set
//  -  OPEN-ADDRSP-009-seed).
void seed_ns0_datatype_hierarchy(StructureFactory& factory)
{
  using ua::DataTypeId;
  auto id = [](DataTypeId dataType)
  {
    return ua::NodeId{dataType};
  };
  const ua::NodeId base = id(DataTypeId::BaseDataType);
  const ua::NodeId number = id(DataTypeId::Number);
  const ua::NodeId integer = id(DataTypeId::Integer);
  const ua::NodeId uinteger = id(DataTypeId::UInteger);

  // Abstract numeric roots.
  factory.add_subtype_edge(number, base);
  factory.add_subtype_edge(integer, number);
  factory.add_subtype_edge(uinteger, number);
  factory.add_subtype_edge(id(DataTypeId::Enumeration), base);

  // Signed / unsigned integer widths.
  for (const DataTypeId signedInt :
    {DataTypeId::SByte, DataTypeId::Int16, DataTypeId::Int32, DataTypeId::Int64})
    factory.add_subtype_edge(id(signedInt), integer);
  for (const DataTypeId unsignedInt :
    {DataTypeId::Byte, DataTypeId::UInt16, DataTypeId::UInt32, DataTypeId::UInt64})
    factory.add_subtype_edge(id(unsignedInt), uinteger);

  // Floating point.
  factory.add_subtype_edge(id(DataTypeId::Float), number);
  factory.add_subtype_edge(id(DataTypeId::Double), number);

  // The remaining built-in scalar types are direct children of BaseDataType.
  for (const DataTypeId builtInScalar : {DataTypeId::Boolean,
         DataTypeId::String,
         DataTypeId::DateTime,
         DataTypeId::Guid,
         DataTypeId::ByteString,
         DataTypeId::XmlElement,
         DataTypeId::NodeId,
         DataTypeId::ExpandedNodeId,
         DataTypeId::StatusCode,
         DataTypeId::QualifiedName,
         DataTypeId::LocalizedText,
         DataTypeId::Structure,
         DataTypeId::DataValue,
         DataTypeId::DiagnosticInfo})
    factory.add_subtype_edge(id(builtInScalar), base);
}

// The DataTypeDefinition is ATTACKER-CONTROLLED wire data (a malicious / misbehaving server). A hostile
// StructureDefinition can carry a pathological field count to drive unbounded allocation: the descriptor
// and every prototype instance eagerly allocate O(field_count) (a Variant per field). The build path does
// NOT chase nested field dependencies (an unresolved field type is rejected, not recursed), so there is no
// nesting/cycle dimension to bound  -  a self-referential / cyclic field graph is simply rejected and the
// type stays opaque. Two attacker-controlled dimensions are bounded: the total field count (unbounded
// allocation) and the optional-field count (the 32-bit encoding mask  -  see below). Both fail closed
// (section 3.1).
constexpr std::size_t maxServerDefinitionFieldCount = 1024;
// A StructureWithOptionalFields encodes optional-field presence in a SINGLE 32-bit EncodingMask (OPC UA
// Part 6 section 5.2.7), so a conformant type has at most 32 optional fields; more would drive `1u << bit`
// with bit >= 32 (shift-count UB) in the built decoder. Reject over-32  to  opaque (section 3.1).
constexpr std::size_t maxOptionalFieldCount = 32;
}  // namespace

std::shared_ptr<TypeResolver> TypeResolver::create(boost::asio::strand<boost::asio::any_io_executor> strand,
  std::weak_ptr<WireOps> wireOps, std::weak_ptr<SupportOps> supportOps,
  ua::client::TypeResolutionPolicy policy, std::shared_ptr<const StructureFactory> clientWideOverlay,
  ua::Logger logger, TypeRegisteredNotifier typeRegistered)
{
  return std::shared_ptr<TypeResolver>(new TypeResolver(std::move(strand),
    std::move(wireOps),
    std::move(supportOps),
    std::move(policy),
    std::move(clientWideOverlay),
    std::move(logger),
    std::move(typeRegistered)));
}

TypeResolver::TypeResolver(boost::asio::strand<boost::asio::any_io_executor> strand,
  std::weak_ptr<WireOps> wireOps, std::weak_ptr<SupportOps> supportOps,
  ua::client::TypeResolutionPolicy policy, std::shared_ptr<const StructureFactory> clientWideOverlay,
  ua::Logger logger, TypeRegisteredNotifier typeRegistered)
  // No private strand (section 8.6): the injected `strand` is ConnectionImpl's; mExecutor (its inner
  // executor) is used only to hop a user callback OFF the strand for delivery (executor-hand-off isolation).
  : mStrand(std::move(strand)), mExecutor(mStrand.get_inner_executor()), mWireOps(std::move(wireOps)),
    mSupportOps(std::move(supportOps)), mPolicy(std::move(policy)),
    mClientWideFactory(std::move(clientWideOverlay)), mLogger(std::move(logger)),
    mTypeRegistered(std::move(typeRegistered)), mDeferGate(mPolicy.defer)
{
  // Working set starts as the built-in standard-types registry (stubbed empty this slice) merged with the
  // Client-wide overlay, re-stamped at ClientOverlay precedence (above server-discovered, below user).
  // This is the overlay CONSULTATION POINT (section 9.8.3): mClientWideFactory is now actually read.
  if (mClientWideFactory)
  {
    mClientWideFactory->for_each(
      [this](const StructureType& entry)
      {
        StructureType overlayEntry = entry;
        overlayEntry.source = TypeSource::ClientOverlay;
        mWorkingFactory.install(std::move(overlayEntry));
      });
  }
  seed_ns0_datatype_hierarchy(mWorkingFactory);  // CL-ADDRSP-009: the fixed NS0 built-in DataType hierarchy
  rebuild_registry();  // publishes generation 1 so registry() is never null after construction
}

std::function<void(ua::VoidResult)> TypeResolver::on_executor(std::function<void(ua::VoidResult)> cb) const
{
  return [executor = mExecutor, cb = std::move(cb)](ua::VoidResult result) mutable
  {
    boost::asio::post(executor,
      ua::async::guarded(
        ua::Logger{}, [cb = std::move(cb), result = std::move(result)]() mutable { cb(std::move(result)); }));
  };
}

std::function<void()> TypeResolver::on_executor_void(std::function<void()> cb) const
{
  return [executor = mExecutor, cb = std::move(cb)]() mutable
  {
    boost::asio::post(executor, ua::async::guarded(ua::Logger{}, [cb = std::move(cb)]() mutable { cb(); }));
  };
}

void TypeResolver::rebuild_registry()
{
  mGeneration += 1;
  mRegistry.store(TypeRegistry::create(mWorkingFactory, mGeneration));
}

// -------- register_types (attach-or-defer, section 8.6.3) --------

void TypeResolver::register_types_async(std::vector<UserTypeRegistration> registrations,
  std::function<void(ua::Result<std::vector<RegistrationOutcome>>)> callback)
{
  auto onExecutor = [executor = mExecutor, callback = std::move(callback)](
                      ua::Result<std::vector<RegistrationOutcome>> result) mutable
  {
    boost::asio::post(executor,
      ua::async::guarded(ua::Logger{},
        [callback = std::move(callback), result = std::move(result)]() mutable
        { callback(std::move(result)); }));
  };
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(onExecutor),
    ua::Result<std::vector<RegistrationOutcome>>{ua::Status::BadConnectionClosed,
      ua::make_error_detail("TypeResolverGone",
        "the type resolver was destroyed before register_types_async could run",
        std::string{"client.tier1.type_resolver.register_types"})},
    [registrations = std::move(registrations)](TypeResolver& self,
      std::function<void(ua::Result<std::vector<RegistrationOutcome>>)>
        completion) mutable
    {
      std::vector<RegistrationOutcome> outcomes;
      outcomes.reserve(registrations.size());
      bool anyInstalled = false;
      auto namespaces = self.mNamespaces;
      if (!namespaces)
      {
        if (auto support = self.mSupportOps.lock())
        {
          namespaces = support->namespace_table();
        }
      }
      for (auto& registration : registrations)
      {
        RegistrationOutcome outcome;
        outcome.namespaceUri = registration.namespaceUri;
        outcome.dataTypeIdentifier = registration.dataTypeIdentifier;
        std::optional<ua::client::NamespaceIndex> index;
        if (namespaces)
        {
          index = namespaces->lookup_index(registration.namespaceUri);
        }
        if (!index)
        {
          // URI absent from the current snapshot: park for a later on_namespace_table_replaced attach.
          outcome.status = ua::Status::BadNotFound;
          outcome.retainedForLaterAttach = true;
          self.mPendingUserRegistrations.push_back(std::move(registration));
          outcomes.push_back(std::move(outcome));
          continue;
        }
        ua::NodeId encodingId = registration.binaryEncodingIdentifier;
        encodingId.namespace_index() = *index;
        ua::NodeId dataTypeId = registration.dataTypeIdentifier;
        dataTypeId.namespace_index() = *index;
        const auto result = self.mWorkingFactory.register_structure_type(
          std::move(encodingId), std::move(dataTypeId), registration.decoder);
        if (result == StructureFactory::InstallResult::ShadowedByHigher)
        {
          outcome.status = ua::Status::BadAlreadyExists;
        }
        else
        {
          outcome.status = ua::Status::Good;
          anyInstalled = true;
        }
        outcomes.push_back(std::move(outcome));
      }
      if (anyInstalled)
      {
        self.rebuild_registry();
      }
      completion(ua::Result<std::vector<RegistrationOutcome>>{std::move(outcomes)});
    })();
}

// -------- Lazy decode-and-defer resolve (section 8.6.4) --------

void TypeResolver::resolve_async(ua::NodeId encodingId,
  std::shared_ptr<const ua::client::NamespaceTable> namespaces, std::function<void(ua::VoidResult)> callback)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    on_executor(std::move(callback)),
    ua::VoidResult{ua::Status::BadConnectionClosed,
      ua::make_error_detail("TypeResolverGone",
        "the type resolver was destroyed before resolve_async could run",
        std::string{"client.tier1.type_resolver.resolve"})},
    [encodingId = std::move(encodingId), namespaces = std::move(namespaces)](
      TypeResolver& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      if (self.mWorkingFactory.find_by_encoding(encodingId) != nullptr)
      {
        // Fast path: already resolved (built-in / overlay / user / earlier server discovery).
        completion(ua::VoidResult{});
        return;
      }
      auto inFlight = self.mResolutionInFlight.find(encodingId);
      if (inFlight != self.mResolutionInFlight.end())
      {
        // Coalesce: a Browse/Read for this encoding is already running  -  append this waiter.
        inFlight->second.push_back(std::move(completion));
        return;
      }
      self.mResolutionInFlight[encodingId].push_back(std::move(completion));
      self.start_resolution(encodingId, std::move(namespaces));
    })();
}

void TypeResolver::note_unresolved_async(ua::NodeId encodingId, std::function<void()> firstSeen)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [encodingId = std::move(encodingId), firstSeen = std::move(firstSeen)](TypeResolver& self) mutable
    {
      if (self.mDeferGate.record_advisory_first_seen(encodingId))
      {
        self.on_executor_void(std::move(firstSeen))();
      }
    })();
}

void TypeResolver::start_resolution(
  const ua::NodeId& encodingId, std::shared_ptr<const ua::client::NamespaceTable> /*namespaces*/)
{
  auto wireOps = mWireOps.lock();
  if (!wireOps)
  {
    // The wire interface (and the Connection behind it) is gone: bail cleanly rather than dereferencing a
    // gone owner across an async boundary (section 9.8.3). Waiters learn the Connection is gone.
    fail_resolution(encodingId,
      ua::VoidResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("TypeResolverConnectionGone",
          "the Connection was gone when type resolution started",
          std::string{"client.tier1.type_resolver.resolve"})});
    return;
  }
  arm_resolution_deadline(encodingId);
  // Browse HasEncoding (reverse) from the encoding node to find its DataType (section 8.6.4).
  ua::BrowseRequest request;
  ua::BrowseDescription browseDescription;
  browseDescription.node_id() = encodingId;
  browseDescription.browse_direction() = ua::BrowseDirection::Inverse;
  browseDescription.reference_type_id() = ua::NodeId{0, hasEncodingReferenceType};
  request.nodes_to_browse().push_back(std::move(browseDescription));
  wireOps->browse_async(std::move(request),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [encodingId](TypeResolver& self, ua::Result<ua::BrowseResponse> response)
      { self.on_browse_done(encodingId, std::move(response)); }));
}

void TypeResolver::on_browse_done(ua::NodeId encodingId, ua::Result<ua::BrowseResponse> response)
{
  // The resolver acts on the References it browses, so an Uncertain answer at any layer is refused as a Bad
  // one is; a Good subcode is consumed.
  if (!response.is_good())
  {
    const ua::StatusCode refused = answer_refused(
      response.status_code(), "ReferencesAnswerUncertain", "client.tier1.type_resolver.resolve");
    fail_resolution(encodingId,
      ua::VoidResult{refused,
        ua::make_error_detail("TypeResolverBrowseFailed",
          "Browse HasEncoding failed during type resolution",
          std::string{"client.tier1.type_resolver.resolve"},
          refused)});
    return;
  }
  // Facade flatten: the wire funnel returns the BrowseResponse verbatim; a bad ResponseHeader.serviceResult
  // is a service-level failure surfaced to the waiters as bad, preserving the exact service status +
  // ErrorDetail. Without this an empty results[] masks the fault as Bad_NodeIdUnknown (no-DataType branch
  // below).
  const ua::StatusCode serviceResult = response.value().response_header().service_result();
  if (!serviceResult.is_good())
  {
    const ua::StatusCode refused =
      answer_refused(serviceResult, "ReferencesAnswerUncertain", "client.tier1.type_resolver.resolve");
    fail_resolution(encodingId,
      ua::VoidResult{refused,
        ua::make_error_detail("TypeResolverBrowseServiceFault",
          "Browse HasEncoding returned a service-level fault during type resolution",
          std::string{"client.tier1.type_resolver.resolve"},
          refused)});
    return;
  }
  const auto& results = response.value().results();
  if (!results.empty() && results[0].status_code().is_uncertain())
  {
    const ua::StatusCode refused = uncertain_answer_refused(
      results[0].status_code(), "ReferencesAnswerUncertain", "client.tier1.type_resolver.resolve");
    fail_resolution(encodingId, ua::VoidResult{refused});
    return;
  }
  if (results.empty() || results[0].references().empty())
  {
    fail_resolution(encodingId,
      ua::VoidResult{ua::Status::BadNodeIdUnknown,
        ua::make_error_detail("TypeResolverNoDataType",
          "Browse HasEncoding returned no DataType for the encoding",
          std::string{"client.tier1.type_resolver.resolve"})});
    return;
  }
  ua::NodeId dataTypeId = results[0].references()[0].node_id().node_id();
  auto wireOps = mWireOps.lock();
  if (!wireOps)
  {
    fail_resolution(encodingId,
      ua::VoidResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("TypeResolverConnectionGone",
          "the Connection was gone before the DataTypeDefinition read",
          std::string{"client.tier1.type_resolver.resolve"})});
    return;
  }
  // Read the DataTypeDefinition attribute of the DataType (section 8.6.4).
  ua::ReadRequest request;
  ua::ReadValueId value;
  value.node_id() = dataTypeId;
  value.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::DataTypeDefinition);
  request.nodes_to_read().push_back(std::move(value));
  wireOps->read_async(std::move(request),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [encodingId, dataTypeId](TypeResolver& self, ua::Result<ua::ReadResponse> readResponse)
      { self.on_definition_read(encodingId, dataTypeId, std::move(readResponse)); }));
}

void TypeResolver::on_definition_read(
  ua::NodeId encodingId, ua::NodeId dataTypeId, ua::Result<ua::ReadResponse> response)
{
  // Facade flatten: a bad ResponseHeader.serviceResult is a service-level failure surfaced as a hard fault,
  // NOT the benign "DataTypeDefinition absent -> fall back" signal (a Good response with an absent/empty
  // Value). A bad serviceResult with empty results[] never reaches the per-item inspection below, so without
  // this it would be masked as absence and mis-routed to the dictionary fallback.
  // The resolver acts on the definition it reads, so an Uncertain answer (the result, the ServiceResult or
  // the DataValue) is refused rather than read as an absent definition.
  if (response.is_uncertain())
  {
    const ua::StatusCode refused = uncertain_answer_refused(
      response.status_code(), "ReadAnswerUncertain", "client.tier1.type_resolver.resolve");
    fail_resolution(encodingId, ua::VoidResult{refused});
    return;
  }
  if (response.is_good())
  {
    const ua::StatusCode serviceResult = response.value().response_header().service_result();
    if (!serviceResult.is_good())
    {
      const ua::StatusCode refused =
        answer_refused(serviceResult, "ReadAnswerUncertain", "client.tier1.type_resolver.resolve");
      fail_resolution(encodingId,
        ua::VoidResult{refused,
          ua::make_error_detail("TypeResolverDefinitionReadServiceFault",
            "the Read of the DataTypeDefinition attribute returned a service-level fault",
            std::string{"client.tier1.type_resolver.resolve"},
            refused)});
      return;
    }
    if (!response.value().results().empty())
    {
      const auto& responseStatus = response.value().results()[0].status();
      if (responseStatus.has_value() && responseStatus.value().is_uncertain())
      {
        const ua::StatusCode refused = uncertain_answer_refused(
          responseStatus.value(), "ReadAnswerUncertain", "client.tier1.type_resolver.resolve");
        fail_resolution(encodingId, ua::VoidResult{refused});
        return;
      }
    }
  }
  bool definitionPresent = false;
  const ua::Variant* definitionValue = nullptr;
  if (response.is_good() && !response.value().results().empty())
  {
    const auto& dataValue = response.value().results()[0];
    const auto& definitionStatus = dataValue.status();
    const bool statusGood = !definitionStatus.has_value() || definitionStatus.value().is_good();
    definitionPresent = statusGood && !dataValue.value().empty();
    if (definitionPresent)
    {
      definitionValue = &dataValue.value();
    }
  }
  if (definitionPresent)
  {
    // Decode the DataTypeDefinition Variant and build a real decode prototype (Slice T1(b) /
    // CL-ADDRSP-013). A StructureDefinition (or Union) yields a clone-able DynamicStructure/DynamicUnion
    // decoder; an EnumDefinition installs provenance-only (an enum value is a plain integer, not an
    // ExtensionObject-bodied structure, so there is no structure decoder to reify). A build failure is
    // NON-fatal: the type stays opaque (null decoder) and the resolution still succeeds.
    std::shared_ptr<const ua::Structure> decoder;
    if (const auto* structureDefinition = definitionValue->try_as<ua::StructureDefinition>())
    {
      decoder = build_server_structure_decoder(encodingId, dataTypeId, *structureDefinition);
    }
    else if (definitionValue->try_as<ua::EnumDefinition>() == nullptr)
    {
      // Neither a StructureDefinition nor an EnumDefinition: an unexpected DataTypeDefinition shape. Stay
      // opaque (provenance-only) rather than mis-decoding it.
      mLogger.debug(
        "type_resolver: server DataTypeDefinition is neither a StructureDefinition nor an EnumDefinition - "
        "leaving type opaque [client.tier1.type_resolver.build_server_decoder]");
    }
    finish_resolution(
      encodingId, std::move(dataTypeId), TypeSource::ServerDataTypeDefinition, std::move(decoder));
    return;
  }
  // DataTypeDefinition absent (CL-ADDRSP-011): consult the deprecated dictionary only when allowed.
  if (!mPolicy.allowDictionaryFallback)
  {
    fail_resolution(encodingId,
      ua::VoidResult{ua::Status::BadDataTypeIdUnknown,
        ua::make_error_detail("TypeResolverDefinitionAbsent",
          "DataTypeDefinition absent and dictionary fallback disabled",
          std::string{"client.tier1.type_resolver.datatype_definition_absent_dictionary_disabled"})});
    return;
  }
  auto wireOps = mWireOps.lock();
  if (!wireOps)
  {
    fail_resolution(encodingId,
      ua::VoidResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("TypeResolverConnectionGone",
          "the Connection was gone before the dictionary read",
          std::string{"client.tier1.type_resolver.resolve"})});
    return;
  }
  // Deprecated DataTypeDictionary fallback (section 8.6.4). Modelled as one Read of the dictionary-bearing
  // node; the full HasComponent  to  DataTypeSystem walk is a later slice.
  ua::ReadRequest request;
  ua::ReadValueId value;
  value.node_id() = dataTypeId;
  value.attribute_id() = static_cast<std::uint32_t>(ua::AttributeId::Value);
  request.nodes_to_read().push_back(std::move(value));
  wireOps->read_async(std::move(request),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [encodingId, dataTypeId](TypeResolver& self, ua::Result<ua::ReadResponse> dictionaryResponse)
      { self.on_dictionary_read(encodingId, dataTypeId, std::move(dictionaryResponse)); }));
}

void TypeResolver::on_dictionary_read(
  ua::NodeId encodingId, ua::NodeId dataTypeId, ua::Result<ua::ReadResponse> response)
{
  // Facade flatten: a bad ResponseHeader.serviceResult is a service-level failure surfaced as a hard fault,
  // NOT the benign "dictionary absent" signal. A bad serviceResult with empty results[] never reaches the
  // per-item inspection below, so without this it would be masked as Bad_DataTypeIdUnknown (dictionary-absent
  // branch at the tail).
  // The resolver acts on the dictionary it reads, so an Uncertain answer (the result, the ServiceResult or
  // the DataValue) is refused rather than read as an absent dictionary.
  if (response.is_uncertain())
  {
    const ua::StatusCode refused = uncertain_answer_refused(response.status_code(),
      "ReadAnswerUncertain",
      "client.tier1.type_resolver.dictionary_read_service_fault");
    fail_resolution(encodingId, ua::VoidResult{refused});
    return;
  }
  if (response.is_good())
  {
    const ua::StatusCode serviceResult = response.value().response_header().service_result();
    if (!serviceResult.is_good())
    {
      const ua::StatusCode refused = answer_refused(
        serviceResult, "ReadAnswerUncertain", "client.tier1.type_resolver.dictionary_read_service_fault");
      fail_resolution(encodingId,
        ua::VoidResult{refused,
          ua::make_error_detail("TypeResolverDictionaryReadServiceFault",
            "the Read of the DataTypeDictionary returned a service-level fault",
            std::string{"client.tier1.type_resolver.dictionary_read_service_fault"},
            refused)});
      return;
    }
    if (!response.value().results().empty())
    {
      const auto& responseStatus = response.value().results()[0].status();
      if (responseStatus.has_value() && responseStatus.value().is_uncertain())
      {
        const ua::StatusCode refused = uncertain_answer_refused(responseStatus.value(),
          "ReadAnswerUncertain",
          "client.tier1.type_resolver.dictionary_read_service_fault");
        fail_resolution(encodingId, ua::VoidResult{refused});
        return;
      }
    }
  }
  bool present = false;
  if (response.is_good() && !response.value().results().empty())
  {
    const auto& dataValue = response.value().results()[0];
    const auto& dictionaryStatus = dataValue.status();
    const bool statusGood = !dictionaryStatus.has_value() || dictionaryStatus.value().is_good();
    present = statusGood && !dataValue.value().empty();
  }
  if (present)
  {
    finish_resolution(encodingId, std::move(dataTypeId), TypeSource::ServerDataTypeDictionary);
    return;
  }
  fail_resolution(encodingId,
    ua::VoidResult{ua::Status::BadDataTypeIdUnknown,
      ua::make_error_detail("TypeResolverDictionaryAbsent",
        "the structure could not be resolved via DataTypeDefinition or DataTypeDictionary",
        std::string{"client.tier1.type_resolver.dictionary_walk_failed"})});
}

void TypeResolver::finish_resolution(const ua::NodeId& encodingId, ua::NodeId dataTypeId, TypeSource source,
  std::shared_ptr<const ua::Structure> decoder)
{
  // Install a provenance-correct entry and publish a fresh registry generation so the codec sees it
  // lock-free. @p decoder is the clone-able decode prototype (server-discovered StructureDefinition, Slice
  // T1(b)); it is null for the dictionary path (still a later slice), for enum/option-set definitions
  // (no ExtensionObject body to reify), and for a fail-closed decoder build (the type stays opaque).
  // The type name is the decoder's own, when one was built; enum / option-set resolutions install no
  // decoder, so they are announced under their DataType id instead.
  std::string typeName = decoder ? std::string{decoder->type_name()} : ua::to_string(dataTypeId);
  mWorkingFactory.install(StructureType{std::move(dataTypeId), encodingId, std::move(decoder), source});
  rebuild_registry();
  if (mTypeRegistered)
  {
    mTypeRegistered(encodingId, std::move(typeName));
  }
  // Advisory coalescing on the resolved path, bounded per section 9.6.18.4.
  fail_resolution(encodingId, ua::VoidResult{});
}

std::shared_ptr<const ua::Structure> TypeResolver::build_server_structure_decoder(
  const ua::NodeId& encodingId, const ua::NodeId& dataTypeId, const ua::StructureDefinition& definition)
{
  // DoS guard: bound the attacker-controlled field count BEFORE any allocation-driving build. Fail closed  -
  // the type stays opaque (non-fatal), it just does not reify.
  if (definition.fields().size() > maxServerDefinitionFieldCount)
  {
    mLogger.warning(
      "type_resolver: server DataTypeDefinition field count {} exceeds cap {} - leaving type opaque "
      "[client.tier1.type_resolver.build_server_decoder]",
      definition.fields().size(),
      maxServerDefinitionFieldCount);
    return nullptr;
  }
  // Correctness/robustness guard (section 3.1): a StructureWithOptionalFields encodes optional-field presence
  // in a SINGLE 32-bit EncodingMask (OPC UA Part 6 section 5.2.7), so a conformant type carries AT MOST 32
  // optional fields. A malicious/misbehaving server can publish more; the built DynamicStructure decoder
  // would then compute `1u << optionalBitIndex` with optionalBitIndex >= 32  -  shift-count UB (bit-aliasing
  // on x86  to wrong presence bits  to  silently mis-decoded typed data delivered to the caller). Fail closed
  // to opaque.
  if (definition.structure_type() == ua::StructureType::StructureWithOptionalFields)
  {
    std::size_t optionalFieldCount = 0;
    for (const auto& field : definition.fields())
    {
      if (field.is_optional())
      {
        ++optionalFieldCount;
      }
    }
    if (optionalFieldCount > maxOptionalFieldCount)
    {
      mLogger.warning(
        "type_resolver: server StructureWithOptionalFields has {} optional fields (> {}, the 32-bit "
        "encoding-mask width) - leaving type opaque [client.tier1.type_resolver.build_server_decoder]",
        optionalFieldCount,
        maxOptionalFieldCount);
      return nullptr;
    }
  }
  try
  {
    // A local registry drives the build in isolation (it is discarded after the prototype is extracted).
    // Index-based ExpandedNodeIds (empty namespace URI) keep everything in the local-index space, so no
    // NamespaceUriLookup is needed and `register_all_with`'s non-NS0 guard never trips. `register_type`
    // eagerly resolves field dependencies against the (empty) local registry: any field whose DataType is
    // a nested / custom / non-primitive ExtensionObject type is unresolved and REJECTED  -  the
    // dependency-chase is DEFERRED this slice (MVP = built-in / NS0 scalar fields), so such a type stays
    // fully opaque rather than half-decoded.
    ua::DynamicTypeRegistry dynamicRegistry;
    const ua::VoidResult registered = dynamicRegistry.register_type(definition,
      ua::ExpandedNodeId{dataTypeId},
      ua::ExpandedNodeId{encodingId},
      ua::String{"ServerDiscoveredType"});
    if (registered.is_bad())
    {
      const auto detail = registered.shared_detail();
      mLogger.debug(
        "type_resolver: server DataTypeDefinition has an unresolved field dependency ({}) - deferring the "
        "nested-type chase, leaving type opaque [client.tier1.type_resolver.build_server_decoder]",
        detail ? detail->code : std::string{"UnresolvedFieldDependency"});
      return nullptr;
    }
    std::shared_ptr<const ua::Structure> prototype;
    dynamicRegistry.register_all_with(
      [&encodingId, &prototype](
        const ua::NodeId& registeredEncoding, std::function<ua::unique_ptr<ua::Structure>()> factory)
      {
        if (registeredEncoding == encodingId)
        {
          prototype = std::shared_ptr<const ua::Structure>(factory());
        }
      });
    return prototype;
  }
  catch (const ua::UaException& ex)
  {
    // A malformed definition can throw out of the builder (for example an out-of-range field index). Fail
    // closed  -  never let a wire definition abort resolution.
    mLogger.warning(
      "type_resolver: building a decoder from the server DataTypeDefinition failed ({}) - leaving type "
      "opaque [client.tier1.type_resolver.build_server_decoder]",
      ex.what());
    return nullptr;
  }
}

void TypeResolver::arm_resolution_deadline(const ua::NodeId& encodingId)
{
  // A non-positive timeout disables the deadline: the resolution then lives as long as the wire operations
  // behind it, which is the pre-deadline behaviour.
  if (mPolicy.resolutionTimeout <= std::chrono::milliseconds::zero())
  {
    return;
  }
  auto timer = std::make_shared<boost::asio::steady_timer>(mStrand);
  timer->expires_after(mPolicy.resolutionTimeout);
  mResolutionTimers[encodingId] = timer;
  // The timer's executor IS the strand, so the handler lands there. Capturing `timer` keeps it alive across
  // the settle that erases the map entry; the capture cycle breaks when the handler runs.
  timer->async_wait(
    [weak = weak_from_this(), encodingId, timer](const boost::system::error_code& error)
    {
      if (error)
      {
        return;  // cancelled - the resolution settled first
      }
      auto self = weak.lock();
      if (!self)
      {
        return;
      }
      self->fail_resolution(encodingId,
        ua::VoidResult{ua::Status::BadTimeout,
          ua::make_error_detail("TypeResolutionTimedOut",
            "type resolution exceeded the configured resolutionTimeout",
            std::string{"client.tier1.type_resolver.resolve"})});
    });
}

void TypeResolver::fail_resolution(const ua::NodeId& encodingId, ua::VoidResult result)
{
  if (auto timer = mResolutionTimers.find(encodingId); timer != mResolutionTimers.end())
  {
    timer->second->cancel();
    mResolutionTimers.erase(timer);
  }
  auto inFlight = mResolutionInFlight.find(encodingId);
  if (inFlight == mResolutionInFlight.end())
  {
    return;
  }
  std::vector<ResolutionWaiter> waiters = std::move(inFlight->second);
  mResolutionInFlight.erase(inFlight);
  for (const auto& waiter : waiters)
  {
    if (waiter)
    {
      waiter(result);
    }
  }
}

// --- DataType subtype discovery (CL-ADDRSP-009) ---

void TypeResolver::resolve_subtype_async(ua::NodeId dataTypeId,
  std::shared_ptr<const ua::client::NamespaceTable> /*namespaces*/,
  std::function<void(ua::VoidResult)> callback)
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    on_executor(std::move(callback)),
    ua::VoidResult{ua::Status::BadConnectionClosed,
      ua::make_error_detail("TypeResolverGone",
        "the type resolver was destroyed before resolve_subtype_async could run",
        std::string{"client.tier1.type_resolver.resolve_subtype"})},
    [dataTypeId = std::move(dataTypeId)](
      TypeResolver& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      // BaseDataType is the hierarchy root  -  it has no supertype to discover.
      if (dataTypeId == ua::NodeId{ua::DataTypeId::BaseDataType})
      {
        completion(ua::VoidResult{});
        return;
      }
      // Fast path: the immediate supertype edge is already recorded (a prior discovery / an overlay seed).
      if (self.mWorkingFactory.immediate_supertype(dataTypeId).has_value())
      {
        completion(ua::VoidResult{});
        return;
      }
      auto inFlight = self.mSubtypeInFlight.find(dataTypeId);
      if (inFlight != self.mSubtypeInFlight.end())
      {
        // Coalesce: a HasSubtype Browse for this DataType is already running  -  append this waiter.
        inFlight->second.push_back(std::move(completion));
        return;
      }
      self.mSubtypeInFlight[dataTypeId].push_back(std::move(completion));
      self.start_subtype_resolution(dataTypeId);
    })();
}

void TypeResolver::start_subtype_resolution(const ua::NodeId& dataTypeId)
{
  auto wireOps = mWireOps.lock();
  if (!wireOps)
  {
    settle_subtype_resolution(dataTypeId,
      ua::VoidResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("TypeResolverConnectionGone",
          "the Connection was gone when subtype resolution started",
          std::string{"client.tier1.type_resolver.resolve_subtype"})});
    return;
  }
  // Browse HasSubtype INVERSE from the DataType to find its (single) immediate supertype (section 5.8.3).
  ua::BrowseRequest request;
  ua::BrowseDescription browseDescription;
  browseDescription.node_id() = dataTypeId;
  browseDescription.browse_direction() = ua::BrowseDirection::Inverse;
  browseDescription.reference_type_id() = ua::NodeId{0, hasSubtypeReferenceType};
  request.nodes_to_browse().push_back(std::move(browseDescription));
  wireOps->browse_async(std::move(request),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [dataTypeId](TypeResolver& self, ua::Result<ua::BrowseResponse> response)
      { self.on_subtype_browse_done(dataTypeId, std::move(response)); }));
}

void TypeResolver::on_subtype_browse_done(ua::NodeId dataTypeId, ua::Result<ua::BrowseResponse> response)
{
  // The resolver records the supertype it browses, so an Uncertain answer at any layer is refused as a Bad
  // one is; a Good subcode is consumed.
  if (!response.is_good())
  {
    const ua::StatusCode refused = answer_refused(
      response.status_code(), "ReferencesAnswerUncertain", "client.tier1.type_resolver.resolve_subtype");
    settle_subtype_resolution(dataTypeId,
      ua::VoidResult{refused,
        ua::make_error_detail("TypeResolverSubtypeBrowseFailed",
          "Browse HasSubtype failed during subtype resolution",
          std::string{"client.tier1.type_resolver.resolve_subtype"},
          refused)});
    return;
  }
  const ua::StatusCode serviceResult = response.value().response_header().service_result();
  if (!serviceResult.is_good())
  {
    const ua::StatusCode refused = answer_refused(
      serviceResult, "ReferencesAnswerUncertain", "client.tier1.type_resolver.resolve_subtype");
    settle_subtype_resolution(dataTypeId,
      ua::VoidResult{refused,
        ua::make_error_detail("TypeResolverSubtypeBrowseServiceFault",
          "Browse HasSubtype returned a service-level fault during subtype resolution",
          std::string{"client.tier1.type_resolver.resolve_subtype"},
          refused)});
    return;
  }
  const auto& results = response.value().results();
  if (!results.empty() && results[0].status_code().is_uncertain())
  {
    const ua::StatusCode refused = uncertain_answer_refused(
      results[0].status_code(), "ReferencesAnswerUncertain", "client.tier1.type_resolver.resolve_subtype");
    settle_subtype_resolution(dataTypeId, ua::VoidResult{refused});
    return;
  }
  if (!results.empty() && !results[0].references().empty())
  {
    // A DataType has a single immediate supertype (section 5.8.3); take the first HasSubtype-inverse target
    // and record the edge, publishing a bumped generation so a re-query of is_subtype_of sees it. If the
    // server exposes no supertype (empty), we settle Good WITHOUT an edge  -  the relation stays undecidable
    // so the caller stops (it must not loop forever chasing a supertype the server won't reveal).
    const ua::NodeId supertype = results[0].references()[0].node_id().node_id();
    mWorkingFactory.add_subtype_edge(dataTypeId, supertype);
    rebuild_registry();
  }
  settle_subtype_resolution(dataTypeId, ua::VoidResult{});
}

void TypeResolver::settle_subtype_resolution(const ua::NodeId& dataTypeId, ua::VoidResult result)
{
  auto inFlight = mSubtypeInFlight.find(dataTypeId);
  if (inFlight == mSubtypeInFlight.end())
  {
    return;
  }
  std::vector<ResolutionWaiter> waiters = std::move(inFlight->second);
  mSubtypeInFlight.erase(inFlight);
  for (const auto& waiter : waiters)
  {
    if (waiter)
    {
      waiter(result);
    }
  }
}

// -------- Namespace hook (bootstrap / reconnect, section 8.6.3) --------

void TypeResolver::on_namespace_table_replaced_async(
  std::shared_ptr<const ua::client::NamespaceTable> snapshot, std::function<void()> callback)
{
  ua::async::post_borrowing(
    this,
    mStrand,
    mLogger,
    [executor = mExecutor, callback = std::move(callback)](ua::VoidResult) mutable
    {
      boost::asio::post(executor,
        ua::async::guarded(ua::Logger{}, [callback = std::move(callback)]() mutable { callback(); }));
    },
    ua::VoidResult{},
    [snapshot = std::move(snapshot)](
      TypeResolver& self, std::function<void(ua::VoidResult)> completion) mutable
    {
      self.mNamespaces = snapshot;
      // Attach any parked user registrations whose URI is now in the snapshot (section 8.6.3
      // attach-or-defer).
      bool anyInstalled = false;
      std::vector<UserTypeRegistration> stillPending;
      for (auto& registration : self.mPendingUserRegistrations)
      {
        std::optional<ua::client::NamespaceIndex> index;
        if (self.mNamespaces)
        {
          index = self.mNamespaces->lookup_index(registration.namespaceUri);
        }
        if (!index)
        {
          stillPending.push_back(std::move(registration));
          continue;
        }
        ua::NodeId encodingId = registration.binaryEncodingIdentifier;
        encodingId.namespace_index() = *index;
        ua::NodeId dataTypeId = registration.dataTypeIdentifier;
        dataTypeId.namespace_index() = *index;
        if (self.mWorkingFactory.register_structure_type(std::move(encodingId),
              std::move(dataTypeId),
              registration.decoder) == StructureFactory::InstallResult::Installed)
        {
          anyInstalled = true;
        }
      }
      self.mPendingUserRegistrations = std::move(stillPending);
      if (anyInstalled)
      {
        self.rebuild_registry();
      }
      if (self.mPolicy.mode == ua::client::TypeResolutionMode::Eager ||
          self.mPolicy.mode == ua::client::TypeResolutionMode::EagerThenLazy)
      {
        self.run_eager_scan();
      }
      completion(ua::VoidResult{});
    })();
}

void TypeResolver::run_eager_scan()
{
  // Bounded connect-time scan (section 9.6.18.7): each declared eager type is resolved (best-effort) up to
  // the eagerScanBudget. eagerTypes are encoding NodeIds.
  std::size_t scanned = 0;
  for (const auto& encodingId : mPolicy.eagerTypes)
  {
    if (scanned >= mPolicy.eagerScanBudget)
    {
      mLogger.warning(
        "type_resolver: eager scan hit budget {} - remaining types resolve lazily", mPolicy.eagerScanBudget);
      break;
    }
    if (mWorkingFactory.find_by_encoding(encodingId) != nullptr)
    {
      continue;  // already resolved
    }
    if (mResolutionInFlight.find(encodingId) != mResolutionInFlight.end())
    {
      continue;  // already in flight
    }
    mResolutionInFlight[encodingId];  // install an empty (no-waiter) in-flight slot
    start_resolution(encodingId, mNamespaces);
    ++scanned;
  }
}

}  // namespace ua::client::detail
