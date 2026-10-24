// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_attribute_service_set.h"
#include "ua_verdict_rules.h"

#include "ua_attribute_wire.h"
#include "ua_access_control.h"
#include "ua_on_strand.h"
#include "ua_callback_safety.h"
#include "ua_address_space.h"
#include "ua_audit_event_payload.h"
#include "ua_audit_write_update_event_payload.h"
#include "ua_diagnostic_collector.h"
#include "ua_data_access_projection.h"
#include "ua_datatype_id.h"
#include "ua_string_lexical_validation.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_enum_definition.h"
#include "ua_enum_field.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_event_bus.h"
#include "ua_instance_utils.h"
#include "ua_numeric_range_parser.h"
#include "ua_log_exception.h"
#include "ua_namespace.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor_route.h"
#include "ua_node_utilities.h"
#include "ua_option_set.h"
#include "ua_option_set_merge.h"
#include "ua_variant.h"
#include "ua_server.h"
#include "ua_server_session_info.h"
#include "ua_session_security.h"
#include "ua_service_fault.h"
#include "ua_stack_utilities.h"
#include "ua_state_machine_runtime.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include "ua_access_level_ex_type.h"
#include "ua_access_level_type.h"
#include "ua_access_restriction_type.h"
#include "ua_attribute_write_mask.h"
#include "ua_role_permission_type.h"
#include "ua_role_permissions.h"
#include "ua_service_request_info.h"
#include "ua_referencetype_id.h"
#include "ua_unknown_structure.h"
#include "ua_allow_nulls_batch.h"
#include "ua_information_model_pairs.h"
#include "ua_namespace_zero_tables.h"
#include "ua_enum_value_type.h"
#include "ua_range.h"
#include "ua_write_type_facts.h"
#include "ua_status_routing.h"

#include "fmt/format.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <map>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace ua::server
{

namespace
{

// Whether the Read service replaces a Variable's Value after reading it, with a projection keyed on its
// BrowseName in namespace 0 (FileType's UserWritable, ValueAsText, ValueAsDictionaryEntries).
bool value_is_projected(const QualifiedName& browseName)
{
  if (browseName.namespace_index() != 0)
  {
    return false;
  }
  const auto name = static_cast<std::string_view>(browseName.name());
  return name == "UserWritable" || name == "ValueAsText" || name == "ValueAsDictionaryEntries";
}

// On whose behalf a Session's read or write is made: its identity (the services build a whole CallerInfo in
// phase 3). None for a call with no Session's access control, which is the server's own.
std::optional<CallerInfo> caller_for(const std::optional<SessionAccessControl>& control)
{
  if (!control)
  {
    return std::nullopt;
  }
  CallerInfo caller;
  caller.identity = control->identity();
  return caller;
}

// Whether the Read service takes @p attributeId from the Node's description rather than its getter: only
// where the two answer the same for every Node. Read from the getters as before are DisplayName,
// Description, InverseName and DataTypeDefinition, which are resolved to the Session's locales;
// ArrayDimensions, encoded differently; a VariableType's Value, answered as its Variant alone; and
// NodeClass, DataType, ValueRank, AccessLevel, IsAbstract, Symmetric, ContainsNoLoops and EventNotifier,
// for which a Node that does not hold the Attribute fails or defaults in its getter while the description
// supplies its own default.
bool read_from_description(AttributeId attributeId)
{
  switch (attributeId)
  {
  case AttributeId::NodeId:
  case AttributeId::BrowseName:
  case AttributeId::WriteMask:
  case AttributeId::MinimumSamplingInterval:
  case AttributeId::Historizing:
  case AttributeId::Executable:
  case AttributeId::AccessLevelEx:
  case AttributeId::AccessRestrictions:
    return true;
  default:
    return false;
  }
}

/// BrowseName compare for a caller holding only the node. A Node may carry no BrowseName Attribute
/// (e.g. minimal test Objects); `get_browse_name()` reports that as an empty name, which matches no
/// expectation these callers hold, so a malformed node simply does not match. Where several
/// comparisons share one node, read the name once and compare it directly rather than calling this
/// repeatedly - each call re-reads the attribute.
bool browse_name_is(const NodeAccessor& node, uint16_t namespaceIndex, std::string_view expected)
{
  const auto browseName = node.get_browse_name();
  return browseName.namespace_index() == namespaceIndex &&
         static_cast<std::string_view>(browseName.name()) == expected;
}

using AllowNullsCallback = std::function<void(StatusCode, std::optional<bool>)>;

/// Resolves the optional AllowNulls Property and reads its Boolean Value. A missing Property means
/// the Server's existing null policy applies; every other failure remains a rich StatusCode.
void read_allow_nulls_async(
  AddressSpace addressSpace, const NodeId& variableId, AllowNullsCallback onComplete) noexcept
{
  instance_utils::find_child_variable_accessor_by_browse_name_async(addressSpace,
    variableId,
    NodeId{ReferenceTypeId::HasProperty},
    QualifiedName{0, String{"AllowNulls"}},
    [variableId, onComplete = std::move(onComplete)](VariableAccessorResult propertyResult) mutable
    {
      if (!propertyResult.is_good())
      {
        if (propertyResult.status_code().as_status() == Status::BadNodeIdUnknown)
          onComplete(StatusCode{Status::Good}, std::nullopt);
        else
          onComplete(
            ::ua::detail::lookup_failure(variableId, propertyResult.status_code(), "AttributeServiceSet"),
            std::nullopt);
        return;
      }

      auto property = std::move(propertyResult).value();
      const auto propertyId = property.get_node_id();
      ReadValueId readId;
      readId.node_id() = propertyId;
      readId.attribute_id() = utils::to_underlying(AttributeId::Value);
      property.read_value_async(0.0,
        false,
        readId,
        /*caller=*/nullptr,  // AllowNulls is a type-model fact, the same for every caller
        [propertyId, onComplete = std::move(onComplete)](DataValueResult readResult) mutable
        {
          if (!readResult.is_good())
          {
            onComplete(server::detail::not_acted_on(server::detail::readAnswerUncertain,
                         readResult.status_code(),
                         "AttributeServiceSet",
                         propertyId),
              std::nullopt);
            return;
          }
          const auto& value = readResult.value();
          // The write's null policy is decided from a Good Value only: a Bad one answers its status, and an
          // Uncertain one is refused.
          if (value.status() && !value.status()->is_good())
          {
            onComplete(
              server::detail::not_acted_on(
                server::detail::readAnswerUncertain, *value.status(), "AttributeServiceSet", propertyId),
              std::nullopt);
            return;
          }
          const auto* allowNulls = value.value().try_as<bool>();
          if (!allowNulls)
          {
            onComplete(
              StatusCode{Status::BadTypeMismatch,
                ErrorDetail::build(
                  "AllowNullsTypeMismatch", "AllowNulls Property Value is not Boolean", "AttributeServiceSet")
                  .context(ua::ContextKeys::nodeId, to_string(propertyId))},
              std::nullopt);
            return;
          }
          onComplete(StatusCode{Status::Good}, *allowNulls);
        });
    });
}

/// Encode a typed `RolePermissionType` vector back into a `RolePermissions`
/// Variant (array of Structures) for the `UserRolePermissions` /
/// `DefaultUserRolePermissions` projection.
Variant encode_role_permissions(const std::vector<RolePermissionType>& perms)
{
  Array<RefStructure<Structure>> out;
  out.payload().reserve(perms.size());
  for (const auto& perm : perms)
  {
    RefStructure<Structure> ref;
    ref = std::unique_ptr<Structure>{std::make_unique<RolePermissionType>(perm).release()};
    out.payload().push_back(std::move(ref));
  }
  return Variant{std::move(out)};
}

/// Enforces the server-side DataValue invariant at the Read wire boundary.
///
/// OPC 10000-4 section 7.11.5 requires a null Value whenever the StatusCode
/// severity is Bad.  Value sources are extension interfaces and may return a stale
/// payload alongside their failure status, so normalize immediately before the
/// DataValue is committed to the Read response.  Uncertain values remain intact.
void null_value_for_bad_status(DataValue& dataValue)
{
  const auto& valueStatus = dataValue.status();
  if (valueStatus && valueStatus.value().is_bad())
  {
    dataValue.value() = Variant{};
  }
}

/// Returns the RequestHeader of whichever request optional is engaged. Exactly one of
/// `readRequest` / `writeRequest` is engaged for the object's lifetime (selected by the
/// constructor that ran); the explicit per-optional guards make the engagement provable to the
/// static analyzer and the trailing throw is unreachable by that invariant.
const RequestHeader& active_request_header(
  const optional<ReadRequest>& readRequest, const optional<WriteRequest>& writeRequest)
{
  if (readRequest)
  {
    return readRequest->request_header();
  }
  if (writeRequest)
  {
    return writeRequest->request_header();
  }
  throw UaException{Status::BadInternalError,
    make_error_detail("NoActiveRequest", "AttributeServiceSet has no active request", "AttributeServiceSet")};
}

optional<AttributeWriteMask::Bit> attribute_id_to_write_mask_bit(AttributeId attrId)
{
  switch (attrId)
  {
  case AttributeId::AccessLevel:
    return AttributeWriteMask::Bit::AccessLevel;
  case AttributeId::ArrayDimensions:
    return AttributeWriteMask::Bit::ArrayDimensions;
  case AttributeId::BrowseName:
    return AttributeWriteMask::Bit::BrowseName;
  case AttributeId::ContainsNoLoops:
    return AttributeWriteMask::Bit::ContainsNoLoops;
  case AttributeId::DataType:
    return AttributeWriteMask::Bit::DataType;
  case AttributeId::Description:
    return AttributeWriteMask::Bit::Description;
  case AttributeId::DisplayName:
    return AttributeWriteMask::Bit::DisplayName;
  case AttributeId::EventNotifier:
    return AttributeWriteMask::Bit::EventNotifier;
  case AttributeId::Executable:
    return AttributeWriteMask::Bit::Executable;
  case AttributeId::Historizing:
    return AttributeWriteMask::Bit::Historizing;
  case AttributeId::InverseName:
    return AttributeWriteMask::Bit::InverseName;
  case AttributeId::IsAbstract:
    return AttributeWriteMask::Bit::IsAbstract;
  case AttributeId::MinimumSamplingInterval:
    return AttributeWriteMask::Bit::MinimumSamplingInterval;
  case AttributeId::Symmetric:
    return AttributeWriteMask::Bit::Symmetric;
  case AttributeId::ValueRank:
    return AttributeWriteMask::Bit::ValueRank;
  case AttributeId::WriteMask:
    return AttributeWriteMask::Bit::WriteMask;
  case AttributeId::AccessLevelEx:
    return AttributeWriteMask::Bit::AccessLevelEx;
  case AttributeId::RolePermissions:
    return AttributeWriteMask::Bit::RolePermissions;
  case AttributeId::AccessRestrictions:
    return AttributeWriteMask::Bit::AccessRestrictions;
  default:
    return std::nullopt;
  }
}

bool is_localized_text_attribute(AttributeId attributeId)
{
  return attributeId == AttributeId::DisplayName || attributeId == AttributeId::Description ||
         attributeId == AttributeId::InverseName;
}

std::optional<StatusCode> validate_localized_text_write(const Variant& value, AttributeId attributeId,
  const NodeId& nodeId, const std::vector<std::string>& supportedLocales)
{
  if (!is_localized_text_attribute(attributeId))
    return std::nullopt;

  const auto* update = value.try_as<LocalizedText>();
  if (!update)
    return std::nullopt;

  for (const auto& [locale, text] : update->translations())
  {
    (void)text;
    const auto localeView = string_view{locale};
    if (localeView.empty())
      continue;

    const auto makeDetail = [&](std::string code) -> std::unique_ptr<ua::ErrorDetail>
    {
      return ErrorDetail::build(
        std::move(code), "LocalizedText locale is not accepted by the server", "AttributeServiceSet")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))
        .context(ua::ContextKeys::nodeAttribute, to_string(attributeId))
        .context(ua::ContextKeys::fieldName, "locale")
        .context(ua::ContextKeys::value, std::string{localeView});
    };

    if (!LocalizedText::is_locale_format_valid(localeView))
    {
      return StatusCode{Status::BadLocaleNotSupported, makeDetail("LocaleIdSyntacticallyInvalid")};
    }

    const bool supported = std::any_of(supportedLocales.begin(),
      supportedLocales.end(),
      [localeView](const std::string& configured) { return std::string_view{configured} == localeView; });
    if (!supported)
    {
      return StatusCode{Status::BadLocaleNotSupported, makeDetail("LocaleIdUnsupported")};
    }
  }

  return std::nullopt;
}

}  // namespace

// =============================================================================================
// Per-request state. The top-level state holds the response payload + per-op barrier; the per-op
// state holds the cursor across the linear authorize/find_node/read_or_write awaits.
// Both are .cpp-private; the service holds them via unique_ptr / vector.
// =============================================================================================

/// One Read operation, as the coroutine running it holds it.
///
/// Moved INTO the frame of @ref AttributeServiceSet::run_read_operation and never leaving it, which
/// is what lets each step name it directly rather than prove, after every suspension, that the state
/// it left behind still exists. Nothing outside that frame can reach it, so nothing outside can
/// invalidate it.
///
/// Where the operation is in its own body is the coroutine's own position, so this carries no step
/// or phase; what it carries is what the steps need to read.
struct ReadOperation
{
  /// Which item of the request this is - the index into the response and the diagnostic collector.
  size_t opIndex{0};

  AddressSpace addressSpace;
  ReadValueId nodeToRead;

  /// What the client asked for, and what the node is actually read for on its behalf. They differ
  /// where the user's view is a narrowing of a stored attribute (UserAccessLevel of AccessLevel).
  AttributeId requestedAttributeId{AttributeId::Value};
  AttributeId effectiveAttributeId{AttributeId::Value};

  /// Filled in by the batched find_nodes and the batched authorize before the operation starts, and
  /// so always engaged by the time its coroutine runs. Optional because the batched head builds the
  /// operation before it has either.
  optional<NodeAccessor> node;
  optional<AccessControl::Verdict> readAccess;

  /// Set for a Variable's Value read with its IndexRange, which the namespace applies; clear for one
  /// read whole because a projection replaces it, and for every other Attribute.
  bool rangeApplied{false};

  /// The Node's description, read once per Node of the request, for an Attribute it answers exactly as
  /// the Node's getters do; absent otherwise, and when the description could not be read.
  optional<NodeDescription> description;

  ReadOperation(size_t initialOpIndex, AddressSpace initialAddressSpace, ReadValueId initialNodeToRead)
    : opIndex(initialOpIndex), addressSpace(std::move(initialAddressSpace)),
      nodeToRead(std::move(initialNodeToRead))
  {}
};

/// One namespace's Value items of a Read, in request order: the operations, and the reads the route sends
/// for them, one per operation.
struct ValueGroup
{
  std::vector<ReadOperation> operations;
  std::vector<ua::detail::ValueRead> reads;
};

/// One Write operation, as the request's coroutine holds it.
///
/// Held in the frame of @ref AttributeServiceSet::dispatch_write_request, one wave at a time in
/// @ref AttributeServiceSet::write_wave, which fills in its classification, its checks' facts and its
/// answer as the request's batched steps proceed.
struct WriteOperation
{
  /// Which item of the request this is - the index into the response and the diagnostic collector.
  size_t opIndex{0};

  AddressSpace addressSpace;
  WriteValue nodeToWrite;
  AttributeId attributeId{AttributeId::Value};

  /// Filled in by the batched find_nodes, so engaged for every item that reaches a wave. Optional because
  /// the batched head builds the operation before it has one.
  optional<NodeAccessor> node;
  optional<VariableAccessor> variable;

  /// Captured before the mutation, for the Part 4 6.5.8 audit event emitted with the item's result.
  Variant oldValue;
  bool auditActive{false};

  bool dictionaryWriteTranslated{false};

  /// The exact prospective policy retained while the owning namespace validates it. `nullopt` is
  /// the Part 3 empty-array operation which clears the node override.
  std::optional<std::vector<RolePermissionType>> proposedRolePermissions;

  /// What the item writes, once the checks of the Node's description have classified it.
  enum class Kind
  {
    VariableValue,
    VariableTypeValue,
    RolePermissions,
    Attribute,
  } kind{Kind::Attribute};

  /// The item's answer once it has one: a refusal, or the namespace's answer to the write.
  std::optional<StatusCode> answer;

  /// Whether the item's result is on the response: once recorded, or once its namespace's write owns it.
  bool recorded{false};

  /// The declared DataType and ValueRank of a Variable's or VariableType's Value, where they can be read.
  NodeId declaredDataType;
  std::optional<ValueRank> declaredRank;

  /// The declared DataType's built-in base, where it is known.
  std::optional<BuiltInTypeId> declaredBase;

  /// The declared structured DataType (its own NodeId) the written Structures are checked against.
  std::optional<NodeId> structureType;

  /// Whether the Data Access step clamped the written value (NR-24 5f): the item then answers Good_Clamped
  /// when it is stored with plain Good.
  bool clamped{false};

  WriteOperation(size_t initialOpIndex, AddressSpace initialAddressSpace, WriteValue initialNodeToWrite)
    : opIndex(initialOpIndex), addressSpace(std::move(initialAddressSpace)),
      nodeToWrite(std::move(initialNodeToWrite))
  {}
};

/// The DataType facts of a Write request, shared by its waves.
struct WriteFactsCache
{
  std::map<NodeId, DataTypeFacts> declared;
  std::map<NodeId, WriteTypeFacts::EncodingFacts> encodings;
  std::map<std::pair<NodeId, NodeId>, bool> subtypes;
};

// =============================================================================================
// Construction / lifetime
// =============================================================================================

shared_ptr<AttributeServiceSet> AttributeServiceSet::create(weak_ptr<SessionInfo> sessionInfo,
  std::vector<LocaleId> sessionLocales, uint32_t requestId, ReadRequest&& readRequest,
  boost::asio::any_io_executor executor, ServiceCallComplete callback)
{
  struct Wrapper : public AttributeServiceSet
  {
  public:
    Wrapper(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales, uint32_t requestId,
      ReadRequest&& readRequest, boost::asio::any_io_executor executor, ServiceCallComplete callback)
      : AttributeServiceSet(sessionInfo, std::move(sessionLocales), requestId, std::move(readRequest),
          std::move(executor), callback)
    {}
  };

  auto service = make_shared<Wrapper>(
    sessionInfo, std::move(sessionLocales), requestId, std::move(readRequest), std::move(executor), callback);
  service->start();
  return service;
}

shared_ptr<AttributeServiceSet> AttributeServiceSet::create(weak_ptr<SessionInfo> sessionInfo,
  uint32_t requestId, WriteRequest&& writeRequest, boost::asio::any_io_executor executor,
  ServiceCallComplete callback)
{
  struct Wrapper : public AttributeServiceSet
  {
  public:
    Wrapper(weak_ptr<SessionInfo> sessionInfo, uint32_t requestId, WriteRequest&& writeRequest,
      boost::asio::any_io_executor executor, ServiceCallComplete callback)
      : AttributeServiceSet(sessionInfo, requestId, std::move(writeRequest), std::move(executor), callback)
    {}
  };

  auto service =
    make_shared<Wrapper>(sessionInfo, requestId, std::move(writeRequest), std::move(executor), callback);
  service->start();
  return service;
}

AttributeServiceSet::AttributeServiceSet(weak_ptr<SessionInfo> sessionInfo,
  std::vector<LocaleId> sessionLocales, uint32_t requestId, ReadRequest&& readRequest,
  boost::asio::any_io_executor executor, ServiceCallComplete callback)
  : ServiceBase(readRequest.request_header().request_handle(), sessionInfo, executor),
    mSessionLocales(std::move(sessionLocales)), mRequestId(requestId), mReadRequest(std::move(readRequest)),
    mServiceCallCompleteCallback(callback), mCancelled(std::make_shared<std::atomic_bool>(false))
{}

AttributeServiceSet::AttributeServiceSet(weak_ptr<SessionInfo> sessionInfo, uint32_t requestId,
  WriteRequest&& writeRequest, boost::asio::any_io_executor executor, ServiceCallComplete callback)
  : ServiceBase(writeRequest.request_header().request_handle(), sessionInfo, executor), mRequestId(requestId),
    mWriteRequest(std::move(writeRequest)), mServiceCallCompleteCallback(callback),
    mCancelled(std::make_shared<std::atomic_bool>(false))
{}

// Destructor - fires Status::BadShutdown when destroyed mid-flight.
AttributeServiceSet::~AttributeServiceSet()
{
  // A destructor is implicitly noexcept: an escaping exception calls std::terminate. try_finish(),
  // service-fault construction, and especially the user completion callback can all throw, so the
  // whole mid-flight teardown is guarded here.
  try
  {
    const bool anyInFlight = mReadResponse || mWriteResponse;
    if (!anyInFlight)
    {
      return;
    }
    if (!try_finish())
    {
      return;
    }
    auto callback = std::move(mServiceCallCompleteCallback);
    mReadResponse.reset();
    mWriteResponse.reset();
    if (callback)
    {
      const auto& requestHeader = active_request_header(mReadRequest, mWriteRequest);
      auto serviceFault = stack_utils::create_service_fault(&requestHeader, Status::BadShutdown);
      callback(std::make_pair(mRequestId, std::static_pointer_cast<ua::Structure>(serviceFault)));
    }
  }
  catch (...)
  {
    ua::detail::ignore_expected_exception();
  }
}

void AttributeServiceSet::begin_processing()
{
  if (mReadRequest)
  {
    start_read_request();
  }
  else
  {
    start_write_request();
  }
}

// =============================================================================================
// Read path - top-level
// =============================================================================================

void AttributeServiceSet::start_read_request()
{
  // start_read_request runs only via begin_processing()'s `if (mReadRequest)` branch, so the
  // Read request optional is always engaged here; the guard makes that provable and binds it once.
  if (!mReadRequest)
  {
    return;
  }
  auto& readRequest = *mReadRequest;

  auto sessionInfo = mSessionInfo.lock();
  DiagnosticSecurityContext securityContext;
  if (sessionInfo)
  {
    securityContext = sessionInfo->diagnostic_security_context();
  }
  DiagnosticCollector collector{
    readRequest.request_header().return_diagnostics(), std::move(securityContext)};

  try
  {
    check(sessionInfo);

    set_timeout();
    mRequestInfo = service_request_info(std::chrono::steady_clock::now(),
      readRequest.request_header().timeout_hint(),
      std::nullopt,
      mCancelled,
      mSessionLocales);

    auto addressSpace = sessionInfo->address_space();

    const size_t noOfOperations{readRequest.nodes_to_read().size()};
    if (noOfOperations == 0)
    {
      throw UaException{Status::BadNothingToDo,
        make_error_detail(
          "EmptyReadRequest", "Read request contains no nodes to read", "AttributeServiceSet")};
    }

    if (readRequest.max_age() < 0)
    {
      throw UaException{Status::BadMaxAgeInvalid,
        ErrorDetail::build("InvalidMaxAge", "maxAge must be non-negative", "AttributeServiceSet")
          .context(ua::ContextKeys::actual, std::to_string(readRequest.max_age()))};
    }

    if (readRequest.timestamps_to_return() >= TimestampsToReturn::Invalid)
    {
      throw UaException{Status::BadTimestampsToReturnInvalid,
        ErrorDetail::build(
          "InvalidTimestampsToReturn", "timestampsToReturn value is not valid", "AttributeServiceSet")
          .context(ua::ContextKeys::actual,
            std::to_string(utils::to_underlying(readRequest.timestamps_to_return())))};
    }

    auto& maxNodesPerRead =
      sessionInfo->server_configuration().server_capabilities().operationLimits.maxNodesPerRead;
    if (maxNodesPerRead && (noOfOperations > maxNodesPerRead.value()))
    {
      throw UaException{Status::BadTooManyOperations,
        ErrorDetail::build("TooManyNodesToRead",
          "Requested node count exceeds the server's per-Read operation limit",
          "AttributeServiceSet")
          .context(ua::ContextKeys::sizeActual, std::to_string(noOfOperations))
          .context(ua::ContextKeys::sizeMax, std::to_string(maxNodesPerRead.value()))};
    }

    // OPC 10000-4 5.3 and 5.6.2.2: the Server should answer Bad_ResponseTooLarge rather than build a
    // response larger than the Client's maxResponseMessageSize. When that is 0 (not used), the server's
    // configured maximum message size bounds it: the same cap the SecureChannel encoder applies to an
    // outgoing message when the client's channel sets no limit (ua_security_policy.cpp). RESIDUAL: a
    // client whose channel limit is larger than the server's configured size is held to the server's
    // size here. Up to MaxNodesPerRead values, each up to the codec limits, were otherwise all read and
    // held before the transport refused the encoded message.
    const uint64_t negotiatedResponseLimit = sessionInfo->max_response_message_size();
    mReadResponseLimit =
      negotiatedResponseLimit != 0
        ? negotiatedResponseLimit
        : sessionInfo->configuration().stack_limits().connectionProtocolLimits.maxMessageSize;
    mReadResponseEstimate = 0;

    auto readResponse = make_shared<ReadResponse>();
    readResponse->results().resize(noOfOperations);
    // Every item starts as Bad_Timeout and is overwritten when it is answered (record_read_result is
    // called exactly once per operation). If the timeoutHint expires first, timeout() sends the
    // response as it stands: finished items carry their results, unfinished ones this status.
    for (auto& result : readResponse->results())
    {
      result.status().emplace(StatusCode{Status::BadTimeout});
    }

    mReadAddressSpace = std::move(addressSpace);
    mReadCollector = std::move(collector);
    mReadResponse = readResponse;
    mReadDefaultLocale = sessionInfo->configuration().defaultLocale;
    mReadAccessControl = SessionAccessControl::create(*sessionInfo);
    mReadCaller = session_caller(*sessionInfo, mReadAccessControl);

    // Group items by namespace index so an unknown namespace is detected once per group. Every item
    // in a known namespace takes the default batch-resolve path: the per-namespace Read override
    // delegate was removed in the interface refactor (invariant I2 makes every namespace materialise and
    // cache its nodes on find_node, so find_node->cache->sync-read serves them all uniformly and the
    // override fork - which bypassed per-node authorization - is gone).
    std::unordered_map<uint16_t, std::vector<size_t>> operationGroups;
    operationGroups.reserve(noOfOperations);
    for (size_t i = 0; i < noOfOperations; ++i)
    {
      const auto& nodeToRead = readRequest.nodes_to_read()[i];
      operationGroups[nodeToRead.node_id().namespace_index()].push_back(i);
    }

    // Answer items in an unknown namespace up front; collect every known-namespace item for the
    // default path (one unit each).
    std::vector<size_t> defaultIndices;
    defaultIndices.reserve(noOfOperations);
    for (auto& [namespaceIndex, indices] : operationGroups)
    {
      auto ns = mReadAddressSpace->namespace_array().get_namespace(namespaceIndex);
      if (!ns)
      {
        for (auto idx : indices)
        {
          readResponse->results()[idx].status().emplace(StatusCode{Status::BadNodeIdUnknown});
        }
        continue;
      }
      for (auto idx : indices)
      {
        defaultIndices.push_back(idx);
      }
    }

    if (defaultIndices.empty())
    {
      complete_read_request();
      return;
    }
    // Retiring any earlier task destroys its frame, which runs the destructors of whatever was in
    // scope at its suspension point and releases the state its continuations hold weakly - so
    // anything still in flight finds an expired pointer and drops itself.
    mReadRequestTask = {};

    // The batched head, as one flow: pre-checks, ONE find_nodes, ONE authorize, then a task per
    // permitted operation. Started HERE, on the strand it resumes on. The indices go in BY VALUE, so
    // they are moved into the request's own frame and live exactly as long as it does.
    mReadRequestTask = run_read_request(std::move(defaultIndices));
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (sessionInfo)
    {
      log_exception(
        sessionInfo->logger().with_category("service"), LogLevel::Error, "AttributeServiceSet", er);
    }
    collector.set_service_detail(er);
    send_service_fault(readRequest.request_header(), er, collector);
  }
}

namespace
{

/// Which operation a Read of @p attributeId has to be authorized for.
///
/// Part 18: reading a Value is a Read, reading the RolePermissions attribute is its own operation,
/// and everything else is metadata the Browse permission governs.
AccessOperation read_access_operation(AttributeId attributeId)
{
  if (attributeId == AttributeId::Value)
  {
    return AccessOperation::Read;
  }
  if (attributeId == AttributeId::RolePermissions)
  {
    return AccessOperation::ReadRolePermissions;
  }
  return AccessOperation::Browse;
}

/// The fixed encoded width of one element of @p type, or 1 for a variable-width type (a lower bound:
/// every encoded element takes at least one byte).
uint64_t fixed_element_width(BuiltInTypeId type) noexcept
{
  switch (type)
  {
  case BuiltInTypeId::Int16:
  case BuiltInTypeId::UInt16:
    return 2;
  case BuiltInTypeId::Int32:
  case BuiltInTypeId::UInt32:
  case BuiltInTypeId::Float:
  case BuiltInTypeId::StatusCode:
  case BuiltInTypeId::String:
  case BuiltInTypeId::ByteString:
  case BuiltInTypeId::XmlElement:
    // A String/ByteString/XmlElement element carries at least its Int32 length prefix.
    return 4;
  case BuiltInTypeId::Int64:
  case BuiltInTypeId::UInt64:
  case BuiltInTypeId::Double:
  case BuiltInTypeId::DateTime:
    return 8;
  case BuiltInTypeId::Guid:
    return 16;
  default:
    return 1;
  }
}

/// A LOWER bound on the OPC UA Binary encoding of @p value's Variant (Part 6 5.2.2.16): the encoding
/// mask, the array length, and each element at its fixed width, plus the bytes a String or
/// ByteString already holds. It never exceeds the real encoding, so a response refused on it is
/// certainly too large; structures and other variable-width types count at their minimum.
/// Cost: O(1) for a scalar or a fixed-width array, O(elements) for an array of Strings/ByteStrings,
/// reading sizes the values already carry - nothing is encoded.
uint64_t encoded_size_lower_bound(const Variant& value)
{
  if (value.empty())
  {
    // An absent Value is not encoded at all: the DataValue mask says so.
    return 0;
  }
  uint64_t size = 1;  // encoding mask
  if (value.is_array())
  {
    const auto& array = value.get_array_base();
    size += 4 + (array.size() * fixed_element_width(array.built_in_type_id()));
    if (const auto* strings = value.try_as<Array<String>>())
    {
      for (const auto& element : *strings)
      {
        size += element.size();
      }
    }
    else if (const auto* byteStrings = value.try_as<Array<ByteString>>())
    {
      for (const auto& element : *byteStrings)
      {
        size += element.size();
      }
    }
    return size;
  }
  if (const auto* string = value.try_as<String>())
  {
    return size + 4 + string->size();
  }
  if (const auto* byteString = value.try_as<ByteString>())
  {
    return size + 4 + byteString->size();
  }
  return size + fixed_element_width(value.get_built_in_type());
}

}  // namespace

/// @par The reference implementation
/// This function, @ref AttributeServiceSet::dispatch_read_request and
/// @ref AttributeServiceSet::read_operation are the worked example of the standard pattern every
/// other request-scoped service converts to: a root that contains and completes, a body that resolves once,
/// authorizes once, spawns and joins, and an operation that answers one item and returns it. Prefer matching
/// it to inventing a variation that reads better in isolation.
ua::async::Task<> AttributeServiceSet::run_read_request(std::vector<size_t> operationIndices)
{
  // This task is a root - nobody awaits it - so an exception that escapes is stored in the promise
  // and read by nobody, and the request never answers.
  try
  {
    co_await dispatch_read_request(operationIndices);
    // Completed HERE, not inside the body: the body has several early exits - nothing to resolve,
    // nothing authorized - and every one of them still owes the client a response. One place that
    // always runs is the only way to be sure each of them does.
    complete_read_request();
  }
  catch (const ua::async::Abandoned&)
  {
    // The request was withdrawn while this was suspended. Whoever withdrew it answered the client.
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(
      mLogger, [this] { fail_read_request(ua::exception_to_status_code(std::current_exception())); })();
  }
  co_return;
}

ua::async::Task<> AttributeServiceSet::dispatch_read_request(std::span<const size_t> operationIndices)
{
  // --- the node-independent pre-checks ---------------------------------------------------------
  //
  // A pre-check that fails records its own answer and yields no operation, so the item is refused
  // without ever entering the batch. `operations` is a local: the batch belongs to this request's
  // body and to nothing else, so nothing else can retire it underneath the folds below.
  std::vector<ReadOperation> operations;
  operations.reserve(operationIndices.size());

  for (const auto opIndex : operationIndices)
  {
    if (auto operation = prepare_read_operation(opIndex))
    {
      operations.push_back(*std::move(operation));
    }
  }

  if (operations.empty())
  {
    co_return;
  }

  // --- ONE lookup of the request's distinct NodeIds ---------------------------------------------
  //
  // A NodeId any item reads for an Attribute other than its Value is looked up with the request's maxAge,
  // which bounds the age of the Attributes its Node describes; one read only for its Value is looked up
  // without, since the Value read carries the maxAge (NR-68 item 2). The route asks each namespace once per
  // maxAge, so a namespace holding both kinds is asked twice. `lookups` and `addressSpace` are locals of
  // this frame, so they outlive the call even when a namespace answers later.
  std::vector<ua::detail::LookupItem> lookups;
  std::vector<size_t> slotOf;
  lookups.reserve(operations.size());
  slotOf.reserve(operations.size());
  {
    std::unordered_map<NodeId, size_t> slots;
    for (const auto& operation : operations)
    {
      const auto& nodeId = operation.nodeToRead.node_id();
      const auto [slot, added] = slots.try_emplace(nodeId, lookups.size());
      if (added)
      {
        lookups.push_back(ua::detail::LookupItem{nodeId, std::nullopt});
      }
      if (operation.requestedAttributeId != AttributeId::Value)
      {
        lookups[slot->second].maxAge = mReadRequest->max_age();
      }
      slotOf.push_back(slot->second);
    }
  }
  auto addressSpace = *mReadAddressSpace;
  auto batch = co_await await_step<BatchResult<NodeAccessorResult>>(
    [this, &addressSpace, &lookups](auto completion)
    {
      ua::detail::NodeAccessorRoute::find_nodes(
        addressSpace.weak(), mRequestInfo, lookups, std::move(completion));
    });

  // --- fold the resolutions, and collect what needs authorizing ---------------------------------
  std::vector<ReadOperation> resolved;
  std::vector<size_t> resolvedSlots;
  std::vector<AccessControl::Item> authorizationItems;
  resolved.reserve(operations.size());
  resolvedSlots.reserve(operations.size());
  authorizationItems.reserve(operations.size());

  for (size_t k = 0; k < operations.size(); ++k)
  {
    auto& operation = operations[k];
    // A short batch is a namespace answering fewer items than it was asked about, which is a
    // contract breach rather than an outcome for the item, so it reads as an internal error.
    NodeAccessorResult found{StatusCode{Status::BadInternalError}};
    if (slotOf[k] < batch.items.size())
    {
      found = batch.items[slotOf[k]];
    }

    if (!found.is_good())
    {
      // OPC 10000-4 section 5.10.2.4 separates two answers a Client acts on differently:
      // Bad_NodeIdInvalid for a syntactically malformed nodeId, and Bad_NodeIdUnknown for a
      // well-formed one that names nothing. The address-space lookup can only ever report the
      // second - a null NodeId lives at NamespaceIndex 0, which exists, so the namespace grouping
      // does not catch it either and the status arrives here as Unknown. `NodeId::is_null()` is
      // already the SDK's own test for "structurally invalid" elsewhere, and it treats both wire
      // encodings (`NodeId{}` and `NodeId{0, ""}`) as the same null id.
      const auto answer =
        ::ua::detail::lookup_failure(operation.nodeToRead.node_id(), found.status_code(), "AttributeService");
      auto status = answer;
      if (operation.nodeToRead.node_id().is_null())
      {
        status = StatusCode{Status::BadNodeIdInvalid};
      }
      if (answer.shared_detail())
      {
        mReadCollector.add_item_detail(operation.opIndex, answer.shared_detail());
      }
      record_read_result(operation.opIndex, DataValue{status});
      continue;
    }

    operation.node = std::move(found).value();
    authorizationItems.push_back(
      AccessControl::Item{*operation.node, read_access_operation(operation.requestedAttributeId)});
    resolved.push_back(std::move(operation));
    resolvedSlots.push_back(slotOf[k]);
  }

  if (resolved.empty())
  {
    co_return;
  }

  // --- ONE authorization call for those nodes ----------------------------------------------------
  std::vector<AccessControl::Verdict> verdicts;
  const bool authorizing = mReadAccessControl.has_value();
  if (authorizing)
  {
    auto accessControl = *mReadAccessControl;
    verdicts = co_await await_step<std::vector<AccessControl::Verdict>>(
      [this, &accessControl, &authorizationItems](auto completion)
      { accessControl.authorize_async(mRequestInfo, authorizationItems, std::move(completion)); });
  }

  // --- fold the verdicts, start a coroutine for each permitted non-Value operation, and group the
  //     Values by namespace -----------------------------------------------------------------------
  //
  // Tasks are EAGER, so every one of these is already in flight by the end of this loop and the join
  // below is a wait on work already running: wall time is the slowest operation, not their sum.
  std::vector<ua::async::Task<>> tasks;
  tasks.reserve(resolved.size());
  // One group per namespace of the Variables whose Value is read, in the order the namespaces first appear.
  std::vector<ValueGroup> groups;
  std::unordered_map<uint16_t, size_t> groupOf;
  // Each Node's description, read once, when an item first needs it.
  std::vector<optional<NodeDescription>> descriptions(lookups.size());
  std::vector<bool> describedSlots(lookups.size(), false);

  for (size_t k = 0; k < resolved.size(); ++k)
  {
    auto& operation = resolved[k];

    if (k < verdicts.size())
    {
      operation.readAccess = std::move(verdicts[k]);
    }
    else
    {
      // No access control at all is a denial, not an omission. Having asked and got no answer for
      // this item is a different fault from never having anyone to ask.
      auto cause = StatusCode{Status::BadUserAccessDenied};
      if (authorizing)
      {
        cause = StatusCode{Status::BadInternalError};
      }
      operation.readAccess = AccessControl::Verdict{.subject = operation.node->get_node_id(),
        .operation = read_access_operation(operation.requestedAttributeId),
        .cause = std::move(cause)};
    }

    if (!operation.readAccess->permitted)
    {
      const auto cause = operation.readAccess->cause;
      if (cause.shared_detail())
      {
        mReadCollector.add_item_detail(operation.opIndex, cause.shared_detail());
      }
      record_read_result(operation.opIndex, DataValue{cause});
      continue;
    }

    if (read_response_too_large())
    {
      // The values already answered exceed the response limit, so the request is refused as a whole
      // below: reading further nodes would only add to a response that is never sent. Operations run
      // inline until their first real suspension, so a namespace that answers synchronously is read
      // no further than the limit; ones already in flight are joined below. O(1) per operation.
      break;
    }

    const auto opIndex = operation.opIndex;
    try
    {
      auto variable = operation.node->as<VariableAccessor>();
      if (!variable || operation.effectiveAttributeId != AttributeId::Value)
      {
        if (read_from_description(operation.effectiveAttributeId))
        {
          const size_t slot = resolvedSlots[k];
          if (!describedSlots[slot])
          {
            describedSlots[slot] = true;
            auto nodeDescription = ua::detail::NodeAccessorRoute::attributes(*operation.node);
            if (nodeDescription.is_good())
            {
              descriptions[slot] = std::move(nodeDescription).value();
            }
          }
          operation.description = descriptions[slot];
        }
        // The operation takes its state WITH it: moved into the task's frame, and nothing outside that
        // frame can reach it again. Started HERE, on the strand it will resume on, which is what lets
        // a collaborator answering on this stack be taken inline.
        tasks.push_back(read_and_record(std::move(operation)));
        continue;
      }

      bool readable = true;
      try
      {
        readable = variable->get_access_level().test(AccessLevelType::Bit::CurrentRead);
      }
      catch (...)
      {
        // AccessLevel not set on the node - default to readable.
        ua::detail::ignore_expected_exception();
      }
      if (!readable)
      {
        // Answered UNPROJECTED: there is no value to narrow to the user's view, and no encoding or
        // index range to apply to a refusal.
        mReadCollector.add_item_detail(opIndex,
          ErrorDetail::build("NotReadable",
            "Variable does not permit reading (CurrentRead not set in AccessLevel)",
            "AttributeServiceSet")
            .context(ua::ContextKeys::nodeId, to_string(operation.nodeToRead.node_id())));
        record_read_result(opIndex, DataValue{StatusCode{Status::BadNotReadable}});
        continue;
      }

      // The namespace answers the Value for the IndexRange (NR-10 rule 8), so the service does not apply
      // it again; a Value a projection replaces is read whole, and the projection's value narrowed.
      ua::detail::ValueRead read{*operation.node, operation.nodeToRead};
      if (value_is_projected(operation.node->get_browse_name()))
      {
        read.value.index_range() = NumericRange{};
      }
      else
      {
        operation.rangeApplied = true;
      }
      const uint16_t namespaceIndex = operation.node->get_node_id().namespace_index();
      // The group's reads and operations are paired by position, and a namespace's entry names its group: a
      // push that throws undoes the one before it, so a later item is not paired with another's read.
      const auto [entry, added] = groupOf.try_emplace(namespaceIndex, groups.size());
      if (added)
      {
        try
        {
          groups.emplace_back();
        }
        catch (...)
        {
          groupOf.erase(entry);
          throw;
        }
      }
      auto& group = groups[entry->second];
      group.reads.push_back(std::move(read));
      try
      {
        group.operations.push_back(std::move(operation));
      }
      catch (...)
      {
        group.reads.pop_back();
        throw;
      }
    }
    catch (...)
    {
      // What the CALL can throw - the frame's allocation, a parameter's move, the vector's growth -
      // or a getter of the Node. None of it can be caught inside the operation: if its frame could not
      // be allocated, its own try does not exist. One item fails and the rest still answer.
      auto status = ua::exception_to_status_code(std::current_exception());
      if (status.shared_detail())
      {
        mReadCollector.add_item_detail(opIndex, status.shared_detail());
      }
      record_read_result(opIndex, DataValue{std::move(status)});
    }
  }

  // --- one Value read per namespace --------------------------------------------------------------
  //
  // Started after every other item has been answered or started, so the response's size is known before
  // any Value is read, and none is started once it is too large. Each group answers its items when its
  // namespace answers, whatever the others do, so a response sent at the timeoutHint carries them.
  for (auto& group : groups)
  {
    if (read_response_too_large())
    {
      break;
    }
    std::vector<size_t> opIndices;
    for (const auto& operation : group.operations)
    {
      opIndices.push_back(operation.opIndex);
    }
    try
    {
      tasks.push_back(read_group(std::move(group)));
    }
    catch (...)
    {
      const auto status = ua::exception_to_status_code(std::current_exception());
      for (const auto opIndex : opIndices)
      {
        record_read_result(opIndex, DataValue{status});
      }
    }
  }

  // --- join -------------------------------------------------------------------------------------
  //
  // Each operation recorded its own answer when it finished (read_and_record), so a response sent at
  // the timeoutHint carries every item that finished, whatever order this loop reaches them in. The
  // join only waits.
  for (auto& task : tasks)
  {
    // `operator co_await` is &&-qualified; the move hands over the handle, and the vector still owns
    // and destroys the frame. Abandoned propagates: the whole request has been withdrawn.
    co_await std::move(task);
  }

  // Checked after the join so values answered asynchronously are counted too. Thrown, so the root
  // answers the whole request with a service fault (OPC 10000-4 5.3) and no partial response is sent.
  if (read_response_too_large())
  {
    throw UaException{Status::BadResponseTooLarge,
      ErrorDetail::build("ReadResponseTooLarge",
        "The values read exceed the maximum response message size (OPC 10000-4 5.3, 5.6.2.2)",
        "AttributeServiceSet")
        .context(ua::ContextKeys::sizeActual, std::to_string(mReadResponseEstimate))
        .context(ua::ContextKeys::sizeMax, std::to_string(mReadResponseLimit))};
  }
  co_return;
}

ua::async::Task<> AttributeServiceSet::read_and_record(ReadOperation operation)
{
  const auto opIndex = operation.opIndex;
  try
  {
    record_read_result(opIndex, co_await read_operation(std::move(operation)));
  }
  catch (const ua::async::Abandoned&)
  {
    // Not this operation's failure - the whole request has been withdrawn.
    throw;
  }
  catch (...)
  {
    // What the BODY threw: unhandled_exception stored it and await_resume rethrew it here.
    auto er = ua::exception_to_status_code(std::current_exception());
    if (er.shared_detail())
    {
      mReadCollector.add_item_detail(opIndex, er.shared_detail());
    }
    record_read_result(opIndex, DataValue{er});
  }
}

ua::async::Task<> AttributeServiceSet::read_group(ValueGroup group)
{
  const auto maxAge = mReadRequest->max_age();
  const bool sourceTimestamp = node_utils::source_timestamp(mReadRequest->timestamps_to_return());
  auto answers = co_await await_step<std::vector<DataValueResult>>(
    [this, &group, maxAge, sourceTimestamp](auto completion)
    {
      ua::detail::NodeAccessorRoute::read_values(mRequestInfo,
        mReadCaller.get(),
        std::move(group.reads),
        maxAge,
        sourceTimestamp,
        std::move(completion));
    });

  std::vector<ua::async::Task<>> finishing;
  finishing.reserve(group.operations.size());
  for (size_t k = 0; k < group.operations.size(); ++k)
  {
    auto& operation = group.operations[k];
    const auto opIndex = operation.opIndex;
    // The route answers one item per read; a missing one is the route's fault, not the item's.
    DataValueResult read{StatusCode{Status::BadInternalError}};
    if (k < answers.size())
    {
      read = std::move(answers[k]);
    }
    try
    {
      finishing.push_back(finish_and_record(std::move(operation), std::move(read)));
    }
    catch (...)
    {
      record_read_result(opIndex, DataValue{ua::exception_to_status_code(std::current_exception())});
    }
  }
  for (auto& task : finishing)
  {
    co_await std::move(task);
  }
}

ua::async::Task<> AttributeServiceSet::finish_and_record(ReadOperation operation, DataValueResult read)
{
  const auto opIndex = operation.opIndex;
  try
  {
    record_read_result(opIndex, co_await finish_value(std::move(operation), std::move(read)));
  }
  catch (const ua::async::Abandoned&)
  {
    // Not this operation's failure - the whole request has been withdrawn.
    throw;
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (er.shared_detail())
    {
      mReadCollector.add_item_detail(opIndex, er.shared_detail());
    }
    record_read_result(opIndex, DataValue{er});
  }
}

bool AttributeServiceSet::read_response_too_large() const noexcept
{
  return mReadResponseLimit != 0 && mReadResponseEstimate > mReadResponseLimit;
}

void AttributeServiceSet::note_read_result_size(const DataValue& value)
{
  // One byte for the DataValue encoding mask, then the value; the status code and timestamps are
  // optional and left out, keeping the sum a lower bound on the encoded result.
  mReadResponseEstimate += 1 + encoded_size_lower_bound(value.value());
}

/// Writes one operation's answer onto the response.
///
/// Called exactly once per operation, from the one place that can: a pre-check that refused it, the
/// batched head folding a bad resolution or a denial, or the join loop above.
void AttributeServiceSet::record_read_result(size_t opIndex, DataValue result)
{
  if (!mReadResponse || opIndex >= mReadResponse->results().size())
  {
    return;
  }

  null_value_for_bad_status(result);
  if (!result.value().empty())
  {
    try
    {
      resolve_in_variant(result.value(), mSessionLocales);
    }
    catch (...)
    {
      // Resolution failure is non-fatal: keep the unresolved value on the response.
      ua::detail::ignore_expected_exception();
    }
  }

  mReadResponse->results()[opIndex] = std::move(result);
}

void AttributeServiceSet::apply_dictionary_snapshot(
  ReadOperation& operation, DataValue& value, data_access_projection::OptionalDictionarySnapshotResult result)
{
  const auto addDetail = [this, &operation](const std::shared_ptr<const ErrorDetail>& detail)
  {
    if (detail)
    {
      mReadCollector.add_item_detail(operation.opIndex, detail);
    }
  };

  if (!result.has_value())
  {
    // Nothing was projected: the item answers the code with no value, not the one it was given.
    value.value() = Variant{};
    value.status() = result.status_code();
    addDetail(result.shared_detail());
    return;
  }
  auto& dictionarySnapshot = result.value();
  if (!dictionarySnapshot.has_value())
  {
    return;
  }

  auto& snapshot = dictionarySnapshot.value();
  if (operation.requestedAttributeId == AttributeId::Value)
  {
    auto entries = data_access_projection::current_dictionary_entries(snapshot);
    if (!entries.is_good())
    {
      value.status() = entries.status_code();
      addDetail(entries.shared_detail());
      return;
    }
    value.value() = Variant{std::move(entries).value()};
    // The entries are answered with the code of the Value reads the snapshot is made from (a Good subcode,
    // or an Uncertain code), combined with the item's status unless the item already holds that code.
    if (value.status().value_or(StatusCode{Status::Good}) != result.status_code())
    {
      server::detail::route_outer_status(value,
        result.status_code(),
        mLogger,
        "AttributeService.ValueAsDictionaryEntriesAnswerCodeNotAnswered",
        operation.nodeToRead.node_id());
    }
    return;
  }
  // The AccessLevel answered below is the owner's attribute, which the codes of the Value reads are not
  // about.

  auto ownerVariable = snapshot.owner.as<VariableAccessor>();
  if (!ownerVariable)
  {
    value.status() = Status::BadTypeMismatch;
    mReadCollector.add_item_detail(operation.opIndex,
      ErrorDetail::build("DictionaryOwnerNotVariable",
        "ValueAsDictionaryEntries owner is not a Variable",
        "AttributeServiceSet")
        .context(ContextKeys::nodeId, snapshot.owner.get_node_id()));
    return;
  }

  value.value() = Variant{ownerVariable->get_access_level().as_underlying_type()};
  value.status() = Status::Good;
  if (operation.requestedAttributeId == AttributeId::UserAccessLevel)
  {
    // The user's view of this attribute is the OWNER's, so the projection that follows must be
    // pointed at the owner rather than the Property node the client named.
    operation.node = snapshot.owner;
  }
}

// =============================================================================================
// Read path - the projections
//
// Each takes what it needs by value and returns what it computed. None of them knows which
// operation it is serving - that stays the dispatcher's business - so none can be wrong about it,
// and none has anything to re-acquire after a suspension.
// =============================================================================================

ua::async::Task<data_access_projection::OptionalDictionarySnapshotResult>
  AttributeServiceSet::project_dictionary(AddressSpace addressSpace, NodeAccessor node)
{
  co_return co_await await_step<data_access_projection::OptionalDictionarySnapshotResult>(
    [this, &addressSpace, &node](auto completion) {
      data_access_projection::dictionary_snapshot_async(addressSpace, node, mStrand, std::move(completion));
    });
}

ua::async::Task<data_access_projection::OptionalLocalizedTextResult>
  AttributeServiceSet::project_value_as_text(AddressSpace addressSpace, NodeAccessor node)
{
  co_return co_await await_step<data_access_projection::OptionalLocalizedTextResult>(
    [this, &addressSpace, &node](auto completion)
    { data_access_projection::value_as_text_async(addressSpace, node, mStrand, std::move(completion)); });
}

ua::async::Task<VoidResult> AttributeServiceSet::authorize_projection_owner(
  AddressSpace addressSpace, NodeAccessor node)
{
  auto references = co_await await_step<NodeAccessor::ReferencesResult>(
    [&node](auto completion) { node.get_references_async(std::move(completion)); });
  if (!references.is_good())
  {
    co_return VoidResult{server::detail::not_acted_on(server::detail::referencesAnswerUncertain,
      references.status_code(),
      "AttributeServiceSet",
      node.get_node_id())};
  }
  const auto ownerId = data_access_projection::owning_variable_of(references.value());
  if (!ownerId)
  {
    co_return VoidResult{};  // Good: the projection answers empty, nothing is disclosed
  }
  auto owner = co_await await_step<NodeAccessorResult>([&addressSpace, &ownerId](auto completion)
    { addressSpace.find_node_async(*ownerId, std::move(completion)); });
  if (!owner.is_good())
  {
    co_return VoidResult{::ua::detail::lookup_failure(*ownerId, owner.status_code(), "AttributeServiceSet")};
  }
  const auto variable = owner.value().as<VariableAccessor>();
  if (!variable || !variable->get_access_level().test(AccessLevelType::Bit::CurrentRead))
  {
    co_return VoidResult{Status::BadNotReadable};
  }
  if (!mReadAccessControl)
  {
    co_return VoidResult{Status::BadUserAccessDenied};
  }
  const std::array item{AccessControl::Item{owner.value(), AccessOperation::Read}};
  auto verdicts = co_await await_step<std::vector<AccessControl::Verdict>>([this, &item](auto completion)
    { mReadAccessControl->authorize_async(mRequestInfo, item, std::move(completion)); });
  if (auto denial = detail::first_denial(verdicts, item.size()))
  {
    co_return VoidResult{std::move(*denial)};
  }
  co_return VoidResult{};
}

ua::async::Task<OptionalStateMachineActiveResult> AttributeServiceSet::state_machine_is_active(
  AddressSpace addressSpace, NodeId target)
{
  co_return co_await await_step<OptionalStateMachineActiveResult>([&addressSpace, &target](auto completion)
    { evaluate_state_machine_variable_active_async(addressSpace, target, std::move(completion)); });
}

ua::async::Task<OptionalMethodExecutableResult> AttributeServiceSet::method_is_executable(
  AddressSpace addressSpace, NodeId target)
{
  co_return co_await await_step<OptionalMethodExecutableResult>([&addressSpace, &target](auto completion)
    { evaluate_state_machine_method_executable_async(addressSpace, target, std::move(completion)); });
}

ua::async::Task<AllowNullsOutcome> AttributeServiceSet::null_value_is_allowed(
  AddressSpace addressSpace, NodeId target)
{
  co_return co_await await_step<AllowNullsOutcome>(
    [&addressSpace, &target](auto completion)
    {
      read_allow_nulls_async(addressSpace,
        target,
        [completion = std::move(completion)](StatusCode status, std::optional<bool> allowed) mutable
        { completion(AllowNullsOutcome{std::move(status), allowed}); });
    });
}

ua::async::Task<DataValueResult> AttributeServiceSet::read_variable_value(VariableAccessor variable,
  double maxAge, bool sourceTimestamp, ReadValueId nodeToRead, std::optional<CallerInfo> caller)
{
  co_return co_await await_step<DataValueResult>(
    [&variable, maxAge, sourceTimestamp, &nodeToRead, &caller](auto completion)
    {
      variable.read_value_async(
        maxAge, sourceTimestamp, nodeToRead, caller ? &*caller : nullptr, std::move(completion));
    });
}

ua::async::Task<Result<bool>> AttributeServiceSet::project_user_writable(
  AddressSpace addressSpace, NodeAccessor node, SessionAccessControl accessControl)
{
  auto referencesResult = co_await await_step<NodeAccessor::ReferencesResult>(
    [&node](auto completion) { node.get_references_async(std::move(completion)); });
  if (!referencesResult.is_good())
  {
    co_return Result<bool>{server::detail::not_acted_on(server::detail::referencesAnswerUncertain,
      referencesResult.status_code(),
      "AttributeServiceSet",
      node.get_node_id())};
  }

  const auto references = std::move(referencesResult).value();
  const auto owner = std::find_if(references.begin(),
    references.end(),
    [](const Reference& reference)
    {
      return !reference.is_forward() && reference.type_id() == NodeId{ReferenceTypeId::HasProperty} &&
             reference.target_id().is_index_based();
    });

  if (owner == references.end())
  {
    // A standard UserWritable Property without its owning File cannot establish the user's rights.
    // Fail closed in the projected Boolean, while leaving the Read itself usable for diagnostics.
    co_return Result<bool>{false};
  }

  const auto ownerId = owner->target_id().node_id();
  auto ownerResult = co_await await_step<NodeAccessorResult>([&addressSpace, &ownerId](auto completion)
    { addressSpace.find_node_async(ownerId, std::move(completion)); });
  if (!ownerResult.is_good())
  {
    co_return Result<bool>{
      ::ua::detail::lookup_failure(ownerId, ownerResult.status_code(), "AttributeServiceSet")};
  }

  auto ownerNode = std::move(ownerResult).value();
  const std::array item{AccessControl::Item{ownerNode, AccessOperation::Write}};
  auto verdicts =
    co_await await_step<std::vector<AccessControl::Verdict>>([this, &accessControl, &item](auto completion)
      { accessControl.authorize_async(mRequestInfo, item, std::move(completion)); });

  co_return Result<bool>{!detail::first_denial(verdicts, item.size()).has_value()};
}

namespace
{

// The three post-processing steps the specification requires of a completed Read, each traceable to
// a different clause and each independently fallible, which is why they are three functions and not
// one. Every one of them is synchronous: nothing here suspends, so none of them is a coroutine.

/// Part 18: the attribute as this Session's roles are permitted to see it.
///
/// What the operation holds so far is the user-INDEPENDENT value; the access control narrows it to
/// what this user may see - masking a stored AccessLevel down to a UserAccessLevel, and so on.
DataValue project_user_attribute_view(
  const ReadOperation& operation, const SessionAccessControl* accessControl, DataValue userIndependentValue)
{
  if (!operation.node || !operation.readAccess || accessControl == nullptr)
  {
    return DataValue{StatusCode{Status::BadInternalError,
      ErrorDetail::build("AttributeProjectionInputMissing",
        "Read reached Attribute projection without its node, completed verdict or Session binding",
        "AttributeServiceSet")
        .context(ContextKeys::nodeId, operation.nodeToRead.node_id().as_definition())
        .context(ContextKeys::nodeAttribute, to_string(operation.requestedAttributeId))}};
  }
  return accessControl->make_client_attribute_value(
    *operation.node, operation.requestedAttributeId, std::move(userIndependentValue), *operation.readAccess);
}

/// Part 4 section 7.29 and Table 183: whether the requested dataEncoding applies to this Value.
///
/// A dataEncoding is meaningful only for a Structure-typed Value: a non-Structure Value can have no
/// encoding applied (Bad_DataEncodingInvalid), and a Structure Value whose requested encoding this
/// Server does not provide is Bad_DataEncodingUnsupported. Non-Value attributes were rejected up
/// front by prepare_read_operation, so only Value reads reach here.
void apply_data_encoding(const ReadValueId& nodeToRead, DataValue& value)
{
  if (nodeToRead.data_encoding().name().empty())
  {
    return;
  }
  const auto& status = value.status();
  if (status && status->is_bad())
  {
    return;
  }

  if (!value.value().is_structure())
  {
    value.status() = Status::BadDataEncodingInvalid;
    value.value() = Variant{};
    return;
  }
  if (nodeToRead.data_encoding().name() != "Default Binary")
  {
    value.status() = StatusCode{Status::BadDataEncodingUnsupported,
      ErrorDetail::build(
        "DataEncodingUnsupported", "The requested data encoding is not provided", "AttributeServiceSet")
        .context(ua::ContextKeys::nodeId, to_string(nodeToRead.node_id()))
        .context(ua::ContextKeys::encoding, std::string{nodeToRead.data_encoding().name()})};
    value.value() = Variant{};
  }
}

// A non-Value Attribute of the operation's Node: from its description where @ref read_from_description
// allows and the description carries it, otherwise from the Node's getters as before.
DataValue read_non_value_attribute(const ReadOperation& operation, TimestampsToReturn timestamps,
  span<const LocaleId> locales, const LocaleId& defaultLocale)
{
  if (operation.description && read_from_description(operation.effectiveAttributeId))
  {
    auto described = operation.description->attribute(operation.effectiveAttributeId);
    if (described.is_good())
    {
      DataValue value = std::move(described).value();
      // A BrowseName without a name is a malformed Node, which the getter path reports.
      const auto* browseName = value.value().try_as<QualifiedName>();
      const bool namelessBrowseName =
        operation.effectiveAttributeId == AttributeId::BrowseName &&
        (browseName == nullptr || static_cast<std::string_view>(browseName->name()).empty());
      if (!namelessBrowseName)
      {
        if (node_utils::server_timestamp(timestamps))
        {
          value.server_timestamp() = DateTime::now();
        }
        return value;
      }
    }
  }
  return node_utils::read_node_sync_attribute(
    *operation.node, operation.effectiveAttributeId, timestamps, locales, defaultLocale);
}

}  // namespace

/// Runs one read operation from its resolved, authorized node to its settled result.
///
/// The per-operation half of a Read, top to bottom in the order it happens: the value read, the File
/// UserWritable projection with its three hops, the two data-access projections, the state-machine
/// activity check and the AllowNulls check.
///
/// The batched half is deliberately elsewhere. One `find_nodes` answers the whole request and one
/// authorization call answers a namespace's nodes; resolving or authorizing per operation would turn
/// a remote namespace's single round trip into one per item.
///
/// The operation's own state lives in this frame, so nothing about it is re-acquired after a
/// suspension and nothing about it can be stale. What outlives a suspension is the REQUEST's state,
/// which every step reaches through @ref read_flow, and whether THIS suspension is still the current
/// one, which the generation @ref ua::async::await_callback re-checks on this strand answers without
/// being asked.
///
/// @param operation This operation's whole state, moved into the frame and never leaving it.
/// @return The Task, which owns its frame and which this service owns in turn.
ua::async::Task<DataValue> AttributeServiceSet::read_operation(ReadOperation operation)
{
  const auto opIndex = operation.opIndex;

  // The specification's post-processing, in the order it requires: the user's view of the attribute,
  // then the dataEncoding rules, then the IndexRange. Applied at each exit that wants it, because
  // three exits below deliberately do not: a refusal has no value to narrow, no encoding to apply
  // and no range to slice. Saying so where they return is what keeps that decision readable.
  const auto projected = [this, &operation](DataValue value)
  {
    return projected_read_result(operation, std::move(value));
  };

  // Every step folds a bad collaborator result the same way: the status becomes the operation's -
  // the value already read is kept - and any rich detail joins the request's collector.
  const auto fail = [this, opIndex](DataValue& value, const StatusCode& status)
  {
    fail_read_value(opIndex, value, status);
  };

  if (!operation.node)
  {
    // The batched head only starts an operation whose node resolved, so this is unreachable. It
    // answers rather than returning silently: a silent return would leave the barrier undecremented.
    co_return DataValue{StatusCode{Status::BadInternalError}};
  }

  // --- what kind of read this is ---------------------------------------------------------------

  if (operation.requestedAttributeId == AttributeId::RolePermissions ||
      operation.requestedAttributeId == AttributeId::UserRolePermissions)
  {
    // Built from guaranteed-resident node/namespace Role data by make_client_attribute_value. There
    // is no independent stored value to read.
    co_return projected(DataValue{});
  }

  // Part 19 section 7.1: ValueAsDictionaryEntries is a projection of its owning
  // MultiStateDictionaryEntryDiscrete Variable, so its access attributes follow the owner rather
  // than the stored attributes of the Property node.
  if ((operation.requestedAttributeId == AttributeId::AccessLevel ||
        operation.requestedAttributeId == AttributeId::UserAccessLevel) &&
      browse_name_is(*operation.node, uint16_t{0}, "ValueAsDictionaryEntries"))
  {
    auto projection = co_await project_dictionary(operation.addressSpace, *operation.node);

    // With no owning Variable to follow - the instance declaration on the VariableType - the Property
    // is an ordinary one and its own AccessLevel stands.
    DataValue result;
    if (auto self = operation.node->as<VariableAccessor>())
    {
      result.value() = Variant{self->get_access_level().as_underlying_type()};
    }
    apply_dictionary_snapshot(operation, result, std::move(projection));
    co_return projected(std::move(result));
  }

  auto variable = operation.node->as<VariableAccessor>();
  const bool readsAValue = variable && operation.effectiveAttributeId == AttributeId::Value;

  if (!readsAValue)
  {
    if (!variable && operation.node->as<MethodAccessor>() &&
        (operation.requestedAttributeId == AttributeId::Executable ||
          operation.requestedAttributeId == AttributeId::UserExecutable))
    {
      const auto targetId = operation.nodeToRead.node_id();
      auto executable = co_await method_is_executable(operation.addressSpace, targetId);

      DataValue result;
      if (!executable.is_good())
      {
        fail(result, executable.status_code());
      }
      else
      {
        result = read_non_value_attribute(
          operation, mReadRequest->timestamps_to_return(), mSessionLocales, mReadDefaultLocale);
        // Executable while the Attribute says so AND the machine's current state is the FromState of a
        // Transition the Method causes. The Call service refuses on the Attribute, so the state never
        // makes a Method the application set not executable read as executable.
        if (executable.value() && !*executable.value() && !result.value().empty())
        {
          result.value() = Variant{false};
        }
      }
      co_return projected(std::move(result));
    }

    // Every other attribute answers from the node synchronously.
    co_return projected(read_non_value_attribute(
      operation, mReadRequest->timestamps_to_return(), mSessionLocales, mReadDefaultLocale));
  }

  // A Variable's Value is read with the other Values of its namespace, by read_group, and is finished by
  // finish_value; the dispatcher never starts one here.
  co_return DataValue{StatusCode{Status::BadInternalError,
    ErrorDetail::build("ValueReadNotGrouped",
      "A Variable's Value reached the per-operation read rather than its namespace's Value read",
      "AttributeServiceSet")
      .context(ua::ContextKeys::nodeId, to_string(operation.nodeToRead.node_id()))}};
}

DataValue AttributeServiceSet::projected_read_result(const ReadOperation& operation, DataValue value)
{
  const SessionAccessControl* accessControl = nullptr;
  if (mReadAccessControl)
  {
    accessControl = &*mReadAccessControl;
  }
  value = project_user_attribute_view(operation, accessControl, std::move(value));
  apply_data_encoding(operation.nodeToRead, value);
  if (!operation.rangeApplied)
  {
    index_range_utils::apply_to_value(value, operation.nodeToRead.index_range());
  }

  // Collected ONCE, at the end: each step above declines when the status is already bad, so
  // collecting after each would add the same detail up to three times.
  const auto& status = value.status();
  if (status && status->is_bad() && status->shared_detail())
  {
    mReadCollector.add_item_detail(operation.opIndex, status->shared_detail());
  }
  note_read_result_size(value);
  return value;
}

void AttributeServiceSet::fail_read_value(size_t opIndex, DataValue& value, const StatusCode& status)
{
  value.status() = status;
  if (status.shared_detail())
  {
    mReadCollector.add_item_detail(opIndex, status.shared_detail());
  }
}

/// Finishes one Value its namespace answered: the projections keyed on the Variable's BrowseName, the
/// state machine's activity, the AllowNulls policy, then the post-processing. A failed read is answered
/// as it is.
///
/// @param operation The operation, moved into the frame and never leaving it.
/// @param readResult The namespace's answer, for the item's IndexRange unless a projection replaces it.
/// @return The Task, which owns its frame.
ua::async::Task<DataValue> AttributeServiceSet::finish_value(
  ReadOperation operation, DataValueResult readResult)
{
  const auto opIndex = operation.opIndex;

  // The specification's post-processing, in the order it requires: the user's view of the attribute,
  // then the dataEncoding rules, then the IndexRange. Applied at each exit that wants it, because
  // three exits below deliberately do not: a refusal has no value to narrow, no encoding to apply
  // and no range to slice. Saying so where they return is what keeps that decision readable.
  const auto projected = [this, &operation](DataValue value)
  {
    return projected_read_result(operation, std::move(value));
  };

  // Every step folds a bad collaborator result the same way: the status becomes the operation's -
  // the value already read is kept - and any rich detail joins the request's collector.
  const auto fail = [this, opIndex](DataValue& value, const StatusCode& status)
  {
    fail_read_value(opIndex, value, status);
  };

  if (!operation.node)
  {
    co_return DataValue{StatusCode{Status::BadInternalError}};
  }

  DataValue result;
  if (!readResult.has_value())
  {
    // Unprojected: the read failed, or the namespace answered Uncertain without a Value, so there is
    // nothing to post-process; the item answers the namespace's code.
    fail(result, readResult.status_code());
    co_return result;
  }

  // The namespace's code on its answer (a Good subcode or an Uncertain code) and the DataValue's own
  // status share the item's one status.
  const StatusCode answered = readResult.status_code();
  result = std::move(readResult).value();
  server::detail::route_outer_status(
    result, answered, mLogger, "AttributeService.ReadAnswerCodeNotAnswered", operation.nodeToRead.node_id());
  {
    const auto& valueStatus = result.status();
    if (valueStatus && valueStatus->is_bad())
    {
      co_return projected(std::move(result));
    }
  }

  // --- the projections, each keyed on the node's own BrowseName --------------------------------
  //
  // Read once: each of these asks about the same node, and each ask takes the node's lock, walks its
  // attribute list and copies the name out.

  const QualifiedName browseName = operation.node->get_browse_name();
  const auto nameIs = [&browseName](std::string_view expected)
  {
    return static_cast<std::string_view>(browseName.name()) == expected;
  };
  const auto qualifiedNameIs = [&browseName, &nameIs](uint16_t namespaceIndex, std::string_view expected)
  {
    return browseName.namespace_index() == namespaceIndex && nameIs(expected);
  };

  const bool valueRequested = operation.requestedAttributeId == AttributeId::Value;

  // Part 20 section 4.2.1: FileType.UserWritable is the static file-writability flag projected
  // through the current user's rights on the owning File Object. The projection depends on the owning
  // Object's permissions rather than on this Variable's value source, so it belongs at the authenticated
  // Read service boundary rather than in each source's read handler.
  const auto* storedUserWritable = result.value().try_as<bool>();
  if (valueRequested && storedUserWritable != nullptr && *storedUserWritable &&
      qualifiedNameIs(uint16_t{0}, "UserWritable"))
  {
    if (!mReadAccessControl)
    {
      // Nothing to ask about the user's rights. Fail closed in the projected Boolean, while leaving
      // the Read itself usable for diagnostics.
      result.value() = Variant{false};
      co_return projected(std::move(result));
    }

    auto writable =
      co_await project_user_writable(operation.addressSpace, *operation.node, *mReadAccessControl);

    if (!writable.is_good())
    {
      fail(result, writable.status_code());
    }
    else
    {
      result.value() = Variant{writable.value()};
    }
    co_return projected(std::move(result));
  }

  if (valueRequested && qualifiedNameIs(uint16_t{0}, "ValueAsText"))
  {
    // SVR-AUTHZ-011 (SVC-8): the projection discloses the OWNER's Value.
    auto owner = co_await authorize_projection_owner(operation.addressSpace, *operation.node);
    if (owner.is_bad())
    {
      fail(result, owner.status_code());
      co_return projected(std::move(result));
    }
    auto projection = co_await project_value_as_text(operation.addressSpace, *operation.node);

    if (!projection.has_value())
    {
      // Nothing was projected: the item answers the code with no value, not the Property's stored one.
      result.value() = Variant{};
      fail(result, projection.status_code());
      co_return projected(std::move(result));
    }
    auto& projectedText = projection.value();
    if (projectedText.has_value())
    {
      result.value() = Variant{std::move(projectedText.value())};
    }
    // The text is answered with the code of the owner's reads it is made from (a Good subcode, or an
    // Uncertain code), combined with the item's status. A wired Property's own read answers the same
    // projection, so the item may already hold that code; it is not combined with itself.
    if (result.status().value_or(StatusCode{Status::Good}) != projection.status_code())
    {
      server::detail::route_outer_status(result,
        projection.status_code(),
        mLogger,
        "AttributeService.ValueAsTextAnswerCodeNotAnswered",
        operation.nodeToRead.node_id());
    }
    co_return projected(std::move(result));
  }

  if (valueRequested && qualifiedNameIs(uint16_t{0}, "ValueAsDictionaryEntries"))
  {
    // SVR-AUTHZ-011 (SVC-8): the projection discloses the OWNER's Value.
    auto owner = co_await authorize_projection_owner(operation.addressSpace, *operation.node);
    if (owner.is_bad())
    {
      fail(result, owner.status_code());
      co_return projected(std::move(result));
    }
    auto projection = co_await project_dictionary(operation.addressSpace, *operation.node);
    apply_dictionary_snapshot(operation, result, std::move(projection));
    co_return projected(std::move(result));
  }

  // --- the state-machine variables, then the null-value policy ---------------------------------

  if (nameIs("CurrentState") || nameIs("LastTransition"))
  {
    const auto targetId = operation.nodeToRead.node_id();
    auto active = co_await state_machine_is_active(operation.addressSpace, targetId);

    if (!active.is_good())
    {
      fail(result, active.status_code());
      co_return projected(std::move(result));
    }
    const auto& stateMachineActive = active.value();
    if (stateMachineActive.has_value() && !stateMachineActive.value())
    {
      result.status() = Status::BadStateNotActive;
      co_return projected(std::move(result));
    }
  }

  {
    const auto& valueStatus = result.status();
    if (result.value().empty() && (!valueStatus || valueStatus->is_good()))
    {
      const auto targetId = operation.nodeToRead.node_id();
      auto allowNulls = co_await null_value_is_allowed(operation.addressSpace, targetId);

      if (allowNulls.status.is_bad())
      {
        fail(result, allowNulls.status);
      }
      else if (allowNulls.allowed.has_value() && !*allowNulls.allowed)
      {
        const auto denied = StatusCode{Status::BadNoData,
          ErrorDetail::build("NullValueNotAllowed",
            "Variable with AllowNulls FALSE cannot return a null Value",
            "AttributeServiceSet")
            .context(ua::ContextKeys::nodeId, to_string(operation.nodeToRead.node_id()))};
        fail(result, denied);
      }
    }
  }

  co_return projected(std::move(result));
}

void AttributeServiceSet::complete_read_request()
{
  // try_finish is what makes a second answer impossible - a cancel or a timeout that already
  // answered the client has taken it, so this returns and sends nothing.
  if (!try_finish())
  {
    mReadResponse.reset();
    return;
  }
  if (!mReadResponse)
    return;
  // complete_read_request is reached only on the Read path, so the Read request optional is
  // always engaged; the guard makes that provable to the analyzer and binds it once.
  if (!mReadRequest)
    return;
  auto& readRequest = *mReadRequest;
  auto& response = *mReadResponse;
  const size_t noOfOperations = response.results().size();

  // Apply timestamps per TimestampsToReturn policy.
  auto tsr = readRequest.timestamps_to_return();
  const bool wantServer = node_utils::server_timestamp(tsr);
  const bool wantSource = node_utils::source_timestamp(tsr);
  auto now = DateTime::now();
  const auto& nodesToRead = readRequest.nodes_to_read();
  for (size_t i = 0; i < response.results().size(); ++i)
  {
    auto& dv = response.results()[i];
    if (wantServer)
    {
      const auto& serverTimestamp = dv.server_timestamp();
      if (!serverTimestamp.has_value() || serverTimestamp->is_null())
        dv.server_timestamp() = now;
    }
    else
      dv.server_timestamp().reset();

    if (!wantSource)
    {
      dv.source_timestamp().reset();
      dv.source_pico_seconds().reset();
    }
    else if (const auto& sourceTimestamp = dv.source_timestamp();
             i < nodesToRead.size() &&
             nodesToRead[i].attribute_id() == utils::to_underlying(AttributeId::Value) &&
             (!sourceTimestamp.has_value() || sourceTimestamp->is_null()))
    {
      // Part 4 7.7.3: a Value read with TimestampsToReturn including Source must carry a
      // SourceTimestamp. When the value source supplies none (absent or null), default it to the
      // server timestamp. This holds even when the result carries a bad status - e.g.
      // Bad_DataEncodingInvalid for a DataEncoding on a non-Structure Value (spec-correct per 7.29):
      // the SourceTimestamp is still expected on a Value read whenever Source/Both was requested.
      dv.source_timestamp() = now;
    }
  }

  // G16: Emit AuditEventPayload for Read failures (Part 4, 6.5.8 - SHOULD).
  if (auto sessionInfo = mSessionInfo.lock())
  {
    if (sessionInfo->server_configuration().auditingEnabled)
    {
      emit_read_audit_if_failed(*sessionInfo, response);
    }
  }

  mReadCollector.apply_to(response.response_header(), response.diagnostic_infos(), noOfOperations);
  stack_utils::prepare_response_header(readRequest.request_header(), response.response_header());

  auto serviceResponse = std::move(mReadResponse);
  if (mServiceCallCompleteCallback)
  {
    mServiceCallCompleteCallback(std::make_pair(mRequestId, serviceResponse));
  }
}

void AttributeServiceSet::fail_read_request(VoidResult error)
{
  if (!mReadResponse)
    return;
  // fail_read_request is reached only on the Read path, so the Read request optional is always
  // engaged; the guard makes that provable to the analyzer.
  if (!mReadRequest)
    return;
  mReadCollector.set_service_detail(error.status_code());
  send_service_fault(mReadRequest->request_header(), error.status_code(), mReadCollector);
  mReadResponse.reset();
}

void AttributeServiceSet::emit_read_audit_if_failed(SessionInfo& sessionInfo, ReadResponse& response)
{
  // Called only from the Read completion path, so the Read request optional is always engaged;
  // the guard makes that provable to the analyzer.
  if (!mReadRequest)
    return;
  bool anyFailed = false;
  for (const auto& dv : response.results())
  {
    const auto& status = dv.status();
    if (status.has_value() && status->is_bad())
    {
      anyFailed = true;
      break;
    }
  }
  if (!anyFailed)
    return;

  const auto sink = sessionInfo.event_sink();
  if (!sink || !static_cast<EventBus*>(sink.get())->has_event_interest())
    return;

  AuditEventPayload auditEvent;
  auditEvent.sourceNode = NodeId{ObjectId::Server};
  auditEvent.sourceName = "Attribute/Read";
  auditEvent.actionTimeStamp = Variant{DateTime::now()};
  auditEvent.status = false;
  auditEvent.serverId = sessionInfo.configuration().application_description_part().applicationUri;
  auditEvent.clientAuditEntryId = mReadRequest->request_header().audit_entry_id();
  auditEvent.message = LocalizedText{"", "Read"};
  auditEvent.severity = 1;
  if (const auto* sec = dynamic_cast<const SessionSecurityContext*>(&sessionInfo))
  {
    if (auto user = sec->user_identity())
      auditEvent.clientUserId = user->userId;
  }
  sink->emit(auditEvent);
}

// =============================================================================================
// Read path - per-operation default flow
// =============================================================================================

std::optional<ReadOperation> AttributeServiceSet::prepare_read_operation(size_t opIndex)
{
  if (!mReadRequest || opIndex >= mReadRequest->nodes_to_read().size())
  {
    return std::nullopt;
  }

  ReadOperation operation{opIndex, *mReadAddressSpace, mReadRequest->nodes_to_read()[opIndex]};

  // Each refusal below settles the operation here and now and reports "no operation to run". None of
  // them needs the node, which is why they happen before the batched find_nodes rather than inside
  // the operation's own coroutine.
  auto sessionInfo = mSessionInfo.lock();
  if (!sessionInfo)
  {
    record_read_result(opIndex, DataValue{StatusCode{Status::BadShutdown}});
    return std::nullopt;
  }

  if (!mReadAccessControl)
  {
    mReadCollector.add_item_detail(opIndex,
      ErrorDetail::build(
        "AuthorizationUnavailable", "Read denied: no committed access identity", "AttributeServiceSet")
        .context(ua::ContextKeys::nodeId, to_string(operation.nodeToRead.node_id())));
    record_read_result(opIndex, DataValue{StatusCode{Status::BadUserAccessDenied}});
    return std::nullopt;
  }

  operation.requestedAttributeId =
    ua::utils::from_underlying<AttributeId>(operation.nodeToRead.attribute_id());
  operation.effectiveAttributeId = AccessControl::user_independent_attribute(operation.requestedAttributeId);

  // Data encoding validation (SVR-ATTR-READ-021, SVR-ATTR-READ-022). Done up-front because it
  // depends only on the request, not on the node.
  if (!operation.nodeToRead.data_encoding().name().empty() &&
      operation.requestedAttributeId != AttributeId::Value)
  {
    // No dataEncoding can be applied to a non-Value Attribute (Part 4 7.29 + Table 183:
    // Bad_DataEncodingInvalid). This depends only on the request, so reject it up-front.
    mReadCollector.add_item_detail(opIndex,
      ErrorDetail::build(
        "DataEncodingOnNonValue", "dataEncoding is only valid for the Value attribute", "AttributeServiceSet")
        .context(ua::ContextKeys::nodeAttribute, to_string(operation.requestedAttributeId))
        .context(ua::ContextKeys::encoding, std::string{operation.nodeToRead.data_encoding().name()}));
    record_read_result(opIndex, DataValue{StatusCode{Status::BadDataEncodingInvalid}});
    return std::nullopt;
  }
  // Whether the requested encoding is APPLICABLE depends on the Value's DataType (only a
  // Structure-typed Value can carry a dataEncoding). That check is deferred to apply_data_encoding,
  // after the value - and hence its type - is known.

  return operation;
}

// =============================================================================================
// Write path - top-level
// =============================================================================================

void AttributeServiceSet::start_write_request()
{
  // start_write_request runs only via begin_processing()'s `else` branch (i.e. when mReadRequest is
  // empty), so the Write request optional is always engaged; the guard makes that provable and binds
  // it once.
  if (!mWriteRequest)
  {
    return;
  }
  auto& writeRequest = *mWriteRequest;

  auto sessionInfo = mSessionInfo.lock();
  DiagnosticSecurityContext securityContext;
  if (sessionInfo)
  {
    securityContext = sessionInfo->diagnostic_security_context();
  }
  DiagnosticCollector collector{
    writeRequest.request_header().return_diagnostics(), std::move(securityContext)};

  try
  {
    check(sessionInfo);

    set_timeout();
    mRequestInfo = service_request_info(std::chrono::steady_clock::now(),
      writeRequest.request_header().timeout_hint(),
      std::nullopt,
      mCancelled,
      mSessionLocales);

    auto addressSpace = sessionInfo->address_space();

    const size_t noOfOperations{writeRequest.nodes_to_write().size()};
    if (noOfOperations == 0)
    {
      throw UaException{Status::BadNothingToDo,
        make_error_detail(
          "EmptyWriteRequest", "Write request contains no nodes to write", "AttributeServiceSet")};
    }

    const auto& capabilities = sessionInfo->server_configuration().server_capabilities();
    const auto& maxNodesPerWrite = capabilities.operationLimits.maxNodesPerWrite;
    if (maxNodesPerWrite && (noOfOperations > maxNodesPerWrite.value()))
    {
      throw UaException{Status::BadTooManyOperations,
        ErrorDetail::build(
          "TooManyNodesToWrite", "Requested node count exceeds the per-call limit", "AttributeServiceSet")
          .context(ua::ContextKeys::sizeActual, std::to_string(noOfOperations))
          .context(ua::ContextKeys::sizeMax, std::to_string(maxNodesPerWrite.value()))};
    }

    auto writeResponse = make_shared<WriteResponse>();
    // Every item starts as Bad_Timeout and is overwritten when it is answered, so a response sent at
    // the timeoutHint reports the unfinished items as such (see timeout()).
    writeResponse->results().resize(noOfOperations);
    for (auto& result : writeResponse->results())
    {
      result = StatusCode{Status::BadTimeout};
    }

    mWriteAddressSpace = std::move(addressSpace);
    mWriteCollector = std::move(collector);
    mWriteSupportedLocales = capabilities.localeIds;
    mWriteAccessControl = SessionAccessControl::create(*sessionInfo);
    mWriteResponse = writeResponse;

    // Group items by namespace index so an unknown namespace is detected once per group. Every item
    // in a known namespace takes the default batch-resolve path: the per-namespace Write override
    // delegate was removed in the interface refactor (invariant I2 + the async write path serve every
    // namespace uniformly, and the override fork - which bypassed per-node authorization - is gone).
    std::unordered_map<uint16_t, std::vector<size_t>> operationGroups;
    operationGroups.reserve(noOfOperations);
    for (size_t i = 0; i < noOfOperations; ++i)
    {
      const auto& nodeToWrite = writeRequest.nodes_to_write()[i];
      operationGroups[nodeToWrite.node_id().namespace_index()].push_back(i);
    }

    // Answer items in an unknown namespace up front; collect every known-namespace item for the
    // default path (one unit each).
    std::vector<size_t> defaultIndices;
    defaultIndices.reserve(noOfOperations);
    for (auto& [namespaceIndex, indices] : operationGroups)
    {
      auto ns = mWriteAddressSpace->namespace_array().get_namespace(namespaceIndex);
      if (!ns)
      {
        for (auto idx : indices)
        {
          writeResponse->results()[idx] = StatusCode{Status::BadNodeIdUnknown};
        }
        continue;
      }
      for (auto idx : indices)
      {
        defaultIndices.push_back(idx);
      }
    }

    if (defaultIndices.empty())
    {
      complete_write_request();
      return;
    }

    // Retire any earlier flows before sizing: destroying a Task runs the destructors of whatever was
    // in scope at its suspension point and releases the state a continuation holds weakly.
    // Retiring any earlier task destroys its frame, releasing the state its continuations hold
    // weakly, so anything still in flight finds an expired pointer and drops itself.
    mWriteRequestTask = {};

    // The batched head: pre-checks, ONE find_nodes, ONE authorize, then a coroutine per permitted
    // operation. Started HERE, on the strand it resumes on. The indices go in BY VALUE, so they are
    // moved into the request's own frame.
    mWriteRequestTask = run_write_request(std::move(defaultIndices));
  }
  catch (...)
  {
    auto er = ua::exception_to_status_code(std::current_exception());
    if (sessionInfo)
    {
      log_exception(
        sessionInfo->logger().with_category("service"), LogLevel::Error, "AttributeServiceSet", er);
    }
    collector.set_service_detail(er);
    send_service_fault(mWriteRequest->request_header(), er, collector);
  }
}

namespace
{

/// Which operation a Write of @p attributeId on @p node has to be authorized for.
///
/// A VariableType's Value is gated by its WriteMask (bit 21, ValueForVariableType), so it takes
/// WriteAttribute, the permission the UserWriteMask is projected from; Write is the Variable's Value
/// permission.
AccessOperation write_access_operation(const NodeAccessor& node, AttributeId attributeId)
{
  switch (attributeId)
  {
  case AttributeId::Value:
    return node.as<VariableTypeAccessor>() ? AccessOperation::WriteAttribute : AccessOperation::Write;
  case AttributeId::RolePermissions:
    return AccessOperation::WriteRolePermissions;
  case AttributeId::Historizing:
    return AccessOperation::WriteHistorizing;
  default:
    return AccessOperation::WriteAttribute;
  }
}

}  // namespace

ua::async::Task<> AttributeServiceSet::run_write_request(std::vector<size_t> operationIndices)
{
  // This task is a root - nobody awaits it - so an exception that escapes is stored in the promise
  // and read by nobody, and the request never answers. @see run_read_request, the reference shape.
  try
  {
    co_await dispatch_write_request(operationIndices);
    // Completed HERE, not inside the body: the body has early exits - nothing to resolve, nothing
    // authorized - and each still owes the client a response.
    complete_write_request();
  }
  catch (const ua::async::Abandoned&)
  {
    // The request was withdrawn while this was suspended. Whoever withdrew it answered the client.
    co_return;
  }
  catch (...)
  {
    ua::async::guarded(
      mLogger, [this] { fail_write_request(ua::exception_to_status_code(std::current_exception())); })();
  }
  co_return;
}

ua::async::Task<> AttributeServiceSet::dispatch_write_request(std::span<const size_t> operationIndices)
{
  // --- 1. the node-independent pre-checks -------------------------------------------------------
  //
  // A pre-check that fails records its own answer and yields no operation, so the item is refused
  // without entering the batch.
  std::vector<WriteOperation> operations;
  std::vector<NodeId> nodeIds;
  operations.reserve(operationIndices.size());
  nodeIds.reserve(operationIndices.size());

  for (const auto opIndex : operationIndices)
  {
    if (auto operation = prepare_write_operation(opIndex))
    {
      nodeIds.push_back(operation->nodeToWrite.node_id());
      operations.push_back(*std::move(operation));
    }
  }

  if (operations.empty())
  {
    co_return;
  }

  // --- 2. ONE find_nodes for the whole request: one lookup per namespace, carrying the request -------
  auto addressSpace = *mWriteAddressSpace;
  std::vector<ua::detail::LookupItem> lookups;
  lookups.reserve(nodeIds.size());
  for (const auto& nodeId : nodeIds)
  {
    lookups.push_back(ua::detail::LookupItem{nodeId, std::nullopt});
  }
  auto batch = co_await await_step<BatchResult<NodeAccessorResult>>(
    [this, &addressSpace, &lookups](auto completion)
    {
      ua::detail::NodeAccessorRoute::find_nodes(
        addressSpace.weak(), mRequestInfo, lookups, std::move(completion));
    });

  // --- fold the resolutions -----------------------------------------------------------------------
  //
  // Two kinds of operation come out of this: those that need an authorization verdict, and
  // UserRolePermissions writes, which are refused by the operation itself before audit interest is
  // determined and so must NOT be authorized first.
  std::vector<WriteOperation> toAuthorize;
  std::vector<WriteOperation> runnable;
  std::vector<AccessControl::Item> authorizationItems;
  toAuthorize.reserve(operations.size());
  authorizationItems.reserve(operations.size());

  for (size_t k = 0; k < operations.size(); ++k)
  {
    auto& operation = operations[k];
    // A short batch is a namespace answering fewer items than it was asked about - a contract
    // breach rather than an outcome for the item.
    NodeAccessorResult resolved{StatusCode{Status::BadInternalError}};
    if (k < batch.items.size())
    {
      resolved = std::move(batch.items[k]);
    }

    if (!resolved.is_good())
    {
      // OPC 10000-4 section 5.10.4, the same distinction the Read path draws: a malformed nodeId is
      // Bad_NodeIdInvalid, and only a well-formed one that resolves to nothing is Bad_NodeIdUnknown.
      const auto answer = ::ua::detail::lookup_failure(
        operation.nodeToWrite.node_id(), resolved.status_code(), "AttributeService");
      auto status = answer;
      if (operation.nodeToWrite.node_id().is_null())
      {
        status = StatusCode{Status::BadNodeIdInvalid};
      }
      if (answer.shared_detail())
      {
        mWriteCollector.add_item_detail(operation.opIndex, answer.shared_detail());
      }
      record_write_result(operation.opIndex, status);
      continue;
    }

    operation.node = std::move(resolved).value();
    operation.variable = operation.node->as<VariableAccessor>();

    if (operation.attributeId == AttributeId::UserRolePermissions)
    {
      // Part 3 5.2.10 L1936: never writeable, whatever the Roles say. Refused before audit interest is
      // determined, so no AuditWriteUpdateEvent is emitted - which is why it is not put through the
      // generic authorization first.
      runnable.push_back(std::move(operation));
      continue;
    }

    authorizationItems.push_back(
      AccessControl::Item{*operation.node, write_access_operation(*operation.node, operation.attributeId)});
    toAuthorize.push_back(std::move(operation));
  }

  // --- 3. ONE authorization call for those nodes --------------------------------------------------
  std::vector<AccessControl::Verdict> verdicts;
  const bool authorizing = mWriteAccessControl.has_value();
  if (authorizing && !authorizationItems.empty())
  {
    auto accessControl = *mWriteAccessControl;
    verdicts = co_await await_step<std::vector<AccessControl::Verdict>>(
      [this, &accessControl, &authorizationItems](auto completion)
      { accessControl.authorize_async(mRequestInfo, authorizationItems, std::move(completion)); });
  }

  for (size_t k = 0; k < toAuthorize.size(); ++k)
  {
    auto& operation = toAuthorize[k];

    // No access control at all is a denial, not an omission.
    const bool permitted = k < verdicts.size() && verdicts[k].permitted;
    if (!permitted)
    {
      auto cause = StatusCode{Status::BadUserAccessDenied};
      if (k < verdicts.size())
      {
        cause = std::move(verdicts[k].cause);
      }
      else if (authorizing)
      {
        cause = StatusCode{Status::BadInternalError};
      }
      if (cause.shared_detail())
      {
        mWriteCollector.add_item_detail(operation.opIndex, cause.shared_detail());
      }
      record_write_result(operation.opIndex, std::move(cause));
      continue;
    }

    runnable.push_back(std::move(operation));
  }

  std::ranges::sort(runnable, {}, &WriteOperation::opIndex);

  // --- 3b. Part 19 section 7.1: a Value write to ValueAsDictionaryEntries is a write to its owner ---
  //
  // Per item, as in the Read (NR-23 keeps the Part 19 projections' per-item lookups). The translated item
  // belongs to its owner's namespace from here on.
  for (auto& operation : runnable)
  {
    if (operation.attributeId != AttributeId::Value)
    {
      continue;
    }
    bool dictionary = false;
    try
    {
      dictionary = browse_name_is(*operation.node, uint16_t{0}, "ValueAsDictionaryEntries");
    }
    catch (...)
    {
      operation.answer = ua::exception_to_status_code(std::current_exception());
      continue;
    }
    if (dictionary)
    {
      try
      {
        operation.answer = co_await translate_dictionary_write(operation);
      }
      catch (const ua::async::Abandoned&)
      {
        throw;
      }
      catch (...)
      {
        operation.answer = ua::exception_to_status_code(std::current_exception());
      }
    }
  }

  // --- the waves ------------------------------------------------------------------------------------
  //
  // Part 4 5.10.4.1 leaves the order undefined when a request names the same Node and Attribute more than
  // once; the Server writes them in request order, the outcome a Client writing the same Attribute twice
  // expects. The k-th occurrence of each (NodeId, Attribute) is in wave k, and the waves run one after
  // another, so two ranged writes to one array each merge into the Value the other left. A request without
  // a repeat is one wave.
  std::vector<std::vector<WriteOperation>> waves;
  {
    std::map<std::pair<NodeId, uint32_t>, size_t> occurrences;
    for (auto& operation : runnable)
    {
      const auto key = std::make_pair(operation.nodeToWrite.node_id(), operation.nodeToWrite.attribute_id());
      const size_t wave = occurrences[key]++;
      if (waves.size() <= wave)
      {
        waves.resize(wave + 1);
      }
      waves[wave].push_back(std::move(operation));
    }
  }

  // The request is one operation (NR-36 rule 4), whatever its waves: its namespaces' versioned Nodes raise
  // one ModelChangeEvent, which the response waits for. A namespace that answers after the request was
  // withdrawn still has its Nodes raised, when its call ends (NR-46).
  auto step = waves.empty() || !mWriteAddressSpace
                ? nullptr
                : ::ua::detail::NodeAccessorRoute::model_change_step(mWriteAddressSpace->weak());
  // The DataType facts, shared by the waves.
  WriteFactsCache facts;
  for (auto& wave : waves)
  {
    co_await write_wave(wave, facts, step);
  }
  if (step)
  {
    co_await await_step<bool>([&step](auto completion) mutable
      { step->close([completion = std::move(completion)]() mutable { completion(true); }); });
  }
  co_return;
}

/// Writes one operation's status onto the response.
///
/// Called exactly once per operation, from the one place that can: a pre-check that refused it, the
/// batched head folding a bad resolution or a denial, or the join loop above. The Part 4 6.5.8 audit
/// event is NOT emitted here - the operation emits its own on its way out, because that is the only
/// place that still holds the old value it needs.
void AttributeServiceSet::record_write_result(size_t opIndex, StatusCode status)
{
  if (!mWriteResponse || opIndex >= mWriteResponse->results().size())
  {
    return;
  }
  mWriteResponse->results()[opIndex] = status;
}

void AttributeServiceSet::complete_write_request()
{
  // try_finish is what makes a second answer impossible - a cancel or a timeout that already
  // answered the client has taken it, so this returns and sends nothing.
  if (!try_finish())
  {
    mWriteResponse.reset();
    return;
  }
  if (!mWriteResponse)
    return;
  // complete_write_request is reached only on the Write path, so the Write request optional is
  // always engaged; the guard makes that provable to the analyzer and binds it once.
  if (!mWriteRequest)
    return;
  auto& writeRequest = *mWriteRequest;
  auto& response = *mWriteResponse;
  const size_t noOfOperations = response.results().size();
  mWriteCollector.apply_to(response.response_header(), response.diagnostic_infos(), noOfOperations);
  stack_utils::prepare_response_header(writeRequest.request_header(), response.response_header());

  auto serviceResponse = std::move(mWriteResponse);
  if (mServiceCallCompleteCallback)
  {
    mServiceCallCompleteCallback(std::make_pair(mRequestId, serviceResponse));
  }
}

void AttributeServiceSet::fail_write_request(VoidResult error)
{
  if (!mWriteResponse)
    return;
  // fail_write_request is reached only on the Write path, so the Write request optional is always
  // engaged; the guard makes that provable to the analyzer.
  if (!mWriteRequest)
    return;
  mWriteCollector.set_service_detail(error.status_code());
  send_service_fault(mWriteRequest->request_header(), error.status_code(), mWriteCollector);
  mWriteResponse.reset();
}

// =============================================================================================
// Write path - per-operation default flow
// =============================================================================================

std::optional<WriteOperation> AttributeServiceSet::prepare_write_operation(size_t opIndex)
{
  if (!mWriteRequest || opIndex >= mWriteRequest->nodes_to_write().size())
  {
    return std::nullopt;
  }

  WriteOperation operation{opIndex, *mWriteAddressSpace, mWriteRequest->nodes_to_write()[opIndex]};

  // Each refusal below records the operation's answer here and now and reports "no operation to
  // run". Neither needs the node, which is why they happen before the batched find_nodes rather
  // than inside the operation's own coroutine.
  auto sessionInfo = mSessionInfo.lock();
  if (!sessionInfo)
  {
    record_write_result(opIndex, StatusCode{Status::BadShutdown});
    return std::nullopt;
  }

  if (!mWriteAccessControl)
  {
    mWriteCollector.add_item_detail(opIndex,
      ErrorDetail::build(
        "AuthorizationUnavailable", "Write denied: no committed access identity", "AttributeServiceSet")
        .context(ua::ContextKeys::nodeId, to_string(operation.nodeToWrite.node_id())));
    record_write_result(opIndex, StatusCode{Status::BadUserAccessDenied});
    return std::nullopt;
  }

  operation.attributeId = ua::utils::from_underlying<AttributeId>(operation.nodeToWrite.attribute_id());
  return operation;
}

namespace
{

/// SVR-ATTR-WRITE-008: the written value's rank against the Variable's ValueRank (OPC 10000-3 section
/// 5.6.2): Any (-2) takes anything, ScalarOrOneDimension (-3) a scalar or a one-dimensional array, Scalar
/// (-1) a scalar, OneOrMoreDimensions (0) an array, and n a array of n dimensions. A ByteString is
/// structurally a one-dimensional array of Byte, and is accepted where one is expected (OPC 10000-4 section
/// 5.10.4.2), so it counts as one dimension when @p byteArrayExpected.
///
/// @return Good, or Bad_TypeMismatch naming the written and the declared rank.
StatusCode check_value_rank(
  ValueRank declaredRank, const Variant& written, bool byteArrayExpected, const NodeId& nodeId)
{
  const int32_t declared = declaredRank.as_int32();
  int32_t writtenRank = ValueRank::scalar;
  if (written.is_array())
  {
    const auto& dimensions = written.get_array_base().dimensions();
    writtenRank = 1;
    if (dimensions.has_value())
    {
      writtenRank = static_cast<int32_t>(dimensions->size());
    }
  }
  else if (byteArrayExpected && written.get_built_in_type() == BuiltInTypeId::ByteString)
  {
    writtenRank = 1;
  }

  bool accepted = false;
  switch (declared)
  {
  case ValueRank::any:
    accepted = true;
    break;
  case ValueRank::scalarOrOneDimension:
    accepted = writtenRank == ValueRank::scalar || writtenRank == 1;
    break;
  case ValueRank::scalar:
    accepted = writtenRank == ValueRank::scalar;
    break;
  case ValueRank::oneOrMore:
    accepted = writtenRank >= 1;
    break;
  default:
    accepted = writtenRank == declared;
    break;
  }
  if (accepted)
  {
    return StatusCode{Status::Good};
  }
  return StatusCode{Status::BadTypeMismatch,
    ErrorDetail::build(
      "ValueRankMismatch", "Written value's rank does not match the ValueRank", "AttributeServiceSet")
      .context(ua::ContextKeys::actual, std::to_string(writtenRank))
      .context(ua::ContextKeys::expected, std::to_string(declared))
      .context(ua::ContextKeys::nodeId, to_string(nodeId))};
}

/// NR-11 rule 1 (DL-115 (1)): whether the value of an IndexRange write is consistent with the range, decided
/// from the value, the range and the declared DataType and ValueRank, without reading the Value held. Whether
/// the range lies within the Value held, and the range's dimension count where the ValueRank is not fixed,
/// are left to whoever holds the data (NR-11 rule 3).
///
/// - A Scalar or n-dimensional ValueRank takes a range of n dimensions, or n + 1 for a String or ByteString,
///   whose last dimension then names a substring of each element: otherwise Bad_IndexRangeNoData for a scalar
///   or one-dimensional Value (SVR-ATTR-WRITE-021) and Bad_IndexRangeInvalid for a multi-dimensional one
///   (SVR-ATTR-WRITE-020).
/// - The value is an array (OPC 10000-4 section 5.10.4.2, Table 59): otherwise Bad_TypeMismatch. A ByteString
///   counts as an array of Byte where one is expected (Table 59), and a substring of a scalar String or
///   ByteString is written as a scalar of that type, the form the merge accepts (the specification is
///   silent).
/// - The value's size in each dimension, and for a substring each element's length, equals the range's
///   (OPC 10000-4 section 7.27): otherwise Bad_IndexRangeInvalid. A value without ArrayDimensions written to
///   a multi-dimensional range holds as many elements as the range selects, which the merge places in
///   row-major order.
StatusCode check_range_write_shape(const Variant& written, const ParsedNumericRange& range,
  const std::optional<ValueRank>& declaredRank, const std::optional<BuiltInTypeId>& declaredBase,
  const NodeId& nodeId)
{
  const size_t rangeDimensions = range.dimension_count();
  const auto builtIn = written.get_built_in_type();
  const bool writtenStrings = builtIn == BuiltInTypeId::String || builtIn == BuiltInTypeId::ByteString;
  const bool declaredStrings =
    declaredBase && (*declaredBase == BuiltInTypeId::String || *declaredBase == BuiltInTypeId::ByteString);
  const bool byteArrayExpected = declaredBase && *declaredBase == BuiltInTypeId::Byte;
  const int32_t rank = declaredRank ? declaredRank->as_int32() : ValueRank::any;
  const bool rankFixed = rank == ValueRank::scalar || rank >= 1;

  if (rankFixed)
  {
    const size_t dimensions = rank == ValueRank::scalar ? 0 : static_cast<size_t>(rank);
    if (rangeDimensions != dimensions && !(declaredStrings && rangeDimensions == dimensions + 1))
    {
      return StatusCode{rank >= 2 ? Status::BadIndexRangeInvalid : Status::BadIndexRangeNoData,
        ErrorDetail::build("IndexRangeRankMismatch",
          "The IndexRange's number of dimensions does not fit the ValueRank",
          "AttributeServiceSet")
          .context(ua::ContextKeys::actual, std::to_string(rangeDimensions))
          .context(ua::ContextKeys::expected, std::to_string(dimensions))
          .context(ua::ContextKeys::nodeId, to_string(nodeId))};
    }
  }

  auto notAnArray = [&nodeId](const char* summary)
  {
    return StatusCode{Status::BadTypeMismatch,
      ErrorDetail::build("IndexRangeValueNotAnArray", summary, "AttributeServiceSet")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
  };
  auto sizeMismatch = [&nodeId](const char* summary, size_t dimension, size_t expected, size_t actual)
  {
    return StatusCode{Status::BadIndexRangeInvalid,
      ErrorDetail::build("IndexRangeSizeMismatch", summary, "AttributeServiceSet")
        .context(ua::ContextKeys::index, std::to_string(dimension))
        .context(ua::ContextKeys::sizeExpected, std::to_string(expected))
        .context(ua::ContextKeys::sizeActual, std::to_string(actual))
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
  };
  auto elementLength = [](const Variant& value, size_t i) -> size_t
  {
    if (value.get_built_in_type() == BuiltInTypeId::String)
    {
      return value.is_array() ? string_view{value.as<Array<String>>()[i]}.size()
                              : string_view{value.as<String>()}.size();
    }
    return value.is_array() ? value.as<Array<ByteString>>()[i].size() : value.as<ByteString>().size();
  };

  // The value's size in each dimension.
  std::vector<size_t> sizes;
  if (written.is_array())
  {
    if (rank == ValueRank::scalar)
    {
      return notAnArray("A substring of a scalar String or ByteString is written as a scalar of that type");
    }
    const auto& array = written.get_array_base();
    if (const auto& dimensions = array.dimensions(); dimensions && dimensions->size() >= 2)
    {
      for (const auto extent : *dimensions)
      {
        sizes.push_back(extent < 0 ? 0 : static_cast<size_t>(extent));
      }
    }
    else
    {
      sizes.push_back(array.size());
    }
  }
  else if (byteArrayExpected && builtIn == BuiltInTypeId::ByteString)
  {
    sizes.push_back(written.as<ByteString>().size());
  }
  else if (writtenStrings && !(rankFixed && rank >= 1))
  {
    // A substring of a scalar String or ByteString: one dimension, the substring's.
    if (rangeDimensions != 1)
    {
      return notAnArray("The value of an IndexRange write must be an array");
    }
    if (const auto length = elementLength(written, 0); length != range.element_count(0))
    {
      return sizeMismatch(
        "The written substring's length does not match the IndexRange", 0, range.element_count(0), length);
    }
    return StatusCode{Status::Good};
  }
  else
  {
    return notAnArray("The value of an IndexRange write must be an array, even of one element");
  }

  // A String or ByteString array takes one more range dimension than its elements' own, naming a substring of
  // each element: by the declared ValueRank where it is fixed, otherwise by the value's own dimensions.
  const size_t declaredDimensions = rank >= 1 ? static_cast<size_t>(rank) : 0;
  const bool substring = writtenStrings && !(byteArrayExpected && !written.is_array()) &&
                         rangeDimensions == (rankFixed ? declaredDimensions : sizes.size()) + 1;
  const size_t elementDimensions = substring ? rangeDimensions - 1 : rangeDimensions;
  if (sizes.size() == elementDimensions)
  {
    for (size_t k = 0; k < sizes.size(); ++k)
    {
      if (sizes[k] != range.element_count(k))
      {
        return sizeMismatch(
          "The written value's size does not match the IndexRange", k, range.element_count(k), sizes[k]);
      }
    }
  }
  else if (sizes.size() == 1 && elementDimensions >= 2)
  {
    // A value without ArrayDimensions fills a multi-dimensional selection in row-major order, as the merge
    // does: it holds as many elements as the range selects.
    size_t selected = 1;
    for (size_t k = 0; k < elementDimensions; ++k)
    {
      selected *= range.element_count(k);
    }
    if (sizes[0] != selected)
    {
      return sizeMismatch(
        "The written value's element count does not match the elements the IndexRange selects",
        0,
        selected,
        sizes[0]);
    }
  }
  else
  {
    return StatusCode{Status::BadIndexRangeInvalid,
      ErrorDetail::build("IndexRangeSizeMismatch",
        "The written value's number of dimensions does not match the IndexRange's",
        "AttributeServiceSet")
        .context(ua::ContextKeys::sizeExpected, std::to_string(elementDimensions))
        .context(ua::ContextKeys::sizeActual, std::to_string(sizes.size()))
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
  }
  if (substring)
  {
    const size_t last = rangeDimensions - 1;
    const size_t elements = written.get_array_base().size();
    for (size_t i = 0; i < elements; ++i)
    {
      if (const auto length = elementLength(written, i); length != range.element_count(last))
      {
        return sizeMismatch("A written element's length does not match the IndexRange's substring",
          last,
          range.element_count(last),
          length);
      }
    }
  }
  return StatusCode{Status::Good};
}

/// SVR-ATTR-WRITE-008: the written value against the declared DataType, as far as that can be
/// decided without leaving the node.
///
/// NS0 numeric ids 1 to 25 are the built-in types and must match exactly, except BaseDataType (24),
/// the root of the DataType hierarchy, whose id is the built-in id of Variant: every value's type is a
/// subtype of it, so it constrains nothing. 26, 27 and 28 are the abstract numeric supertypes - Number,
/// Integer and UInteger - which accept only their concrete subtypes per the OPC UA DataType hierarchy.
/// Anything above 28 is an enum or a structure, whose check needs the DataType node itself and so
/// belongs to the asynchronous phase.
///
/// @return Good when there is nothing to object to, including when the declared type is one this
///         check cannot decide.
StatusCode check_declared_type(const NodeId& declaredDataType, const Variant& written, const NodeId& nodeId)
{
  if (declaredDataType.is_null() || declaredDataType.namespace_index() != 0 || !declaredDataType.is_numeric())
  {
    return StatusCode{Status::Good};
  }

  const auto numericId = declaredDataType.identifier().get_numeric();
  const auto writtenTypeId = written.get_built_in_type();
  if (writtenTypeId == BuiltInTypeId::Null)
  {
    return StatusCode{Status::Good};
  }

  if (numericId == utils::to_underlying(DataTypeId::BaseDataType))
  {
    // Part 4 section 5.10.4.2: subtypes of the Attribute's DataType are accepted.
    return StatusCode{Status::Good};
  }

  if (numericId > 0 && numericId <= 25)
  {
    const auto declaredTypeId = static_cast<BuiltInTypeId>(numericId);
    const bool byteStringToByte =
      (declaredTypeId == BuiltInTypeId::Byte && writtenTypeId == BuiltInTypeId::ByteString);
    if (writtenTypeId == declaredTypeId || byteStringToByte)
    {
      return StatusCode{Status::Good};
    }
    return StatusCode{Status::BadTypeMismatch,
      ErrorDetail::build("TypeMismatch", "Written type does not match declared type", "AttributeServiceSet")
        .context(ua::ContextKeys::typeActual, to_string(writtenTypeId))
        .context(ua::ContextKeys::typeExpected, to_string(declaredTypeId))
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
  }

  if (numericId < 26 || numericId > 28)
  {
    // An enum or structure: decided later, with the DataType node in hand.
    return StatusCode{Status::Good};
  }

  const bool isSignedInteger =
    (writtenTypeId == BuiltInTypeId::SByte || writtenTypeId == BuiltInTypeId::Int16 ||
      writtenTypeId == BuiltInTypeId::Int32 || writtenTypeId == BuiltInTypeId::Int64);
  const bool isUnsignedInteger =
    (writtenTypeId == BuiltInTypeId::Byte || writtenTypeId == BuiltInTypeId::UInt16 ||
      writtenTypeId == BuiltInTypeId::UInt32 || writtenTypeId == BuiltInTypeId::UInt64);
  const bool isFloatingPoint =
    (writtenTypeId == BuiltInTypeId::Float || writtenTypeId == BuiltInTypeId::Double);

  const bool isCompatible = numericId == 26   ? (isSignedInteger || isUnsignedInteger || isFloatingPoint)
                            : numericId == 27 ? isSignedInteger
                                              : isUnsignedInteger;
  if (isCompatible)
  {
    return StatusCode{Status::Good};
  }

  std::string_view abstractTypeName = "UInteger";
  if (numericId == 26)
  {
    abstractTypeName = "Number";
  }
  else if (numericId == 27)
  {
    abstractTypeName = "Integer";
  }
  return StatusCode{Status::BadTypeMismatch,
    ErrorDetail::build("TypeMismatch",
      "Written type is not a valid subtype of the declared abstract type",
      "AttributeServiceSet")
      .context(ua::ContextKeys::typeActual, to_string(writtenTypeId))
      .context(ua::ContextKeys::typeExpected, std::string{abstractTypeName})
      .context(ua::ContextKeys::nodeId, to_string(nodeId))};
}

/// SVR-ATTR-WRITE-025: the written value against an enumerated DataType's declared members.
StatusCode check_enum_member(
  const shared_ptr<const DataTypeDefinition>& definition, const Variant& written, const NodeId& nodeId)
{
  const auto* enumDefinition = dynamic_cast<const EnumDefinition*>(definition.get());
  if (enumDefinition == nullptr)
  {
    return StatusCode{Status::Good};
  }

  const auto* writtenInt32 = written.try_as<int32_t>();
  if (writtenInt32 == nullptr)
  {
    return StatusCode{Status::Good};
  }

  for (size_t i = 0; i < enumDefinition->fields().size(); ++i)
  {
    if (enumDefinition->fields()[i].value() == *writtenInt32)
    {
      return StatusCode{Status::Good};
    }
  }

  return StatusCode{Status::BadOutOfRange,
    ErrorDetail::build(
      "EnumOutOfRange", "Value is not a valid enum value for the node's DataType", "AttributeServiceSet")
      .context(ua::ContextKeys::actual, std::to_string(*writtenInt32))
      .context(ua::ContextKeys::nodeId, to_string(nodeId))};
}

}  // namespace

namespace
{

/// Why a write of an Attribute other than a Variable's Value cannot be performed as sent, or nothing.
///
/// Part 4 5.10.4.2 Table 59: "A Server shall return a Bad_WriteNotSupported error if an indexRange is
/// provided and writing of indexRange is not possible for the Node" and "The Server returns a
/// Bad_WriteNotSupported error if it does not support writing of timestamps"; 5.10.4.4 Table 61, for a value,
/// status code and timestamp combination the Server does not support, "the Server shall not perform any write
/// on this Node and shall return this StatusCode". The SDK keeps no timestamps or status for these
/// Attributes, a VariableType's Value included, so any of the three is refused. A status of 0 and a null
/// timestamp are what an unset field encodes as, so they are not; a Good status with info bits is.
std::optional<StatusCode> unsupported_non_value_write(const WriteValue& nodeToWrite)
{
  const auto refuse = [&nodeToWrite](auto detail)
  {
    return StatusCode{Status::BadWriteNotSupported,
      detail.context(ua::ContextKeys::nodeId, to_string(nodeToWrite.node_id()))
        .context(
          ua::ContextKeys::nodeAttribute, to_string(static_cast<AttributeId>(nodeToWrite.attribute_id())))};
  };
  if (!nodeToWrite.index_range().empty())
  {
    return refuse(ErrorDetail::build("IndexRangeWriteNotSupported",
      "An IndexRange is written only to a Variable's Value",
      "AttributeServiceSet"));
  }
  const DataValue& written = nodeToWrite.value();
  if (const auto& status = written.status(); status.has_value() && status->as_uint32() != 0)
  {
    return refuse(ErrorDetail::build(
      "StatusWriteNotSupported", "A status is written only with a Variable's Value", "AttributeServiceSet"));
  }
  const auto isSet = [](const std::optional<DateTime>& timestamp)
  {
    return timestamp.has_value() && !timestamp->is_null();
  };
  if (isSet(written.source_timestamp()) || isSet(written.server_timestamp()))
  {
    return refuse(ErrorDetail::build("TimestampWriteNotSupported",
      "A timestamp is written only with a Variable's Value",
      "AttributeServiceSet"));
  }
  return std::nullopt;
}

/// Why the ArrayDimensions a write sends do not fit the node's ValueRank, or nothing.
///
/// Part 3 5.6.2 Table 13, for a Variable: "The number of elements shall be equal to the number of dimensions
/// of the Value. This Attribute shall be null if the Value is not an array."; 5.6.5 Table 14, for a
/// VariableType: "The number of elements shall be equal to the value of the ValueRank Attribute. This
/// Attribute shall be null if ValueRank <= 0." Only what the ValueRank decides is checked: a Variable of
/// ValueRank 0 or -2 takes any count, its Value deciding it. Null and an empty array mean the same (Part
/// 6 5.1.9) and fit every ValueRank; a value that is not a one-dimensional array of UInt32 is left to the
/// encoder. A misfit is answered as a Value of the wrong rank is (Part 4 5.10.4.2 Table 59), with the same
/// detail: the number of dimensions written as `actual` and the declared ValueRank as `expected`.
std::optional<StatusCode> misfitting_array_dimensions(const NodeAccessor& node, const WriteValue& nodeToWrite)
{
  const Variant& written = nodeToWrite.value().value();
  if (written.empty() || !written.is_array_of_uint32())
  {
    return std::nullopt;
  }
  if (const auto& shape = written.get_array_base().dimensions(); shape.has_value() && shape->size() > 1)
  {
    return std::nullopt;
  }
  const auto count = written.as<Array<uint32_t>>().payload().size();
  if (count == 0)
  {
    return std::nullopt;
  }
  const auto variableType = node.as<VariableTypeAccessor>();
  std::optional<ValueRank> declared;
  try
  {
    if (variableType)
    {
      declared = variableType->get_value_rank();
    }
    else if (const auto variable = node.as<VariableAccessor>())
    {
      declared = variable->get_value_rank();
    }
  }
  catch (...)
  {
    // A stored ValueRank that cannot be read leaves nothing to check against, as on the Value path.
    ua::detail::ignore_expected_exception();
  }
  if (!declared)
  {
    return std::nullopt;
  }
  const int32_t rank = declared->as_int32();
  std::optional<size_t> expected;
  if (rank > 0)
  {
    expected = static_cast<size_t>(rank);
  }
  else if (variableType || rank == ValueRank::scalar)
  {
    expected = 0;
  }
  else if (rank == ValueRank::scalarOrOneDimension)
  {
    expected = 1;
  }
  if (!expected || count == *expected)
  {
    return std::nullopt;
  }
  return StatusCode{Status::BadTypeMismatch,
    ErrorDetail::build(
      "ValueRankMismatch", "ArrayDimensions does not fit the ValueRank", "AttributeServiceSet")
      .context(ua::ContextKeys::actual, std::to_string(count))
      .context(ua::ContextKeys::expected, std::to_string(rank))
      .context(ua::ContextKeys::nodeId, to_string(nodeToWrite.node_id()))};
}

}  // namespace

namespace
{

/// SVR-ATTR-WRITE-008: the declared DataType's built-in base as its own id gives it: namespace 0 ids 1 to 25.
std::optional<BuiltInTypeId> built_in_base_of_id(const NodeId& declaredDataType)
{
  if (declaredDataType.namespace_index() == 0 && declaredDataType.is_numeric() &&
      declaredDataType.identifier().get_numeric() > 0 && declaredDataType.identifier().get_numeric() <= 25)
  {
    return static_cast<BuiltInTypeId>(declaredDataType.identifier().get_numeric());
  }
  return std::nullopt;
}

/// The Structures a written value holds: a scalar one, or the elements of an array of them (a null element
/// included, as null).
std::vector<const Structure*> written_structures(const Variant& written)
{
  std::vector<const Structure*> structures;
  if (const auto* scalar = written.try_as<RefStructure<Structure>>())
  {
    structures.push_back(scalar->get());
  }
  else if (const auto* array = written.try_as<Array<RefStructure<Structure>>>())
  {
    for (const auto& element : array->payload())
    {
      structures.push_back(element.get());
    }
  }
  return structures;
}

/// The written type of a Structure that is not an UnknownStructure, or the name to report when its namespace
/// is not one this server knows.
std::variant<NodeId, std::string> decoded_structure_type(
  const Structure& structure, const AddressSpace& addressSpace)
{
  try
  {
    return structure.type_id(addressSpace.codec_namespace_context());
  }
  catch (...)
  {
    return std::string{structure.type_name()};
  }
}

StatusCode structure_mismatch(
  const NodeId& declaredType, const NodeId& nodeId, const std::string& writtenType)
{
  return StatusCode{Status::BadTypeMismatch,
    ErrorDetail::build("TypeMismatch",
      "Written structure is neither the declared DataType nor a subtype of it",
      "AttributeServiceSet")
      .context(ua::ContextKeys::typeActual, writtenType)
      .context(ua::ContextKeys::typeExpected, to_string(declaredType))
      .context(ua::ContextKeys::nodeId, to_string(nodeId))};
}

}  // namespace

ua::async::Task<std::optional<StatusCode>> AttributeServiceSet::translate_dictionary_write(
  WriteOperation& operation)
{
  auto* flow = &operation;
  auto projection = co_await project_dictionary(flow->addressSpace, *flow->node);

  if (!projection.is_good())
  {
    // The write is translated from the snapshot's tables, which the SDK does not do from reads the namespace
    // answered Uncertain, with or without a value.
    co_return server::detail::not_acted_on(server::detail::readAnswerUncertain,
      projection.status_code(),
      "AttributeServiceSet",
      flow->nodeToWrite.node_id());
  }
  const auto& dictionaryProjection = projection.value();
  if (!dictionaryProjection.has_value())
  {
    co_return StatusCode{Status::BadNotWritable,
      ErrorDetail::build("DictionaryOwnerUnavailable",
        "ValueAsDictionaryEntries has no resolvable owning Variable",
        "AttributeServiceSet")
        .context(ContextKeys::nodeId, flow->nodeToWrite.node_id())};
  }

  auto target =
    data_access_projection::dictionary_write_target(dictionaryProjection.value(), flow->nodeToWrite.value());
  if (!target.is_good())
  {
    co_return target.status_code();
  }

  auto translated = std::move(target).value();
  flow->nodeToWrite.node_id() = translated.owner.get_node_id();
  flow->nodeToWrite.value() = std::move(translated.value);
  flow->dictionaryWriteTranslated = true;
  flow->node = std::move(translated.owner);
  flow->variable = flow->node->as<VariableAccessor>();

  // The owner is a DIFFERENT node from the one the request named and the batch authorized, so it is
  // authorized in its own right.
  if (!mWriteAccessControl)
  {
    co_return StatusCode{Status::BadUserAccessDenied};
  }

  const std::array item{
    AccessControl::Item{*flow->node, write_access_operation(*flow->node, flow->attributeId)}};
  auto verdicts = co_await await_step<std::vector<AccessControl::Verdict>>([this, &item](auto completion)
    { mWriteAccessControl->authorize_async(mRequestInfo, item, std::move(completion)); });

  // SVR-AUTHZ-015: the one verdict rule, the same as the Read half of the owner authorization.
  if (auto denial = detail::first_denial(verdicts, item.size()))
  {
    co_return std::move(*denial);
  }
  co_return std::nullopt;
}

void AttributeServiceSet::early_write_checks(WriteOperation& operation, bool auditInterest)
{
  // A refusal whose detail goes to the collector while the item's status carries none, as today.
  const auto refuseNoting = [this, &operation](Status status, shared_ptr<const ErrorDetail> detail)
  {
    mWriteCollector.add_item_detail(operation.opIndex, std::move(detail));
    operation.answer = StatusCode{status};
  };
  const NodeId& nodeId = operation.nodeToWrite.node_id();

  // SVR-SECADMIN-057: the per-Node UserRolePermissions Attribute is the per-Session-derived view of
  // RolePermissions - Part 3 5.2.10 L1936 "shall not be writeable". Rejected regardless of Role, and
  // BEFORE audit interest is determined, so the rejection emits no AuditWriteUpdateEventPayload.
  if (operation.attributeId == AttributeId::UserRolePermissions)
  {
    operation.kind = WriteOperation::Kind::Attribute;
    operation.answer = StatusCode{Status::BadNotWritable,
      ErrorDetail::build("UserRolePermissionsNotWritable",
        "The UserRolePermissions Attribute is a read-only per-Session derived view and cannot be written",
        "server.tier1.authz.rbac.user_role_permissions.not_writable")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
    return;
  }

  auto& node = *operation.node;

  // SVR-SECADMIN-048..053: a RolePermissions write is gated by the Part 18 2.4b stack. Its checks come
  // before audit interest is determined, so a refusal emits no audit event (SVR-EVT-AUD-022); audit
  // interest is determined once the owning namespace has accepted the update.
  if (operation.attributeId == AttributeId::RolePermissions)
  {
    operation.kind = WriteOperation::Kind::RolePermissions;
    if (auto sessionInfo = mSessionInfo.lock(); !sessionInfo || !mWriteAccessControl)
    {
      refuseNoting(Status::BadUserAccessDenied,
        ErrorDetail::build("AuthorizationUnavailable",
          "RolePermissions Write denied: no committed access identity is available",
          "AttributeServiceSet")
          .context(ua::ContextKeys::nodeId, to_string(nodeId)));
      return;
    }
    auto decoded = attribute_wire::decode_role_permissions(operation.nodeToWrite.value().value());
    if (!decoded.is_good())
    {
      operation.answer = decoded.status_code();
      return;
    }
    // The WriteMask check remains the node's capability gate. The canonical AccessControl helper has
    // already discharged Table 37 bit 3; the operability invariant belongs to the owning namespace.
    const auto writeMask = node.get_write_mask();
    if (!writeMask || !writeMask->test(AttributeWriteMask::Bit::RolePermissions))
    {
      refuseNoting(Status::BadNotWritable,
        ErrorDetail::build("NotWritable",
          "WriteMask does not permit writing the RolePermissions Attribute",
          "AttributeServiceSet")
          .context(ua::ContextKeys::nodeId, to_string(nodeId)));
      return;
    }
    // A range would replace every entry with the ones sent; refused whole instead.
    if (auto refused = unsupported_non_value_write(operation.nodeToWrite))
    {
      operation.answer = *refused;
      return;
    }
    if (!operation.addressSpace.namespace_array().get_namespace(nodeId.namespace_index()))
    {
      refuseNoting(Status::BadNodeIdUnknown,
        ErrorDetail::build("RolePermissionsNamespaceMissing",
          "The namespace owning the RolePermissions Attribute is no longer registered",
          "AttributeServiceSet")
          .context(ua::ContextKeys::nodeId, to_string(nodeId))
          .context(ua::ContextKeys::namespaceIndex, nodeId.namespace_index()));
      return;
    }
    auto proposed = std::move(decoded).value();
    if (!proposed.empty())
    {
      operation.proposedRolePermissions = std::move(proposed);
    }
    return;
  }

  operation.auditActive = auditInterest;

  // --- a non-Value attribute takes its own path, and so does a VariableType's Value ---------------
  // A VariableType's Value is part of the type's description, writable when its WriteMask has
  // ValueForVariableType (Part 3 8.60 Table 43); the Variable's AccessLevel rules below do not apply.
  const auto variableType = operation.attributeId == AttributeId::Value && !operation.variable
                              ? node.as<VariableTypeAccessor>()
                              : std::nullopt;
  if (operation.attributeId != AttributeId::Value || variableType)
  {
    operation.kind = variableType ? WriteOperation::Kind::VariableTypeValue : WriteOperation::Kind::Attribute;
    auto writeMask = node.get_write_mask();
    auto maskBit = variableType
                     ? optional<AttributeWriteMask::Bit>{AttributeWriteMask::Bit::ValueForVariableType}
                     : attribute_id_to_write_mask_bit(operation.attributeId);
    if (!maskBit)
    {
      refuseNoting(Status::BadAttributeIdInvalid,
        ErrorDetail::build(
          "AttributeIdInvalid", "Attribute has no corresponding WriteMask bit", "AttributeServiceSet")
          .context(ua::ContextKeys::nodeAttribute, to_string(operation.attributeId))
          .context(ua::ContextKeys::nodeId, to_string(nodeId)));
      return;
    }
    if (!writeMask || !writeMask->test(*maskBit))
    {
      operation.answer = StatusCode{Status::BadNotWritable,
        ErrorDetail::build(
          "NotWritable", "WriteMask does not permit writing the attribute", "AttributeServiceSet")
          .context(ua::ContextKeys::nodeId, to_string(nodeId))
          .context(ua::ContextKeys::nodeAttribute, to_string(operation.attributeId))};
      return;
    }
    // What this path cannot write is refused whole, rather than written without it.
    if (auto refused = unsupported_non_value_write(operation.nodeToWrite))
    {
      operation.answer = *refused;
      return;
    }
    if (operation.attributeId == AttributeId::ArrayDimensions)
    {
      if (auto refused = misfitting_array_dimensions(node, operation.nodeToWrite))
      {
        operation.answer = *refused;
        return;
      }
    }
    if (auto localeError = validate_localized_text_write(
          operation.nodeToWrite.value().value(), operation.attributeId, nodeId, mWriteSupportedLocales))
    {
      operation.answer = *localeError;
      return;
    }
    if (variableType)
    {
      // An Attribute that cannot be read leaves nothing to check against, as on the Variable path.
      try
      {
        operation.declaredDataType = variableType->get_data_type();
      }
      catch (...)
      {
        ua::detail::ignore_expected_exception();
      }
      try
      {
        operation.declaredRank = variableType->get_value_rank();
      }
      catch (...)
      {
        ua::detail::ignore_expected_exception();
      }
      // A null Value is accepted: the type then gives its instances no default.
      if (!operation.nodeToWrite.value().value().empty())
      {
        if (const auto mismatch =
              check_declared_type(operation.declaredDataType, operation.nodeToWrite.value().value(), nodeId);
            mismatch.is_bad())
        {
          operation.answer = mismatch;
        }
      }
    }
    return;
  }

  // --- what the Variable's AccessLevel permits ---------------------------------------------------
  operation.kind = WriteOperation::Kind::VariableValue;
  if (!operation.variable)
  {
    operation.kind = WriteOperation::Kind::Attribute;
    operation.answer = StatusCode{Status::BadAttributeIdInvalid,
      ErrorDetail::build(
        "AttributeIdInvalid", "Node is not a Variable; cannot write Value attribute", "AttributeServiceSet")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
    return;
  }

  const auto accessLevel = operation.variable->get_access_level();
  if (!accessLevel.test(AccessLevelType::Bit::CurrentWrite))
  {
    operation.answer = StatusCode{Status::BadNotWritable,
      ErrorDetail::build("NotWritable",
        "Variable does not permit writing (CurrentWrite not set in AccessLevel)",
        "AttributeServiceSet")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
    return;
  }

  // OPC 10000-3 section 8.57: without StatusWrite "only StatusCode Good is writable", so a Value that states
  // Good explicitly is written as one that states nothing; a Good subcode is not Good.
  if (const auto& writtenStatus = operation.nodeToWrite.value().status();
      writtenStatus.has_value() && writtenStatus->as_status() != Status::Good &&
      !accessLevel.test(AccessLevelType::Bit::StatusWrite))
  {
    operation.answer = StatusCode{Status::BadWriteNotSupported,
      ErrorDetail::build("StatusWriteNotSupported",
        "Variable does not permit status writes (StatusWrite not set in AccessLevel)",
        "AttributeServiceSet")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
    return;
  }

  // OPC 10000-3 section 8.57: without TimestampWrite "only null timestamps are writable"; a Server that does
  // not write a timestamp says so with Bad_WriteNotSupported (OPC 10000-4 section 5.10.4.2).
  if (const auto& sourceTimestamp = operation.nodeToWrite.value().source_timestamp();
      sourceTimestamp.has_value() && !sourceTimestamp->is_null() &&
      !accessLevel.test(AccessLevelType::Bit::TimestampWrite))
  {
    operation.answer = StatusCode{Status::BadWriteNotSupported,
      ErrorDetail::build("TimestampWriteNotSupported",
        "Variable does not permit SourceTimestamp writes (TimestampWrite not set in AccessLevel)",
        "AttributeServiceSet")
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
    return;
  }

  try
  {
    operation.declaredDataType = operation.variable->get_data_type();
  }
  catch (...)
  {
    // DataType attribute not set: there is no declared type to check against.
    ua::detail::ignore_expected_exception();
  }
  try
  {
    operation.declaredRank = operation.variable->get_value_rank();
  }
  catch (...)
  {
    // A stored ValueRank that is not an Int32: there is no declared rank to check against.
    ua::detail::ignore_expected_exception();
  }

  // A null Value has no type to compare; the AllowNulls policy decides it once its Property is read.
  if (!operation.nodeToWrite.value().value().empty())
  {
    if (const auto mismatch =
          check_declared_type(operation.declaredDataType, operation.nodeToWrite.value().value(), nodeId);
        mismatch.is_bad())
    {
      operation.answer = mismatch;
    }
  }
}

void AttributeServiceSet::typed_value_checks(WriteOperation& operation, const DataTypeFacts* facts)
{
  const Variant& written = operation.nodeToWrite.value().value();
  const NodeId& nodeId = operation.nodeToWrite.node_id();
  operation.declaredBase = built_in_base_of_id(operation.declaredDataType);
  if (facts == nullptr || !facts->found)
  {
    return;
  }

  StatusCode enumCheck{Status::Good};
  try
  {
    enumCheck = check_enum_member(facts->definition, written, nodeId);
  }
  catch (...)
  {
    // A definition that will not parse is not a reason to reject the write.
    ua::detail::ignore_expected_exception();
  }
  if (enumCheck.is_bad())
  {
    operation.answer = enumCheck;
    return;
  }

  // A few NS0 String subtypes constrain their own lexical form (OPC 10000-3 sections 8.43 to 8.47), and no
  // built-in type check can see it: they are all String on the wire and in a Variant.
  const NodeId& declaredId = facts->ownId;
  if (const StatusCode lexical = string_lexical_validation::validate(declaredId, written); lexical.is_bad())
  {
    operation.answer = StatusCode{lexical.value(),
      ErrorDetail::build("LexicalFormInvalid",
        "Written value is outside the lexical space its declared DataType defines",
        "AttributeServiceSet")
        .context(ua::ContextKeys::typeExpected, ua::to_string(declaredId))
        .context(ua::ContextKeys::nodeId, ua::to_string(nodeId))};
    return;
  }

  // Nodes whose declared DataType is a non-builtin subtype (Duration of Double, Image of ByteString) were
  // skipped by the check on the declared id alone, which can only decide NS0 ids up to 28.
  if (WriteTypeFacts::needs_no_lookup(declaredId))
  {
    return;
  }
  const auto baseType = facts->base;
  operation.declaredBase = baseType;
  // Variant is the BaseDataType root, which accepts anything, so it is "no constraint" too.
  if (!baseType.has_value() || *baseType == BuiltInTypeId::Variant)
  {
    return;
  }
  const BuiltInTypeId writtenType = written.get_built_in_type();
  const bool byteStringToByte =
    (*baseType == BuiltInTypeId::Byte && writtenType == BuiltInTypeId::ByteString);
  if (writtenType != *baseType && writtenType != BuiltInTypeId::Null && !byteStringToByte)
  {
    operation.answer = StatusCode{Status::BadTypeMismatch,
      ErrorDetail::build("TypeMismatch",
        "Written type does not match the built-in base type of the declared DataType",
        "AttributeServiceSet")
        .context(ua::ContextKeys::typeActual, to_string(writtenType))
        .context(ua::ContextKeys::typeExpected, to_string(*baseType))
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
    return;
  }
  if (*baseType == BuiltInTypeId::ExtensionObject)
  {
    operation.structureType = declaredId;
  }
}

void AttributeServiceSet::structure_and_rank_checks(WriteOperation& operation, const WriteFactsCache& facts)
{
  const Variant& written = operation.nodeToWrite.value().value();
  const NodeId& nodeId = operation.nodeToWrite.node_id();
  if (operation.structureType)
  {
    const NodeId& declaredType = *operation.structureType;
    for (const Structure* structure : written_structures(written))
    {
      if (structure == nullptr)
      {
        // A null element of an array carries no type to compare.
        continue;
      }
      NodeId writtenType;
      if (const auto* unknown = dynamic_cast<const UnknownStructure*>(structure))
      {
        // Not decoded: the encoding Node names its DataType by an inverse HasEncoding Reference.
        const auto known = facts.encodings.find(unknown->encoding_id());
        if (known == facts.encodings.end() || !known->second.found)
        {
          operation.answer = structure_mismatch(
            declaredType, nodeId, fmt::format("unknown encoding {}", to_string(unknown->encoding_id())));
          return;
        }
        const auto& dataType = known->second.dataType;
        if (!dataType)
        {
          operation.answer = structure_mismatch(declaredType,
            nodeId,
            fmt::format("encoding {} of no DataType", to_string(unknown->encoding_id())));
          return;
        }
        writtenType = dataType.value();
      }
      else
      {
        auto decoded = decoded_structure_type(*structure, operation.addressSpace);
        if (const auto* name = std::get_if<std::string>(&decoded))
        {
          operation.answer = structure_mismatch(declaredType, nodeId, *name);
          return;
        }
        writtenType = std::get<NodeId>(std::move(decoded));
      }
      if (writtenType == declaredType)
      {
        continue;
      }
      const auto subtype = facts.subtypes.find(std::make_pair(writtenType, declaredType));
      if (subtype == facts.subtypes.end() || !subtype->second)
      {
        operation.answer = structure_mismatch(declaredType, nodeId, to_string(writtenType));
        return;
      }
    }
  }

  // --- the written value's rank against the ValueRank ---------------------------------------------
  // An indexRange Write writes a slice whose shape the range sets.
  if (operation.nodeToWrite.index_range().empty() && operation.declaredRank.has_value())
  {
    const bool byteArrayExpected =
      operation.declaredBase.has_value() && *operation.declaredBase == BuiltInTypeId::Byte;
    if (const auto rank = check_value_rank(*operation.declaredRank, written, byteArrayExpected, nodeId);
        rank.is_bad())
    {
      operation.answer = rank;
    }
  }
}

void AttributeServiceSet::late_write_checks(WriteOperation& operation, const WriteFactsCache& facts)
{
  const NodeId& nodeId = operation.nodeToWrite.node_id();
  // Part 4 section 7.24: an IndexRange write is a read-modify-write of the stored array, which the namespace
  // performs, deciding whether the range lies within the Value it holds (NR-11 rule 3). WriteFullArrayOnly,
  // the range's syntax and whether the written value is consistent with the range (NR-11 rule 1, DL-115 (1))
  // are checked here.
  if (!operation.nodeToWrite.index_range().empty())
  {
    const auto accessLevelEx = operation.variable->get_access_level_ex();
    if (accessLevelEx && accessLevelEx->test(AccessLevelExType::Bit::WriteFullArrayOnly))
    {
      operation.answer = StatusCode{Status::BadWriteNotSupported,
        ErrorDetail::build("IndexRangeWriteNotSupported",
          "IndexRange writes are not supported when WriteFullArrayOnly is set",
          "AttributeServiceSet")
          .context(ua::ContextKeys::nodeId, nodeId)};
      return;
    }
    auto rangeResult = parse_numeric_range(operation.nodeToWrite.index_range());
    if (!rangeResult.is_good())
    {
      operation.answer = rangeResult.status_code();
      return;
    }
    if (const auto shape = check_range_write_shape(operation.nodeToWrite.value().value(),
          rangeResult.value(),
          operation.declaredRank,
          operation.declaredBase,
          nodeId);
        shape.is_bad())
    {
      operation.answer = shape;
    }
    return;
  }

  // Part 3 section 8.40: a written OptionSet carrying ValidBits merges into the stored one, which the
  // namespace performs; the ValidBits are checked here.
  const auto* written = operation.nodeToWrite.value().value().try_as<OptionSet>();
  if (written == nullptr || written->valid_bits().empty())
  {
    return;
  }
  if (written->valid_bits().size() != written->value().size())
  {
    operation.answer = StatusCode{Status::BadOutOfRange,
      ErrorDetail::build("OptionSetValidBitsSizeMismatch",
        "OptionSet ValidBits size does not match Value size",
        "AttributeServiceSet")
        .context(ua::ContextKeys::sizeActual, std::to_string(written->valid_bits().size()))
        .context(ua::ContextKeys::sizeExpected, std::to_string(written->value().size()))
        .context(ua::ContextKeys::nodeId, to_string(nodeId))};
    return;
  }
  // The DataType drives server-side ValidBits filtering. A node with none simply skips it.
  const auto known = facts.declared.find(operation.declaredDataType);
  if (known == facts.declared.end() || !known->second.found)
  {
    return;
  }
  try
  {
    if (const auto* enumDefinition = dynamic_cast<const EnumDefinition*>(known->second.definition.get()))
    {
      auto serverMask = build_server_valid_bits_mask(enumDefinition->fields(), written->valid_bits().size());
      if (auto validated = validate_client_valid_bits(written->valid_bits(), serverMask); validated.is_bad())
      {
        operation.answer = validated.status_code();
      }
    }
  }
  catch (...)
  {
    // A definition that will not parse is not a reason to refuse the merge.
    ua::detail::ignore_expected_exception();
  }
}

ua::async::Task<> AttributeServiceSet::information_model_pairs(std::vector<WriteOperation>& wave)
{
  // Started together; each answers its own item.
  std::vector<std::pair<size_t, std::shared_ptr<std::optional<VoidResult>>>> checks;
  auto addressSpace = *mWriteAddressSpace;
  const auto pending = std::make_shared<std::atomic<size_t>>(1);
  auto checked = co_await await_step<bool>(
    [&](auto completion)
    {
      auto one = [pending, completion]() mutable
      {
        if (pending->fetch_sub(1, std::memory_order_acq_rel) == 1)
        {
          completion(true);
        }
      };
      for (size_t k = 0; k < wave.size(); ++k)
      {
        auto& operation = wave[k];
        if (operation.answer || operation.kind != WriteOperation::Kind::VariableValue || !operation.node ||
            !operation.nodeToWrite.index_range().empty() ||
            !operation.nodeToWrite.value().value().is_array() ||
            !is_information_model_pair(operation.node->get_browse_name()))
        {
          continue;
        }
        auto result = std::make_shared<std::optional<VoidResult>>();
        checks.emplace_back(k, result);
        pending->fetch_add(1, std::memory_order_acq_rel);
        check_information_model_pair_async(addressSpace,
          *operation.node,
          operation.nodeToWrite.value().value().get_array_base().size(),
          [result, one](VoidResult answered) mutable
          {
            *result = std::move(answered);
            one();
          });
      }
      one();
    });
  (void)checked;
  for (auto& [k, result] : checks)
  {
    const auto& pairResult = *result;
    if (!pairResult)
    {
      wave[k].answer = StatusCode{Status::BadInternalError};
    }
    else if (!pairResult.value().is_good())
    {
      wave[k].answer = pairResult.value().status_code();
    }
  }
}

namespace
{

using namespace_zero_tables::DataAccessKind;

/// Decides a TypeDefinition for the Data Access step: nullopt for a type outside namespace 0, which is walked
/// up; 0 for a namespace-0 type of no Data Access subtree; otherwise one more than its rule.
std::optional<int> data_access_decision(const NodeId& type)
{
  if (type.namespace_index() != 0)
  {
    return std::nullopt;
  }
  if (!type.is_numeric())
  {
    return 0;
  }
  const auto rows = namespace_zero_tables::data_access_variable_types();
  const uint32_t id = type.identifier().get_numeric();
  const auto found = std::ranges::lower_bound(rows,
    id,
    std::ranges::less{},
    [](const namespace_zero_tables::DataAccessTypeRow& row) { return row.id; });
  return (found != rows.end() && found->id == id) ? 1 + static_cast<int>(found->kind) : 0;
}

/// The names of the Properties that bound a Value write under @p kind, in the order they are tried.
std::vector<QualifiedName> bounding_properties(DataAccessKind kind)
{
  switch (kind)
  {
  case DataAccessKind::Analog:
    // NR-59: InstrumentRange when present, otherwise EURange.
    return {QualifiedName{0, "InstrumentRange"}, QualifiedName{0, "EURange"}};
  case DataAccessKind::MultiStateDiscrete:
    return {QualifiedName{0, "EnumStrings"}};
  case DataAccessKind::MultiStateValueDiscrete:
    return {QualifiedName{0, "EnumValues"}};
  }
  return {};
}

/// The check of one written value against the first bounding Property read that holds the expected type; a
/// Property of another type bounds nothing.
VoidResult check_data_access_value(DataAccessKind kind, Variant& value,
  const std::vector<std::optional<Variant>>& bounds, DataAccessOutOfRangePolicy policy)
{
  for (const auto& bound : bounds)
  {
    if (!bound)
    {
      continue;
    }
    switch (kind)
    {
    case DataAccessKind::Analog:
      if (const auto* range = bound->try_as<Range>())
      {
        return data_access_utils::apply_analog_range(value, *range, policy);
      }
      // A Property of another type is not a range: the next one is tried.
      continue;
    case DataAccessKind::MultiStateDiscrete:
      if (const auto* strings = bound->try_as<Array<LocalizedText>>())
      {
        return data_access_utils::check_enum_strings_index(value, strings->payload());
      }
      return VoidResult{};
    case DataAccessKind::MultiStateValueDiscrete:
      if (const auto* structures = bound->try_as<Array<RefStructure<Structure>>>())
      {
        std::vector<EnumValueType> entries;
        for (const auto& element : structures->payload())
        {
          if (const auto* entry = dynamic_cast<const EnumValueType*>(element.get()))
          {
            entries.push_back(*entry);
          }
        }
        return data_access_utils::check_enum_values_member(value, entries);
      }
      return VoidResult{};
    }
  }
  return VoidResult{};
}

/// The first local target of a read's References, or nullopt.
std::optional<NodeId> first_local_target(const std::vector<Reference>& references)
{
  for (const auto& reference : references)
  {
    if (!reference.is_remote() && reference.target_id().is_local())
    {
      return reference.target_id().node_id();
    }
  }
  return std::nullopt;
}

/// The status an item is refused with when a read the Data Access check acts on was answered @p answered, not
/// Good: a Bad answer is the item's; an Uncertain one, with or without a payload, is refused with the
/// ErrorDetail @p code (server::detail::not_acted_on).
StatusCode unanswered(std::string_view code, const StatusCode& answered, const NodeId& nodeId)
{
  return server::detail::not_acted_on(code, answered, "AttributeServiceSet", nodeId);
}

}  // namespace

ua::async::Task<> AttributeServiceSet::data_access_rules(std::vector<WriteOperation>& wave,
  DataAccessOutOfRangePolicy policy, std::optional<uint32_t> maxNodesPerBrowse,
  std::optional<uint32_t> maxNodesPerRead)
{
  auto addressSpace = *mWriteAddressSpace;
  const RequestInfo request = mRequestInfo;

  // 1. the written Variables' TypeDefinitions: one read per namespace.
  std::vector<size_t> written;
  std::vector<namespace_calls::ReferenceRead> typeReads;
  for (size_t k = 0; k < wave.size(); ++k)
  {
    const auto& operation = wave[k];
    if (operation.answer || operation.kind != WriteOperation::Kind::VariableValue || !operation.node ||
        operation.nodeToWrite.value().value().empty())
    {
      continue;
    }
    written.push_back(k);
    typeReads.push_back(namespace_calls::ReferenceRead{*operation.node,
      operation.nodeToWrite.node_id(),
      BrowseDirection::Forward,
      NodeId{ReferenceTypeId::HasTypeDefinition}});
  }
  if (written.empty())
  {
    co_return;
  }
  auto typeReferences = co_await await_step<std::vector<Result<std::vector<Reference>>>>(
    [&](auto completion)
    {
      namespace_calls::read_references(
        addressSpace, request, std::move(typeReads), maxNodesPerBrowse, std::move(completion));
    });

  // 2. each TypeDefinition's rule: a namespace-0 type from the table, any other walked up to namespace 0.
  std::vector<std::optional<NodeId>> typeOf(written.size());
  std::map<NodeId, int> decided;
  std::vector<NodeId> toWalk;
  for (size_t w = 0; w < written.size(); ++w)
  {
    auto& operation = wave[written[w]];
    if (w >= typeReferences.size())
    {
      operation.answer = StatusCode{Status::BadInternalError};
      continue;
    }
    if (!typeReferences[w].is_good())
    {
      operation.answer = unanswered(server::detail::referencesAnswerUncertain,
        typeReferences[w].status_code(),
        operation.nodeToWrite.node_id());
      continue;
    }
    typeOf[w] = first_local_target(typeReferences[w].value());
    if (!typeOf[w] || decided.contains(*typeOf[w]))
    {
      continue;
    }
    if (const auto decision = data_access_decision(*typeOf[w]))
    {
      decided.emplace(*typeOf[w], *decision);
    }
    else if (std::find(toWalk.begin(), toWalk.end(), *typeOf[w]) == toWalk.end())
    {
      toWalk.push_back(*typeOf[w]);
    }
  }
  std::map<NodeId, StatusCode> walkFailed;
  if (!toWalk.empty())
  {
    auto found = co_await await_step<std::vector<NodeAccessorResult>>([&](auto completion)
      { namespace_calls::find_nodes(addressSpace, request, toWalk, std::move(completion)); });
    std::vector<std::pair<NodeAccessor, NodeId>> starts;
    for (size_t t = 0; t < toWalk.size(); ++t)
    {
      if (t < found.size() && found[t].is_good())
      {
        starts.emplace_back(found[t].value(), toWalk[t]);
      }
      else
      {
        walkFailed.emplace(toWalk[t],
          t < found.size()
            ? ::ua::detail::lookup_failure(toWalk[t], found[t].status_code(), "AttributeServiceSet")
            : StatusCode{Status::BadInternalError});
      }
    }
    if (!starts.empty())
    {
      auto ends = co_await await_step<std::vector<SupertypeWalkEnd>>(
        [&](auto completion)
        {
          walk_supertypes(
            addressSpace,
            request,
            starts,
            maxTypeWalkDepth,
            [](std::size_t, const NodeId& type) { return data_access_decision(type); },
            std::move(completion));
        });
      for (size_t t = 0; t < starts.size(); ++t)
      {
        const NodeId& type = starts[t].second;
        if (t >= ends.size())
        {
          walkFailed.emplace(type, StatusCode{Status::BadInternalError});
        }
        else if (ends[t].how == SupertypeWalkEnd::How::Decided)
        {
          decided.emplace(type, ends[t].value);
        }
        else if (ends[t].how == SupertypeWalkEnd::How::NoSuper)
        {
          decided.emplace(type, 0);
        }
        else
        {
          walkFailed.emplace(type, ends[t].failure);
        }
      }
    }
  }

  // 3. the bounding Properties of the Data Access Variables: their HasProperty References, their lookup, and
  // the read of those whose BrowseName the rule names.
  std::vector<size_t> ruled;
  std::vector<DataAccessKind> kindOf;
  std::vector<namespace_calls::ReferenceRead> propertyReads;
  for (size_t w = 0; w < written.size(); ++w)
  {
    auto& operation = wave[written[w]];
    if (operation.answer || !typeOf[w])
    {
      continue;
    }
    if (const auto failed = walkFailed.find(*typeOf[w]); failed != walkFailed.end())
    {
      operation.answer = failed->second;
      continue;
    }
    const auto rule = decided.find(*typeOf[w]);
    if (rule == decided.end() || rule->second == 0)
    {
      continue;
    }
    ruled.push_back(written[w]);
    kindOf.push_back(static_cast<DataAccessKind>(rule->second - 1));
    propertyReads.push_back(namespace_calls::ReferenceRead{*operation.node,
      operation.nodeToWrite.node_id(),
      BrowseDirection::Forward,
      NodeId{ReferenceTypeId::HasProperty}});
  }
  if (ruled.empty())
  {
    co_return;
  }
  auto propertyReferences = co_await await_step<std::vector<Result<std::vector<Reference>>>>(
    [&](auto completion)
    {
      namespace_calls::read_references(
        addressSpace, request, std::move(propertyReads), maxNodesPerBrowse, std::move(completion));
    });
  std::vector<NodeId> candidates;
  std::vector<size_t> candidateOf;
  for (size_t r = 0; r < ruled.size(); ++r)
  {
    auto& operation = wave[ruled[r]];
    if (r >= propertyReferences.size() || !propertyReferences[r].is_good())
    {
      operation.answer = r < propertyReferences.size() ? unanswered(server::detail::referencesAnswerUncertain,
                                                           propertyReferences[r].status_code(),
                                                           operation.nodeToWrite.node_id())
                                                       : StatusCode{Status::BadInternalError};
      continue;
    }
    for (const auto& reference : propertyReferences[r].value())
    {
      if (!reference.is_remote() && reference.target_id().is_local())
      {
        candidates.push_back(reference.target_id().node_id());
        candidateOf.push_back(r);
      }
    }
  }
  std::vector<NodeAccessorResult> candidateNodes;
  if (!candidates.empty())
  {
    candidateNodes = co_await await_step<std::vector<NodeAccessorResult>>([&](auto completion)
      { namespace_calls::find_nodes(addressSpace, request, candidates, std::move(completion)); });
  }
  // Each ruled Variable's bounding Properties, by the position of their name in its rule.
  std::vector<std::vector<std::optional<Variant>>> bounds(ruled.size());
  std::vector<std::vector<QualifiedName>> names(ruled.size());
  for (size_t r = 0; r < ruled.size(); ++r)
  {
    names[r] = bounding_properties(kindOf[r]);
    bounds[r].resize(names[r].size());
  }

  struct PropertyRead
  {
    std::vector<NodeAccessor> nodes;
    std::vector<ReadValueId> ids;
  };

  auto reads = std::make_shared<PropertyRead>();
  std::vector<std::pair<size_t, size_t>> readFor;
  std::vector<uint16_t> indexAt;
  for (size_t c = 0; c < candidates.size() && c < candidateNodes.size(); ++c)
  {
    const size_t r = candidateOf[c];
    if (wave[ruled[r]].answer || !candidateNodes[c].is_good())
    {
      // A Property that is gone, or not found, does not bound the write.
      continue;
    }
    const auto browseName = candidateNodes[c].value().get_browse_name();
    const auto named = std::find(names[r].begin(), names[r].end(), browseName);
    if (named == names[r].end())
    {
      continue;
    }
    ReadValueId id;
    id.node_id() = candidates[c];
    id.attribute_id() = utils::to_underlying(AttributeId::Value);
    indexAt.push_back(id.node_id().namespace_index());
    reads->nodes.push_back(candidateNodes[c].value());
    reads->ids.push_back(std::move(id));
    readFor.emplace_back(r, static_cast<size_t>(std::distance(names[r].begin(), named)));
  }
  if (!readFor.empty())
  {
    auto values = co_await await_step<std::vector<DataValueResult>>(
      [&](auto completion)
      {
        namespace_calls::by_namespace<DataValueResult>(
          addressSpace,
          indexAt,
          maxNodesPerRead,
          [reads, request](Namespace& nameSpace,
            std::span<const size_t>
              positions,
            std::function<void(BatchResult<DataValueResult>)>
              answer)
          {
            std::vector<ValueReadItem> items;
            items.reserve(positions.size());
            for (const size_t position : positions)
            {
              items.push_back(ValueReadItem{*reads->nodes[position], reads->ids[position]});
            }
            // Read without a caller: the bounds are facts of the model, not of the writing Session.
            nameSpace.read_values_async(request, nullptr, items, 0.0, false, std::move(answer));
          },
          std::move(completion));
      });
    for (size_t v = 0; v < readFor.size(); ++v)
    {
      const auto [r, position] = readFor[v];
      auto& operation = wave[ruled[r]];
      if (operation.answer)
      {
        continue;
      }
      if (v >= values.size() || !values[v].is_good())
      {
        operation.answer = v < values.size() ? unanswered(server::detail::readAnswerUncertain,
                                                 values[v].status_code(),
                                                 operation.nodeToWrite.node_id())
                                             : StatusCode{Status::BadInternalError};
        continue;
      }
      const auto& value = values[v].value();
      if (value.status() && !value.status()->is_good())
      {
        // Non-fatal: a bound without a Good Value does not bound the write, as a missing Property does not.
        continue;
      }
      bounds[r][position] = value.value();
    }
  }

  // 4. the checks (NR-35): a refusal is the item's answer; a clamp replaces the value written.
  for (size_t r = 0; r < ruled.size(); ++r)
  {
    auto& operation = wave[ruled[r]];
    if (operation.answer)
    {
      continue;
    }
    try
    {
      Variant& value = operation.nodeToWrite.value().value();
      auto checked = check_data_access_value(kindOf[r], value, bounds[r], policy);
      if (checked.is_bad())
      {
        operation.answer = checked.status_code();
      }
      else if (checked.status_code().as_status() == Status::GoodClamped)
      {
        operation.clamped = true;
      }
    }
    catch (...)
    {
      operation.answer = ua::exception_to_status_code(std::current_exception());
    }
  }
}

ua::async::Task<> AttributeServiceSet::write_wave(
  std::vector<WriteOperation>& wave, WriteFactsCache& facts, shared_ptr<::ua::detail::ModelChangeStep> step)
{
  using Kind = WriteOperation::Kind;
  auto addressSpace = *mWriteAddressSpace;
  const RequestInfo request = mRequestInfo;
  const auto caller = caller_for(mWriteAccessControl);

  std::optional<uint32_t> maxNodesPerWrite;
  std::optional<uint32_t> maxNodesPerRead;
  std::optional<uint32_t> maxNodesPerBrowse;
  bool auditInterest = false;
  bool auditingEnabled = false;
  std::optional<DataAccessOutOfRangePolicy> dataAccessWritePolicy;
  {
    // Scoped deliberately: a lock on the session must not span a suspension.
    if (auto sessionInfo = mSessionInfo.lock())
    {
      const auto& limits = sessionInfo->server_configuration().server_capabilities().operationLimits;
      maxNodesPerWrite = limits.maxNodesPerWrite;
      maxNodesPerRead = limits.maxNodesPerRead;
      maxNodesPerBrowse = limits.maxNodesPerBrowse;
      auditingEnabled = sessionInfo->server_configuration().auditingEnabled;
      dataAccessWritePolicy = sessionInfo->server_configuration().dataAccessWritePolicy;
      if (auditingEnabled)
      {
        const auto sink = sessionInfo->event_sink();
        auditInterest = sink && static_cast<EventBus*>(sink.get())->has_event_interest();
      }
    }
  }

  const auto isOpen = [](const WriteOperation& operation)
  {
    return !operation.answer.has_value();
  };
  const auto writesAValue = [](const WriteOperation& operation)
  {
    return !operation.nodeToWrite.value().value().empty();
  };

  // An item that has its answer is recorded, with its audit event, before the wave next waits, so a response
  // sent at the timeoutHint carries it (DL-62 (2)); an audited Variable Value item first waits for the old
  // Value step 5c reads for its event.
  bool oldValuesRead = false;
  const auto settle = [this, &wave, &oldValuesRead]
  {
    for (auto& operation : wave)
    {
      if (operation.recorded || !operation.answer)
      {
        continue;
      }
      if (!oldValuesRead && operation.kind == Kind::VariableValue && operation.auditActive &&
          operation.variable)
      {
        continue;
      }
      operation.recorded = true;
      record_write_outcome(operation, *operation.answer);
    }
  };

  // --- 4. the checks the Node's description decides, in today's order -------------------------------
  for (auto& operation : wave)
  {
    if (!isOpen(operation))
    {
      continue;
    }
    try
    {
      early_write_checks(operation, auditInterest);
    }
    catch (...)
    {
      operation.auditActive = false;
      operation.answer = ua::exception_to_status_code(std::current_exception());
    }
  }

  // --- 5. the reads the remaining checks need, started together -------------------------------------
  //
  // 5a the declared DataTypes' facts; 5b the AllowNulls Properties of the Variables written null; 5c the
  // old Values the audit events report (read for every audited Variable Value item, refused ones too, as the
  // read precedes the checks); 5d one RolePermissions validation per namespace.
  std::vector<NodeId> declaredToResolve;
  std::vector<NodeAccessor> nullVariables;
  std::vector<NodeId> nullVariableIds;
  std::vector<size_t> nullVariableOf(wave.size(), 0);

  struct AuditReads
  {
    std::vector<NodeAccessor> nodes;
    std::vector<ReadValueId> ids;
  };

  auto auditReads = std::make_shared<AuditReads>();
  std::vector<size_t> auditOf;
  std::vector<uint16_t> auditIndexAt;
  auto updates = std::make_shared<std::vector<RolePermissionsUpdate>>();
  std::vector<size_t> updateOf;
  std::vector<uint16_t> updateIndexAt;
  for (size_t k = 0; k < wave.size(); ++k)
  {
    auto& operation = wave[k];
    if (operation.kind == Kind::VariableValue && operation.auditActive && operation.variable)
    {
      ReadValueId readId;
      readId.node_id() = operation.nodeToWrite.node_id();
      readId.attribute_id() = utils::to_underlying(AttributeId::Value);
      readId.index_range() = operation.nodeToWrite.index_range();
      auditIndexAt.push_back(readId.node_id().namespace_index());
      auditReads->nodes.push_back(*operation.node);
      auditReads->ids.push_back(std::move(readId));
      auditOf.push_back(k);
    }
    if (!isOpen(operation))
    {
      continue;
    }
    if (operation.kind == Kind::RolePermissions)
    {
      updateIndexAt.push_back(operation.nodeToWrite.node_id().namespace_index());
      updates->push_back(
        RolePermissionsUpdate{operation.nodeToWrite.node_id(), operation.proposedRolePermissions});
      updateOf.push_back(k);
      continue;
    }
    if (operation.kind != Kind::VariableValue && operation.kind != Kind::VariableTypeValue)
    {
      continue;
    }
    if (!writesAValue(operation))
    {
      if (operation.kind == Kind::VariableValue)
      {
        const auto& variableId = operation.nodeToWrite.node_id();
        const auto known = std::find(nullVariableIds.begin(), nullVariableIds.end(), variableId);
        nullVariableOf[k] = static_cast<size_t>(std::distance(nullVariableIds.begin(), known));
        if (known == nullVariableIds.end())
        {
          nullVariableIds.push_back(variableId);
          nullVariables.push_back(*operation.node);
        }
      }
      continue;
    }
    const NodeId& declared = operation.declaredDataType;
    if (!WriteTypeFacts::needs_no_lookup(declared) && !facts.declared.contains(declared) &&
        std::find(declaredToResolve.begin(), declaredToResolve.end(), declared) == declaredToResolve.end())
    {
      declaredToResolve.push_back(declared);
    }
  }

  struct WaveReads
  {
    std::map<NodeId, DataTypeFacts> declared;
    std::vector<AllowNullsOutcome> allowNulls;
    std::vector<DataValueResult> audit;
    std::vector<VoidResult> validations;
  };

  settle();
  auto reads = co_await await_step<shared_ptr<WaveReads>>(
    [&](auto completion)
    {
      auto joined = std::make_shared<WaveReads>();
      auto remaining = std::make_shared<std::atomic<int>>(5);
      auto one = [joined, remaining, completion]() mutable
      {
        if (remaining->fetch_sub(1, std::memory_order_acq_rel) == 1)
        {
          completion(joined);
        }
      };
      WriteTypeFacts::resolve_declared_async(addressSpace,
        request,
        std::move(declaredToResolve),
        [joined, one](std::map<NodeId, DataTypeFacts> resolved) mutable
        {
          joined->declared = std::move(resolved);
          one();
        });
      AllowNullsBatch::resolve_async(addressSpace,
        request,
        std::move(nullVariables),
        maxNodesPerBrowse,
        maxNodesPerRead,
        [joined, one](std::vector<AllowNullsOutcome> outcomes) mutable
        {
          joined->allowNulls = std::move(outcomes);
          one();
        });
      namespace_calls::by_namespace<DataValueResult>(
        addressSpace,
        auditIndexAt,
        maxNodesPerRead,
        [auditReads, request, caller](Namespace& nameSpace,
          std::span<const size_t>
            positions,
          std::function<void(BatchResult<DataValueResult>)>
            answer)
        {
          std::vector<ValueReadItem> items;
          items.reserve(positions.size());
          for (const size_t position : positions)
          {
            items.push_back(ValueReadItem{*auditReads->nodes[position], auditReads->ids[position]});
          }
          nameSpace.read_values_async(
            request, caller ? &*caller : nullptr, items, 0.0, false, std::move(answer));
        },
        [joined, one](std::vector<DataValueResult> values) mutable
        {
          joined->audit = std::move(values);
          one();
        });
      namespace_calls::by_namespace<VoidResult>(
        addressSpace,
        updateIndexAt,
        maxNodesPerWrite,
        [updates, request](Namespace& nameSpace,
          std::span<const size_t>
            positions,
          std::function<void(BatchResult<VoidResult>)>
            answer)
        {
          std::vector<RolePermissionsUpdate> asked;
          asked.reserve(positions.size());
          for (const size_t position : positions)
          {
            asked.push_back((*updates)[position]);
          }
          nameSpace.validate_role_permissions_updates_async(request, asked, std::move(answer));
        },
        [joined, one](std::vector<VoidResult> verdicts) mutable
        {
          joined->validations = std::move(verdicts);
          one();
        });
      one();
    });
  for (auto& [declared, typeFacts] : reads->declared)
  {
    facts.declared.insert_or_assign(declared, std::move(typeFacts));
  }

  // 5c: a failed or Bad old-value read is non-fatal: the audit event records an empty old value, as a
  // DataValue's value is when its status is an error (Part 4 7.11, Table 135). The read applied the write's
  // IndexRange, as the event's new value is that range.
  for (size_t a = 0; a < auditOf.size() && a < reads->audit.size(); ++a)
  {
    auto& oldRead = reads->audit[a];
    if (oldRead.is_good())
    {
      DataValue oldValue = std::move(oldRead).value();
      if (!oldValue.status() || !oldValue.status()->is_bad())
      {
        wave[auditOf[a]].oldValue = std::move(oldValue.value());
      }
    }
  }

  // 5d: the owning namespace's verdict on each RolePermissions update.
  for (size_t u = 0; u < updateOf.size(); ++u)
  {
    auto& operation = wave[updateOf[u]];
    VoidResult verdict = u < reads->validations.size() ? reads->validations[u]
                                                       : VoidResult{StatusCode{Status::BadInternalError}};
    if (verdict.is_bad())
    {
      operation.answer = verdict.status_code();
      continue;
    }
    auto sessionInfo = mSessionInfo.lock();
    if (!sessionInfo)
    {
      mWriteCollector.add_item_detail(operation.opIndex,
        ErrorDetail::build("RolePermissionsWriteSessionClosed",
          "The Session closed while the namespace validated the RolePermissions update",
          "AttributeServiceSet")
          .context(ua::ContextKeys::nodeId, to_string(operation.nodeToWrite.node_id())));
      operation.answer = StatusCode{Status::BadSessionClosed};
      continue;
    }
    // Snapshot the Attribute before it is written so the audit event describes both sides. Refusals
    // before this point deliberately emit no audit event.
    bool interested = false;
    Variant oldPermissions;
    if (sessionInfo->server_configuration().auditingEnabled)
    {
      const auto sink = sessionInfo->event_sink();
      interested = sink && static_cast<EventBus*>(sink.get())->has_event_interest();
      if (interested)
      {
        try
        {
          const auto current = operation.node->get_role_permissions();
          oldPermissions = encode_role_permissions(current.value_or(std::vector<RolePermissionType>{}));
        }
        catch (...)
        {
          operation.answer = ua::exception_to_status_code(std::current_exception());
          continue;
        }
      }
    }
    operation.auditActive = interested;
    operation.oldValue = std::move(oldPermissions);
  }
  oldValuesRead = true;

  // --- 5'. the checks that need what was read, in today's order ---------------------------------------
  for (size_t k = 0; k < wave.size(); ++k)
  {
    auto& operation = wave[k];
    if (!isOpen(operation) ||
        (operation.kind != Kind::VariableValue && operation.kind != Kind::VariableTypeValue))
    {
      continue;
    }
    try
    {
      if (!writesAValue(operation))
      {
        if (operation.kind != Kind::VariableValue)
        {
          continue;
        }
        const size_t v = nullVariableOf[k];
        const AllowNullsOutcome allowNulls =
          v < reads->allowNulls.size()
            ? reads->allowNulls[v]
            : AllowNullsOutcome{StatusCode{Status::BadInternalError}, std::nullopt};
        if (allowNulls.status.is_bad())
        {
          operation.answer = allowNulls.status;
        }
        else if (allowNulls.allowed.has_value() && !*allowNulls.allowed)
        {
          operation.answer = StatusCode{Status::BadTypeMismatch,
            ErrorDetail::build("NullValueNotAllowed",
              "Variable with AllowNulls FALSE rejects a null Value write",
              "AttributeServiceSet")
              .context(ua::ContextKeys::nodeId, to_string(operation.nodeToWrite.node_id()))};
        }
        continue;
      }
      const auto known = facts.declared.find(operation.declaredDataType);
      typed_value_checks(operation, known == facts.declared.end() ? nullptr : &known->second);
    }
    catch (...)
    {
      operation.answer = ua::exception_to_status_code(std::current_exception());
    }
  }

  // The written structures' types, for the items whose declared DataType is structured: first the
  // DataTypes the encodings of undecoded ones name, then whether each written type is a subtype.
  std::vector<NodeId> encodings;
  for (const auto& operation : wave)
  {
    if (!isOpen(operation) || !operation.structureType)
    {
      continue;
    }
    for (const Structure* structure : written_structures(operation.nodeToWrite.value().value()))
    {
      if (const auto* unknown = dynamic_cast<const UnknownStructure*>(structure))
      {
        if (!facts.encodings.contains(unknown->encoding_id()) &&
            std::find(encodings.begin(), encodings.end(), unknown->encoding_id()) == encodings.end())
        {
          encodings.push_back(unknown->encoding_id());
        }
      }
    }
  }
  if (!encodings.empty())
  {
    settle();
    auto resolved = co_await await_step<std::vector<WriteTypeFacts::EncodingFacts>>(
      [&addressSpace, &request, &encodings](auto completion)
      { WriteTypeFacts::resolve_encodings_async(addressSpace, request, encodings, std::move(completion)); });
    for (size_t e = 0; e < encodings.size(); ++e)
    {
      facts.encodings.insert_or_assign(
        encodings[e], e < resolved.size() ? resolved[e] : WriteTypeFacts::EncodingFacts{});
    }
  }
  std::vector<std::pair<NodeId, NodeId>> questions;
  for (const auto& operation : wave)
  {
    if (!isOpen(operation) || !operation.structureType)
    {
      continue;
    }
    for (const Structure* structure : written_structures(operation.nodeToWrite.value().value()))
    {
      if (structure == nullptr)
      {
        continue;
      }
      std::optional<NodeId> writtenType;
      if (const auto* unknown = dynamic_cast<const UnknownStructure*>(structure))
      {
        const auto known = facts.encodings.find(unknown->encoding_id());
        if (known != facts.encodings.end())
        {
          writtenType = known->second.dataType;
        }
      }
      else if (auto decoded = decoded_structure_type(*structure, addressSpace);
               std::holds_alternative<NodeId>(decoded))
      {
        writtenType = std::get<NodeId>(decoded);
      }
      if (!writtenType || *writtenType == *operation.structureType)
      {
        continue;
      }
      auto question = std::make_pair(*writtenType, *operation.structureType);
      if (!facts.subtypes.contains(question) &&
          std::find(questions.begin(), questions.end(), question) == questions.end())
      {
        questions.push_back(std::move(question));
      }
    }
  }
  if (!questions.empty())
  {
    settle();
    auto answered =
      co_await await_step<std::vector<bool>>([&addressSpace, &request, &questions](auto completion)
        { WriteTypeFacts::resolve_subtypes_async(addressSpace, request, questions, std::move(completion)); });
    for (size_t q = 0; q < questions.size(); ++q)
    {
      facts.subtypes.insert_or_assign(questions[q], q < answered.size() && answered[q]);
    }
  }
  for (auto& operation : wave)
  {
    if (!isOpen(operation) ||
        (operation.kind != Kind::VariableValue && operation.kind != Kind::VariableTypeValue) ||
        !writesAValue(operation))
    {
      continue;
    }
    try
    {
      structure_and_rank_checks(operation, facts);
    }
    catch (...)
    {
      operation.answer = ua::exception_to_status_code(std::current_exception());
    }
  }

  // --- 6. NR-24 step 5e, the information-model pairs, and 5f, the Data Access rules --------------------
  settle();
  co_await information_model_pairs(wave);
  if (dataAccessWritePolicy)
  {
    settle();
    co_await data_access_rules(wave, *dataAccessWritePolicy, maxNodesPerBrowse, maxNodesPerRead);
  }

  // --- 6'. the checks on the value steps 5e and 5f leave (DL-62 (4)) ----------------------------------
  for (auto& operation : wave)
  {
    if (!isOpen(operation) || operation.kind != Kind::VariableValue)
    {
      continue;
    }
    try
    {
      late_write_checks(operation, facts);
    }
    catch (...)
    {
      operation.answer = ua::exception_to_status_code(std::current_exception());
    }
  }

  // --- 7. ONE write_async per namespace with every item still open --------------------------------------
  //
  // Each namespace's items are one task that records them, with their audit events, when that namespace
  // answers, whatever the others do, so a response sent at the timeoutHint carries every write made.
  settle();
  std::vector<std::vector<WriteOperation>> groups;
  {
    std::map<uint16_t, size_t> groupOf;
    for (auto& operation : wave)
    {
      if (!isOpen(operation))
      {
        continue;
      }
      const auto [entry, added] =
        groupOf.try_emplace(operation.nodeToWrite.node_id().namespace_index(), groups.size());
      if (added)
      {
        groups.emplace_back();
      }
      groups[entry->second].push_back(std::move(operation));
      // Its group records it from here on.
      operation.recorded = true;
    }
  }
  std::vector<ua::async::Task<>> tasks;
  tasks.reserve(groups.size());
  for (auto& group : groups)
  {
    std::vector<size_t> opIndices;
    opIndices.reserve(group.size());
    for (const auto& operation : group)
    {
      opIndices.push_back(operation.opIndex);
    }
    try
    {
      tasks.push_back(write_group(std::move(group), request, caller, maxNodesPerWrite, step));
    }
    catch (...)
    {
      // Only the task's frame can fail to be allocated here, and the group went with it: nothing was written.
      const auto status = ua::exception_to_status_code(std::current_exception());
      for (const auto opIndex : opIndices)
      {
        record_write_result(opIndex, status);
      }
    }
  }
  for (auto& task : tasks)
  {
    // Abandoned propagates: the whole request has been withdrawn.
    co_await std::move(task);
  }

  // --- 8. the items answered since the last wait ------------------------------------------------------
  settle();
}

ua::async::Task<> AttributeServiceSet::write_group(std::vector<WriteOperation> group, RequestInfo request,
  std::optional<CallerInfo> caller, std::optional<uint32_t> maxNodesPerWrite,
  shared_ptr<::ua::detail::ModelChangeStep> step)
{
  struct Writes
  {
    std::vector<NodeAccessor> nodes;
    std::vector<WriteValue> values;
  };

  auto addressSpace = *mWriteAddressSpace;
  auto writes = std::make_shared<Writes>();
  std::vector<uint16_t> indexAt;
  indexAt.reserve(group.size());
  for (const auto& operation : group)
  {
    indexAt.push_back(operation.nodeToWrite.node_id().namespace_index());
    writes->nodes.push_back(*operation.node);
    writes->values.push_back(operation.nodeToWrite);
  }

  // Awaited, never blocking: a namespace may answer the write by posting to the strand this Write runs on.
  auto written = co_await await_step<std::vector<VoidResult>>(
    [&addressSpace, &indexAt, maxNodesPerWrite, writes, &request, &caller, &step](auto completion)
    {
      namespace_calls::by_namespace<VoidResult>(
        addressSpace,
        indexAt,
        maxNodesPerWrite,
        [writes, request, caller, step](Namespace& nameSpace,
          std::span<const size_t>
            positions,
          std::function<void(BatchResult<VoidResult>)>
            answer)
        {
          std::vector<ValueWriteItem> items;
          items.reserve(positions.size());
          for (const size_t position : positions)
          {
            items.push_back(ValueWriteItem{*writes->nodes[position], writes->values[position]});
          }
          nameSpace.write_async(request,
            caller ? &*caller : nullptr,
            items,
            ::ua::detail::NodeAccessorRoute::recording_writes(std::move(answer), *step, items));
        },
        [completion](std::vector<VoidResult> results) mutable { completion(std::move(results)); });
    });
  ::ua::detail::NodeAccessorRoute::model_written(addressSpace.weak(), writes->values, written);
  for (size_t w = 0; w < group.size() && w < written.size(); ++w)
  {
    // NR-36 rule 6: a client's write of a NodeVersion is a model change no verb names (OPC 10000-3 9.32.2).
    const auto& writtenNode = group[w].node;
    if (group[w].kind == WriteOperation::Kind::VariableValue && !written[w].is_bad() && writtenNode &&
        writtenNode.value().get_browse_name() == QualifiedName{0, "NodeVersion"})
    {
      step->record_unspecified();
    }
  }
  for (size_t w = 0; w < group.size(); ++w)
  {
    // The item's status as the node answered it, a Good subcode such as Good_CompletesAsynchronously
    // included; a value the Data Access step clamped and the node stored with plain Good answers Good_Clamped
    // (OPC 10000-4 7.39.2).
    StatusCode status = w < written.size() ? written[w].status_code() : StatusCode{Status::BadInternalError};
    if (group[w].clamped && status.as_status() == Status::Good)
    {
      status = StatusCode{Status::GoodClamped, status.shared_detail()};
    }
    record_write_outcome(group[w], std::move(status));
  }
}

void AttributeServiceSet::record_write_outcome(WriteOperation& operation, StatusCode status)
{
  // A Variable's Value reports the detail of whatever it answers; any other item that of what is not Good.
  if (status.shared_detail() && (operation.kind == WriteOperation::Kind::VariableValue || !status.is_good()))
  {
    mWriteCollector.add_item_detail(operation.opIndex, status.shared_detail());
  }
  record_write_result(operation.opIndex, status);
  if (!operation.auditActive)
  {
    return;
  }
  if (auto sessionInfo = mSessionInfo.lock())
  {
    // Guarded for the reason every strand-side call is: a dependency accessor reached after teardown
    // throws by design, and meeting one must log and stop rather than lose the status.
    ua::async::guarded(mLogger,
      [this, &sessionInfo, &operation, status]
      { emit_write_audit_event(*sessionInfo, operation, status); })();
  }
}

void AttributeServiceSet::emit_write_audit_event(
  SessionInfo& sessionInfo, WriteOperation& flow, StatusCode result)
{
  const auto sink = sessionInfo.event_sink();
  if (!sink)
    return;

  AuditWriteUpdateEventPayload auditEvent;
  auditEvent.sourceNode = flow.nodeToWrite.node_id();
  if (flow.node)
  {
    auditEvent.sourceNode = flow.node->get_node_id();
  }
  auditEvent.sourceName = "Attribute/Write";
  auditEvent.actionTimeStamp = Variant{DateTime::now()};
  auditEvent.status = result.is_good();
  auditEvent.serverId = sessionInfo.configuration().application_description_part().applicationUri;
  auditEvent.attributeId = flow.nodeToWrite.attribute_id();
  auditEvent.oldValue = std::move(flow.oldValue);
  auditEvent.newValue = flow.nodeToWrite.value().value();
  if (!flow.nodeToWrite.index_range().empty())
    auditEvent.indexRange = Variant{flow.nodeToWrite.index_range()};
  auditEvent.message = LocalizedText{"", "Write"};
  auditEvent.severity = 1;
  if (mWriteRequest)
    auditEvent.clientAuditEntryId = mWriteRequest->request_header().audit_entry_id();

  if (const auto* sec = dynamic_cast<const SessionSecurityContext*>(&sessionInfo))
  {
    if (auto user = sec->user_identity())
      auditEvent.clientUserId = user->userId;
  }

  sink->emit(auditEvent);
}

// =============================================================================================
// Common: cancel / timeout / fault
// =============================================================================================

void AttributeServiceSet::abort(StatusCode reason)
{
  // Set NOW, not inside the post: a collaborator that answers on the strand itself (a value source
  // computing synchronously, a namespace resolving on the caller's stack) parks the strand for the
  // whole call, so the post below cannot run before the answer is in hand. With the token already
  // set, the body's next co_await - the answer's own resumption - throws Abandoned and the request
  // never sends its response; the post then answers with the fault, as every other service does.
  if (mCancelled)
    mCancelled->store(true);
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [reason = std::move(reason)](AttributeServiceSet& self)
    {
      DiagnosticCollector collector{0};
      const auto& requestHeader = active_request_header(self.mReadRequest, self.mWriteRequest);
      self.send_service_fault(requestHeader, reason, collector);
      // The Read path stops on the token: its coroutines throw ua::async::Abandoned at their next
      // resumption and unwind. Nothing here needs to reach into their state, and try_finish has
      // already taken the right to answer, so a body that got a turn before then changes nothing.
      self.mReadResponse.reset();
      self.mWriteResponse.reset();
    })();
}

void AttributeServiceSet::timeout()
{
  // Read and Write run to the full timeoutHint (OPC 10000-4 section 7.33: the Server should wait at
  // least that long) and then answer per item rather than failing the whole request: a finished item
  // keeps its result and an unfinished one keeps the Bad_Timeout it was created with, meaning its
  // outcome is unknown (section 7.39.2 allows a Service-level code as an operation result). The token
  // is set first so every operation still running unwinds at its next resumption instead of writing
  // into a response that has been handed away.
  if (mCancelled)
  {
    mCancelled->store(true);
  }

  if (mReadResponse)
  {
    complete_read_request();
    return;
  }
  if (mWriteResponse)
  {
    complete_write_request();
    return;
  }

  // The timer fired before the request built its response: nothing was started, so the request fails.
  DiagnosticCollector collector{0};
  const auto& requestHeader = active_request_header(mReadRequest, mWriteRequest);
  send_service_fault(requestHeader, Status::BadTimeout, collector);
}

void AttributeServiceSet::set_timeout()
{
  const auto& requestHeader = active_request_header(mReadRequest, mWriteRequest);
  ServiceBase::set_timeout(requestHeader.timeout_hint());
}

void AttributeServiceSet::send_service_fault(
  const RequestHeader& requestHeader, StatusCode status, const DiagnosticCollector& collector)
{
  if (!try_finish())
    return;

  auto serviceFault = stack_utils::create_service_fault(&requestHeader, status);
  Array<DiagnosticInfo> unused;
  collector.apply_to(serviceFault->response_header(), unused, 0);
  if (mServiceCallCompleteCallback)
  {
    mServiceCallCompleteCallback(std::make_pair(mRequestId, serviceFault));
  }
}

}  // namespace ua::server
