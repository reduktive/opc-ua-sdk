// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_connection.h"

#include "ua_alarm_condition_tracker_impl.h"
#include "ua_attribute_id.h"
#include "ua_sync_wait.h"
#include "ua_client_observers.h"
#include "ua_connection_impl.h"
#include "ua_event_subscriber_impl.h"
#include "ua_error_detail.h"
#include "ua_file_transfer_client.h"
#include "ua_read_request.h"
#include "ua_read_value_id.h"
#include "ua_server_diagnostics_access_state.h"
#include "ua_status.h"
#include "ua_type_registry.h"
#include "ua_type_resolver.h"
#include "ua_typed_access.h"
#include "ua_to_string.h"

#include <string>
#include <utility>

namespace ua::client
{

namespace
{

/// Source tags for the value-sugar manufactured boundary failures (the design specification).
constexpr std::string_view readValueSource = "client.tier2.connection.read_value";
constexpr std::string_view resolveExpandedSource = "client.tier2.connection.resolve_expanded";

/// Resolves a URI-tagged @ref ua::ExpandedNodeId to a local @ref ua::NodeId against @p snapshot  -  the
/// Connection's CURRENT NamespaceTable  -  per the OPEN-NSREMAP ruling (per-Session resolution at call time,
/// CL-ADDRSP-004). The rich @ref NamespaceTable::resolve_local ErrorDetail (unresolved URI / out-of-range
/// index) is propagated unchanged. A null snapshot (no NamespaceArray read yet) fails with
/// `Bad_InvalidState`.
ua::Result<ua::NodeId> resolve_against_current_table(
  const std::shared_ptr<const NamespaceTable>& snapshot, const ua::ExpandedNodeId& node)
{
  if (!snapshot)
  {
    return ua::Result<ua::NodeId>{ua::Status::BadInvalidState,
      ua::make_error_detail("NamespaceTableUnavailable",
        "the Connection has no NamespaceArray snapshot yet; cannot resolve a URI-tagged NodeId",
        std::string{resolveExpandedSource})};
  }
  if (node.server_index() != 0)
  {
    // A non-zero ServerIndex names a node on a DIFFERENT Server (Part 3 section 8.2). Silently stripping it
    // and reading the LOCAL namespace would be incorrect (Part 4 section 5.10.2). This Connection has no
    // cross-Server registry configured, so CL-ATTR-029's documented default is to refuse rather than hand the
    // caller a wrong-Server value.
    return ua::Result<ua::NodeId>{ua::Status::BadNotImplemented,
      ua::ErrorDetail::build("ServerIndexRoutingUnsupported",
        "the ExpandedNodeId names a node on another Server (non-zero ServerIndex); cross-Server routing is "
        "not implemented",
        std::string{resolveExpandedSource})
        .context(ua::ContextKeys::value, node.server_index())};
  }
  return snapshot->resolve_local(node);
}

/// Builds a single-node Read of the Value attribute (the `read_value` request shape).
ua::ReadRequest make_value_read(ua::NodeId node)
{
  ua::ReadValueId target;
  target.node_id() = std::move(node);
  target.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  ua::ReadRequest request;
  request.nodes_to_read().push_back(std::move(target));
  return request;
}

/// Source tag + builds a single-node Read of BOTH the Value and the DataType attribute (the checked-read
/// shape, CL-ADDRSP-009): results[0] is the Value, results[1] the declared DataType NodeId.
constexpr std::string_view checkedReadSource = "client.tier2.connection.read_value_checked";

ua::ReadRequest make_value_and_datatype_read(ua::NodeId node)
{
  ua::ReadValueId valueTarget;
  valueTarget.node_id() = node;
  valueTarget.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  ua::ReadValueId dataTypeTarget;
  dataTypeTarget.node_id() = std::move(node);
  dataTypeTarget.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::DataType);
  ua::ReadRequest request;
  request.nodes_to_read().push_back(std::move(valueTarget));
  request.nodes_to_read().push_back(std::move(dataTypeTarget));
  return request;
}

/// Source tag + the NoSubDataTypes bit (Part 3 section 8.58, AccessLevelEx bit 11) + builds a single-node
/// Read of the declared DataType and AccessLevelEx attributes (the checked-write pre-flight, CL-ATTR-025):
/// results[0] is the declared DataType NodeId, results[1] the AccessLevelEx UInt32.
constexpr std::string_view checkedWriteSource = "client.tier2.connection.write_value_checked";
constexpr std::uint32_t accessLevelExNoSubDataTypes = 1U << 11;

ua::ReadRequest make_datatype_and_accesslevelex_read(ua::NodeId node)
{
  ua::ReadValueId dataTypeTarget;
  dataTypeTarget.node_id() = node;
  dataTypeTarget.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::DataType);
  ua::ReadValueId accessLevelExTarget;
  accessLevelExTarget.node_id() = std::move(node);
  accessLevelExTarget.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::AccessLevelEx);
  ua::ReadRequest request;
  request.nodes_to_read().push_back(std::move(dataTypeTarget));
  request.nodes_to_read().push_back(std::move(accessLevelExTarget));
  return request;
}

}  // namespace

Connection::Connection(std::shared_ptr<detail::ConnectionImpl> impl) : mImpl(std::move(impl))
{}

// ============ Lifecycle ============

void Connection::close_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState});
    return;
  }
  mImpl->close_async(std::move(callback));
}

void Connection::close_sync()
{
  try_close_sync().value();
}

ua::VoidResult Connection::try_close_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this](auto completion) { close_async(std::move(completion)); });
}

void Connection::reactivate_async(
  UserIdentity newIdentity, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState});
    return;
  }
  mImpl->reactivate_async(std::move(newIdentity), std::move(callback));
}

void Connection::reactivate_sync(UserIdentity newIdentity)
{
  try_reactivate_sync(std::move(newIdentity)).value();
}

ua::VoidResult Connection::try_reactivate_sync(UserIdentity newIdentity) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, identity = std::move(newIdentity)](auto completion) mutable
    { reactivate_async(std::move(identity), std::move(completion)); });
}

// ============ State (atomic snapshot) ============

ConnectionState Connection::state() const
{
  if (!mImpl)
  {
    return ConnectionState::Closed;
  }
  const auto snapshot = mImpl->info();
  return snapshot ? snapshot->state : ConnectionState::Connecting;
}

ua::Result<ua::NodeId> Connection::session_id() const
{
  if (!mImpl)
  {
    return ua::Result<ua::NodeId>{ua::Status::BadSessionIdInvalid};
  }
  const auto snapshot = mImpl->info();
  if (!snapshot || snapshot->sessionId.is_null())
  {
    return ua::Result<ua::NodeId>{ua::Status::BadSessionIdInvalid};
  }
  return ua::Result<ua::NodeId>{snapshot->sessionId};
}

std::shared_ptr<const NamespaceTable> Connection::namespace_table() const
{
  if (!mImpl)
  {
    return nullptr;
  }
  return mImpl->namespace_table_snapshot();
}

std::shared_ptr<const ServerTable> Connection::server_table() const
{
  if (!mImpl)
  {
    return nullptr;
  }
  return mImpl->server_table_snapshot();
}

// ============ Observer registration (section 7.8) ============
// Each forwards to the strand-posting ConnectionImpl setter (which replaces the per-Connection family slot
// and re-resolves the sink snapshot). A moved-from handle silently drops the registration (no
// ConnectionImpl).

void Connection::set_connection_observer(std::shared_ptr<ConnectionObserver> observer) noexcept
{
  if (mImpl)
  {
    mImpl->set_connection_observer_async(std::move(observer));
  }
}

void Connection::set_subscription_observer(std::shared_ptr<SubscriptionObserver> observer) noexcept
{
  if (mImpl)
  {
    mImpl->set_subscription_observer_async(std::move(observer));
  }
}

void Connection::set_security_observer(std::shared_ptr<SecurityObserver> observer) noexcept
{
  if (mImpl)
  {
    mImpl->set_security_observer_async(std::move(observer));
  }
}

void Connection::set_type_observer(std::shared_ptr<TypeObserver> observer) noexcept
{
  if (mImpl)
  {
    mImpl->set_type_observer_async(std::move(observer));
  }
}

void Connection::set_address_space_observer(std::shared_ptr<AddressSpaceObserver> observer) noexcept
{
  if (mImpl)
  {
    mImpl->set_address_space_observer_async(std::move(observer));
  }
}

void Connection::set_server_state_observer(std::shared_ptr<ServerStateObserver> observer) noexcept
{
  if (mImpl)
  {
    mImpl->set_server_state_observer_async(std::move(observer));
  }
}

void Connection::set_alarm_observer(std::shared_ptr<AlarmObserver> observer) noexcept
{
  if (mImpl)
  {
    mImpl->set_alarm_observer_async(std::move(observer));
  }
}

// ============ Sub-accessors ============

ServiceSet Connection::service_requests()
{
  return ServiceSet{mImpl};
}

TypedAccess Connection::typed()
{
  return TypedAccess{mImpl};
}

Subscriptions Connection::subscriptions()
{
  return Subscriptions{mImpl};
}

EventSubscriber Connection::events()
{
  return detail::EventSubscriberHandleFactory::create(mImpl ? mImpl->events_impl() : nullptr);
}

AlarmConditionTracker Connection::alarms()
{
  return detail::AlarmConditionTrackerHandleFactory::create(mImpl ? mImpl->alarms_impl() : nullptr);
}

HistoryFacade Connection::history()
{
  if (!mImpl)
  {
    // Moved-from handle: hand back an inert facade (empty wire interface + no executor). Its methods
    // fast-fail Bad_ConnectionClosed inline rather than dereferencing a null ConnectionImpl.
    return HistoryFacade{std::weak_ptr<detail::WireOps>{}, boost::asio::any_io_executor{}};
  }
  // A lightweight value handle over the same tier-1 wire interface (section 8.9): weak WireOps (locked per
  // op, bail if gone) + the Connection executor for the callback hand-off + the Connection logger so the
  // cursor's best-effort continuation-point release logs at the wire boundary (CL-HIST-009). Mirrors
  // TypedAccess/ServiceSet.
  return HistoryFacade{mImpl->wire_ops(), mImpl->executor(), mImpl->logger()};
}

FileTransferClient Connection::files()
{
  if (!mImpl)
  {
    // Moved-from handle: hand back an inert facade (empty wire interface + no executor). Its methods
    // fast-fail Bad_ConnectionClosed inline rather than dereferencing a null ConnectionImpl.
    return FileTransferClient{std::weak_ptr<detail::WireOps>{}, boost::asio::any_io_executor{}};
  }
  // A copyable value handle over the same tier-1 wire interface (section 8.10): weak WireOps (locked per op,
  // bail if gone) + the Connection executor for the callback hand-off + the Connection logger so the
  // FileHandle's best-effort dtor Close logs at the wire boundary (CL-FILE-001). Mirrors history()/typed().
  return FileTransferClient{
    mImpl->wire_ops(), mImpl->executor(), mImpl->logger(), mImpl->session_generation_token()};
}

DataAccessAccessor Connection::data_access() noexcept
{
  if (!mImpl)
  {
    // Moved-from handle: hand back an inert accessor (empty interface roles + no executor). Its factories
    // fast-fail Bad_ConnectionClosed rather than dereferencing a null ConnectionImpl.
    return DataAccessAccessor{std::weak_ptr<detail::WireOps>{},
      std::weak_ptr<detail::SupportOps>{},
      boost::asio::any_io_executor{},
      ua::Logger{}};
  }
  // A copyable value handle over the same tier-1 wire + support interfaces (section 8.18): weak WireOps +
  // weak SupportOps (locked per op, bail if gone) + the Connection executor for the callback hand-off + the
  // Connection logger for advisory wire-boundary outcomes. Mirrors files()/history().
  return DataAccessAccessor{mImpl->wire_ops(), mImpl->support_ops(), mImpl->executor(), mImpl->logger()};
}

PropertyAccessor Connection::node(ua::NodeId nodeId) noexcept
{
  if (!mImpl)
  {
    // Moved-from handle: hand back an inert accessor. Its reads fast-fail Bad_ConnectionClosed.
    return PropertyAccessor{std::move(nodeId),
      std::weak_ptr<detail::WireOps>{},
      std::weak_ptr<detail::SupportOps>{},
      boost::asio::any_io_executor{},
      ua::Logger{}};
  }
  return PropertyAccessor{
    std::move(nodeId), mImpl->wire_ops(), mImpl->support_ops(), mImpl->executor(), mImpl->logger()};
}

StateMachineAccessor Connection::state_machine_accessor() noexcept
{
  if (!mImpl)
  {
    // Moved-from handle: hand back an inert accessor (empty interface roles + no executor). Its factories
    // fast-fail Bad_ConnectionClosed rather than dereferencing a null ConnectionImpl.
    return StateMachineAccessor{std::weak_ptr<detail::WireOps>{},
      std::weak_ptr<detail::SupportOps>{},
      boost::asio::any_io_executor{},
      ua::Logger{}};
  }
  // A copyable value handle over the same tier-1 wire + support interfaces (section 8.18): weak WireOps +
  // weak SupportOps (locked per op, bail if gone) + the Connection executor for the callback hand-off + the
  // Connection logger for advisory wire-boundary outcomes. Mirrors data_access()/node().
  return StateMachineAccessor{mImpl->wire_ops(), mImpl->support_ops(), mImpl->executor(), mImpl->logger()};
}

ServerDiagnosticsAccessor Connection::server_diagnostics() noexcept
{
  // Each accessor carries its own shared EnabledFlag TTL cache (section 8.18.2). Copies of the returned
  // handle share the cache; a fresh handle from a later server_diagnostics() call starts a fresh cache
  // (always re-reads the flag), which is correct  -  the TTL is only a benefit when the same handle is
  // reused.
  auto cacheState = std::make_shared<detail::ServerDiagnosticsCacheState>();
  if (!mImpl)
  {
    // Moved-from handle: hand back an inert accessor (empty interface roles + no executor). Its ops fast-fail
    // Bad_ConnectionClosed rather than dereferencing a null ConnectionImpl.
    return ServerDiagnosticsAccessor{std::weak_ptr<detail::WireOps>{},
      std::weak_ptr<detail::SupportOps>{},
      boost::asio::any_io_executor{},
      ua::Logger{},
      std::move(cacheState),
      {}};
  }
  // A copyable value handle over the same tier-1 wire + support interfaces (section 8.18): weak WireOps +
  // weak SupportOps (locked per op, bail if gone) + the Connection executor for the callback hand-off + the
  // Connection logger for the disabled-advisory. Mirrors data_access()/state_machine_accessor().
  return ServerDiagnosticsAccessor{mImpl->wire_ops(),
    mImpl->support_ops(),
    mImpl->executor(),
    mImpl->logger(),
    std::move(cacheState),
    [sink = std::weak_ptr<detail::ObserverSink>{mImpl->observer_sink()}](
      std::shared_ptr<const ua::ErrorDetail> detail)
    {
      if (auto observerSink = sink.lock())
      {
        observerSink->fire_advisory_diagnostic(std::move(detail));
      }
    }};
}

void Connection::create_subscription_async(
  SubscriptionConfig config, std::function<void(ua::Result<Subscription>)> callback) noexcept
{
  // Thin convenience delegating to the subscriptions() sub-accessor (section 7.4).
  subscriptions().create_async(std::move(config), std::move(callback));
}

// ============ Value conveniences ============

void Connection::read_value_async(
  ua::NodeId node, std::function<void(ua::Result<ua::DataValue>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::DataValue>{ua::Status::BadInvalidState});
    return;
  }
  const auto wrapLevel = mImpl->diagnostic_policy().wrapLevel;
  const auto namespaceTable = mImpl->namespace_table_snapshot();
  ua::NodeId targetNode = node;
  mImpl->read_async(make_value_read(std::move(node)),
    [callback = std::move(callback),
      wrapLevel,
      namespaceTable = std::move(namespaceTable),
      targetNode = std::move(targetNode)](ua::Result<ua::ReadResponse> result) mutable
    {
      if (!result.has_value())
      {
        const ua::StatusCode cause = result.status_code();
        if (wrapLevel == ua::client::ClientDiagnosticPolicy::WrapLevel::Minimal)
        {
          callback(ua::Result<ua::DataValue>{cause});
          return;
        }
        auto detail = ua::ErrorDetail::build(
          "ReadValueFailure", "The typed read-value operation failed", std::string{readValueSource});
        detail.context(ua::ContextKeys::nodeId, targetNode).cause(cause);
        if (wrapLevel == ua::client::ClientDiagnosticPolicy::WrapLevel::Verbose && namespaceTable)
        {
          if (const auto uri = namespaceTable->lookup_uri(
                static_cast<ua::client::NamespaceIndex>(targetNode.namespace_index())))
          {
            detail.context(ua::ContextKeys::namespaceUri, std::string{*uri});
          }
        }
        std::shared_ptr<const ua::ErrorDetail> outer = std::move(detail);
        callback(ua::Result<ua::DataValue>{ua::StatusCode{cause.as_uint32(), std::move(outer)}});
        return;
      }
      // Facade flatten (CL-ATTR-004): the tier-0 wire-op funnel returns a normal response verbatim -
      // it does NOT flatten the ResponseHeader.serviceResult. A bad serviceResult is a service-level
      // failure, so the value facade surfaces it as a bad Result (mirrors the Discovery facade).
      const ua::StatusCode serviceResult = result.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        callback(ua::Result<ua::DataValue>{serviceResult,
          ua::make_error_detail("ReadValueServiceFault",
            "the Read service returned a service-level error",
            std::string{readValueSource},
            serviceResult)});
        return;
      }
      auto& results = result.value().results();
      if (results.size() != 1)
      {
        // Slot alignment (CL-ATTR-004): a single-node Read MUST return exactly one DataValue. Any
        // other count means the response cannot be positionally mapped, so reject it rather than hand
        // back an empty-indexed or mis-aligned value.
        callback(ua::Result<ua::DataValue>{ua::Status::BadUnexpectedError,
          ua::make_error_detail("ReadValueResultCountMismatch",
            "the server returned a Read response whose result count is not exactly one for the single "
            "requested node",
            std::string{readValueSource})});
        return;
      }
      // Two layers: the ServiceResult (a Good subcode or an Uncertain code included) is the status of the
      // outer Result, the DataValue keeps its own.
      callback(ua::detail::held(std::move(results[0]), serviceResult));
    });
}

ua::DataValue Connection::read_value_sync(ua::NodeId node)
{
  return ua::detail::good_data_value(try_read_value_sync(std::move(node)));
}

ua::Result<ua::DataValue> Connection::try_read_value_sync(ua::NodeId node) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::DataValue>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, node = std::move(node)](auto completion) mutable
    { read_value_async(std::move(node), std::move(completion)); });
}

void Connection::read_value_async(
  ua::ExpandedNodeId node, std::function<void(ua::Result<ua::DataValue>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::DataValue>{ua::Status::BadInvalidState});
    return;
  }
  // Per-Session resolution at call time (OPEN-NSREMAP): resolve the URI against the CURRENT snapshot, so a
  // NamespaceArray renumbered across a reconnect maps to the new index. The user's ExpandedNodeId is
  // untouched.
  auto resolved = resolve_against_current_table(mImpl->namespace_table_snapshot(), node);
  if (!resolved.has_value())
  {
    // Local rejection before any wire request: propagate the rich resolve ErrorDetail unchanged
    // (single-wrap).
    callback(ua::Result<ua::DataValue>{resolved.status_code(), resolved.shared_detail()});
    return;
  }
  read_value_async(std::move(resolved).value(), std::move(callback));
}

ua::DataValue Connection::read_value_sync(ua::ExpandedNodeId node)
{
  return ua::detail::good_data_value(try_read_value_sync(std::move(node)));
}

ua::Result<ua::DataValue> Connection::try_read_value_sync(ua::ExpandedNodeId node) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::DataValue>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, node = std::move(node)](auto completion) mutable
    { read_value_async(std::move(node), std::move(completion)); });
}

void Connection::write_value_async(
  ua::NodeId node, ua::Variant value, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState});
    return;
  }
  TypedAccess{mImpl}.write_attribute_async(
    std::move(node), ua::AttributeId::Value, ua::DataValue{std::move(value)}, std::move(callback));
}

void Connection::write_value_sync(ua::NodeId node, ua::Variant value)
{
  try_write_value_sync(std::move(node), std::move(value)).value();
}

ua::VoidResult Connection::try_write_value_sync(ua::NodeId node, ua::Variant value) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, node = std::move(node), value = std::move(value)](auto completion) mutable
    { write_value_async(std::move(node), std::move(value), std::move(completion)); });
}

void Connection::write_value_async(
  ua::ExpandedNodeId node, ua::Variant value, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState});
    return;
  }
  auto resolved = resolve_against_current_table(mImpl->namespace_table_snapshot(), node);
  if (!resolved.has_value())
  {
    // Local rejection before any wire request: propagate the rich resolve ErrorDetail unchanged
    // (single-wrap).
    callback(ua::VoidResult{resolved.status_code(), resolved.shared_detail()});
    return;
  }
  write_value_async(std::move(resolved).value(), std::move(value), std::move(callback));
}

void Connection::write_value_sync(ua::ExpandedNodeId node, ua::Variant value)
{
  try_write_value_sync(std::move(node), std::move(value)).value();
}

ua::VoidResult Connection::try_write_value_sync(ua::ExpandedNodeId node, ua::Variant value) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, node = std::move(node), value = std::move(value)](auto completion) mutable
    { write_value_async(std::move(node), std::move(value), std::move(completion)); });
}

void Connection::read_value_checked_async(
  ua::NodeId node, std::function<void(ua::Result<ua::DataValue>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::DataValue>{ua::Status::BadInvalidState});
    return;
  }
  // Snapshot the DataType subtype graph at call time (free-threaded atomic load). The NS0 built-in hierarchy
  // is seeded at resolver construction, so the check is decidable synchronously for built-in types; vendor /
  // not-yet-discovered relations fall through to fail-open.
  const auto resolver = mImpl->type_resolver();
  std::shared_ptr<const detail::TypeRegistry> registry = resolver ? resolver->registry() : nullptr;

  mImpl->read_async(make_value_and_datatype_read(std::move(node)),
    [callback = std::move(callback), registry = std::move(registry)](
      ua::Result<ua::ReadResponse> result) mutable
    {
      if (!result.has_value())
      {
        callback(ua::Result<ua::DataValue>{result.status_code(), result.shared_detail()});
        return;
      }
      const ua::StatusCode serviceResult = result.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        callback(ua::Result<ua::DataValue>{serviceResult,
          ua::make_error_detail("ReadValueCheckedServiceFault",
            "the checked Read service returned a service-level error",
            std::string{checkedReadSource},
            serviceResult)});
        return;
      }
      auto& results = result.value().results();
      if (results.size() != 2)
      {
        // Slot alignment: a checked read requests exactly two attributes (Value, DataType), so it must return
        // exactly two results; any other count cannot be positionally mapped.
        callback(ua::Result<ua::DataValue>{ua::Status::BadUnexpectedError,
          ua::make_error_detail("ReadValueCheckedResultCountMismatch",
            "the server returned a checked-Read response whose result count is not exactly two",
            std::string{checkedReadSource})});
        return;
      }
      ua::DataValue value = std::move(results[0]);

      // Validate the Value's concrete type against the declared DataType (results[1]). The check is
      // best-effort: a missing registry, a bad-quality/absent DataType read, a non-NodeId DataType value, or
      // an Undecidable verdict all FAIL OPEN (deliver the value)  -  only a proven disjoint mismatch rejects
      // (section 5.8.3).
      //
      // A BAD-QUALITY Value is delivered VERBATIM without type validation (the two-layer model, as for the
      // plain read_value): the server's own StatusCode + ErrorDetail ride on the DataValue and MUST NOT be
      // swallowed by a synthesised Bad_TypeMismatch (the design specification), and a stale/absent bad value
      // is not a real value to type-check.
      const bool valueGood = !value.status().has_value() || value.status()->is_good();
      const ua::DataValue& dataTypeResult = results[1];
      const bool dataTypeGood = !dataTypeResult.status().has_value() || dataTypeResult.status()->is_good();
      if (registry && valueGood && dataTypeGood)
      {
        const ua::Result<ua::NodeId> declaredDataType = dataTypeResult.value().to<ua::NodeId>();
        if (declaredDataType.is_good())
        {
          const detail::SubtypeCheck verdict =
            detail::check_value_subtype(value.value(), declaredDataType.value(), *registry);
          if (verdict == detail::SubtypeCheck::Reject)
          {
            callback(ua::Result<ua::DataValue>{ua::Status::BadTypeMismatch,
              ua::make_error_detail("ReadValueNotSubtypeOfDeclaredDataType",
                "the value's concrete DataType is not a subtype of the Variable's declared DataType",
                std::string{checkedReadSource})});
            return;
          }
        }
      }
      callback(ua::detail::held(std::move(value), serviceResult));
    });
}

void Connection::write_value_checked_async(
  ua::NodeId node, ua::Variant value, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::VoidResult{ua::Status::BadInvalidState});
    return;
  }
  const auto resolver = mImpl->type_resolver();
  std::shared_ptr<const detail::TypeRegistry> registry = resolver ? resolver->registry() : nullptr;

  // Pre-flight the target's declared DataType + AccessLevelEx, then decide locally (NoSubDataTypes) or
  // forward. Capture mImpl (not `this`): the completion may outlive this Connection handle; the impl
  // shared_ptr keeps the orchestrator alive so the forwarded write is safe.
  //
  // Build the request into a LOCAL first (the design specification section 5): `node` is used to build the
  // pre-flight request AND move-captured for the forwarded write. Passing `make_...(node)` and `[node =
  // std::move(node)]` as two arguments to one `read_async(...)` call is INDETERMINATELY sequenced (C++17)  -
  // on a right-to-left arg evaluation the capture would move `node` before the request reads it, targeting a
  // null node. Sequencing the request build before the capture makes the single move well-defined.
  std::shared_ptr<detail::ConnectionImpl> impl = mImpl;
  ua::ReadRequest preflight = make_datatype_and_accesslevelex_read(node);
  impl->read_async(std::move(preflight),
    [impl,
      node = std::move(node),
      value = std::move(value),
      callback = std::move(callback),
      registry = std::move(registry)](ua::Result<ua::ReadResponse> result) mutable
    {
      // A failed pre-flight must NOT block a legitimate write: fall through and forward the write (the server
      // remains the authority). Only a decidable NoSubDataTypes strict-subtype violation short-circuits.
      bool refuse = false;
      if (result.is_good() && result.value().response_header().service_result().is_good() &&
          result.value().results().size() == 2)
      {
        const auto& results = result.value().results();
        const ua::DataValue& dataTypeResult = results[0];
        const ua::DataValue& accessLevelExResult = results[1];
        const bool attributesGood =
          (!dataTypeResult.status().has_value() || dataTypeResult.status()->is_good()) &&
          (!accessLevelExResult.status().has_value() || accessLevelExResult.status()->is_good());
        if (registry && attributesGood)
        {
          const ua::Result<std::uint32_t> accessLevelEx = accessLevelExResult.value().to<std::uint32_t>();
          const ua::Result<ua::NodeId> declaredDataType = dataTypeResult.value().to<ua::NodeId>();
          if (accessLevelEx.is_good() && declaredDataType.is_good() &&
              (accessLevelEx.value() & accessLevelExNoSubDataTypes) != 0)
          {
            // NoSubDataTypes: only the EXACT declared DataType is accepted. Refuse a value we can PROVE is a
            // strict subtype (decidably a subtype AND not the exact type). An encoding-aliased value (enum as
            // Int32, Duration as Double) is NOT a decidable subtype of its declared type, so it is forwarded.
            const std::optional<ua::NodeId> valueType = detail::value_concrete_datatype(value);
            if (valueType && *valueType != declaredDataType.value() &&
                registry->is_subtype_of(*valueType, declaredDataType.value()) == std::optional<bool>{true})
            {
              refuse = true;
            }
          }
        }
      }
      if (refuse)
      {
        callback(ua::VoidResult{ua::Status::BadTypeMismatch,
          ua::make_error_detail("WriteSubtypeToNoSubDataTypesTarget",
            "the Variable's AccessLevelEx.NoSubDataTypes is set: it accepts only its exact declared "
            "DataType, "
            "not a subtype of it",
            std::string{checkedWriteSource})});
        return;
      }
      TypedAccess{std::move(impl)}.write_attribute_async(
        std::move(node), ua::AttributeId::Value, ua::DataValue{std::move(value)}, std::move(callback));
    });
}

void Connection::write_value_checked_sync(ua::NodeId node, ua::Variant value)
{
  try_write_value_checked_sync(std::move(node), std::move(value)).value();
}

ua::VoidResult Connection::try_write_value_checked_sync(ua::NodeId node, ua::Variant value) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, node = std::move(node), value = std::move(value)](auto completion) mutable
    { write_value_checked_async(std::move(node), std::move(value), std::move(completion)); });
}

ua::DataValue Connection::read_value_checked_sync(ua::NodeId node)
{
  return ua::detail::good_data_value(try_read_value_checked_sync(std::move(node)));
}

ua::Result<ua::DataValue> Connection::try_read_value_checked_sync(ua::NodeId node) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::DataValue>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, node = std::move(node)](auto completion) mutable
    { read_value_checked_async(std::move(node), std::move(completion)); });
}

// ============================================================================
// Blocking wrappers
//
// One blocking_call per asynchronous operation, the shape every tier-2 facade uses
// (ua_sync_wait.h): the throwing form is `try_*_sync(...).value()`, and the non-throwing
// form arms the existing `*_async`. No operation is reimplemented here.
//
// Each blocks the calling thread until the completion runs; called from the executor thread that
// would run it, each refuses with Bad_WouldBlock before starting anything.
// ============================================================================

Subscription Connection::create_subscription_sync(SubscriptionConfig config)
{
  return ua::detail::good_value(try_create_subscription_sync(std::move(config)));
}

ua::Result<Subscription> Connection::try_create_subscription_sync(SubscriptionConfig config) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<Subscription>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, config = std::move(config)](auto completion) mutable
    { create_subscription_async(std::move(config), std::move(completion)); });
}

}  // namespace ua::client
