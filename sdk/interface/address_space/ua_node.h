// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Address-space node interface and its optional value/method capability interfaces.
/// @ingroup address_space

#ifndef UA_NODE_H
#define UA_NODE_H

#include <cstdint>
#include <functional>
#include <optional>
#include <utility>
#include <vector>
#include "ua_defines.h"
#include "ua_reference.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_attribute_write_mask.h"
#include "ua_role_permission_type.h"
#include "ua_access_restriction_type.h"
#include "ua_node_class.h"
#include "ua_node_description.h"

namespace ua
{
/// The Session on whose behalf a value is being read. A node whose Value differs per caller - a
/// `NamespaceMetadata` user-permission Property, or any namespace applying row-level filtering -
/// produces its answer from this. Null where there is no Session: internal reads, and sampling of a
/// node whose value is the same for everyone. Forward-declared so authorization does not enter every
/// node translation unit.
class AccessIdentity;
}  // namespace ua

#include "ua_event_notifier_type.h"
#include "ua_duration.h"
#include "ua_attribute_id.h"
#include "ua_locale_id.h"
#include "ua_call_method_result.h"
#include "ua_result.h"
#include "ua_data_value.h"
#include "ua_status_code.h"
#include "ua_message_security_mode.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_string.h"
#include "ua_variant.h"

namespace ua
{

class AddressSpace;
class DataTypeDefinition;
class CallMethodRequest;
class CallMethodResult;
class ReadValueId;
class WriteValue;
class AccessLevelType;
class AccessLevelExType;
class KeyValuePair;

namespace detail
{
class MethodCallContextInternalAccess;
class MethodCallAuthorizationInternalAccess;
}  // namespace detail

/// Per-call session context threaded through to method handlers.
///
/// Populated by the Call service from the active session and passed by shared ownership to the
/// namespace's call_async (CallItem::context), so a handler that completes asynchronously may retain it past
/// the call's synchronous portion. A null `shared_ptr<const MethodCallContext>` indicates no session context
/// is available - e.g. direct calls from tests or internal SDK operations; handlers that require session
/// state must fail closed in that case.
/// @ingroup address_space
struct MethodCallContext
{
  /// Authenticated user identity of the calling session (the ClientUserId reported in
  /// condition events).
  String clientUserId;

  /// NodeId of the calling session, used for cross-session validation (e.g. ConditionRefresh).
  NodeId sessionId;

  /// Security mode of the secure channel over which the call was made.
  MessageSecurityMode channelSecurityMode{MessageSecurityMode::Invalid};

  /// Locale preference list supplied by the session at ActivateSession.
  ///
  /// Handlers may use it to resolve LocalizedText values in output arguments.
  std::vector<LocaleId> sessionLocales;

private:
  friend class detail::MethodCallContextInternalAccess;
  friend class detail::MethodCallAuthorizationInternalAccess;
  uint64_t mServerChannelAssociationEpoch{0};
  uint32_t mServerRequestId{0};
  bool mHasServerResponseCorrelation{false};
  std::function<VoidResult()> mAuthorizeObjectWrite;
};

class ValueSource;

/// Optional capability interface for Variable nodes whose Value an application can own.
///
/// A namespace implementation whose Variable nodes accept a @ref ValueSource inherits from this interface
/// and overrides Node::external_value_source() to return `this`. Implementations that do not (e.g.
/// proxies to remote servers) do not inherit it; callers detect support via
/// Node::external_value_source(), which returns nullptr when unsupported.
/// @ingroup address_space
class ExternalValueSource
{
public:
  ExternalValueSource() = default;
  virtual ~ExternalValueSource() = default;

  ExternalValueSource(const ExternalValueSource&) = delete;
  ExternalValueSource& operator=(const ExternalValueSource&) = delete;
  ExternalValueSource(ExternalValueSource&&) = delete;
  ExternalValueSource& operator=(ExternalValueSource&&) = delete;

  /// Makes @p source the owner of the Variable's Value, replacing any attached one; null detaches it.
  ///
  /// A Variable holds no Value itself, only its source. A write to a Variable with no source gives it a
  /// default source, which holds the Value written. Attaching a source replaces whichever source the
  /// Variable has, a default one and the Value it held included: every read and write of the Value goes to
  /// the new source, which applies IndexRanges and ValidBits itself. After a source is detached, the next
  /// write gives the Variable a new, empty default source. A call already made to a replaced source is not
  /// affected.
  ///
  /// A MonitoredItem on the Value at sampling interval 0 is fed by @ref notify_value_changed only when the
  /// Variable's MinimumSamplingInterval is explicitly 0, the source's claim that it reports every change
  /// (OPC 10000-4 5.12.1.2, exception-based); otherwise it is sampled through the source. A source whose
  /// Value differs per caller cannot report through @ref notify_value_changed, so its Variable's
  /// MinimumSamplingInterval is -1 or the source's own figure, and its items are sampled for each
  /// subscription's current caller. An item's feed is decided when it is created or modified.
  ///
  /// @param source The source; may serve other Variables too.
  /// @return Success, or an @ref ErrorDetail when the node refuses the source. Never throws.
  virtual VoidResult set_value_source(std::shared_ptr<ValueSource> source) = 0;

  /// Signals that the externally-managed value has changed.
  ///
  /// The value is forwarded to the MonitoredItems on this node fed by reports: those on an attribute other
  /// than the Value, and those on the Value at sampling interval 0 of a Variable whose
  /// MinimumSamplingInterval is 0 (see @ref set_value_source). The same value reaches every such item,
  /// whatever its Session, so a source whose Value differs per caller does not report through this member.
  ///
  /// @param newValue The updated value to publish to subscribers.
  virtual void notify_value_changed(DataValue newValue) = 0;
};

/// Optional capability interface for Method nodes that support runtime call-handler registration.
///
/// A namespace implementation whose Method nodes accept programmatic handler installation
/// inherits from this interface and overrides Node::method_call_source() to return `this`.
/// Implementations that do not support handler registration (e.g. proxies to remote servers)
/// do not inherit it; callers detect support via Node::method_call_source(), which returns
/// nullptr when unsupported.
/// @ingroup address_space
class MethodCallSource
{
public:
  /// Handler invoked to execute a method call.
  ///
  /// Receives the request, the calling session's @ref MethodCallContext (null when no session
  /// context is available), and a completion callback to invoke with the @ref CallResult.
  using CallHandler = std::function<void(const CallMethodRequest& methodToCall,
    shared_ptr<const MethodCallContext> context, std::function<void(CallResult)> callback)>;

  MethodCallSource() = default;
  virtual ~MethodCallSource() = default;

  MethodCallSource(const MethodCallSource&) = delete;
  MethodCallSource& operator=(const MethodCallSource&) = delete;
  MethodCallSource(MethodCallSource&&) = delete;
  MethodCallSource& operator=(MethodCallSource&&) = delete;

  /// Installs the handler invoked when the method is called.
  ///
  /// @param handler Invoked for each call; ownership is transferred to the node.
  /// @return Good, or a bad @ref StatusCode when the source rejects registration.
  virtual StatusCode set_call_handler(CallHandler handler) = 0;
};

// InitialAttribute and InitialAttributes are declared in ua_node_description.h, beside the
// NodeDescription::try_from_attributes that builds a description from them.

/// The four Attributes a Server derives per Session rather than stores.
///
/// `UserAccessLevel`, `UserWriteMask`, `UserExecutable` and `UserRolePermissions` are each the
/// non-user Attribute of the same node masked by the calling Session's permissions. They are never
/// held on a node and never answered by a namespace: the service reads the source Attribute and the
/// access-control layer derives the user view from it and the authorization verdict. A node that
/// stored one could disagree with what is actually enforced, and a caller reading one directly would
/// get an answer that is not specific to any Session.
///
/// Reading or writing one of these on a node is therefore a programming error rather than a missing
/// value, and is refused rather than answered empty.
/// @param attributeId Attribute to classify.
/// @return True for the four Session-derived Attributes described above.
[[nodiscard]] constexpr bool is_session_derived_attribute(AttributeId attributeId) noexcept
{
  return attributeId == AttributeId::UserAccessLevel || attributeId == AttributeId::UserWriteMask ||
         attributeId == AttributeId::UserExecutable || attributeId == AttributeId::UserRolePermissions;
}

/// The completion a Method call is answered through: by a method handler, a @ref MethodCallSource's handler
/// and @ref MethodAccessor::call_async.
/// @ingroup address_space
using CallMethodCompleteCallback = std::function<void(CallResult)>;

/// A Node a namespace hands out: its current non-Value Attributes, whether it has been deleted, and the two
/// optional capability probes.
///
/// Every other operation on a Node - References, Values, attribute writes, Method calls, Views - is a
/// member of the namespace that owns it (@ref Namespace), reached through the address space by the
/// services and by @ref NodeAccessor. A namespace that does not write its own Node class hands out the
/// Nodes of a @ref DescribedNodes store. Instances are held by `std::shared_ptr`.
/// @ingroup address_space
class Node : public std::enable_shared_from_this<Node>
{
public:
  Node() = default;

  virtual ~Node() = default;

  Node(const Node&) = delete;
  Node& operator=(const Node&) = delete;
  Node(Node&&) = delete;
  Node& operator=(Node&&) = delete;

  /// The Node's current non-Value Attributes.
  ///
  /// Every reader of a Node's Attributes reads this: the accessor getters, Browse and
  /// TranslateBrowsePaths, access control, event filters, and the Read service for every Attribute but
  /// a Variable's Value. So an implementation:
  ///
  /// - answers at once and never blocks, waits for I/O or calls back into the SDK;
  /// - is safe to call from any thread while a write to this Node is being applied, and returns either
  ///   the description before the write or the one after it, never a mixture (a description is
  ///   immutable, so returning a copy of the one held under the Node's lock is enough);
  /// - is answered by the one Node its namespace hands out for this NodeId while anyone holds it, so
  ///   that every holder sees the same Attributes.
  ///
  /// **Writes.** The namespace that hands out a Node applies a successful write of a non-Value
  /// Attribute to that Node before it completes the write, so that every getter on every accessor sees
  /// the new value once the write's completion runs. A namespace with its own Node class applies it
  /// itself (`NodeDescription::try_with_attribute` merges LocalizedText per OPC 10000-4 5.10.4.1); one
  /// using `DescribedNodes` calls `DescribedNodes::record_write`. A change the namespace learns of
  /// from its source is applied the same way, whenever it learns of it.
  ///
  /// @return The description.
  virtual NodeDescription attributes() const = 0;

  /// True once this Node's namespace has deleted it.
  ///
  /// A held accessor keeps its Node after a delete; this is how its getters, access control and the
  /// monitoring helper learn the Node is gone and answer `Bad_NodeIdUnknown` rather than its last
  /// Attributes. A pure read that never blocks: an implementation keeps the flag in an atomic.
  ///
  /// The namespace that deletes a Node sets this before its delete completes. The default answers false:
  /// a namespace that never deletes Nodes implements nothing.
  ///
  /// @return `true` once the Node has been deleted.
  virtual bool deleted() const noexcept
  {
    return false;
  }

  /// Returns this node's external value-source capability, or nullptr when unsupported.
  ///
  /// The returned pointer is owned by the node and remains valid for the node's lifetime.
  ///
  /// @return The @ref ExternalValueSource interface, or nullptr if the implementation does not
  ///         support runtime value-handler registration.
  virtual ExternalValueSource* external_value_source() noexcept
  {
    return nullptr;
  }

  /// Returns this node's method call-source capability, or nullptr when unsupported.
  ///
  /// The returned pointer is owned by the node and remains valid for the node's lifetime.
  ///
  /// @return The @ref MethodCallSource interface, or nullptr if the implementation does not support
  ///         runtime call-handler registration.
  virtual MethodCallSource* method_call_source() noexcept
  {
    return nullptr;
  }
};

/// The outcome of looking one Node up, or of creating one: the Node its namespace hands out, or a bad
/// @ref StatusCode carrying any @ref ErrorDetail (`Bad_NodeIdUnknown` for a NodeId the namespace does
/// not hold). The address space builds accessors from these; a namespace never builds an accessor.
/// @ingroup address_space
using NodeResult = Result<shared_ptr<Node>>;

}  // namespace ua

#endif  // UA_NODE_H
