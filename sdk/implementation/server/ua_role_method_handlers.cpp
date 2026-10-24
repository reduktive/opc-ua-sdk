// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_role_method_handlers.h"
#include "ua_whole_value_source.h"

#include "events/ua_event_bus.h"
#include "ua_array.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_endpoint_type.h"
#include "ua_exceptions.h"
#include "ua_identity_mapping_rule_type.h"
#include "ua_instantiation_service.h"
#include "ua_method_adapter.h"
#include "ua_method_id.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_role_mapping_rule_changed_audit_event_payload.h"
#include "ua_self_owning_operation.h"
#include "ua_attribute_wire.h"
#include "ua_instance_utils.h"
#include "ua_namespace_route.h"
#include "ua_weak_address_space.h"
#include "ua_string.h"
#include "ua_to_string.h"
#include "ua_variant.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <unordered_map>

namespace ua::server
{

namespace
{

enum class MethodKind
{
  AddIdentity,
  RemoveIdentity,
  AddApplication,
  RemoveApplication,
  AddEndpoint,
  RemoveEndpoint,
};

struct PerRoleMethodSpec
{
  WellKnownRole role;
  MethodKind kind;
  MethodId methodId;
  ObjectId roleObjectId;
  std::string_view sourceName;
};

// Per-role management Methods. UA-1.05.06 ships these only on the six
// configurable Roles (Observer ... SecurityAdmin). The fixed Anonymous,
// AuthenticatedUser and TrustedApplication Roles carry only an Identities
// Property - no management Methods and no Applications/Endpoints - so they have
// no entries here (their MethodId enum constants still exist in the generated
// ids, but the NodeSet defines no corresponding Method nodes).
constexpr std::array<PerRoleMethodSpec, 36> perRoleMethods{{
  {WellKnownRole::Observer,
    MethodKind::AddIdentity,
    MethodId::WellKnownRole_Observer_AddIdentity,
    ObjectId::WellKnownRole_Observer,
    "RoleSet/Observer/AddIdentity"},
  {WellKnownRole::Observer,
    MethodKind::RemoveIdentity,
    MethodId::WellKnownRole_Observer_RemoveIdentity,
    ObjectId::WellKnownRole_Observer,
    "RoleSet/Observer/RemoveIdentity"},
  {WellKnownRole::Observer,
    MethodKind::AddApplication,
    MethodId::WellKnownRole_Observer_AddApplication,
    ObjectId::WellKnownRole_Observer,
    "RoleSet/Observer/AddApplication"},
  {WellKnownRole::Observer,
    MethodKind::RemoveApplication,
    MethodId::WellKnownRole_Observer_RemoveApplication,
    ObjectId::WellKnownRole_Observer,
    "RoleSet/Observer/RemoveApplication"},
  {WellKnownRole::Observer,
    MethodKind::AddEndpoint,
    MethodId::WellKnownRole_Observer_AddEndpoint,
    ObjectId::WellKnownRole_Observer,
    "RoleSet/Observer/AddEndpoint"},
  {WellKnownRole::Observer,
    MethodKind::RemoveEndpoint,
    MethodId::WellKnownRole_Observer_RemoveEndpoint,
    ObjectId::WellKnownRole_Observer,
    "RoleSet/Observer/RemoveEndpoint"},

  {WellKnownRole::Operator,
    MethodKind::AddIdentity,
    MethodId::WellKnownRole_Operator_AddIdentity,
    ObjectId::WellKnownRole_Operator,
    "RoleSet/Operator/AddIdentity"},
  {WellKnownRole::Operator,
    MethodKind::RemoveIdentity,
    MethodId::WellKnownRole_Operator_RemoveIdentity,
    ObjectId::WellKnownRole_Operator,
    "RoleSet/Operator/RemoveIdentity"},
  {WellKnownRole::Operator,
    MethodKind::AddApplication,
    MethodId::WellKnownRole_Operator_AddApplication,
    ObjectId::WellKnownRole_Operator,
    "RoleSet/Operator/AddApplication"},
  {WellKnownRole::Operator,
    MethodKind::RemoveApplication,
    MethodId::WellKnownRole_Operator_RemoveApplication,
    ObjectId::WellKnownRole_Operator,
    "RoleSet/Operator/RemoveApplication"},
  {WellKnownRole::Operator,
    MethodKind::AddEndpoint,
    MethodId::WellKnownRole_Operator_AddEndpoint,
    ObjectId::WellKnownRole_Operator,
    "RoleSet/Operator/AddEndpoint"},
  {WellKnownRole::Operator,
    MethodKind::RemoveEndpoint,
    MethodId::WellKnownRole_Operator_RemoveEndpoint,
    ObjectId::WellKnownRole_Operator,
    "RoleSet/Operator/RemoveEndpoint"},

  {WellKnownRole::Engineer,
    MethodKind::AddIdentity,
    MethodId::WellKnownRole_Engineer_AddIdentity,
    ObjectId::WellKnownRole_Engineer,
    "RoleSet/Engineer/AddIdentity"},
  {WellKnownRole::Engineer,
    MethodKind::RemoveIdentity,
    MethodId::WellKnownRole_Engineer_RemoveIdentity,
    ObjectId::WellKnownRole_Engineer,
    "RoleSet/Engineer/RemoveIdentity"},
  {WellKnownRole::Engineer,
    MethodKind::AddApplication,
    MethodId::WellKnownRole_Engineer_AddApplication,
    ObjectId::WellKnownRole_Engineer,
    "RoleSet/Engineer/AddApplication"},
  {WellKnownRole::Engineer,
    MethodKind::RemoveApplication,
    MethodId::WellKnownRole_Engineer_RemoveApplication,
    ObjectId::WellKnownRole_Engineer,
    "RoleSet/Engineer/RemoveApplication"},
  {WellKnownRole::Engineer,
    MethodKind::AddEndpoint,
    MethodId::WellKnownRole_Engineer_AddEndpoint,
    ObjectId::WellKnownRole_Engineer,
    "RoleSet/Engineer/AddEndpoint"},
  {WellKnownRole::Engineer,
    MethodKind::RemoveEndpoint,
    MethodId::WellKnownRole_Engineer_RemoveEndpoint,
    ObjectId::WellKnownRole_Engineer,
    "RoleSet/Engineer/RemoveEndpoint"},

  {WellKnownRole::Supervisor,
    MethodKind::AddIdentity,
    MethodId::WellKnownRole_Supervisor_AddIdentity,
    ObjectId::WellKnownRole_Supervisor,
    "RoleSet/Supervisor/AddIdentity"},
  {WellKnownRole::Supervisor,
    MethodKind::RemoveIdentity,
    MethodId::WellKnownRole_Supervisor_RemoveIdentity,
    ObjectId::WellKnownRole_Supervisor,
    "RoleSet/Supervisor/RemoveIdentity"},
  {WellKnownRole::Supervisor,
    MethodKind::AddApplication,
    MethodId::WellKnownRole_Supervisor_AddApplication,
    ObjectId::WellKnownRole_Supervisor,
    "RoleSet/Supervisor/AddApplication"},
  {WellKnownRole::Supervisor,
    MethodKind::RemoveApplication,
    MethodId::WellKnownRole_Supervisor_RemoveApplication,
    ObjectId::WellKnownRole_Supervisor,
    "RoleSet/Supervisor/RemoveApplication"},
  {WellKnownRole::Supervisor,
    MethodKind::AddEndpoint,
    MethodId::WellKnownRole_Supervisor_AddEndpoint,
    ObjectId::WellKnownRole_Supervisor,
    "RoleSet/Supervisor/AddEndpoint"},
  {WellKnownRole::Supervisor,
    MethodKind::RemoveEndpoint,
    MethodId::WellKnownRole_Supervisor_RemoveEndpoint,
    ObjectId::WellKnownRole_Supervisor,
    "RoleSet/Supervisor/RemoveEndpoint"},

  {WellKnownRole::ConfigureAdmin,
    MethodKind::AddIdentity,
    MethodId::WellKnownRole_ConfigureAdmin_AddIdentity,
    ObjectId::WellKnownRole_ConfigureAdmin,
    "RoleSet/ConfigureAdmin/AddIdentity"},
  {WellKnownRole::ConfigureAdmin,
    MethodKind::RemoveIdentity,
    MethodId::WellKnownRole_ConfigureAdmin_RemoveIdentity,
    ObjectId::WellKnownRole_ConfigureAdmin,
    "RoleSet/ConfigureAdmin/RemoveIdentity"},
  {WellKnownRole::ConfigureAdmin,
    MethodKind::AddApplication,
    MethodId::WellKnownRole_ConfigureAdmin_AddApplication,
    ObjectId::WellKnownRole_ConfigureAdmin,
    "RoleSet/ConfigureAdmin/AddApplication"},
  {WellKnownRole::ConfigureAdmin,
    MethodKind::RemoveApplication,
    MethodId::WellKnownRole_ConfigureAdmin_RemoveApplication,
    ObjectId::WellKnownRole_ConfigureAdmin,
    "RoleSet/ConfigureAdmin/RemoveApplication"},
  {WellKnownRole::ConfigureAdmin,
    MethodKind::AddEndpoint,
    MethodId::WellKnownRole_ConfigureAdmin_AddEndpoint,
    ObjectId::WellKnownRole_ConfigureAdmin,
    "RoleSet/ConfigureAdmin/AddEndpoint"},
  {WellKnownRole::ConfigureAdmin,
    MethodKind::RemoveEndpoint,
    MethodId::WellKnownRole_ConfigureAdmin_RemoveEndpoint,
    ObjectId::WellKnownRole_ConfigureAdmin,
    "RoleSet/ConfigureAdmin/RemoveEndpoint"},

  {WellKnownRole::SecurityAdmin,
    MethodKind::AddIdentity,
    MethodId::WellKnownRole_SecurityAdmin_AddIdentity,
    ObjectId::WellKnownRole_SecurityAdmin,
    "RoleSet/SecurityAdmin/AddIdentity"},
  {WellKnownRole::SecurityAdmin,
    MethodKind::RemoveIdentity,
    MethodId::WellKnownRole_SecurityAdmin_RemoveIdentity,
    ObjectId::WellKnownRole_SecurityAdmin,
    "RoleSet/SecurityAdmin/RemoveIdentity"},
  {WellKnownRole::SecurityAdmin,
    MethodKind::AddApplication,
    MethodId::WellKnownRole_SecurityAdmin_AddApplication,
    ObjectId::WellKnownRole_SecurityAdmin,
    "RoleSet/SecurityAdmin/AddApplication"},
  {WellKnownRole::SecurityAdmin,
    MethodKind::RemoveApplication,
    MethodId::WellKnownRole_SecurityAdmin_RemoveApplication,
    ObjectId::WellKnownRole_SecurityAdmin,
    "RoleSet/SecurityAdmin/RemoveApplication"},
  {WellKnownRole::SecurityAdmin,
    MethodKind::AddEndpoint,
    MethodId::WellKnownRole_SecurityAdmin_AddEndpoint,
    ObjectId::WellKnownRole_SecurityAdmin,
    "RoleSet/SecurityAdmin/AddEndpoint"},
  {WellKnownRole::SecurityAdmin,
    MethodKind::RemoveEndpoint,
    MethodId::WellKnownRole_SecurityAdmin_RemoveEndpoint,
    ObjectId::WellKnownRole_SecurityAdmin,
    "RoleSet/SecurityAdmin/RemoveEndpoint"},
}};

/// Well-known Role name -> spec NodeId (Part 6 / NS0). When `AddRole` is called
/// with `namespaceIndex == 0` and a `roleName` matching one of these, the
/// server reuses the spec-defined well-known NodeId rather than allocating a
/// custom id (Part 18 4.2.2 L322-325 / SVR-SECADMIN-038).
struct WellKnownRoleName
{
  std::string_view name;
  uint32_t nodeId;
};

constexpr std::array<WellKnownRoleName, 9> wellKnownRoleNames{{
  {"Anonymous", utils::to_underlying(ObjectId::WellKnownRole_Anonymous)},
  {"AuthenticatedUser", utils::to_underlying(ObjectId::WellKnownRole_AuthenticatedUser)},
  {"Observer", utils::to_underlying(ObjectId::WellKnownRole_Observer)},
  {"Operator", utils::to_underlying(ObjectId::WellKnownRole_Operator)},
  {"Engineer", utils::to_underlying(ObjectId::WellKnownRole_Engineer)},
  {"Supervisor", utils::to_underlying(ObjectId::WellKnownRole_Supervisor)},
  {"ConfigureAdmin", utils::to_underlying(ObjectId::WellKnownRole_ConfigureAdmin)},
  {"SecurityAdmin", utils::to_underlying(ObjectId::WellKnownRole_SecurityAdmin)},
  {"TrustedApplication", utils::to_underlying(ObjectId::WellKnownRole_TrustedApplication)},
}};

std::optional<uint32_t> well_known_role_node_id(std::string_view roleName)
{
  for (const auto& entry : wellKnownRoleNames)
  {
    if (roleName == entry.name)
    {
      return entry.nodeId;
    }
  }
  return std::nullopt;
}

/// Shared state captured by every installed handler. Holds the active
/// `RoleConfiguration`, the `EventBus` for audit emission, the AddressSpace
/// for Variable mirroring, the server's ApplicationUri (for the audit
/// `ServerId` field), and the AddRole NodeId allocator counter.
struct RoleManagementContext
{
  std::weak_ptr<RoleConfiguration> roleConfig;
  std::weak_ptr<EventBus> eventBus;
  WeakAddressSpace addressSpace;
  ua::String serverApplicationUri;
  std::atomic<uint32_t> nextCustomRoleId{30000};
};

// ---------------------------------------------------------------------------
// ErrorDetail-tagged rejection helper
// ---------------------------------------------------------------------------

/// Build a non-Good `CallResult` carrying a structured source tag in the
/// ErrorDetail `code`. The tag distinguishes admin-gate / channel-floor
/// rejections from argument-validation rejections (which previously all shared
/// a single "InvalidMethodArguments" code). Tags follow the
/// `server.tier1.authz.rbac.management.*` taxonomy.
CallResult management_error(StatusCode status, std::string tag, std::string message)
{
  return CallResult{status,
    ErrorDetail::build(std::move(tag), "Role management operation failed", "RoleMethodHandler")
      .context(ua::ContextKeys::errorMessage, std::move(message))};
}

/// Overload carrying a pre-built, context-bearing ErrorDetail. Used where the
/// rejection has in-scope runtime facts that belong in structured context
/// (built via `ErrorDetail::build(...).context(...)`) rather than prose.
CallResult management_error(StatusCode status, std::unique_ptr<ErrorDetail> detail)
{
  return CallResult{status, std::move(detail)};
}

// ---------------------------------------------------------------------------
// Variable mirroring (matches the populate_role_set path's encoding)
// ---------------------------------------------------------------------------

/// The forward, local child of `parent` reached by a `referenceType` Reference whose BrowseName name is
/// `browseName`; `nullopt` when there is none.
optional<NodeAccessor> find_child(AddressSpace& addressSpace, const NodeAccessor& parent,
  ReferenceTypeId referenceType, std::string_view browseName)
{
  auto references = parent.try_get_references_sync();
  if (!references)
  {
    return std::nullopt;
  }
  for (const auto& ref : references.value())
  {
    if (!ref.is_forward() || ref.is_remote() || !ref.type_id().is_numeric())
    {
      continue;
    }
    if (ref.type_id().identifier().get_numeric() != utils::to_underlying(referenceType))
    {
      continue;
    }
    auto childResult = addressSpace.try_find_node_sync(ref.target_id().node_id());
    if (!childResult)
    {
      continue;
    }
    if (static_cast<std::string_view>(childResult.value().get_browse_name().name()) == browseName)
    {
      return childResult.value();
    }
  }
  return std::nullopt;
}

optional<NodeAccessor> find_property_child(
  AddressSpace& addressSpace, const NodeAccessor& parent, std::string_view browseName)
{
  return find_child(addressSpace, parent, ReferenceTypeId::HasProperty, browseName);
}

/// Best-effort mirror of a role Object's Property value, then @p done.
///
/// Asynchronous throughout: this runs inside a role-management Method handler, on a thread of the
/// address space's executor, and the lookups and the write may be answered by a post to that
/// executor. A Property that was not materialised (Part 18 4.2.2 makes several of them optional) and a
/// failed write both leave the mirror unchanged and still call @p done: the role configuration is the
/// source of truth, and the Method has already changed it.
void mirror_property_async(AddressSpace addressSpace, const NodeId& roleObjectId, std::string_view browseName,
  Variant value, std::function<void()> done)
{
  instance_utils::find_child_by_browse_name_async(std::move(addressSpace),
    roleObjectId,
    NodeId{ReferenceTypeId::HasProperty},
    QualifiedName{0, String{browseName}},
    [value = std::move(value), done = std::move(done)](NodeAccessorResult child) mutable
    {
      auto variable = child.is_good() ? child.value().as<VariableAccessor>() : std::nullopt;
      if (!variable)
      {
        done();
        return;
      }
      DataValue dv;
      dv.value() = std::move(value);
      dv.server_timestamp() = DateTime::now();
      variable->write_value_async(std::move(dv), [done = std::move(done)](VoidResult) mutable { done(); });
    });
}

template<typename T>
Array<RefStructure<Structure>> to_structure_array(const std::vector<T>& items)
{
  Array<RefStructure<Structure>> out;
  out.payload().reserve(items.size());
  for (const auto& item : items)
  {
    RefStructure<Structure> ref;
    ref = std::unique_ptr<Structure>{std::make_unique<T>(item).release()};
    out.payload().push_back(std::move(ref));
  }
  return out;
}

Array<String> to_string_array(const std::vector<String>& items)
{
  Array<String> out;
  out.payload().reserve(items.size());
  for (const auto& a : items)
  {
    out.payload().push_back(a);
  }
  return out;
}

void mirror_identities(AddressSpace& addressSpace, const NodeId& roleObjectId,
  const std::vector<IdentityMappingRuleType>& rules, std::function<void()> done)
{
  mirror_property_async(addressSpace,
    roleObjectId,
    "Identities",
    Variant{to_structure_array<IdentityMappingRuleType>(rules)},
    std::move(done));
}

void mirror_applications(AddressSpace& addressSpace, const NodeId& roleObjectId,
  const std::vector<String>& applications, std::function<void()> done)
{
  mirror_property_async(
    addressSpace, roleObjectId, "Applications", Variant{to_string_array(applications)}, std::move(done));
}

void mirror_endpoints(AddressSpace& addressSpace, const NodeId& roleObjectId,
  const std::vector<EndpointType>& endpoints, std::function<void()> done)
{
  mirror_property_async(addressSpace,
    roleObjectId,
    "Endpoints",
    Variant{to_structure_array<EndpointType>(endpoints)},
    std::move(done));
}

// ---------------------------------------------------------------------------
// Audit event emission (G.6)
// ---------------------------------------------------------------------------

void emit_audit(RoleManagementContext& ctx, const NodeId& roleObjectId, const NodeId& methodId,
  std::string_view sourceName, const std::vector<Variant>& inputArguments,
  shared_ptr<const MethodCallContext> callContext, StatusCode status)
{
  auto bus = ctx.eventBus.lock();
  if (!bus || !bus->has_event_interest())
  {
    return;
  }
  RoleMappingRuleChangedAuditEventPayload event;
  event.sourceNode = roleObjectId;
  event.sourceName = String{sourceName};
  event.actionTimeStamp = Variant{DateTime::now()};
  // Performed unless Bad: an Uncertain answer (a delete that left a Reference behind) did the action.
  event.status = !status.is_bad();
  event.serverId = ctx.serverApplicationUri;
  event.methodId = methodId;
  Array<Variant> auditInputArguments;
  auditInputArguments.payload().reserve(inputArguments.size());
  for (const auto& arg : inputArguments)
  {
    auditInputArguments.payload().push_back(arg);
  }
  event.inputArguments = Variant{auditInputArguments};
  event.message = LocalizedText{"", sourceName};
  event.severity = 1;
  if (callContext)
  {
    event.clientUserId = callContext->clientUserId;
  }
  bus->emit(event);
}

// ---------------------------------------------------------------------------
// Per-role method handler installation
// ---------------------------------------------------------------------------

/// The Role Object a per-role management Method acts on, the Method Node its handler is installed on,
/// and the SourceName its audit event carries. The well-known Roles name their NS0 Nodes from the
/// `perRoleMethods` table; a Role created by AddRole names the Nodes its instantiation allocated. Both
/// install the same handler bodies through this one shape.
struct RoleMethodTarget
{
  NodeId roleObjectId;
  NodeId methodId;
  std::string sourceName;
  /// The Method Node itself, when the caller has already resolved it. AddRole installs its handlers on a
  /// thread of the address space's executor, where a blocking lookup by `methodId` is refused.
  optional<NodeAccessor> methodNode;
};

template<typename Body>
void install_call_handler(const NodeAccessor& method, Body body)
{
  auto* source = method->method_call_source();
  if (!source)
  {
    return;
  }
  source->set_call_handler(std::move(body));
}

/// Start-up form: resolves the Method Node on the application thread, then installs the handler.
template<typename Body>
void install_method_handler(AddressSpace& addressSpace, const NodeId& methodNodeId, Body body)
{
  auto methodResult = addressSpace.try_find_node_sync(methodNodeId);
  if (!methodResult)
  {
    return;
  }
  install_call_handler(methodResult.value(), std::move(body));
}

template<typename Body>
void install_method_handler(AddressSpace& addressSpace, const RoleMethodTarget& target, Body body)
{
  if (target.methodNode)
  {
    install_call_handler(*target.methodNode, std::move(body));
    return;
  }
  install_method_handler(addressSpace, target.methodId, std::move(body));
}

void install_add_identity_handler(
  AddressSpace& addressSpace, const RoleMethodTarget& target, std::shared_ptr<RoleManagementContext> ctx)
{
  const NodeId roleObjectId = target.roleObjectId;
  const NodeId methodId = target.methodId;
  const std::string sourceName = target.sourceName;

  install_method_handler(addressSpace,
    target,
    [ctx, roleObjectId, methodId, sourceName](const CallMethodRequest& req,
      shared_ptr<const MethodCallContext>
        callContext,
      std::function<void(CallResult)>
        complete)
    {
      auto roleConfig = ctx->roleConfig.lock();
      auto lockedAddressSpace = ctx->addressSpace.lock();
      if (!roleConfig || !lockedAddressSpace)
      {
        complete(CallResult{StatusCode{Status::BadInternalError}});
        return;
      }
      // AddIdentity requires an encrypted channel AND an admin caller
      // (Part 18 4.4.5 L873-874 / SVR-SECADMIN-040).
      const auto& args = req.input_arguments();
      if (args.size() != 1)
      {
        complete(management_error(Status::BadInvalidArgument,
          ErrorDetail::build("InvalidMethodArguments",
            "AddIdentity requires exactly one argument (IdentityMappingRuleType)",
            "server.tier1.authz.rbac.management.invalid_arguments")
            .context(ua::ContextKeys::sizeExpected, "1")
            .context(ua::ContextKeys::sizeActual, std::to_string(args.size()))));
        return;
      }
      const auto* rule = args[0].try_as<IdentityMappingRuleType>();
      if (!rule)
      {
        complete(management_error(Status::BadTypeMismatch,
          "server.tier1.authz.rbac.management.invalid_arguments",
          "AddIdentity argument is not an IdentityMappingRuleType structure"));
        return;
      }
      // Propagate the format-discipline + duplicate + role-not-found errors
      // with their ErrorDetail chain intact (Part 18 4.4.3 enforces the
      // criteria format at config time; non-Good results carry the source
      // tag).
      auto addResult = roleConfig->add_identity_rule(roleObjectId, *rule);
      if (addResult.is_bad())
      {
        complete(CallResult{addResult.status_code(), addResult.shared_detail()});
        return;
      }
      // The Method answers once the mirrored Property has been written, as it did when the write blocked.
      auto finish = [ctx,
                      roleObjectId,
                      methodId,
                      sourceName,
                      inputCopy = std::vector<Variant>{args.begin(), args.end()},
                      callContext,
                      complete = std::move(complete)]() mutable
      {
        emit_audit(*ctx, roleObjectId, methodId, sourceName, inputCopy, callContext, StatusCode{});
        complete(CallResult{CallMethodResult{}});
      };
      auto def = roleConfig->get_role(roleObjectId);
      if (!def)
      {
        finish();
        return;
      }
      mirror_identities(*lockedAddressSpace, roleObjectId, def->identities, std::move(finish));
    });
}

void install_remove_identity_handler(
  AddressSpace& addressSpace, const RoleMethodTarget& target, std::shared_ptr<RoleManagementContext> ctx)
{
  const NodeId roleObjectId = target.roleObjectId;
  const NodeId methodId = target.methodId;
  const std::string sourceName = target.sourceName;

  install_method_handler(addressSpace,
    target,
    [ctx, roleObjectId, methodId, sourceName](const CallMethodRequest& req,
      shared_ptr<const MethodCallContext>
        callContext,
      std::function<void(CallResult)>
        complete)
    {
      auto roleConfig = ctx->roleConfig.lock();
      auto lockedAddressSpace = ctx->addressSpace.lock();
      if (!roleConfig || !lockedAddressSpace)
      {
        complete(CallResult{StatusCode{Status::BadInternalError}});
        return;
      }
      const auto& args = req.input_arguments();
      if (args.size() != 1)
      {
        complete(management_error(Status::BadInvalidArgument,
          ErrorDetail::build("InvalidMethodArguments",
            "RemoveIdentity requires exactly one argument",
            "server.tier1.authz.rbac.management.invalid_arguments")
            .context(ua::ContextKeys::sizeExpected, "1")
            .context(ua::ContextKeys::sizeActual, std::to_string(args.size()))));
        return;
      }
      const auto* rule = args[0].try_as<IdentityMappingRuleType>();
      if (!rule)
      {
        complete(management_error(Status::BadTypeMismatch,
          "server.tier1.authz.rbac.management.invalid_arguments",
          "RemoveIdentity argument is not IdentityMappingRuleType"));
        return;
      }
      if (!roleConfig->remove_identity_rule(roleObjectId, *rule))
      {
        complete(management_error(Status::BadNotFound,
          ErrorDetail::build("EntryNotFound",
            "Identity rule not present on role",
            "server.tier1.authz.rbac.management.not_found")
            .context(ua::ContextKeys::nodeId, ua::to_string(roleObjectId))));
        return;
      }
      // The Method answers once the mirrored Property has been written, as it did when the write blocked.
      auto finish = [ctx,
                      roleObjectId,
                      methodId,
                      sourceName,
                      inputCopy = std::vector<Variant>{args.begin(), args.end()},
                      callContext,
                      complete = std::move(complete)]() mutable
      {
        emit_audit(*ctx, roleObjectId, methodId, sourceName, inputCopy, callContext, StatusCode{});
        complete(CallResult{CallMethodResult{}});
      };
      auto def = roleConfig->get_role(roleObjectId);
      if (!def)
      {
        finish();
        return;
      }
      mirror_identities(*lockedAddressSpace, roleObjectId, def->identities, std::move(finish));
    });
}

void install_add_application_handler(
  AddressSpace& addressSpace, const RoleMethodTarget& target, std::shared_ptr<RoleManagementContext> ctx)
{
  const NodeId roleObjectId = target.roleObjectId;
  const NodeId methodId = target.methodId;
  const std::string sourceName = target.sourceName;

  install_method_handler(addressSpace,
    target,
    [ctx, roleObjectId, methodId, sourceName](const CallMethodRequest& req,
      shared_ptr<const MethodCallContext>
        callContext,
      std::function<void(CallResult)>
        complete)
    {
      auto roleConfig = ctx->roleConfig.lock();
      auto lockedAddressSpace = ctx->addressSpace.lock();
      if (!roleConfig || !lockedAddressSpace)
      {
        complete(CallResult{StatusCode{Status::BadInternalError}});
        return;
      }
      const auto& args = req.input_arguments();
      if (args.size() != 1)
      {
        complete(management_error(Status::BadInvalidArgument,
          ErrorDetail::build("InvalidMethodArguments",
            "AddApplication requires exactly one argument",
            "server.tier1.authz.rbac.management.invalid_arguments")
            .context(ua::ContextKeys::sizeExpected, "1")
            .context(ua::ContextKeys::sizeActual, std::to_string(args.size()))));
        return;
      }
      const auto* uri = args[0].try_as<String>();
      if (!uri)
      {
        complete(management_error(Status::BadTypeMismatch,
          "server.tier1.authz.rbac.management.invalid_arguments",
          "AddApplication argument is not a String"));
        return;
      }
      if (uri->empty())
      {
        complete(management_error(Status::BadInvalidArgument,
          ErrorDetail::build("InvalidMethodArguments",
            "AddApplication ApplicationUri must not be empty",
            "server.tier1.authz.rbac.management.invalid_arguments")
            .context(ua::ContextKeys::nodeId, ua::to_string(roleObjectId))));
        return;
      }
      if (!roleConfig->add_application(roleObjectId, *uri))
      {
        complete(management_error(Status::BadEntryExists,
          ErrorDetail::build("EntryDuplicate",
            "Application URI already present on role",
            "server.tier1.authz.rbac.management.duplicate")
            .context(ua::ContextKeys::applicationUri, std::string{*uri})
            .context(ua::ContextKeys::nodeId, ua::to_string(roleObjectId))));
        return;
      }
      // The Method answers once the mirrored Property has been written, as it did when the write blocked.
      auto finish = [ctx,
                      roleObjectId,
                      methodId,
                      sourceName,
                      inputCopy = std::vector<Variant>{args.begin(), args.end()},
                      callContext,
                      complete = std::move(complete)]() mutable
      {
        emit_audit(*ctx, roleObjectId, methodId, sourceName, inputCopy, callContext, StatusCode{});
        complete(CallResult{CallMethodResult{}});
      };
      auto def = roleConfig->get_role(roleObjectId);
      if (!def)
      {
        finish();
        return;
      }
      mirror_applications(*lockedAddressSpace, roleObjectId, def->applications, std::move(finish));
    });
}

void install_remove_application_handler(
  AddressSpace& addressSpace, const RoleMethodTarget& target, std::shared_ptr<RoleManagementContext> ctx)
{
  const NodeId roleObjectId = target.roleObjectId;
  const NodeId methodId = target.methodId;
  const std::string sourceName = target.sourceName;

  install_method_handler(addressSpace,
    target,
    [ctx, roleObjectId, methodId, sourceName](const CallMethodRequest& req,
      shared_ptr<const MethodCallContext>
        callContext,
      std::function<void(CallResult)>
        complete)
    {
      auto roleConfig = ctx->roleConfig.lock();
      auto lockedAddressSpace = ctx->addressSpace.lock();
      if (!roleConfig || !lockedAddressSpace)
      {
        complete(CallResult{StatusCode{Status::BadInternalError}});
        return;
      }
      const auto& args = req.input_arguments();
      if (args.size() != 1)
      {
        complete(management_error(Status::BadInvalidArgument,
          ErrorDetail::build("InvalidMethodArguments",
            "RemoveApplication requires exactly one argument",
            "server.tier1.authz.rbac.management.invalid_arguments")
            .context(ua::ContextKeys::sizeExpected, "1")
            .context(ua::ContextKeys::sizeActual, std::to_string(args.size()))));
        return;
      }
      const auto* uri = args[0].try_as<String>();
      if (!uri)
      {
        complete(management_error(Status::BadTypeMismatch,
          "server.tier1.authz.rbac.management.invalid_arguments",
          "RemoveApplication argument is not a String"));
        return;
      }
      if (!roleConfig->remove_application(roleObjectId, *uri))
      {
        complete(management_error(Status::BadNotFound,
          ErrorDetail::build("EntryNotFound",
            "Application URI not present on role",
            "server.tier1.authz.rbac.management.not_found")
            .context(ua::ContextKeys::applicationUri, std::string{*uri})
            .context(ua::ContextKeys::nodeId, ua::to_string(roleObjectId))));
        return;
      }
      // The Method answers once the mirrored Property has been written, as it did when the write blocked.
      auto finish = [ctx,
                      roleObjectId,
                      methodId,
                      sourceName,
                      inputCopy = std::vector<Variant>{args.begin(), args.end()},
                      callContext,
                      complete = std::move(complete)]() mutable
      {
        emit_audit(*ctx, roleObjectId, methodId, sourceName, inputCopy, callContext, StatusCode{});
        complete(CallResult{CallMethodResult{}});
      };
      auto def = roleConfig->get_role(roleObjectId);
      if (!def)
      {
        finish();
        return;
      }
      mirror_applications(*lockedAddressSpace, roleObjectId, def->applications, std::move(finish));
    });
}

void install_add_endpoint_handler(
  AddressSpace& addressSpace, const RoleMethodTarget& target, std::shared_ptr<RoleManagementContext> ctx)
{
  const NodeId roleObjectId = target.roleObjectId;
  const NodeId methodId = target.methodId;
  const std::string sourceName = target.sourceName;

  install_method_handler(addressSpace,
    target,
    [ctx, roleObjectId, methodId, sourceName](const CallMethodRequest& req,
      shared_ptr<const MethodCallContext>
        callContext,
      std::function<void(CallResult)>
        complete)
    {
      auto roleConfig = ctx->roleConfig.lock();
      auto lockedAddressSpace = ctx->addressSpace.lock();
      if (!roleConfig || !lockedAddressSpace)
      {
        complete(CallResult{StatusCode{Status::BadInternalError}});
        return;
      }
      const auto& args = req.input_arguments();
      if (args.size() != 1)
      {
        complete(management_error(Status::BadInvalidArgument,
          ErrorDetail::build("InvalidMethodArguments",
            "AddEndpoint requires exactly one argument",
            "server.tier1.authz.rbac.management.invalid_arguments")
            .context(ua::ContextKeys::sizeExpected, "1")
            .context(ua::ContextKeys::sizeActual, std::to_string(args.size()))));
        return;
      }
      const auto* endpoint = args[0].try_as<EndpointType>();
      if (!endpoint)
      {
        complete(management_error(Status::BadTypeMismatch,
          "server.tier1.authz.rbac.management.invalid_arguments",
          "AddEndpoint argument is not an EndpointType"));
        return;
      }
      if (endpoint->endpoint_url().empty())
      {
        complete(management_error(Status::BadInvalidArgument,
          ErrorDetail::build("InvalidMethodArguments",
            "AddEndpoint EndpointUrl must not be empty",
            "server.tier1.authz.rbac.management.invalid_arguments")
            .context(ua::ContextKeys::nodeId, ua::to_string(roleObjectId))));
        return;
      }
      if (!roleConfig->add_endpoint(roleObjectId, *endpoint))
      {
        complete(management_error(Status::BadEntryExists,
          ErrorDetail::build("EntryDuplicate",
            "Endpoint already present on role",
            "server.tier1.authz.rbac.management.duplicate")
            .context(ua::ContextKeys::endpointUrl, std::string{endpoint->endpoint_url()})
            .context(ua::ContextKeys::nodeId, ua::to_string(roleObjectId))));
        return;
      }
      // The Method answers once the mirrored Property has been written, as it did when the write blocked.
      auto finish = [ctx,
                      roleObjectId,
                      methodId,
                      sourceName,
                      inputCopy = std::vector<Variant>{args.begin(), args.end()},
                      callContext,
                      complete = std::move(complete)]() mutable
      {
        emit_audit(*ctx, roleObjectId, methodId, sourceName, inputCopy, callContext, StatusCode{});
        complete(CallResult{CallMethodResult{}});
      };
      auto def = roleConfig->get_role(roleObjectId);
      if (!def)
      {
        finish();
        return;
      }
      mirror_endpoints(*lockedAddressSpace, roleObjectId, def->endpoints, std::move(finish));
    });
}

void install_remove_endpoint_handler(
  AddressSpace& addressSpace, const RoleMethodTarget& target, std::shared_ptr<RoleManagementContext> ctx)
{
  const NodeId roleObjectId = target.roleObjectId;
  const NodeId methodId = target.methodId;
  const std::string sourceName = target.sourceName;

  install_method_handler(addressSpace,
    target,
    [ctx, roleObjectId, methodId, sourceName](const CallMethodRequest& req,
      shared_ptr<const MethodCallContext>
        callContext,
      std::function<void(CallResult)>
        complete)
    {
      auto roleConfig = ctx->roleConfig.lock();
      auto lockedAddressSpace = ctx->addressSpace.lock();
      if (!roleConfig || !lockedAddressSpace)
      {
        complete(CallResult{StatusCode{Status::BadInternalError}});
        return;
      }
      const auto& args = req.input_arguments();
      if (args.size() != 1)
      {
        complete(management_error(Status::BadInvalidArgument,
          ErrorDetail::build("InvalidMethodArguments",
            "RemoveEndpoint requires exactly one argument",
            "server.tier1.authz.rbac.management.invalid_arguments")
            .context(ua::ContextKeys::sizeExpected, "1")
            .context(ua::ContextKeys::sizeActual, std::to_string(args.size()))));
        return;
      }
      const auto* endpoint = args[0].try_as<EndpointType>();
      if (!endpoint)
      {
        complete(management_error(Status::BadTypeMismatch,
          "server.tier1.authz.rbac.management.invalid_arguments",
          "RemoveEndpoint argument is not an EndpointType"));
        return;
      }
      if (!roleConfig->remove_endpoint(roleObjectId, *endpoint))
      {
        complete(management_error(Status::BadNotFound,
          ErrorDetail::build(
            "EntryNotFound", "Endpoint not present on role", "server.tier1.authz.rbac.management.not_found")
            .context(ua::ContextKeys::endpointUrl, std::string{endpoint->endpoint_url()})
            .context(ua::ContextKeys::nodeId, ua::to_string(roleObjectId))));
        return;
      }
      // The Method answers once the mirrored Property has been written, as it did when the write blocked.
      auto finish = [ctx,
                      roleObjectId,
                      methodId,
                      sourceName,
                      inputCopy = std::vector<Variant>{args.begin(), args.end()},
                      callContext,
                      complete = std::move(complete)]() mutable
      {
        emit_audit(*ctx, roleObjectId, methodId, sourceName, inputCopy, callContext, StatusCode{});
        complete(CallResult{CallMethodResult{}});
      };
      auto def = roleConfig->get_role(roleObjectId);
      if (!def)
      {
        finish();
        return;
      }
      mirror_endpoints(*lockedAddressSpace, roleObjectId, def->endpoints, std::move(finish));
    });
}

void install_role_management_handler(AddressSpace& addressSpace, MethodKind kind,
  const RoleMethodTarget& target, std::shared_ptr<RoleManagementContext> ctx)
{
  switch (kind)
  {
  case MethodKind::AddIdentity:
    install_add_identity_handler(addressSpace, target, std::move(ctx));
    break;
  case MethodKind::RemoveIdentity:
    install_remove_identity_handler(addressSpace, target, std::move(ctx));
    break;
  case MethodKind::AddApplication:
    install_add_application_handler(addressSpace, target, std::move(ctx));
    break;
  case MethodKind::RemoveApplication:
    install_remove_application_handler(addressSpace, target, std::move(ctx));
    break;
  case MethodKind::AddEndpoint:
    install_add_endpoint_handler(addressSpace, target, std::move(ctx));
    break;
  case MethodKind::RemoveEndpoint:
    install_remove_endpoint_handler(addressSpace, target, std::move(ctx));
    break;
  }
}

/// The six Optional RoleType management Methods (Part 18 4.4.1 Table 4), by BrowseName.
struct RoleTypeManagementMethod
{
  MethodKind kind;
  std::string_view browseName;
};

constexpr std::array<RoleTypeManagementMethod, 6> roleTypeManagementMethods{{
  {MethodKind::AddIdentity, "AddIdentity"},
  {MethodKind::RemoveIdentity, "RemoveIdentity"},
  {MethodKind::AddApplication, "AddApplication"},
  {MethodKind::RemoveApplication, "RemoveApplication"},
  {MethodKind::AddEndpoint, "AddEndpoint"},
  {MethodKind::RemoveEndpoint, "RemoveEndpoint"},
}};

bool is_role_type_management_method(std::string_view browseName)
{
  return std::any_of(roleTypeManagementMethods.begin(),
    roleTypeManagementMethods.end(),
    [browseName](const RoleTypeManagementMethod& method) { return method.browseName == browseName; });
}

/// Installs the six management handlers on the Method Nodes AddRole instantiated under the Role
/// `roleObjectId`; `components` are the Role's HasComponent children, already resolved, so nothing here
/// looks a Node up. The bodies, checks and audit are the well-known Roles' own; only the Nodes differ. A
/// Method the instantiation did not create is skipped, as the well-known path skips a Method its NodeSet
/// lacks. The handlers live on the Method Nodes, so RemoveRole's subtree delete takes them with the Role.
void install_added_role_management_handlers(AddressSpace& addressSpace, const NodeId& roleObjectId,
  std::string_view roleName, const std::vector<NodeAccessor>& components,
  const std::shared_ptr<RoleManagementContext>& ctx)
{
  for (const auto& method : roleTypeManagementMethods)
  {
    const auto methodNode = std::find_if(components.begin(),
      components.end(),
      [&method](const NodeAccessor& component)
      {
        return component.get_node_class() == NodeClass::Method &&
               static_cast<std::string_view>(component.get_browse_name().name()) == method.browseName;
      });
    if (methodNode == components.end())
    {
      continue;
    }
    std::string sourceName{"RoleSet/"};
    sourceName.append(roleName).append("/").append(method.browseName);
    install_role_management_handler(addressSpace,
      method.kind,
      RoleMethodTarget{roleObjectId, methodNode->get_node_id(), std::move(sourceName), *methodNode},
      ctx);
  }
}

// ---------------------------------------------------------------------------
// Write notifiers on the two writable *Exclude Variables (no audit emission)
// ---------------------------------------------------------------------------

/// Serves an *Exclude Variable from the role configuration: reads report the configured flag and writes
/// change it. The Variable is already resolved, so this does no lookup and cannot block.
void wire_exclude_property(const NodeAccessor& child, const NodeId& roleObjectId,
  std::shared_ptr<RoleManagementContext> ctx, bool isApplications)
{
  auto var = child.as<VariableAccessor>();
  if (!var)
  {
    return;
  }
  auto* writeSource = child->external_value_source();
  if (!writeSource)
  {
    return;
  }

  // A Boolean scalar: the namespace refuses a ranged read or write before the source sees it.
  detail::WholeValueRead readHandler =
    [ctx, roleObjectId, isApplications](
      const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
  {
    auto roleConfig = ctx->roleConfig.lock();
    if (!roleConfig)
    {
      complete(DataValueResult{StatusCode{Status::BadInternalError},
        ErrorDetail::build("RoleConfigurationUnavailable",
          "Role configuration is unavailable while reading an Exclude Property",
          "server.tier1.authz.rbac.management.exclude.read")
          .context(ua::ContextKeys::nodeId, ua::to_string(roleObjectId))});
      return;
    }
    auto role = roleConfig->get_role(roleObjectId);
    if (!role)
    {
      complete(DataValueResult{StatusCode{Status::BadNodeIdUnknown},
        ErrorDetail::build("RoleNotFound",
          "Role configuration was not found while reading an Exclude Property",
          "server.tier1.authz.rbac.management.exclude.read")
          .context(ua::ContextKeys::nodeId, ua::to_string(roleObjectId))});
      return;
    }
    complete(DataValue{Variant{isApplications ? role->applicationsExclude : role->endpointsExclude}});
  };

  ValueSource::WriteValueHandler handler = [ctx, roleObjectId, isApplications](
                                             const ValueSource::WriteContext& /*context*/,
                                             const Node& /*node*/,
                                             const WriteValue& write,
                                             std::function<void(ValueSource::WriteResult)>
                                               complete)
  {
    const bool* flag = write.value().value().try_as<bool>();
    if (!flag)
    {
      complete(ValueSource::WriteResult{StatusCode{Status::BadTypeMismatch}});
      return;
    }
    auto roleConfig = ctx->roleConfig.lock();
    if (!roleConfig)
    {
      complete(ValueSource::WriteResult{StatusCode{Status::BadInternalError}});
      return;
    }
    const bool ok = isApplications ? roleConfig->set_applications_exclude(roleObjectId, *flag)
                                   : roleConfig->set_endpoints_exclude(roleObjectId, *flag);
    if (!ok)
    {
      complete(ValueSource::WriteResult{StatusCode{Status::BadNodeIdUnknown}});
      return;
    }
    complete(ValueSource::Written{});
  };
  (void)writeSource->set_value_source(detail::whole_value_source(std::move(readHandler), std::move(handler)));
}

/// Start-up form: resolves the *Exclude Variable on the application thread, then wires it.
void install_exclude_write_handler(AddressSpace& addressSpace, const NodeId& roleObjectId,
  std::string_view propertyName, std::shared_ptr<RoleManagementContext> ctx, bool isApplications)
{
  auto roleNode = addressSpace.try_find_node_sync(roleObjectId);
  if (!roleNode)
  {
    return;
  }
  auto node = roleNode.value();
  if (auto child = find_property_child(addressSpace, node, propertyName))
  {
    wire_exclude_property(*child, roleObjectId, std::move(ctx), isApplications);
  }
}

// ---------------------------------------------------------------------------
// G.3: RoleSet.AddRole / RemoveRole
// ---------------------------------------------------------------------------

/// AddRole after its arguments are validated: every step that touches the address space.
///
/// A coroutine on its own strand, because this runs inside a Method handler on a thread of the address
/// space's executor and every step - the RoleSet browse, the NodeId probe, the instantiation, the
/// lookups and writes on the new Role - may be answered by a post to that executor. The steps, their
/// order and their failures are the ones the blocking form had.
class AddRoleOperation final : public ua::async::SelfOwningOperation<AddRoleOperation>
{
public:
  struct Request
  {
    std::shared_ptr<RoleManagementContext> ctx;
    std::shared_ptr<RoleConfiguration> roleConfig;
    // Held weakly, so that a step waiting for a namespace's answer does not keep the address space (CALLS-21
    // rule 1); each step locks it for its own call.
    WeakAddressSpace addressSpace;
    String roleName;
    uint16_t namespaceIndex{0};
    std::vector<Variant> inputArguments;
    shared_ptr<const MethodCallContext> callContext;
    std::function<void(CallResult)> complete;
  };

  /// @p owner is the address space @p request names, locked by the caller: the strand and the logger are
  /// taken from it.
  static void start(Request request, const AddressSpace& owner)
  {
    launch(std::make_shared<AddRoleOperation>(std::move(request), owner));
  }

  AddRoleOperation(Request request, const AddressSpace& owner)
    : ua::async::SelfOwningOperation<AddRoleOperation>(
        boost::asio::make_strand(owner.executor()), owner.logger()),
      mRequest(std::move(request))
  {}

private:
  friend class ua::async::SelfOwningOperation<AddRoleOperation>;

  /// The address space, locked for one step's call; nullopt, with @p completion answered AddressSpaceGone,
  /// when it is gone.
  template<typename Answer, typename Completion>
  std::optional<AddressSpace> owner_or_gone(Completion& completion)
  {
    auto owner = mRequest.addressSpace.lock();
    if (!owner)
      completion(Answer{::ua::detail::address_space_gone("AddRole")});
    return owner;
  }

  auto find_node(NodeId nodeId)
  {
    return await_step<NodeAccessorResult>(
      [this, nodeId = std::move(nodeId)](auto completion) mutable
      {
        if (auto owner = owner_or_gone<NodeAccessorResult>(completion))
          owner->find_node_async(nodeId, std::move(completion));
      });
  }

  auto get_references(NodeAccessor node)
  {
    return await_step<NodeAccessor::ReferencesResult>([node = std::move(node)](auto completion) mutable
      { node.get_references_async(std::move(completion)); });
  }

  auto write_attribute(NodeAccessor node, AttributeId attributeId, Variant encoded)
  {
    return await_step<VoidResult>(
      [node = std::move(node), attributeId, encoded = std::move(encoded)](auto completion) mutable
      { node.write_attribute_async(attributeId, std::move(encoded), std::move(completion)); });
  }

  auto instantiate(NodeId newRoleId)
  {
    return await_step<NodeSubtreeResult>(
      [this, newRoleId = std::move(newRoleId)](auto completion) mutable
      {
        const NodeId roleSetId{0, utils::to_underlying(ObjectId::Server_ServerCapabilities_RoleSet)};
        InstantiationOptions options;
        options.targetNamespaceIndex = mRequest.namespaceIndex;
        auto allocateChild = guid_node_id_allocator();
        options.nodeIdAllocator = [newRoleId, rootPending = true, allocateChild = std::move(allocateChild)](
                                    uint16_t namespaceIndex, const QualifiedName& browseName) mutable
        {
          if (rootPending)
          {
            rootPending = false;
            return newRoleId;
          }
          return allocateChild(namespaceIndex, browseName);
        };
        options.optionalChildFilter = [](const ChildFilterInfo& child)
        {
          const auto name = static_cast<std::string_view>(child.browseName.name());
          if (child.nodeClass == NodeClass::Method)
          {
            return is_role_type_management_method(name);
          }
          return name == "ApplicationsExclude" || name == "EndpointsExclude" || name == "Applications" ||
                 name == "Endpoints";
        };
        auto owner = owner_or_gone<NodeSubtreeResult>(completion);
        if (!owner)
          return;
        InstantiationService{*owner}.instantiate_object_async(roleSetId,
          QualifiedName{mRequest.namespaceIndex, mRequest.roleName},
          NodeId{ObjectTypeId::RoleType},
          options,
          std::move(completion));
      });
  }

  auto mirror_exclude(NodeId roleId, std::string_view browseName)
  {
    return await_step<VoidResult>(
      [this, roleId = std::move(roleId), browseName](auto completion) mutable
      {
        auto owner = owner_or_gone<VoidResult>(completion);
        if (!owner)
          return;
        mirror_property_async(std::move(*owner),
          roleId,
          browseName,
          Variant{true},
          [completion = std::move(completion)]() mutable { completion(VoidResult{}); });
      });
  }

  auto find_exclude(NodeId roleId, std::string_view browseName)
  {
    return await_step<NodeAccessorResult>(
      [this, roleId = std::move(roleId), browseName](auto completion) mutable
      {
        auto owner = owner_or_gone<NodeAccessorResult>(completion);
        if (!owner)
          return;
        instance_utils::find_child_by_browse_name_async(std::move(*owner),
          roleId,
          NodeId{ReferenceTypeId::HasProperty},
          QualifiedName{0, String{browseName}},
          std::move(completion));
      });
  }

  /// The forward, local HasComponent children of @p node that resolve; a dangling Reference is skipped.
  ua::async::Task<std::vector<NodeAccessor>> find_components(NodeAccessor node)
  {
    std::vector<NodeAccessor> components;
    auto references = co_await get_references(std::move(node));
    if (!references.is_good())
      co_return components;
    for (const auto& ref : references.value())
    {
      if (!ref.is_forward() || ref.is_remote() || ref.type_id() != NodeId{ReferenceTypeId::HasComponent})
        continue;
      auto child = co_await find_node(ref.target_id().node_id());
      if (child.is_good())
        components.push_back(std::move(child).value());
    }
    co_return components;
  }

  /// True iff the RoleSet Object already has a HasComponent child whose BrowseName matches the new
  /// Role's name (Part 18 4.2.2 L314 BrowseName uniqueness / SVR-SECADMIN-035). Dangling references to
  /// deleted children are skipped.
  ua::async::Task<bool> role_set_has_child_named()
  {
    const NodeId roleSetId{0, utils::to_underlying(ObjectId::Server_ServerCapabilities_RoleSet)};
    auto roleSet = co_await find_node(roleSetId);
    if (!roleSet.is_good())
      co_return false;
    auto references = co_await get_references(roleSet.value());
    if (!references.is_good())
      co_return false;
    const std::string_view wanted = static_cast<std::string_view>(mRequest.roleName);
    for (const auto& ref : references.value())
    {
      if (!ref.is_forward() || ref.is_remote() || ref.type_id() != NodeId{ReferenceTypeId::HasComponent})
        continue;
      auto child = co_await find_node(ref.target_id().node_id());
      // Non-fatal: a dangling reference names no child, so it cannot collide; nor is a child the namespace
      // is uncertain of compared.
      if (!child.is_good())
        continue;
      if (static_cast<std::string_view>(child.value().get_browse_name().name()) == wanted)
        co_return true;
    }
    co_return false;
  }

  /// A NodeId in the target namespace that no node has yet, or null after 1000 taken candidates.
  ua::async::Task<NodeId> allocate_custom_role_id()
  {
    for (int attempts = 0; attempts < 1000; ++attempts)
    {
      const uint32_t candidate = mRequest.ctx->nextCustomRoleId.fetch_add(1, std::memory_order_acq_rel);
      NodeId id{mRequest.namespaceIndex, candidate};
      auto existing = co_await find_node(id);
      if (existing.is_bad())
        co_return id;
    }
    co_return NodeId{};
  }

  ua::async::Task<> run()
  {
    try
    {
      // BrowseName uniqueness within the RoleSet Object. Naming the collision aids the operator.
      if (co_await role_set_has_child_named())
      {
        answer(management_error(Status::BadInvalidArgument,
          ErrorDetail::build("AddRoleBrowseNameCollision",
            "AddRole roleName collides with an existing Role under the RoleSet Object",
            "server.tier1.authz.rbac.management.add_role.browse_name_collision")
            .context(ua::ContextKeys::nodeBrowseName, std::string{mRequest.roleName})));
        co_return;
      }

      // Well-known NodeId reuse (Part 18 4.2.2 L322-325 / SVR-SECADMIN-038): a well-known Role name under
      // the OPC UA NamespaceUri (ns 0) reuses the spec-defined NodeId rather than allocating a custom one.
      NodeId newRoleId;
      const auto wellKnownId = (mRequest.namespaceIndex == 0)
                                 ? well_known_role_node_id(static_cast<std::string_view>(mRequest.roleName))
                                 : std::nullopt;
      if (wellKnownId)
      {
        newRoleId = NodeId{0, *wellKnownId};
      }
      else
      {
        newRoleId = co_await allocate_custom_role_id();
        if (newRoleId.is_null())
        {
          answer(management_error(Status::BadOutOfRange,
            ErrorDetail::build("AddRoleAllocationFailed",
              "Could not allocate a new role NodeId",
              "server.tier1.authz.rbac.management.add_role.allocation_failed")
              .context(ua::ContextKeys::namespaceIndex, std::to_string(mRequest.namespaceIndex))));
          co_return;
        }
      }

      RoleConfiguration::RoleDefinition def;
      def.roleId = newRoleId;
      def.browseName = QualifiedName{mRequest.namespaceIndex, mRequest.roleName};
      // Part 18 4.2.2 L316-318 / SVR-SECADMIN-036: new Roles default to excluding all Applications and
      // Endpoints until explicitly configured.
      def.applicationsExclude = true;
      def.endpointsExclude = true;
      if (!mRequest.roleConfig->add_custom_role(std::move(def)))
      {
        answer(management_error(Status::BadOutOfRange,
          "server.tier1.authz.rbac.management.add_role.config_full",
          "RoleConfiguration is full (64 role bits already allocated)"));
        co_return;
      }
      mUncommittedRoleId = newRoleId;

      // Instantiate RoleType under RoleSet so its mandatory members, the two optional Exclude
      // Properties, and the six optional management Methods with the Applications / Endpoints
      // Properties they maintain are materialised with inherited attributes. Part 18 4.4.1 makes the
      // Methods Optional, their absence meaning the Server does not allow the change; Identities is
      // not writable (CurrentWrite FALSE), so a Role without AddIdentity could never be granted to
      // any Session. Each child copies its declaration's RolePermissions and AccessRestrictions,
      // so the Methods carry the RoleType baseline (SecurityAdmin alone may Call, encrypted channel).
      auto created = co_await instantiate(newRoleId);
      if (!created.is_good())
      {
        mRequest.roleConfig->remove_role(newRoleId);
        answer(CallResult{created.status_code(), created.shared_detail()});
        co_return;
      }
      auto subtree = std::move(created).value();

      auto newRole = co_await find_node(newRoleId);
      if (!newRole.is_good())
      {
        mRequest.roleConfig->remove_role(newRoleId);
        answer(CallResult{::ua::detail::lookup_failure(newRoleId, newRole.status_code(), "AddRole")});
        co_return;
      }
      auto roleType = co_await find_node(NodeId{ObjectTypeId::RoleType});
      if (roleType.is_good())
      {
        // Best-effort, as the setters were: the Role exists and is configured either way.
        if (auto permissions = roleType.value().get_role_permissions())
          (void)co_await write_attribute(
            newRole.value(), AttributeId::RolePermissions, attribute_wire::role_permissions(*permissions));
        if (auto restrictions = roleType.value().get_access_restrictions())
          (void)co_await write_attribute(newRole.value(),
            AttributeId::AccessRestrictions,
            attribute_wire::access_restrictions(*restrictions));
      }
      (void)co_await mirror_exclude(newRoleId, "ApplicationsExclude");
      (void)co_await mirror_exclude(newRoleId, "EndpointsExclude");
      for (const bool isApplications : {true, false})
      {
        auto exclude =
          co_await find_exclude(newRoleId, isApplications ? "ApplicationsExclude" : "EndpointsExclude");
        // Non-fatal: the *Exclude Properties are optional (Part 18 4.2.2); one that was not materialised
        // has nothing to serve.
        if (!exclude.is_good())
          continue;
        wire_exclude_property(exclude.value(), newRoleId, mRequest.ctx, isApplications);
      }
      const auto components = co_await find_components(newRole.value());
      auto owner = mRequest.addressSpace.lock();
      if (!owner)
      {
        // The subtree's address space is gone too, so destroying the subtree on this throw removes nothing.
        throw UaException{::ua::detail::address_space_gone("AddRole")};
      }
      install_added_role_management_handlers(
        *owner, newRoleId, static_cast<std::string_view>(mRequest.roleName), components, mRequest.ctx);
      subtree.release();
      mUncommittedRoleId = NodeId{};

      CallMethodResult result;
      result.output_arguments().resize(1);
      result.output_arguments()[0] = Variant{newRoleId};
      emit_audit(*mRequest.ctx,
        newRoleId,
        NodeId{0, utils::to_underlying(MethodId::Server_ServerCapabilities_RoleSet_AddRole)},
        "RoleSet/AddRole",
        mRequest.inputArguments,
        mRequest.callContext,
        StatusCode{});
      answer(CallResult{std::move(result)});
    }
    catch (const ua::async::Abandoned&)
    {
      roll_back_uncommitted_role();
      answer(CallResult{StatusCode{Status::BadOperationAbandoned}});
    }
    catch (...)
    {
      roll_back_uncommitted_role();
      answer(CallResult{ua::exception_to_status_code(std::current_exception())});
    }
  }

  /// A Role added to the configuration whose Node was not committed (the operation was abandoned or threw
  /// after add_custom_role) gives its role bit back, as the explicit failure paths above do.
  void roll_back_uncommitted_role()
  {
    if (!mUncommittedRoleId.is_null())
    {
      mRequest.roleConfig->remove_role(std::exchange(mUncommittedRoleId, NodeId{}));
    }
  }

  void fail_to_start(StatusCode status)
  {
    answer(CallResult{std::move(status)});
  }

  void answer(CallResult result)
  {
    if (auto complete = std::exchange(mRequest.complete, nullptr))
      complete(std::move(result));
  }

  Request mRequest;
  /// Set from add_custom_role until the Role's subtree is committed; see roll_back_uncommitted_role.
  NodeId mUncommittedRoleId;
};

void install_add_role_handler(AddressSpace& addressSpace, std::shared_ptr<RoleManagementContext> ctx)
{
  install_method_handler(addressSpace,
    NodeId{0, utils::to_underlying(MethodId::Server_ServerCapabilities_RoleSet_AddRole)},
    [ctx](const CallMethodRequest& req,
      shared_ptr<const MethodCallContext>
        callContext,
      std::function<void(CallResult)>
        complete)
    {
      auto roleConfig = ctx->roleConfig.lock();
      auto lockedAddressSpace = ctx->addressSpace.lock();
      if (!roleConfig || !lockedAddressSpace)
      {
        complete(CallResult{StatusCode{Status::BadInternalError}});
        return;
      }
      // The Method service checks administrator authorization and the import-authored
      // EncryptionRequired restriction before dispatch (Part 18 section 4.2.2).
      const auto& args = req.input_arguments();
      if (args.size() != 2)
      {
        complete(management_error(Status::BadInvalidArgument,
          ErrorDetail::build("InvalidMethodArguments",
            "AddRole requires 2 arguments (roleName, namespaceUri)",
            "server.tier1.authz.rbac.management.invalid_arguments")
            .context(ua::ContextKeys::sizeExpected, "2")
            .context(ua::ContextKeys::sizeActual, std::to_string(args.size()))));
        return;
      }
      const auto* roleName = args[0].try_as<String>();
      const auto* namespaceUri = args[1].try_as<String>();
      if (!roleName || !namespaceUri)
      {
        complete(management_error(Status::BadTypeMismatch,
          "server.tier1.authz.rbac.management.invalid_arguments",
          "AddRole arguments must be (String roleName, String namespaceUri)"));
        return;
      }
      if (roleName->empty())
      {
        complete(management_error(Status::BadInvalidArgument,
          "server.tier1.authz.rbac.management.add_role.empty_name",
          "AddRole roleName must not be empty"));
        return;
      }

      // Resolve the NamespaceUri (Part 18 4.2.2: AddRole(RoleName, NamespaceUri))
      // to a namespace index via the server's NamespaceArray. The OPC UA
      // NamespaceUri "http://opcfoundation.org/UA/" resolves to index 0, which
      // preserves the well-known-Role-reuse branch below. An unknown URI is a
      // client error: reject with BadInvalidArgument and a propagated detail.
      const std::string_view namespaceUriView = static_cast<std::string_view>(*namespaceUri);
      uint16_t resolvedIndex = 0;
      try
      {
        resolvedIndex = lockedAddressSpace->namespace_array().get_namespace_index(namespaceUriView);
      }
      catch (const UaException&)
      {
        complete(management_error(Status::BadInvalidArgument,
          ErrorDetail::build("AddRoleUnknownNamespace",
            "AddRole NamespaceUri is not a known namespace",
            "server.tier1.authz.rbac.management.add_role.unknown_namespace")
            .context(ua::ContextKeys::namespaceUri, std::string{namespaceUriView})));
        return;
      }

      AddRoleOperation::start(AddRoleOperation::Request{ctx,
                                std::move(roleConfig),
                                lockedAddressSpace->weak(),
                                *roleName,
                                resolvedIndex,
                                std::vector<Variant>{args.begin(), args.end()},
                                std::move(callContext),
                                std::move(complete)},
        *lockedAddressSpace);
    });
}

void install_remove_role_handler(AddressSpace& addressSpace, std::shared_ptr<RoleManagementContext> ctx)
{
  install_method_handler(addressSpace,
    NodeId{0, utils::to_underlying(MethodId::Server_ServerCapabilities_RoleSet_RemoveRole)},
    [ctx](const CallMethodRequest& req,
      shared_ptr<const MethodCallContext>
        callContext,
      std::function<void(CallResult)>
        complete)
    {
      auto roleConfig = ctx->roleConfig.lock();
      auto lockedAddressSpace = ctx->addressSpace.lock();
      if (!roleConfig || !lockedAddressSpace)
      {
        complete(CallResult{StatusCode{Status::BadInternalError}});
        return;
      }
      // The Method service checks administrator authorization and the import-authored
      // EncryptionRequired restriction before dispatch (Part 18 section 4.2.3).
      const auto& args = req.input_arguments();
      if (args.size() != 1)
      {
        complete(management_error(Status::BadInvalidArgument,
          ErrorDetail::build("InvalidMethodArguments",
            "RemoveRole requires 1 argument (roleId)",
            "server.tier1.authz.rbac.management.invalid_arguments")
            .context(ua::ContextKeys::sizeExpected, "1")
            .context(ua::ContextKeys::sizeActual, std::to_string(args.size()))));
        return;
      }
      const auto* roleId = args[0].try_as<NodeId>();
      if (!roleId)
      {
        complete(management_error(Status::BadTypeMismatch,
          "server.tier1.authz.rbac.management.invalid_arguments",
          "RemoveRole argument must be a NodeId"));
        return;
      }
      if (!roleConfig->get_role(*roleId))
      {
        complete(management_error(Status::BadNodeIdUnknown,
          ErrorDetail::build("RemoveRoleNotRegistered",
            "Role not registered",
            "server.tier1.authz.rbac.management.remove_role.not_registered")
            .context(ua::ContextKeys::nodeId, ua::to_string(*roleId))));
        return;
      }
      roleConfig->remove_role(*roleId);

      // Copy roleId out of the argument array and snapshot the inputs: `args`
      // (hence *roleId) may not outlive the asynchronous delete callback.
      const NodeId roleIdCopy = *roleId;
      std::vector<Variant> inputCopy{args.begin(), args.end()};

      // Sequence the audit + completion AFTER the node delete actually finishes,
      // so a client never observes Good while the role Object is still browsable
      // (the server address space deletes asynchronously). delete_node_async
      // invokes the callback exactly once, so `complete` runs exactly once; the
      // delete status is propagated to both the audit and the method result.
      lockedAddressSpace->delete_node_async(roleIdCopy,
        /*deleteForwardHierarchicallyReferencedNodes=*/true,
        ReferenceHalves::Both,
        [ctx, callContext, roleIdCopy, inputCopy = std::move(inputCopy), complete = std::move(complete)](
          VoidResult deleteResult) mutable
        {
          emit_audit(*ctx,
            roleIdCopy,
            NodeId{0, utils::to_underlying(MethodId::Server_ServerCapabilities_RoleSet_RemoveRole)},
            "RoleSet/RemoveRole",
            inputCopy,
            callContext,
            deleteResult.status_code());
          if (deleteResult.is_bad())
          {
            complete(CallResult{deleteResult.status_code()});
            return;
          }
          // Uncertain_ReferenceNotDeleted (a Reference to the Role left behind in another namespace) is the
          // method's result too: its canonical meaning is what happened (Part 4 5.11.2.4), and the Role is
          // removed. An Uncertain method status travels in the CallMethodResult, as the Call service expects.
          CallMethodResult removed;
          removed.status_code() = deleteResult.status_code();
          complete(CallResult{std::move(removed)});
        });
    });
}

}  // namespace

void attach_role_management_handlers(AddressSpace addressSpace, std::shared_ptr<RoleConfiguration> roleConfig,
  std::weak_ptr<EventBus> eventBus, ua::String serverApplicationUri,
  const std::optional<std::vector<WellKnownRole>>& selection)
{
  auto ctx = std::make_shared<RoleManagementContext>();
  ctx->roleConfig = roleConfig;
  ctx->eventBus = std::move(eventBus);
  ctx->addressSpace = addressSpace.weak();
  ctx->serverApplicationUri = std::move(serverApplicationUri);

  install_add_role_handler(addressSpace, ctx);
  install_remove_role_handler(addressSpace, ctx);

  for (const auto& spec : perRoleMethods)
  {
    if (selection.has_value() &&
        std::find(selection->begin(), selection->end(), spec.role) == selection->end())
    {
      continue;
    }
    install_role_management_handler(addressSpace,
      spec.kind,
      RoleMethodTarget{NodeId{0, utils::to_underlying(spec.roleObjectId)},
        NodeId{0, utils::to_underlying(spec.methodId)},
        std::string{spec.sourceName},
        std::nullopt},
      ctx);
  }

  // Write notifiers on the two writable *Exclude Variables, installed on all
  // eight well-known role Objects regardless of `selection` (the *Exclude
  // Variables exist independently of the per-role management Methods).
  // install_exclude_write_handler no-ops where the property is absent. No audit
  // emission on these (Part 18 4.5 lists only the 6 management methods +
  // AddRole/RemoveRole).
  for (const uint32_t roleObjectId : {15644u, 15656u, 15668u, 15680u, 16036u, 15692u, 15716u, 15704u})
  {
    install_exclude_write_handler(
      addressSpace, NodeId{0, roleObjectId}, "ApplicationsExclude", ctx, /*isApplications=*/true);
    install_exclude_write_handler(
      addressSpace, NodeId{0, roleObjectId}, "EndpointsExclude", ctx, /*isApplications=*/false);
  }
}

}  // namespace ua::server
