// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_access_control.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_namespace.h"
#include "ua_namespace_array.h"
#include "ua_namespace_metadata_publication.h"
#include "ua_namespace_route.h"
#include "ua_node.h"
#include "ua_role_permission_type.h"
#include "ua_role_permissions.h"
#include "ua_role_permission_utils.h"
#include "ua_server_session_info.h"
#include "ua_session_security.h"
#include "ua_status_routing.h"
#include "ua_timer.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include "ua_weak_address_space.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ua::server
{
namespace
{

StatusCode permission_denied(const NodeId& nodeId, AccessOperation operation)
{
  return StatusCode{Status::BadUserAccessDenied,
    ErrorDetail::build("RoleNotGranted",
      "No granted Role carries the permission bit required for this operation",
      "AccessControl")
      .context(ContextKeys::nodeId, to_string(nodeId))
      .context(ContextKeys::value, std::to_string(utils::to_underlying(operation)))};
}

StatusCode unknown_role_denied(const NodeId& nodeId, const NodeId& roleId, AccessOperation operation)
{
  return StatusCode{Status::BadUserAccessDenied,
    ErrorDetail::build("RoleUnknownToConfiguration",
      "The effective RolePermissions name a Role that is not registered in RoleConfiguration",
      "AccessControl")
      .context(ContextKeys::nodeId, to_string(nodeId))
      .context(ContextKeys::actual, roleId.as_definition())
      .context(ContextKeys::value, std::to_string(utils::to_underlying(operation)))};
}

StatusCode channel_refused(const NodeId& nodeId, MessageSecurityMode mode)
{
  return StatusCode{Status::BadSecurityModeInsufficient,
    ErrorDetail::build("AccessRestrictionsNotSatisfied",
      "The SecureChannel does not satisfy the Node's effective AccessRestrictions",
      "AccessControl")
      .context(ContextKeys::nodeId, to_string(nodeId))
      .context(ContextKeys::securityMode, to_string(mode))};
}

StatusCode node_deleted()
{
  return StatusCode{Status::BadNodeIdUnknown,
    ErrorDetail::build("NodeDeleted", "The node has been deleted", "AccessControl")};
}

StatusCode missing_namespace(uint16_t namespaceIndex, const NodeId* nodeId = nullptr)
{
  auto builder = ErrorDetail::build(
    "NamespaceUnavailable", "The Node's owning namespace is not registered", "AccessControl")
                   .context(ContextKeys::namespaceIndex, std::to_string(namespaceIndex));
  if (nodeId)
  {
    builder.context(ContextKeys::nodeId, to_string(*nodeId));
  }
  return StatusCode{Status::BadNodeIdUnknown, std::move(builder)};
}

StatusCode resolution_failure(uint16_t namespaceIndex, const NodeId& nodeId, StatusCode cause)
{
  return StatusCode{Status::BadUserAccessDenied,
    ErrorDetail::build("AuthorizationResolutionFailed",
      "The namespace could not resolve effective permissions for this subject",
      "AccessControl")
      .context(ContextKeys::namespaceIndex, std::to_string(namespaceIndex))
      .context(ContextKeys::nodeId, to_string(nodeId))
      .cause(std::move(cause))};
}

StatusCode resolution_timeout(uint16_t namespaceIndex, std::chrono::milliseconds timeout)
{
  return StatusCode{Status::BadUserAccessDenied,
    ErrorDetail::build("AuthorizationResolutionDeadlineExceeded",
      "The namespace did not complete effective-permission resolution before the authorization deadline",
      "AccessControl")
      .context(ContextKeys::namespaceIndex, std::to_string(namespaceIndex))
      .context(ContextKeys::limit, std::to_string(timeout.count()))
      .cause(StatusCode{Status::BadTimeout})};
}

void log_resolution_failure(const Logger& logger, uint16_t namespaceIndex, const NodeId& nodeId,
  const StatusCode& failure, std::string_view message)
{
  if (const auto& detail = failure.shared_detail())
  {
    logger.warning({{"namespace_index", uint64_t{namespaceIndex}},
                     {"node_id", to_string(nodeId)},
                     {"status", to_string(failure)},
                     {"detail", to_string(*detail)}},
      "{}",
      message);
    return;
  }
  logger.warning({{"namespace_index", uint64_t{namespaceIndex}},
                   {"node_id", to_string(nodeId)},
                   {"status", to_string(failure)}},
    "{}",
    message);
}

AccessControl::Verdict denied(StatusCode cause, bool channelRefused = false)
{
  return AccessControl::Verdict{.permitted = false,
    .channelRefused = channelRefused,
    .mask = PermissionType{},
    .cause = std::move(cause)};
}

AccessControl::Verdict from_mask(PermissionType mask, const NodeId& nodeId, AccessOperation operation,
  std::optional<NodeId> unknownRole = std::nullopt)
{
  bool permitted = mask.test(role_permission_utils::permission_bit_for_operation(operation));
  StatusCode cause{Status::Good};
  if (unknownRole)
  {
    permitted = false;
    cause = unknown_role_denied(nodeId, *unknownRole, operation);
  }
  else if (!permitted)
  {
    cause = permission_denied(nodeId, operation);
  }
  return AccessControl::Verdict{.subject = nodeId,
    .operation = operation,
    .permitted = permitted,
    .channelRefused = false,
    .mask = mask,
    .cause = std::move(cause)};
}

void associate_verdicts(
  std::span<const AccessControl::Item> items, std::vector<AccessControl::Verdict>& verdicts) noexcept
{
  const size_t count = std::min(items.size(), verdicts.size());
  for (size_t index = 0; index < count; ++index)
  {
    verdicts[index].operation = items[index].operation;
    if (!verdicts[index].subject.is_null() || items[index].node->deleted())
    {
      // A deleted Node has no NodeId to read; its verdict already says why it was refused.
      continue;
    }
    try
    {
      verdicts[index].subject = items[index].node.get_node_id();
    }
    catch (...)
    {
      verdicts[index] = denied(ua::exception_to_status_code(std::current_exception()));
      verdicts[index].operation = items[index].operation;
    }
  }
}

StatusCode projection_association_failure(const NodeId& expectedSubject, AttributeId attribute,
  AccessOperation expectedOperation, const AccessControl::Verdict& actual)
{
  return StatusCode{Status::BadInternalError,
    ErrorDetail::build("AttributeProjectionVerdictMismatch",
      "The completed access verdict is not associated with the Attribute being projected",
      "AccessControl")
      .context(ContextKeys::nodeId, expectedSubject.as_definition())
      .context(ContextKeys::nodeAttribute, to_string(attribute))
      .context(ContextKeys::expected, std::to_string(utils::to_underlying(expectedOperation)))
      .context(ContextKeys::actual, std::to_string(utils::to_underlying(actual.operation)))};
}

StatusCode projection_type_failure(const NodeId& nodeId, AttributeId attribute, std::string expectedType)
{
  return StatusCode{Status::BadTypeMismatch,
    ErrorDetail::build("AttributeProjectionTypeMismatch",
      "The user-independent Attribute value has the wrong type for projection",
      "AccessControl")
      .context(ContextKeys::nodeId, nodeId.as_definition())
      .context(ContextKeys::nodeAttribute, to_string(attribute))
      .context(ContextKeys::expected, std::move(expectedType))};
}

/// Finds a Role that this identity holds but the configuration never registered.
///
/// Only a *held* Role is a candidate. RolePermissions are additive, so an entry naming a Role the
/// caller does not hold can never widen the caller's mask and so can never be the reason a request is
/// refused; vetoing on it would deny every caller a node whose permissions mention a Role this server
/// does not implement - the shape a NodeSet import produces, and one that a single RolePermissions
/// Write could otherwise use to make a Node permanently unreadable, its own RolePermissions Attribute
/// included. SVR-AUTHZ-025 asks that a denial caused by an unregistered Role be reported distinctly,
/// not that an unregistered Role cause one. A held Role remains a veto: access must never rest on the
/// authority of a Role the server cannot vouch for.
std::optional<NodeId> first_unknown_role(
  const AccessIdentity& identity, const std::vector<RolePermissionType>& permissions)
{
  const auto registeredRoles = identity.registered_roles();
  if (!registeredRoles)
  {
    return std::nullopt;
  }
  const auto grantedRoles = identity.granted_roles();
  for (const auto& permission : permissions)
  {
    if (std::find(grantedRoles.begin(), grantedRoles.end(), permission.role_id()) == grantedRoles.end())
    {
      continue;
    }
    if (std::find(registeredRoles->begin(), registeredRoles->end(), permission.role_id()) ==
        registeredRoles->end())
    {
      return permission.role_id();
    }
  }
  return std::nullopt;
}

/// @overload Takes the node's effective permissions already resolved.
///
/// Resolving them reads an Attribute off the node and rebuilds a vector, and the mask evaluation
/// beside this one needs the same answer. Resolving once and asking both questions of it turns two
/// reads per item into one.
std::optional<NodeId> first_unknown_role(
  const std::optional<std::vector<RolePermissionType>>& resolved, const AccessIdentity& identity)
{
  if (!resolved)
  {
    return std::nullopt;
  }
  return first_unknown_role(identity, *resolved);
}

/// Everything the owning namespace contributes to a decision, fetched when the namespace changes
/// rather than once per item.
///
/// The namespace instance, its default RolePermissions and its default AccessRestrictions are all
/// invariant across a namespace, and all three were fetched per node - an array lookup, a vector
/// copy and two virtual calls each. Items arrive grouped in practice, since a Read names nodes in
/// one namespace far more often than it interleaves several, so a one-entry cache turns per-item
/// work into per-namespace work, and degrades to the old behaviour rather than to something worse
/// when they do interleave.
class NamespaceScope
{
public:
  struct Entry
  {
    std::shared_ptr<Namespace> instance;
    std::optional<std::vector<RolePermissionType>> roleDefaults;
    std::optional<AccessRestrictionType> restrictionDefaults;
  };

  const Entry& for_namespace(uint16_t index, const AddressSpace& addressSpace)
  {
    if (mIndex && *mIndex == index)
    {
      return mEntry;
    }
    mEntry = Entry{};
    mEntry.instance = addressSpace.namespace_array().get_namespace(index);
    if (mEntry.instance)
    {
      mEntry.roleDefaults = mEntry.instance->default_role_permissions();
      mEntry.restrictionDefaults = mEntry.instance->default_access_restrictions();
    }
    mIndex = index;
    return mEntry;
  }

private:
  std::optional<uint16_t> mIndex;
  Entry mEntry;
};

StatusCode exception_status() noexcept
{
  return ua::exception_to_status_code(std::current_exception());
}

// A Node's description leaves out an Attribute the Node could not read or decode, as it leaves out one the
// Node does not have. For the two Attributes a decision reads, an absent one is read from the Node, so that a
// read that fails throws and denies the item instead of letting the namespace's defaults govern the Node.
NodeDescription with_security_attributes_confirmed(NodeDescription description, const NodeAccessor& node)
{
  if (!description.access_restrictions())
  {
    description = description.with_access_restrictions(node.get_access_restrictions());
  }
  if (description.role_permissions() == nullptr)
  {
    description = description.with_role_permissions(node.get_role_permissions());
  }
  return description;
}

bool gate_passes(const std::optional<AccessRestrictionType>& namespaceDefault, const NodeDescription& node,
  AccessOperation operation, const EndpointSecurityContext& channel)
{
  const auto restrictions = role_permissions::resolve_access_restrictions(node, namespaceDefault);
  return role_permission_utils::access_restrictions_satisfied(
    restrictions, channel.messageSecurityMode, operation);
}

Variant encode_role_permissions(const std::vector<RolePermissionType>& permissions)
{
  Array<RefStructure<Structure>> encoded;
  encoded.payload().reserve(permissions.size());
  for (const auto& permission : permissions)
  {
    RefStructure<Structure> entry;
    entry = std::make_unique<RolePermissionType>(permission);
    encoded.payload().push_back(std::move(entry));
  }
  return Variant{std::move(encoded)};
}

// What an item is denied when its namespace's answer needs the namespace again and the namespace is gone:
// `Bad_Shutdown` (`AddressSpaceGone`) when the address space is gone too, `NamespaceReleased` otherwise.
StatusCode namespace_owner_lost(const WeakAddressSpace& addressSpace)
{
  if (addressSpace.lock())
  {
    return ua::detail::namespace_released();
  }
  return ua::detail::address_space_gone("AccessControl");
}

struct PendingNamespace
{
  enum class State
  {
    Pending,
    Processing,
    Complete
  };

  uint16_t index{};
  // Weak: the completion given to the namespace reaches this group, and must not keep the namespace alive.
  std::weak_ptr<Namespace> instance;
  std::vector<size_t> itemIndexes;
  std::vector<size_t> itemSubjectIndexes;
  std::vector<NodeId> itemNodeIds;
  // The Attributes each item was decided with, so that the namespace's answer is not followed by a second
  // read.
  std::vector<NodeDescription> itemDescriptions;
  std::vector<NodeId> nodeIds;
  State state{State::Pending};
};

// Reached from the completion each namespace is given, so it holds the address space and the namespaces
// weakly.
struct AuthorizationState final : std::enable_shared_from_this<AuthorizationState>
{
  AuthorizationState(const AddressSpace& addressSpaceValue, Logger loggerValue,
    std::chrono::milliseconds timeoutValue, RequestInfo requestValue,
    std::shared_ptr<const AccessIdentity> identityValue, const EndpointSecurityContext& channelValue,
    std::vector<AccessControl::Item> itemsValue, std::vector<AccessControl::Verdict> verdictsValue,
    std::vector<std::shared_ptr<PendingNamespace>> groupsValue, AccessControl::AuthorizeCallback doneValue)
    : addressSpace(addressSpaceValue.weak()), executor(addressSpaceValue.executor()),
      logger(std::move(loggerValue)), timeout(timeoutValue), request(std::move(requestValue)),
      identity(std::move(identityValue)), channel(channelValue), items(std::move(itemsValue)),
      verdicts(std::move(verdictsValue)), groups(std::move(groupsValue)), done(std::move(doneValue))
  {}

  WeakAddressSpace addressSpace;
  boost::asio::any_io_executor executor;
  Logger logger;
  std::chrono::milliseconds timeout;
  RequestInfo request;
  std::shared_ptr<const AccessIdentity> identity;
  EndpointSecurityContext channel;
  std::vector<AccessControl::Item> items;
  std::vector<AccessControl::Verdict> verdicts;
  std::vector<std::shared_ptr<PendingNamespace>> groups;
  AccessControl::AuthorizeCallback done;
  std::mutex mutex;
  size_t remaining{};
  bool finished{false};
  Timer deadline;

  // @p namespaces holds each group's namespace, in group order, for the calls made here.
  void start(std::span<const std::shared_ptr<Namespace>> namespaces)
  {
    remaining = groups.size();
    auto self = shared_from_this();
    deadline = Timer::schedule_after(executor,
      timeout,
      [self](boost::system::error_code error)
      {
        if (!error)
        {
          self->on_timeout();
        }
      });

    for (size_t groupIndex = 0; groupIndex < groups.size(); ++groupIndex)
    {
      const auto& group = groups[groupIndex];
      {
        const std::lock_guard lock(mutex);
        if (finished)
        {
          break;
        }
      }
      try
      {
        namespaces[groupIndex]->effective_permissions_async(request,
          identity,
          group->nodeIds,
          [self, group](EffectivePermissionsResult result) mutable
          { self->on_resolution(group, std::move(result)); });
      }
      catch (...)
      {
        EffectivePermissionsResult result;
        result.batchStatus = VoidResult{exception_status()};
        on_resolution(group, std::move(result));
      }
    }
  }

  void on_resolution(const std::shared_ptr<PendingNamespace>& group, EffectivePermissionsResult result)
  {
    {
      const std::lock_guard lock(mutex);
      if (finished || group->state != PendingNamespace::State::Pending)
      {
        return;
      }
      group->state = PendingNamespace::State::Processing;
    }

    std::vector<std::pair<size_t, AccessControl::Verdict>> resolved;
    resolved.reserve(group->itemIndexes.size());
    if (!result.batchStatus.is_good())
    {
      // An Uncertain batch is every item's code, and the SDK does not authorize on it.
      const auto answer = result.batchStatus.status_code();
      for (size_t offset = 0; offset < group->itemIndexes.size(); ++offset)
      {
        const size_t itemIndex = group->itemIndexes[offset];
        const NodeId& nodeId = group->itemNodeIds[offset];
        const auto failure =
          server::detail::not_acted_on(server::detail::answerUncertain, answer, "AccessControl", nodeId);
        log_resolution_failure(logger,
          group->index,
          nodeId,
          failure,
          "Namespace effective-permission resolution failed; denying its item");
        resolved.emplace_back(itemIndex, denied(resolution_failure(group->index, nodeId, failure)));
      }
    }
    else if (result.items.size() != group->nodeIds.size())
    {
      const StatusCode shapeFailure{Status::BadUnexpectedError,
        ErrorDetail::build("AuthorizationResultCardinalityMismatch",
          "The namespace returned a different number of permission results than requested",
          "AccessControl")
          .context(ContextKeys::namespaceIndex, std::to_string(group->index))
          .context(ContextKeys::expected, std::to_string(group->nodeIds.size()))
          .context(ContextKeys::actual, std::to_string(result.items.size()))};
      for (size_t offset = 0; offset < group->itemIndexes.size(); ++offset)
      {
        log_resolution_failure(logger,
          group->index,
          group->itemNodeIds[offset],
          shapeFailure,
          "Namespace effective-permission resolution returned an invalid result; denying its item");
        resolved.emplace_back(group->itemIndexes[offset],
          denied(resolution_failure(group->index, group->itemNodeIds[offset], shapeFailure)));
      }
    }
    else
    {
      // A granted answer reads the namespace's defaults; it is locked for that, once, when first needed.
      std::shared_ptr<Namespace> nameSpace;
      std::optional<StatusCode> ownerLost;
      for (size_t offset = 0; offset < group->itemIndexes.size(); ++offset)
      {
        const size_t itemIndex = group->itemIndexes[offset];
        const auto& item = items[itemIndex];
        const NodeId& nodeId = group->itemNodeIds[offset];
        const auto& permissionResult = result.items[group->itemSubjectIndexes[offset]];
        try
        {
          if (item.node->deleted())
          {
            // Deleted while its namespace was resolving: refused as a Node deleted before the question.
            resolved.emplace_back(itemIndex, denied(node_deleted()));
          }
          else if (!permissionResult.is_good())
          {
            // An Uncertain answer, with or without permissions, grants nothing: the SDK does not authorize on
            // an answer the namespace is uncertain of.
            const auto failure = server::detail::not_acted_on(
              server::detail::answerUncertain, permissionResult.status_code(), "AccessControl", nodeId);
            log_resolution_failure(logger,
              group->index,
              nodeId,
              failure,
              "Namespace effective-permission resolution failed for an item; denying it");
            resolved.emplace_back(itemIndex, denied(resolution_failure(group->index, nodeId, failure)));
          }
          else
          {
            if (!nameSpace && !ownerLost)
            {
              nameSpace = group->instance.lock();
              if (!nameSpace)
              {
                ownerLost = namespace_owner_lost(addressSpace);
              }
            }
            if (ownerLost)
            {
              resolved.emplace_back(itemIndex, denied(*ownerLost));
            }
            else
            {
              resolved.emplace_back(itemIndex,
                from_mask(permissionResult.value(),
                  nodeId,
                  item.operation,
                  first_unknown_role(
                    role_permissions::resolve_role_permissions(
                      group->itemDescriptions[offset], nameSpace->default_role_permissions()),
                    *identity)));
            }
          }
        }
        catch (...)
        {
          resolved.emplace_back(itemIndex, denied(exception_status()));
        }
      }
    }

    AccessControl::AuthorizeCallback completion;
    std::vector<AccessControl::Verdict> completedVerdicts;
    {
      const std::lock_guard lock(mutex);
      if (finished || group->state != PendingNamespace::State::Processing)
      {
        return;
      }
      for (auto& [itemIndex, verdict] : resolved)
      {
        verdicts[itemIndex] = std::move(verdict);
      }
      group->state = PendingNamespace::State::Complete;
      --remaining;
      if (remaining == 0)
      {
        finished = true;
        deadline.cancel();
        completion = std::move(done);
        completedVerdicts = std::move(verdicts);
      }
    }
    associate_verdicts(items, completedVerdicts);
    if (completion)
    {
      completion(std::move(completedVerdicts));
    }
  }

  void on_timeout()
  {
    AccessControl::AuthorizeCallback completion;
    std::vector<AccessControl::Verdict> completedVerdicts;
    std::vector<std::pair<uint16_t, NodeId>> timedOutItems;
    {
      const std::lock_guard lock(mutex);
      if (finished)
      {
        return;
      }
      for (const auto& group : groups)
      {
        if (group->state == PendingNamespace::State::Complete)
        {
          continue;
        }
        const auto timeoutStatus = resolution_timeout(group->index, timeout);
        for (size_t offset = 0; offset < group->itemIndexes.size(); ++offset)
        {
          const size_t itemIndex = group->itemIndexes[offset];
          verdicts[itemIndex] = denied(timeoutStatus);
          timedOutItems.emplace_back(group->index, group->itemNodeIds[offset]);
        }
        group->state = PendingNamespace::State::Complete;
      }
      remaining = 0;
      finished = true;
      completion = std::move(done);
      completedVerdicts = std::move(verdicts);
    }
    deadline.cancel();
    associate_verdicts(items, completedVerdicts);
    for (const auto& [namespaceIndex, nodeId] : timedOutItems)
    {
      log_resolution_failure(logger,
        namespaceIndex,
        nodeId,
        resolution_timeout(namespaceIndex, timeout),
        "Namespace effective-permission resolution exceeded the authorization deadline; denying its item");
    }
    if (completion)
    {
      completion(std::move(completedVerdicts));
    }
  }
};

// Reached from the completion the namespace is given, so it holds the address space and the namespace weakly.
struct NamespaceAuthorizationState final : std::enable_shared_from_this<NamespaceAuthorizationState>
{
  NamespaceAuthorizationState(const AddressSpace& addressSpaceValue, Logger loggerValue,
    std::chrono::milliseconds timeoutValue, RequestInfo requestValue,
    std::shared_ptr<const AccessIdentity> identityValue, const std::shared_ptr<Namespace>& namespaceValue,
    uint16_t namespaceIndexValue, AccessControl::AuthorizeNamespaceCallback doneValue)
    : addressSpace(addressSpaceValue.weak()), executor(addressSpaceValue.executor()),
      logger(std::move(loggerValue)), timeout(timeoutValue), request(std::move(requestValue)),
      identity(std::move(identityValue)), instance(namespaceValue), namespaceIndex(namespaceIndexValue),
      done(std::move(doneValue))
  {}

  WeakAddressSpace addressSpace;
  boost::asio::any_io_executor executor;
  Logger logger;
  std::chrono::milliseconds timeout;
  RequestInfo request;
  std::shared_ptr<const AccessIdentity> identity;
  std::weak_ptr<Namespace> instance;
  uint16_t namespaceIndex{};
  AccessControl::AuthorizeNamespaceCallback done;
  std::mutex mutex;
  bool finished{false};
  Timer deadline;

  NodeId diagnostic_subject() const
  {
    return NodeId{namespaceIndex, uint32_t{0}};
  }

  // @p nameSpace is the namespace the state was built for, held by the caller for the call made here.
  void start(Namespace& nameSpace)
  {
    auto self = shared_from_this();
    deadline = Timer::schedule_after(executor,
      timeout,
      [self](boost::system::error_code error)
      {
        if (!error)
        {
          self->on_timeout();
        }
      });
    try
    {
      nameSpace.effective_permissions_async(request,
        identity,
        std::nullopt,
        [self](EffectivePermissionsResult result) mutable { self->on_resolution(std::move(result)); });
    }
    catch (...)
    {
      EffectivePermissionsResult result;
      result.batchStatus = VoidResult{exception_status()};
      on_resolution(std::move(result));
    }
  }

  void on_resolution(EffectivePermissionsResult result)
  {
    AccessControl::Verdict verdict;
    const NodeId subject = diagnostic_subject();
    if (!result.batchStatus.is_good())
    {
      // An Uncertain answer, the batch's or the item's, grants nothing: the SDK does not authorize on it.
      const auto failure = server::detail::not_acted_on(
        server::detail::answerUncertain, result.batchStatus.status_code(), "AccessControl", subject);
      log_resolution_failure(logger,
        namespaceIndex,
        subject,
        failure,
        "Namespace effective-permission resolution failed; denying the namespace operation");
      verdict = denied(resolution_failure(namespaceIndex, subject, failure));
    }
    else if (result.items.size() != 1)
    {
      const StatusCode shapeFailure{Status::BadUnexpectedError,
        ErrorDetail::build("AuthorizationResultCardinalityMismatch",
          "A namespace-subject permission call shall return exactly one result",
          "AccessControl")
          .context(ContextKeys::namespaceIndex, std::to_string(namespaceIndex))
          .context(ContextKeys::expected, "1")
          .context(ContextKeys::actual, std::to_string(result.items.size()))};
      log_resolution_failure(logger,
        namespaceIndex,
        subject,
        shapeFailure,
        "Namespace effective-permission resolution returned an invalid result; denying the namespace "
        "operation");
      verdict = denied(resolution_failure(namespaceIndex, subject, shapeFailure));
    }
    else if (!result.items.front().is_good())
    {
      const auto failure = server::detail::not_acted_on(
        server::detail::answerUncertain, result.items.front().status_code(), "AccessControl", subject);
      log_resolution_failure(logger,
        namespaceIndex,
        subject,
        failure,
        "Namespace effective-permission resolution failed; denying the namespace operation");
      verdict = denied(resolution_failure(namespaceIndex, subject, failure));
    }
    else if (const auto nameSpace = instance.lock())
    {
      std::optional<NodeId> unknownRole;
      const auto defaults = nameSpace->default_role_permissions();
      if (defaults)
      {
        unknownRole = first_unknown_role(*identity, *defaults);
      }
      verdict =
        from_mask(result.items.front().value(), subject, AccessOperation::AddNodes, std::move(unknownRole));
    }
    else
    {
      // A granted answer reads the namespace's defaults, which a released namespace no longer answers.
      verdict = denied(namespace_owner_lost(addressSpace));
    }

    AccessControl::AuthorizeNamespaceCallback completion;
    {
      const std::lock_guard lock(mutex);
      if (finished)
      {
        return;
      }
      finished = true;
      completion = std::move(done);
    }
    deadline.cancel();
    completion(std::move(verdict));
  }

  void on_timeout()
  {
    AccessControl::AuthorizeNamespaceCallback completion;
    {
      const std::lock_guard lock(mutex);
      if (finished)
      {
        return;
      }
      finished = true;
      completion = std::move(done);
    }
    const auto failure = resolution_timeout(namespaceIndex, timeout);
    log_resolution_failure(logger,
      namespaceIndex,
      diagnostic_subject(),
      failure,
      "Namespace effective-permission resolution exceeded the authorization deadline; denying it");
    completion(denied(std::move(failure)));
  }
};

}  // namespace

AccessControl::AccessControl(
  AddressSpace addressSpace, std::chrono::milliseconds authorizationTimeout, Logger logger)
  : mAddressSpace(addressSpace.weak()), mAuthorizationTimeout(authorizationTimeout),
    mLogger(std::move(logger).with_category("access_control"))
{
  if (mAuthorizationTimeout <= std::chrono::milliseconds::zero())
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidAuthorizationTimeout", "Authorization timeout must be greater than zero", "AccessControl")
        .context(ContextKeys::actual, std::to_string(mAuthorizationTimeout.count()))};
  }
}

void AccessControl::authorize_async(const RequestInfo& request,
  std::shared_ptr<const AccessIdentity> identity, std::span<const Item> items,
  const EndpointSecurityContext& channel, AuthorizeCallback done) const
{
  std::vector<Verdict> verdicts(items.size());
  if (!done)
  {
    return;
  }
  if (!identity)
  {
    const StatusCode cause{Status::BadUserAccessDenied,
      ErrorDetail::build("AccessIdentityMissing",
        "No committed access identity is available for this operation",
        "AccessControl")};
    std::fill(verdicts.begin(), verdicts.end(), denied(cause));
    associate_verdicts(items, verdicts);
    done(std::move(verdicts));
    return;
  }
  // Held only for this call: the state below, which the namespaces' completions reach, holds it weakly.
  const auto addressSpace = mAddressSpace.lock();
  if (!addressSpace)
  {
    std::fill(verdicts.begin(), verdicts.end(), denied(ua::detail::address_space_gone("AccessControl")));
    associate_verdicts(items, verdicts);
    done(std::move(verdicts));
    return;
  }

  std::vector<Item> ownedItems(items.begin(), items.end());
  NamespaceScope namespaceScope;
  std::unordered_map<uint16_t, std::shared_ptr<PendingNamespace>> byNamespace;
  std::vector<std::shared_ptr<PendingNamespace>> groups;
  // Each group's namespace, in group order, held here for the calls the state makes when it starts.
  std::vector<std::shared_ptr<Namespace>> groupNamespaces;

  for (size_t itemIndex = 0; itemIndex < ownedItems.size(); ++itemIndex)
  {
    const auto& item = ownedItems[itemIndex];
    try
    {
      const Node& node = *item.node;
      // A deleted Node is refused here: its namespace is not asked about a Node it no longer holds.
      if (node.deleted())
      {
        verdicts[itemIndex] = denied(node_deleted());
        continue;
      }
      const NodeId nodeId = item.node.get_node_id();
      const uint16_t namespaceIndex = nodeId.namespace_index();
      const auto& scope = namespaceScope.for_namespace(namespaceIndex, *addressSpace);
      auto owningNamespace = scope.instance;
      if (!owningNamespace)
      {
        verdicts[itemIndex] = denied(missing_namespace(namespaceIndex, &nodeId));
        continue;
      }
      // The Attributes the decision reads, taken once for the item.
      NodeDescription nodeDescription = with_security_attributes_confirmed(
        item.description ? *item.description : node.attributes(), item.node);
      if (!gate_passes(scope.restrictionDefaults, nodeDescription, item.operation, channel))
      {
        verdicts[itemIndex] = denied(channel_refused(nodeId, channel.messageSecurityMode), true);
        continue;
      }
      auto mask = owningNamespace->effective_permissions(*identity, &node);
      if (mask)
      {
        // An unknown role DENIES, so this is evaluated for every item and not only for the ones
        // already refused - it can turn a granted mask into a refusal.
        verdicts[itemIndex] = from_mask(*mask,
          nodeId,
          item.operation,
          first_unknown_role(
            role_permissions::resolve_role_permissions(nodeDescription, scope.roleDefaults), *identity));
        continue;
      }
      auto groupIt = byNamespace.find(namespaceIndex);
      if (groupIt == byNamespace.end())
      {
        auto group = std::make_shared<PendingNamespace>();
        group->index = namespaceIndex;
        group->instance = owningNamespace;
        // A new group enters both lists and the map, or none of them, so that an allocation failure for one
        // item cannot leave a group paired with another group's namespace.
        groups.push_back(group);
        try
        {
          groupNamespaces.push_back(owningNamespace);
        }
        catch (...)
        {
          groups.pop_back();
          throw;
        }
        try
        {
          groupIt = byNamespace.emplace(namespaceIndex, std::move(group)).first;
        }
        catch (...)
        {
          groups.pop_back();
          groupNamespaces.pop_back();
          throw;
        }
      }
      auto& group = *groupIt->second;
      group.itemIndexes.push_back(itemIndex);
      group.itemNodeIds.push_back(nodeId);
      group.itemDescriptions.push_back(std::move(nodeDescription));
      const auto subject = std::find(group.nodeIds.begin(), group.nodeIds.end(), nodeId);
      if (subject == group.nodeIds.end())
      {
        group.nodeIds.push_back(nodeId);
        group.itemSubjectIndexes.push_back(group.nodeIds.size() - 1);
      }
      else
      {
        group.itemSubjectIndexes.push_back(
          static_cast<size_t>(std::distance(group.nodeIds.begin(), subject)));
      }
    }
    catch (...)
    {
      verdicts[itemIndex] = denied(exception_status());
    }
  }

  if (groups.empty())
  {
    associate_verdicts(ownedItems, verdicts);
    done(std::move(verdicts));
    return;
  }

  auto state = std::make_shared<AuthorizationState>(*addressSpace,
    mLogger,
    mAuthorizationTimeout,
    request,
    std::move(identity),
    channel,
    std::move(ownedItems),
    std::move(verdicts),
    std::move(groups),
    std::move(done));
  state->start(groupNamespaces);
}

void AccessControl::authorize_namespace_async(const RequestInfo& request,
  std::shared_ptr<const AccessIdentity> identity, uint16_t namespaceIndex,
  const EndpointSecurityContext& channel, AuthorizeNamespaceCallback done) const
{
  if (!done)
  {
    return;
  }
  if (!identity)
  {
    done(denied(StatusCode{Status::BadUserAccessDenied,
      ErrorDetail::build(
        "AccessIdentityMissing", "No committed access identity is available", "AccessControl")}));
    return;
  }
  const auto addressSpace = mAddressSpace.lock();
  if (!addressSpace)
  {
    done(denied(ua::detail::address_space_gone("AccessControl")));
    return;
  }
  auto owningNamespace = addressSpace->namespace_array().get_namespace(namespaceIndex);
  if (!owningNamespace)
  {
    done(denied(missing_namespace(namespaceIndex)));
    return;
  }
  const auto failureDone = done;
  try
  {
    if (!role_permission_utils::access_restrictions_satisfied(owningNamespace->default_access_restrictions(),
          channel.messageSecurityMode,
          AccessOperation::AddNodes))
    {
      const NodeId namespaceSubject{namespaceIndex, uint32_t{0}};
      done(denied(channel_refused(namespaceSubject, channel.messageSecurityMode), true));
      return;
    }
    const NodeId namespaceSubject{namespaceIndex, uint32_t{0}};
    const auto mask = owningNamespace->effective_permissions(*identity, static_cast<const Node*>(nullptr));
    if (mask)
    {
      std::optional<NodeId> unknownRole;
      const auto defaults = owningNamespace->default_role_permissions();
      if (defaults)
      {
        unknownRole = first_unknown_role(*identity, *defaults);
      }
      done(from_mask(*mask, namespaceSubject, AccessOperation::AddNodes, std::move(unknownRole)));
      return;
    }

    auto state = std::make_shared<NamespaceAuthorizationState>(*addressSpace,
      mLogger,
      mAuthorizationTimeout,
      request,
      std::move(identity),
      owningNamespace,
      namespaceIndex,
      std::move(done));
    state->start(*owningNamespace);
  }
  catch (...)
  {
    failureDone(denied(exception_status()));
  }
}

DataValue AccessControl::make_client_attribute_value(const AccessIdentity& identity, const NodeAccessor& node,
  AttributeId attribute, DataValue userIndependentValue, const Verdict& readAccess,
  const EndpointSecurityContext& channel) const
{
  NodeId nodeId;
  try
  {
    nodeId = node.get_node_id();
  }
  catch (...)
  {
    return DataValue{exception_status()};
  }
  return make_client_attribute_value(
    identity, nodeId, node, attribute, std::move(userIndependentValue), readAccess, channel);
}

DataValue AccessControl::make_client_attribute_value(const AccessIdentity& identity, const NodeId& nodeId,
  const NodeAccessor& node, AttributeId attribute, DataValue userIndependentValue, const Verdict& readAccess,
  const EndpointSecurityContext& channel) const
{
  try
  {
    // The association is checked against the NodeId the caller names, not one read from the Node: a
    // deleted Node no longer answers its NodeId, and a value read before the deletion is still projected.
    const AccessOperation expectedOperation = attribute_read_operation(attribute);
    if (readAccess.subject != nodeId || readAccess.operation != expectedOperation)
    {
      return DataValue{projection_association_failure(nodeId, attribute, expectedOperation, readAccess)};
    }
    if (!readAccess.permitted)
    {
      if (readAccess.cause.is_bad())
      {
        return DataValue{readAccess.cause};
      }
      return DataValue{StatusCode{Status::BadInternalError,
        ErrorDetail::build("AttributeProjectionDeniedWithoutCause",
          "A denied Attribute-read verdict did not retain a bad cause",
          "AccessControl")
          .context(ContextKeys::nodeId, nodeId.as_definition())
          .context(ContextKeys::nodeAttribute, to_string(attribute))}};
    }
    if (!readAccess.mask.test(role_permission_utils::permission_bit_for_operation(expectedOperation)))
    {
      return DataValue{projection_association_failure(nodeId, attribute, expectedOperation, readAccess)};
    }
    const auto& valueStatus = userIndependentValue.status();
    if (valueStatus && valueStatus.value().is_bad())
    {
      return userIndependentValue;
    }

    // Only five Attributes read the owning namespace. Resolving it up front charged every projected
    // Value - the notification path - for a lookup it never reads, so it is resolved on demand.
    shared_ptr<Namespace> owningNamespace;
    // What a projection that needs the owning namespace answers without it: the address space gone, or no
    // namespace at the index.
    StatusCode withoutNamespace;
    const auto resolveOwningNamespace =
      [this, &owningNamespace, &withoutNamespace, &nodeId]() -> const shared_ptr<Namespace>&
    {
      if (!owningNamespace)
      {
        if (const auto addressSpace = mAddressSpace.lock())
        {
          owningNamespace = addressSpace->namespace_array().get_namespace(nodeId.namespace_index());
          if (!owningNamespace)
          {
            withoutNamespace = missing_namespace(nodeId.namespace_index(), &nodeId);
          }
        }
        else
        {
          withoutNamespace = ua::detail::address_space_gone("AccessControl");
        }
      }
      return owningNamespace;
    };

    PermissionType capabilityMask = readAccess.mask;
    if (attribute == AttributeId::UserAccessLevel || attribute == AttributeId::UserWriteMask ||
        attribute == AttributeId::UserExecutable)
    {
      if (!resolveOwningNamespace())
      {
        return DataValue{withoutNamespace};
      }
      const auto restrictions =
        role_permissions::resolve_access_restrictions(node, owningNamespace->default_access_restrictions());
      if (!role_permission_utils::access_restrictions_satisfied(restrictions, channel.messageSecurityMode))
      {
        capabilityMask = PermissionType{};
      }
    }

    if (attribute == AttributeId::UserAccessLevel)
    {
      const auto* stored = userIndependentValue.value().try_as<uint8_t>();
      if (!stored)
      {
        return DataValue{projection_type_failure(nodeId, attribute, "Byte")};
      }
      userIndependentValue.value() =
        Variant{numeric_cast<uint8_t>(*stored & role_permissions::project_access_level(capabilityMask))};
      return userIndependentValue;
    }

    if (attribute == AttributeId::UserWriteMask)
    {
      const auto* stored = userIndependentValue.value().try_as<uint32_t>();
      if (!stored)
      {
        return DataValue{projection_type_failure(nodeId, attribute, "UInt32")};
      }
      userIndependentValue.value() = Variant{*stored & role_permissions::project_write_mask(capabilityMask)};
      return userIndependentValue;
    }

    if (attribute == AttributeId::UserExecutable)
    {
      const auto* stored = userIndependentValue.value().try_as<bool>();
      if (!stored)
      {
        return DataValue{projection_type_failure(nodeId, attribute, "Boolean")};
      }
      userIndependentValue.value() = Variant{*stored && capabilityMask.test(PermissionType::Bit::Call)};
      return userIndependentValue;
    }

    if (attribute == AttributeId::RolePermissions)
    {
      if (!resolveOwningNamespace())
      {
        return DataValue{withoutNamespace};
      }
      auto configured = node.get_role_permissions();
      if (!configured && !owningNamespace->default_role_permissions())
      {
        return DataValue{StatusCode{Status::BadAttributeIdInvalid}};
      }
      if (!configured)
      {
        configured.emplace();
      }
      userIndependentValue.value() = encode_role_permissions(*configured);
      userIndependentValue.status() = Status::Good;
      return userIndependentValue;
    }

    if (attribute == AttributeId::UserRolePermissions)
    {
      if (!resolveOwningNamespace())
      {
        return DataValue{withoutNamespace};
      }
      const auto namespaceDefaults = owningNamespace->default_role_permissions();
      if (!namespaceDefaults)
      {
        return DataValue{StatusCode{Status::BadAttributeIdInvalid}};
      }
      const auto permissions = role_permissions::resolve_role_permissions(node, namespaceDefaults);
      const auto filtered =
        permissions ? role_permissions::filter_role_permissions(*permissions, identity.granted_roles())
                    : std::vector<RolePermissionType>{};
      userIndependentValue.value() = encode_role_permissions(filtered);
      userIndependentValue.status() = Status::Good;
      return userIndependentValue;
    }

    // No Value branch. A Value that depends on the caller is produced by the node that serves it,
    // from the identity passed to the read - so by the time a value reaches this projection there is
    // nothing left to substitute, and nothing here needs to know which nodes are special. That is
    // what removes the per-value lookup, and with it the publication snapshot it used to consult.
    return userIndependentValue;
  }
  catch (...)
  {
    return DataValue{exception_status()};
  }
}

AttributeId AccessControl::user_independent_attribute(AttributeId clientAttribute) noexcept
{
  switch (clientAttribute)
  {
  case AttributeId::UserWriteMask:
    return AttributeId::WriteMask;
  case AttributeId::UserAccessLevel:
    return AttributeId::AccessLevel;
  case AttributeId::UserRolePermissions:
    return AttributeId::RolePermissions;
  case AttributeId::UserExecutable:
    return AttributeId::Executable;
  default:
    return clientAttribute;
  }
}

bool AccessControl::produces_value(AttributeId clientAttribute) noexcept
{
  return clientAttribute == AttributeId::UserAccessLevel || clientAttribute == AttributeId::UserWriteMask ||
         clientAttribute == AttributeId::UserExecutable || clientAttribute == AttributeId::RolePermissions ||
         clientAttribute == AttributeId::UserRolePermissions;
}

AccessOperation AccessControl::attribute_read_operation(AttributeId attribute) noexcept
{
  if (attribute == AttributeId::Value)
    return AccessOperation::Read;
  if (attribute == AttributeId::RolePermissions)
    return AccessOperation::ReadRolePermissions;
  return AccessOperation::Browse;
}

SessionAccessControl::SessionAccessControl(AccessControl helper,
  std::shared_ptr<const AccessIdentity> identity, std::shared_ptr<const EndpointSecurityContext> channel)
  : mHelper(std::move(helper)), mIdentity(std::move(identity)), mChannel(std::move(channel))
{}

std::optional<SessionAccessControl> SessionAccessControl::create(const SessionInfo& sessionInfo)
{
  const auto* securityContext = dynamic_cast<const SessionSecurityContext*>(&sessionInfo);
  if (!securityContext)
  {
    return std::nullopt;
  }
  return create(*securityContext,
    sessionInfo.address_space(),
    sessionInfo.server_configuration().authzTimeout,
    sessionInfo.logger());
}

std::optional<SessionAccessControl> SessionAccessControl::create(
  const SessionSecurityContext& securityContext, AddressSpace addressSpace,
  std::chrono::milliseconds authorizationTimeout, Logger logger)
{
  auto result = create_result(securityContext, std::move(addressSpace), authorizationTimeout, logger);
  if (!result.is_good())
  {
    const auto status = result.status_code();
    if (const auto& detail = result.shared_detail())
    {
      logger.warning({{"status", to_string(status)}, {"detail", to_string(*detail)}},
        "Session access identity acquisition failed closed");
    }
    else
    {
      logger.warning({{"status", to_string(status)}}, "Session access identity acquisition failed closed");
    }
    return std::nullopt;
  }
  return std::move(result).value();
}

SessionAccessControl::CreateResult SessionAccessControl::create_result(
  const SessionSecurityContext& securityContext, AddressSpace addressSpace,
  std::chrono::milliseconds authorizationTimeout, Logger logger)
{
  auto identityResult = securityContext.access_identity_result();
  auto endpointSecurity = securityContext.endpoint_security();
  if (!identityResult.is_good())
  {
    // An Uncertain identity is not acted on: access is decided on a Good one only.
    return CreateResult{identityResult.status_code(), identityResult.shared_detail()};
  }
  auto accessIdentity = std::move(identityResult).value();
  if (!endpointSecurity)
  {
    return CreateResult{StatusCode{Status::BadUserAccessDenied},
      ErrorDetail::build("EndpointSecurityContextUnavailable",
        "The Session has no current endpoint security context",
        "SessionAccessControl")};
  }
  return CreateResult{
    SessionAccessControl{AccessControl{std::move(addressSpace), authorizationTimeout, std::move(logger)},
      std::move(accessIdentity),
      std::move(endpointSecurity)}};
}

void SessionAccessControl::authorize_async(const RequestInfo& request,
  std::span<const AccessControl::Item> items, AccessControl::AuthorizeCallback done) const
{
  mHelper.authorize_async(request, mIdentity, items, *mChannel, std::move(done));
}

void SessionAccessControl::authorize_namespace_async(
  const RequestInfo& request, uint16_t namespaceIndex, AccessControl::AuthorizeNamespaceCallback done) const
{
  mHelper.authorize_namespace_async(request, mIdentity, namespaceIndex, *mChannel, std::move(done));
}

DataValue SessionAccessControl::make_client_attribute_value(const NodeAccessor& node, AttributeId attribute,
  DataValue userIndependentValue, const AccessControl::Verdict& readAccess) const
{
  return mHelper.make_client_attribute_value(
    *mIdentity, node, attribute, std::move(userIndependentValue), readAccess, *mChannel);
}

DataValue SessionAccessControl::make_client_attribute_value(const NodeId& nodeId, const NodeAccessor& node,
  AttributeId attribute, DataValue userIndependentValue, const AccessControl::Verdict& readAccess) const
{
  return mHelper.make_client_attribute_value(
    *mIdentity, nodeId, node, attribute, std::move(userIndependentValue), readAccess, *mChannel);
}

const std::shared_ptr<const AccessIdentity>& SessionAccessControl::identity() const noexcept
{
  return mIdentity;
}

const EndpointSecurityContext& SessionAccessControl::channel() const noexcept
{
  return *mChannel;
}

}  // namespace ua::server
