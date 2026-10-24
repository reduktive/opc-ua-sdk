// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_metadata_publication.h"
#include "ua_whole_value_source.h"

#include "ua_self_owning_operation.h"

#include "ua_attribute_wire.h"
#include "ua_callback_safety.h"

#include "ua_namespace.h"
#include "ua_namespace_array.h"
#include "ua_namespace_metadata.h"
#include "ua_namespace_registration_coordinator.h"
#include "ua_namespace_route.h"
#include "ua_default_namespace.h"
#include "ua_node_accessor.h"
#include "ua_numeric_range.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_on_strand.h"
#include "ua_permission_type.h"
#include "ua_referencetype_id.h"
#include "ua_role_configuration.h"
#include "ua_role_permission_utils.h"
#include "ua_role_permissions.h"
#include "ua_role_permission_type.h"
#include "ua_instance_utils.h"
#include "ua_instantiation_service.h"
#include "ua_to_result.h"
#include "ua_variable_id.h"
#include "ua_well_known_role_permissions.h"
#include "ua_variant.h"
#include "ua_version_time.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>

namespace ua::server
{

namespace
{

std::mutex gPublicationRegistryMutex;
std::unordered_map<const NamespaceArray*, std::weak_ptr<const NamespaceMetadataPublication>>
  gPublicationRegistry;

// The per-well-known-role default bitmask now lives in one place, `well_known_role_permissions`,
// because two consumers need it: this publication and the NS0 Role type-metadata decoration, whose
// stamp is each Role's default mask widened by the Browse and Read floor. Two implementations of one
// policy matrix would drift apart.

struct WellKnownRoleSpec
{
  WellKnownRole role;
  uint32_t roleObjectId;
};

constexpr std::array<WellKnownRoleSpec, 9> wellKnownRoleSpecs{{
  {WellKnownRole::Anonymous, utils::to_underlying(ObjectId::WellKnownRole_Anonymous)},
  {WellKnownRole::AuthenticatedUser, utils::to_underlying(ObjectId::WellKnownRole_AuthenticatedUser)},
  {WellKnownRole::Observer, utils::to_underlying(ObjectId::WellKnownRole_Observer)},
  {WellKnownRole::Operator, utils::to_underlying(ObjectId::WellKnownRole_Operator)},
  {WellKnownRole::Engineer, utils::to_underlying(ObjectId::WellKnownRole_Engineer)},
  {WellKnownRole::Supervisor, utils::to_underlying(ObjectId::WellKnownRole_Supervisor)},
  {WellKnownRole::ConfigureAdmin, utils::to_underlying(ObjectId::WellKnownRole_ConfigureAdmin)},
  {WellKnownRole::SecurityAdmin, utils::to_underlying(ObjectId::WellKnownRole_SecurityAdmin)},
  {WellKnownRole::TrustedApplication, utils::to_underlying(ObjectId::WellKnownRole_TrustedApplication)},
}};

Array<RefStructure<Structure>> to_structure_array(const std::vector<RolePermissionType>& items)
{
  Array<RefStructure<Structure>> out;
  out.payload().reserve(items.size());
  for (const auto& item : items)
  {
    RefStructure<Structure> ref;
    ref = std::unique_ptr<Structure>{std::make_unique<RolePermissionType>(item).release()};
    out.payload().push_back(std::move(ref));
  }
  return out;
}

std::vector<RolePermissionType> filtered_role_permissions(
  const std::vector<RolePermissionType>& permissions, std::span<const NodeId> grantedRoles)
{
  return role_permissions::filter_role_permissions(permissions, grantedRoles);
}

/// Wraps a governing Property's answer with the status and timestamp every Read of one carries.
DataValue governing_value(Variant value)
{
  DataValue answer;
  answer.value() = std::move(value);
  answer.status() = Status::Good;
  answer.server_timestamp() = DateTime::now();
  return answer;
}

RolePermissionType role_permission(const NodeId& roleId, const PermissionType& permissions)
{
  RolePermissionType entry;
  entry.role_id() = roleId;
  entry.permissions() = permissions;
  return entry;
}

std::vector<RolePermissionType> namespace_default_property_permissions()
{
  PermissionType permissions = well_known_role_permissions(WellKnownRole::SecurityAdmin);
  permissions.set(PermissionType::Bit::Read);
  permissions.set(PermissionType::Bit::ReadRolePermissions);
  return {role_permission(NodeId{ObjectId::WellKnownRole_SecurityAdmin}, permissions)};
}

std::vector<RolePermissionType> materialized_role_permissions(
  const RoleConfiguration& roleConfig, const std::optional<std::vector<WellKnownRole>>& selection)
{
  std::vector<RolePermissionType> defaults;
  defaults.reserve(wellKnownRoleSpecs.size());
  for (const auto& spec : wellKnownRoleSpecs)
  {
    if (selection.has_value() &&
        std::find(selection->begin(), selection->end(), spec.role) == selection->end())
    {
      continue;
    }
    const NodeId roleId{0, spec.roleObjectId};
    if (!roleConfig.role_bit(roleId).has_value())
    {
      continue;
    }
    defaults.push_back(role_permission(roleId, well_known_role_permissions(spec.role)));
  }
  return defaults;
}

}  // namespace

NamespaceMetadataPublication::NamespaceMetadataPublication(AddressSpace addressSpace)
  : mAddressSpace(addressSpace.weak()), mRegistryKey(&addressSpace.namespace_array())
{}

std::shared_ptr<NamespaceMetadataPublication> NamespaceMetadataPublication::create(AddressSpace addressSpace)
{
  auto publication =
    std::shared_ptr<NamespaceMetadataPublication>{new NamespaceMetadataPublication{std::move(addressSpace)}};
  publication->publish_registry_entry();
  return publication;
}

std::shared_ptr<const NamespaceMetadataPublication> NamespaceMetadataPublication::for_address_space(
  const AddressSpace& addressSpace)
{
  const auto* key = &addressSpace.namespace_array();
  const std::lock_guard lock(gPublicationRegistryMutex);
  const auto found = gPublicationRegistry.find(key);
  if (found == gPublicationRegistry.end())
  {
    return nullptr;
  }
  auto publication = found->second.lock();
  if (!publication)
  {
    gPublicationRegistry.erase(found);
  }
  return publication;
}

void NamespaceMetadataPublication::publish_registry_entry()
{
  const std::lock_guard lock(gPublicationRegistryMutex);
  gPublicationRegistry[mRegistryKey] = shared_from_this();
}

void install_server_namespace_defaults(AddressSpace addressSpace, const RoleConfiguration& roleConfig,
  const std::optional<std::vector<WellKnownRole>>& selection)
{
  detail::AddressSpaceNamespaceLifecycle::set_server_namespace_defaults(
    addressSpace, materialized_role_permissions(roleConfig, selection));
}

namespace
{

constexpr std::array<string_view, 2> rolePermissionPropertyNames{
  "DefaultRolePermissions", "DefaultUserRolePermissions"};

VersionTime next_configuration_version() noexcept
{
  using namespace std::chrono;
  constexpr uint64_t unixToVersionTimeEpochSeconds = 946684800ULL;
  static std::atomic<VersionTime> lastIssued{0};

  const auto unixSeconds = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
  const auto versionSeconds = unixSeconds > static_cast<int64_t>(unixToVersionTimeEpochSeconds)
                                ? static_cast<uint64_t>(unixSeconds) - unixToVersionTimeEpochSeconds
                                : uint64_t{1};
  const auto clockCandidate = static_cast<VersionTime>(
    std::min(versionSeconds, static_cast<uint64_t>(std::numeric_limits<VersionTime>::max())));

  auto observed = lastIssued.load(std::memory_order_relaxed);
  for (;;)
  {
    const auto next = observed == std::numeric_limits<VersionTime>::max()
                        ? observed
                        : std::max(clockCandidate, static_cast<VersionTime>(observed + 1U));
    if (lastIssued.compare_exchange_weak(
          observed, next, std::memory_order_relaxed, std::memory_order_relaxed))
    {
      return next;
    }
  }
}

DataValue metadata_value(Variant value)
{
  DataValue result;
  result.value() = std::move(value);
  result.server_timestamp() = DateTime::now();
  return result;
}

bool is_missing_child(const StatusCode& status)
{
  return status.equivalent(StatusCode{Status::BadNodeIdUnknown});
}

struct MetadataPropertyWrite
{
  QualifiedName browseName;
  /// Disengaged for a Property that is answered rather than stored, which is how
  /// `DefaultUserRolePermissions` is published: it has no value that is correct for every reader.
  std::optional<DataValue> value;
};

class NamespaceMetadataPublicationPreparation final : public detail::NamespaceRegistrationPreparation
{
public:
  NamespaceMetadataPublicationPreparation(std::shared_ptr<NamespaceMetadataPublication> publication,
    std::vector<NamespaceMetadata> metadataHandles, std::vector<uint16_t> ownedNamespaceIndices)
    : mPublication(std::move(publication)), mMetadataHandles(std::move(metadataHandles)),
      mOwnedNamespaceIndices(std::move(ownedNamespaceIndices))
  {}

  void commit() noexcept override
  {
    if (mCommitted)
    {
      return;
    }
    for (auto& metadata : mMetadataHandles)
    {
      metadata.release();
    }
    mCommitted = true;
  }

private:
  std::shared_ptr<NamespaceMetadataPublication> mPublication;
  std::vector<NamespaceMetadata> mMetadataHandles;
  std::vector<uint16_t> mOwnedNamespaceIndices;
  bool mCommitted{false};
};

class NamespaceMetadataPublicationOperation final
  : public ua::async::SelfOwningOperation<NamespaceMetadataPublicationOperation>
{
public:
  NamespaceMetadataPublicationOperation(AddressSpace addressSpace,
    std::vector<NamespaceMetadataSnapshot> namespaces,
    std::shared_ptr<NamespaceMetadataPublication> publication,
    detail::NamespaceRegistrationPreparationCallback complete)
    : ua::async::SelfOwningOperation<NamespaceMetadataPublicationOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mNamespaces(std::move(namespaces)),
      mPublication(std::move(publication)), mComplete(std::move(complete))
  {}

  static void start(AddressSpace addressSpace, std::vector<NamespaceMetadataSnapshot> namespaces,
    std::shared_ptr<NamespaceMetadataPublication> publication,
    detail::NamespaceRegistrationPreparationCallback complete)
  {
    launch(std::make_shared<NamespaceMetadataPublicationOperation>(
      std::move(addressSpace), std::move(namespaces), std::move(publication), std::move(complete)));
  }

private:
  friend class ua::async::SelfOwningOperation<NamespaceMetadataPublicationOperation>;

  const NamespaceMetadataSnapshot& current_namespace() const
  {
    return mNamespaces[mNamespaceIndex];
  }

  QualifiedName current_browse_name() const
  {
    const auto& current = current_namespace();
    return QualifiedName{current.namespaceIndex, current.namespaceUri};
  }

  InstantiationOptions current_instantiation_options(uint16_t targetNamespaceIndex) const
  {
    const bool includeStandardProperties = current_namespace().defaultRolePermissions.has_value();

    InstantiationOptions options;
    options.parentReferenceType = NodeId{ReferenceTypeId::HasComponent};
    options.nodeIdAllocator = guid_node_id_allocator();
    options.targetNamespaceIndex = targetNamespaceIndex;
    options.optionalChildFilter = [includeStandardProperties](const ChildFilterInfo& child)
    {
      const auto name = static_cast<string_view>(child.browseName.name());
      if (name == "ConfigurationVersion" || name == "DefaultAccessRestrictions")
      {
        return true;
      }
      return includeStandardProperties &&
             std::find(rolePermissionPropertyNames.begin(), rolePermissionPropertyNames.end(), name) !=
               rolePermissionPropertyNames.end();
    };
    return options;
  }

  /// The address space, locked for one step's call; nullopt, with @p completion answered AddressSpaceGone,
  /// when it is gone. The operation holds it weakly (CALLS-21 rule 1).
  template<typename Answer, typename Completion>
  std::optional<AddressSpace> owner_or_gone(Completion& completion)
  {
    auto owner = mAddressSpace.lock();
    if (!owner)
      completion(Answer{::ua::detail::address_space_gone("NamespaceMetadataPublication")});
    return owner;
  }

  auto find_node(const NodeId& nodeId)
  {
    return await_step<NodeAccessorResult>(
      [this, nodeId](auto completion)
      {
        if (auto owner = owner_or_gone<NodeAccessorResult>(completion))
          owner->find_node_async(nodeId, std::move(completion));
      });
  }

  /// Writes one attribute of a metadata node without blocking: publication runs on the executor, and
  /// namespace 1 may be the application's own namespace answering by a post to it.
  auto write_attribute(NodeAccessor node, AttributeId attributeId, Variant encoded)
  {
    return await_step<VoidResult>([node, attributeId, encoded = std::move(encoded)](auto completion) mutable
      { node.write_attribute_async(attributeId, std::move(encoded), std::move(completion)); });
  }

  /// Stamps a metadata node's AccessRestrictions and RolePermissions (see the callers for why), and
  /// reports the first failure.
  ua::async::Task<VoidResult> stamp_access(NodeAccessor node,
    std::optional<AccessRestrictionType> restrictions,
    std::optional<std::vector<RolePermissionType>> permissions)
  {
    auto restricted = co_await write_attribute(
      node, AttributeId::AccessRestrictions, attribute_wire::access_restrictions(restrictions));
    if (restricted.is_bad())
      co_return restricted;
    co_return co_await write_attribute(
      node, AttributeId::RolePermissions, attribute_wire::role_permissions(permissions));
  }

  auto find_child_id(const NodeId& parent, const NodeId& referenceType, QualifiedName browseName)
  {
    return await_step<NodeIdResult>(
      [this, parent, referenceType, browseName](auto completion)
      {
        if (auto owner = owner_or_gone<NodeIdResult>(completion))
          instance_utils::find_child_id_by_browse_name_async(
            std::move(*owner), parent, referenceType, browseName, std::move(completion));
      });
  }

  auto attach_metadata(const NodeId& nodeId)
  {
    return await_step<NamespaceMetadataResult>(
      [this, nodeId](auto completion)
      {
        if (auto owner = owner_or_gone<NamespaceMetadataResult>(completion))
          NamespaceMetadata::attach_async(std::move(*owner), nodeId, std::move(completion));
      });
  }

  auto create_metadata(uint16_t targetNamespaceIndex)
  {
    return await_step<NamespaceMetadataResult>(
      [this, targetNamespaceIndex](auto completion)
      {
        auto owner = owner_or_gone<NamespaceMetadataResult>(completion);
        if (!owner)
          return;
        NamespaceMetadata::create_async(std::move(*owner),
          NodeId{ObjectId::Server_Namespaces},
          current_browse_name(),
          current_instantiation_options(targetNamespaceIndex),
          std::move(completion));
      });
  }

  ua::async::Task<> run()
  {
    try
    {
      if (mNamespaces.empty())
      {
        complete(VoidResult{});
        co_return;
      }

      auto parent = co_await find_node(NodeId{ObjectId::Server_Namespaces});
      if (!parent.is_good())
      {
        const auto& represented = mNamespaces.front();
        const auto cause = ::ua::detail::lookup_failure(
          NodeId{ObjectId::Server_Namespaces}, parent.status_code(), "NamespaceMetadataPublication");
        fail(StatusCode{cause.value(),
          ErrorDetail::build("NamespaceMetadataParentUnavailable",
            "The Server Namespaces Object is unavailable",
            "NamespaceMetadataPublication")
            .context(ContextKeys::namespaceIndex, represented.namespaceIndex)
            .context(ContextKeys::namespaceUri, std::string{represented.namespaceUri})
            .cause(cause)});
        co_return;
      }
      mNamespacesParent.emplace(std::move(parent).value());

      for (mNamespaceIndex = 0; mNamespaceIndex < mNamespaces.size(); ++mNamespaceIndex)
      {
        if (!co_await publish_one_namespace())
        {
          co_return;
        }

        if (mCurrentMetadata)
        {
          mPreparedMetadata.push_back(std::move(*mCurrentMetadata));
          mCurrentMetadata.reset();
        }
      }

      complete(VoidResult{});
    }
    catch (const ua::async::Abandoned&)
    {
      // Withdrawn while suspended: whoever withdrew it answered the caller.
      ::ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      fail(ua::exception_to_status_code(std::current_exception()));
    }
  }

  void fail_to_start(StatusCode status)
  {
    fail(status);
  }

  /// One namespace, start to finish. Returns false when it has already answered.
  ua::async::Task<bool> publish_one_namespace()
  {
    // Obligation 5: a caller may suppress publication for a namespace that owes no Object. Nothing
    // is created, adopted or recorded, so no node of this namespace reaches the governing map.
    if (current_namespace().options.publication == NamespaceMetadataOptions::Publication::Suppress)
    {
      co_return true;
    }

    // --- get the metadata Object: declared by the namespace, already present, or created ------
    bool declared = false;
    bool created = false;
    NamespaceMetadataResult metadataResult{StatusCode{Status::BadInternalError}};

    if (const auto metadataObject = current_namespace().metadataObject; metadataObject.has_value())
    {
      const auto& declaredId = metadataObject.value();
      if (declaredId.namespace_index() != current_namespace().namespaceIndex)
      {
        fail(StatusCode{Status::BadConfigurationError,
          ErrorDetail::build("NamespaceMetadataForeignNode",
            "A namespace declared a metadata Object belonging to another namespace",
            "NamespaceMetadataPublication")
            .context(ContextKeys::namespaceIndex, current_namespace().namespaceIndex)
            .context(ContextKeys::namespaceUri, std::string{current_namespace().namespaceUri})
            .context(ContextKeys::nodeId, to_string(declaredId))});
        co_return false;
      }
      declared = true;
      metadataResult = co_await attach_metadata(declaredId);
    }
    else
    {
      auto childId = co_await find_child_id(
        NodeId{ObjectId::Server_Namespaces}, NodeId{ReferenceTypeId::HasComponent}, current_browse_name());
      if (childId.is_good())
      {
        // Already published - by a NodeSet that carried its own Object, or by this participant on an
        // earlier preparation. Either way it is adopted, wherever it lives: governance follows the
        // NodeId, so an Object in its own namespace and one in namespace 1 are both self-consistent.
        metadataResult = co_await attach_metadata(childId.value());
      }
      else if (!is_missing_child(childId.status_code()))
      {
        fail(childId.status_code());
        co_return false;
      }
      else
      {
        // An Object the SDK creates is created in namespace 1, always. Namespace 1 is reserved for
        // the local Server (Part 5 6.3.1) and is the SDK's own namespace, so creation cannot be
        // declined and no namespace is obliged to accept nodes it did not ask for. The Object
        // describes the represented namespace through its BrowseName and NamespaceUri, which is how
        // a client associates the two; its NodeId namespace governs access to it, so nothing
        // diverges and nothing needs recording.
        created = true;
        metadataResult = co_await create_metadata(uint16_t{1});
      }
    }

    if (!metadataResult.is_good())
    {
      // The publication writes into the Object it finds or creates, so an Uncertain answer, with or without
      // the Object, is refused.
      const StatusCode answer = ::ua::detail::answer_failure(
        metadataResult.status_code(), "LookupAnswerUncertain", "NamespaceMetadataPublication");
      if (declared)
      {
        if (answer.equivalent(StatusCode{Status::BadNodeIdUnknown}))
        {
          fail_declared_metadata("NamespaceMetadataUnresolvable",
            "The declared metadata Object does not resolve through its namespace",
            answer);
        }
        else
        {
          fail_declared_metadata("NamespaceMetadataWrongType",
            "The declared node is not a NamespaceMetadataType instance",
            answer);
        }
        co_return false;
      }
      fail(answer);
      co_return false;
    }
    mCurrentMetadata.emplace(std::move(metadataResult).value());

    if (created)
    {
      // Same reason as the Properties below: the Object is a namespace 1 node, so stamp the
      // represented namespace's channel restriction on it rather than inherit namespace 1's.
      auto objectNode = co_await find_node(mCurrentMetadata->node_id());
      if (!objectNode.is_good())
      {
        fail(::ua::detail::lookup_failure(
          mCurrentMetadata->node_id(), objectNode.status_code(), "NamespaceMetadataPublication"));
        co_return false;
      }
      auto stamped = co_await stamp_access(objectNode.value(),
        current_namespace().defaultAccessRestrictions,
        current_namespace().defaultRolePermissions);
      if (stamped.is_bad())
      {
        fail(stamped.status_code());
        co_return false;
      }
    }

    // --- a declared Object has to prove it describes THIS namespace, then be linked ----------
    if (declared)
    {
      auto property = co_await await_step<PropertyResult>(
        [this](auto completion) { mCurrentMetadata->namespace_uri_property_async(std::move(completion)); });
      if (!property.is_good())
      {
        fail_declared_metadata("NamespaceMetadataUriMissing",
          "The declared metadata Object has no readable NamespaceUri Property",
          ::ua::detail::lookup_failure(
            mCurrentMetadata->node_id(), property.status_code(), "NamespaceMetadataPublication"));
        co_return false;
      }
      mCurrentNamespaceUri.emplace(std::move(property).value());

      auto value = co_await await_step<DataValueResult>(
        [this](auto completion) { mCurrentNamespaceUri->read_value_async(std::move(completion)); });
      mCurrentNamespaceUri.reset();
      if (!value.is_good())
      {
        fail_declared_metadata("NamespaceMetadataUriUnreadable",
          "The declared metadata Object's NamespaceUri Value cannot be read",
          ::ua::detail::read_failure(value.status_code(), "NamespaceMetadataPublication"));
        co_return false;
      }
      const auto* actual = value.value().value().try_as<String>();
      if (!actual || *actual != current_namespace().namespaceUri)
      {
        fail_declared_metadata("NamespaceMetadataUriMismatch",
          "The declared metadata Object describes a different namespace",
          StatusCode{Status::BadConfigurationError});
        co_return false;
      }
      if (!mNamespacesParent)
      {
        fail(StatusCode{Status::BadInvalidState});
        co_return false;
      }

      auto linked = co_await await_step<VoidResult>(
        [this](auto completion)
        {
          mNamespacesParent->add_reference_if_not_present_async(NodeId{ReferenceTypeId::HasComponent},
            mCurrentMetadata->node_id(),
            true,
            ReferenceHalves::Both,
            std::move(completion));
        });
      if (linked.is_bad())
      {
        fail_declared_metadata("NamespaceMetadataLinkFailed",
          "The declared metadata Object could not be linked from Server.Namespaces",
          linked.status_code());
        co_return false;
      }
    }

    // --- an Object we did not create may be missing its optional members, or carrying ones ----
    // --- this namespace has no business serving ----------------------------------------------
    if (!created)
    {
      auto options = current_instantiation_options(mCurrentMetadata->node_id().namespace_index());
      auto materialised = co_await await_step<VoidResult>(
        [this, options = std::move(options)](auto completion) mutable
        {
          auto owner = owner_or_gone<VoidResult>(completion);
          if (!owner)
            return;
          InstantiationService{*owner}.instantiate_optional_members_async(mCurrentMetadata->node_id(),
            NodeId{ObjectTypeId::NamespaceMetadataType},
            options,
            std::move(completion));
        });
      if (materialised.is_bad())
      {
        fail(materialised.status_code());
        co_return false;
      }

      if (!current_namespace().defaultRolePermissions.has_value())
      {
        // A namespace declaring no Role model must not serve the standard Role Properties. One that
        // DECLARED its own Object is refused for carrying them; one we merely found gets them removed.
        const bool validateOpaqueProperties = declared;
        for (const auto& propertyName : rolePermissionPropertyNames)
        {
          auto found = co_await find_child_id(mCurrentMetadata->node_id(),
            NodeId{ReferenceTypeId::HasProperty},
            QualifiedName{0, propertyName});
          if (!found.is_good())
          {
            if (!is_missing_child(found.status_code()))
            {
              fail(found.status_code());
              co_return false;
            }
            continue;
          }

          if (validateOpaqueProperties)
          {
            fail_declared_metadata("NamespaceMetadataOpaqueRoleProperty",
              "A namespace declaring no Role model serves a standard Role Property",
              StatusCode{Status::BadConfigurationError});
            co_return false;
          }

          auto removed = co_await await_step<VoidResult>(
            [this, nodeId = found.value()](auto completion)
            {
              if (auto owner = owner_or_gone<VoidResult>(completion))
                owner->delete_node_async(nodeId, false, ReferenceHalves::Both, std::move(completion));
            });
          if (removed.is_bad())
          {
            fail(removed.status_code());
            co_return false;
          }
        }
      }
    }

    if (!co_await write_metadata_properties(created))
    {
      co_return false;
    }
    co_return true;
  }

  /// Makes `DefaultUserRolePermissions` answer from the reading Session rather than from a stored array.
  ///
  /// Part 3 5.2.9 (RolePermissions), third paragraph: the value "shall be a readonly list of Permissions
  /// for each Role assigned to the current Session". There is therefore no array that is correct for
  /// every reader, and nothing is stored on the node at all - the node produces the answer per read.
  ///
  /// It filters this namespace's declared defaults, which is also what is published on the
  /// `DefaultRolePermissions` Property beside it and what Part 3 4.8.3 makes the server evaluate for a
  /// node of the namespace carrying no `RolePermissions` of its own. So the user view, the administrator
  /// view and the decision the server will actually reach all come from one array. Note 5.2.9 defines
  /// this Property from the Session's Roles and never says its entries are a subset of that array;
  /// filtering it is this SDK's choice, made so those three cannot diverge.
  ///
  /// The array is captured here rather than re-read per Read. `default_ns::Namespace::set_namespace_defaults`
  /// refuses a second call, so a namespace's defaults are fixed once configured and there is nothing to
  /// re-read for.
  ///
  /// With no Session the answer is the empty array. The specification does not state that case; it
  /// follows from "for each Role assigned to the current Session", since a caller that presented no
  /// identity holds none. Answering with the unfiltered array would disclose to such a caller what the
  /// administrator-only Property beside it holds.
  ///
  /// This runs only on an Object this server created. An Object that already existed belongs to the
  /// namespace that published it, which has taken responsibility for its own nodes' permissions along
  /// with everything else about them; the server does not reach into it to change what it answers.
  ///
  /// @return False when a node this server just created cannot answer per Session, which is a refusal
  ///         rather than a fallback: serving one array to everyone is what this exists to prevent.
  bool install_user_role_permissions_projection()
  {
    auto published = current_namespace().defaultRolePermissions.value_or(std::vector<RolePermissionType>{});
    auto* source = (*mCurrentProperty)->external_value_source();
    const auto installed =
      source
        ? source->set_value_source(detail::whole_value_source(
            [published = std::move(published)](
              const ValueSource::ReadContext& context, std::function<void(DataValueResult)> complete)
            {
              // The identity is valid only for this call, so the filtered answer is computed before
              // returning.
              const auto* identity = context.caller != nullptr ? context.caller->identity.get() : nullptr;
              const auto granted = identity != nullptr
                                     ? filtered_role_permissions(published, identity->granted_roles())
                                     : std::vector<RolePermissionType>{};
              complete(DataValueResult{governing_value(Variant{to_structure_array(granted)})});
            }))
        : VoidResult{StatusCode{Status::BadNotSupported}};
    if (installed.is_bad())
    {
      fail(StatusCode{installed.status_code().value(),
        ErrorDetail::build("NamespaceMetadataUserPropertyNotProjectable",
          "A metadata Property cannot answer per Session, so publishing "
          "DefaultUserRolePermissions would serve one fixed array to every Session as that Session's own "
          "permissions. Declare a vendor-specific Role model by returning nullopt from "
          "default_role_permissions(), which publishes neither Role Property.",
          "NamespaceMetadataPublication")
          .context(ContextKeys::namespaceUri, std::string{current_namespace().namespaceUri})
          .context(ContextKeys::nodeId, to_string(mCurrentProperty->get_node_id()))
          .cause(installed.status_code())});
      return false;
    }
    return true;
  }

  ua::async::Task<bool> write_metadata_properties(bool created)
  {
    const auto& current = current_namespace();
    std::vector<MetadataPropertyWrite> propertyWrites;
    propertyWrites.reserve(current.defaultRolePermissions.has_value() ? 11 : 9);
    propertyWrites.push_back(
      {QualifiedName{0, "NamespaceUri"}, metadata_value(Variant{current.namespaceUri})});
    // Obligation 3: descriptive facts are the registering caller's to supply. An absent option keeps
    // the conservative unknown, which claims nothing rather than asserting a fact no source gave.
    const auto& options = current.options;
    propertyWrites.push_back({QualifiedName{0, "NamespaceVersion"},
      metadata_value(Variant{options.namespaceVersion.value_or(String{})})});
    propertyWrites.push_back({QualifiedName{0, "NamespacePublicationDate"},
      metadata_value(Variant{options.namespacePublicationDate.value_or(DateTime{})})});
    propertyWrites.push_back({QualifiedName{0, "IsNamespaceSubset"},
      metadata_value(Variant{options.isNamespaceSubset.value_or(true)})});
    propertyWrites.push_back({QualifiedName{0, "StaticNodeIdTypes"},
      metadata_value(Variant{options.staticNodeIdTypes.value_or(Array<int32_t>{})})});
    propertyWrites.push_back({QualifiedName{0, "StaticNumericNodeIdRange"},
      metadata_value(Variant{options.staticNumericNodeIdRange.value_or(Array<NumericRange>{})})});
    propertyWrites.push_back({QualifiedName{0, "StaticStringNodeIdPattern"},
      metadata_value(Variant{options.staticStringNodeIdPattern.value_or(String{})})});
    propertyWrites.push_back(
      {QualifiedName{0, "ConfigurationVersion"}, metadata_value(Variant{next_configuration_version()})});
    if (current.defaultRolePermissions.has_value())
    {
      propertyWrites.push_back({QualifiedName{0, "DefaultRolePermissions"},
        metadata_value(Variant{to_structure_array(*current.defaultRolePermissions)})});
      // No value for the user Property: it is projected per read, never stored. It stays in this list
      // so the loop below still walks to it and installs the projection.
      propertyWrites.push_back({QualifiedName{0, "DefaultUserRolePermissions"}, std::nullopt});
    }
    const auto restrictions = current.defaultAccessRestrictions;
    propertyWrites.push_back({QualifiedName{0, "DefaultAccessRestrictions"},
      metadata_value(Variant{restrictions ? restrictions->as_underlying_type() : uint16_t{0}})});

    for (auto& write : propertyWrites)
    {
      auto found = co_await await_step<VariableAccessorResult>(
        [this, browseName = write.browseName](auto completion)
        {
          auto owner = owner_or_gone<VariableAccessorResult>(completion);
          if (!owner)
            return;
          instance_utils::find_child_variable_accessor_by_browse_name_async(std::move(*owner),
            mCurrentMetadata->node_id(),
            NodeId{ReferenceTypeId::HasProperty},
            browseName,
            std::move(completion));
        });
      if (!found.is_good())
      {
        fail(::ua::detail::lookup_failure(
          mCurrentMetadata->node_id(), found.status_code(), "NamespaceMetadataPublication"));
        co_return false;
      }
      mCurrentProperty.emplace(std::move(found).value());

      if (created)
      {
        // The Object and its Properties are namespace 1 nodes, so namespace 1's defaults would govern
        // reading them - which would both expose a namespace's metadata to whoever namespace 1 admits
        // and let a namespace requiring an encrypted channel have its metadata read over an
        // unencrypted one. Part 3 5.2.9 and 5.2.11 give the remedy: a Node overrides its namespace
        // default by carrying the Attribute itself. Stamping both here reproduces exactly the policy
        // the represented namespace declares. The stamp is what that namespace declared when it was
        // published, as are the values written below it, and the two are taken from one read of the
        // namespace - so what the metadata says and what governs reading it cannot describe different
        // policies. A vendor-model namespace has no Role defaults to stamp, so namespace
        // 1 governs the Role side of its metadata; it keeps the channel condition either way.
        // Part 3 5.2.9: DefaultRolePermissions is readable by administrators only, which is stricter than
        // the namespace default and must not be displaced by it.
        auto permissions =
          write.browseName == QualifiedName{0, "DefaultRolePermissions"}
            ? std::optional<std::vector<RolePermissionType>>{namespace_default_property_permissions()}
            : current_namespace().defaultRolePermissions;
        auto stamped = co_await stamp_access(
          *mCurrentProperty, current_namespace().defaultAccessRestrictions, permissions);
        if (stamped.is_bad())
        {
          fail(stamped.status_code());
          co_return false;
        }
      }
      // Whether an Object this server did not create may have its Properties written depends on WHICH
      // Property, not on the Object.
      //
      // The descriptive Properties - NamespaceUri, NamespaceVersion, NamespacePublicationDate,
      // IsNamespaceSubset and the static NodeId declarations - describe what the namespace CONTAINS.
      // NS0 and NS1 carry theirs from the standard NodeSet, where they are authoritative and this
      // server has nothing truer to say; overwriting them replaces the published version and
      // publication date of the standard namespace with this server's idea of them.
      //
      // The access-control Properties describe what this server ENFORCES. No NodeSet can know a
      // server's Role configuration, so they are the server's to publish wherever the Object came
      // from, and Part 3 5.2.9 obliges it to publish them for a namespace declaring the Role model.
      // Gating these on creation left NS0 and NS1 - the only namespaces whose metadata Objects are
      // never created here - publishing no Role defaults at all.
      const bool serverOwnedProperty = write.browseName == QualifiedName{0, "DefaultRolePermissions"} ||
                                       write.browseName == QualifiedName{0, "DefaultUserRolePermissions"} ||
                                       write.browseName == QualifiedName{0, "DefaultAccessRestrictions"};
      if (!created && !serverOwnedProperty)
      {
        mCurrentProperty.reset();
        continue;
      }

      // The projection is content rather than policy: a Property whose value differs per Session has
      // to answer per Session wherever it lives.
      if (write.browseName == QualifiedName{0, "DefaultUserRolePermissions"} &&
          current_namespace().defaultRolePermissions.has_value())
      {
        if (!install_user_role_permissions_projection())
        {
          co_return false;
        }
        // The Value now differs per Session, so its source cannot report it through notify_value_changed,
        // which pushes one Value to every item: -1, Part 3's "indeterminate", has its MonitoredItems sampled
        // for each Subscription's current caller (NR-49), as the ValueAsText wiring does. An imported
        // Property carries the NodeSet schema's 0, which would make an item at interval 0 write-fed.
        auto sampling = co_await write_attribute(*mCurrentProperty,
          AttributeId::MinimumSamplingInterval,
          attribute_wire::minimum_sampling_interval(Duration{-1}));
        if (sampling.is_bad())
        {
          fail(sampling.status_code());
          co_return false;
        }
      }

      if (!write.value.has_value())
      {
        // Answered, not stored. Nothing to write, and writing an array here would be the defect the
        // projection above exists to prevent.
        mCurrentProperty.reset();
        continue;
      }

      auto written =
        co_await await_step<VoidResult>([this, value = std::move(*write.value)](auto completion) mutable
          { mCurrentProperty->write_value_async(std::move(value), std::move(completion)); });
      mCurrentProperty.reset();
      if (written.is_bad())
      {
        fail(written.status_code());
        co_return false;
      }
    }
    co_return true;
  }

  void fail_declared_metadata(string_view code, string_view message, const StatusCode& cause)
  {
    fail(StatusCode{cause.value(),
      ErrorDetail::build(std::string{code}, std::string{message}, "NamespaceMetadataPublication")
        .context(ContextKeys::namespaceIndex, current_namespace().namespaceIndex)
        .context(ContextKeys::namespaceUri, std::string{current_namespace().namespaceUri})
        .context(ContextKeys::nodeId, to_string(*current_namespace().metadataObject))
        .cause(cause)});
  }

  void fail(StatusCode status)
  {
    mCurrentProperty.reset();
    mCurrentNamespaceUri.reset();
    mCurrentMetadata.reset();
    if (auto completion = std::move(mComplete))
    {
      completion(detail::NamespaceRegistrationPreparationResult{std::move(status)});
    }
  }

  void complete(VoidResult result)
  {
    if (result.is_bad())
    {
      fail(result.status_code());
      return;
    }
    if (!mComplete)
    {
      return;
    }

    std::vector<uint16_t> owned;
    owned.reserve(mNamespaces.size());
    for (const auto& snapshot : mNamespaces)
    {
      owned.push_back(snapshot.namespaceIndex);
    }
    auto preparation = std::make_shared<NamespaceMetadataPublicationPreparation>(
      mPublication, std::move(mPreparedMetadata), std::move(owned));
    auto complete = std::move(mComplete);
    complete(detail::NamespaceRegistrationPreparationResult{std::move(preparation)});
  }

  WeakAddressSpace mAddressSpace;
  std::vector<NamespaceMetadataSnapshot> mNamespaces;
  std::shared_ptr<NamespaceMetadataPublication> mPublication;
  detail::NamespaceRegistrationPreparationCallback mComplete;
  size_t mNamespaceIndex{0};
  std::optional<NamespaceMetadata> mCurrentMetadata;
  std::optional<NodeAccessor> mNamespacesParent;
  std::optional<Property> mCurrentNamespaceUri;
  std::optional<VariableAccessor> mCurrentProperty;
  std::vector<NamespaceMetadata> mPreparedMetadata;
};

}  // namespace

void NamespaceMetadataPublication::prepare_async(detail::NamespaceRegistrationCandidate candidate,
  detail::NamespaceRegistrationPreparationCallback complete) noexcept
{
  if (!complete)
  {
    return;
  }
  const auto logger = candidate.stagedAddressSpace.logger();
  auto fallbackComplete = complete;
  try
  {
    if (!candidate.namespaceObject)
    {
      throw UaException{Status::BadInvalidArgument,
        ErrorDetail::build("NamespaceMissing",
          "Namespace metadata preparation requires a namespace implementation",
          "NamespaceMetadataPublication")
          .context(ContextKeys::namespaceIndex, candidate.namespaceIndex)
          .context(ContextKeys::namespaceUri, std::string{candidate.namespaceUri})};
    }

    NamespaceMetadataSnapshot snapshot;
    snapshot.namespaceIndex = candidate.namespaceIndex;
    snapshot.namespaceUri = candidate.namespaceUri;
    snapshot.defaultRolePermissions = candidate.namespaceObject->default_role_permissions();
    snapshot.defaultAccessRestrictions = candidate.namespaceObject->default_access_restrictions();
    snapshot.metadataObject = candidate.metadataObject;
    snapshot.options = candidate.metadataOptions;

    // Obligation 4: an engaged default_role_permissions() declares the standard Part 3 Role model,
    // and Part 3 5.2.9 obliges the server to publish DefaultRolePermissions for such a namespace.
    // Advertising permissions and suppressing their publication cannot both hold.
    if (snapshot.defaultRolePermissions.has_value() &&
        snapshot.options.publication == NamespaceMetadataOptions::Publication::Suppress)
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("NamespaceMetadataSuppressedWhilePublishingPermissions",
          "Publication was suppressed for a namespace whose default_role_permissions() is engaged, "
          "which declares the standard Role model and obliges the server to publish its "
          "DefaultRolePermissions. Request publication, or declare a vendor-specific model by "
          "returning nullopt from default_role_permissions()",
          "NamespaceMetadataPublication")
          .context(ContextKeys::namespaceIndex, candidate.namespaceIndex)
          .context(ContextKeys::namespaceUri, std::string{candidate.namespaceUri})};
    }

    std::vector<NamespaceMetadataSnapshot> namespaces;
    namespaces.push_back(std::move(snapshot));
    NamespaceMetadataPublicationOperation::start(std::move(candidate.stagedAddressSpace),
      std::move(namespaces),
      shared_from_this(),
      std::move(complete));
  }
  catch (...)
  {
    const detail::NamespaceRegistrationPreparationResult failure{
      ua::exception_to_status_code(std::current_exception())};
    ua::async::guarded(
      logger, [complete = std::move(fallbackComplete), failure]() mutable { complete(failure); })();
  }
}

void NamespaceMetadataPublication::prepare_async(
  std::vector<NamespaceMetadataSnapshot> namespaces, std::function<void(VoidResult)> complete) noexcept
{
  if (!complete)
  {
    return;
  }

  auto addressSpace = mAddressSpace.lock();
  if (!addressSpace)
  {
    complete(VoidResult{Status::BadShutdown,
      ErrorDetail::build("NamespaceMetadataOwnerGone",
        "The address space was destroyed before metadata preparation began",
        "NamespaceMetadataPublication")});
    return;
  }

  const auto logger = addressSpace->logger();
  auto fallbackComplete = complete;
  try
  {
    auto commitAndComplete = [complete = std::move(complete)](
                               detail::NamespaceRegistrationPreparationResult prepared) mutable
    {
      if (!prepared.is_good())
      {
        complete(VoidResult{prepared.status_code(), prepared.shared_detail()});
        return;
      }
      prepared.value()->commit();
      complete(VoidResult{});
    };
    NamespaceMetadataPublicationOperation::start(
      std::move(*addressSpace), std::move(namespaces), shared_from_this(), std::move(commitAndComplete));
  }
  catch (...)
  {
    const VoidResult failure{ua::exception_to_status_code(std::current_exception())};
    ua::async::guarded(
      logger, [complete = std::move(fallbackComplete), failure]() mutable { complete(failure); })();
  }
}

}  // namespace ua::server
