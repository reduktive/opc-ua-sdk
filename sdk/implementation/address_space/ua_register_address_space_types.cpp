// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_register_address_space_types.h"

#include "ua_address_space.h"
#include "ua_address_space_model_access.h"
#include "ua_dynamic_type_descriptor.h"
#include "ua_dynamic_type_registry.h"
#include "ua_error_detail.h"
#include "ua_namespace_array.h"
#include "ua_namespace_route.h"
#include "ua_node_id.h"
#include "ua_structure_factory.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/strand.hpp>

#include <future>
#include <memory>
#include <optional>
#include <utility>

namespace ua::dynamic_types
{

namespace
{

/// URI -> local namespace index, resolved against the address space's namespace table.
/// Returns nullopt for a URI the table does not know (rather than throwing), matching the
/// contract NamespaceIndexLookup requires so register_all_with simply skips such types.
/// @p addressSpace must outlive the lookup, which is used only while the discovered types are bridged.
NamespaceIndexLookup make_ns_index_lookup(ua::AddressSpace& addressSpace)
{
  return [&addressSpace](string_view uri) -> std::optional<uint16_t>
  {
    try
    {
      return addressSpace.namespace_array().get_namespace_index(uri);
    }
    catch (...)
    {
      return std::nullopt;
    }
  };
}

}  // namespace

void register_address_space_types_async(ua::AddressSpace addressSpace, ua::StructureFactory& factory,
  TypeFilter filter, std::function<void(LoaderRegistrationStatsResult)> completion)
{
  // The load is asynchronous: keep the model-access adapter and the throwaway registry alive until the
  // loader's callback fires. The registry is safe to discard after bridging - make_factory captures each
  // descriptor by shared_ptr into the CreateMethod closures handed to the factory. The address space is
  // held weakly (CALLS-21 rule 1), as the adapter holds it, and locked only to bridge the types.
  auto access = std::make_shared<AddressSpaceModelAccess>(addressSpace);
  auto registry = std::make_shared<DynamicTypeRegistry>();

  load_types_async(boost::asio::make_strand(addressSpace.executor()),
    addressSpace.logger(),
    *access,
    *registry,
    std::move(filter),
    [weakAddressSpace = addressSpace.weak(), access, registry, &factory, completion = std::move(completion)](
      LoaderRegistrationStatsResult result) mutable
    {
      std::optional<ua::AddressSpace> owner;
      if (result.is_good())
      {
        owner = weakAddressSpace.lock();
      }
      if (result.is_good() && !owner)
      {
        result =
          LoaderRegistrationStatsResult{ua::detail::address_space_gone("register_address_space_types")};
      }
      if (owner)
      {
        // Bridge the discovered types into the decode factory. register_all_with (the lookup
        // overload) never throws and skips URIs absent from the table; the try/catch is defensive
        // so a stray exception surfaces as an ErrorDetail rather than aborting inside a handler.
        try
        {
          registry->register_all_with(
            [&factory](const NodeId& encodingId, StructureFactory::CreateMethod method)
            { factory.register_type(encodingId, std::move(method)); },
            make_ns_index_lookup(*owner));
        }
        catch (...)
        {
          result = LoaderRegistrationStatsResult{ua::exception_to_status_code(std::current_exception()),
            ua::ErrorDetail::build("FactoryBridgeFailed",
              "failed to register discovered types into the decode factory",
              "register_address_space_types")};
        }
      }
      completion(std::move(result));
    });
}

LoaderRegistrationStatsResult try_register_address_space_types_sync(
  ua::AddressSpace addressSpace, ua::StructureFactory& factory, TypeFilter filter) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<LoaderRegistrationStatsResult>(addressSpace.executor(),
      [&](std::function<void(LoaderRegistrationStatsResult)> complete)
      {
        register_address_space_types_async(
          std::move(addressSpace), factory, std::move(filter), std::move(complete));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

LoaderRegistrationStats register_address_space_types_sync(
  ua::AddressSpace addressSpace, ua::StructureFactory& factory, TypeFilter filter)
{
  return ua::detail::good_value(
    try_register_address_space_types_sync(std::move(addressSpace), factory, std::move(filter)));
}

}  // namespace ua::dynamic_types
