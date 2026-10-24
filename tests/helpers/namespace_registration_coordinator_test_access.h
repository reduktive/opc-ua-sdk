// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_HELPERS_NAMESPACE_REGISTRATION_COORDINATOR_TEST_ACCESS_H
#define UA_TESTS_HELPERS_NAMESPACE_REGISTRATION_COORDINATOR_TEST_ACCESS_H

#include "ua_address_space.h"
#include "ua_address_space_impl.h"
#include "ua_namespace_registration_coordinator.h"

namespace ua::test_helpers
{

/// Friend-only access to lifecycle test interfaces; adds no supported AddressSpace API.
class NamespaceRegistrationCoordinatorTestAccess
{
public:
  static void install_participant(
    AddressSpace& addressSpace, shared_ptr<detail::NamespaceRegistrationParticipant> participant)
  {
    detail::AddressSpaceNamespaceLifecycle::install_participant(addressSpace, std::move(participant));
  }

  static void prepare_installed_namespaces_async(
    AddressSpace& addressSpace, std::function<void(VoidResult)> callback)
  {
    detail::AddressSpaceNamespaceLifecycle::prepare_installed_namespaces_async(
      addressSpace, std::move(callback));
  }

  static void set_maximum_namespaces(AddressSpace& addressSpace, std::size_t maximumNamespaces)
  {
    addressSpace.mImpl->namespace_registration_coordinator().set_maximum_namespaces_for_tests(
      maximumNamespaces);
  }
};

}  // namespace ua::test_helpers

#endif  // UA_TESTS_HELPERS_NAMESPACE_REGISTRATION_COORDINATOR_TEST_ACCESS_H
