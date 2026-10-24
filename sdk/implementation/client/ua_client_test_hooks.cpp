// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_client_test_hooks.h"

#include "ua_core_client_impl.h"

namespace ua::client
{

void CoreClientTestAccess::set_test_hooks(const CoreClient& client, ClientTestHooks hooks)
{
  CoreClientImpl::TestHooks internal;
  internal.transportDecorator = std::move(hooks.transportDecorator);
  internal.securityPolicyFactory = std::move(hooks.securityPolicyFactory);
  client.mImpl->mTestHooks = std::move(internal);
}

std::shared_ptr<CoreClientImpl> CoreClientTestAccess::impl(const CoreClient& client)
{
  return client.mImpl;
}

std::shared_ptr<PullCertificateManager> CoreClientTestAccess::pull_cert_manager(const CoreClientImpl& impl)
{
  return impl.mPullCertManager;
}

std::shared_ptr<detail::PullCertificateManagerClientHost> CoreClientTestAccess::pull_cert_host(
  const CoreClientImpl& impl)
{
  return impl.mPullCertHost;
}

void CoreClientTestAccess::set_connection_establisher(
  CoreClientImpl& impl, std::shared_ptr<detail::ConnectionEstablisher> establisher)
{
  impl.mConnectionEstablisher = std::move(establisher);
}

std::size_t CoreClientTestAccess::connection_registry_size(const CoreClientImpl& impl)
{
  const std::lock_guard<std::mutex> lock(impl.mRegistryMutex);
  return impl.mConnections.size();
}

}  // namespace ua::client
