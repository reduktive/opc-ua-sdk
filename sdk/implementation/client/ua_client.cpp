// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Public tier-1 client::Client method forwarding into the composed CoreClient's impl.
//
// Client (tier-1) composes a CoreClient by value (client design section 7.1) and is a friend of
// it, so it reaches the shared CoreClientImpl through `mCore.mImpl`. Every method here is a
// MANAGED entry point; the unmanaged wire surface stays on CoreClient and is reached explicitly
// via Client::core().

#include "ua_sync_wait.h"
#include "ua_certificate_validation_paths.h"
#include "ua_client.h"
#include "ua_client_config_bundle.h"
#include "ua_core_client_impl.h"
#include "ua_client_observers.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_discovery.h"
#include "ua_easy_connect.h"
#include "ua_server_cert_validator.h"

#include "ua_exceptions.h"
#include "ua_to_result.h"

#include <future>
#include <utility>

namespace
{

[[noreturn]] void throw_invalid_state()
{
  throw ua::UaException{ua::Status::BadInvalidState, nullptr};
}

}  // namespace

namespace ua::client
{

Client::Client(CoreClient core) : mCore(std::move(core))
{}

Client::~Client() = default;

CoreClient& Client::core() noexcept
{
  return mCore;
}

const CoreClient& Client::core() const noexcept
{
  return mCore;
}

void Client::connect_async(ConnectionConfig config, ConnectCallback callback) noexcept
{
  if (!mCore.mImpl)
  {
    callback(ConnectResult{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }
  try
  {
    // Pass `callback` by COPY, never std::move (this function is noexcept): if the callee throws and unwinds
    // into the catch, a moved-from callback would be empty and invoking it would throw out of a noexcept
    // function -> std::terminate. See open_channel_async.
    mCore.mImpl->connect_async(std::move(config), callback);
  }
  catch (...)
  {
    callback(ua::exception_to_status_code(std::current_exception()));
  }
}

void Client::easy_connect_async(EasyConnectConfig policy, ConnectCallback callback) noexcept
{
  auto impl = mCore.mImpl;
  if (!impl)
  {
    if (callback)
    {
      callback(ConnectResult{ua::Status::BadInvalidState,
        ua::make_error_detail(
          "EasyConnectClientShutDown", "the Client has been shut down", "client.tier1.easy_connect")});
    }
    return;
  }

  // Bind the resolver's collaborators to this Client. `storeAccessor` is deliberately resolved at
  // VALIDATION time (not captured by value) so it sees the trust material as of the validation -
  // which is the whole point after an AcceptAndPersist writes to it.
  std::weak_ptr<CoreClientImpl> weakImpl = impl;
  detail::EasyConnectDeps deps;
  deps.logger = impl->logger();

  deps.getEndpoints = [weakImpl](
                        std::string url, GetEndpointsOptions options, Discovery::GetEndpointsCallback cb)
  {
    auto self = weakImpl.lock();
    if (!self)
    {
      cb(Discovery::GetEndpointsResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("EasyConnectClientDestroyed",
          "the Client was destroyed before discovery completed",
          "client.tier1.easy_connect.discovery")});
      return;
    }
    // Built the same way Client::discovery() builds it, so easy-connect's discovery hop is the
    // ordinary tier-1 facade and not a second, divergent path.
    Discovery{self->discovery_channel_factory(),
      self->mdns_transport(),
      self->configuration().allowDeprecatedSecurityPolicies}
      .get_endpoints_async(std::move(url), std::move(options), std::move(cb));
  };

  deps.decodeCertificate =
    [weakImpl](
      const ua::ByteString& der) -> ua::Result<std::vector<std::shared_ptr<const ua::X509Certificate>>>
  {
    using ChainResult = ua::Result<std::vector<std::shared_ptr<const ua::X509Certificate>>>;
    auto self = weakImpl.lock();
    if (!self)
    {
      return ChainResult{ua::Status::BadConnectionClosed,
        ua::make_error_detail("EasyConnectClientDestroyed",
          "the Client was destroyed before the discovered server certificate could be decoded",
          "client.tier1.easy_connect.certificate_decode")};
    }
    try
    {
      // The one chain parser: a GetEndpoints serverCertificate may carry the issuers after the leaf.
      auto parsed = ua::detail::parse_certificate_field(*self->crypto(), der);
      if (!parsed.is_good())
      {
        return ChainResult{parsed.status_code()};
      }
      return ChainResult{std::move(parsed).value()};
    }
    catch (...)
    {
      return ChainResult{ua::exception_to_status_code(std::current_exception())};
    }
  };

  deps.storeAccessor = [weakImpl]() -> std::shared_ptr<ua::CertificateStore>
  {
    auto self = weakImpl.lock();
    return self ? self->certificate_store() : nullptr;
  };

  deps.validate = [weakImpl](std::shared_ptr<const ua::X509Certificate> certificate,
                    std::vector<std::shared_ptr<const ua::X509Certificate>>
                      presentedIssuers,
                    std::string endpointUrl,
                    std::function<void(ua::VoidResult)>
                      verdict)
  {
    auto storeAccessor = [weakImpl]() -> std::shared_ptr<ua::CertificateStore>
    {
      auto self = weakImpl.lock();
      return self ? self->certificate_store() : nullptr;
    };
    // Same interface the managed connect path uses for re-validation, so easy-connect's verdict and the
    // channel's own OPN check agree by construction.
    ua::CertificateValidationRequest request;
    request.certificate = std::move(certificate);
    request.presentedIssuers = std::move(presentedIssuers);
    request.use = ua::CertificateUse::ServerApplicationInstance;
    if (!endpointUrl.empty())
    {
      request.endpointUrl = std::move(endpointUrl);
    }
    auto self = weakImpl.lock();
    detail::make_server_cert_revalidation(
      std::move(storeAccessor), std::move(request), self ? self->logger() : ua::Logger{})(std::move(verdict));
  };

  detail::resolve_easy_connect_async(std::move(deps),
    std::move(policy),
    [weakImpl, callback = std::move(callback)](detail::EasyConnectResolutionResult resolved) mutable
    {
      if (!resolved.is_good())
      {
        if (callback)
        {
          callback(ConnectResult{resolved.status_code(), resolved.shared_detail()});
        }
        return;
      }
      auto self = weakImpl.lock();
      if (!self)
      {
        if (callback)
        {
          callback(ConnectResult{ua::Status::BadConnectionClosed,
            ua::make_error_detail("EasyConnectClientDestroyed",
              "the Client was destroyed before the resolved connect could start",
              "client.tier1.easy_connect")});
        }
        return;
      }
      auto resolution = std::move(resolved).value();
      self->connect_async(
        std::move(resolution.config), std::move(resolution.discoveryEndpoints), std::move(callback));
    });
}

Connection Client::easy_connect_sync(EasyConnectConfig policy)
{
  return ua::detail::good_value(try_easy_connect_sync(std::move(policy)));
}

Client::ConnectResult Client::try_easy_connect_sync(EasyConnectConfig policy) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ConnectResult>(
      (mCore.mImpl ? mCore.mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(ConnectResult)> complete)
      { easy_connect_async(std::move(policy), std::move(complete)); });
  }
  catch (...)
  {
    return ConnectResult{ua::exception_to_status_code(std::current_exception())};
  }
}

Connection Client::connect_sync(ConnectionConfig config)
{
  return ua::detail::good_value(try_connect_sync(std::move(config)));
}

Client::ConnectResult Client::try_connect_sync(ConnectionConfig config) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ConnectResult>(
      (mCore.mImpl ? mCore.mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(ConnectResult)> complete)
      { connect_async(std::move(config), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

Discovery Client::discovery()
{
  if (!mCore.mImpl)
  {
    // A shut-down / moved-from Client yields an inert Discovery: every wire call fails fast with a
    // BadInvalidState ErrorDetail (run_discovery guards the null factory) and start_mdns_browse reports
    // no transport, rather than dereferencing a null impl.
    return Discovery{nullptr, nullptr, false};
  }
  return Discovery{mCore.mImpl->discovery_channel_factory(),
    mCore.mImpl->mdns_transport(),
    mCore.mImpl->configuration().allowDeprecatedSecurityPolicies};
}

void Client::set_mdns_transport(std::shared_ptr<ua::mdns::MdnsTransport> transport)
{
  if (!mCore.mImpl)
    throw_invalid_state();
  mCore.mImpl->set_mdns_transport(std::move(transport));
}

void Client::set_connection_observer(std::shared_ptr<ConnectionObserver> observer)
{
  if (!mCore.mImpl)
    throw_invalid_state();
  mCore.mImpl->set_connection_observer(std::move(observer));
}

void Client::set_subscription_observer(std::shared_ptr<SubscriptionObserver> observer)
{
  if (!mCore.mImpl)
    throw_invalid_state();
  mCore.mImpl->set_subscription_observer(std::move(observer));
}

void Client::set_security_observer(std::shared_ptr<SecurityObserver> observer)
{
  if (!mCore.mImpl)
    throw_invalid_state();
  mCore.mImpl->set_security_observer(std::move(observer));
}

void Client::set_type_observer(std::shared_ptr<TypeObserver> observer)
{
  if (!mCore.mImpl)
    throw_invalid_state();
  mCore.mImpl->set_type_observer(std::move(observer));
}

void Client::set_address_space_observer(std::shared_ptr<AddressSpaceObserver> observer)
{
  if (!mCore.mImpl)
    throw_invalid_state();
  mCore.mImpl->set_address_space_observer(std::move(observer));
}

void Client::set_server_state_observer(std::shared_ptr<ServerStateObserver> observer)
{
  if (!mCore.mImpl)
    throw_invalid_state();
  mCore.mImpl->set_server_state_observer(std::move(observer));
}

void Client::set_alarm_observer(std::shared_ptr<AlarmObserver> observer)
{
  if (!mCore.mImpl)
    throw_invalid_state();
  mCore.mImpl->set_alarm_observer(std::move(observer));
}

void Client::start_pull_cert_management_async(
  PullCertManagementConfig config, StartPullCertManagementCallback callback) noexcept
{
  if (!mCore.mImpl)
  {
    callback(PullCertificateManagerResult{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }
  try
  {
    // Pass `callback` by COPY, never std::move: this function is noexcept. If the callee unwinds into the
    // catch, std::move would have left `callback` empty and invoking it here throws out of a noexcept
    // function -> std::terminate. The callee takes the callback by value, so the copy is cheap.
    mCore.mImpl->start_pull_cert_management_async(std::move(config), callback);
  }
  catch (...)
  {
    callback(ua::exception_to_status_code(std::current_exception()));
  }
}

std::shared_ptr<PullCertificateManager> Client::start_pull_cert_management_sync(
  PullCertManagementConfig config)
{
  return ua::detail::good_value(try_start_pull_cert_management_sync(std::move(config)));
}

Client::PullCertificateManagerResult Client::try_start_pull_cert_management_sync(
  PullCertManagementConfig config) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PullCertificateManagerResult>(
      (mCore.mImpl ? mCore.mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(PullCertificateManagerResult)> complete)
      { start_pull_cert_management_async(std::move(config), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

// --- Shutdown (delegates to the composed tier-0 root, which owns the cascade) ---

void Client::shutdown_async(ShutdownCallback callback) noexcept
{
  mCore.shutdown_async(std::move(callback));
}

void Client::shutdown_sync()
{
  mCore.shutdown_sync();
}

VoidResult Client::try_shutdown_sync() noexcept
{
  return mCore.try_shutdown_sync();
}

// --- Factory ---

Client Client::create(boost::asio::any_io_executor executor, CreateConfig config, ClientComponents components)
{
  return Client{CoreClient::create(std::move(executor), std::move(config), std::move(components))};
}

Client::CreateResult Client::try_create(
  boost::asio::any_io_executor executor, CreateConfig config, ClientComponents components) noexcept
{
  auto createdCore = CoreClient::try_create(std::move(executor), std::move(config), std::move(components));
  if (!createdCore.is_good())
  {
    return CreateResult{createdCore.status_code(), createdCore.shared_detail()};
  }
  return CreateResult{Client{std::move(createdCore).value()}};
}

}  // namespace ua::client
