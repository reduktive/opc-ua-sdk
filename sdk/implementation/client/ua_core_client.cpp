// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Public client::Client method forwarding to CoreClientImpl.

#include "ua_sync_wait.h"
#include "ua_core_client.h"
#include "ua_client_config_bundle.h"
#include "ua_core_client_impl.h"
#include "ua_client_observers.h"
#include "ua_client_own_cert_validation.h"
#include "ua_connection.h"
#include "ua_connection_config.h"
#include "ua_discovery.h"

#include "ua_application_configuration.h"
#include "ua_certificate_store.h"
#include "ua_exceptions.h"
#include "ua_log_sink.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_x509_certificate.h"

#include <chrono>
#include <future>
#include <string>

namespace
{

[[noreturn]] void throw_invalid_state()
{
  throw ua::UaException{ua::Status::BadInvalidState, nullptr};
}

}  // namespace

namespace ua::client
{

CoreClient::CoreClient(std::shared_ptr<CoreClientImpl> impl) : mImpl(std::move(impl))
{}

CoreClient::~CoreClient() = default;

// --- Open channel ---

void CoreClient::open_channel_async(OpenChannelConfig config, OpenChannelCallback callback) noexcept
{
  if (!mImpl)
  {
    callback(SecureChannelResult{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }
  try
  {
    // Pass `callback` by COPY, never std::move: this function is noexcept. If the callee is or ever
    // becomes able to throw and unwinds into the catch, std::move would have left `callback` empty and
    // invoking it here throws std::bad_function_call OUT OF A noexcept FUNCTION -> std::terminate (a
    // hard crash of long-running server/client). The callee takes the callback by value (copies it),
    // so the copy costs nothing meaningful and keeps the error path always able to complete the caller.
    mImpl->open_channel_async(std::move(config), callback);
  }
  catch (...)
  {
    callback(ua::exception_to_status_code(std::current_exception()));
  }
}

SecureChannel CoreClient::open_channel_sync(OpenChannelConfig config)
{
  return ua::detail::good_value(try_open_channel_sync(std::move(config)));
}

CoreClient::SecureChannelResult CoreClient::try_open_channel_sync(OpenChannelConfig config) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<SecureChannelResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(SecureChannelResult)> complete)
      { open_channel_async(std::move(config), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

// --- Managed connect ---

// --- Reverse Connect ---

void CoreClient::start_reverse_connect_async(client::ReverseConnectListenerConfig config,
  std::function<void(client::ReverseConnectHandleResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(client::ReverseConnectHandleResult{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }
  try
  {
    mImpl->start_reverse_connect(
      std::move(config), callback);  // copy, not move - noexcept catch must never invoke an empty callback
                                     // (see open_channel_async)
  }
  catch (...)
  {
    callback(ua::exception_to_status_code(std::current_exception()));
  }
}

client::ReverseConnectHandle CoreClient::start_reverse_connect_sync(
  client::ReverseConnectListenerConfig config)
{
  return ua::detail::good_value(try_start_reverse_connect_sync(std::move(config)));
}

client::ReverseConnectHandleResult CoreClient::try_start_reverse_connect_sync(
  client::ReverseConnectListenerConfig config) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<client::ReverseConnectHandleResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(client::ReverseConnectHandleResult)> complete)
      { start_reverse_connect_async(std::move(config), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CoreClient::stop_reverse_connect_async(
  client::ReverseConnectHandle handle, std::function<void(VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(VoidResult{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }
  try
  {
    mImpl->stop_reverse_connect(handle, callback);  // copy, not move - noexcept catch must never invoke an
                                                    // empty callback (see open_channel_async)
  }
  catch (...)
  {
    callback(ua::exception_to_status_code(std::current_exception()));
  }
}

void CoreClient::stop_reverse_connect_sync(client::ReverseConnectHandle handle)
{
  try_stop_reverse_connect_sync(handle).value();
}

VoidResult CoreClient::try_stop_reverse_connect_sync(client::ReverseConnectHandle handle) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(VoidResult)> complete)
      { stop_reverse_connect_async(handle, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void CoreClient::stop_all_reverse_connects_async(std::function<void(VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(VoidResult{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }
  try
  {
    mImpl->stop_all_reverse_connects(callback);  // copy, not move - noexcept catch must never invoke an empty
                                                 // callback (see open_channel_async)
  }
  catch (...)
  {
    callback(ua::exception_to_status_code(std::current_exception()));
  }
}

void CoreClient::stop_all_reverse_connects_sync()
{
  try_stop_all_reverse_connects_sync().value();
}

VoidResult CoreClient::try_stop_all_reverse_connects_sync() noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(VoidResult)> complete)
      { stop_all_reverse_connects_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

// --- Shutdown ---
//
// Foolproof shutdown: move mImpl into the completion lambda so the facade's
// strong-ref drops as the last action of the cascade. After shutdown_async
// returns, the facade is empty; the impl is destroyed once child closes
// (reverse-connects + tracked channels) have drained.

void CoreClient::shutdown_async(ShutdownCallback callback) noexcept
{
  auto impl = std::move(mImpl);
  if (!impl)
  {
    callback(VoidResult{ua::StatusCode{ua::Status::BadInvalidState}});
    return;
  }
  auto& raw = *impl;
  raw.shutdown_async(
    [impl = std::move(impl), callback = std::move(callback)](VoidResult result) mutable
    {
      impl.reset();
      callback(std::move(result));
    });
}

void CoreClient::shutdown_sync()
{
  try_shutdown_sync().value();
}

VoidResult CoreClient::try_shutdown_sync() noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(VoidResult)> complete) { shutdown_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

// --- Type registration ---

void CoreClient::register_structure_type(
  const ua::NodeId& encodingId, ua::StructureFactory::CreateMethod factory)
{
  if (!mImpl)
    throw_invalid_state();
  mImpl->structure_factory().register_type(encodingId, std::move(factory));
}

// --- Configuration ---

const CombinedConfig& CoreClient::config() const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->config();
}

std::shared_ptr<const ua::Crypto> CoreClient::crypto() const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->crypto();
}

// --- Discovery ---

// --- Logging ---

void CoreClient::set_log_level(ua::LogLevel level)
{
  if (!mImpl)
    throw_invalid_state();
  mImpl->set_log_level(level);
}

// --- Observer registration (section 7.8) ---

// --- Pull-Model certificate management (client design section 8.1A) ---

// --- Factory ---

CoreClient CoreClient::create(
  boost::asio::any_io_executor executor, CreateConfig config, ClientComponents components)
{
  // Unprefixed create throws on failure (config-invalid or an own-cert precondition); the fallible
  // surface is try_create. value() rethrows the create-time ErrorDetail as a UaException.
  return try_create(executor, std::move(config), std::move(components)).value();
}

CoreClient::CreateResult CoreClient::try_create(
  boost::asio::any_io_executor executor, CreateConfig config, ClientComponents components) noexcept
{
  try
  {
    config.application.validate();  // throws UaException on an invalid configuration

    CombinedConfig frozen;
    frozen.identity = std::move(config.identity);
    frozen.application = std::make_shared<const ua::ApplicationConfig>(std::move(config.application));
    frozen.client = config.client;

    auto impl = CoreClientImpl::create(executor,
      std::move(frozen),
      std::move(components.crypto),
      std::move(components.applicationGroupCertificateStore),
      std::move(components.logSink),
      components.logLevel);

    // section 10.2 / Part 6 section 6.2.2 own-cert preconditions: validate every ApplicationInstance
    // certificate held by the resolved store against the configured applicationUri. A store with no own
    // certificate (a legitimate None-only client) is exempt: nothing is validated and create
    // succeeds  -  the missing-own-cert-under-security case is caught later at channel open.
    if (auto store = impl->certificate_store())
    {
      const std::string& applicationUri = impl->configuration().application_description_part().applicationUri;
      // A sync-only wait (API-4.6). The read posts to the store's strand on the executor, so it is
      // refused at once on a thread of that executor - create() called from a handler on a
      // single-threaded executor, whose one worker is the caller - and it is bounded by a deadline,
      // which catches an executor no thread is running. The deadline is generous on purpose: it must
      // never fire on a merely busy executor, only on one that cannot make progress at all.
      //
      // The outer Result is the wait's own answer and fails create; the inner one is the store's,
      // and a store failure only degrades the validation (below).
      constexpr auto ownCertReadDeadline = std::chrono::milliseconds{10'000};
      using OwnCerts = CertificateStore::ApplicationCertificateListResult;
      auto ownCertsCall = ua::async::detail::blocking_call<ua::Result<OwnCerts>>(
        impl->executor(),
        [&store](std::function<void(ua::Result<OwnCerts>)> complete)
        {
          store->get_application_certificates_async([complete = std::move(complete)](OwnCerts result)
            { complete(ua::Result<OwnCerts>{std::move(result)}); });
        },
        ownCertReadDeadline);
      if (ownCertsCall.status_code() == Status::BadTimeout)
      {
        return CreateResult{Status::BadTimeout,
          ErrorDetail::build("ExecutorNotRunning",
            "CoreClient::create timed out reading the certificate store. The executor passed to "
            "create must already be serviced by a running thread",
            "CoreClient::create")
            .context(ua::ContextKeys::limit, std::to_string(ownCertReadDeadline.count()) + "ms")};
      }
      if (!ownCertsCall.is_good())
      {
        return CreateResult{ownCertsCall.status_code()};
      }

      auto ownCerts = std::move(ownCertsCall).value();
      if (ownCerts.is_good())
      {
        for (const auto& ownCert : ownCerts.value())
        {
          if (!ownCert.certificate)
          {
            continue;
          }
          // The signer is the first issuer, as at channel open (check_own_certificate_for_endpoint).
          const ua::X509Certificate* signer =
            ownCert.issuerCertificates.empty() ? nullptr : ownCert.issuerCertificates.front().get();
          auto validation = detail::validate_own_application_certificate(applicationUri,
            *ownCert.certificate,
            signer,
            impl->configuration().allowDeprecatedSecurityPolicies);
          if (validation.is_bad())
          {
            return CreateResult{validation.status_code(), validation.shared_detail()};
          }
        }
      }
      else
      {
        // The store failed to enumerate its own certificates. Do not fail create on it  -  a
        // store-enumeration error degrades to unvalidated-but-logged, not a hard create failure  -  but
        // never silently discard the ErrorDetail (the design specification): log it at this create boundary
        // so the missed own-cert validation is diagnosable rather than invisible.
        impl->logger().warning(
          "create-time own-certificate validation skipped: the certificate store could not enumerate its "
          "application certificates ({}); the own certificate is not validated at create",
          ownCerts.shared_detail() ? ua::to_string(*ownCerts.shared_detail())
                                   : ua::to_string(ownCerts.status_code()));
      }
    }

    return CreateResult{CoreClient{std::move(impl)}};
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

}  // namespace ua::client
