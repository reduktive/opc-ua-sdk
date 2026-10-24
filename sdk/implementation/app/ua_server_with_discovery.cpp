// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// ServerWithDiscovery - convenience wrapper pairing a ua::server::Server with a
// DiscoveryRegistration driver over a single injected executor (interface lock 2.7, 3(b)).
//
// One injected boost::asio::any_io_executor reaches:
//   - ua::server::Server::create  (the served server),
//   - the ua::client::Client backing the ClientLdsRegistrar (the outbound registration channel),
//   - DiscoveryRegistration::create (the registration driver, built post-bind in start_async).
//
// Start ordering (interface lock 2.7):
//   try_start the server  ->  read post-bind discovery_urls() + application_description()
//   ->  map ApplicationDescription -> ua::RegisteredServer (is_online = true)
//   ->  seed the client trust store with certificates AND CRLs (server app-group store, or
//       ldsTrustOverride)
//   ->  DiscoveryRegistration::create(serverIdentity)  ->  registration().start_async(done).
//
// Shutdown ordering (interface lock 3(b)): registration().stop_async (bounded isOnline=false
// deregister, executor still live) -> server.shutdown_async -> release the Client. The wrapper
// does NOT own or stop the io_context - the host does - so the bounded deregister runs on a
// live executor before the server shuts down.
//
// ErrorDetail tags (highest priority - never discarded):
//   app.discovery.server_with_discovery.start_failed
//   app.discovery.server_with_discovery.registration

#include "ua_server_with_discovery.h"
#include "ua_server_with_discovery_state.h"

#include "ua_certificate_store.h"
#include "ua_sync_wait.h"
#include "ua_certificate_store_files.h"
#include "ua_core_client.h"
#include "ua_crypto.h"
#include "ua_error_detail.h"
#include "ua_lds_registrar.h"
#include "ua_owner_only_directory.h"
#include "ua_status.h"
#include "ua_to_result.h"
#include "ua_trust_list_validation_options.h"

#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"

namespace ua::app
{

namespace
{

constexpr auto sourceStartFailed = "app.discovery.server_with_discovery.start_failed";
constexpr auto sourceRegistration = "app.discovery.server_with_discovery.registration";

ua::VoidResult make_void_failure(
  ua::StatusCode status, std::string code, std::string summary, std::string source)
{
  // Build the ErrorDetail in sequential statements rather than a single fluent chain so that each
  // move into a by-value builder sink (code, source, summary) has unambiguous sequencing. Each
  // variable is moved exactly once and never read afterwards.
  auto builder =
    ua::ErrorDetail::build(std::move(code), "Server-with-discovery start failed", std::move(source));
  builder.context(ua::ContextKeys::errorMessage, std::move(summary));
  builder.cause(status);
  auto detail = std::shared_ptr<const ua::ErrorDetail>(builder);
  return ua::VoidResult{ua::StatusCode{status.value(), std::move(detail)}};
}

/// Map the server's post-bind ApplicationDescription onto a RegisteredServer wire record.
/// Field correspondence (Part 4 7.31 / 5.4.2): applicationUri->serverUri, productUri->productUri,
/// applicationName->serverNames[0], applicationType->serverType, gatewayServerUri->gatewayServerUri,
/// discoveryUrls->discoveryUrls. isOnline is set true for the live-registration cycles; the driver
/// flips it false for the bounded deregister at shutdown.
ua::RegisteredServer make_server_identity(const ua::ApplicationDescription& description)
{
  ua::RegisteredServer identity;
  identity.server_uri() = description.application_uri();
  identity.product_uri() = description.product_uri();
  identity.server_names().push_back(description.application_name());
  identity.server_type() = description.application_type();
  identity.gateway_server_uri() = description.gateway_server_uri();
  for (const auto& url : description.discovery_urls())
  {
    identity.discovery_urls().push_back(url);
  }
  identity.is_online() = true;
  return identity;
}

}  // namespace

ServerWithDiscovery::ServerWithDiscovery(boost::asio::any_io_executor executor,
  ua::server::CreateConfig serverConfig, ua::server::ServerComponents serverComponents,
  DiscoveryRegistrationConfig discoveryConfig)
  : mState(std::make_unique<State>())
{
  mState->executor = executor;
  mState->discoveryConfig = std::move(discoveryConfig);

  // The registration client uses the server's provider: one crypto provider per application, and
  // Server::create below refuses a null one.
  auto crypto = serverComponents.crypto;
  // The registrar validates LDS certificates with the server's application-group policy (revocation
  // checking included, CheckRevocationStatusOffline by default); a store created with empty options
  // skipped CRL checks the server's own store performs (security review B3-12(d)). Copied here
  // because serverConfig is moved into the server below; one copy of a 32-bit option set per wrapper.
  const ua::TrustListValidationOptions clientTrustValidationOptions =
    serverConfig.application.file_trust_list_configuration()
      .defaultApplicationGroupTrustListValidationOptions;
  mState->server = std::make_unique<ua::server::Server>(
    ua::server::Server::create(executor, std::move(serverConfig), std::move(serverComponents)));

  // Client backing the registrar. We retain a trust store handle so start_async can seed it from
  // the server's app-group store (or ldsTrustOverride) before any authenticated registration. The
  // conventional discovery case is SecurityMode::None, for which the store stays empty harmlessly.
  // A predictable path in the shared temporary directory let another local user pre-create it and
  // plant trusted certificates for the registrar (security review B3-9): the store lives in a
  // per-user, owner-only, owner-checked directory instead. Within it each wrapper has a new,
  // empty directory of its own, removed with the wrapper: seeding only adds, so a shared or reused
  // store kept every certificate and CRL any earlier run or other instance had trusted, including
  // ones since removed from this server's trust list (closing review of B3-12(d)).
  mState->clientTrustDirectory = ua::security::create_owner_only_subdirectory(
    ua::security::private_user_directory("uasdk-lds-client-trust", "ServerWithDiscovery"),
    "instance-",
    "ServerWithDiscovery");
  mState->clientCertStore = ua::CertificateStoreFiles::create(executor,
    crypto,
    {.trustListPath = mState->clientTrustDirectory,
      .validationOptions = clientTrustValidationOptions,
      .storeRejectedCertificates = false});

  ua::client::CreateConfig clientConfig{.identity = ua::ApplicationIdentity::load_default(),
    .application = ua::ApplicationConfig::load_default(),
    .client = {}};
  mState->client = std::make_shared<ua::client::CoreClient>(ua::client::CoreClient::create(executor,
    std::move(clientConfig),
    {.crypto = crypto, .applicationGroupCertificateStore = mState->clientCertStore}));

  mState->registrar = std::make_shared<ClientLdsRegistrar>(mState->client);
}

ServerWithDiscovery ServerWithDiscovery::create(boost::asio::any_io_executor executor,
  ua::server::CreateConfig serverConfig, ua::server::ServerComponents serverComponents,
  DiscoveryRegistrationConfig discoveryConfig)
{
  return ServerWithDiscovery(
    std::move(executor), std::move(serverConfig), std::move(serverComponents), std::move(discoveryConfig));
}

ServerWithDiscovery::CreateResult ServerWithDiscovery::try_create(boost::asio::any_io_executor executor,
  ua::server::CreateConfig serverConfig, ua::server::ServerComponents serverComponents,
  DiscoveryRegistrationConfig discoveryConfig) noexcept
{
  try
  {
    return ServerWithDiscovery(
      std::move(executor), std::move(serverConfig), std::move(serverComponents), std::move(discoveryConfig));
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

ServerWithDiscovery::~ServerWithDiscovery() = default;
ServerWithDiscovery::ServerWithDiscovery(ServerWithDiscovery&&) noexcept = default;
ServerWithDiscovery& ServerWithDiscovery::operator=(ServerWithDiscovery&&) noexcept = default;

void ServerWithDiscovery::start_async(std::function<void(ua::VoidResult)> done) noexcept
{
  auto state = mState.get();
  // 1. Start the server (bind listeners); discovery_urls() and application_description() are valid
  //    once it completes.
  state->server->start_async(
    [state, done = std::move(done)](ua::VoidResult started) mutable
    {
      if (started.is_bad())
      {
        done(make_void_failure(started.status_code(),
          "ServerStartFailed",
          "Failed to start the server before discovery registration",
          sourceStartFailed));
        return;
      }

      // 2. Read post-bind identity and build the RegisteredServer record.
      ua::RegisteredServer serverIdentity = make_server_identity(state->server->application_description());

      // 3. Seed the client trust store, then create + start the registration driver. Explicit
      //    ldsTrustOverride wins; otherwise mirror the server's application-group store.
      seed_client_trust(state,
        [state, serverIdentity = std::move(serverIdentity), done = std::move(done)](
          ua::VoidResult seeded) mutable
        { finish_start(state, std::move(serverIdentity), std::move(seeded), std::move(done)); });
    });
}

void ServerWithDiscovery::finish_start(State* state, ua::RegisteredServer serverIdentity,
  ua::VoidResult seeded, std::function<void(ua::VoidResult)> done) noexcept
{
  std::unique_lock lifecycle{state->lifecycleMutex};
  if (state->stopping)
  {
    lifecycle.unlock();
    // The shutdown is releasing the registrar; a driver created now would run over a null one.
    done(make_void_failure(ua::StatusCode{ua::Status::BadShutdown},
      "ServerStartFailed",
      "Shutdown began before discovery registration started",
      sourceStartFailed));
    return;
  }
  if (seeded.is_bad())
  {
    lifecycle.unlock();
    done(make_void_failure(seeded.status_code(),
      "ServerStartFailed",
      "Failed to seed client trust before discovery registration",
      sourceStartFailed));
    return;
  }
  state->registration = DiscoveryRegistration::create(
    state->executor, state->registrar, std::move(serverIdentity), state->discoveryConfig);
  // Posted under the lock, so a stop the shutdown posts afterwards lands behind it on the strand;
  // releasing it first would let that stop overtake the start. Only a post that fails runs @p done here,
  // under the lock, and the lock is recursive for a done that calls shutdown_async on this thread.
  state->registration->start_async(std::move(done));
}

namespace
{

/// One asynchronous seeding step: starts its store operation and calls the continuation when it
/// completes, whatever the outcome.
using TrustStep = std::function<void(std::function<void()> next)>;

/// Runs @p steps in order, each after the previous one completed, then @p finished. One store
/// operation in flight at a time, so the lists land in the order they are listed.
void run_trust_steps(
  std::shared_ptr<std::vector<TrustStep>> steps, size_t index, std::function<void()> finished)
{
  if (index >= steps->size())
  {
    finished();
    return;
  }
  const auto& step = (*steps)[index];
  step([steps, index, finished = std::move(finished)]() mutable
    { run_trust_steps(steps, index + 1, std::move(finished)); });
}

/// The steps that add @p material to @p store; an empty list adds no step.
std::shared_ptr<std::vector<TrustStep>> add_trust_steps(
  std::shared_ptr<ua::CertificateStore> store, std::shared_ptr<TrustOverride> material)
{
  auto steps = std::make_shared<std::vector<TrustStep>>();
  if (!material->trustedCertificates.empty())
  {
    steps->push_back(
      [store, material](std::function<void()> next)
      {
        store->add_to_trusted_certificates_async(
          material->trustedCertificates, [next](ua::VoidResult) { next(); });
      });
  }
  if (!material->issuerCertificates.empty())
  {
    steps->push_back(
      [store, material](std::function<void()> next)
      {
        store->add_to_issuer_certificates_async(
          material->issuerCertificates, [next](ua::VoidResult) { next(); });
      });
  }
  if (!material->trustedCrls.empty())
  {
    steps->push_back([store, material](std::function<void()> next)
      { store->add_to_trusted_crls_async(material->trustedCrls, [next](ua::VoidResult) { next(); }); });
  }
  if (!material->issuerCrls.empty())
  {
    steps->push_back([store, material](std::function<void()> next)
      { store->add_to_issuer_crls_async(material->issuerCrls, [next](ua::VoidResult) { next(); }); });
  }
  return steps;
}

/// The steps that read @p store's trusted and issuer certificates and CRLs into @p material. A list
/// that cannot be read is left empty.
std::shared_ptr<std::vector<TrustStep>> mirror_trust_steps(
  std::shared_ptr<ua::CertificateStore> store, std::shared_ptr<TrustOverride> material)
{
  auto steps = std::make_shared<std::vector<TrustStep>>();
  steps->push_back(
    [store, material](std::function<void()> next)
    {
      store->get_trusted_certificates_async(
        [material, next](ua::CertificateListResult result)
        {
          if (result.is_good())
            material->trustedCertificates = std::move(result).value();
          next();
        });
    });
  steps->push_back(
    [store, material](std::function<void()> next)
    {
      store->get_issuer_certificates_async(
        [material, next](ua::CertificateListResult result)
        {
          if (result.is_good())
            material->issuerCertificates = std::move(result).value();
          next();
        });
    });
  steps->push_back(
    [store, material](std::function<void()> next)
    {
      store->get_trusted_crls_async(
        [material, next](ua::CrlListResult result)
        {
          if (result.is_good())
            material->trustedCrls = std::move(result).value();
          next();
        });
    });
  steps->push_back(
    [store, material](std::function<void()> next)
    {
      store->get_issuer_crls_async(
        [material, next](ua::CrlListResult result)
        {
          if (result.is_good())
            material->issuerCrls = std::move(result).value();
          next();
        });
    });
  return steps;
}

}  // namespace

void ServerWithDiscovery::seed_client_trust(State* state, std::function<void(ua::VoidResult)> seeded) noexcept
{
  // Building the step closures can throw (e.g. bad_alloc when a std::function heap-allocates), and
  // this is noexcept: `seeded` is captured BY COPY into the steps so that if construction or dispatch
  // throws, the surviving original still reports the failure rather than the error being dropped.
  //
  // The client store validates with the server's revocation policy (security review B3-12(d)), so
  // the CRLs are seeded with the certificates: a CA-issued LDS certificate whose CRL is missing
  // would be refused as revocation-unknown. Cost: one read and one add per list, once per start.
  // nosemgrep: use-after-move-in-catch (deliberate copy-before-move; surviving original reports failure)
  try
  {
    auto clientStore = state->clientCertStore;
    const auto seedFrom = [clientStore, seeded](std::shared_ptr<TrustOverride> material)
    {
      run_trust_steps(add_trust_steps(clientStore, material), 0, [seeded] { seeded(ua::VoidResult{}); });
    };

    const auto& ldsTrustOverride = state->discoveryConfig.ldsTrustOverride;
    if (ldsTrustOverride.has_value())
    {
      seedFrom(std::make_shared<TrustOverride>(*ldsTrustOverride));
      return;
    }

    auto serverStore = state->server->application_certificate_store();
    if (!serverStore)
    {
      seeded(ua::VoidResult{});
      return;
    }

    auto material = std::make_shared<TrustOverride>();
    run_trust_steps(
      mirror_trust_steps(serverStore, material), 0, [seedFrom, material] { seedFrom(material); });
  }
  catch (...)
  {
    seeded(ua::VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

ua::server::Server& ServerWithDiscovery::server() noexcept
{
  return *mState->server;
}

DiscoveryRegistration& ServerWithDiscovery::registration()
{
  if (!mState || !mState->registration)
  {
    throw ua::UaException{ua::Status::BadInvalidState,
      ua::make_error_detail("RegistrationNotStarted",
        "the discovery-registration driver exists only after start_async has succeeded",
        sourceRegistration)};
  }
  return *mState->registration;
}

void ServerWithDiscovery::start_sync()
{
  try_start_sync().value();
}

ua::VoidResult ServerWithDiscovery::try_start_sync() noexcept
{
  return ua::async::detail::blocking_call<ua::VoidResult>(
    mState->executor, [this](auto completion) { start_async(std::move(completion)); });
}

void ServerWithDiscovery::shutdown_sync(ua::server::ShutdownOptions options)
{
  try_shutdown_sync(std::move(options)).value();
}

ua::VoidResult ServerWithDiscovery::try_shutdown_sync(ua::server::ShutdownOptions options) noexcept
{
  return ua::async::detail::blocking_call<ua::VoidResult>(mState->executor,
    [this, &options](auto completion) { shutdown_async(std::move(options), std::move(completion)); });
}

void ServerWithDiscovery::shutdown_async(std::function<void(ua::VoidResult)> done) noexcept
{
  shutdown_async(ua::server::ShutdownOptions{}, std::move(done));
}

void ServerWithDiscovery::shutdown_async(
  ua::server::ShutdownOptions options, std::function<void(ua::VoidResult)> done) noexcept
{
  auto state = mState.get();
  std::shared_ptr<DiscoveryRegistration> discoveryRegistration;
  {
    const std::lock_guard lifecycle{state->lifecycleMutex};
    state->stopping = true;
    discoveryRegistration = state->registration;
  }

  // 1. Bounded final deregister (isOnline=false) while the executor is still live.
  auto afterDeregister = [state, options = std::move(options), done = std::move(done)](ua::VoidResult) mutable
  {
    // 2. Shut the server down.
    auto afterServer = [state, done = std::move(done)](ua::VoidResult serverResult) mutable
    {
      // 3. Release the client (tears down the registrar's long-lived channel owner).
      if (state->client)
      {
        auto client = state->client;
        client->shutdown_async(
          [state, done = std::move(done), serverResult](ua::VoidResult) mutable
          {
            state->client.reset();
            state->registrar.reset();
            done(serverResult);
          });
        return;
      }
      done(serverResult);
    };

    state->server->shutdown_async(std::move(options), std::move(afterServer));
  };

  if (discoveryRegistration)
  {
    discoveryRegistration->stop_async(std::move(afterDeregister));
  }
  else
  {
    afterDeregister(ua::VoidResult{});
  }
}

}  // namespace ua::app
