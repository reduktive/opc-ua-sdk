// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server.h"

#include "ua_error_detail_keys.h"
#include "ua_server_endpoint_configuration.h"
#include "ua_server_impl.h"
#include "ua_sync_wait.h"
#include "ua_address_space.h"
#include "ua_callback_safety.h"
#include "ua_conditions.h"
#include "ua_timer.h"
#include "ua_crypto.h"
#include "ua_log_sink.h"
#include "ua_to_result.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_guid.h"
#include <future>

namespace
{

[[noreturn]] void throw_invalid_state()
{
  throw ua::UaException{ua::Status::BadInvalidState, nullptr};
}

// Part 5: Server.ServerArray[0] is the local Server's URI. `AddressSpaceImpl::initialise` publishes
// this one value as both ServerArray[0] and the URI of the server's own namespace, so an empty
// applicationUri leaves both non-conformant and unaddressable rather than failing at construction.
void require_application_uri(const ua::ApplicationConfig& application)
{
  if (!application.application_description_part().applicationUri.empty())
  {
    return;
  }
  throw ua::UaException{ua::Status::BadConfigurationError,
    ua::ErrorDetail::build("ApplicationUriMissing",
      "ApplicationConfig::application_description_part().applicationUri must be a non-empty, "
      "globally unique URI: it is published as Server.ServerArray[0] and as the URI of the server's own "
      "namespace",
      "ApplicationConfiguration")};
}

// Composes a caller-supplied `<RequiredModel>` resolver with the server's built-in fallback: the
// caller's resolver (if any) is consulted first, and the server's fallback (its compiled-in NS0)
// only handles a model the caller's resolver did not. So a caller supplies just the EXTRA models it
// has, and the standard OPC UA base model is always satisfied by the server without being re-supplied.
std::function<std::unique_ptr<ua::Stream>(const ua::ModelRef&)> compose_required_model_resolver(
  std::function<std::unique_ptr<ua::Stream>(const ua::ModelRef&)> caller,
  std::function<std::unique_ptr<ua::Stream>(const ua::ModelRef&)> serverFallback)
{
  return [caller = std::move(caller), serverFallback = std::move(serverFallback)](
           const ua::ModelRef& model) -> std::unique_ptr<ua::Stream>
  {
    if (caller)
    {
      if (auto stream = caller(model))
      {
        return stream;
      }
    }
    return serverFallback ? serverFallback(model) : nullptr;
  };
}

}  // namespace

namespace ua::server
{

Server::Server(shared_ptr<ServerImpl> impl) : mImpl(std::move(impl))
{}

Server::~Server() = default;

Server Server::create(
  boost::asio::any_io_executor executor, ::ua::server::CreateConfig config, ServerComponents components)
{
  // A null ServerComponents::crypto is refused by ServerImpl::create, the one path every server takes.
  config.application.validate();
  config.server.validate();
  // DEF-2: endpoints declared in the configuration pass the same security gates add_endpoint applies.
  // Failing at create, not skipping: a skipped endpoint silently shrinks the advertised surface.
  const auto gateOrThrow = [&](
                             const ::ua::server::ServerEndpointConfig& endpoint, const std::string& ownerName)
  {
    auto gate = ::ua::server::validate_endpoint_security_gates(config.application, endpoint);
    if (!gate.is_good())
    {
      throw UaException{gate.status_code().as_status(),
        ErrorDetail::build("ConfiguredEndpointRejected",
          "An endpoint declared in the configuration fails the endpoint security gates",
          "Server")
          .context(ua::ContextKeys::listenerName, ownerName)
          .context(ua::ContextKeys::endpointName, endpoint.name)
          .cause(gate.status_code())};
    }
  };
  for (const auto& listener : config.server.listeners())
    for (const auto& endpoint : listener.endpoints)
      gateOrThrow(endpoint, listener.name);
  for (const auto& target : config.server.reverseConnectTargets)
    for (const auto& endpoint : target.endpoints)
      gateOrThrow(endpoint, target.name + " (reverse connect)");
  require_application_uri(config.application);

  ::ua::server::CombinedConfig frozen;
  frozen.identity = std::move(config.identity);
  frozen.application = std::make_shared<const ::ua::ApplicationConfig>(std::move(config.application));
  frozen.server = std::move(config.server);

  return Server(ServerImpl::create(executor, std::move(frozen), std::move(components)));
}

Server::CreateResult Server::try_create(boost::asio::any_io_executor executor,
  ::ua::server::CreateConfig config, ServerComponents components) noexcept
{
  try
  {
    return create(std::move(executor), std::move(config), std::move(components));
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

AddressSpace Server::address_space()
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->address_space();
}

const Crypto& Server::crypto() const
{
  if (!mImpl)
    throw_invalid_state();
  return *mImpl->crypto();
}

const ::ua::server::CombinedConfig& Server::config() const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->config();
}

VoidResult Server::try_start_sync() noexcept
{
  if (!mImpl)
    return VoidResult{StatusCode{Status::BadInvalidState}};
  try
  {
    // Refused before preparation is launched: blocking the executor here would prevent its completion.
    return ua::async::detail::blocking_call<VoidResult>(mImpl->executor(),
      [this](std::function<void(VoidResult)> complete) { start_async(std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void Server::start_async(CompleteCallback callback) noexcept
{
  if (!mImpl)
  {
    detail::invoke_user_callback(callback, VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  mImpl->start_async(std::move(callback));
}

void Server::start_sync()
{
  try_start_sync().value();
}

void Server::shutdown_async(ShutdownOptions params, CompleteCallback callback) noexcept
{
  if (!mImpl)
  {
    callback(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  // Direct dispatch - no strong-impl wrapper. The facade's mImpl is the sole
  // strong owner of ServerImpl; the callback is stored as-is inside
  // mShutdownCallback. ~ServerImpl is the terminal delivery point: if the
  // facade is dropped mid-grace, the destructor cancels the grace timer and
  // fires the callback once with BadServerHalted. A follow-up shutdown call
  // still reaches ServerImpl and is rejected with BadInvalidState.
  mImpl->shutdown_async(std::move(params), std::move(callback));
}

VoidResult Server::try_shutdown_sync(ShutdownOptions params) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(VoidResult)> complete)
      { shutdown_async(std::move(params), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

void Server::shutdown_sync(ShutdownOptions params)
{
  try_shutdown_sync(std::move(params)).value();
}

Conditions& Server::conditions()
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->conditions();
}

void Server::set_event_listener(std::function<void(const BaseEvent&)> listener)
{
  if (!mImpl)
    throw_invalid_state();
  mImpl->event_bus().set_event_listener(std::move(listener));
}

void Server::emit_event(BaseEvent& event)
{
  if (!mImpl)
    throw_invalid_state();

  // Resolve a companion-spec event type's namespace index from its URI (NS0
  // events carry no URI, so this is a no-op for them). The payload constructs
  // its type id namespace-index-free; the server - which owns the namespace
  // table - fills in the concrete `event_type` here, before dispatch/filtering.
  const ExpandedNodeId expandedType = event.event_type_expanded();
  if (!expandedType.namespace_uri().empty() && expandedType.node_id().is_numeric())
  {
    const uint16_t nsIndex =
      mImpl->address_space().namespace_array().get_namespace_index(expandedType.namespace_uri());
    event.eventType = NodeId{nsIndex, expandedType.node_id().identifier().get_numeric()};
  }

  mImpl->event_bus().emit(event);
}

EventSink& Server::event_sink()
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->event_bus();
}

shared_ptr<const UaBinaryDataValueCodec> Server::ua_binary_data_value_codec()
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->ua_binary_data_value_codec();
}

void Server::register_structure_type(const NodeId& encodingId, StructureFactory::CreateMethod factory)
{
  if (!mImpl)
    throw_invalid_state();
  mImpl->register_structure_type(encodingId, std::move(factory));
}

Result<NodeSetImportSummary> Server::try_import_nodeset_sync(
  shared_ptr<const NodeSetDocument> document, NodeSetImportOptions options)
{
  if (!mImpl)
    throw_invalid_state();
  if (!options.structureResolver)
    options.structureResolver = mImpl->structure_resolver();
  // Compose so a caller-supplied resolver is honoured first, with the server's own NS0 as a
  // fallback for the UA base model - the caller supplies only the extra models it has.
  options.resolveRequiredModel = compose_required_model_resolver(
    std::move(options.resolveRequiredModel), mImpl->required_model_resolver());
  return ua::try_import_nodeset_sync(mImpl->address_space(), std::move(document), std::move(options));
}

Result<NodeSetImportSummary> Server::try_import_nodeset_sync(
  const Stream& nodeset, NodeSetImportOptions options)
{
  if (!mImpl)
    throw_invalid_state();
  if (!options.structureResolver)
    options.structureResolver = mImpl->structure_resolver();
  // Compose so a caller-supplied resolver is honoured first, with the server's own NS0 as a
  // fallback for the UA base model - the caller supplies only the extra models it has.
  options.resolveRequiredModel = compose_required_model_resolver(
    std::move(options.resolveRequiredModel), mImpl->required_model_resolver());
  return ua::try_import_nodeset_sync(mImpl->address_space(), nodeset, std::move(options));
}

NodeSetImportSummary Server::import_nodeset_sync(
  shared_ptr<const NodeSetDocument> document, NodeSetImportOptions options)
{
  if (!mImpl)
    throw_invalid_state();
  if (!options.structureResolver)
    options.structureResolver = mImpl->structure_resolver();
  // Compose so a caller-supplied resolver is honoured first, with the server's own NS0 as a
  // fallback for the UA base model - the caller supplies only the extra models it has.
  options.resolveRequiredModel = compose_required_model_resolver(
    std::move(options.resolveRequiredModel), mImpl->required_model_resolver());
  return ua::import_nodeset_sync(mImpl->address_space(), std::move(document), std::move(options));
}

NodeSetImportSummary Server::import_nodeset_sync(const Stream& nodeset, NodeSetImportOptions options)
{
  if (!mImpl)
    throw_invalid_state();
  if (!options.structureResolver)
    options.structureResolver = mImpl->structure_resolver();
  // Compose so a caller-supplied resolver is honoured first, with the server's own NS0 as a
  // fallback for the UA base model - the caller supplies only the extra models it has.
  options.resolveRequiredModel = compose_required_model_resolver(
    std::move(options.resolveRequiredModel), mImpl->required_model_resolver());
  return ua::import_nodeset_sync(mImpl->address_space(), nodeset, std::move(options));
}

void Server::import_nodeset_async(shared_ptr<const NodeSetDocument> document, NodeSetImportOptions options,
  std::function<void(Result<NodeSetImportSummary>)> completion)
{
  if (!mImpl)
    throw_invalid_state();
  if (!options.structureResolver)
    options.structureResolver = mImpl->structure_resolver();
  // Compose so a caller-supplied resolver is honoured first, with the server's own NS0 as a
  // fallback for the UA base model - the caller supplies only the extra models it has.
  options.resolveRequiredModel = compose_required_model_resolver(
    std::move(options.resolveRequiredModel), mImpl->required_model_resolver());
  ua::import_nodeset_async(
    mImpl->address_space(), std::move(document), std::move(options), std::move(completion));
}

Result<dynamic_types::LoaderRegistrationStats> Server::try_register_address_space_types_sync(
  dynamic_types::TypeFilter filter)
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->try_register_address_space_types_sync(std::move(filter));
}

dynamic_types::LoaderRegistrationStats Server::register_address_space_types_sync(
  dynamic_types::TypeFilter filter)
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->register_address_space_types_sync(std::move(filter));
}

void Server::register_address_space_types_async(dynamic_types::TypeFilter filter,
  std::function<void(Result<dynamic_types::LoaderRegistrationStats>)> completion)
{
  if (!mImpl)
    throw_invalid_state();
  mImpl->register_address_space_types_async(std::move(filter), std::move(completion));
}

ListenerHandleListResult Server::try_listen_sync(
  TransportProfileId transportProfileId, string_view hostname, uint16_t port, ListenOptions options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ListenerHandleListResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(ListenerHandleListResult)> complete)
      { listen_async(transportProfileId, hostname, port, options, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

ListenerHandleList Server::listen_sync(
  TransportProfileId transportProfileId, string_view hostname, uint16_t port, ListenOptions options)
{
  return ua::detail::good_value(try_listen_sync(transportProfileId, hostname, port, options));
}

ListenerHandleResult Server::try_listen_sync(
  ua::transport::BindAddress bindAddress, ListenOptions options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ListenerHandleResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(ListenerHandleResult)> complete)
      { listen_async(std::move(bindAddress), options, std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

ListenerHandle Server::listen_sync(ua::transport::BindAddress bindAddress, ListenOptions options)
{
  return ua::detail::good_value(try_listen_sync(std::move(bindAddress), options));
}

void Server::listen_async(TransportProfileId transportProfileId, string_view hostname, uint16_t port,
  ListenOptions options, ListenCompleteManyCallback callback) noexcept
{
  if (!mImpl)
  {
    callback(ListenerHandleListResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  mImpl->listen_async(transportProfileId, hostname, port, options, std::move(callback));
}

void Server::listen_async(
  ua::transport::BindAddress bindAddress, ListenOptions options, ListenCompleteOneCallback callback) noexcept
{
  if (!mImpl)
  {
    callback(ListenerHandleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  mImpl->listen_async(std::move(bindAddress), options, std::move(callback));
}

void Server::add_endpoint(ListenerHandle listener, ServerEndpointConfig endpoint)
{
  if (!mImpl)
    throw_invalid_state();
  mImpl->add_endpoint(listener, std::move(endpoint));
}

void Server::remove_endpoint(ListenerHandle listener, ServerEndpointConfig endpoint)
{
  if (!mImpl)
    throw_invalid_state();
  mImpl->remove_endpoint(listener, std::move(endpoint));
}

std::vector<ServerEndpointConfig> Server::endpoints(ListenerHandle listener) const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->endpoints(listener);
}

ua::transport::BindAddress Server::requested_bind_address(ListenerHandle listener) const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->requested_bind_address(listener);
}

ua::transport::BindAddress Server::bound_bind_address(ListenerHandle listener) const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->bound_bind_address(listener);
}

std::vector<ua::transport::EndpointUrl> Server::advertised_urls(ListenerHandle listener) const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->advertised_urls(listener);
}

CertificateStore& Server::default_application_group_certificate_store() const
{
  if (!mImpl)
    throw_invalid_state();
  return *mImpl->default_application_group_certificate_store();
}

std::vector<std::string> Server::discovery_urls() const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->discovery_urls();
}

ApplicationDescription Server::application_description() const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->application_description();
}

std::shared_ptr<CertificateStore> Server::application_certificate_store() const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->default_application_group_certificate_store();
}

void Server::set_node_management_delegate(std::shared_ptr<NodeManagementDelegate> delegate)
{
  if (!mImpl)
    throw_invalid_state();
  mImpl->set_node_management_delegate(std::move(delegate));
}

void Server::set_observer(std::shared_ptr<ServerObserver> observer)
{
  if (!mImpl)
    throw_invalid_state();
  mImpl->set_observer(std::move(observer));
}

void Server::set_log_level(LogLevel level)
{
  if (!mImpl)
    throw_invalid_state();
  mImpl->set_log_level(level);
}

ServerHealthSnapshot Server::health_snapshot() const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->health_snapshot();
}

std::vector<SessionHealthSnapshot> Server::session_health_snapshots() const
{
  if (!mImpl)
    throw_invalid_state();
  return mImpl->session_health_snapshots();
}

// --- Reverse Connect (stubs) ---

void Server::start_reverse_connect_async(ServerConfig::ReverseConnectTarget target,
  std::function<void(ReverseConnectHandleResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ReverseConnectHandleResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  try
  {
    // Copy `callback`, do not std::move it: the impl takes it by value, so moving leaves the outer
    // `callback` empty and the catch below would invoke an empty std::function -> std::bad_function_call
    // escaping this noexcept function -> std::terminate(). The copy keeps it live for the error path.
    mImpl->start_reverse_connect_async(std::move(target), callback);
  }
  catch (...)
  {
    callback(ua::exception_to_status_code(std::current_exception()));
  }
}

ReverseConnectHandleResult Server::try_start_reverse_connect_sync(
  ServerConfig::ReverseConnectTarget target) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<ReverseConnectHandleResult>(
      (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
      [&](std::function<void(ReverseConnectHandleResult)> complete)
      { start_reverse_connect_async(std::move(target), std::move(complete)); });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

ReverseConnectHandle Server::start_reverse_connect_sync(ServerConfig::ReverseConnectTarget target)
{
  return ua::detail::good_value(try_start_reverse_connect_sync(std::move(target)));
}

void Server::stop_reverse_connect_async(
  ReverseConnectHandle handle, std::function<void(VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  try
  {
    mImpl->stop_reverse_connect_async(
      handle, callback);  // copy, not move - catch needs it live (see start_reverse_connect_async)
  }
  catch (...)
  {
    callback(ua::exception_to_status_code(std::current_exception()));
  }
}

VoidResult Server::try_stop_reverse_connect_sync(ReverseConnectHandle handle) noexcept
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

void Server::stop_reverse_connect_sync(ReverseConnectHandle handle)
{
  try_stop_reverse_connect_sync(handle).value();
}

void Server::stop_all_reverse_connects_async(std::function<void(VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  try
  {
    mImpl->stop_all_reverse_connects_async(
      callback);  // copy, not move - catch needs it live (see start_reverse_connect_async)
  }
  catch (...)
  {
    callback(ua::exception_to_status_code(std::current_exception()));
  }
}

VoidResult Server::try_stop_all_reverse_connects_sync() noexcept
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

void Server::stop_all_reverse_connects_sync()
{
  try_stop_all_reverse_connects_sync().value();
}

}  // namespace ua::server
