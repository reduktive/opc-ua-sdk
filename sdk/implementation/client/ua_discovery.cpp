// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Discovery facade implementation + the production ephemeral-channel factory (client design
/// section 7.6).

#include "ua_discovery.h"
#include "ua_discovery_channel.h"

#include "ua_core_client.h"
#include "ua_core_client_impl.h"
#include "ua_client_answer_status.h"
#include "ua_client_security_policy_gate.h"
#include "ua_client_secure_channel.h"
#include "ua_connection.h"
#include "ua_typed_access.h"

#include "ua_array.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_sync_wait.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_ref_structure.h"
#include "ua_relative_path_element.h"
#include "ua_server_on_network.h"

#include "fmt/format.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace ua::client
{

namespace
{

/// Maps a decoded discovery response to the facade result payload. `extract` maps a good response to the
/// payload `ResultT` by value (e.g. a `std::vector<ElementT>` of records, or a richer reply carrying extra
/// response fields such as FindServersOnNetwork's lastCounterResetTime  -  CL-DISC-013). Transport-bad and
/// serviceResult-bad responses surface as a source-tagged `Result<ResultT>` error (never discards the inner
/// ErrorDetail  -  the tier-0 chain is preserved as the cause). A payload carries the response's code and its
/// ServiceResult combined (@ref ua::detail::combined_status), so a Good subcode or an Uncertain code the
/// server answers reaches the caller.
template<typename ResponseT, typename ResultT, typename Extract>
ua::Result<ResultT> map_discovery_response(
  ua::Result<ResponseT> response, const std::string& url, Extract extract, const std::string& opName)
{
  if (!response.has_value())
  {
    return ua::Result<ResultT>{response.status_code(),
      ua::ErrorDetail::build(opName + "Failed", "Discovery call failed", "client.Discovery")
        .context(ua::ContextKeys::endpointUrl, url)
        .context(ua::ContextKeys::service, opName)
        .cause(response.shared_detail())};
  }

  const ResponseT& value = response.value();
  const ua::StatusCode serviceResult = value.response_header().service_result();
  if (serviceResult.is_bad())
  {
    // The tier-0 layer does not flatten a normal response's serviceResult; the facade surfaces it here
    // (CL-DISC-003 / CL-DISC-009).
    return ua::Result<ResultT>{serviceResult,
      ua::ErrorDetail::build(
        opName + "ServiceFault", "Discovery service returned an error", "client.Discovery")
        .context(ua::ContextKeys::endpointUrl, url)
        .context(ua::ContextKeys::service, opName)
        .cause(serviceResult.shared_detail())};
  }

  return ua::detail::held<ResultT>(
    extract(value), ua::detail::combined_status(response.status_code(), serviceResult));
}

/// Orchestrates one discovery query: open an ephemeral channel  to  issue the session-less request  to  close
/// the channel (on success AND on error)  to  deliver the decoded result. The `factory` shared_ptr is pinned
/// for the whole chain so a transient `Discovery` value handle going out of scope cannot pull it.
template<typename ResponseT, typename ResultT, typename Issue, typename Extract>
void run_discovery(std::shared_ptr<detail::DiscoveryChannelFactory> factory, std::string url,
  std::optional<std::chrono::milliseconds> timeout, Issue issue, Extract extract, std::string opName,
  std::function<void(ua::Result<ResultT>)> callback)
{
  if (!factory)
  {
    callback(ua::Result<ResultT>{ua::Status::BadInvalidState,
      ua::ErrorDetail::build(opName + "Failed", "discovery facade has no channel factory", "client.Discovery")
        .context(ua::ContextKeys::endpointUrl, url)});
    return;
  }

  auto* rawFactory = factory.get();
  rawFactory->open_async(url,
    timeout,
    [factory = std::move(factory),
      url,
      issue = std::move(issue),
      extract,
      opName = std::move(opName),
      callback = std::move(callback)](
      ua::Result<std::shared_ptr<detail::DiscoveryChannel>> channelResult) mutable
    {
      // The query is sent over this channel, so only a Good open is used: an Uncertain one is refused
      // (ServiceAnswerUncertain) and the channel it opened is closed.
      if (!channelResult.is_good())
      {
        const ua::StatusCode refused =
          detail::answer_refused(channelResult.status_code(), "ServiceAnswerUncertain", "client.Discovery");
        ua::Result<ResultT> failure{refused.as_status(),
          ua::ErrorDetail::build(
            "DiscoveryChannelOpenFailed", "failed to open discovery channel", "client.Discovery")
            .context(ua::ContextKeys::endpointUrl, url)
            .cause(refused.shared_detail())};
        if (!channelResult.has_value())
        {
          callback(std::move(failure));
          return;
        }
        auto opened = std::move(channelResult).value();
        detail::DiscoveryChannel* rawOpened = opened.get();
        rawOpened->close_async(
          [opened = std::move(opened), callback = std::move(callback), failure = std::move(failure)](
            ua::VoidResult) mutable { callback(std::move(failure)); });
        return;
      }

      auto channel = channelResult.value();
      issue(channel,
        [channel,
          url = std::move(url),
          extract = std::move(extract),
          opName = std::move(opName),
          callback = std::move(callback)](ua::Result<ResponseT> response) mutable
        {
          ua::Result<ResultT> outcome =
            map_discovery_response<ResponseT, ResultT>(std::move(response), url, extract, opName);
          // Close the ephemeral channel unconditionally, then deliver. The channel is the sole owner of
          // the discovery channel here, and close_async may complete asynchronously (deferred close), so
          // the close continuation captures `channel` by value to keep it alive until the close completes
          //  -  without it the channel would be destroyed while its own close_async was still in flight.
          detail::DiscoveryChannel* rawChannel = channel.get();
          rawChannel->close_async(
            [channel = std::move(channel), callback = std::move(callback), outcome = std::move(outcome)](
              ua::VoidResult) mutable { callback(std::move(outcome)); });
        });
    });
}

constexpr std::string_view gdsNamespaceUri{"http://opcfoundation.org/UA/GDS/"};
constexpr std::string_view gdsQuerySource{"client.Discovery.gds_query_servers"};

ua::RelativePath make_gds_path(
  ua::ReferenceTypeId referenceType, std::uint16_t namespaceIndex, std::string_view targetName)
{
  ua::RelativePathElement element;
  element.reference_type_id() = ua::NodeId{referenceType};
  element.include_subtypes() = true;
  element.target_name() = ua::QualifiedName{namespaceIndex, targetName};
  ua::RelativePath path;
  path.elements().push_back(std::move(element));
  return path;
}

/// The QueryServers reply decoded from the Call's answer, with the Call's code: the service's and the
/// Method's combined (@ref ua::detail::combined_status). An answer that is not Good and has no output
/// arguments is answered with the code and no reply.
ua::Result<Discovery::GdsQueryServersReply> decode_gds_query_servers(ua::Result<ua::CallResult> call)
{
  if (!call.has_value())
  {
    return ua::Result<Discovery::GdsQueryServersReply>{call.status_code(), call.shared_detail()};
  }
  const ua::StatusCode serviceCode = call.status_code();
  ua::CallResult method = std::move(call).value();
  if (!method.has_value())
  {
    return ua::Result<Discovery::GdsQueryServersReply>{method.status_code(), method.shared_detail()};
  }
  const ua::StatusCode answered = ua::detail::combined_status(serviceCode, method.status_code());

  ua::CallMethodResult methodResult = std::move(method).value();
  auto& outputs = methodResult.output_arguments();
  if (outputs.empty() && !answered.is_good())
  {
    return ua::Result<Discovery::GdsQueryServersReply>{answered};
  }
  if (outputs.size() != 2)
  {
    return ua::Result<Discovery::GdsQueryServersReply>{ua::Status::BadUnexpectedError,
      ua::ErrorDetail::build("GdsQueryServersOutputCountMismatch",
        "QueryServers returned an unexpected number of output arguments",
        std::string{gdsQuerySource})
        .context(ua::ContextKeys::sizeActual, outputs.size())
        .context(ua::ContextKeys::sizeExpected, std::size_t{2})};
  }

  try
  {
    Discovery::GdsQueryServersReply reply;
    reply.lastCounterResetTime = outputs[0].as<ua::DateTime>();
    const auto& structures = outputs[1].as<ua::Array<ua::RefStructure<ua::Structure>>>();
    reply.servers.reserve(structures.size());
    for (const auto& structure : structures)
    {
      const auto* server = dynamic_cast<const ua::ServerOnNetwork*>(structure.get());
      if (!server)
      {
        return ua::Result<Discovery::GdsQueryServersReply>{ua::Status::BadTypeMismatch,
          ua::make_error_detail("GdsQueryServersServerTypeMismatch",
            "QueryServers returned a servers element with the wrong structure type",
            std::string{gdsQuerySource})};
      }
      reply.servers.push_back(*server);
    }
    return ua::detail::held(std::move(reply), answered);
  }
  catch (...)
  {
    return ua::Result<Discovery::GdsQueryServersReply>{
      ua::exception_to_status_code(std::current_exception())};
  }
}

class GdsQueryServersFlow : public std::enable_shared_from_this<GdsQueryServersFlow>
{
public:
  GdsQueryServersFlow(std::shared_ptr<detail::DiscoveryChannelFactory> factory,
    ConnectionConfig connectionConfig, GdsServerFilter filter, Discovery::GdsQueryServersCallback callback)
    : mFactory(std::move(factory)), mConnectionConfig(std::move(connectionConfig)),
      mFilter(std::move(filter)), mCallback(std::move(callback))
  {}

  void start()
  {
    if (!mFactory)
    {
      finish(Discovery::GdsQueryServersResult{ua::Status::BadInvalidState,
        ua::make_error_detail("GdsConnectionFactoryMissing",
          "the discovery facade has no GDS connection factory",
          std::string{gdsQuerySource})});
      return;
    }
    mConnectionConfig.reconnect = std::nullopt;
    auto self = shared_from_this();
    mFactory->open_gds_async(std::move(mConnectionConfig),
      [self = std::move(self)](ua::Result<std::shared_ptr<detail::GdsConnection>> connectionResult) mutable
      {
        self->resume([self, connectionResult = std::move(connectionResult)]() mutable
          { self->on_open(std::move(connectionResult)); });
      });
  }

private:
  void on_open(ua::Result<std::shared_ptr<detail::GdsConnection>> result)
  {
    if (!result.has_value())
    {
      finish(Discovery::GdsQueryServersResult{result.status_code(), result.shared_detail()});
      return;
    }
    const ua::StatusCode opened = result.status_code();
    mConnection = std::move(result).value();
    // The query runs over this Connection, so only a Good open is used: an Uncertain one is refused
    // (ServiceAnswerUncertain) and the Connection closed.
    if (!opened.is_good())
    {
      close_then_finish(Discovery::GdsQueryServersResult{
        detail::uncertain_answer_refused(opened, "ServiceAnswerUncertain", gdsQuerySource)});
      return;
    }
    const auto namespaceTable = mConnection->namespace_table();
    const auto namespaceIndex = namespaceTable ? namespaceTable->lookup_index(gdsNamespaceUri) : std::nullopt;
    if (!namespaceIndex)
    {
      close_then_finish(Discovery::GdsQueryServersResult{ua::Status::BadNodeIdUnknown,
        ua::ErrorDetail::build("GdsNamespaceMissing",
          "the connected server does not expose the standard GDS namespace",
          std::string{gdsQuerySource})
          .context(ua::ContextKeys::namespaceUri, std::string{gdsNamespaceUri})});
      return;
    }
    mGdsNamespaceIndex = *namespaceIndex;
    auto self = shared_from_this();
    mConnection->resolve_path_async(ua::NodeId{ua::ObjectId::ObjectsFolder},
      make_gds_path(ua::ReferenceTypeId::Organizes, mGdsNamespaceIndex, "Directory"),
      [self = std::move(self)](ua::NodeIdResult translated) mutable
      {
        self->resume([self, translated = std::move(translated)]() mutable
          { self->on_directory(std::move(translated)); });
      });
  }

  void on_directory(ua::NodeIdResult translated)
  {
    auto local = require_local_node(std::move(translated), "GdsDirectoryResolutionFailed");
    if (!local.is_good())
    {
      close_then_finish(Discovery::GdsQueryServersResult{local.status_code()});
      return;
    }
    mDirectory = std::move(local).value();
    auto self = shared_from_this();
    mConnection->resolve_path_async(mDirectory,
      make_gds_path(ua::ReferenceTypeId::HasComponent, mGdsNamespaceIndex, "QueryServers"),
      [self = std::move(self)](ua::NodeIdResult method) mutable {
        self->resume([self, method = std::move(method)]() mutable { self->on_method(std::move(method)); });
      });
  }

  void on_method(ua::NodeIdResult translated)
  {
    auto local = require_local_node(std::move(translated), "GdsQueryServersResolutionFailed");
    if (!local.is_good())
    {
      close_then_finish(Discovery::GdsQueryServersResult{local.status_code()});
      return;
    }

    ua::Array<ua::String> capabilities;
    capabilities.reserve(mFilter.serverCapabilities.size());
    for (auto& capability : mFilter.serverCapabilities)
    {
      capabilities.push_back(ua::String{std::move(capability)});
    }
    std::vector<ua::Variant> arguments;
    arguments.reserve(6);
    arguments.emplace_back(mFilter.startingRecordId);
    arguments.emplace_back(mFilter.maxRecordsToReturn);
    arguments.emplace_back(ua::String{std::move(mFilter.applicationName)});
    arguments.emplace_back(ua::String{std::move(mFilter.applicationUri)});
    arguments.emplace_back(ua::String{std::move(mFilter.productUri)});
    arguments.emplace_back(std::move(capabilities));

    auto self = shared_from_this();
    mConnection->call_method_async(mDirectory,
      std::move(local).value(),
      std::move(arguments),
      [self = std::move(self)](ua::Result<ua::CallResult> result) mutable
      {
        self->resume([self, result = std::move(result)]() mutable
          { self->close_then_finish(decode_gds_query_servers(std::move(result))); });
      });
  }

  /// Names which GDS node failed to resolve, keeping the resolution's own failure as the cause. The SDK
  /// calls what this finds, so only a Good resolution is used: an Uncertain one is refused
  /// (ReferencesAnswerUncertain), and a Good subcode is consumed.
  ua::Result<ua::NodeId> require_local_node(ua::NodeIdResult resolved, std::string_view code)
  {
    if (resolved.is_good())
    {
      return ua::Result<ua::NodeId>{std::move(resolved).value()};
    }
    const ua::StatusCode failure =
      detail::answer_refused(resolved.status_code(), "ReferencesAnswerUncertain", gdsQuerySource);
    return {failure.as_status(),
      ua::ErrorDetail::build(std::string{code},
        "the standard GDS browse path did not resolve to one local node",
        std::string{gdsQuerySource})
        .cause(failure)};
  }

  void close_then_finish(Discovery::GdsQueryServersResult outcome)
  {
    auto connection = std::move(mConnection);
    if (!connection)
    {
      finish(std::move(outcome));
      return;
    }
    auto self = shared_from_this();
    connection->close_async(
      [self = std::move(self), connection = std::move(connection), outcome = std::move(outcome)](
        ua::VoidResult closeResult) mutable
      {
        self->resume(
          [self,
            connection = std::move(connection),
            outcome = std::move(outcome),
            closeResult = std::move(closeResult)]() mutable
          {
            if (outcome.is_good() && closeResult.is_bad())
            {
              self->finish(Discovery::GdsQueryServersResult{closeResult.status_code()});
              return;
            }
            self->finish(std::move(outcome));
          });
      });
  }

  template<typename Continuation>
  void resume(Continuation continuation) noexcept
  {
    try
    {
      continuation();
    }
    catch (...)
    {
      auto failure = Discovery::GdsQueryServersResult{ua::exception_to_status_code(std::current_exception())};
      try
      {
        close_then_finish(failure);
      }
      catch (...)
      {
        // close_async setup failed before taking ownership; complete through the noexcept callback boundary.
        finish(std::move(failure));
      }
    }
  }

  void finish(Discovery::GdsQueryServersResult outcome) noexcept
  {
    auto callback = std::move(mCallback);
    ua::detail::invoke_user_callback(callback, std::move(outcome));
  }

  std::shared_ptr<detail::DiscoveryChannelFactory> mFactory;
  ConnectionConfig mConnectionConfig;
  GdsServerFilter mFilter;
  Discovery::GdsQueryServersCallback mCallback;
  std::shared_ptr<detail::GdsConnection> mConnection;
  std::uint16_t mGdsNamespaceIndex{0};
  ua::NodeId mDirectory;
};

constexpr std::string_view gdsApplicationsSource{"client.Discovery.gds_query_applications"};

/// The QueryApplications reply decoded from the Call's answer, with the Call's code: the service's and the
/// Method's combined (@ref ua::detail::combined_status). An answer that is not Good and has no output
/// arguments is answered with the code and no reply.
ua::Result<Discovery::GdsQueryApplicationsReply> decode_gds_query_applications(
  ua::Result<ua::CallResult> call)
{
  if (!call.has_value())
    return {call.status_code(), call.shared_detail()};
  const ua::StatusCode serviceCode = call.status_code();
  ua::CallResult method = std::move(call).value();
  if (!method.has_value())
    return {method.status_code(), method.shared_detail()};
  const ua::StatusCode answered = ua::detail::combined_status(serviceCode, method.status_code());
  auto methodResult = std::move(method).value();
  auto& outputs = methodResult.output_arguments();
  if (outputs.empty() && !answered.is_good())
    return {answered};
  if (outputs.size() != 3)
  {
    return {ua::Status::BadUnexpectedError,
      ua::ErrorDetail::build("GdsQueryApplicationsOutputCountMismatch",
        "QueryApplications returned an unexpected number of output arguments",
        std::string{gdsApplicationsSource})
        .context(ua::ContextKeys::sizeActual, outputs.size())
        .context(ua::ContextKeys::sizeExpected, std::size_t{3})};
  }
  try
  {
    Discovery::GdsQueryApplicationsReply reply;
    reply.lastCounterResetTime = outputs[0].as<ua::DateTime>();
    reply.nextRecordId = outputs[1].as<std::uint32_t>();
    const auto& structures = outputs[2].as<ua::Array<ua::RefStructure<ua::Structure>>>();
    reply.applications.reserve(structures.size());
    for (const auto& structure : structures)
    {
      const auto* application = dynamic_cast<const ua::ApplicationDescription*>(structure.get());
      if (!application)
      {
        return {ua::Status::BadTypeMismatch,
          ua::make_error_detail("GdsQueryApplicationsTypeMismatch",
            "QueryApplications returned an applications element with the wrong structure type",
            std::string{gdsApplicationsSource})};
      }
      reply.applications.push_back(*application);
    }
    return ua::detail::held(std::move(reply), answered);
  }
  catch (...)
  {
    return {ua::exception_to_status_code(std::current_exception())};
  }
}

class GdsQueryApplicationsFlow : public std::enable_shared_from_this<GdsQueryApplicationsFlow>
{
public:
  GdsQueryApplicationsFlow(std::shared_ptr<detail::DiscoveryChannelFactory> factory,
    ConnectionConfig connectionConfig, GdsApplicationFilter filter,
    Discovery::GdsQueryApplicationsCallback callback)
    : mFactory(std::move(factory)), mConnectionConfig(std::move(connectionConfig)),
      mFilter(std::move(filter)), mCallback(std::move(callback))
  {}

  void start()
  {
    if (!mFactory)
    {
      finish({ua::Status::BadInvalidState,
        ua::make_error_detail("GdsConnectionFactoryMissing",
          "the discovery facade has no GDS connection factory",
          std::string{gdsApplicationsSource})});
      return;
    }
    mConnectionConfig.reconnect = std::nullopt;
    auto self = shared_from_this();
    mFactory->open_gds_async(std::move(mConnectionConfig),
      [self = std::move(self)](ua::Result<std::shared_ptr<detail::GdsConnection>> result) mutable
      { self->resume([self, result = std::move(result)]() mutable { self->on_open(std::move(result)); }); });
  }

private:
  void on_open(ua::Result<std::shared_ptr<detail::GdsConnection>> result)
  {
    if (!result.has_value())
    {
      finish({result.status_code(), result.shared_detail()});
      return;
    }
    const ua::StatusCode opened = result.status_code();
    mConnection = std::move(result).value();
    // The query runs over this Connection, so only a Good open is used: an Uncertain one is refused
    // (ServiceAnswerUncertain) and the Connection closed.
    if (!opened.is_good())
    {
      close_then_finish(
        {detail::uncertain_answer_refused(opened, "ServiceAnswerUncertain", gdsApplicationsSource)});
      return;
    }
    const auto namespaceTable = mConnection->namespace_table();
    const auto namespaceIndex = namespaceTable ? namespaceTable->lookup_index(gdsNamespaceUri) : std::nullopt;
    if (!namespaceIndex)
    {
      close_then_finish({ua::Status::BadNodeIdUnknown,
        ua::ErrorDetail::build("GdsNamespaceMissing",
          "the connected server does not expose the standard GDS namespace",
          std::string{gdsApplicationsSource})
          .context(ua::ContextKeys::namespaceUri, std::string{gdsNamespaceUri})});
      return;
    }
    mGdsNamespaceIndex = *namespaceIndex;
    auto self = shared_from_this();
    mConnection->resolve_path_async(ua::NodeId{ua::ObjectId::ObjectsFolder},
      make_gds_path(ua::ReferenceTypeId::Organizes, mGdsNamespaceIndex, "Directory"),
      [self = std::move(self)](ua::NodeIdResult translated) mutable
      {
        self->resume([self, translated = std::move(translated)]() mutable
          { self->on_directory(std::move(translated)); });
      });
  }

  void on_directory(ua::NodeIdResult translated)
  {
    auto local = require_local_node(std::move(translated), "GdsDirectoryResolutionFailed");
    if (!local.is_good())
    {
      close_then_finish({local.status_code(), local.shared_detail()});
      return;
    }
    mDirectory = std::move(local).value();
    auto self = shared_from_this();
    mConnection->resolve_path_async(mDirectory,
      make_gds_path(ua::ReferenceTypeId::HasComponent, mGdsNamespaceIndex, "QueryApplications"),
      [self = std::move(self)](ua::NodeIdResult method) mutable {
        self->resume([self, method = std::move(method)]() mutable { self->on_method(std::move(method)); });
      });
  }

  void on_method(ua::NodeIdResult translated)
  {
    auto local = require_local_node(std::move(translated), "GdsQueryApplicationsResolutionFailed");
    if (!local.is_good())
    {
      close_then_finish({local.status_code(), local.shared_detail()});
      return;
    }
    ua::Array<ua::String> capabilities;
    capabilities.reserve(mFilter.capabilities.size());
    for (auto& capability : mFilter.capabilities)
      capabilities.push_back(ua::String{std::move(capability)});
    std::vector<ua::Variant> arguments;
    arguments.reserve(7);
    arguments.emplace_back(mFilter.startingRecordId);
    arguments.emplace_back(mFilter.maxRecordsToReturn);
    arguments.emplace_back(ua::String{std::move(mFilter.applicationName)});
    arguments.emplace_back(ua::String{std::move(mFilter.applicationUri)});
    arguments.emplace_back(mFilter.applicationType);
    arguments.emplace_back(ua::String{std::move(mFilter.productUri)});
    arguments.emplace_back(std::move(capabilities));
    auto self = shared_from_this();
    mConnection->call_method_async(mDirectory,
      std::move(local).value(),
      std::move(arguments),
      [self = std::move(self)](ua::Result<ua::CallResult> result) mutable
      {
        self->resume([self, result = std::move(result)]() mutable
          { self->close_then_finish(decode_gds_query_applications(std::move(result))); });
      });
  }

  /// Names which GDS node failed to resolve, keeping the resolution's own failure as the cause. The SDK
  /// calls what this finds, so only a Good resolution is used: an Uncertain one is refused
  /// (ReferencesAnswerUncertain), and a Good subcode is consumed.
  ua::Result<ua::NodeId> require_local_node(ua::NodeIdResult resolved, std::string_view code)
  {
    if (resolved.is_good())
    {
      return ua::Result<ua::NodeId>{std::move(resolved).value()};
    }
    const ua::StatusCode failure =
      detail::answer_refused(resolved.status_code(), "ReferencesAnswerUncertain", gdsApplicationsSource);
    return {failure.as_status(),
      ua::ErrorDetail::build(std::string{code},
        "the standard GDS browse path did not resolve to one local node",
        std::string{gdsApplicationsSource})
        .cause(failure)};
  }

  void close_then_finish(Discovery::GdsQueryApplicationsResult outcome)
  {
    auto connection = std::move(mConnection);
    if (!connection)
    {
      finish(std::move(outcome));
      return;
    }
    auto self = shared_from_this();
    connection->close_async(
      [self = std::move(self), connection = std::move(connection), outcome = std::move(outcome)](
        ua::VoidResult closeResult) mutable
      {
        self->resume(
          [self,
            connection = std::move(connection),
            outcome = std::move(outcome),
            closeResult = std::move(closeResult)]() mutable
          {
            if (outcome.is_good() && closeResult.is_bad())
            {
              self->finish({closeResult.status_code(), closeResult.shared_detail()});
              return;
            }
            self->finish(std::move(outcome));
          });
      });
  }

  template<typename Continuation>
  void resume(Continuation continuation) noexcept
  {
    try
    {
      continuation();
    }
    catch (...)
    {
      auto failure =
        Discovery::GdsQueryApplicationsResult{ua::exception_to_status_code(std::current_exception())};
      try
      {
        close_then_finish(failure);
      }
      catch (...)
      {
        // close_async setup failed before taking ownership; complete through the noexcept callback boundary.
        finish(std::move(failure));
      }
    }
  }

  void finish(Discovery::GdsQueryApplicationsResult outcome) noexcept
  {
    auto callback = std::move(mCallback);
    ua::detail::invoke_user_callback(callback, std::move(outcome));
  }

  std::shared_ptr<detail::DiscoveryChannelFactory> mFactory;
  ConnectionConfig mConnectionConfig;
  GdsApplicationFilter mFilter;
  Discovery::GdsQueryApplicationsCallback mCallback;
  std::shared_ptr<detail::GdsConnection> mConnection;
  std::uint16_t mGdsNamespaceIndex{0};
  ua::NodeId mDirectory;
};

}  // namespace

// --- Construction ---

Discovery::Discovery(std::shared_ptr<detail::DiscoveryChannelFactory> channelFactory,
  std::shared_ptr<ua::mdns::MdnsTransport> mdnsTransport, bool allowDeprecatedSecurityPolicies)
  : mChannelFactory(std::move(channelFactory)), mMdnsTransport(std::move(mdnsTransport)),
    mAllowDeprecatedSecurityPolicies(allowDeprecatedSecurityPolicies)
{}

// --- FindServers ---

void Discovery::find_servers_async(
  std::string discoveryUrl, FindServersOptions options, FindServersCallback callback) noexcept
{
  try
  {
    ua::FindServersRequest request;
    request.endpoint_url() = discoveryUrl;  // CL-DISC-003  -  thread the caller URL verbatim.
    for (const auto& serverUri : options.serverUris)
    {
      request.server_uris().push_back(ua::String{serverUri});  // CL-DISC-008
    }
    for (const auto& locale : options.localeIds)
    {
      request.locale_ids().push_back(ua::String{locale});
    }
    if (options.timeout)
    {
      request.request_header().timeout_hint() = static_cast<uint32_t>(options.timeout->count());
    }

    run_discovery<ua::FindServersResponse, std::vector<ua::ApplicationDescription>>(
      mChannelFactory,
      std::move(discoveryUrl),
      options.timeout,
      [request = std::move(request)](std::shared_ptr<detail::DiscoveryChannel> channel,
        std::function<void(ua::Result<ua::FindServersResponse>)>
          issueCallback) mutable
      { channel->find_servers_async(std::move(request), std::move(issueCallback)); },
      [](const ua::FindServersResponse& response) {
        return std::vector<ua::ApplicationDescription>(response.servers().begin(), response.servers().end());
      },
      "FindServers",
      callback);
  }
  catch (...)
  {
    callback(FindServersResult{ua::exception_to_status_code(std::current_exception())});
  }
}

std::vector<ua::ApplicationDescription> Discovery::find_servers_sync(
  std::string discoveryUrl, FindServersOptions options)
{
  return ua::detail::good_value(try_find_servers_sync(std::move(discoveryUrl), std::move(options)));
}

Discovery::FindServersResult Discovery::try_find_servers_sync(
  std::string discoveryUrl, FindServersOptions options) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<ua::ApplicationDescription>>>(
    (mChannelFactory ? mChannelFactory->executor() : boost::asio::any_io_executor{}),
    [&](FindServersCallback callback)
    { find_servers_async(std::move(discoveryUrl), std::move(options), std::move(callback)); });
}

// --- GetEndpoints ---

void Discovery::get_endpoints_async(
  std::string discoveryUrl, GetEndpointsOptions options, GetEndpointsCallback callback) noexcept
{
  try
  {
    ua::GetEndpointsRequest request;
    request.endpoint_url() = discoveryUrl;  // CL-DISC-009  -  thread the caller URL verbatim.
    for (const auto& profile : options.profileUris)
    {
      request.profile_uris().push_back(ua::String{profile});
    }
    for (const auto& locale : options.localeIds)
    {
      request.locale_ids().push_back(ua::String{locale});
    }
    if (options.timeout)
    {
      request.request_header().timeout_hint() = static_cast<uint32_t>(options.timeout->count());
    }

    run_discovery<ua::GetEndpointsResponse, std::vector<ua::EndpointDescription>>(
      mChannelFactory,
      std::move(discoveryUrl),
      options.timeout,
      [request = std::move(request)](std::shared_ptr<detail::DiscoveryChannel> channel,
        std::function<void(ua::Result<ua::GetEndpointsResponse>)>
          issueCallback) mutable
      { channel->get_endpoints_async(std::move(request), std::move(issueCallback)); },
      [allowDeprecated = mAllowDeprecatedSecurityPolicies](const ua::GetEndpointsResponse& response)
      {
        std::vector<ua::EndpointDescription> endpoints(
          response.endpoints().begin(), response.endpoints().end());
        if (!allowDeprecated)
        {
          std::erase_if(endpoints,
            [](const ua::EndpointDescription& endpoint)
            {
              return detail::is_deprecated_client_security_policy_uri(
                std::string_view{endpoint.security_policy_uri()});
            });
        }
        else
        {
          // Explicit opt-in keeps legacy candidates, but never lets a server-provided securityLevel promote
          // them above a current policy. Within each class, higher SecurityLevel remains preferred.
          std::stable_sort(endpoints.begin(),
            endpoints.end(),
            [](const ua::EndpointDescription& left, const ua::EndpointDescription& right)
            {
              const bool leftDeprecated = detail::is_deprecated_client_security_policy_uri(
                std::string_view{left.security_policy_uri()});
              const bool rightDeprecated = detail::is_deprecated_client_security_policy_uri(
                std::string_view{right.security_policy_uri()});
              if (leftDeprecated != rightDeprecated)
              {
                return !leftDeprecated;
              }
              return left.security_level() > right.security_level();
            });
        }
        return endpoints;
      },
      "GetEndpoints",
      callback);
  }
  catch (...)
  {
    callback(GetEndpointsResult{ua::exception_to_status_code(std::current_exception())});
  }
}

std::vector<ua::EndpointDescription> Discovery::get_endpoints_sync(
  std::string discoveryUrl, GetEndpointsOptions options)
{
  return ua::detail::good_value(try_get_endpoints_sync(std::move(discoveryUrl), std::move(options)));
}

Discovery::GetEndpointsResult Discovery::try_get_endpoints_sync(
  std::string discoveryUrl, GetEndpointsOptions options) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<ua::EndpointDescription>>>(
    (mChannelFactory ? mChannelFactory->executor() : boost::asio::any_io_executor{}),
    [&](GetEndpointsCallback callback)
    { get_endpoints_async(std::move(discoveryUrl), std::move(options), std::move(callback)); });
}

// --- FindServersOnNetwork ---

void Discovery::find_servers_on_network_async(
  std::string ldsMeUrl, FindServersOnNetworkOptions options, FindServersOnNetworkCallback callback) noexcept
{
  try
  {
    ua::FindServersOnNetworkRequest request;
    request.starting_record_id() = options.startingRecordId;  // CL-DISC-013 pagination inputs.
    request.max_records_to_return() = options.maxRecordsToReturn;
    for (const auto& capability : options.serverCapabilityFilter)
    {
      request.server_capability_filter().push_back(ua::String{capability});
    }
    if (options.timeout)
    {
      request.request_header().timeout_hint() = static_cast<uint32_t>(options.timeout->count());
    }

    run_discovery<ua::FindServersOnNetworkResponse, FindServersOnNetworkReply>(
      mChannelFactory,
      std::move(ldsMeUrl),
      options.timeout,
      [request = std::move(request)](std::shared_ptr<detail::DiscoveryChannel> channel,
        std::function<void(ua::Result<ua::FindServersOnNetworkResponse>)>
          issueCallback) mutable
      { channel->find_servers_on_network_async(std::move(request), std::move(issueCallback)); },
      // CL-DISC-013: surface the response's lastCounterResetTime alongside the records so a paginating caller
      // can detect a server record-counter reset (Part 4 section 5.4.3) and re-request from
      // startingRecordId=0.
      [](const ua::FindServersOnNetworkResponse& response)
      {
        return FindServersOnNetworkReply{
          std::vector<ua::ServerOnNetwork>(response.servers().begin(), response.servers().end()),
          response.last_counter_reset_time()};
      },
      "FindServersOnNetwork",
      callback);
  }
  catch (...)
  {
    callback(FindServersOnNetworkResult{ua::exception_to_status_code(std::current_exception())});
  }
}

Discovery::FindServersOnNetworkReply Discovery::find_servers_on_network_sync(
  std::string ldsMeUrl, FindServersOnNetworkOptions options)
{
  return ua::detail::good_value(try_find_servers_on_network_sync(std::move(ldsMeUrl), std::move(options)));
}

Discovery::FindServersOnNetworkResult Discovery::try_find_servers_on_network_sync(
  std::string ldsMeUrl, FindServersOnNetworkOptions options) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<FindServersOnNetworkReply>>(
    (mChannelFactory ? mChannelFactory->executor() : boost::asio::any_io_executor{}),
    [&](FindServersOnNetworkCallback callback)
    { find_servers_on_network_async(std::move(ldsMeUrl), std::move(options), std::move(callback)); });
}

// --- GDS QueryServers ---

void Discovery::gds_query_servers_async(
  ConnectionConfig connectionConfig, GdsServerFilter filter, GdsQueryServersCallback callback) noexcept
{
  try
  {
    auto flow = std::make_shared<GdsQueryServersFlow>(
      mChannelFactory, std::move(connectionConfig), std::move(filter), callback);
    flow->start();
  }
  catch (...)
  {
    callback(GdsQueryServersResult{ua::exception_to_status_code(std::current_exception())});
  }
}

Discovery::GdsQueryServersReply Discovery::gds_query_servers_sync(
  ConnectionConfig connectionConfig, GdsServerFilter filter)
{
  return ua::detail::good_value(try_gds_query_servers_sync(std::move(connectionConfig), std::move(filter)));
}

Discovery::GdsQueryServersResult Discovery::try_gds_query_servers_sync(
  ConnectionConfig connectionConfig, GdsServerFilter filter) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<GdsQueryServersReply>>(
    (mChannelFactory ? mChannelFactory->executor() : boost::asio::any_io_executor{}),
    [this, connectionConfig = std::move(connectionConfig), filter = std::move(filter)](
      GdsQueryServersCallback callback) mutable
    { gds_query_servers_async(std::move(connectionConfig), std::move(filter), std::move(callback)); });
}

// --- GDS QueryApplications ---

void Discovery::gds_query_applications_async(ConnectionConfig connectionConfig, GdsApplicationFilter filter,
  GdsQueryApplicationsCallback callback) noexcept
{
  try
  {
    auto flow = std::make_shared<GdsQueryApplicationsFlow>(
      mChannelFactory, std::move(connectionConfig), std::move(filter), callback);
    flow->start();
  }
  catch (...)
  {
    callback(GdsQueryApplicationsResult{ua::exception_to_status_code(std::current_exception())});
  }
}

Discovery::GdsQueryApplicationsReply Discovery::gds_query_applications_sync(
  ConnectionConfig connectionConfig, GdsApplicationFilter filter)
{
  return ua::detail::good_value(
    try_gds_query_applications_sync(std::move(connectionConfig), std::move(filter)));
}

Discovery::GdsQueryApplicationsResult Discovery::try_gds_query_applications_sync(
  ConnectionConfig connectionConfig, GdsApplicationFilter filter) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<GdsQueryApplicationsReply>>(
    (mChannelFactory ? mChannelFactory->executor() : boost::asio::any_io_executor{}),
    [this, connectionConfig = std::move(connectionConfig), filter = std::move(filter)](
      GdsQueryApplicationsCallback callback) mutable
    { gds_query_applications_async(std::move(connectionConfig), std::move(filter), std::move(callback)); });
}

// --- Cached-endpoint admin (CL-DISC-001) ---

ua::Result<ua::EndpointDescription> Discovery::configure_endpoint(ManualEndpointConfig config) const noexcept
{
  // Discovery-disabled path (Part 4 section 5.4.1): build the EndpointDescription from admin params directly.
  // No channel is opened and no request is issued.
  if (config.endpointUrl.empty())
  {
    return ua::Result<ua::EndpointDescription>{ua::Status::BadInvalidArgument,
      ua::ErrorDetail::build(
        "ManualEndpointMissingField", "manual endpoint requires an endpoint URL", "client.Discovery")
        .context(ua::ContextKeys::fieldName, std::string{"endpointUrl"})};
  }
  if (config.securityPolicyUri.empty())
  {
    return ua::Result<ua::EndpointDescription>{ua::Status::BadSecurityPolicyRejected,
      ua::ErrorDetail::build(
        "ManualEndpointMissingField", "manual endpoint requires a security policy URI", "client.Discovery")
        .context(ua::ContextKeys::fieldName, std::string{"securityPolicyUri"})
        .context(ua::ContextKeys::endpointUrl, config.endpointUrl)};
  }

  auto policyValidation =
    detail::validate_client_security_policy_uri(config.securityPolicyUri, mAllowDeprecatedSecurityPolicies);
  if (policyValidation.is_bad())
  {
    return ua::Result<ua::EndpointDescription>{policyValidation.status_code()};
  }

  ua::EndpointDescription endpoint;
  endpoint.endpoint_url() = config.endpointUrl;
  endpoint.security_policy_uri() = config.securityPolicyUri;
  endpoint.security_mode() = config.securityMode;
  endpoint.server_certificate() = config.serverCertificate;
  return ua::Result<ua::EndpointDescription>{std::move(endpoint)};
}

// --- mDNS browse (CL-DISC-015 / CL-DISC-006) ---

Discovery::MdnsBrowseResult Discovery::start_mdns_browse(ua::mdns::MdnsBrowseConfig config) noexcept
{
  try
  {
    if (!mMdnsTransport)
    {
      return MdnsBrowseResult{ua::Status::BadNotSupported,
        ua::ErrorDetail::build("MdnsTransportMissing", "no mDNS transport is installed", "client.Discovery")};
    }

    const std::string serviceType = ua::mdns::service_type_for_scheme(config.scheme);
    ua::Result<std::shared_ptr<ua::mdns::MdnsBrowser>> browse =
      mMdnsTransport->start_browse(serviceType, config);
    if (browse.is_bad())
    {
      // Source-tag the transport failure; preserve its ErrorDetail as the cause (never discarded).
      return MdnsBrowseResult{browse.status_code(),
        ua::ErrorDetail::build(
          "MdnsBrowseStartFailed", "mDNS transport failed to start the browse", "client.Discovery")
          .context(ua::ContextKeys::uri, serviceType)
          .cause(browse.shared_detail())};
    }
    return browse;
  }
  catch (...)
  {
    return MdnsBrowseResult{ua::exception_to_status_code(std::current_exception())};
  }
}

// --- Production ephemeral-channel factory ---

namespace detail
{

namespace
{

/// Wraps a tier-0 `SecureChannel` as a `DiscoveryChannel`  -  forwards the session-less discovery ops and
/// close. The channel is held by value (move-only) and lives until this object is destroyed.
class SecureChannelDiscoveryChannel : public DiscoveryChannel
{
public:
  explicit SecureChannelDiscoveryChannel(SecureChannel channel) : mChannel(std::move(channel))
  {}

  void find_servers_async(ua::FindServersRequest request,
    std::function<void(ua::Result<ua::FindServersResponse>)> callback) override
  {
    mChannel.find_servers_async(std::move(request), std::move(callback));
  }

  void get_endpoints_async(ua::GetEndpointsRequest request,
    std::function<void(ua::Result<ua::GetEndpointsResponse>)> callback) override
  {
    mChannel.get_endpoints_async(std::move(request), std::move(callback));
  }

  void find_servers_on_network_async(ua::FindServersOnNetworkRequest request,
    std::function<void(ua::Result<ua::FindServersOnNetworkResponse>)> callback) override
  {
    mChannel.find_servers_on_network_async(std::move(request), std::move(callback));
  }

  void close_async(std::function<void(ua::VoidResult)> callback) override
  {
    mChannel.close_async(std::move(callback));
  }

private:
  SecureChannel mChannel;
};

class ManagedGdsConnection : public GdsConnection
{
public:
  explicit ManagedGdsConnection(Connection connection) : mConnection(std::move(connection))
  {}

  std::shared_ptr<const NamespaceTable> namespace_table() const override
  {
    return mConnection.namespace_table();
  }

  void resolve_path_async(
    ua::NodeId start, ua::RelativePath path, std::function<void(ua::NodeIdResult)> callback) override
  {
    mConnection.typed().resolve_path_async(std::move(start), std::move(path), std::move(callback));
  }

  void call_method_async(ua::NodeId object, ua::NodeId method, std::vector<ua::Variant> arguments,
    std::function<void(ua::Result<ua::CallResult>)> callback) override
  {
    mConnection.typed().call_method_async(
      std::move(object), std::move(method), std::move(arguments), std::move(callback));
  }

  void close_async(std::function<void(ua::VoidResult)> callback) override
  {
    mConnection.close_async(std::move(callback));
  }

private:
  Connection mConnection;
};

/// Opens ephemeral None-policy channels via `CoreClientImpl::open_channel_async`.
class ClientDiscoveryChannelFactory : public DiscoveryChannelFactory
{
public:
  ClientDiscoveryChannelFactory(std::weak_ptr<CoreClientImpl> client, ua::Logger logger)
    : mClient(std::move(client)), mLogger(std::move(logger))
  {}

  [[nodiscard]] boost::asio::any_io_executor executor() const override
  {
    auto client = mClient.lock();
    return client ? client->executor() : boost::asio::any_io_executor{};
  }

  void open_async(std::string discoveryUrl, std::optional<std::chrono::milliseconds> timeout,
    std::function<void(ua::Result<std::shared_ptr<DiscoveryChannel>>)> callback) override
  {
    using ChannelResult = ua::Result<std::shared_ptr<DiscoveryChannel>>;

    auto client = mClient.lock();
    if (!client)
    {
      // Wire-boundary diagnostic: log the abort before the ErrorDetail travels back through the facade
      // (the design specification  -  log at the boundary where context is richest).
      mLogger.warning({{"endpointUrl", discoveryUrl}},
        "discovery channel open aborted: owning client was destroyed before the channel opened");
      callback(ChannelResult{ua::Status::BadInvalidState,
        ua::ErrorDetail::build("DiscoveryClientGone",
          "client was destroyed before the discovery channel opened",
          "client.Discovery")
          .context(ua::ContextKeys::endpointUrl, discoveryUrl)});
      return;
    }

    CoreClient::OpenChannelConfig config;
    config.endpointUrl = discoveryUrl;  // verbatim  -  no hard-coded default (CL-DISC-002).
    config.securityMode = ua::MessageSecurityMode::None;
    config.securityPolicyId = ua::SecurityPolicyId::None;
    config.timeout = timeout;

    client->open_channel_async(std::move(config),
      [callback = std::move(callback), logger = mLogger, url = discoveryUrl](
        CoreClient::SecureChannelResult secureChannelResult) mutable
      {
        if (!secureChannelResult.has_value())
        {
          // Wire-boundary diagnostic: the underlying channel-open failed. Log it here (with the target URL
          // and status) before surfacing the source-tagged Result to the facade.
          logger.warning(
            {{"endpointUrl", url},
              {"status", fmt::format("0x{:08x}", secureChannelResult.status_code().as_uint32())}},
            "discovery channel open failed");
          callback(ChannelResult{secureChannelResult.status_code(), secureChannelResult.shared_detail()});
          return;
        }
        // The open's code (a Good subcode or an Uncertain code) travels with the channel; the facade decides.
        const ua::StatusCode opened = secureChannelResult.status_code();
        auto channel =
          std::make_shared<SecureChannelDiscoveryChannel>(std::move(secureChannelResult).value());
        callback(ua::detail::held(std::static_pointer_cast<DiscoveryChannel>(std::move(channel)), opened));
      });
  }

  void open_gds_async(ua::client::ConnectionConfig config,
    std::function<void(ua::Result<std::shared_ptr<GdsConnection>>)> callback) override
  {
    using ConnectionResult = ua::Result<std::shared_ptr<GdsConnection>>;
    auto client = mClient.lock();
    if (!client)
    {
      callback(ConnectionResult{ua::Status::BadInvalidState,
        ua::make_error_detail("GdsClientGone",
          "the Client was destroyed before the temporary GDS Connection opened",
          "client.Discovery.gds_connection")});
      return;
    }
    const std::string endpointUrl = config.endpointUrl;
    client->connect_async(std::move(config),
      [callback = std::move(callback), logger = mLogger, endpointUrl](Client::ConnectResult result) mutable
      {
        if (!result.has_value())
        {
          logger.warning({{"endpointUrl", endpointUrl},
                           {"status", fmt::format("0x{:08x}", result.status_code().as_uint32())}},
            "temporary GDS connection open failed");
          callback(ConnectionResult{result.status_code(), result.shared_detail()});
          return;
        }
        // The connect's code (a Good subcode or an Uncertain code) travels with the Connection; the flow
        // decides.
        const ua::StatusCode opened = result.status_code();
        auto connection = std::make_shared<ManagedGdsConnection>(std::move(result).value());
        callback(ua::detail::held(std::static_pointer_cast<GdsConnection>(std::move(connection)), opened));
      });
  }

private:
  std::weak_ptr<CoreClientImpl> mClient;
  ua::Logger mLogger;
};

}  // namespace

std::shared_ptr<DiscoveryChannelFactory> make_secure_channel_discovery_factory(
  std::weak_ptr<CoreClientImpl> client, ua::Logger logger)
{
  return std::make_shared<ClientDiscoveryChannelFactory>(std::move(client), std::move(logger));
}

}  // namespace detail

}  // namespace ua::client
