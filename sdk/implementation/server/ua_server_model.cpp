// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_server_model.h"
#include "ua_whole_value_source.h"

#include "ua_self_owning_operation.h"

#include "ua_server_diagnostics_summary_data_type.h"

#include "ua_aggregate_descriptions.h"
#include "ua_aggregate_registry.h"
#include "ua_array.h"
#include "ua_build_info.h"
#include "ua_date_time.h"
#include "ua_namespace_history_delegate.h"
#include "ua_localized_text.h"
#include "ua_log_exception.h"
#include "ua_namespace.h"
#include "ua_qualified_name.h"
#include "ua_server_state.h"
#include "ua_string.h"
#include "ua_server_status_data_type.h"
#include "ua_logger.h"
#include "ua_node.h"
#include "ua_node_accessor_route.h"
#include "ua_namespace_items.h"
#include "ua_namespace_route.h"
#include "ua_sync_wait.h"
#include "ua_weak_address_space.h"
#include "ua_method_id.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_server_config_bundle.h"
#include "ua_server_counters.h"
#include "ua_to_result.h"
#include "ua_variable_id.h"
#include "ua_subscription_router.h"
#include "ua_server_session.h"
#include "ua_session_diagnostics_helper.h"
#include "ua_session_diagnostics_data_type.h"
#include "ua_session_security_diagnostics_data_type.h"
#include "ua_subscription.h"
#include "ua_subscription_diagnostics_data_type.h"
#include "ua_subscription_diagnostics_node_manager.h"
#include "ua_sampling_interval_diagnostics_data_type.h"
#include "ua_sampling_interval_diagnostics_node_manager.h"

#include <algorithm>
#include "ua_ref_structure.h"

#include <cassert>
#include <cctype>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string_view>

namespace ua::server
{

namespace
{

void wire_server_array_handler(AddressSpace addressSpace, Logger logger)
{
  auto result = addressSpace.try_find_node_sync(NodeId{VariableId::Server_ServerArray});
  assert(result.is_good());
  auto* target = result.value()->external_value_source();
  assert(target);
  auto weakAs = addressSpace.weak();
  target->set_value_source(detail::whole_value_source(
    [weakAs, logger](
      const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete) mutable
    {
      try
      {
        auto as = weakAs.lock();
        if (!as)
        {
          DataValue dv;
          dv.status() = StatusCode{Status::BadInternalError};
          complete(std::move(dv));
          return;
        }
        DataValue dataValue;
        dataValue.source_timestamp() = DateTime::now();
        dataValue.value() = as->server_array().get_server_array();
        complete(std::move(dataValue));
      }
      catch (...)
      {
        auto er = ua::exception_to_status_code(std::current_exception());
        log_exception(logger, LogLevel::Warning, "wire_server_array_handler", er);
        DataValue dv;
        dv.status() = er;
        complete(std::move(dv));
      }
    }));
}

void wire_namespace_array_handler(AddressSpace addressSpace, Logger logger)
{
  auto result = addressSpace.try_find_node_sync(NodeId{VariableId::Server_NamespaceArray});
  assert(result.is_good());
  auto* target = result.value()->external_value_source();
  assert(target);
  auto weakAs = addressSpace.weak();
  target->set_value_source(detail::whole_value_source(
    [weakAs, logger](
      const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete) mutable
    {
      try
      {
        auto as = weakAs.lock();
        if (!as)
        {
          DataValue dv;
          dv.status() = StatusCode{Status::BadInternalError};
          complete(std::move(dv));
          return;
        }
        DataValue dataValue;
        dataValue.source_timestamp() = DateTime::now();
        dataValue.value() = as->namespace_array().get_namespace_array();
        complete(std::move(dataValue));
      }
      catch (...)
      {
        auto er = ua::exception_to_status_code(std::current_exception());
        log_exception(logger, LogLevel::Warning, "wire_namespace_array_handler", er);
        DataValue dv;
        dv.status() = er;
        complete(std::move(dv));
      }
    }));
}

void wire_current_time_handler(AddressSpace addressSpace, Logger logger)
{
  auto result = addressSpace.try_find_node_sync(NodeId{VariableId::Server_ServerStatus_CurrentTime});
  assert(result.is_good());
  auto* target = result.value()->external_value_source();
  assert(target);
  target->set_value_source(detail::whole_value_source(
    [logger](
      const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete) mutable
    {
      try
      {
        auto now = DateTime::now();
        DataValue dataValue;
        dataValue.source_timestamp() = now;
        dataValue.value() = Variant{now};
        complete(std::move(dataValue));
      }
      catch (...)
      {
        auto er = ua::exception_to_status_code(std::current_exception());
        log_exception(logger, LogLevel::Warning, "wire_current_time_handler", er);
        DataValue dv;
        dv.status() = er;
        complete(std::move(dv));
      }
    }));
}

void wire_server_status_state_handler(
  AddressSpace addressSpace, std::shared_ptr<ServerDynamicState> state, Logger logger)
{
  auto result = addressSpace.try_find_node_sync(NodeId{VariableId::Server_ServerStatus_State});
  if (!result)
  {
    logger.warning({}, "Could not find Server_ServerStatus_State node for dynamic handler");
    return;
  }
  auto* evs = result.value()->external_value_source();
  if (!evs)
    return;
  evs->set_value_source(detail::whole_value_source(
    [state](const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
    {
      DataValue dv;
      dv.value() = Variant{utils::to_underlying(state->serverState.load())};
      dv.server_timestamp() = DateTime::now();
      dv.source_timestamp() = DateTime::now();
      complete(std::move(dv));
    }));
}

void wire_seconds_till_shutdown_handler(
  AddressSpace addressSpace, std::shared_ptr<ServerDynamicState> state, Logger logger)
{
  auto result = addressSpace.try_find_node_sync(NodeId{VariableId::Server_ServerStatus_SecondsTillShutdown});
  if (!result)
  {
    logger.warning({}, "Could not find Server_ServerStatus_SecondsTillShutdown node for dynamic handler");
    return;
  }
  auto* evs = result.value()->external_value_source();
  if (!evs)
    return;
  evs->set_value_source(detail::whole_value_source(
    [state](const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
    {
      DataValue dv;
      dv.value() = Variant{state->secondsTillShutdown.load()};
      dv.server_timestamp() = DateTime::now();
      dv.source_timestamp() = DateTime::now();
      complete(std::move(dv));
    }));
}

void wire_shutdown_reason_handler(
  AddressSpace addressSpace, std::shared_ptr<ServerDynamicState> state, Logger logger)
{
  auto result = addressSpace.try_find_node_sync(NodeId{VariableId::Server_ServerStatus_ShutdownReason});
  if (!result)
  {
    logger.warning({}, "Could not find Server_ServerStatus_ShutdownReason node for dynamic handler");
    return;
  }
  auto* evs = result.value()->external_value_source();
  if (!evs)
    return;
  evs->set_value_source(detail::whole_value_source(
    [state](const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
    {
      DataValue dv;
      {
        const std::shared_lock lk(state->mutex);
        dv.value() = Variant{state->shutdownReason};
      }
      dv.server_timestamp() = DateTime::now();
      dv.source_timestamp() = DateTime::now();
      complete(std::move(dv));
    }));
}

void wire_service_level_handler(
  AddressSpace addressSpace, std::shared_ptr<ServerDynamicState> state, Logger logger)
{
  auto result = addressSpace.try_find_node_sync(NodeId{VariableId::Server_ServiceLevel});
  if (!result)
  {
    logger.warning({}, "Could not find Server_ServiceLevel node for dynamic handler");
    return;
  }
  auto* evs = result.value()->external_value_source();
  if (!evs)
    return;
  evs->set_value_source(detail::whole_value_source(
    [state](const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
    {
      DataValue dv;
      dv.value() = Variant{state->serviceLevel.load()};
      dv.server_timestamp() = DateTime::now();
      dv.source_timestamp() = DateTime::now();
      complete(std::move(dv));
    }));
}

void wire_start_time_handler(
  AddressSpace addressSpace, std::shared_ptr<ServerDynamicState> state, Logger logger)
{
  auto result = addressSpace.try_find_node_sync(NodeId{VariableId::Server_ServerStatus_StartTime});
  if (!result)
  {
    logger.warning({}, "Could not find Server_ServerStatus_StartTime node for dynamic handler");
    return;
  }
  auto* evs = result.value()->external_value_source();
  if (!evs)
    return;
  evs->set_value_source(detail::whole_value_source(
    [state](const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
    {
      DataValue dv;
      dv.value() = Variant{state->startTime};
      dv.server_timestamp() = DateTime::now();
      dv.source_timestamp() = DateTime::now();
      complete(std::move(dv));
    }));
}

void wire_server_status_handler(
  AddressSpace addressSpace, std::shared_ptr<ServerDynamicState> state, Logger logger)
{
  auto result = addressSpace.try_find_node_sync(NodeId{VariableId::Server_ServerStatus});
  if (!result)
  {
    logger.warning({}, "Could not find Server_ServerStatus node for dynamic handler");
    return;
  }
  auto* evs = result.value()->external_value_source();
  if (!evs)
    return;
  evs->set_value_source(detail::whole_value_source(
    [state](const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
    {
      ServerStatusDataType status;
      status.start_time() = state->startTime;
      status.current_time() = DateTime::now();
      status.state() = state->serverState.load();
      status.build_info() = state->buildInfo;
      status.seconds_till_shutdown() = state->secondsTillShutdown.load();
      {
        const std::shared_lock lk(state->mutex);
        status.shutdown_reason() = state->shutdownReason;
      }
      DataValue dv;
      dv.value() = Variant{std::move(status)};
      dv.server_timestamp() = DateTime::now();
      complete(std::move(dv));
    }));
}

/// The write of a static Value, with a SourceTimestamp: the time the value was established.
///
/// A client reading with TimestampsToReturn Source or Both expects one (UACTT finding F1b - GetEndpoints
/// 002/004 read LocaleIdArray with Source requested and rejected the response when it was absent).
WriteValue static_value(VariableId id, Variant value)
{
  WriteValue write;
  write.node_id() = NodeId{id};
  write.attribute_id() = utils::to_underlying(AttributeId::Value);
  write.value().value() = std::move(value);
  write.value().source_timestamp() = DateTime::now();
  return write;
}

/// The server's own writes of @p writes in one batch each step (NR-31's phases): one lookup of their Nodes,
/// then one write through the route, no caller. @p done receives one answer per write, in write order: the
/// lookup's failure for a Node not found, otherwise the write's answer. Nothing here holds the address space
/// while a namespace answers; an address space already gone answers every write `Bad_Shutdown`
/// (AddressSpaceGone).
void write_in_one_batch(const WeakAddressSpace& addressSpace, std::vector<WriteValue> writes,
  std::function<void(std::vector<VoidResult>)> done)
{
  auto owner = addressSpace.lock();
  if (!owner)
  {
    done(std::vector<VoidResult>(writes.size(), VoidResult{::ua::detail::address_space_gone("ServerModel")}));
    return;
  }
  std::vector<NodeId> nodeIds;
  nodeIds.reserve(writes.size());
  for (const auto& write : writes)
  {
    nodeIds.push_back(write.node_id());
  }
  owner->find_nodes_async(nodeIds,
    [writes = std::move(writes), done = std::move(done)](BatchResult<NodeAccessorResult> found) mutable
    {
      std::vector<VoidResult> answers(writes.size());
      std::vector<std::size_t> sent;
      std::vector<::ua::detail::ValueWrite> valueWrites;
      for (std::size_t i = 0; i < writes.size(); ++i)
      {
        // The server writes only into a Node the namespace found without doubt: an Uncertain answer, with or
        // without the Node, is refused.
        if (!found.batchStatus.is_good())
        {
          answers[i] = VoidResult{::ua::detail::lookup_failure(
            writes[i].node_id(), found.batchStatus.status_code(), "ServerModel")};
        }
        else if (i >= found.items.size() || !found.items[i].is_good())
        {
          answers[i] = i < found.items.size()
                         ? VoidResult{::ua::detail::lookup_failure(
                             writes[i].node_id(), found.items[i].status_code(), "ServerModel")}
                         : VoidResult{Status::BadInternalError};
        }
        else
        {
          sent.push_back(i);
          valueWrites.push_back(
            ::ua::detail::ValueWrite{std::move(found.items[i]).value(), std::move(writes[i])});
        }
      }
      if (valueWrites.empty())
      {
        done(std::move(answers));
        return;
      }
      ::ua::detail::NodeAccessorRoute::write_values(RequestInfo{},
        nullptr,
        std::move(valueWrites),
        [answers = std::move(answers), sent = std::move(sent), done = std::move(done)](
          std::vector<VoidResult> written) mutable
        {
          for (std::size_t k = 0; k < sent.size() && k < written.size(); ++k)
          {
            answers[sent[k]] = std::move(written[k]);
          }
          done(std::move(answers));
        });
    });
}

/// The position of the first failed answer in @p answers, if any.
std::optional<std::size_t> first_failure(const std::vector<VoidResult>& answers)
{
  const auto failed = std::ranges::find_if(answers, [](const VoidResult& answer) { return answer.is_bad(); });
  if (failed == answers.end())
  {
    return std::nullopt;
  }
  return numeric_cast<std::size_t>(failed - answers.begin());
}

void write_static_value(std::vector<WriteValue>& writes, VariableId id, Variant value)
{
  writes.push_back(static_value(id, std::move(value)));
}

void write_optional_uint32(
  AddressSpace& addressSpace, std::vector<WriteValue>& writes, VariableId id, optional<uint32_t> value)
{
  if (value)
  {
    write_static_value(writes, id, Variant{*value});
    return;
  }
  // An optional limit the Server does not impose is not advertised -- `ServerConfig`'s own
  // documentation says nullopt means "not advertised / treated as unbounded", and OPC 10000-5 states
  // the obligation over PRESENCE: where the Server imposes no maximum, the Property shall not be
  // provided. Leaving the NS0 node in place with no value publishes a Property a Client reads as an
  // unanswerable limit rather than as an absent one, which is the opposite of what nullopt means.
  (void)addressSpace.try_delete_node_sync(NodeId{id}, /*deleteForwardHierarchicallyReferencedNodes=*/true);
}

void write_server_capabilities(
  AddressSpace& addressSpace, std::vector<WriteValue>& writes, const ServerConfig::ServerCapabilities& caps)
{
  write_static_value(writes,
    VariableId::Server_ServerCapabilities_MinSupportedSampleRate,
    Variant{caps.minSupportedSampleRate});
  write_static_value(writes,
    VariableId::Server_ServerCapabilities_MaxBrowseContinuationPoints,
    Variant{caps.maxBrowseContinuationPoints});
  write_static_value(writes,
    VariableId::Server_ServerCapabilities_MaxQueryContinuationPoints,
    Variant{caps.maxQueryContinuationPoints});
  write_static_value(writes,
    VariableId::Server_ServerCapabilities_MaxHistoryContinuationPoints,
    Variant{caps.maxHistoryContinuationPoints});
  write_optional_uint32(
    addressSpace, writes, VariableId::Server_ServerCapabilities_MaxArrayLength, caps.maxArrayLength);
  write_optional_uint32(
    addressSpace, writes, VariableId::Server_ServerCapabilities_MaxStringLength, caps.maxStringLength);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_MaxByteStringLength,
    caps.maxByteStringLength);
  write_optional_uint32(
    addressSpace, writes, VariableId::Server_ServerCapabilities_MaxSessions, caps.maxSessions);
  write_optional_uint32(
    addressSpace, writes, VariableId::Server_ServerCapabilities_MaxSubscriptions, caps.maxSubscriptions);
  write_optional_uint32(
    addressSpace, writes, VariableId::Server_ServerCapabilities_MaxMonitoredItems, caps.maxMonitoredItems);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_MaxSubscriptionsPerSession,
    caps.maxSubscriptionsPerSession);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_MaxMonitoredItemsPerSubscription,
    caps.maxMonitoredItemsPerSubscription);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_MaxSelectClauseParameters,
    caps.maxSelectClauseParameters);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_MaxWhereClauseParameters,
    caps.maxWhereClauseParameters);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_MaxMonitoredItemsQueueSize,
    caps.maxMonitoredItemsQueueSize);

  // OperationLimits
  const auto& ol = caps.operationLimits;
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRead,
    ol.maxNodesPerRead);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadData,
    ol.maxNodesPerHistoryReadData);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadEvents,
    ol.maxNodesPerHistoryReadEvents);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerWrite,
    ol.maxNodesPerWrite);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateData,
    ol.maxNodesPerHistoryUpdateData);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateEvents,
    ol.maxNodesPerHistoryUpdateEvents);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall,
    ol.maxNodesPerMethodCall);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse,
    ol.maxNodesPerBrowse);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerRegisterNodes,
    ol.maxNodesPerRegisterNodes);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIds,
    ol.maxNodesPerTranslateBrowsePathsToNodeIds);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_OperationLimits_MaxNodesPerNodeManagement,
    ol.maxNodesPerNodeManagement);
  write_optional_uint32(addressSpace,
    writes,
    VariableId::Server_ServerCapabilities_OperationLimits_MaxMonitoredItemsPerCall,
    ol.maxMonitoredItemsPerCall);

  // Mandatory ServerCapabilities array properties (OPC 10000-5 6.3.1, OPC 10000-7). These are
  // imported from NS0 with no value; reading a value-less Variable's Value returns
  // BadAttributeIdInvalid, which (UACTT finding F1) cascades into every Discovery test's setup.
  // Populate them explicitly so the Value read returns Good - empty arrays are valid values.
  auto toStringArray = [](const std::vector<std::string>& items)
  {
    Array<String> out;
    out.payload().reserve(items.size());
    for (const auto& item : items)
    {
      out.payload().push_back(String{item});
    }
    return out;
  };
  write_static_value(writes,
    VariableId::Server_ServerCapabilities_ServerProfileArray,
    Variant{toStringArray(caps.serverProfiles)});
  write_static_value(
    writes, VariableId::Server_ServerCapabilities_LocaleIdArray, Variant{toStringArray(caps.localeIds)});
  // SoftwareCertificates is an array of structures (SignedSoftwareCertificate); structure arrays
  // go into a Variant as Array<RefStructure<Structure>> (the empty case - the server signs no
  // software certificates).
  write_static_value(writes,
    VariableId::Server_ServerCapabilities_SoftwareCertificates,
    Variant{Array<RefStructure<Structure>>{}});
  write_static_value(
    writes, VariableId::Server_ServerCapabilities_ConformanceUnits, Variant{Array<QualifiedName>{}});
}

bool has_language_translation(const LocalizedText& description, string_view language)
{
  for (const auto& [locale, text] : description.translations())
  {
    const auto [translationLanguage, region] =
      LocalizedText::parse_locale_id(static_cast<string_view>(locale));
    UA_UNUSED(region);
    if (static_cast<string_view>(translationLanguage) == language && !text.empty())
    {
      return true;
    }
  }
  return false;
}

/// Populates HistoryServerCapabilities (and the Server's default HA configuration) from the registered
/// namespaces' history delegates.
///
/// A coroutine on its own strand because it runs from the start continuation on the Server's strand: every
/// lookup, write and Reference change is awaited, never waited on, and each is one batch (NR-31's phases):
/// the static Values, the aggregates' Description translations, and the AggregateFunctions folders'
/// Organizes. The operation holds the address space weakly (CALLS-21 rule 1): one gone before a step fails
/// the start with AddressSpaceGone. Failures are what they were - a missing standard node or an
/// untranslatable advertised locale fails the start - and are raised as exceptions inside the body, which the
/// body turns into the answer.
class HistoryCapabilitiesOperation final : public ua::async::SelfOwningOperation<HistoryCapabilitiesOperation>
{
public:
  static void start(AddressSpace addressSpace, ServerConfig::HistoryConfig historyConfiguration,
    ServerConfig::ServerCapabilities serverCapabilities, std::function<void(VoidResult)> done)
  {
    launch(std::make_shared<HistoryCapabilitiesOperation>(std::move(addressSpace),
      std::move(historyConfiguration),
      std::move(serverCapabilities),
      std::move(done)));
  }

  HistoryCapabilitiesOperation(const AddressSpace& addressSpace,
    ServerConfig::HistoryConfig historyConfiguration, ServerConfig::ServerCapabilities serverCapabilities,
    std::function<void(VoidResult)> done)
    : ua::async::SelfOwningOperation<HistoryCapabilitiesOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mHistoryConfiguration(std::move(historyConfiguration)),
      mServerCapabilities(std::move(serverCapabilities)), mDone(std::move(done))
  {}

private:
  friend class ua::async::SelfOwningOperation<HistoryCapabilitiesOperation>;

  auto find_all(std::vector<NodeId> nodeIds)
  {
    return await_step<BatchResult<NodeAccessorResult>>(
      [this, nodeIds = std::move(nodeIds)](auto completion) mutable
      {
        auto owner = mAddressSpace.lock();
        if (!owner)
        {
          completion(BatchResult<NodeAccessorResult>{
            VoidResult{::ua::detail::address_space_gone("HistoryCapabilities")}, {}});
          return;
        }
        owner->find_nodes_async(nodeIds, std::move(completion));
      });
  }

  auto write_all(std::vector<WriteValue> writes)
  {
    return await_step<std::vector<VoidResult>>([this, writes = std::move(writes)](auto completion) mutable
      { write_in_one_batch(mAddressSpace, std::move(writes), std::move(completion)); });
  }

  auto add_all(std::shared_ptr<const std::vector<ReferenceChange>> changes)
  {
    return await_step<std::vector<VoidResult>>(
      [this, changes = std::move(changes)](auto completion) mutable
      {
        ::ua::detail::NodeAccessorRoute::add_references(
          mAddressSpace, RequestInfo{}, changes, std::move(completion));
      });
  }

  /// The Description translations the supported aggregates @p aggregates lack: English, and each advertised
  /// locale's language, as (aggregate, locale, text). Throws for a missing aggregate or Description, an
  /// advertised locale that is invalid or has no built-in translation, before anything is written.
  struct Translation
  {
    NodeId aggregateId;
    std::string locale;
    std::string text;
  };

  std::vector<Translation> missing_translations(
    const std::vector<NodeId>& aggregateIds, const BatchResult<NodeAccessorResult>& aggregates) const
  {
    std::vector<Translation> missing;
    for (std::size_t i = 0; i < aggregateIds.size(); ++i)
    {
      const auto& aggregateId = aggregateIds[i];
      if (!aggregates.batchStatus.is_good() || i >= aggregates.items.size() || !aggregates.items[i].is_good())
      {
        const StatusCode cause =
          !aggregates.batchStatus.is_good()
            ? ::ua::detail::lookup_failure(aggregateId, aggregates.batchStatus.status_code(), "ServerModel")
          : i < aggregates.items.size()
            ? ::ua::detail::lookup_failure(aggregateId, aggregates.items[i].status_code(), "ServerModel")
            : StatusCode{Status::BadInternalError};
        throw UaException{Status::BadConfigurationError,
          ErrorDetail::build("AggregateDescriptionNodeMissing",
            "A supported standard Aggregate Object is missing from the address space",
            "ServerModel")
            .context(ContextKeys::nodeId, aggregateId)
            .cause(cause)};
      }

      auto aggregate = aggregates.items[i].value();
      auto descriptionValue = aggregate.read_attribute(AttributeId::Description);
      const auto* storedDescription = descriptionValue.try_as<LocalizedText>();
      if (!storedDescription || storedDescription->text().empty())
      {
        throw UaException{Status::BadConfigurationError,
          ErrorDetail::build("AggregateDescriptionMissing",
            "A supported standard Aggregate Object has no mandatory Description",
            "ServerModel")
            .context(ContextKeys::nodeId, aggregateId)};
      }

      LocalizedText aggregateDescription = *storedDescription;
      if (!has_language_translation(aggregateDescription, "en"))
      {
        std::string englishText{static_cast<string_view>(std::as_const(aggregateDescription).text())};
        aggregateDescription =
          aggregateDescription.merged_with(LocalizedText{LocaleId{String{"en"}}, String{englishText}});
        missing.push_back(Translation{aggregateId, "en", std::move(englishText)});
      }

      for (const auto& configuredLocale : mServerCapabilities.localeIds)
      {
        if (!LocalizedText::is_locale_format_valid(configuredLocale))
        {
          throw UaException{Status::BadConfigurationError,
            ErrorDetail::build("AdvertisedLocaleInvalid",
              "An advertised Server LocaleId is syntactically invalid",
              "ServerModel")
              .context(ContextKeys::nodeId, aggregateId)
              .context(ContextKeys::locale, configuredLocale)};
        }

        const auto [languageValue, region] = LocalizedText::parse_locale_id(configuredLocale);
        UA_UNUSED(region);
        const std::string language{static_cast<string_view>(languageValue)};
        if (has_language_translation(aggregateDescription, language))
        {
          continue;
        }

        const auto builtInDescriptions = aggregates::standard_aggregate_descriptions(language);
        const auto translation = std::ranges::find_if(builtInDescriptions,
          [&aggregateId](const aggregates::StandardAggregateDescription& candidate)
          { return NodeId{candidate.objectId} == aggregateId; });
        if (translation == builtInDescriptions.end())
        {
          throw UaException{Status::BadConfigurationError,
            ErrorDetail::build("AggregateDescriptionTranslationMissing",
              "An advertised locale has no translation for a supported standard Aggregate",
              "ServerModel")
              .context(ContextKeys::nodeId, aggregateId)
              .context(ContextKeys::locale, configuredLocale)};
        }

        aggregateDescription = aggregateDescription.merged_with(
          LocalizedText{LocaleId{String{language}}, String{translation->text}});
        missing.push_back(Translation{aggregateId, language, std::string{translation->text}});
      }
    }
    return missing;
  }

  /// Writes the missing translations, one Description write each, in one batch. A Description write merges
  /// the translation of its locale into the held Description (`LocalizedText::merged_with`), and the batch's
  /// translations are of different locales or different aggregates, so their order does not matter.
  ua::async::Task<> localize_standard_aggregate_descriptions(
    const std::vector<NodeId>& aggregateIds, const BatchResult<NodeAccessorResult>& aggregates)
  {
    const auto missing = missing_translations(aggregateIds, aggregates);
    if (missing.empty())
    {
      co_return;
    }
    std::vector<WriteValue> writes;
    writes.reserve(missing.size());
    for (const auto& translation : missing)
    {
      WriteValue write;
      write.node_id() = translation.aggregateId;
      write.attribute_id() = utils::to_underlying(AttributeId::Description);
      write.value().value() =
        Variant{LocalizedText{LocaleId{String{translation.locale}}, String{translation.text}}};
      writes.push_back(std::move(write));
    }
    const auto written = co_await write_all(std::move(writes));
    if (const auto failed = first_failure(written))
    {
      throw UaException{Status::BadConfigurationError,
        ErrorDetail::build("AggregateDescriptionWriteFailed",
          "A standard Aggregate Description translation could not be written",
          "ServerModel")
          .context(ContextKeys::nodeId, missing[*failed].aggregateId)
          .context(ContextKeys::locale, missing[*failed].locale)
          .cause(written[*failed].status_code())};
    }
    co_return;
  }

  ua::async::Task<> run()
  {
    try
    {
      co_await populate();
      answer(VoidResult{});
    }
    catch (const ua::async::Abandoned&)
    {
      answer(VoidResult{StatusCode{Status::BadOperationAbandoned}});
    }
    catch (...)
    {
      answer(VoidResult{ua::exception_to_status_code(std::current_exception())});
    }
  }

  /// The capabilities of every registered namespace's history delegate, OR-ed, and whether there is any.
  std::pair<NamespaceHistoryDelegate::Capabilities, bool> aggregated_capabilities() const
  {
    auto owner = mAddressSpace.lock();
    if (!owner)
    {
      throw UaException{::ua::detail::address_space_gone("HistoryCapabilities")};
    }
    NamespaceHistoryDelegate::Capabilities aggregated;
    bool hasAnyDelegate = false;
    const auto& nsArray = owner->namespace_array();
    auto nsUris = nsArray.get_namespace_array();
    for (uint16_t i = 0; i < numeric_cast<uint16_t>(nsUris.size()); ++i)
    {
      auto ns = nsArray.get_namespace(i);
      if (!ns)
        continue;
      auto delegate = ns->history_delegate();
      if (!delegate)
        continue;
      hasAnyDelegate = true;
      auto caps = delegate->capabilities();
      aggregated.readRaw |= caps.readRaw;
      aggregated.readModified |= caps.readModified;
      aggregated.readProcessed |= caps.readProcessed;
      aggregated.readAtTime |= caps.readAtTime;
      aggregated.readEvents |= caps.readEvents;
      aggregated.readAnnotations |= caps.readAnnotations;
      aggregated.updateData |= caps.updateData;
      aggregated.updateEvent |= caps.updateEvent;
      aggregated.insertAnnotation |= caps.insertAnnotation;
      aggregated.deleteRaw |= caps.deleteRaw;
      aggregated.deleteAtTime |= caps.deleteAtTime;
      aggregated.deleteEvents |= caps.deleteEvents;
    }
    return {aggregated, hasAnyDelegate};
  }

  ua::async::Task<> populate()
  {
    // Aggregate capabilities across all namespaces by OR-ing each delegate's capabilities.
    const auto [aggregated, hasAnyDelegate] = aggregated_capabilities();

    // Part 13 4.2.1.2 standard defaults for the Server's Part 11 DefaultHAConfiguration instance.
    // The calculator's CalcConfig uses the same values when a request selects server defaults.
    std::vector<WriteValue> writes{
      static_value(
        VariableId::DefaultHAConfiguration_AggregateConfiguration_TreatUncertainAsBad, Variant{true}),
      static_value(
        VariableId::DefaultHAConfiguration_AggregateConfiguration_PercentDataBad, Variant{uint8_t{100}}),
      static_value(
        VariableId::DefaultHAConfiguration_AggregateConfiguration_PercentDataGood, Variant{uint8_t{100}}),
      static_value(
        VariableId::DefaultHAConfiguration_AggregateConfiguration_UseSlopedExtrapolation, Variant{false}),
      static_value(VariableId::DefaultHAConfiguration_Stepped, Variant{false}),
      static_value(
        VariableId::HistoryServerCapabilities_AccessHistoryDataCapability, Variant{hasAnyDelegate}),
      static_value(
        VariableId::HistoryServerCapabilities_AccessHistoryEventsCapability, Variant{aggregated.readEvents}),
      static_value(VariableId::HistoryServerCapabilities_MaxReturnDataValues,
        Variant{mHistoryConfiguration.maxReturnDataValues}),
      static_value(VariableId::HistoryServerCapabilities_MaxReturnEventValues,
        Variant{mHistoryConfiguration.maxReturnEventValues}),
      static_value(
        VariableId::HistoryServerCapabilities_InsertDataCapability, Variant{aggregated.updateData}),
      static_value(
        VariableId::HistoryServerCapabilities_ReplaceDataCapability, Variant{aggregated.updateData}),
      static_value(
        VariableId::HistoryServerCapabilities_UpdateDataCapability, Variant{aggregated.updateData}),
      static_value(VariableId::HistoryServerCapabilities_DeleteRawCapability, Variant{aggregated.deleteRaw}),
      static_value(
        VariableId::HistoryServerCapabilities_DeleteAtTimeCapability, Variant{aggregated.deleteAtTime}),
      static_value(
        VariableId::HistoryServerCapabilities_InsertEventCapability, Variant{aggregated.updateEvent}),
      static_value(
        VariableId::HistoryServerCapabilities_ReplaceEventCapability, Variant{aggregated.updateEvent}),
      static_value(
        VariableId::HistoryServerCapabilities_UpdateEventCapability, Variant{aggregated.updateEvent}),
      static_value(
        VariableId::HistoryServerCapabilities_DeleteEventCapability, Variant{aggregated.deleteEvents}),
      static_value(VariableId::HistoryServerCapabilities_InsertAnnotationCapability,
        Variant{aggregated.insertAnnotation}),
      static_value(VariableId::HistoryServerCapabilities_ServerTimestampSupported, Variant{true})};
    const auto written = co_await write_all(std::move(writes));
    if (const auto failed = first_failure(written))
    {
      throw UaException{written[*failed].status_code()};
    }

    // Advertise the aggregate functions the built-in calculator can compute - but only when a delegate
    // can supply the raw history the turnkey path needs. Without read_raw, ReadProcessedDetails returns
    // BadHistoryOperationUnsupported, so advertising would be a false capability claim. (Native
    // read_processed delegates have an aggregate set opaque to the SDK; advertising on their behalf is a
    // follow-up - they would need to report their supported aggregates.) The supported set is Organized
    // into both the ServerCapabilities and HistoryServerCapabilities AggregateFunctions folders.
    if (!aggregated.readRaw)
    {
      co_return;
    }
    const std::vector<NodeId> aggregateIds = aggregates::AggregatorRegistry::instance().supported();
    const auto aggregates = co_await find_all(aggregateIds);
    co_await localize_standard_aggregate_descriptions(aggregateIds, aggregates);

    const std::vector<NodeId> folderIds{NodeId{ObjectId::Server_ServerCapabilities_AggregateFunctions},
      NodeId{ObjectId::HistoryServerCapabilities_AggregateFunctions},
      NodeId{ObjectId::DefaultHAConfiguration_AggregateFunctions}};
    const auto folders = co_await find_all(folderIds);
    auto changes = std::make_shared<std::vector<ReferenceChange>>();
    for (std::size_t f = 0; f < folderIds.size() && folders.batchStatus.is_good(); ++f)
    {
      // Best-effort model enrichment: a missing optional aggregate folder does not invalidate the
      // other HistoryServerCapabilities nodes or the aggregate functions published under them.
      if (f >= folders.items.size() || !folders.items[f].is_good())
        continue;
      for (const auto& aggregateId : aggregateIds)
      {
        // Both halves: Part 3 5.3.2 recommends instantiating hierarchical References in both directions.
        const auto pair =
          ReferenceChange::both_halves(folderIds[f], NodeId{ReferenceTypeId::Organizes}, aggregateId);
        changes->insert(changes->end(), pair.begin(), pair.end());
      }
    }
    if (!changes->empty())
    {
      // Best-effort, as the folders are: a refused Organizes leaves the aggregate unlisted under that folder
      // only.
      (void)co_await add_all(std::move(changes));
    }
    co_return;
  }

  void fail_to_start(StatusCode status)
  {
    answer(VoidResult{std::move(status)});
  }

  void answer(VoidResult result)
  {
    if (auto done = std::exchange(mDone, nullptr))
      done(std::move(result));
  }

  WeakAddressSpace mAddressSpace;
  ServerConfig::HistoryConfig mHistoryConfiguration;
  ServerConfig::ServerCapabilities mServerCapabilities;
  std::function<void(VoidResult)> mDone;
};

void write_static_values(AddressSpace& addressSpace, const CombinedConfig& config)
{
  const auto& identity = config.identity;
  std::vector<WriteValue> writes;

  // BuildInfo sub-properties
  const auto& bi = identity.buildInfo;
  write_static_value(writes, VariableId::Server_ServerStatus_BuildInfo_ProductUri, Variant{bi.product_uri()});
  write_static_value(
    writes, VariableId::Server_ServerStatus_BuildInfo_ManufacturerName, Variant{bi.manufacturer_name()});
  write_static_value(
    writes, VariableId::Server_ServerStatus_BuildInfo_ProductName, Variant{bi.product_name()});
  write_static_value(
    writes, VariableId::Server_ServerStatus_BuildInfo_SoftwareVersion, Variant{bi.software_version()});
  write_static_value(
    writes, VariableId::Server_ServerStatus_BuildInfo_BuildNumber, Variant{bi.build_number()});
  write_static_value(writes, VariableId::Server_ServerStatus_BuildInfo_BuildDate, Variant{bi.build_date()});

  // Container variable for BuildInfo - write aggregate so reads don't fail
  write_static_value(writes, VariableId::Server_ServerStatus_BuildInfo, Variant{bi});

  // Top-level Server properties (non-shutdown)
  write_static_value(writes, VariableId::Server_Auditing, Variant{config.server.auditingEnabled});

  // ServerRedundancy
  write_static_value(
    writes, VariableId::Server_ServerRedundancy_RedundancySupport, Variant{int32_t{0}});  // None = 0

  // ServerCapabilities
  write_server_capabilities(addressSpace, writes, config.server.server_capabilities());

  // One lookup and one write for every static Value (NR-31's phases), waited on from Server::create's thread.
  const auto written = ua::async::detail::blocking_call<Result<std::vector<VoidResult>>>(
    addressSpace.executor(),
    [&](std::function<void(Result<std::vector<VoidResult>>)> complete)
    {
      write_in_one_batch(addressSpace.weak(),
        std::move(writes),
        [complete = std::move(complete)](std::vector<VoidResult> answers) { complete(std::move(answers)); });
    });
  if (!written.is_good())
  {
    throw UaException{written.status_code()};
  }
  if (const auto failed = first_failure(written.value()))
  {
    throw UaException{written.value()[*failed].status_code()};
  }
}

void wire_get_monitored_items(const ServerObject& server, SubscriptionRouter::Weak registry)
{
  server.set_get_monitored_items_handler_sync(
    [registry](const MethodCall& call,
      const ServerObject::GetMonitoredItemsInputArguments& args,
      MethodResultCallback<ServerObject::GetMonitoredItemsOutputArguments>
        complete)
    {
      const auto& context = ::ua::detail::MethodCallAccess::shared_context(call);
      // 1. Find owning session via registry (thread-safe shared_mutex read). The address space keeps this
      // handler; once the server and its router are gone, no Subscription is found
      // (COMP-SVR-SUBSCRIPTION-SERVER-STATE-01).
      auto router = registry.lock();
      auto owner = router ? router->find_owner(IntegerId{args.subscriptionId}) : nullptr;
      if (!owner)
      {
        complete(StatusCode{Status::BadSubscriptionIdInvalid});
        return;
      }

      // 2. Verify caller owns the subscription (Part 4 5.12.2.1: "shall verify session context")
      if (!context || owner->session_id() != context->sessionId)
      {
        complete(StatusCode{Status::BadUserAccessDenied});
        return;
      }

      // 3. Delegate to the owning session (posts to session strand -> subscription strand)
      owner->get_monitored_items_async(IntegerId{args.subscriptionId},
        [complete = std::move(complete)](Result<MonitoredItemHandles> result) mutable
        {
          if (!result.is_good())
          {
            complete(result.status_code());
            return;
          }

          auto handles = std::move(result).value();
          ServerObject::GetMonitoredItemsOutputArguments out;
          out.serverHandles = std::move(handles.serverHandles);
          out.clientHandles = std::move(handles.clientHandles);
          complete(std::move(out));
        });
    });
}

void wire_resend_data(const ServerObject& server, SubscriptionRouter::Weak registry)
{
  server.set_resend_data_handler_sync(
    [registry](const MethodCall& call,
      const ServerObject::ResendDataInputArguments& args,
      MethodResultCallback<>
        complete)
    {
      const auto& context = ::ua::detail::MethodCallAccess::shared_context(call);
      // 1. Find owning session via registry (thread-safe shared_mutex read). The address space keeps this
      // handler; once the server and its router are gone, no Subscription is found
      // (COMP-SVR-SUBSCRIPTION-SERVER-STATE-01).
      auto router = registry.lock();
      auto owner = router ? router->find_owner(IntegerId{args.subscriptionId}) : nullptr;
      if (!owner)
      {
        complete(StatusCode{Status::BadSubscriptionIdInvalid});
        return;
      }

      // 2. Verify caller owns the subscription (Part 4 5.12.2.3 session context).
      if (!context || owner->session_id() != context->sessionId)
      {
        complete(StatusCode{Status::BadUserAccessDenied});
        return;
      }

      // 3. Delegate to the owning session (posts to session strand -> subscription strand).
      owner->resend_data_async(IntegerId{args.subscriptionId},
        [complete = std::move(complete)](StatusCode status) mutable
        {
          if (status.is_bad())
          {
            complete(status);
            return;
          }
          complete(VoidResult{});
        });
    });
}

void wire_set_subscription_durable(const ServerObject& server, SubscriptionRouter::Weak registry)
{
  server.set_set_subscription_durable_handler_sync(
    [registry](const MethodCall& call,
      const ServerObject::SetSubscriptionDurableInputArguments& args,
      MethodResultCallback<ServerObject::SetSubscriptionDurableOutputArguments>
        complete)
    {
      const auto& context = ::ua::detail::MethodCallAccess::shared_context(call);
      // 1. Find owning session via registry (thread-safe shared_mutex read). The address space keeps this
      // handler; once the server and its router are gone, no Subscription is found
      // (COMP-SVR-SUBSCRIPTION-SERVER-STATE-01).
      auto router = registry.lock();
      auto owner = router ? router->find_owner(IntegerId{args.subscriptionId}) : nullptr;
      if (!owner)
      {
        complete(StatusCode{Status::BadSubscriptionIdInvalid});
        return;
      }

      // 2. Verify caller owns the subscription (Part 4 5.13.9 session context).
      if (!context || owner->session_id() != context->sessionId)
      {
        complete(StatusCode{Status::BadUserAccessDenied});
        return;
      }

      // 3. Delegate to the owning session (posts to session strand -> subscription strand). A bad
      //    status (e.g. Bad_InvalidState when the subscription already has monitored items) becomes
      //    the operation-level result; success carries the revised lifetime in hours.
      owner->set_subscription_durable_async(IntegerId{args.subscriptionId},
        args.lifetimeInHours,
        [complete = std::move(complete)](Result<uint32_t> result) mutable
        {
          if (!result.is_good())
          {
            complete(result.status_code());
            return;
          }

          ServerObject::SetSubscriptionDurableOutputArguments out;
          out.revisedLifetimeInHours = result.value();
          complete(out);
        });
    });
}

/// Map a wire integer ServerState value to the enum, rejecting out-of-range values.
optional<ServerState> decode_server_state(int32_t raw)
{
  switch (raw)
  {
  case utils::to_underlying(ServerState::Running):
    return ServerState::Running;
  case utils::to_underlying(ServerState::Failed):
    return ServerState::Failed;
  case utils::to_underlying(ServerState::NoConfiguration):
    return ServerState::NoConfiguration;
  case utils::to_underlying(ServerState::Suspended):
    return ServerState::Suspended;
  case utils::to_underlying(ServerState::Shutdown):
    return ServerState::Shutdown;
  case utils::to_underlying(ServerState::Test):
    return ServerState::Test;
  case utils::to_underlying(ServerState::CommunicationFault):
    return ServerState::CommunicationFault;
  case utils::to_underlying(ServerState::Unknown):
    return ServerState::Unknown;
  default:
    return std::nullopt;
  }
}

void wire_request_server_state_change(ServerObject& server, AddressSpace& /*addressSpace*/,
  std::shared_ptr<ServerDynamicState> dynamicState, ShutdownRequestHandler shutdownHandler, Logger logger)
{
  // The Executable Attribute is deliberately left at its conforming default of True.
  //
  // OPC 10000-5 section 5.5 Table 7: every Method the specification defines shall be Executable unless its
  // own definition says otherwise, and RequestServerStateChange's does not. Executable is what a
  // Client reads to decide whether a Method is offered at all, so writing False on a Method that is
  // fully wired below advertises a missing feature rather than a refused one -- the caller never
  // attempts it and never learns why.
  //
  // Refusing the call is authorization's job, and the SDK already does it: every Method invocation is
  // checked for `Call` against its owning Namespace and the committed AccessIdentity. A deployment
  // that does not want this Method callable authors ordinary RolePermissions there, where the refusal
  // reaches the caller as Bad_UserAccessDenied and says what happened.

  server.set_request_server_state_change_handler_sync(
    [dynamicState = std::move(dynamicState), shutdownHandler = std::move(shutdownHandler), logger](
      const MethodCall& /*call*/,
      const ServerObject::RequestServerStateChangeInputArguments& args,
      MethodResultCallback<>
        complete) mutable
    {
      // The State argument must be an Int32 ServerState enumeration (Part 3 5.10.3).
      if (!args.state.is_int32())
      {
        complete(StatusCode{Status::BadInvalidArgument});
        return;
      }

      auto requestedState = decode_server_state(args.state.as<int32_t>());
      if (!requestedState)
      {
        complete(StatusCode{Status::BadInvalidArgument});
        return;
      }

      // Shutdown drives the graceful-shutdown handler (drains sessions, sets reason/seconds).
      if (*requestedState == ServerState::Shutdown)
      {
        ShutdownOptions params;
        params.grace = std::chrono::seconds{args.secondsTillShutdown};
        params.reason = args.reason;

        shutdownHandler(std::move(params),
          [complete = std::move(complete)](VoidResult shutdownResult) mutable
          { complete(std::move(shutdownResult)); });
        return;
      }

      // Non-shutdown transitions update ServerStatus.State (and the shutdown-related
      // fields where relevant). The State read handler reflects server_state, so the
      // store is the node-write path. ProgressEvent emission is a follow-up (see report).
      if (dynamicState)
      {
        // Carry the supplied shutdown hints so a subsequent ServerStatus read is coherent.
        dynamicState->secondsTillShutdown.store(args.secondsTillShutdown, std::memory_order_relaxed);
        {
          const std::unique_lock lk(dynamicState->mutex);
          dynamicState->shutdownReason = args.reason;
        }
        dynamicState->serverState.store(*requestedState, std::memory_order_relaxed);
      }
      else
      {
        logger.warning({}, "RequestServerStateChange: dynamic state unavailable; cannot honour transition");
        complete(StatusCode{Status::BadInvalidState});
        return;
      }

      complete(VoidResult{});
    });
}

void wire_diagnostics_counter_handler(AddressSpace& addressSpace, VariableId id,
  std::shared_ptr<ServerSummaryCounters> counters, std::atomic<uint32_t> ServerSummaryCounters::*field)
{
  auto result = addressSpace.try_find_node_sync(NodeId{id});
  assert(result.is_good());
  auto* target = result.value()->external_value_source();
  assert(target);
  target->set_value_source(detail::whole_value_source(
    [counters, field](
      const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
    {
      DataValue dv;
      dv.source_timestamp() = DateTime::now();
      dv.value() = Variant{(counters.get()->*field).load(std::memory_order_relaxed)};
      complete(std::move(dv));
    }));
}

// The ServerDiagnosticsSummary Variable's OWN Value, composed from the same counters its children
// expose. OPC 10000-5 section 6.3.2 defines that Variable as carrying a ServerDiagnosticsSummaryDataType,
// so a client that reads the parent rather than walking twelve children is doing the ordinary thing
// -- and until this handler existed it got whatever default the node held, which decodes as nothing
// and surfaced to the caller as Bad_DecodingError. The children stay wired as well: the standard
// defines both, and a client may read either.
void wire_diagnostics_summary_value_handler(
  AddressSpace& addressSpace, const std::shared_ptr<ServerSummaryCounters>& counters)
{
  auto result =
    addressSpace.try_find_node_sync(NodeId{VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary});
  assert(result.is_good());
  auto* target = result.value()->external_value_source();
  assert(target);
  target->set_value_source(detail::whole_value_source(
    [counters](const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
    {
      const auto load = [&counters](std::atomic<uint32_t> ServerSummaryCounters::*field)
      {
        return (counters.get()->*field).load(std::memory_order_relaxed);
      };

      ua::ServerDiagnosticsSummaryDataType summary;
      summary.server_view_count() = load(&ServerSummaryCounters::serverViewCount);
      summary.current_session_count() = load(&ServerSummaryCounters::currentSessionCount);
      summary.cumulated_session_count() = load(&ServerSummaryCounters::cumulatedSessionCount);
      summary.security_rejected_session_count() = load(&ServerSummaryCounters::securityRejectedSessionCount);
      summary.rejected_session_count() = load(&ServerSummaryCounters::rejectedSessionCount);
      summary.session_timeout_count() = load(&ServerSummaryCounters::sessionTimeoutCount);
      summary.session_abort_count() = load(&ServerSummaryCounters::sessionAbortCount);
      summary.publishing_interval_count() = load(&ServerSummaryCounters::publishingIntervalCount);
      summary.current_subscription_count() = load(&ServerSummaryCounters::currentSubscriptionCount);
      summary.cumulated_subscription_count() = load(&ServerSummaryCounters::cumulatedSubscriptionCount);
      summary.security_rejected_requests_count() =
        load(&ServerSummaryCounters::securityRejectedRequestsCount);
      summary.rejected_requests_count() = load(&ServerSummaryCounters::rejectedRequestsCount);

      DataValue dv;
      dv.source_timestamp() = DateTime::now();
      dv.value() = Variant{summary};
      complete(std::move(dv));
    }));
}

void wire_diagnostics_summary_handlers(AddressSpace& addressSpace, const DiagnosticState& diagnostics)
{
  auto c = diagnostics.summaryCounters;

  wire_diagnostics_summary_value_handler(addressSpace, c);

  wire_diagnostics_counter_handler(addressSpace,
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_ServerViewCount,
    c,
    &ServerSummaryCounters::serverViewCount);
  wire_diagnostics_counter_handler(addressSpace,
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount,
    c,
    &ServerSummaryCounters::currentSessionCount);
  wire_diagnostics_counter_handler(addressSpace,
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSessionCount,
    c,
    &ServerSummaryCounters::cumulatedSessionCount);
  wire_diagnostics_counter_handler(addressSpace,
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedSessionCount,
    c,
    &ServerSummaryCounters::securityRejectedSessionCount);
  wire_diagnostics_counter_handler(addressSpace,
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedSessionCount,
    c,
    &ServerSummaryCounters::rejectedSessionCount);
  wire_diagnostics_counter_handler(addressSpace,
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionTimeoutCount,
    c,
    &ServerSummaryCounters::sessionTimeoutCount);
  wire_diagnostics_counter_handler(addressSpace,
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SessionAbortCount,
    c,
    &ServerSummaryCounters::sessionAbortCount);
  wire_diagnostics_counter_handler(addressSpace,
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_PublishingIntervalCount,
    c,
    &ServerSummaryCounters::publishingIntervalCount);
  wire_diagnostics_counter_handler(addressSpace,
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSubscriptionCount,
    c,
    &ServerSummaryCounters::currentSubscriptionCount);
  wire_diagnostics_counter_handler(addressSpace,
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_CumulatedSubscriptionCount,
    c,
    &ServerSummaryCounters::cumulatedSubscriptionCount);
  wire_diagnostics_counter_handler(addressSpace,
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_SecurityRejectedRequestsCount,
    c,
    &ServerSummaryCounters::securityRejectedRequestsCount);
  wire_diagnostics_counter_handler(addressSpace,
    VariableId::Server_ServerDiagnostics_ServerDiagnosticsSummary_RejectedRequestsCount,
    c,
    &ServerSummaryCounters::rejectedRequestsCount);
}

// Wire the SessionDiagnosticsArray Variable: on each read, build one
// SessionDiagnosticsDataType element per currently live session.
void wire_session_diagnostics_array_handler(
  AddressSpace& addressSpace, SessionDiagnosticsProvider provider, Logger logger)
{
  if (!provider)
    return;

  auto result = addressSpace.try_find_node_sync(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray});
  if (!result)
  {
    logger.warning({}, "Could not find SessionDiagnosticsArray node for dynamic handler");
    return;
  }
  auto* target = result.value()->external_value_source();
  if (!target)
    return;

  target->set_value_source(detail::whole_value_source(
    [provider, logger](
      const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete) mutable
    {
      try
      {
        // Take a safe snapshot of live sessions; the provider holds its own lock only
        // for the snapshot copy, never while we build records here.
        auto sessions = provider();

        Array<RefStructure<Structure>> elements;
        elements.resize(sessions.size());
        for (size_t i = 0; i < sessions.size(); ++i)
        {
          const auto& entry = sessions[i];
          if (!entry.counters || !entry.securityState || !entry.descriptiveState)
            continue;
          elements[i] = RefStructure<Structure>{std::make_unique<SessionDiagnosticsDataType>(
            build_session_diagnostics(*entry.counters, *entry.securityState, *entry.descriptiveState))};
        }

        DataValue dv;
        dv.source_timestamp() = DateTime::now();
        dv.value() = Variant{std::move(elements)};
        complete(std::move(dv));
      }
      catch (...)
      {
        auto er = ua::exception_to_status_code(std::current_exception());
        log_exception(logger, LogLevel::Warning, "wire_session_diagnostics_array_handler", er);
        DataValue dv;
        dv.status() = er;
        complete(std::move(dv));
      }
    }));
}

// Wire the SessionSecurityDiagnosticsArray Variable: one
// SessionSecurityDiagnosticsDataType element per currently live session.
void wire_session_security_diagnostics_array_handler(
  AddressSpace& addressSpace, SessionDiagnosticsProvider provider, Logger logger)
{
  if (!provider)
    return;

  auto result = addressSpace.try_find_node_sync(
    NodeId{VariableId::Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray});
  if (!result)
  {
    logger.warning({}, "Could not find SessionSecurityDiagnosticsArray node for dynamic handler");
    return;
  }
  auto* target = result.value()->external_value_source();
  if (!target)
    return;

  target->set_value_source(detail::whole_value_source(
    [provider, logger](
      const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete) mutable
    {
      try
      {
        auto sessions = provider();

        Array<RefStructure<Structure>> elements;
        elements.resize(sessions.size());
        for (size_t i = 0; i < sessions.size(); ++i)
        {
          const auto& entry = sessions[i];
          if (!entry.securityState)
            continue;
          elements[i] = RefStructure<Structure>{std::make_unique<SessionSecurityDiagnosticsDataType>(
            build_session_security_diagnostics(*entry.securityState))};
        }

        DataValue dv;
        dv.source_timestamp() = DateTime::now();
        dv.value() = Variant{std::move(elements)};
        complete(std::move(dv));
      }
      catch (...)
      {
        auto er = ua::exception_to_status_code(std::current_exception());
        log_exception(logger, LogLevel::Warning, "wire_session_security_diagnostics_array_handler", er);
        DataValue dv;
        dv.status() = er;
        complete(std::move(dv));
      }
    }));
}

// Wire the SubscriptionDiagnosticsArray Variable: on each read, build one
// SubscriptionDiagnosticsDataType element per currently live subscription (server-wide).
void wire_subscription_diagnostics_array_handler(
  AddressSpace& addressSpace, SubscriptionDiagnosticsProvider provider, Logger logger)
{
  if (!provider)
    return;

  auto result = addressSpace.try_find_node_sync(
    NodeId{VariableId::Server_ServerDiagnostics_SubscriptionDiagnosticsArray});
  if (!result)
  {
    logger.warning({}, "Could not find SubscriptionDiagnosticsArray node for dynamic handler");
    return;
  }
  auto* target = result.value()->external_value_source();
  if (!target)
    return;

  target->set_value_source(detail::whole_value_source(
    [provider, logger](
      const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete) mutable
    {
      try
      {
        auto subscriptions = provider();

        Array<RefStructure<Structure>> elements;
        elements.resize(subscriptions.size());
        for (size_t i = 0; i < subscriptions.size(); ++i)
        {
          const auto& entry = subscriptions[i];
          if (!entry.info)
            continue;
          elements[i] = RefStructure<Structure>{std::make_unique<SubscriptionDiagnosticsDataType>(
            build_subscription_diagnostics(*entry.info, entry.sessionId))};
        }

        DataValue dv;
        dv.source_timestamp() = DateTime::now();
        dv.value() = Variant{std::move(elements)};
        complete(std::move(dv));
      }
      catch (...)
      {
        auto er = ua::exception_to_status_code(std::current_exception());
        log_exception(logger, LogLevel::Warning, "wire_subscription_diagnostics_array_handler", er);
        DataValue dv;
        dv.status() = er;
        complete(std::move(dv));
      }
    }));
}

// Wire the SamplingIntervalDiagnosticsArray Variable: aggregate all live monitored items across all
// subscriptions by their (revised) sampling interval into one element per distinct interval.
void wire_sampling_interval_diagnostics_array_handler(
  AddressSpace& addressSpace, SubscriptionDiagnosticsProvider provider, Logger logger)
{
  if (!provider)
    return;

  auto result = addressSpace.try_find_node_sync(
    NodeId{VariableId::Server_ServerDiagnostics_SamplingIntervalDiagnosticsArray});
  if (!result)
  {
    logger.warning({}, "Could not find SamplingIntervalDiagnosticsArray node for dynamic handler");
    return;
  }
  auto* target = result.value()->external_value_source();
  if (!target)
    return;

  target->set_value_source(detail::whole_value_source(
    [provider, logger](
      const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete) mutable
    {
      try
      {
        auto aggregates = aggregate_sampling_interval_diagnostics(provider());
        Array<RefStructure<Structure>> elements;
        elements.resize(aggregates.size());
        for (size_t i = 0; i < aggregates.size(); ++i)
          elements[i] = RefStructure<Structure>{
            std::make_unique<SamplingIntervalDiagnosticsDataType>(std::move(aggregates[i]))};

        DataValue dv;
        dv.source_timestamp() = DateTime::now();
        dv.value() = Variant{std::move(elements)};
        complete(std::move(dv));
      }
      catch (...)
      {
        auto er = ua::exception_to_status_code(std::current_exception());
        log_exception(logger, LogLevel::Warning, "wire_sampling_interval_diagnostics_array_handler", er);
        DataValue dv;
        dv.status() = er;
        complete(std::move(dv));
      }
    }));
}

void wire_enabled_flag_handlers(AddressSpace& addressSpace, const DiagnosticState& diagnostics)
{
  auto enabled = diagnostics.enabled;

  // Read handler: return current enabled flag value
  auto result = addressSpace.try_find_node_sync(NodeId{VariableId::Server_ServerDiagnostics_EnabledFlag});
  assert(result.is_good());
  auto* target = result.value()->external_value_source();
  assert(target);

  detail::WholeValueRead read =
    [enabled](const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
  {
    DataValue dv;
    dv.source_timestamp() = DateTime::now();
    dv.value() = Variant{enabled->load(std::memory_order_relaxed)};
    complete(std::move(dv));
  };

  // Write handler: set flag and reset counters on TRUE. The flag is a Boolean scalar, so the namespace
  // refuses a ranged write before the source sees it.
  auto summaryCounters = diagnostics.summaryCounters;
  auto scCounters = diagnostics.secureChannelCounters;
  auto connCounters = diagnostics.connectionCounters;
  auto onChanged = diagnostics.onEnabledFlagChanged;

  target->set_value_source(detail::whole_value_source(std::move(read),
    [enabled, summaryCounters, scCounters, connCounters, onChanged](
      const ValueSource::WriteContext& /*context*/,
      const Node& /*node*/,
      const WriteValue& write,
      std::function<void(ValueSource::WriteResult)>
        complete)
    {
      const DataValue& dv = write.value();
      if (!dv.value().is_boolean())
      {
        complete(ValueSource::WriteResult{StatusCode{Status::BadTypeMismatch}});
        return;
      }

      const bool newValue = dv.value().as<bool>();

      if (newValue)
      {
        // Reset all counters then enable
        summaryCounters->reset();
        scCounters->reset();
        connCounters->reset();
        enabled->store(true, std::memory_order_relaxed);
      }
      else
      {
        // Disable - counters retain current values
        enabled->store(false, std::memory_order_relaxed);
      }

      // Answered once the diagnostics nodes match the flag, so a Client that browses them after the
      // response finds what it asked for.
      if (onChanged)
      {
        onChanged(newValue, [complete]() { complete(ValueSource::Written{}); });
      }
      else
      {
        complete(ValueSource::Written{});
      }
    }));
}

}  // namespace

namespace
{
// Case-insensitive "does `haystack` contain `needle`". Profile URIs are operator-provided strings,
// so match leniently on the well-known marker substring rather than requiring an exact URI.
bool contains_ignore_case(std::string_view haystack, std::string_view needle)
{
  if (needle.empty())
    return true;
  auto lower = [](unsigned char c)
  {
    return static_cast<char>(std::tolower(c));
  };
  const auto found = std::search(haystack.begin(),
    haystack.end(),
    needle.begin(),
    needle.end(),
    [&](char a, char b)
    { return lower(static_cast<unsigned char>(a)) == lower(static_cast<unsigned char>(b)); });
  return found != haystack.end();
}
}  // namespace

std::vector<ProfileFeatureInconsistency> find_advertised_profile_inconsistencies(
  const ServerConfig& serverConfig)
{
  const auto& caps = serverConfig.server_capabilities();

  struct Requirement
  {
    std::string_view marker;  ///< substring identifying the profile/facet in the advertised URI
    bool enabled;  ///< whether the gating feature is actually on in this configuration
    std::string_view feature;  ///< human-readable feature the profile requires
    std::string_view setting;  ///< the configuration setting that is currently off
  };

  // Only the unambiguous, boolean-gated features - advertising these while the feature is off would
  // mislead a client. New entries are added here as further boolean-gated facets become checkable.
  const Requirement requirements[] = {
    {"Auditing", serverConfig.auditingEnabled, "audit event generation", "ServerConfig::auditingEnabled"},
    {"DurableSubscription",
      serverConfig.subscriptionLimits.durableSubscriptionsEnabled,
      "durable subscriptions",
      "ServerConfig::subscriptionLimits.durableSubscriptionsEnabled"},
  };

  std::vector<ProfileFeatureInconsistency> inconsistencies;
  for (const auto& profile : caps.serverProfiles)
  {
    for (const auto& requirement : requirements)
    {
      if (!requirement.enabled && contains_ignore_case(profile, requirement.marker))
      {
        inconsistencies.push_back(
          {profile, std::string{requirement.feature}, std::string{requirement.setting}});
      }
    }
  }
  return inconsistencies;
}

ServerModel ServerModel::create(AddressSpace addressSpace, const CombinedConfig& config,
  const DiagnosticState& diagnostics, std::shared_ptr<ServerDynamicState> dynamicState,
  ShutdownRequestHandler shutdownHandler, Logger logger, SubscriptionRouter::Weak subscriptionRouter)
{
  // The Server object and all its forward-referenced children were imported during
  // ServerImpl::create_standard_nodes_from_nodeset; here we attach the generated handle.

  // Attach generated handle to the imported Server node
  auto serverResult = ServerObject::try_attach_sync(addressSpace, NodeId{ObjectId::Server});
  assert(serverResult.is_good());
  auto server = std::move(serverResult).value();

  // Wire dynamic value handlers
  wire_server_array_handler(addressSpace, logger);
  wire_namespace_array_handler(addressSpace, logger);
  wire_current_time_handler(addressSpace, logger);

  // Write static values (identity, capabilities, operation limits)
  write_static_values(addressSpace, config);

  // NOTE: the advertised-ServerProfile consistency check is run from ServerImpl::start(), NOT here -
  // model creation happens during Server::create(), before the operator installs a log sink, so a
  // warning emitted here would be swallowed by the not-yet-configured logger. See
  // find_advertised_profile_inconsistencies() and ServerImpl::start().

  // Wire dynamic shutdown/status handlers - lambdas co-own dynamicState via shared_ptr
  wire_server_status_state_handler(addressSpace, dynamicState, logger);
  wire_seconds_till_shutdown_handler(addressSpace, dynamicState, logger);
  wire_shutdown_reason_handler(addressSpace, dynamicState, logger);
  wire_service_level_handler(addressSpace, dynamicState, logger);
  wire_start_time_handler(addressSpace, dynamicState, logger);
  wire_server_status_handler(addressSpace, dynamicState, logger);

  // Wire method handlers
  wire_get_monitored_items(server, subscriptionRouter);
  wire_resend_data(server, subscriptionRouter);
  wire_set_subscription_durable(server, subscriptionRouter);
  wire_request_server_state_change(server, addressSpace, dynamicState, std::move(shutdownHandler), logger);

  // Wire diagnostic summary read handlers and EnabledFlag read/write handlers
  wire_diagnostics_summary_handlers(addressSpace, diagnostics);
  wire_enabled_flag_handlers(addressSpace, diagnostics);

  // Wire the live session-diagnostics array nodes (built per-read from the live session set).
  wire_session_diagnostics_array_handler(addressSpace, diagnostics.sessionDiagnosticsProvider, logger);
  wire_session_security_diagnostics_array_handler(
    addressSpace, diagnostics.sessionDiagnosticsProvider, logger);

  // Wire the live subscription-diagnostics array nodes (built per-read from the live subscription
  // set across all sessions, via the SubscriptionRouter).
  wire_subscription_diagnostics_array_handler(
    addressSpace, diagnostics.subscriptionDiagnosticsProvider, logger);
  wire_sampling_interval_diagnostics_array_handler(
    addressSpace, diagnostics.subscriptionDiagnosticsProvider, logger);

  ServerModel model;
  model.mServer = std::move(server);
  return model;
}

void ServerModel::populate_history_capabilities_async(AddressSpace addressSpace,
  ServerConfig::HistoryConfig histConfig, ServerConfig::ServerCapabilities serverCapabilities,
  std::function<void(VoidResult)> done)
{
  HistoryCapabilitiesOperation::start(
    std::move(addressSpace), std::move(histConfig), std::move(serverCapabilities), std::move(done));
}

}  // namespace ua::server
