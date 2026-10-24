// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_diagnostics_helper.h"
#include "ua_whole_value_source.h"

#include "ua_instance_utils.h"
#include "ua_namespace_route.h"
#include "ua_weak_address_space.h"
#include "ua_self_owning_operation.h"
#include "ua_sync_wait.h"
#include "ua_callback_safety.h"
#include "ua_referencetype_id.h"
#include "ua_server_counters.h"
#include "ua_service_counter_data_type.h"
#include "ua_session_diagnostics_data_type.h"
#include "ua_session_security_diagnostics_data_type.h"
#include "ua_session_description.h"
#include "ua_session_security.h"
#include "ua_to_result.h"
#include "ua_node.h"

#include <future>

namespace ua::server
{

namespace
{

ServiceCounterDataType load_counter(const ServiceCounter& sc)
{
  ServiceCounterDataType dt;
  dt.total_count() = sc.totalCount.load(std::memory_order_relaxed);
  dt.error_count() = sc.errorCount.load(std::memory_order_relaxed);
  return dt;
}

}  // namespace

SessionDiagnosticsDataType build_session_diagnostics(
  const SessionCounters& c, const SessionSecurityState& sec, const SessionDescriptiveState& desc)
{
  // The session's strand writes these on ActivateSession while this runs on the reading thread.
  const std::scoped_lock lock{sec.mutex, desc.mutex};
  SessionDiagnosticsDataType dt;
  dt.session_id() = sec.sessionId;

  // Part 5 12.11 Table 230. All eight are Mandatory components of SessionDiagnosticsVariableType
  // (7.14 Table 79); ClientLastContactTime is derived rather than stored, so a request costs one
  // monotonic store and no wall-clock read.
  dt.session_name() = desc.sessionName;
  dt.client_description() = desc.clientDescription;
  dt.server_uri() = desc.serverUri;
  dt.endpoint_url() = desc.endpointUrl;
  Array<String> locales;
  locales.resize(desc.localeIds.size());
  for (size_t i = 0; i < desc.localeIds.size(); ++i)
  {
    locales[i] = desc.localeIds[i];
  }
  dt.locale_ids() = std::move(locales);
  dt.actual_session_timeout() = static_cast<double>(desc.revisedSessionTimeout.count());
  dt.client_connection_time() = desc.clientConnectionTime;
  dt.client_last_contact_time() = desc.last_contact_time();
  dt.total_request_count() = load_counter(c.totalRequests);
  dt.unauthorized_request_count() = c.unauthorizedRequestCount.load(std::memory_order_relaxed);
  dt.read_count() = load_counter(c.read);
  dt.history_read_count() = load_counter(c.historyRead);
  dt.write_count() = load_counter(c.write);
  dt.history_update_count() = load_counter(c.historyUpdate);
  dt.call_count() = load_counter(c.call);
  dt.create_monitored_items_count() = load_counter(c.createMonitoredItems);
  dt.modify_monitored_items_count() = load_counter(c.modifyMonitoredItems);
  dt.set_monitoring_mode_count() = load_counter(c.setMonitoringMode);
  dt.set_triggering_count() = load_counter(c.setTriggering);
  dt.delete_monitored_items_count() = load_counter(c.deleteMonitoredItems);
  dt.create_subscription_count() = load_counter(c.createSubscription);
  dt.modify_subscription_count() = load_counter(c.modifySubscription);
  dt.set_publishing_mode_count() = load_counter(c.setPublishingMode);
  dt.publish_count() = load_counter(c.publish);
  dt.republish_count() = load_counter(c.republish);
  dt.transfer_subscriptions_count() = load_counter(c.transferSubscriptions);
  dt.delete_subscriptions_count() = load_counter(c.deleteSubscriptions);
  dt.add_nodes_count() = load_counter(c.addNodes);
  dt.add_references_count() = load_counter(c.addReferences);
  dt.delete_nodes_count() = load_counter(c.deleteNodes);
  dt.delete_references_count() = load_counter(c.deleteReferences);
  dt.browse_count() = load_counter(c.browse);
  dt.browse_next_count() = load_counter(c.browseNext);
  dt.translate_browse_paths_to_node_ids_count() = load_counter(c.translateBrowsePaths);
  dt.query_first_count() = load_counter(c.queryFirst);
  dt.query_next_count() = load_counter(c.queryNext);
  dt.register_nodes_count() = load_counter(c.registerNodes);
  dt.unregister_nodes_count() = load_counter(c.unregisterNodes);
  return dt;
}

SessionSecurityDiagnosticsDataType build_session_security_diagnostics(const SessionSecurityState& sec)
{
  // The session's strand writes these on ActivateSession while this runs on the reading thread.
  const std::lock_guard lock{sec.mutex};
  SessionSecurityDiagnosticsDataType dt;
  dt.session_id() = sec.sessionId;
  dt.client_user_id_of_session() = sec.clientUserId;

  Array<String> history;
  history.resize(sec.clientUserIdHistory.size());
  for (size_t i = 0; i < sec.clientUserIdHistory.size(); ++i)
  {
    history[i] = sec.clientUserIdHistory[i];
  }
  dt.client_user_id_history() = std::move(history);

  dt.authentication_mechanism() = sec.authenticationMechanism;
  dt.encoding() = sec.encoding;
  dt.transport_protocol() = sec.transportProtocol;
  dt.security_mode() = sec.securityMode;
  dt.security_policy_uri() = sec.securityPolicyUri;
  dt.client_certificate() = sec.clientCertificate;
  return dt;
}

namespace
{

const NodeId& has_component_ref()
{
  static const NodeId ref{ReferenceTypeId::HasComponent};
  return ref;
}

}  // namespace

// CreateSessionDiagnosticsHelper flow:
//   create_async
//     -> SessionDiagnosticsObject::create_async
//        -> on_object_created
//             -> find_child_id_by_browse_name_async("SessionDiagnostics")
//                -> on_diag_child_found
//                     -> resolve_and_set_value_source_async (diag source)
//                        -> on_diag_handler_set
//                             -> find_child_id_by_browse_name_async("SessionSecurityDiagnostics")
//                                -> on_secdiag_child_found
//                                     -> resolve_and_set_value_source_async (sec source)
//                                        -> on_secdiag_handler_set
//                                             -> complete_create | fail_create
//
// On any failure: fail_create forwards status + shared_detail() to the user callback.
SessionDiagnosticsHelper::SessionDiagnosticsHelper(SessionDiagnosticsObject object,
  std::shared_ptr<SessionCounters> counters, std::shared_ptr<SessionSecurityState> securityState,
  std::shared_ptr<SessionDescriptiveState> descriptiveState, std::vector<NodeId> securityDiagNodeIds)
  : mObject(std::move(object)), mCounters(std::move(counters)), mSecurityState(std::move(securityState)),
    mDescriptiveState(std::move(descriptiveState)), mSecurityDiagnosticNodeIds(std::move(securityDiagNodeIds))
{}

const NodeId& SessionDiagnosticsHelper::node_id() const
{
  return mObject.node_id();
}

const std::vector<NodeId>& SessionDiagnosticsHelper::security_diagnostic_node_ids() const
{
  return mSecurityDiagnosticNodeIds;
}

void SessionDiagnosticsHelper::release()
{
  mObject.release();
}

/// Builds a session's diagnostics object and wires its two live read handlers.
///
/// Strictly linear, and every step is fatal: instantiate the SessionDiagnosticsType object, find its
/// SessionDiagnostics child and give it a handler that snapshots the counters, then do the same for
/// SessionSecurityDiagnostics. The two handlers are what make the nodes live - they rebuild their
/// struct from the session's state on every read rather than caching it.
class SessionDiagnosticsHelper::CreateOperation final : public ua::async::SelfOwningOperation<CreateOperation>
{
public:
  static void start(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    std::shared_ptr<SessionCounters> counters, std::shared_ptr<SessionSecurityState> securityState,
    std::shared_ptr<SessionDescriptiveState> descriptiveState, const InstantiationOptions& options,
    CreateCompleteCallback complete)
  {
    launch(std::make_shared<CreateOperation>(std::move(addressSpace),
      parent,
      browseName,
      std::move(counters),
      std::move(securityState),
      std::move(descriptiveState),
      options,
      std::move(complete)));
  }

  CreateOperation(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    std::shared_ptr<SessionCounters> counters, std::shared_ptr<SessionSecurityState> securityState,
    std::shared_ptr<SessionDescriptiveState> descriptiveState, const InstantiationOptions& options,
    CreateCompleteCallback complete)
    : ua::async::SelfOwningOperation<CreateOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mParent(parent), mBrowseName(browseName),
      mCounters(std::move(counters)), mSecurityState(std::move(securityState)),
      mDescriptiveState(std::move(descriptiveState)), mOptions(options), mComplete(std::move(complete))
  {}

private:
  friend class ua::async::SelfOwningOperation<CreateOperation>;

  // Declared ahead of the body that co_awaits them: an `auto` return type has to be deduced before a
  // caller can name it.
  /// The address space, locked for one step's call; nullopt, with @p completion answered AddressSpaceGone,
  /// when it is gone. The operation holds it weakly (CALLS-21 rule 1).
  template<typename Answer, typename Completion>
  std::optional<AddressSpace> owner_or_gone(Completion& completion)
  {
    auto owner = mAddressSpace.lock();
    if (!owner)
      completion(Answer{::ua::detail::address_space_gone("SessionDiagnostics")});
    return owner;
  }

  auto create_object()
  {
    return await_step<SessionDiagnosticsObjectResult>(
      [this](auto completion) mutable
      {
        if (auto owner = owner_or_gone<SessionDiagnosticsObjectResult>(completion))
          SessionDiagnosticsObject::create_async(
            std::move(*owner), mParent, mBrowseName, mOptions, std::move(completion));
      });
  }

  auto find_child(NodeId parent, const char* browseName)
  {
    return await_step<NodeIdResult>(
      [this, parent = std::move(parent), browseName](auto completion) mutable
      {
        if (auto owner = owner_or_gone<NodeIdResult>(completion))
          instance_utils::find_child_id_by_browse_name_async(std::move(*owner),
            parent,
            has_component_ref(),
            QualifiedName{0, browseName},
            std::move(completion));
      });
  }

  auto attach_whole_value_source(NodeId nodeId, detail::WholeValueRead handler)
  {
    return await_step<VoidResult>(
      [this, nodeId = std::move(nodeId), handler = std::move(handler)](auto completion) mutable
      {
        if (auto owner = owner_or_gone<VoidResult>(completion))
          instance_utils::resolve_and_set_value_source_async(
            std::move(*owner), nodeId, detail::whole_value_source(std::move(handler)), std::move(completion));
      });
  }

  ua::async::Task<> run()
  {
    try
    {
      auto objectResult = co_await create_object();
      if (!objectResult.is_good())
      {
        refuse(
          ::ua::detail::answer_failure(objectResult.status_code(), "AnswerUncertain", "SessionDiagnostics"));
        co_return;
      }
      auto object = std::move(objectResult).value();

      auto diagChild = co_await find_child(object.node_id(), "SessionDiagnostics");
      if (!diagChild.is_good())
      {
        refuse(::ua::detail::lookup_failure(object.node_id(), diagChild.status_code(), "SessionDiagnostics"));
        co_return;
      }

      auto diagHandlerSet = co_await attach_whole_value_source(std::move(diagChild).value(),
        [counters = mCounters, securityState = mSecurityState, descriptiveState = mDescriptiveState](
          const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
        {
          DataValue dv;
          dv.source_timestamp() = DateTime::now();
          dv.value() = Variant{build_session_diagnostics(*counters, *securityState, *descriptiveState)};
          complete(std::move(dv));
        });
      if (!diagHandlerSet.is_good())
      {
        refuse(::ua::detail::answer_failure(
          diagHandlerSet.status_code(), "AnswerUncertain", "SessionDiagnostics"));
        co_return;
      }

      auto secDiagChild = co_await find_child(object.node_id(), "SessionSecurityDiagnostics");
      if (!secDiagChild.is_good())
      {
        refuse(
          ::ua::detail::lookup_failure(object.node_id(), secDiagChild.status_code(), "SessionDiagnostics"));
        co_return;
      }
      auto secDiagNodeId = std::move(secDiagChild).value();

      auto secDiagHandlerSet = co_await attach_whole_value_source(secDiagNodeId,
        [securityState = mSecurityState](
          const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
        {
          DataValue dv;
          dv.source_timestamp() = DateTime::now();
          dv.value() = Variant{build_session_security_diagnostics(*securityState)};
          complete(std::move(dv));
        });
      if (!secDiagHandlerSet.is_good())
      {
        refuse(::ua::detail::answer_failure(
          secDiagHandlerSet.status_code(), "AnswerUncertain", "SessionDiagnostics"));
        co_return;
      }

      SessionDiagnosticsHelper helper{std::move(object),
        std::move(mCounters),
        std::move(mSecurityState),
        std::move(mDescriptiveState),
        std::vector<NodeId>{std::move(secDiagNodeId)}};
      answer(SessionDiagnosticsHelperResult{std::move(helper)});
    }
    catch (const ua::async::Abandoned&)
    {
      fail(StatusCode{Status::BadOperationAbandoned}, nullptr);
    }
    catch (...)
    {
      const auto bad = ua::exception_to_status_code(std::current_exception());
      fail(bad, bad.shared_detail());
    }
  }

  void fail_to_start(StatusCode status)
  {
    fail(status, status.shared_detail());
  }

  /// Answers @p failure, a step's answer as the step builders map it: a Bad answer as it is, an Uncertain
  /// one, with or without a value, refused (Bad_InternalError). Each step acts on its answer, so the helper
  /// is built only from Good answers.
  void refuse(const StatusCode& failure)
  {
    fail(failure, failure.shared_detail());
  }

  void fail(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    answer(SessionDiagnosticsHelperResult{status, std::move(detail)});
  }

  /// Fires once, and through invoke_user_callback: this runs inside an Asio-posted continuation, so a
  /// throwing application callback would otherwise unwind out of io_context::run() and terminate the
  /// process. No Logger is in scope, so the no-logger overload is used.
  void answer(SessionDiagnosticsHelperResult result)
  {
    if (auto complete = std::exchange(mComplete, nullptr))
    {
      detail::invoke_user_callback([&] { complete(std::move(result)); });
    }
  }

  WeakAddressSpace mAddressSpace;
  NodeId mParent;
  QualifiedName mBrowseName;
  std::shared_ptr<SessionCounters> mCounters;
  std::shared_ptr<SessionSecurityState> mSecurityState;
  std::shared_ptr<SessionDescriptiveState> mDescriptiveState;
  InstantiationOptions mOptions;
  CreateCompleteCallback mComplete;
};

void SessionDiagnosticsHelper::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, std::shared_ptr<SessionCounters> counters,
  std::shared_ptr<SessionSecurityState> securityState,
  std::shared_ptr<SessionDescriptiveState> descriptiveState, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  // Declared noexcept: the throwing setup work is inside the operation, whose launch reports an
  // allocation failure through fail_to_start rather than letting it escape. The error surface of an
  // *_async function is its callback, not an exception.
  try
  {
    CreateOperation::start(std::move(addressSpace),
      parent,
      browseName,
      std::move(counters),
      std::move(securityState),
      std::move(descriptiveState),
      options,
      std::move(complete));
  }
  catch (...)
  {
    detail::invoke_user_callback([&]
      { complete(SessionDiagnosticsHelperResult{ua::exception_to_status_code(std::current_exception())}); });
  }
}

SessionDiagnosticsHelperResult SessionDiagnosticsHelper::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, std::shared_ptr<SessionCounters> counters,
  std::shared_ptr<SessionSecurityState> securityState,
  std::shared_ptr<SessionDescriptiveState> descriptiveState, const InstantiationOptions& options) noexcept
{
  try
  {
    // The chain below this used to answer on the calling stack, which is the only reason this wait
    // returned. It posts now, so a thread of the address space's executor would be waiting for work
    // queued behind it: refuse rather than hang.
    const auto executor = addressSpace.executor();

    return ua::async::detail::blocking_call<SessionDiagnosticsHelperResult>(executor,
      [&](std::function<void(SessionDiagnosticsHelperResult)> complete)
      {
        SessionDiagnosticsHelper::create_async(addressSpace,
          parent,
          browseName,
          std::move(counters),
          std::move(securityState),
          std::move(descriptiveState),
          options,
          std::move(complete));
      });
  }
  catch (...)
  {
    return ua::exception_to_status_code(std::current_exception());
  }
}

SessionDiagnosticsHelper SessionDiagnosticsHelper::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, std::shared_ptr<SessionCounters> counters,
  std::shared_ptr<SessionSecurityState> securityState,
  std::shared_ptr<SessionDescriptiveState> descriptiveState, const InstantiationOptions& options)
{
  return ua::detail::good_value(try_create_sync(addressSpace,
    parent,
    browseName,
    std::move(counters),
    std::move(securityState),
    std::move(descriptiveState),
    options));
}

}  // namespace ua::server
