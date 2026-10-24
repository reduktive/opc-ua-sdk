// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_whole_value_source.h"
#include "ua_push_management_wiring.h"
#include "ua_access_level_type.h"
#include "ua_array.h"
#include "ua_call_method_result.h"
#include "ua_data_value.h"
#include "ua_datatype_id.h"
#include "ua_date_time.h"
#include "ua_localized_text.h"
#include "ua_method_adapter.h"
#include "ua_node.h"
#include "ua_node_class.h"
#include "ua_method_id.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_ref_structure.h"
#include "ua_referencetype_id.h"
#include "ua_structure.h"
#include "ua_transaction_error_type.h"
#include "ua_value_rank.h"
#include "ua_variable_id.h"
#include "ua_variabletype_id.h"

#include "instantiation/ua_instantiation_options.h"
#include "instantiation/ua_instantiation_service.h"
#include "ua_guid.h"
#include "ua_log_exception.h"
#include "ua_to_string.h"

#include "ua_certificate_update_requested_audit_event_payload.h"
#include "ua_certificate_updated_audit_event_payload.h"
#include "ua_trust_list_update_requested_audit_event_payload.h"
#include "ua_trust_list_updated_audit_event_payload.h"

#include <future>

#include <cassert>

namespace ua
{

namespace
{

// ---------------------------------------------------------------------------
// Helper: find a method node and register a MethodAdapter handler on it.
// ---------------------------------------------------------------------------

template<typename ArgsTuple>
void register_method_handler(AddressSpace& addressSpace, MethodId methodId,
  typename MethodAdapter<ArgsTuple>::Handler handler, const Logger& logger)
{
  auto findResult = addressSpace.try_find_node_sync(NodeId{methodId});
  if (!findResult)
  {
    logger.warning("Push management: could not find method node {}", utils::to_underlying(methodId));
    return;
  }

  auto* source = findResult.value()->method_call_source();
  if (!source)
  {
    logger.warning("Push management: method node {} has no MethodCallSource", utils::to_underlying(methodId));
    return;
  }

  source->set_call_handler(MethodAdapter<ArgsTuple>{std::move(handler)});
}

// ---------------------------------------------------------------------------
// Security check helpers
// ---------------------------------------------------------------------------

bool require_encrypted_channel(
  shared_ptr<const MethodCallContext> context, CallMethodResult& result, CallMethodCompleteCallback& complete)
{
  if (!context)
  {
    result.status_code() = StatusCode{Status::BadUserAccessDenied};
    complete(CallResult{std::move(result)});
    return false;
  }

  if (context->channelSecurityMode != MessageSecurityMode::SignAndEncrypt)
  {
    result.status_code() = StatusCode{Status::BadSecurityModeInsufficient};
    complete(CallResult{std::move(result)});
    return false;
  }

  return true;
}

bool require_authenticated_channel(
  shared_ptr<const MethodCallContext> context, CallMethodResult& result, CallMethodCompleteCallback& complete)
{
  if (!context)
  {
    result.status_code() = StatusCode{Status::BadUserAccessDenied};
    complete(CallResult{std::move(result)});
    return false;
  }

  // Authenticated = at least Sign or SignAndEncrypt
  if (context->channelSecurityMode == MessageSecurityMode::Invalid ||
      context->channelSecurityMode == MessageSecurityMode::None)
  {
    result.status_code() = StatusCode{Status::BadSecurityModeInsufficient};
    complete(CallResult{std::move(result)});
    return false;
  }

  return true;
}

// ---------------------------------------------------------------------------
// Certificate type helpers
// ---------------------------------------------------------------------------

NodeId certificate_type_to_node_id(CertificateType type)
{
  switch (type)
  {
  case CertificateType::RsaMinApplication:
    return NodeId{0, utils::to_underlying(ObjectTypeId::RsaMinApplicationCertificateType)};
  case CertificateType::RsaSha256Application:
    return NodeId{0, utils::to_underlying(ObjectTypeId::RsaSha256ApplicationCertificateType)};
  case CertificateType::EccNistP256Application:
    return NodeId{0, utils::to_underlying(ObjectTypeId::EccNistP256ApplicationCertificateType)};
  case CertificateType::EccNistP384Application:
    return NodeId{0, utils::to_underlying(ObjectTypeId::EccNistP384ApplicationCertificateType)};
  case CertificateType::EccBrainpoolP256r1Application:
    return NodeId{0, utils::to_underlying(ObjectTypeId::EccBrainpoolP256r1ApplicationCertificateType)};
  case CertificateType::EccBrainpoolP384r1Application:
    return NodeId{0, utils::to_underlying(ObjectTypeId::EccBrainpoolP384r1ApplicationCertificateType)};
  case CertificateType::EccCurve25519Application:
    return NodeId{0, utils::to_underlying(ObjectTypeId::EccCurve25519ApplicationCertificateType)};
  case CertificateType::EccCurve448Application:
    return NodeId{0, utils::to_underlying(ObjectTypeId::EccCurve448ApplicationCertificateType)};
  default:
    return NodeId{};
  }
}

// ---------------------------------------------------------------------------
// Audit event helpers
// ---------------------------------------------------------------------------

void fill_audit_base(AuditEventPayload& event, const std::string& serverId, bool success)
{
  event.sourceNode = NodeId{ObjectId::Server};
  event.actionTimeStamp = Variant{DateTime::now()};
  event.status = success;
  event.serverId = serverId;
}

void emit_trust_list_update_requested(std::weak_ptr<EventSink> sink, const std::string& serverId)
{
  auto s = sink.lock();
  if (!s)
    return;
  TrustListUpdateRequestedAuditEventPayload event;
  fill_audit_base(event, serverId, true);
  event.sourceName = "CertificateGroup/TrustListManager";
  event.message = LocalizedText{"", "Trust list update requested"};
  event.severity = 1;
  s->emit(event);
}

void emit_trust_list_updated(
  std::weak_ptr<EventSink> sink, const std::string& serverId, const NodeId& trustListId)
{
  auto s = sink.lock();
  if (!s)
    return;
  TrustListUpdatedAuditEventPayload event;
  fill_audit_base(event, serverId, true);
  event.sourceName = "CertificateGroup/TrustListManager";
  event.message = LocalizedText{"", "Trust list updated"};
  event.severity = 1;
  event.trustListId = trustListId;
  s->emit(event);
}

void emit_certificate_update_requested(
  std::weak_ptr<EventSink> sink, const std::string& serverId, const NodeId& methodId)
{
  auto s = sink.lock();
  if (!s)
    return;
  CertificateUpdateRequestedAuditEventPayload event;
  fill_audit_base(event, serverId, true);
  event.sourceName = "ServerConfiguration";
  event.message = LocalizedText{"", "Certificate update requested"};
  event.severity = 1;
  event.methodId = methodId;
  s->emit(event);
}

void emit_certificate_updated(
  std::weak_ptr<EventSink> sink, const std::string& serverId, const NodeId& groupId, const NodeId& typeId)
{
  auto s = sink.lock();
  if (!s)
    return;
  CertificateUpdatedAuditEventPayload event;
  fill_audit_base(event, serverId, true);
  event.sourceName = "ServerConfiguration";
  event.message = LocalizedText{"", "Certificate updated"};
  event.severity = 1;
  event.certificateGroup = groupId;
  event.certificateType = typeId;
  s->emit(event);
}

// ---------------------------------------------------------------------------
// Certificate group NodeId tables
// ---------------------------------------------------------------------------

// The NS0 nodes belonging to one CertificateGroup. Part 12 7.8.3 gives every group the same
// CertificateGroupType shape, so the handlers below differ only in which nodes they bind to.
struct TrustListNodeIds
{
  MethodId open;
  MethodId close;
  MethodId read;
  MethodId write;
  MethodId getPosition;
  MethodId setPosition;
  MethodId openWithMasks;
  MethodId closeAndUpdate;
  MethodId addCertificate;
  MethodId removeCertificate;
  VariableId lastUpdateTime;
  VariableId openCount;
  VariableId certificateTypes;
  NodeId trustList;  // Identifies the group in TrustListUpdated audit events.
};

TrustListNodeIds application_group_node_ids()
{
  return TrustListNodeIds{
    .open = MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Open,
    .close = MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Close,
    .read = MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Read,
    .write = MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Write,
    .getPosition =
      MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_GetPosition,
    .setPosition =
      MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_SetPosition,
    .openWithMasks =
      MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_OpenWithMasks,
    .closeAndUpdate =
      MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_CloseAndUpdate,
    .addCertificate =
      MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate,
    .removeCertificate =
      MethodId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_RemoveCertificate,
    .lastUpdateTime =
      VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_LastUpdateTime,
    .openCount =
      VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_OpenCount,
    .certificateTypes =
      VariableId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateTypes,
    .trustList = NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList},
  };
}

TrustListNodeIds user_token_group_node_ids()
{
  return TrustListNodeIds{
    .open = MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_Open,
    .close = MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_Close,
    .read = MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_Read,
    .write = MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_Write,
    .getPosition =
      MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_GetPosition,
    .setPosition =
      MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_SetPosition,
    .openWithMasks =
      MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_OpenWithMasks,
    .closeAndUpdate =
      MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_CloseAndUpdate,
    .addCertificate =
      MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_AddCertificate,
    .removeCertificate =
      MethodId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_RemoveCertificate,
    .lastUpdateTime =
      VariableId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_LastUpdateTime,
    .openCount = VariableId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_OpenCount,
    .certificateTypes =
      VariableId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateTypes,
    .trustList = NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList},
  };
}

// ---------------------------------------------------------------------------
// TrustListManager FileType method handlers
// ---------------------------------------------------------------------------

void wire_trust_list_open(
  AddressSpace& addressSpace, const TrustListNodeIds& ids, std::weak_ptr<TrustListManager> tlm, Logger logger)
{
  using Args = std::tuple<uint8_t>;

  auto handler = [tlm](const NodeId&,
                   const Args& args,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_authenticated_channel(context, result, complete))
      return;

    auto mgr = tlm.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    auto mode = std::get<0>(args);
    mgr->open_async(context->sessionId,
      mode,
      [result = std::move(result), complete = std::move(complete)](Result<uint32_t> openResult) mutable
      {
        if (!openResult)
        {
          result.status_code() = openResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        result.output_arguments().resize(1);
        result.output_arguments()[0] = Variant{openResult.value()};
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(addressSpace, ids.open, std::move(handler), logger);
}

void wire_trust_list_close(
  AddressSpace& addressSpace, const TrustListNodeIds& ids, std::weak_ptr<TrustListManager> tlm, Logger logger)
{
  using Args = std::tuple<uint32_t>;

  auto handler = [tlm](const NodeId&,
                   const Args& args,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_authenticated_channel(context, result, complete))
      return;

    auto mgr = tlm.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    mgr->close_async(context->sessionId,
      std::get<0>(args),
      [result = std::move(result), complete = std::move(complete)](VoidResult closeResult) mutable
      {
        if (!closeResult)
          result.status_code() = closeResult.status_code();
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(addressSpace, ids.close, std::move(handler), logger);
}

void wire_trust_list_read(
  AddressSpace& addressSpace, const TrustListNodeIds& ids, std::weak_ptr<TrustListManager> tlm, Logger logger)
{
  using Args = std::tuple<uint32_t, int32_t>;

  auto handler = [tlm](const NodeId&,
                   const Args& args,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_authenticated_channel(context, result, complete))
      return;

    auto mgr = tlm.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    mgr->read_async(context->sessionId,
      std::get<0>(args),
      std::get<1>(args),
      [result = std::move(result), complete = std::move(complete)](Result<ByteString> readResult) mutable
      {
        if (!readResult)
        {
          result.status_code() = readResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        result.output_arguments().resize(1);
        result.output_arguments()[0] = Variant{std::move(readResult).value()};
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(addressSpace, ids.read, std::move(handler), logger);
}

void wire_trust_list_write(
  AddressSpace& addressSpace, const TrustListNodeIds& ids, std::weak_ptr<TrustListManager> tlm, Logger logger)
{
  using Args = std::tuple<uint32_t, ByteString>;

  auto handler = [tlm](const NodeId&,
                   const Args& args,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_authenticated_channel(context, result, complete))
      return;

    auto mgr = tlm.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    mgr->write_async(context->sessionId,
      std::get<0>(args),
      std::get<1>(args),
      [result = std::move(result), complete = std::move(complete)](VoidResult writeResult) mutable
      {
        if (!writeResult)
          result.status_code() = writeResult.status_code();
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(addressSpace, ids.write, std::move(handler), logger);
}

void wire_trust_list_get_position(
  AddressSpace& addressSpace, const TrustListNodeIds& ids, std::weak_ptr<TrustListManager> tlm, Logger logger)
{
  using Args = std::tuple<uint32_t>;

  auto handler = [tlm](const NodeId&,
                   const Args& args,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_authenticated_channel(context, result, complete))
      return;

    auto mgr = tlm.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    mgr->get_position_async(context->sessionId,
      std::get<0>(args),
      [result = std::move(result), complete = std::move(complete)](Result<uint64_t> posResult) mutable
      {
        if (!posResult)
        {
          result.status_code() = posResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        result.output_arguments().resize(1);
        result.output_arguments()[0] = Variant{posResult.value()};
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(addressSpace, ids.getPosition, std::move(handler), logger);
}

void wire_trust_list_set_position(
  AddressSpace& addressSpace, const TrustListNodeIds& ids, std::weak_ptr<TrustListManager> tlm, Logger logger)
{
  using Args = std::tuple<uint32_t, uint64_t>;

  auto handler = [tlm](const NodeId&,
                   const Args& args,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_authenticated_channel(context, result, complete))
      return;

    auto mgr = tlm.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    mgr->set_position_async(context->sessionId,
      std::get<0>(args),
      std::get<1>(args),
      [result = std::move(result), complete = std::move(complete)](VoidResult setResult) mutable
      {
        if (!setResult)
          result.status_code() = setResult.status_code();
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(addressSpace, ids.setPosition, std::move(handler), logger);
}

// ---------------------------------------------------------------------------
// TrustListManager-specific method handlers
// ---------------------------------------------------------------------------

void wire_trust_list_open_with_masks(
  AddressSpace& addressSpace, const TrustListNodeIds& ids, std::weak_ptr<TrustListManager> tlm, Logger logger)
{
  using Args = std::tuple<uint32_t>;

  auto handler = [tlm](const NodeId&,
                   const Args& args,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_authenticated_channel(context, result, complete))
      return;

    auto mgr = tlm.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    mgr->open_with_masks_async(context->sessionId,
      std::get<0>(args),
      [result = std::move(result), complete = std::move(complete)](Result<uint32_t> openResult) mutable
      {
        if (!openResult)
        {
          result.status_code() = openResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        result.output_arguments().resize(1);
        result.output_arguments()[0] = Variant{openResult.value()};
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(addressSpace, ids.openWithMasks, std::move(handler), logger);
}

void wire_trust_list_close_and_update(AddressSpace& addressSpace, const TrustListNodeIds& ids,
  std::weak_ptr<TrustListManager> tlm, std::weak_ptr<EventSink> eventSink, std::string serverId,
  Logger logger)
{
  using Args = std::tuple<uint32_t>;

  auto handler = [tlm, eventSink, serverId = std::move(serverId), trustListId = ids.trustList](const NodeId&,
                   const Args& args,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_encrypted_channel(context, result, complete))
      return;

    auto mgr = tlm.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    emit_trust_list_update_requested(eventSink, serverId);

    mgr->close_and_update_async(context->sessionId,
      std::get<0>(args),
      [result = std::move(result), complete = std::move(complete), eventSink, serverId, trustListId](
        Result<bool> updateResult) mutable
      {
        if (!updateResult)
        {
          result.status_code() = updateResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        emit_trust_list_updated(eventSink, serverId, trustListId);
        result.output_arguments().resize(1);
        result.output_arguments()[0] = Variant{updateResult.value()};
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(addressSpace, ids.closeAndUpdate, std::move(handler), logger);
}

// Part 12 7.8.2.3: "When the TrustList changes the Server shall re-evaluate the Certificate associated with
// any open Sessions." AddCertificate and RemoveCertificate change it at once, so the open Sessions and
// SecureChannels re-evaluate now - the caller's once this response is written. The Method succeeded (the
// TrustList is changed) whatever the dispatch reports, so a dispatch failure is logged, not returned.
void reevaluate_then_complete(const std::weak_ptr<CertificatePushService>& pushService, NodeId sessionId,
  std::optional<server::MethodResponseCorrelation> correlation, const Logger& logger, CallMethodResult result,
  CallMethodCompleteCallback complete)
{
  auto mgr = pushService.lock();
  if (!mgr)
  {
    complete(CallResult{std::move(result)});
    return;
  }
  mgr->reevaluate_certificates_async(std::move(sessionId),
    correlation,
    [result = std::move(result), complete = std::move(complete), logger](VoidResult dispatched) mutable
    {
      if (dispatched.is_bad())
        log_exception(logger.with_category("security"),
          LogLevel::Warning,
          "TrustList certificate re-evaluation",
          dispatched.status_code());
      complete(CallResult{std::move(result)});
    });
}

void wire_trust_list_add_certificate(AddressSpace& addressSpace, const TrustListNodeIds& ids,
  std::weak_ptr<TrustListManager> tlm, std::weak_ptr<CertificatePushService> pushService,
  std::weak_ptr<EventSink> eventSink, std::string serverId, Logger logger)
{
  using Args = std::tuple<ByteString, bool>;

  auto handler =
    [tlm, pushService, eventSink, serverId = std::move(serverId), trustListId = ids.trustList, logger](
      const NodeId&,
      const Args& args,
      shared_ptr<const MethodCallContext>
        context,
      CallMethodResult result,
      CallMethodCompleteCallback complete)
  {
    if (!require_encrypted_channel(context, result, complete))
      return;

    auto mgr = tlm.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    emit_trust_list_update_requested(eventSink, serverId);

    mgr->add_certificate_async(context->sessionId,
      std::get<0>(args),
      std::get<1>(args),
      [result = std::move(result),
        complete = std::move(complete),
        eventSink,
        serverId,
        trustListId,
        pushService,
        logger,
        sessionId = context->sessionId,
        correlation = ua::detail::MethodCallContextInternalAccess::response_correlation(*context)](
        VoidResult addResult) mutable
      {
        if (!addResult)
        {
          result.status_code() = addResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        emit_trust_list_updated(eventSink, serverId, trustListId);
        reevaluate_then_complete(
          pushService, std::move(sessionId), correlation, logger, std::move(result), std::move(complete));
      });
  };

  register_method_handler<Args>(addressSpace, ids.addCertificate, std::move(handler), logger);
}

void wire_trust_list_remove_certificate(AddressSpace& addressSpace, const TrustListNodeIds& ids,
  std::weak_ptr<TrustListManager> tlm, std::weak_ptr<CertificatePushService> pushService,
  std::weak_ptr<EventSink> eventSink, std::string serverId, Logger logger)
{
  using Args = std::tuple<String, bool>;

  auto handler =
    [tlm, pushService, eventSink, serverId = std::move(serverId), trustListId = ids.trustList, logger](
      const NodeId&,
      const Args& args,
      shared_ptr<const MethodCallContext>
        context,
      CallMethodResult result,
      CallMethodCompleteCallback complete)
  {
    if (!require_encrypted_channel(context, result, complete))
      return;

    auto mgr = tlm.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    emit_trust_list_update_requested(eventSink, serverId);

    auto thumbprint = std::string(static_cast<string_view>(std::get<0>(args)));
    mgr->remove_certificate_async(context->sessionId,
      std::move(thumbprint),
      std::get<1>(args),
      [result = std::move(result),
        complete = std::move(complete),
        eventSink,
        serverId,
        trustListId,
        pushService,
        logger,
        sessionId = context->sessionId,
        correlation = ua::detail::MethodCallContextInternalAccess::response_correlation(*context)](
        VoidResult removeResult) mutable
      {
        if (!removeResult)
        {
          result.status_code() = removeResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        emit_trust_list_updated(eventSink, serverId, trustListId);
        reevaluate_then_complete(
          pushService, std::move(sessionId), correlation, logger, std::move(result), std::move(complete));
      });
  };

  register_method_handler<Args>(addressSpace, ids.removeCertificate, std::move(handler), logger);
}

// Bind every TrustListType Method of one certificate group to its TrustListManager.
void wire_trust_list_group(AddressSpace& addressSpace, const TrustListNodeIds& ids,
  const std::weak_ptr<TrustListManager>& tlm, const std::weak_ptr<CertificatePushService>& pushService,
  const PushManagementWiringParams& params)
{
  // FileType methods.
  wire_trust_list_open(addressSpace, ids, tlm, params.logger);
  wire_trust_list_close(addressSpace, ids, tlm, params.logger);
  wire_trust_list_read(addressSpace, ids, tlm, params.logger);
  wire_trust_list_write(addressSpace, ids, tlm, params.logger);
  wire_trust_list_get_position(addressSpace, ids, tlm, params.logger);
  wire_trust_list_set_position(addressSpace, ids, tlm, params.logger);

  // TrustListManager-specific methods (with audit events).
  wire_trust_list_open_with_masks(addressSpace, ids, tlm, params.logger);
  wire_trust_list_close_and_update(addressSpace, ids, tlm, params.eventSink, params.serverId, params.logger);
  wire_trust_list_add_certificate(
    addressSpace, ids, tlm, pushService, params.eventSink, params.serverId, params.logger);
  wire_trust_list_remove_certificate(
    addressSpace, ids, tlm, pushService, params.eventSink, params.serverId, params.logger);
}

// ---------------------------------------------------------------------------
// ServerConfiguration method handlers
// ---------------------------------------------------------------------------

void wire_update_certificate(AddressSpace& addressSpace, std::weak_ptr<CertificatePushService> pushService,
  std::weak_ptr<EventSink> eventSink, std::string serverId, Logger logger)
{
  using Args = std::tuple<NodeId, NodeId, ByteString, Array<ByteString>, String, ByteString>;

  auto handler = [pushService, eventSink, serverId = std::move(serverId), logger](const NodeId&,
                   const Args& args,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_encrypted_channel(context, result, complete))
      return;

    auto mgr = pushService.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    emit_certificate_update_requested(
      eventSink, serverId, NodeId{MethodId::ServerConfiguration_UpdateCertificate});

    auto& [groupId, typeId, cert, issuers, keyFormat, privateKey] = args;
    std::vector<ByteString> issuerVec(issuers.begin(), issuers.end());

    mgr->update_certificate_async(context->sessionId,
      groupId,
      typeId,
      cert,
      std::move(issuerVec),
      keyFormat,
      privateKey,
      [result = std::move(result), complete = std::move(complete)](Result<bool> updateResult) mutable
      {
        if (!updateResult)
        {
          result.status_code() = updateResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        result.output_arguments().resize(1);
        result.output_arguments()[0] = Variant{updateResult.value()};
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(
    addressSpace, MethodId::ServerConfiguration_UpdateCertificate, std::move(handler), logger);
}

void wire_create_signing_request(
  AddressSpace& addressSpace, std::weak_ptr<CertificatePushService> pushService, Logger logger)
{
  using Args = std::tuple<NodeId, NodeId, String, bool, ByteString>;

  auto handler = [pushService](const NodeId&,
                   const Args& args,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_encrypted_channel(context, result, complete))
      return;

    auto mgr = pushService.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    auto& [groupId, typeId, subjectName, regeneratePrivateKey, nonce] = args;

    mgr->create_signing_request_async(context->sessionId,
      groupId,
      typeId,
      subjectName,
      regeneratePrivateKey,
      nonce,
      [result = std::move(result), complete = std::move(complete)](Result<ByteString> csrResult) mutable
      {
        if (!csrResult)
        {
          result.status_code() = csrResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        result.output_arguments().resize(1);
        result.output_arguments()[0] = Variant{std::move(csrResult).value()};
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(
    addressSpace, MethodId::ServerConfiguration_CreateSigningRequest, std::move(handler), logger);
}

void wire_apply_changes(AddressSpace& addressSpace, std::weak_ptr<CertificatePushService> pushService,
  std::weak_ptr<EventSink> eventSink, std::string serverId, Logger logger)
{
  using Args = std::tuple<>;

  auto handler = [pushService, eventSink, serverId = std::move(serverId), logger](const NodeId&,
                   const Args&,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_authenticated_channel(context, result, complete))
      return;

    const auto correlation = ua::detail::MethodCallContextInternalAccess::response_correlation(*context);
    if (!correlation)
    {
      result.status_code() = StatusCode{Status::BadInternalError,
        make_error_detail("MissingMethodResponseCorrelation",
          "ApplyChanges requires a SecureChannel response correlation",
          "PushManagement")};
      log_exception(logger.with_category("security"), LogLevel::Error, "ApplyChanges", result.status_code());
      complete(CallResult{std::move(result)});
      return;
    }

    auto mgr = pushService.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    mgr->apply_changes_async(context->sessionId,
      *correlation,
      [result = std::move(result), complete = std::move(complete), eventSink, serverId, logger](
        VoidResult applyResult) mutable
      {
        if (!applyResult)
        {
          log_exception(
            logger.with_category("security"), LogLevel::Error, "ApplyChanges", applyResult.status_code());
          result.status_code() = applyResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        // CertificateUpdated auditing is advisory: a host sink must not suppress the Method response.
        try
        {
          emit_certificate_updated(eventSink,
            serverId,
            NodeId{ObjectId::ServerConfiguration_CertificateGroups_DefaultApplicationGroup},
            NodeId{0, utils::to_underlying(ObjectTypeId::RsaSha256ApplicationCertificateType)});
        }
        catch (...)
        {
          log_exception(logger.with_category("security"),
            LogLevel::Error,
            "ApplyChanges CertificateUpdated audit sink",
            ua::exception_to_status_code(std::current_exception()));
        }
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(
    addressSpace, MethodId::ServerConfiguration_ApplyChanges, std::move(handler), logger);
}

void wire_cancel_changes(
  AddressSpace& addressSpace, std::weak_ptr<CertificatePushService> pushService, Logger logger)
{
  using Args = std::tuple<>;

  auto handler = [pushService](const NodeId&,
                   const Args&,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_authenticated_channel(context, result, complete))
      return;

    auto mgr = pushService.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    mgr->cancel_changes_async(context->sessionId,
      [result = std::move(result), complete = std::move(complete)](VoidResult cancelResult) mutable
      {
        if (!cancelResult)
        {
          result.status_code() = cancelResult.status_code();
        }
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(
    addressSpace, MethodId::ServerConfiguration_CancelChanges, std::move(handler), logger);
}

void wire_get_rejected_list(
  AddressSpace& addressSpace, std::weak_ptr<CertificatePushService> pushService, Logger logger)
{
  using Args = std::tuple<>;

  auto handler = [pushService](const NodeId&,
                   const Args&,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_authenticated_channel(context, result, complete))
      return;

    auto mgr = pushService.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    mgr->get_rejected_list_async(
      [result = std::move(result), complete = std::move(complete)](
        Result<std::vector<ByteString>> listResult) mutable
      {
        if (!listResult.has_value())
        {
          result.status_code() = listResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        auto& certs = listResult.value();
        Array<ByteString> certArray;
        for (auto& c : certs)
          certArray.push_back(std::move(c));

        result.output_arguments().resize(1);
        result.output_arguments()[0] = Variant{std::move(certArray)};
        // The Method answers the code the list was answered with; the Call service answers a Good subcode
        // as plain Good.
        result.status_code() = listResult.status_code();
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(
    addressSpace, MethodId::ServerConfiguration_GetRejectedList, std::move(handler), logger);
}

// Part 12 7.10.5: GetCertificates(certificateGroupId) -> (certificateTypeIds[],
// certificates[]). Requires an authenticated SecureChannel; the SecurityAdmin
// Role requirement is enforced by the NodeSet AccessRestrictions / RolePermissions
// on the Method node via the generic Call service (consistent with the other
// ServerConfiguration Methods, which carry no explicit in-handler Role gate).
//
// GetCertificates is an Optional member of ServerConfigurationType that the
// standard NodeSet does NOT pre-instantiate on the ServerConfiguration instance;
// it is materialised from the type declaration (with its InputArguments /
// OutputArguments) at the OPC-reserved id 32333 by
// ensure_optional_server_configuration_members() before this wiring runs.
void wire_get_certificates(
  AddressSpace& addressSpace, std::weak_ptr<CertificatePushService> pushService, Logger logger)
{
  using Args = std::tuple<NodeId>;

  auto handler = [pushService](const NodeId&,
                   const Args& args,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_authenticated_channel(context, result, complete))
      return;

    auto mgr = pushService.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    const auto& [certificateGroupId] = args;

    mgr->get_certificates_async(certificateGroupId,
      [result = std::move(result), complete = std::move(complete)](
        Result<std::pair<std::vector<NodeId>, std::vector<ByteString>>> getResult) mutable
      {
        if (!getResult.has_value())
        {
          result.status_code() = getResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        auto& [typeIds, certs] = getResult.value();
        Array<NodeId> typeIdArray;
        for (auto& id : typeIds)
          typeIdArray.push_back(std::move(id));
        Array<ByteString> certArray;
        for (auto& certificate : certs)
          certArray.push_back(std::move(certificate));

        result.output_arguments().resize(2);
        result.output_arguments()[0] = Variant{std::move(typeIdArray)};
        result.output_arguments()[1] = Variant{std::move(certArray)};
        // The Method answers the code the certificates were answered with; the Call service answers a Good
        // subcode as plain Good.
        result.status_code() = getResult.status_code();
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(
    addressSpace, MethodId::ServerConfiguration_GetCertificates, std::move(handler), logger);
}

// Part 12 7.10.10: ResetToServerDefaults() - no arguments. Requires an
// authenticated SecureChannel (the SecurityAdmin Role requirement is enforced by
// the NodeSet AccessRestrictions / RolePermissions via the generic Call service).
// The instance Method node (i=25709) is shipped by the NodeSet, so no on-demand
// materialisation is needed. Clears the TrustListManager and transitions the server to
// SHUTDOWN via the requestShutdown hook.
void wire_reset_to_server_defaults(
  AddressSpace& addressSpace, std::weak_ptr<CertificatePushService> pushService, Logger logger)
{
  using Args = std::tuple<>;

  auto handler = [pushService](const NodeId&,
                   const Args&,
                   shared_ptr<const MethodCallContext>
                     context,
                   CallMethodResult result,
                   CallMethodCompleteCallback complete)
  {
    if (!require_authenticated_channel(context, result, complete))
      return;

    auto mgr = pushService.lock();
    if (!mgr)
    {
      result.status_code() = StatusCode{Status::BadInternalError};
      complete(CallResult{std::move(result)});
      return;
    }

    mgr->reset_to_server_defaults_async(context->sessionId,
      [result = std::move(result), complete = std::move(complete)](VoidResult resetResult) mutable
      {
        if (resetResult.is_bad())
        {
          result.status_code() = resetResult.status_code();
          complete(CallResult{std::move(result)});
          return;
        }
        complete(CallResult{std::move(result)});
      });
  };

  register_method_handler<Args>(
    addressSpace, MethodId::ServerConfiguration_ResetToServerDefaults, std::move(handler), logger);
}

// ---------------------------------------------------------------------------
// Property initialization
// ---------------------------------------------------------------------------

void write_property(AddressSpace& addressSpace, VariableId variableId, Variant value, const Logger& logger)
{
  auto findResult = addressSpace.try_find_node_sync(NodeId{variableId});
  if (!findResult)
  {
    logger.warning("Push management: could not find variable node {}", utils::to_underlying(variableId));
    return;
  }

  auto accessor = findResult.value().as<VariableAccessor>();
  if (!accessor)
  {
    logger.warning("Push management: node {} is not a VariableAccessor", utils::to_underlying(variableId));
    return;
  }

  DataValue dv;
  dv.value() = std::move(value);
  accessor->write_value_sync(std::move(dv));
}

void initialize_properties(AddressSpace& addressSpace, const PushManagementWiringParams& params)
{
  // SupportedPrivateKeyFormats
  {
    Array<String> formats;
    formats.push_back(String{"PEM"});
    write_property(addressSpace,
      VariableId::ServerConfiguration_SupportedPrivateKeyFormats,
      Variant{std::move(formats)},
      params.logger);
  }

  // MaxTrustListSize
  write_property(addressSpace,
    VariableId::ServerConfiguration_MaxTrustListSize,
    Variant{params.maxTrustListSize},
    params.logger);

  // MulticastDnsEnabled
  write_property(
    addressSpace, VariableId::ServerConfiguration_MulticastDnsEnabled, Variant{false}, params.logger);

  // HasSecureElement
  write_property(addressSpace,
    VariableId::ServerConfiguration_HasSecureElement,
    Variant{params.crypto->has_secure_element()},
    params.logger);
}

// ---------------------------------------------------------------------------
// Dynamic property handlers (LastUpdateTime, OpenCount)
// ---------------------------------------------------------------------------

void wire_last_update_time(AddressSpace& addressSpace, const TrustListNodeIds& ids,
  std::shared_ptr<const TrustListInfo> trustListInfo, Logger logger)
{
  auto result = addressSpace.try_find_node_sync(NodeId{ids.lastUpdateTime});
  if (!result)
  {
    logger.warning("Push management: could not find TrustListManager LastUpdateTime variable node");
    return;
  }

  auto* evs = result.value()->external_value_source();
  if (!evs)
    return;

  evs->set_value_source(detail::whole_value_source(
    [trustListInfo](
      const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
    {
      DataValue dv;
      dv.value() = Variant{trustListInfo->last_update_time()};
      dv.server_timestamp() = DateTime::now();
      dv.source_timestamp() = DateTime::now();
      complete(std::move(dv));
    }));
}

void wire_open_count(AddressSpace& addressSpace, const TrustListNodeIds& ids,
  std::shared_ptr<const TrustListInfo> trustListInfo, Logger logger)
{
  auto result = addressSpace.try_find_node_sync(NodeId{ids.openCount});
  if (!result)
  {
    logger.warning("Push management: could not find TrustListManager OpenCount variable node");
    return;
  }

  auto* evs = result.value()->external_value_source();
  if (!evs)
    return;

  evs->set_value_source(detail::whole_value_source(
    [trustListInfo](
      const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
    {
      DataValue dv;
      dv.value() = Variant{trustListInfo->open_count()};
      dv.server_timestamp() = DateTime::now();
      dv.source_timestamp() = DateTime::now();
      complete(std::move(dv));
    }));
}

void wire_certificate_types(AddressSpace& addressSpace, const TrustListNodeIds& ids,
  std::shared_ptr<CertificateStore> certificateStore, Logger logger)
{
  auto result = addressSpace.try_find_node_sync(NodeId{ids.certificateTypes});
  if (!result)
  {
    logger.warning("Push management: could not find CertificateTypes variable node");
    return;
  }

  auto* evs = result.value()->external_value_source();
  if (!evs)
    return;

  evs->set_value_source(detail::whole_value_source(
    [certificateStore](
      const ValueSource::ReadContext& /*context*/, std::function<void(DataValueResult)> complete)
    {
      certificateStore->get_application_certificates_async(

        [complete = std::move(complete)](
          CertificateStore::ApplicationCertificateListResult appCertsResult) mutable
        {
          Array<NodeId> certTypes;
          if (appCertsResult.is_good())
          {
            for (const auto& appCert : appCertsResult.value())
            {
              auto nodeId = certificate_type_to_node_id(appCert.certificateType);
              if (!nodeId.is_null())
                certTypes.push_back(std::move(nodeId));
            }
          }

          DataValue dv;
          dv.value() = Variant{std::move(certTypes)};
          dv.server_timestamp() = DateTime::now();
          dv.source_timestamp() = DateTime::now();
          complete(std::move(dv));
        });
    }));
}

// ---------------------------------------------------------------------------
// TransactionDiagnostics / SupportsTransactions (Part 12 7.10.11, UA-1.05.06)
// ---------------------------------------------------------------------------

// GetCertificates (Method) and SupportsTransactions (Variable) are Optional
// members of ServerConfigurationType that the UA-1.05.06 NodeSet does NOT
// pre-instantiate on the ServerConfiguration instance (i=12637) - unlike
// UpdateCertificate / ApplyChanges / ... which are present. Their instance NodeIds
// are nevertheless reserved in NodeIds.csv (the OPC id registry that drives the
// generated id enums): GetCertificates=32333 (+ InputArguments=32334 /
// OutputArguments=32335), SupportsTransactions=18663.
//
// Materialise them FROM the type definition with the InstantiationService, so the
// nodes are fully formed (the Method's argument metadata is copied from the type
// declaration) - never hand-rolled. The reserved ids are assigned by a browse-name
// allocator so the wiring + generated MethodId/VariableId enums bind correctly.
// The instantiation engine skips members already present on the instance, so this
// only creates the two missing optionals (and GetCertificates' arg children).
//
// GetCertificates' InputArguments / OutputArguments are Mandatory, so they are
// instantiated by the recursion regardless of the filter - but the allocator must
// still map their browse names to the reserved arg ids (32334 / 32335).
void ensure_optional_server_configuration_members(AddressSpace& addressSpace, const Logger& logger)
{
  const NodeId serverConfigType{0, utils::to_underlying(ObjectTypeId::ServerConfigurationType)};
  const NodeId serverConfig{0, utils::to_underlying(ObjectId::ServerConfiguration)};

  auto reservedAllocator = [&logger](uint16_t nsIndex, const QualifiedName& browseName) -> NodeId
  {
    const auto& name = browseName.name();
    if (name == "GetCertificates")
      return NodeId{0, utils::to_underlying(MethodId::ServerConfiguration_GetCertificates)};
    if (name == "InputArguments")
      return NodeId{0, 32334U};  // ServerConfiguration_GetCertificates_InputArguments
    if (name == "OutputArguments")
      return NodeId{0, 32335U};  // ServerConfiguration_GetCertificates_OutputArguments
    if (name == "SupportsTransactions")
      return NodeId{0, utils::to_underlying(VariableId::ServerConfiguration_SupportsTransactions)};
    // Defensive: the filter restricts to the names above, so this is unreachable;
    // fall back to a collision-free Guid id and warn rather than risk a reserved-id clash.
    logger.warning(
      "Push management: unexpected optional member '{}' during instantiation", std::string{name});
    return NodeId{nsIndex, Guid::create_and_generate()};
  };

  auto filter = [](const ChildFilterInfo& info)
  {
    const auto name = info.browseName.name();
    return name == "GetCertificates" || name == "SupportsTransactions";
  };

  // The filter selects the members and the allocator names them; the depth budget comes from the
  // address space's own limits.
  InstantiationOptions options;
  options.nodeIdAllocator = reservedAllocator;
  options.optionalChildFilter = filter;

  // Bridge the async instantiation to this synchronous setup path, which runs on the server setup
  // thread; on an address-space executor thread it is refused, and the refusal is logged below.
  auto result = ua::async::detail::blocking_call<VoidResult>(addressSpace.executor(),
    [&](std::function<void(VoidResult)> complete)
    {
      InstantiationService{addressSpace}.instantiate_optional_members_async(
        serverConfig, serverConfigType, options, std::move(complete));
    });
  if (result.is_bad())
  {
    logger.warning("Push management: failed to instantiate optional ServerConfiguration members ({})",
      result.status_code().as_uint32());
  }

  // SupportsTransactions advertises true: the SDK implements the push transaction
  // model (queues changes; applyChangesRequired always TRUE). The type declaration
  // carries no Value, so set it explicitly (idempotent).
  const NodeId supportsTxnId{0, utils::to_underlying(VariableId::ServerConfiguration_SupportsTransactions)};
  if (auto node = addressSpace.try_find_node_sync(supportsTxnId))
  {
    if (auto var = node.value().as<VariableAccessor>())
    {
      var->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
      var->write_value_sync(true);
    }
  }
  else
  {
    logger.warning("Push management: SupportsTransactions node was not materialised");
  }

  // Ensure GetCertificates is callable.
  const NodeId getCertificatesId{0, utils::to_underlying(MethodId::ServerConfiguration_GetCertificates)};
  if (auto node = addressSpace.try_find_node_sync(getCertificatesId))
  {
    if (auto method = node.value().as<MethodAccessor>())
      method->set_executable(true);
  }
  else
  {
    logger.warning("Push management: GetCertificates method node was not materialised");
  }
}

// All TransactionDiagnostics child Variables, in fixed order.
constexpr VariableId transactionDiagnosticsVars[] = {
  VariableId::ServerConfiguration_TransactionDiagnostics_StartTime,
  VariableId::ServerConfiguration_TransactionDiagnostics_EndTime,
  VariableId::ServerConfiguration_TransactionDiagnostics_Result,
  VariableId::ServerConfiguration_TransactionDiagnostics_AffectedTrustLists,
  VariableId::ServerConfiguration_TransactionDiagnostics_AffectedCertificateGroups,
  VariableId::ServerConfiguration_TransactionDiagnostics_Errors,
};

// Part 12 7.10.11: if no transaction has started, every TransactionDiagnostics
// Variable carries a status of Bad_OutOfService. Apply that initial state.
void initialize_transaction_diagnostics(AddressSpace& addressSpace, const Logger& logger)
{
  for (auto variableId : transactionDiagnosticsVars)
  {
    auto findResult = addressSpace.try_find_node_sync(NodeId{variableId});
    if (!findResult)
    {
      logger.warning("Push management: could not find TransactionDiagnostics variable node {}",
        utils::to_underlying(variableId));
      continue;
    }
    auto accessor = findResult.value().as<VariableAccessor>();
    if (!accessor)
      continue;

    DataValue dv;
    dv.status() = StatusCode{Status::BadOutOfService};
    accessor->write_value_sync(std::move(dv));
  }
}

// Write a TransactionDiagnostics snapshot to the NS0 Object after a transaction
// terminal point. Invoked from the CertificatePushService strand, so every lookup
// and write is asynchronous: the namespace may answer by a post to the executor
// that strand runs on. Each Variable is written independently and best-effort
// (a failure is logged). The writes go through the internal accessor, which is not
// subject to the node's RolePermissions/AccessRestrictions (those gate Client
// reads, not server-internal population).
void publish_transaction_diagnostics(
  const WeakAddressSpace& weakAddressSpace, const TransactionDiagnosticsRecord& record, const Logger& logger)
{
  auto addressSpaceOpt = weakAddressSpace.lock();
  if (!addressSpaceOpt)
    return;
  AddressSpace addressSpace = *addressSpaceOpt;

  auto write = [&addressSpace, &logger](VariableId variableId, Variant value)
  {
    DataValue dv;
    dv.value() = std::move(value);
    dv.server_timestamp() = DateTime::now();
    dv.source_timestamp() = DateTime::now();
    addressSpace.find_node_async(NodeId{variableId},
      [logger, variableId, dv = std::move(dv)](NodeAccessorResult findResult) mutable
      {
        // The diagnostics are written only to a Variable the namespace found without doubt.
        if (!findResult.is_good())
        {
          logger.warning("Push management: could not find TransactionDiagnostics variable node {}",
            utils::to_underlying(variableId));
          return;
        }
        auto accessor = findResult.value().as<VariableAccessor>();
        if (!accessor)
          return;
        accessor->write_value_async(std::move(dv),
          [logger, variableId](VoidResult written)
          {
            if (written.is_bad())
              logger.warning("Push management: TransactionDiagnostics variable {} was not written: {}",
                utils::to_underlying(variableId),
                ua::to_string(written.status_code()));
          });
      });
  };

  write(VariableId::ServerConfiguration_TransactionDiagnostics_StartTime, Variant{record.startTime});
  write(VariableId::ServerConfiguration_TransactionDiagnostics_EndTime, Variant{record.endTime});
  write(VariableId::ServerConfiguration_TransactionDiagnostics_Result, Variant{record.result});

  Array<NodeId> trustLists;
  for (const auto& id : record.affectedTrustLists)
    trustLists.push_back(id);
  write(VariableId::ServerConfiguration_TransactionDiagnostics_AffectedTrustLists,
    Variant{std::move(trustLists)});

  Array<NodeId> groups;
  for (const auto& id : record.affectedCertificateGroups)
    groups.push_back(id);
  write(VariableId::ServerConfiguration_TransactionDiagnostics_AffectedCertificateGroups,
    Variant{std::move(groups)});

  Array<RefStructure<Structure>> errors;
  errors.payload().reserve(record.errors.size());
  for (const auto& error : record.errors)
  {
    RefStructure<Structure> ref;
    ref = std::unique_ptr<Structure>{std::make_unique<TransactionErrorType>(error).release()};
    errors.payload().push_back(std::move(ref));
  }
  write(VariableId::ServerConfiguration_TransactionDiagnostics_Errors, Variant{std::move(errors)});
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

PushManagementComponents wire_push_management(PushManagementWiringParams params)
{
  // Create strands - one per component
  auto tlmStrand = boost::asio::make_strand(params.executor);
  auto pushStrand = boost::asio::make_strand(params.executor);

  auto pushWeakHolder = std::make_shared<std::weak_ptr<CertificatePushService>>();
  // A trust-list modification is refused up front while another session owns the push transaction.
  // The claim it grants is withdrawn when dropped (TrustListModificationClaim).
  const auto modificationClaim =
    [pushWeakHolder](const NodeId& sessionId) -> Result<std::shared_ptr<TrustListModificationClaim>>
  {
    if (auto mgr = pushWeakHolder->lock())
      return mgr->claim_trust_list_modification(sessionId);
    return std::shared_ptr<TrustListModificationClaim>{};  // no push service: nothing to claim
  };
  // AddCertificate / RemoveCertificate: refused while any transaction is held (Part 12 7.8.2.4, 7.8.2.5).
  const auto immediateModificationClaim =
    [pushWeakHolder](const NodeId& sessionId) -> Result<std::shared_ptr<TrustListModificationClaim>>
  {
    if (auto mgr = pushWeakHolder->lock())
      return mgr->claim_immediate_trust_list_modification(sessionId);
    return std::shared_ptr<TrustListModificationClaim>{};
  };

  // Open with write access opens or joins the Session's transaction (Part 12 Figure 22).
  const auto openedForWrite = [pushWeakHolder](
                                NodeId sessionId, std::shared_ptr<TrustListModificationClaim> claim)
  {
    if (auto mgr = pushWeakHolder->lock())
      mgr->on_trust_list_opened_for_write(std::move(sessionId), std::move(claim));
  };

  // Create TrustListManager
  TrustListManager::Dependencies tlmDeps{
    .strand = std::move(tlmStrand),
    .certificateStore = params.certificateStore,
    .crypto = params.crypto,
    .executor = params.executor,
    .maxTrustListSize = params.maxTrustListSize,
    .activityTimeout = params.activityTimeout,
    .logger = params.logger,
    .modificationClaim = modificationClaim,
    .immediateModificationClaim = immediateModificationClaim,
    .openedForWrite = openedForWrite,
    .stageUntilApply = true,  // the push transaction applies the change (Part 12 7.8.2.3)
  };

  // We need a two-phase init: TrustListManager needs a callback that references
  // CertificatePushService, but CertificatePushService needs TrustListManager.
  // Solution: create TLM with a callback that captures a shared_ptr<weak_ptr> and
  // fill it in after creating the CertificatePushService.
  const auto applicationIds = application_group_node_ids();
  const auto userTokenIds = user_token_group_node_ids();

  auto trustList = TrustListManager::create(std::move(tlmDeps),
    [pushWeakHolder, trustListId = applicationIds.trustList](
      NodeId sessionId, std::shared_ptr<TrustListModificationClaim> claim)
    {
      if (auto mgr = pushWeakHolder->lock())
        mgr->on_trust_list_modified(std::move(sessionId), trustListId, std::move(claim));
    });

  // Part 12 7.8.3.3: the DefaultUserTokenGroup exists only to expose its TrustList, so it gets its
  // own TrustListManager over the user-token store and no certificate-update path.
  std::shared_ptr<TrustListManager> userTokenTrustList;
  if (params.userTokenCertificateStore)
  {
    TrustListManager::Dependencies userTokenDeps{
      .strand = boost::asio::make_strand(params.executor),
      .certificateStore = params.userTokenCertificateStore,
      .crypto = params.crypto,
      .executor = params.executor,
      .maxTrustListSize = params.maxTrustListSize,
      .activityTimeout = params.activityTimeout,
      .logger = params.logger,
      .modificationClaim = modificationClaim,
      .immediateModificationClaim = immediateModificationClaim,
      .openedForWrite = openedForWrite,
      .stageUntilApply = true,
    };
    userTokenTrustList = TrustListManager::create(std::move(userTokenDeps),
      [pushWeakHolder, trustListId = userTokenIds.trustList](
        NodeId sessionId, std::shared_ptr<TrustListModificationClaim> claim)
      {
        if (auto mgr = pushWeakHolder->lock())
          mgr->on_trust_list_modified(std::move(sessionId), trustListId, std::move(claim));
      });
  }

  // Diagnostics sink: weak-capture the address space so the push service can
  // populate the NS0 TransactionDiagnostics Object at each transaction terminal
  // point without extending the address space's lifetime.
  auto diagnosticsWeakAddressSpace = params.addressSpace.weak();
  auto diagnosticsLogger = params.logger;

  // Create CertificatePushService
  CertificatePushService::Dependencies pushDeps{
    .strand = std::move(pushStrand),
    .crypto = params.crypto,
    .certificateStore = params.certificateStore,
    .trustList = trustList,
    .userTokenTrustList = userTokenTrustList,
    .executor = params.executor,
    .logger = params.logger,
    .applicationUri = std::move(params.applicationUri),
    .hostnames = std::move(params.hostnames),
    .closeAllChannels = std::move(params.closeAllChannels),
    .reevaluateCertificates = std::move(params.reevaluateCertificates),
    .requestShutdown = std::move(params.requestShutdown),
    .publishTransactionDiagnostics = [diagnosticsWeakAddressSpace, diagnosticsLogger](
                                       TransactionDiagnosticsRecord record)
    { publish_transaction_diagnostics(diagnosticsWeakAddressSpace, record, diagnosticsLogger); },
    .dependencyFailureDetailBuilder = {},
    .applyWriteStateCheck = {},
    .certificateDerEncoder = {},
    .sessionExists = std::move(params.sessionExists),
    .servedEndpointPolicies = std::move(params.servedEndpointPolicies),
  };

  auto certificatePushService = CertificatePushService::create(std::move(pushDeps));
  *pushWeakHolder = certificatePushService;

  // Create observer
  auto observer = make_push_certificate_observer(certificatePushService, trustList, userTokenTrustList);

  // Wire method handlers
  auto& addressSpace = params.addressSpace;

  wire_trust_list_group(addressSpace, applicationIds, trustList, certificatePushService, params);
  if (userTokenTrustList)
  {
    wire_trust_list_group(addressSpace, userTokenIds, userTokenTrustList, certificatePushService, params);
  }

  // Materialise the Optional ServerConfiguration members (GetCertificates +
  // SupportsTransactions) from the type definition BEFORE wiring handlers, so the
  // GetCertificates Method node exists for wire_get_certificates to bind to.
  ensure_optional_server_configuration_members(addressSpace, params.logger);

  // ServerConfiguration methods (with audit events)
  wire_update_certificate(
    addressSpace, certificatePushService, params.eventSink, params.serverId, params.logger);
  wire_create_signing_request(addressSpace, certificatePushService, params.logger);
  wire_apply_changes(addressSpace, certificatePushService, params.eventSink, params.serverId, params.logger);
  wire_cancel_changes(addressSpace, certificatePushService, params.logger);
  wire_get_rejected_list(addressSpace, certificatePushService, params.logger);
  wire_get_certificates(addressSpace, certificatePushService, params.logger);
  wire_reset_to_server_defaults(addressSpace, certificatePushService, params.logger);

  // Initialize properties
  initialize_properties(addressSpace, params);

  // Seed the TransactionDiagnostics Object (Part 12 7.10.11, UA-1.05.06).
  initialize_transaction_diagnostics(addressSpace, params.logger);

  // Wire dynamic properties (LastUpdateTime, OpenCount) - uses the info object directly
  wire_last_update_time(addressSpace, applicationIds, trustList->info(), params.logger);
  wire_open_count(addressSpace, applicationIds, trustList->info(), params.logger);
  wire_certificate_types(addressSpace, applicationIds, params.certificateStore, params.logger);

  if (userTokenTrustList)
  {
    wire_last_update_time(addressSpace, userTokenIds, userTokenTrustList->info(), params.logger);
    wire_open_count(addressSpace, userTokenIds, userTokenTrustList->info(), params.logger);
    // Part 12 7.8.3.3: this group "shall leave CertificateTypes list empty" - no certificate type
    // can be assigned to a user credential, so the Property is written once as an empty array
    // rather than reflecting the store's contents.
    write_property(addressSpace, userTokenIds.certificateTypes, Variant{Array<NodeId>{}}, params.logger);
  }

  return PushManagementComponents{
    .trustList = std::move(trustList),
    .userTokenTrustList = std::move(userTokenTrustList),
    .certificatePushService = std::move(certificatePushService),
    .observer = std::move(observer),
  };
}

}  // namespace ua
