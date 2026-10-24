// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_SESSION_DIAGNOSTICS_DATA_TYPE_H
#define UA_DATA_TYPE_SESSION_DIAGNOSTICS_DATA_TYPE_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_structure.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_node_id.h"
#include "ua_string.h"
#include "ua_application_description.h"
#include "ua_locale_id.h"
#include "ua_duration.h"
#include "ua_utc_time.h"
#include "ua_service_counter_data_type.h"
#include "ua_array.h"

namespace ua
{

class StructureFactory;

/// OPC UA SessionDiagnosticsDataType structured data type.
/// @ingroup ua_data_types
class SessionDiagnosticsDataType : public Structure
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"SessionDiagnosticsDataType"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::SessionDiagnosticsDataType};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{ObjectId::SessionDiagnosticsDataType_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::SessionDiagnosticsDataType_Encoding_DefaultXml};

  /// Constructs a `SessionDiagnosticsDataType` with all fields value-initialised.
  SessionDiagnosticsDataType() = default;
  /// Defaulted copy: `SessionDiagnosticsDataType` is a value type (memberwise copy).
  /// @param other The value to copy from.
  SessionDiagnosticsDataType(const SessionDiagnosticsDataType& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  SessionDiagnosticsDataType(SessionDiagnosticsDataType&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  SessionDiagnosticsDataType& operator=(const SessionDiagnosticsDataType& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  SessionDiagnosticsDataType& operator=(SessionDiagnosticsDataType&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~SessionDiagnosticsDataType() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const SessionDiagnosticsDataType& obj) const = default;

  /// Tests whether this value's type matches `dataTypeId` or one of its supertypes.
  /// @param ns     Namespace context used to resolve `dataTypeId`.
  /// @param dataTypeId Candidate type identifier.
  /// @return `true` if this value is of type `dataTypeId` or a subtype of it.
  bool is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const override;

  /// @return The type's `ExpandedNodeId`.
  ExpandedNodeId type_id() const override;

  /// Resolves the type's `NodeId` in a namespace context.
  /// @param ns Namespace context supplying the runtime namespace index.
  /// @return The type's `NodeId`.
  NodeId type_id(const CodecNamespaceContext& ns) const override;

  /// @return The unqualified OPC UA type name.
  String type_name() const override;

  /// Encodes the type's encoding id.
  /// @param limit   Remaining stack-depth budget guarding against deep nesting.
  /// @param ns      Namespace context used to resolve the encoding id.
  /// @param encoder Sink the encoding id is written to.
  void encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const override;

  /// Encodes this value's fields.
  /// @param limit   Remaining stack-depth budget guarding against deep nesting.
  /// @param encoder Sink the fields are written to.
  void encode(StackDepth limit, Encoder& encoder) const override;

  /// Decodes this value's fields, replacing the current contents.
  /// @param limit   Remaining stack-depth budget guarding against deep nesting.
  /// @param decoder Source the fields are read from.
  void decode(StackDepth limit, Decoder& decoder) override;

  /// Resolves this value's localized-text fields to the preferred locales.
  /// @param locales Preferred locales, most-preferred first.
  void resolve(span<const LocaleId> locales) override;

  /// Polymorphically deep-copies this value.
  /// @return A heap-allocated copy held by its `Structure` base.
  unique_ptr<Structure> clone() const override;

  /// Formats this value as human-readable text, for logging and debugging.
  /// @param indent Indentation depth applied to nested structures.
  /// @return The formatted representation.
  std::string to_string(int indent = 0) const override;

  /// Registers this type's decode factories so encoded values can be
  /// reconstructed by their encoding id.
  /// @param ns              Namespace context the encoding ids are registered under.
  /// @param uaBinaryFactory Binary-codec factory to register with, or null to skip.
  /// @param xmlFactory      XML-codec factory to register with, or null to skip.
  static void register_type(
    const CodecNamespaceContext& ns, StructureFactory* uaBinaryFactory, StructureFactory* xmlFactory);

  /// Accesses the `SessionId` field.
  /// @return A mutable reference to the `SessionId` field.
  NodeId& session_id();
  /// @return A const reference to the `SessionId` field.
  const NodeId& session_id() const;

  /// Accesses the `SessionName` field.
  /// @return A mutable reference to the `SessionName` field.
  String& session_name();
  /// @return A const reference to the `SessionName` field.
  const String& session_name() const;

  /// Accesses the `ClientDescription` field.
  /// @return A mutable reference to the `ClientDescription` field.
  ApplicationDescription& client_description();
  /// @return A const reference to the `ClientDescription` field.
  const ApplicationDescription& client_description() const;

  /// Accesses the `ServerUri` field.
  /// @return A mutable reference to the `ServerUri` field.
  String& server_uri();
  /// @return A const reference to the `ServerUri` field.
  const String& server_uri() const;

  /// Accesses the `EndpointUrl` field.
  /// @return A mutable reference to the `EndpointUrl` field.
  String& endpoint_url();
  /// @return A const reference to the `EndpointUrl` field.
  const String& endpoint_url() const;

  /// Accesses the `LocaleIds` field.
  /// @return A mutable reference to the `LocaleIds` field.
  Array<LocaleId>& locale_ids();
  /// @return A const reference to the `LocaleIds` field.
  const Array<LocaleId>& locale_ids() const;

  /// Accesses the `ActualSessionTimeout` field.
  /// @return A mutable reference to the `ActualSessionTimeout` field.
  Duration& actual_session_timeout();
  /// @return A const reference to the `ActualSessionTimeout` field.
  const Duration& actual_session_timeout() const;

  /// Accesses the `MaxResponseMessageSize` field.
  /// @return A mutable reference to the `MaxResponseMessageSize` field.
  uint32_t& max_response_message_size();
  /// @return A const reference to the `MaxResponseMessageSize` field.
  const uint32_t& max_response_message_size() const;

  /// Accesses the `ClientConnectionTime` field.
  /// @return A mutable reference to the `ClientConnectionTime` field.
  UtcTime& client_connection_time();
  /// @return A const reference to the `ClientConnectionTime` field.
  const UtcTime& client_connection_time() const;

  /// Accesses the `ClientLastContactTime` field.
  /// @return A mutable reference to the `ClientLastContactTime` field.
  UtcTime& client_last_contact_time();
  /// @return A const reference to the `ClientLastContactTime` field.
  const UtcTime& client_last_contact_time() const;

  /// Accesses the `CurrentSubscriptionsCount` field.
  /// @return A mutable reference to the `CurrentSubscriptionsCount` field.
  uint32_t& current_subscriptions_count();
  /// @return A const reference to the `CurrentSubscriptionsCount` field.
  const uint32_t& current_subscriptions_count() const;

  /// Accesses the `CurrentMonitoredItemsCount` field.
  /// @return A mutable reference to the `CurrentMonitoredItemsCount` field.
  uint32_t& current_monitored_items_count();
  /// @return A const reference to the `CurrentMonitoredItemsCount` field.
  const uint32_t& current_monitored_items_count() const;

  /// Accesses the `CurrentPublishRequestsInQueue` field.
  /// @return A mutable reference to the `CurrentPublishRequestsInQueue` field.
  uint32_t& current_publish_requests_in_queue();
  /// @return A const reference to the `CurrentPublishRequestsInQueue` field.
  const uint32_t& current_publish_requests_in_queue() const;

  /// Accesses the `TotalRequestCount` field.
  /// @return A mutable reference to the `TotalRequestCount` field.
  ServiceCounterDataType& total_request_count();
  /// @return A const reference to the `TotalRequestCount` field.
  const ServiceCounterDataType& total_request_count() const;

  /// Accesses the `UnauthorizedRequestCount` field.
  /// @return A mutable reference to the `UnauthorizedRequestCount` field.
  uint32_t& unauthorized_request_count();
  /// @return A const reference to the `UnauthorizedRequestCount` field.
  const uint32_t& unauthorized_request_count() const;

  /// Accesses the `ReadCount` field.
  /// @return A mutable reference to the `ReadCount` field.
  ServiceCounterDataType& read_count();
  /// @return A const reference to the `ReadCount` field.
  const ServiceCounterDataType& read_count() const;

  /// Accesses the `HistoryReadCount` field.
  /// @return A mutable reference to the `HistoryReadCount` field.
  ServiceCounterDataType& history_read_count();
  /// @return A const reference to the `HistoryReadCount` field.
  const ServiceCounterDataType& history_read_count() const;

  /// Accesses the `WriteCount` field.
  /// @return A mutable reference to the `WriteCount` field.
  ServiceCounterDataType& write_count();
  /// @return A const reference to the `WriteCount` field.
  const ServiceCounterDataType& write_count() const;

  /// Accesses the `HistoryUpdateCount` field.
  /// @return A mutable reference to the `HistoryUpdateCount` field.
  ServiceCounterDataType& history_update_count();
  /// @return A const reference to the `HistoryUpdateCount` field.
  const ServiceCounterDataType& history_update_count() const;

  /// Accesses the `CallCount` field.
  /// @return A mutable reference to the `CallCount` field.
  ServiceCounterDataType& call_count();
  /// @return A const reference to the `CallCount` field.
  const ServiceCounterDataType& call_count() const;

  /// Accesses the `CreateMonitoredItemsCount` field.
  /// @return A mutable reference to the `CreateMonitoredItemsCount` field.
  ServiceCounterDataType& create_monitored_items_count();
  /// @return A const reference to the `CreateMonitoredItemsCount` field.
  const ServiceCounterDataType& create_monitored_items_count() const;

  /// Accesses the `ModifyMonitoredItemsCount` field.
  /// @return A mutable reference to the `ModifyMonitoredItemsCount` field.
  ServiceCounterDataType& modify_monitored_items_count();
  /// @return A const reference to the `ModifyMonitoredItemsCount` field.
  const ServiceCounterDataType& modify_monitored_items_count() const;

  /// Accesses the `SetMonitoringModeCount` field.
  /// @return A mutable reference to the `SetMonitoringModeCount` field.
  ServiceCounterDataType& set_monitoring_mode_count();
  /// @return A const reference to the `SetMonitoringModeCount` field.
  const ServiceCounterDataType& set_monitoring_mode_count() const;

  /// Accesses the `SetTriggeringCount` field.
  /// @return A mutable reference to the `SetTriggeringCount` field.
  ServiceCounterDataType& set_triggering_count();
  /// @return A const reference to the `SetTriggeringCount` field.
  const ServiceCounterDataType& set_triggering_count() const;

  /// Accesses the `DeleteMonitoredItemsCount` field.
  /// @return A mutable reference to the `DeleteMonitoredItemsCount` field.
  ServiceCounterDataType& delete_monitored_items_count();
  /// @return A const reference to the `DeleteMonitoredItemsCount` field.
  const ServiceCounterDataType& delete_monitored_items_count() const;

  /// Accesses the `CreateSubscriptionCount` field.
  /// @return A mutable reference to the `CreateSubscriptionCount` field.
  ServiceCounterDataType& create_subscription_count();
  /// @return A const reference to the `CreateSubscriptionCount` field.
  const ServiceCounterDataType& create_subscription_count() const;

  /// Accesses the `ModifySubscriptionCount` field.
  /// @return A mutable reference to the `ModifySubscriptionCount` field.
  ServiceCounterDataType& modify_subscription_count();
  /// @return A const reference to the `ModifySubscriptionCount` field.
  const ServiceCounterDataType& modify_subscription_count() const;

  /// Accesses the `SetPublishingModeCount` field.
  /// @return A mutable reference to the `SetPublishingModeCount` field.
  ServiceCounterDataType& set_publishing_mode_count();
  /// @return A const reference to the `SetPublishingModeCount` field.
  const ServiceCounterDataType& set_publishing_mode_count() const;

  /// Accesses the `PublishCount` field.
  /// @return A mutable reference to the `PublishCount` field.
  ServiceCounterDataType& publish_count();
  /// @return A const reference to the `PublishCount` field.
  const ServiceCounterDataType& publish_count() const;

  /// Accesses the `RepublishCount` field.
  /// @return A mutable reference to the `RepublishCount` field.
  ServiceCounterDataType& republish_count();
  /// @return A const reference to the `RepublishCount` field.
  const ServiceCounterDataType& republish_count() const;

  /// Accesses the `TransferSubscriptionsCount` field.
  /// @return A mutable reference to the `TransferSubscriptionsCount` field.
  ServiceCounterDataType& transfer_subscriptions_count();
  /// @return A const reference to the `TransferSubscriptionsCount` field.
  const ServiceCounterDataType& transfer_subscriptions_count() const;

  /// Accesses the `DeleteSubscriptionsCount` field.
  /// @return A mutable reference to the `DeleteSubscriptionsCount` field.
  ServiceCounterDataType& delete_subscriptions_count();
  /// @return A const reference to the `DeleteSubscriptionsCount` field.
  const ServiceCounterDataType& delete_subscriptions_count() const;

  /// Accesses the `AddNodesCount` field.
  /// @return A mutable reference to the `AddNodesCount` field.
  ServiceCounterDataType& add_nodes_count();
  /// @return A const reference to the `AddNodesCount` field.
  const ServiceCounterDataType& add_nodes_count() const;

  /// Accesses the `AddReferencesCount` field.
  /// @return A mutable reference to the `AddReferencesCount` field.
  ServiceCounterDataType& add_references_count();
  /// @return A const reference to the `AddReferencesCount` field.
  const ServiceCounterDataType& add_references_count() const;

  /// Accesses the `DeleteNodesCount` field.
  /// @return A mutable reference to the `DeleteNodesCount` field.
  ServiceCounterDataType& delete_nodes_count();
  /// @return A const reference to the `DeleteNodesCount` field.
  const ServiceCounterDataType& delete_nodes_count() const;

  /// Accesses the `DeleteReferencesCount` field.
  /// @return A mutable reference to the `DeleteReferencesCount` field.
  ServiceCounterDataType& delete_references_count();
  /// @return A const reference to the `DeleteReferencesCount` field.
  const ServiceCounterDataType& delete_references_count() const;

  /// Accesses the `BrowseCount` field.
  /// @return A mutable reference to the `BrowseCount` field.
  ServiceCounterDataType& browse_count();
  /// @return A const reference to the `BrowseCount` field.
  const ServiceCounterDataType& browse_count() const;

  /// Accesses the `BrowseNextCount` field.
  /// @return A mutable reference to the `BrowseNextCount` field.
  ServiceCounterDataType& browse_next_count();
  /// @return A const reference to the `BrowseNextCount` field.
  const ServiceCounterDataType& browse_next_count() const;

  /// Accesses the `TranslateBrowsePathsToNodeIdsCount` field.
  /// @return A mutable reference to the `TranslateBrowsePathsToNodeIdsCount` field.
  ServiceCounterDataType& translate_browse_paths_to_node_ids_count();
  /// @return A const reference to the `TranslateBrowsePathsToNodeIdsCount` field.
  const ServiceCounterDataType& translate_browse_paths_to_node_ids_count() const;

  /// Accesses the `QueryFirstCount` field.
  /// @return A mutable reference to the `QueryFirstCount` field.
  ServiceCounterDataType& query_first_count();
  /// @return A const reference to the `QueryFirstCount` field.
  const ServiceCounterDataType& query_first_count() const;

  /// Accesses the `QueryNextCount` field.
  /// @return A mutable reference to the `QueryNextCount` field.
  ServiceCounterDataType& query_next_count();
  /// @return A const reference to the `QueryNextCount` field.
  const ServiceCounterDataType& query_next_count() const;

  /// Accesses the `RegisterNodesCount` field.
  /// @return A mutable reference to the `RegisterNodesCount` field.
  ServiceCounterDataType& register_nodes_count();
  /// @return A const reference to the `RegisterNodesCount` field.
  const ServiceCounterDataType& register_nodes_count() const;

  /// Accesses the `UnregisterNodesCount` field.
  /// @return A mutable reference to the `UnregisterNodesCount` field.
  ServiceCounterDataType& unregister_nodes_count();
  /// @return A const reference to the `UnregisterNodesCount` field.
  const ServiceCounterDataType& unregister_nodes_count() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  NodeId mSessionId{};  ///< Session ID.
  String mSessionName{};  ///< Session name.
  ApplicationDescription mClientDescription{};  ///< Client description.
  String mServerUri{};  ///< Server URI.
  String mEndpointUrl{};  ///< Endpoint URL.
  Array<LocaleId> mLocaleIds{};  ///< Locale ids.
  Duration mActualSessionTimeout{};  ///< Actual session timeout.
  uint32_t mMaxResponseMessageSize{};  ///< Max response message size.
  UtcTime mClientConnectionTime{};  ///< Client connection time.
  UtcTime mClientLastContactTime{};  ///< Client last contact time.
  uint32_t mCurrentSubscriptionsCount{};  ///< Current subscriptions count.
  uint32_t mCurrentMonitoredItemsCount{};  ///< Current monitored items count.
  uint32_t mCurrentPublishRequestsInQueue{};  ///< Current publish requests in queue.
  ServiceCounterDataType mTotalRequestCount{};  ///< Total request count.
  uint32_t mUnauthorizedRequestCount{};  ///< Unauthorized request count.
  ServiceCounterDataType mReadCount{};  ///< Read count.
  ServiceCounterDataType mHistoryReadCount{};  ///< History read count.
  ServiceCounterDataType mWriteCount{};  ///< Write count.
  ServiceCounterDataType mHistoryUpdateCount{};  ///< History update count.
  ServiceCounterDataType mCallCount{};  ///< Call count.
  ServiceCounterDataType mCreateMonitoredItemsCount{};  ///< Create monitored items count.
  ServiceCounterDataType mModifyMonitoredItemsCount{};  ///< Modify monitored items count.
  ServiceCounterDataType mSetMonitoringModeCount{};  ///< Set monitoring mode count.
  ServiceCounterDataType mSetTriggeringCount{};  ///< Set triggering count.
  ServiceCounterDataType mDeleteMonitoredItemsCount{};  ///< Delete monitored items count.
  ServiceCounterDataType mCreateSubscriptionCount{};  ///< Create subscription count.
  ServiceCounterDataType mModifySubscriptionCount{};  ///< Modify subscription count.
  ServiceCounterDataType mSetPublishingModeCount{};  ///< Set publishing mode count.
  ServiceCounterDataType mPublishCount{};  ///< Publish count.
  ServiceCounterDataType mRepublishCount{};  ///< Republish count.
  ServiceCounterDataType mTransferSubscriptionsCount{};  ///< Transfer subscriptions count.
  ServiceCounterDataType mDeleteSubscriptionsCount{};  ///< Delete subscriptions count.
  ServiceCounterDataType mAddNodesCount{};  ///< Add nodes count.
  ServiceCounterDataType mAddReferencesCount{};  ///< Add references count.
  ServiceCounterDataType mDeleteNodesCount{};  ///< Delete nodes count.
  ServiceCounterDataType mDeleteReferencesCount{};  ///< Delete references count.
  ServiceCounterDataType mBrowseCount{};  ///< Browse count.
  ServiceCounterDataType mBrowseNextCount{};  ///< Browse next count.
  ServiceCounterDataType
    mTranslateBrowsePathsToNodeIdsCount{};  ///< Translate browse paths to node ids count.
  ServiceCounterDataType mQueryFirstCount{};  ///< Query first count.
  ServiceCounterDataType mQueryNextCount{};  ///< Query next count.
  ServiceCounterDataType mRegisterNodesCount{};  ///< Register nodes count.
  ServiceCounterDataType mUnregisterNodesCount{};  ///< Unregister nodes count.
};

template<>
inline string_view get_typename<SessionDiagnosticsDataType>()
{
  return SessionDiagnosticsDataType::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_SESSION_DIAGNOSTICS_DATA_TYPE_H
