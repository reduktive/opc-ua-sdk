// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_SUBSCRIPTION_DIAGNOSTICS_DATA_TYPE_H
#define UA_DATA_TYPE_SUBSCRIPTION_DIAGNOSTICS_DATA_TYPE_H

#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"
#include "ua_structure.h"
#include "ua_node_id.h"
#include "ua_built_in_type_id.h"
#include "ua_ref_structure.h"
#include "ua_node_id.h"
#include "ua_duration.h"

namespace ua
{

class StructureFactory;

/// OPC UA SubscriptionDiagnosticsDataType structured data type.
/// @ingroup ua_data_types
class SubscriptionDiagnosticsDataType : public Structure
{
public:
  /// The unqualified OPC UA type name.
  static constexpr string_view typeName{"SubscriptionDiagnosticsDataType"};
  /// The namespace URI that owns this type.
  static constexpr string_view typeNamespaceUri = specNamespaceUri;
  /// The type's well-known `DataTypeId`.
  static constexpr DataTypeId typeId{DataTypeId::SubscriptionDiagnosticsDataType};

  /// The Default Binary encoding's `ObjectId`.
  static const ObjectId defaultBinaryEncodingId{
    ObjectId::SubscriptionDiagnosticsDataType_Encoding_DefaultBinary};
  /// The Default XML encoding's `ObjectId`.
  static const ObjectId defaultXmlEncodingId{ObjectId::SubscriptionDiagnosticsDataType_Encoding_DefaultXml};

  /// Constructs a `SubscriptionDiagnosticsDataType` with all fields value-initialised.
  SubscriptionDiagnosticsDataType() = default;
  /// Defaulted copy: `SubscriptionDiagnosticsDataType` is a value type (memberwise copy).
  /// @param other The value to copy from.
  SubscriptionDiagnosticsDataType(const SubscriptionDiagnosticsDataType& other) = default;
  /// Defaulted move.
  /// @param other The value to move from.
  SubscriptionDiagnosticsDataType(SubscriptionDiagnosticsDataType&& other) noexcept = default;
  /// Defaulted memberwise copy assignment.
  /// @param other The value to copy from.
  /// @return A reference to this value.
  SubscriptionDiagnosticsDataType& operator=(const SubscriptionDiagnosticsDataType& other) = default;
  /// Defaulted memberwise move assignment.
  /// @param other The value to move from.
  /// @return A reference to this value.
  SubscriptionDiagnosticsDataType& operator=(SubscriptionDiagnosticsDataType&& other) noexcept = default;

  /// Defaulted destructor. Declared to complete the rule of five (the value-type copy/move members
  /// above are user-declared); `override` because the polymorphic base `Structure` has a virtual
  /// destructor. Satisfies cppcoreguidelines-special-member-functions.
  ~SubscriptionDiagnosticsDataType() override = default;

  /// Equality is memberwise over all fields.
  /// @param obj The value to compare against.
  /// @return `true` if all fields are equal.
  bool operator==(const SubscriptionDiagnosticsDataType& obj) const = default;

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

  /// Accesses the `SubscriptionId` field.
  /// @return A mutable reference to the `SubscriptionId` field.
  uint32_t& subscription_id();
  /// @return A const reference to the `SubscriptionId` field.
  const uint32_t& subscription_id() const;

  /// Accesses the `Priority` field.
  /// @return A mutable reference to the `Priority` field.
  uint8_t& priority();
  /// @return A const reference to the `Priority` field.
  const uint8_t& priority() const;

  /// Accesses the `PublishingInterval` field.
  /// @return A mutable reference to the `PublishingInterval` field.
  Duration& publishing_interval();
  /// @return A const reference to the `PublishingInterval` field.
  const Duration& publishing_interval() const;

  /// Accesses the `MaxKeepAliveCount` field.
  /// @return A mutable reference to the `MaxKeepAliveCount` field.
  uint32_t& max_keep_alive_count();
  /// @return A const reference to the `MaxKeepAliveCount` field.
  const uint32_t& max_keep_alive_count() const;

  /// Accesses the `MaxLifetimeCount` field.
  /// @return A mutable reference to the `MaxLifetimeCount` field.
  uint32_t& max_lifetime_count();
  /// @return A const reference to the `MaxLifetimeCount` field.
  const uint32_t& max_lifetime_count() const;

  /// Accesses the `MaxNotificationsPerPublish` field.
  /// @return A mutable reference to the `MaxNotificationsPerPublish` field.
  uint32_t& max_notifications_per_publish();
  /// @return A const reference to the `MaxNotificationsPerPublish` field.
  const uint32_t& max_notifications_per_publish() const;

  /// Accesses the `PublishingEnabled` field.
  /// @return A mutable reference to the `PublishingEnabled` field.
  bool& publishing_enabled();
  /// @return A const reference to the `PublishingEnabled` field.
  const bool& publishing_enabled() const;

  /// Accesses the `ModifyCount` field.
  /// @return A mutable reference to the `ModifyCount` field.
  uint32_t& modify_count();
  /// @return A const reference to the `ModifyCount` field.
  const uint32_t& modify_count() const;

  /// Accesses the `EnableCount` field.
  /// @return A mutable reference to the `EnableCount` field.
  uint32_t& enable_count();
  /// @return A const reference to the `EnableCount` field.
  const uint32_t& enable_count() const;

  /// Accesses the `DisableCount` field.
  /// @return A mutable reference to the `DisableCount` field.
  uint32_t& disable_count();
  /// @return A const reference to the `DisableCount` field.
  const uint32_t& disable_count() const;

  /// Accesses the `RepublishRequestCount` field.
  /// @return A mutable reference to the `RepublishRequestCount` field.
  uint32_t& republish_request_count();
  /// @return A const reference to the `RepublishRequestCount` field.
  const uint32_t& republish_request_count() const;

  /// Accesses the `RepublishMessageRequestCount` field.
  /// @return A mutable reference to the `RepublishMessageRequestCount` field.
  uint32_t& republish_message_request_count();
  /// @return A const reference to the `RepublishMessageRequestCount` field.
  const uint32_t& republish_message_request_count() const;

  /// Accesses the `RepublishMessageCount` field.
  /// @return A mutable reference to the `RepublishMessageCount` field.
  uint32_t& republish_message_count();
  /// @return A const reference to the `RepublishMessageCount` field.
  const uint32_t& republish_message_count() const;

  /// Accesses the `TransferRequestCount` field.
  /// @return A mutable reference to the `TransferRequestCount` field.
  uint32_t& transfer_request_count();
  /// @return A const reference to the `TransferRequestCount` field.
  const uint32_t& transfer_request_count() const;

  /// Accesses the `TransferredToAltClientCount` field.
  /// @return A mutable reference to the `TransferredToAltClientCount` field.
  uint32_t& transferred_to_alt_client_count();
  /// @return A const reference to the `TransferredToAltClientCount` field.
  const uint32_t& transferred_to_alt_client_count() const;

  /// Accesses the `TransferredToSameClientCount` field.
  /// @return A mutable reference to the `TransferredToSameClientCount` field.
  uint32_t& transferred_to_same_client_count();
  /// @return A const reference to the `TransferredToSameClientCount` field.
  const uint32_t& transferred_to_same_client_count() const;

  /// Accesses the `PublishRequestCount` field.
  /// @return A mutable reference to the `PublishRequestCount` field.
  uint32_t& publish_request_count();
  /// @return A const reference to the `PublishRequestCount` field.
  const uint32_t& publish_request_count() const;

  /// Accesses the `DataChangeNotificationsCount` field.
  /// @return A mutable reference to the `DataChangeNotificationsCount` field.
  uint32_t& data_change_notifications_count();
  /// @return A const reference to the `DataChangeNotificationsCount` field.
  const uint32_t& data_change_notifications_count() const;

  /// Accesses the `EventNotificationsCount` field.
  /// @return A mutable reference to the `EventNotificationsCount` field.
  uint32_t& event_notifications_count();
  /// @return A const reference to the `EventNotificationsCount` field.
  const uint32_t& event_notifications_count() const;

  /// Accesses the `NotificationsCount` field.
  /// @return A mutable reference to the `NotificationsCount` field.
  uint32_t& notifications_count();
  /// @return A const reference to the `NotificationsCount` field.
  const uint32_t& notifications_count() const;

  /// Accesses the `LatePublishRequestCount` field.
  /// @return A mutable reference to the `LatePublishRequestCount` field.
  uint32_t& late_publish_request_count();
  /// @return A const reference to the `LatePublishRequestCount` field.
  const uint32_t& late_publish_request_count() const;

  /// Accesses the `CurrentKeepAliveCount` field.
  /// @return A mutable reference to the `CurrentKeepAliveCount` field.
  uint32_t& current_keep_alive_count();
  /// @return A const reference to the `CurrentKeepAliveCount` field.
  const uint32_t& current_keep_alive_count() const;

  /// Accesses the `CurrentLifetimeCount` field.
  /// @return A mutable reference to the `CurrentLifetimeCount` field.
  uint32_t& current_lifetime_count();
  /// @return A const reference to the `CurrentLifetimeCount` field.
  const uint32_t& current_lifetime_count() const;

  /// Accesses the `UnacknowledgedMessageCount` field.
  /// @return A mutable reference to the `UnacknowledgedMessageCount` field.
  uint32_t& unacknowledged_message_count();
  /// @return A const reference to the `UnacknowledgedMessageCount` field.
  const uint32_t& unacknowledged_message_count() const;

  /// Accesses the `DiscardedMessageCount` field.
  /// @return A mutable reference to the `DiscardedMessageCount` field.
  uint32_t& discarded_message_count();
  /// @return A const reference to the `DiscardedMessageCount` field.
  const uint32_t& discarded_message_count() const;

  /// Accesses the `MonitoredItemCount` field.
  /// @return A mutable reference to the `MonitoredItemCount` field.
  uint32_t& monitored_item_count();
  /// @return A const reference to the `MonitoredItemCount` field.
  const uint32_t& monitored_item_count() const;

  /// Accesses the `DisabledMonitoredItemCount` field.
  /// @return A mutable reference to the `DisabledMonitoredItemCount` field.
  uint32_t& disabled_monitored_item_count();
  /// @return A const reference to the `DisabledMonitoredItemCount` field.
  const uint32_t& disabled_monitored_item_count() const;

  /// Accesses the `MonitoringQueueOverflowCount` field.
  /// @return A mutable reference to the `MonitoringQueueOverflowCount` field.
  uint32_t& monitoring_queue_overflow_count();
  /// @return A const reference to the `MonitoringQueueOverflowCount` field.
  const uint32_t& monitoring_queue_overflow_count() const;

  /// Accesses the `NextSequenceNumber` field.
  /// @return A mutable reference to the `NextSequenceNumber` field.
  uint32_t& next_sequence_number();
  /// @return A const reference to the `NextSequenceNumber` field.
  const uint32_t& next_sequence_number() const;

  /// Accesses the `EventQueueOverflowCount` field.
  /// @return A mutable reference to the `EventQueueOverflowCount` field.
  uint32_t& event_queue_overflow_count();
  /// @return A const reference to the `EventQueueOverflowCount` field.
  const uint32_t& event_queue_overflow_count() const;

  /// @return The `BuiltInTypeId` this type encodes as on the wire.
  static BuiltInTypeId built_in_type_id();

protected:
  /// Appends this value's fields to a buffer; used by to_string().
  /// @param[in,out] output Buffer the field lines are appended to.
  /// @param indent         Indentation depth applied to nested structures.
  void append_fields(std::string& output, int indent = 0) const override;

private:
  NodeId mSessionId{};  ///< Session ID.
  uint32_t mSubscriptionId{};  ///< Subscription ID.
  uint8_t mPriority{};  ///< Priority.
  Duration mPublishingInterval{};  ///< Publishing interval.
  uint32_t mMaxKeepAliveCount{};  ///< Max keep alive count.
  uint32_t mMaxLifetimeCount{};  ///< Max lifetime count.
  uint32_t mMaxNotificationsPerPublish{};  ///< Max notifications per publish.
  bool mPublishingEnabled{};  ///< Publishing enabled.
  uint32_t mModifyCount{};  ///< Modify count.
  uint32_t mEnableCount{};  ///< Enable count.
  uint32_t mDisableCount{};  ///< Disable count.
  uint32_t mRepublishRequestCount{};  ///< Republish request count.
  uint32_t mRepublishMessageRequestCount{};  ///< Republish message request count.
  uint32_t mRepublishMessageCount{};  ///< Republish message count.
  uint32_t mTransferRequestCount{};  ///< Transfer request count.
  uint32_t mTransferredToAltClientCount{};  ///< Transferred to alt client count.
  uint32_t mTransferredToSameClientCount{};  ///< Transferred to same client count.
  uint32_t mPublishRequestCount{};  ///< Publish request count.
  uint32_t mDataChangeNotificationsCount{};  ///< Data change notifications count.
  uint32_t mEventNotificationsCount{};  ///< Event notifications count.
  uint32_t mNotificationsCount{};  ///< Notifications count.
  uint32_t mLatePublishRequestCount{};  ///< Late publish request count.
  uint32_t mCurrentKeepAliveCount{};  ///< Current keep alive count.
  uint32_t mCurrentLifetimeCount{};  ///< Current lifetime count.
  uint32_t mUnacknowledgedMessageCount{};  ///< Unacknowledged message count.
  uint32_t mDiscardedMessageCount{};  ///< Discarded message count.
  uint32_t mMonitoredItemCount{};  ///< Monitored item count.
  uint32_t mDisabledMonitoredItemCount{};  ///< Disabled monitored item count.
  uint32_t mMonitoringQueueOverflowCount{};  ///< Monitoring queue overflow count.
  uint32_t mNextSequenceNumber{};  ///< Next sequence number.
  uint32_t mEventQueueOverflowCount{};  ///< Event queue overflow count.
};

template<>
inline string_view get_typename<SubscriptionDiagnosticsDataType>()
{
  return SubscriptionDiagnosticsDataType::typeName;
}

}  // namespace ua

#endif  // !UA_DATA_TYPE_SUBSCRIPTION_DIAGNOSTICS_DATA_TYPE_H
