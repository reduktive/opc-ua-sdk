// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVER_CAPABILITIES_H
#define UA_SERVER_CAPABILITIES_H

#include "ua_base_object.h"
#include "ua_node_accessor.h"
#include "ua_property.h"
#include "ua_operation_limits.h"
#include "ua_folder.h"
#include "ua_role_set.h"

namespace ua
{

struct MethodCallContext;

class ServerCapabilities;
using ServerCapabilitiesResult = Result<ServerCapabilities>;

/// Address-space handle for the OPC UA ServerCapabilitiesType ObjectType.
/// @ingroup ua_information_model
class ServerCapabilities : public BaseObject
{
public:
  /// Constructs an empty `ServerCapabilities` handle that references no node.
  ServerCapabilities() = default;

  /// Completion callback for create_async: receives the created `ServerCapabilities` handle, or an
  /// @ref ErrorDetail on failure.
  using CreateCompleteCallback = std::function<void(ServerCapabilitiesResult)>;
  /// Completion callback for attach_async: receives the attached `ServerCapabilities` handle, or an
  /// @ref ErrorDetail on failure.
  using AttachCompleteCallback = std::function<void(ServerCapabilitiesResult)>;

  /// Creates a new `ServerCapabilitiesType` instance under `parent`.
  ///
  /// Instantiates the type's full child tree and completes asynchronously. The
  /// callback runs on an unspecified worker thread - do not block it.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @param complete     Receives the outcome: on success a `ServerCapabilities` handle,
  ///                     on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_create_sync, create_sync
  static void create_async(AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
    const InstantiationOptions& options, CreateCompleteCallback complete) noexcept;

  /// Creates a new `ServerCapabilitiesType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see create_async
  static ServerCapabilitiesResult try_create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options) noexcept;

  /// Creates a new `ServerCapabilitiesType` instance under `parent`, blocking until complete.  ///
  /// **The returned handle OWNS the node it creates.** Destroying it removes that node and its
  /// subtree from the address space. Call `release()` to keep the node as permanent server
  /// content, or `remove_async()` to delete it eagerly. A handle obtained through `attach_*`
  /// owns nothing and only references the node.
  /// @param addressSpace Address space the instance is created in.
  /// @param parent       Parent node the new instance is organized under.
  /// @param browseName   Browse name for the new instance.
  /// @param options      Instantiation options (target namespace, node-id allocation, ...).
  /// @return The new `ServerCapabilities` handle. A Good subcode is not returned; @ref try_create_sync
  ///         returns it.
  /// @throws UaException when the instantiation is not Good, an Uncertain answer included.
  /// @see create_async
  static ServerCapabilities create_sync(AddressSpace addressSpace, const NodeId& parent,
    const QualifiedName& browseName, const InstantiationOptions& options);

  /// Wraps an existing node as a `ServerCapabilitiesType` handle, without taking ownership.
  ///
  /// The handle does no RAII cleanup; destroying it leaves the node in place.
  /// Completes asynchronously; the callback runs on an unspecified worker thread.
  /// @param addressSpace    Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @param complete        Receives the outcome: on success a `ServerCapabilities` handle,
  ///                        on failure an @ref ErrorDetail. This overload never throws.
  /// @see try_attach_sync, attach_sync
  static void attach_async(
    AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept;

  /// Wraps an existing node as a `ServerCapabilitiesType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see attach_async
  static ServerCapabilitiesResult try_attach_sync(
    AddressSpace addressSpace, const NodeId& existingInstance) noexcept;

  /// Wraps an existing node as a `ServerCapabilitiesType` handle, blocking until complete.
  /// @param addressSpace     Address space the node lives in.
  /// @param existingInstance Node id of the existing instance to wrap.
  /// @return The `ServerCapabilities` handle. A Good subcode is not returned; @ref try_attach_sync
  ///         returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  /// @see attach_async
  static ServerCapabilities attach_sync(AddressSpace addressSpace, const NodeId& existingInstance);

  // --- Property accessors (return Property handles) ---

  /// Completion callback for a property attach: receives a @ref Property handle, or an @ref ErrorDetail on
  /// failure.
  using PropertyCompleteCallback = std::function<void(PropertyResult)>;

  /// Attaches a `Property` handle for the `ServerProfileArray` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_server_profile_array_property_sync, server_profile_array_property_sync
  void server_profile_array_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ServerProfileArray` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_server_profile_array_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ServerProfileArray` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_server_profile_array_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property server_profile_array_property_sync() const;

  /// Attaches a `Property` handle for the `LocaleIdArray` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_locale_id_array_property_sync, locale_id_array_property_sync
  void locale_id_array_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `LocaleIdArray` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_locale_id_array_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `LocaleIdArray` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_locale_id_array_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property locale_id_array_property_sync() const;

  /// Attaches a `Property` handle for the `MinSupportedSampleRate` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_min_supported_sample_rate_property_sync, min_supported_sample_rate_property_sync
  void min_supported_sample_rate_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MinSupportedSampleRate` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_min_supported_sample_rate_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MinSupportedSampleRate` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_min_supported_sample_rate_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property min_supported_sample_rate_property_sync() const;

  /// Attaches a `Property` handle for the `MaxBrowseContinuationPoints` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_browse_continuation_points_property_sync, max_browse_continuation_points_property_sync
  void max_browse_continuation_points_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxBrowseContinuationPoints` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_browse_continuation_points_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxBrowseContinuationPoints` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_browse_continuation_points_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_browse_continuation_points_property_sync() const;

  /// Attaches a `Property` handle for the `MaxQueryContinuationPoints` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_query_continuation_points_property_sync, max_query_continuation_points_property_sync
  void max_query_continuation_points_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxQueryContinuationPoints` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_query_continuation_points_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxQueryContinuationPoints` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_query_continuation_points_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_query_continuation_points_property_sync() const;

  /// Attaches a `Property` handle for the `MaxHistoryContinuationPoints` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_history_continuation_points_property_sync, max_history_continuation_points_property_sync
  void max_history_continuation_points_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxHistoryContinuationPoints` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_history_continuation_points_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxHistoryContinuationPoints` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_history_continuation_points_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_history_continuation_points_property_sync() const;

  /// Attaches a `Property` handle for the `MaxLogObjectContinuationPoints` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_log_object_continuation_points_property_sync,
  /// max_log_object_continuation_points_property_sync
  void max_log_object_continuation_points_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxLogObjectContinuationPoints` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_log_object_continuation_points_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxLogObjectContinuationPoints` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_log_object_continuation_points_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_log_object_continuation_points_property_sync() const;

  /// Attaches a `Property` handle for the `SoftwareCertificates` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_software_certificates_property_sync, software_certificates_property_sync
  void software_certificates_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `SoftwareCertificates` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_software_certificates_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `SoftwareCertificates` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_software_certificates_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property software_certificates_property_sync() const;

  /// Attaches a `Property` handle for the `MaxArrayLength` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_array_length_property_sync, max_array_length_property_sync
  void max_array_length_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxArrayLength` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_array_length_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxArrayLength` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_array_length_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_array_length_property_sync() const;

  /// Attaches a `Property` handle for the `MaxStringLength` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_string_length_property_sync, max_string_length_property_sync
  void max_string_length_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxStringLength` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_string_length_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxStringLength` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_string_length_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_string_length_property_sync() const;

  /// Attaches a `Property` handle for the `MaxByteStringLength` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_byte_string_length_property_sync, max_byte_string_length_property_sync
  void max_byte_string_length_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxByteStringLength` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_byte_string_length_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxByteStringLength` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_byte_string_length_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_byte_string_length_property_sync() const;

  /// Attaches a `Property` handle for the `MaxSessions` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_sessions_property_sync, max_sessions_property_sync
  void max_sessions_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxSessions` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_sessions_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxSessions` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref try_max_sessions_property_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_sessions_property_sync() const;

  /// Attaches a `Property` handle for the `MaxSubscriptions` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_subscriptions_property_sync, max_subscriptions_property_sync
  void max_subscriptions_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxSubscriptions` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_subscriptions_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxSubscriptions` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_subscriptions_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_subscriptions_property_sync() const;

  /// Attaches a `Property` handle for the `MaxMonitoredItems` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_monitored_items_property_sync, max_monitored_items_property_sync
  void max_monitored_items_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxMonitoredItems` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_monitored_items_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxMonitoredItems` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_monitored_items_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_monitored_items_property_sync() const;

  /// Attaches a `Property` handle for the `MaxSubscriptionsPerSession` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_subscriptions_per_session_property_sync, max_subscriptions_per_session_property_sync
  void max_subscriptions_per_session_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxSubscriptionsPerSession` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_subscriptions_per_session_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxSubscriptionsPerSession` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_subscriptions_per_session_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_subscriptions_per_session_property_sync() const;

  /// Attaches a `Property` handle for the `MaxMonitoredItemsPerSubscription` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_monitored_items_per_subscription_property_sync,
  /// max_monitored_items_per_subscription_property_sync
  void max_monitored_items_per_subscription_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxMonitoredItemsPerSubscription` property, blocking until
  /// complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_monitored_items_per_subscription_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxMonitoredItemsPerSubscription` property, blocking until
  /// complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_monitored_items_per_subscription_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_monitored_items_per_subscription_property_sync() const;

  /// Attaches a `Property` handle for the `MaxSelectClauseParameters` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_select_clause_parameters_property_sync, max_select_clause_parameters_property_sync
  void max_select_clause_parameters_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxSelectClauseParameters` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_select_clause_parameters_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxSelectClauseParameters` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_select_clause_parameters_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_select_clause_parameters_property_sync() const;

  /// Attaches a `Property` handle for the `MaxWhereClauseParameters` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_where_clause_parameters_property_sync, max_where_clause_parameters_property_sync
  void max_where_clause_parameters_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxWhereClauseParameters` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_where_clause_parameters_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxWhereClauseParameters` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_where_clause_parameters_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_where_clause_parameters_property_sync() const;

  /// Attaches a `Property` handle for the `MaxMonitoredItemsQueueSize` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_max_monitored_items_queue_size_property_sync, max_monitored_items_queue_size_property_sync
  void max_monitored_items_queue_size_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `MaxMonitoredItemsQueueSize` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_max_monitored_items_queue_size_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `MaxMonitoredItemsQueueSize` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_max_monitored_items_queue_size_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property max_monitored_items_queue_size_property_sync() const;

  /// Attaches a `Property` handle for the `ConformanceUnits` property.
  /// @param complete Receives the @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_conformance_units_property_sync, conformance_units_property_sync
  void conformance_units_property_async(PropertyCompleteCallback complete) const noexcept;
  /// Attaches a `Property` handle for the `ConformanceUnits` property, blocking until complete.
  /// @return The @ref Property handle, or an @ref ErrorDetail on failure. Never throws.
  PropertyResult try_conformance_units_property_sync() const noexcept;
  /// Attaches a `Property` handle for the `ConformanceUnits` property, blocking until complete.
  /// @return The @ref Property handle. A Good subcode is not returned; @ref
  /// try_conformance_units_property_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Property conformance_units_property_sync() const;

  // --- Typed value read shortcuts ---

  /// Reads the `ServerProfileArray` property value, typed as `String`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_server_profile_array_sync, read_server_profile_array_sync
  void read_server_profile_array_async(std::function<void(StringResult)> complete) const noexcept;
  /// Reads the `ServerProfileArray` property value as `String`, blocking until complete.
  /// @return The value with the read's code, as @ref read_server_profile_array_async gives it. Never throws.
  StringResult try_read_server_profile_array_sync() const noexcept;
  /// Reads the `ServerProfileArray` property value as `String`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_server_profile_array_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  String read_server_profile_array_sync() const;

  /// Reads the `MaxBrowseContinuationPoints` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_browse_continuation_points_sync, read_max_browse_continuation_points_sync
  void read_max_browse_continuation_points_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `MaxBrowseContinuationPoints` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_browse_continuation_points_async gives it.
  /// Never throws.
  UInt16Result try_read_max_browse_continuation_points_sync() const noexcept;
  /// Reads the `MaxBrowseContinuationPoints` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_browse_continuation_points_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_max_browse_continuation_points_sync() const;

  /// Reads the `MaxQueryContinuationPoints` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_query_continuation_points_sync, read_max_query_continuation_points_sync
  void read_max_query_continuation_points_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `MaxQueryContinuationPoints` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_query_continuation_points_async gives it. Never
  /// throws.
  UInt16Result try_read_max_query_continuation_points_sync() const noexcept;
  /// Reads the `MaxQueryContinuationPoints` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_query_continuation_points_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_max_query_continuation_points_sync() const;

  /// Reads the `MaxHistoryContinuationPoints` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_history_continuation_points_sync, read_max_history_continuation_points_sync
  void read_max_history_continuation_points_async(std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `MaxHistoryContinuationPoints` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_history_continuation_points_async gives it.
  /// Never throws.
  UInt16Result try_read_max_history_continuation_points_sync() const noexcept;
  /// Reads the `MaxHistoryContinuationPoints` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_history_continuation_points_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_max_history_continuation_points_sync() const;

  /// Reads the `MaxLogObjectContinuationPoints` property value, typed as `uint16_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_log_object_continuation_points_sync, read_max_log_object_continuation_points_sync
  void read_max_log_object_continuation_points_async(
    std::function<void(UInt16Result)> complete) const noexcept;
  /// Reads the `MaxLogObjectContinuationPoints` property value as `uint16_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_log_object_continuation_points_async gives it.
  /// Never throws.
  UInt16Result try_read_max_log_object_continuation_points_sync() const noexcept;
  /// Reads the `MaxLogObjectContinuationPoints` property value as `uint16_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_log_object_continuation_points_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint16_t read_max_log_object_continuation_points_sync() const;

  /// Reads the `MaxArrayLength` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_array_length_sync, read_max_array_length_sync
  void read_max_array_length_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxArrayLength` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_array_length_async gives it. Never throws.
  UInt32Result try_read_max_array_length_sync() const noexcept;
  /// Reads the `MaxArrayLength` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_array_length_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_array_length_sync() const;

  /// Reads the `MaxStringLength` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_string_length_sync, read_max_string_length_sync
  void read_max_string_length_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxStringLength` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_string_length_async gives it. Never throws.
  UInt32Result try_read_max_string_length_sync() const noexcept;
  /// Reads the `MaxStringLength` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_string_length_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_string_length_sync() const;

  /// Reads the `MaxByteStringLength` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_byte_string_length_sync, read_max_byte_string_length_sync
  void read_max_byte_string_length_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxByteStringLength` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_byte_string_length_async gives it. Never
  /// throws.
  UInt32Result try_read_max_byte_string_length_sync() const noexcept;
  /// Reads the `MaxByteStringLength` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_byte_string_length_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_byte_string_length_sync() const;

  /// Reads the `MaxSessions` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_sessions_sync, read_max_sessions_sync
  void read_max_sessions_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxSessions` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_sessions_async gives it. Never throws.
  UInt32Result try_read_max_sessions_sync() const noexcept;
  /// Reads the `MaxSessions` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_sessions_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_sessions_sync() const;

  /// Reads the `MaxSubscriptions` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_subscriptions_sync, read_max_subscriptions_sync
  void read_max_subscriptions_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxSubscriptions` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_subscriptions_async gives it. Never throws.
  UInt32Result try_read_max_subscriptions_sync() const noexcept;
  /// Reads the `MaxSubscriptions` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_subscriptions_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_subscriptions_sync() const;

  /// Reads the `MaxMonitoredItems` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_monitored_items_sync, read_max_monitored_items_sync
  void read_max_monitored_items_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxMonitoredItems` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_monitored_items_async gives it. Never throws.
  UInt32Result try_read_max_monitored_items_sync() const noexcept;
  /// Reads the `MaxMonitoredItems` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_max_monitored_items_sync
  /// returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_monitored_items_sync() const;

  /// Reads the `MaxSubscriptionsPerSession` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_subscriptions_per_session_sync, read_max_subscriptions_per_session_sync
  void read_max_subscriptions_per_session_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxSubscriptionsPerSession` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_subscriptions_per_session_async gives it. Never
  /// throws.
  UInt32Result try_read_max_subscriptions_per_session_sync() const noexcept;
  /// Reads the `MaxSubscriptionsPerSession` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_subscriptions_per_session_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_subscriptions_per_session_sync() const;

  /// Reads the `MaxMonitoredItemsPerSubscription` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_monitored_items_per_subscription_sync, read_max_monitored_items_per_subscription_sync
  void read_max_monitored_items_per_subscription_async(
    std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxMonitoredItemsPerSubscription` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_monitored_items_per_subscription_async gives
  /// it. Never throws.
  UInt32Result try_read_max_monitored_items_per_subscription_sync() const noexcept;
  /// Reads the `MaxMonitoredItemsPerSubscription` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_monitored_items_per_subscription_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_monitored_items_per_subscription_sync() const;

  /// Reads the `MaxSelectClauseParameters` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_select_clause_parameters_sync, read_max_select_clause_parameters_sync
  void read_max_select_clause_parameters_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxSelectClauseParameters` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_select_clause_parameters_async gives it. Never
  /// throws.
  UInt32Result try_read_max_select_clause_parameters_sync() const noexcept;
  /// Reads the `MaxSelectClauseParameters` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_select_clause_parameters_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_select_clause_parameters_sync() const;

  /// Reads the `MaxWhereClauseParameters` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_where_clause_parameters_sync, read_max_where_clause_parameters_sync
  void read_max_where_clause_parameters_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxWhereClauseParameters` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_where_clause_parameters_async gives it. Never
  /// throws.
  UInt32Result try_read_max_where_clause_parameters_sync() const noexcept;
  /// Reads the `MaxWhereClauseParameters` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_where_clause_parameters_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_where_clause_parameters_sync() const;

  /// Reads the `MaxMonitoredItemsQueueSize` property value, typed as `uint32_t`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_max_monitored_items_queue_size_sync, read_max_monitored_items_queue_size_sync
  void read_max_monitored_items_queue_size_async(std::function<void(UInt32Result)> complete) const noexcept;
  /// Reads the `MaxMonitoredItemsQueueSize` property value as `uint32_t`, blocking until complete.
  /// @return The value with the read's code, as @ref read_max_monitored_items_queue_size_async gives it.
  /// Never throws.
  UInt32Result try_read_max_monitored_items_queue_size_sync() const noexcept;
  /// Reads the `MaxMonitoredItemsQueueSize` property value as `uint32_t`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref
  /// try_read_max_monitored_items_queue_size_sync returns it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  uint32_t read_max_monitored_items_queue_size_sync() const;

  /// Reads the `ConformanceUnits` property value, typed as `QualifiedName`.
  /// @param complete Receives the value with the read's code, a Good subcode or an Uncertain code included;
  /// no value when that code is Bad, when an Uncertain reading holds none, or with Bad_TypeMismatch when the
  /// value is not of that type. Never throws.
  /// @see try_read_conformance_units_sync, read_conformance_units_sync
  void read_conformance_units_async(std::function<void(QualifiedNameResult)> complete) const noexcept;
  /// Reads the `ConformanceUnits` property value as `QualifiedName`, blocking until complete.
  /// @return The value with the read's code, as @ref read_conformance_units_async gives it. Never throws.
  QualifiedNameResult try_read_conformance_units_sync() const noexcept;
  /// Reads the `ConformanceUnits` property value as `QualifiedName`, blocking until complete.
  /// @return The property value. A Good subcode is not returned; @ref try_read_conformance_units_sync returns
  /// it.
  /// @throws UaException when the read is not Good, an Uncertain reading included.
  QualifiedName read_conformance_units_sync() const;

  // --- Typed value write shortcuts ---

  /// Writes the `ServerProfileArray` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_server_profile_array_sync, write_server_profile_array_sync
  void write_server_profile_array_async(
    String value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ServerProfileArray` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_server_profile_array_sync(String value) const noexcept;
  /// Writes the `ServerProfileArray` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_server_profile_array_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_server_profile_array_sync(String value) const;

  /// Writes the `MaxBrowseContinuationPoints` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_browse_continuation_points_sync, write_max_browse_continuation_points_sync
  void write_max_browse_continuation_points_async(
    uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxBrowseContinuationPoints` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_browse_continuation_points_sync(uint16_t value) const noexcept;
  /// Writes the `MaxBrowseContinuationPoints` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_browse_continuation_points_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_browse_continuation_points_sync(uint16_t value) const;

  /// Writes the `MaxQueryContinuationPoints` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_query_continuation_points_sync, write_max_query_continuation_points_sync
  void write_max_query_continuation_points_async(
    uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxQueryContinuationPoints` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_query_continuation_points_sync(uint16_t value) const noexcept;
  /// Writes the `MaxQueryContinuationPoints` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_query_continuation_points_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_query_continuation_points_sync(uint16_t value) const;

  /// Writes the `MaxHistoryContinuationPoints` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_history_continuation_points_sync, write_max_history_continuation_points_sync
  void write_max_history_continuation_points_async(
    uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxHistoryContinuationPoints` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_history_continuation_points_sync(uint16_t value) const noexcept;
  /// Writes the `MaxHistoryContinuationPoints` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_history_continuation_points_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_history_continuation_points_sync(uint16_t value) const;

  /// Writes the `MaxLogObjectContinuationPoints` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_log_object_continuation_points_sync, write_max_log_object_continuation_points_sync
  void write_max_log_object_continuation_points_async(
    uint16_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxLogObjectContinuationPoints` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_log_object_continuation_points_sync(uint16_t value) const noexcept;
  /// Writes the `MaxLogObjectContinuationPoints` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_log_object_continuation_points_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_log_object_continuation_points_sync(uint16_t value) const;

  /// Writes the `MaxArrayLength` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_array_length_sync, write_max_array_length_sync
  void write_max_array_length_async(uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxArrayLength` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_array_length_sync(uint32_t value) const noexcept;
  /// Writes the `MaxArrayLength` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_array_length_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_array_length_sync(uint32_t value) const;

  /// Writes the `MaxStringLength` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_string_length_sync, write_max_string_length_sync
  void write_max_string_length_async(uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxStringLength` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_string_length_sync(uint32_t value) const noexcept;
  /// Writes the `MaxStringLength` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_string_length_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_string_length_sync(uint32_t value) const;

  /// Writes the `MaxByteStringLength` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_byte_string_length_sync, write_max_byte_string_length_sync
  void write_max_byte_string_length_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxByteStringLength` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_byte_string_length_sync(uint32_t value) const noexcept;
  /// Writes the `MaxByteStringLength` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_byte_string_length_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_byte_string_length_sync(uint32_t value) const;

  /// Writes the `MaxSessions` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_sessions_sync, write_max_sessions_sync
  void write_max_sessions_async(uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxSessions` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_sessions_sync(uint32_t value) const noexcept;
  /// Writes the `MaxSessions` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_sessions_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_sessions_sync(uint32_t value) const;

  /// Writes the `MaxSubscriptions` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_subscriptions_sync, write_max_subscriptions_sync
  void write_max_subscriptions_async(uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxSubscriptions` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_subscriptions_sync(uint32_t value) const noexcept;
  /// Writes the `MaxSubscriptions` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_subscriptions_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_subscriptions_sync(uint32_t value) const;

  /// Writes the `MaxMonitoredItems` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_monitored_items_sync, write_max_monitored_items_sync
  void write_max_monitored_items_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxMonitoredItems` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_monitored_items_sync(uint32_t value) const noexcept;
  /// Writes the `MaxMonitoredItems` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_monitored_items_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_monitored_items_sync(uint32_t value) const;

  /// Writes the `MaxSubscriptionsPerSession` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_subscriptions_per_session_sync, write_max_subscriptions_per_session_sync
  void write_max_subscriptions_per_session_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxSubscriptionsPerSession` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_subscriptions_per_session_sync(uint32_t value) const noexcept;
  /// Writes the `MaxSubscriptionsPerSession` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_subscriptions_per_session_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_subscriptions_per_session_sync(uint32_t value) const;

  /// Writes the `MaxMonitoredItemsPerSubscription` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_monitored_items_per_subscription_sync,
  /// write_max_monitored_items_per_subscription_sync
  void write_max_monitored_items_per_subscription_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxMonitoredItemsPerSubscription` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_monitored_items_per_subscription_sync(uint32_t value) const noexcept;
  /// Writes the `MaxMonitoredItemsPerSubscription` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_monitored_items_per_subscription_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_monitored_items_per_subscription_sync(uint32_t value) const;

  /// Writes the `MaxSelectClauseParameters` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_select_clause_parameters_sync, write_max_select_clause_parameters_sync
  void write_max_select_clause_parameters_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxSelectClauseParameters` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_select_clause_parameters_sync(uint32_t value) const noexcept;
  /// Writes the `MaxSelectClauseParameters` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_select_clause_parameters_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_select_clause_parameters_sync(uint32_t value) const;

  /// Writes the `MaxWhereClauseParameters` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_where_clause_parameters_sync, write_max_where_clause_parameters_sync
  void write_max_where_clause_parameters_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxWhereClauseParameters` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_where_clause_parameters_sync(uint32_t value) const noexcept;
  /// Writes the `MaxWhereClauseParameters` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_where_clause_parameters_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_where_clause_parameters_sync(uint32_t value) const;

  /// Writes the `MaxMonitoredItemsQueueSize` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_max_monitored_items_queue_size_sync, write_max_monitored_items_queue_size_sync
  void write_max_monitored_items_queue_size_async(
    uint32_t value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `MaxMonitoredItemsQueueSize` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_max_monitored_items_queue_size_sync(uint32_t value) const noexcept;
  /// Writes the `MaxMonitoredItemsQueueSize` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_max_monitored_items_queue_size_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_max_monitored_items_queue_size_sync(uint32_t value) const;

  /// Writes the `ConformanceUnits` property value.
  /// @param value    The new value to write.
  /// @param complete Receives success, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_write_conformance_units_sync, write_conformance_units_sync
  void write_conformance_units_async(
    QualifiedName value, std::function<void(VoidResult)> complete) const noexcept;
  /// Writes the `ConformanceUnits` property value, blocking until complete.
  /// @param value The new value to write.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_write_conformance_units_sync(QualifiedName value) const noexcept;
  /// Writes the `ConformanceUnits` property value, blocking until complete.
  /// @param value The new value to write.
  /// A Good subcode is not returned; @ref try_write_conformance_units_sync returns it.
  /// @throws UaException when the write is not Good, an Uncertain answer included.
  void write_conformance_units_sync(QualifiedName value) const;

  // --- Child-object accessors (return typed instance handles) ---

  /// Attaches a typed `OperationLimits` handle for the `OperationLimits` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_operation_limits_sync, operation_limits_sync
  void operation_limits_async(std::function<void(OperationLimitsResult)> complete) const noexcept;
  /// Attaches a typed `OperationLimits` handle for the `OperationLimits` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  OperationLimitsResult try_operation_limits_sync() const noexcept;
  /// Attaches a typed `OperationLimits` handle for the `OperationLimits` child, blocking until complete.
  /// @return The `OperationLimits` handle. A Good subcode is not returned; @ref try_operation_limits_sync
  /// returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  OperationLimits operation_limits_sync() const;

  /// Attaches a typed `Folder` handle for the `ModellingRules` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_modelling_rules_sync, modelling_rules_sync
  void modelling_rules_async(std::function<void(FolderResult)> complete) const noexcept;
  /// Attaches a typed `Folder` handle for the `ModellingRules` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  FolderResult try_modelling_rules_sync() const noexcept;
  /// Attaches a typed `Folder` handle for the `ModellingRules` child, blocking until complete.
  /// @return The `Folder` handle. A Good subcode is not returned; @ref try_modelling_rules_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Folder modelling_rules_sync() const;

  /// Attaches a typed `Folder` handle for the `AggregateFunctions` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_aggregate_functions_sync, aggregate_functions_sync
  void aggregate_functions_async(std::function<void(FolderResult)> complete) const noexcept;
  /// Attaches a typed `Folder` handle for the `AggregateFunctions` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  FolderResult try_aggregate_functions_sync() const noexcept;
  /// Attaches a typed `Folder` handle for the `AggregateFunctions` child, blocking until complete.
  /// @return The `Folder` handle. A Good subcode is not returned; @ref try_aggregate_functions_sync returns
  /// it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  Folder aggregate_functions_sync() const;

  /// Attaches a typed `RoleSet` handle for the `RoleSet` child.
  /// @param complete Receives the handle, or an @ref ErrorDetail on failure. Never throws.
  /// @see try_role_set_sync, role_set_sync
  void role_set_async(std::function<void(RoleSetResult)> complete) const noexcept;
  /// Attaches a typed `RoleSet` handle for the `RoleSet` child, blocking until complete.
  /// @return The handle, or an @ref ErrorDetail on failure. Never throws.
  RoleSetResult try_role_set_sync() const noexcept;
  /// Attaches a typed `RoleSet` handle for the `RoleSet` child, blocking until complete.
  /// @return The `RoleSet` handle. A Good subcode is not returned; @ref try_role_set_sync returns it.
  /// @throws UaException when the answer is not Good, an Uncertain one included.
  RoleSet role_set_sync() const;

private:
  explicit ServerCapabilities(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  static void create_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    InstantiationOptions options, CreateCompleteCallback complete) noexcept;

  static void attach_impl_async(
    AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept;

  // Common helper: finds a child property by browse name and attaches a Property handle.
  void find_property_async(
    QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept;
};

}  // namespace ua

#endif  // UA_SERVER_CAPABILITIES_H
