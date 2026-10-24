// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side accessor for the OPC UA Subscription Service Set on a Session.
/// @ingroup client

#ifndef UA_SESSION_SUBSCRIPTION_SERVICES_H
#define UA_SESSION_SUBSCRIPTION_SERVICES_H

#include "ua_create_subscription_request.h"
#include "ua_create_subscription_response.h"
#include "ua_delete_subscriptions_request.h"
#include "ua_delete_subscriptions_response.h"
#include "ua_modify_subscription_request.h"
#include "ua_modify_subscription_response.h"
#include "ua_publish_request.h"
#include "ua_publish_response.h"
#include "ua_republish_request.h"
#include "ua_republish_response.h"
#include "ua_result.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_set_publishing_mode_response.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_transfer_subscriptions_response.h"

#include <functional>
#include <memory>

namespace ua::client
{

class Session;
class SessionImpl;

/// Non-owning accessor for OPC UA Subscription Service Set operations on a Session.
///
/// Provides the Subscription services - CreateSubscription, ModifySubscription,
/// SetPublishingMode, Publish, Republish, TransferSubscriptions and
/// DeleteSubscriptions - used to manage subscriptions and exchange Notification
/// Messages with the server. Instances are vended by a @ref Session and hold
/// only a weak reference to the owning session's implementation; they do not
/// extend its lifetime and become inert once the session is gone. Copyable as a
/// lightweight handle.
/// @ingroup client
class SessionSubscriptionServices
{
public:
  // CreateSubscription
  /// Result of a CreateSubscription invocation: a @ref CreateSubscriptionResponse, or an
  /// @ref ErrorDetail on failure.
  using CreateSubscriptionResponseResult = ua::Result<ua::CreateSubscriptionResponse>;
  /// Callback receiving the outcome of @ref create_subscription_async.
  using CreateSubscriptionCallback = std::function<void(CreateSubscriptionResponseResult)>;

  /// Creates a subscription on the server via the CreateSubscription service.
  ///
  /// Posts the request and completes asynchronously; the callback runs on an
  /// unspecified worker thread, so do not block it. A successful Result indicates
  /// only that the service request itself completed; inspect the response for the
  /// assigned subscription identifier and the revised publishing parameters.
  ///
  /// @param request  The CreateSubscription request. Consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref CreateSubscriptionResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see create_subscription_sync, try_create_subscription_sync
  void create_subscription_async(
    ua::CreateSubscriptionRequest request, CreateSubscriptionCallback callback) noexcept;

  /// Creates a subscription on the server, blocking until complete.
  ///
  /// @param request The CreateSubscription request. Consumed by value.
  /// @return The service response.
  /// @throws UaException if the service request fails.
  /// @see create_subscription_async, try_create_subscription_sync
  /// A Good subcode on the answer is not returned; try_create_subscription_sync() returns it.
  ua::CreateSubscriptionResponse create_subscription_sync(ua::CreateSubscriptionRequest request);

  /// Creates a subscription on the server, blocking until complete.
  ///
  /// @param request The CreateSubscription request. Consumed by value.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see create_subscription_async, create_subscription_sync
  CreateSubscriptionResponseResult try_create_subscription_sync(
    ua::CreateSubscriptionRequest request) noexcept;

  // ModifySubscription
  /// Result of a ModifySubscription invocation: a @ref ModifySubscriptionResponse, or an
  /// @ref ErrorDetail on failure.
  using ModifySubscriptionResponseResult = ua::Result<ua::ModifySubscriptionResponse>;
  /// Callback receiving the outcome of @ref modify_subscription_async.
  using ModifySubscriptionCallback = std::function<void(ModifySubscriptionResponseResult)>;

  /// Modifies an existing subscription's parameters via the ModifySubscription service.
  ///
  /// Posts the request and completes asynchronously; the callback runs on an
  /// unspecified worker thread, so do not block it. The response carries the
  /// values the server revised the request to.
  ///
  /// @param request  The ModifySubscription request. Consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref ModifySubscriptionResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see modify_subscription_sync, try_modify_subscription_sync
  void modify_subscription_async(
    ua::ModifySubscriptionRequest request, ModifySubscriptionCallback callback) noexcept;

  /// Modifies an existing subscription's parameters, blocking until complete.
  ///
  /// @param request The ModifySubscription request. Consumed by value.
  /// @return The service response.
  /// @throws UaException if the service request fails.
  /// @see modify_subscription_async, try_modify_subscription_sync
  /// A Good subcode on the answer is not returned; try_modify_subscription_sync() returns it.
  ua::ModifySubscriptionResponse modify_subscription_sync(ua::ModifySubscriptionRequest request);

  /// Modifies an existing subscription's parameters, blocking until complete.
  ///
  /// @param request The ModifySubscription request. Consumed by value.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see modify_subscription_async, modify_subscription_sync
  ModifySubscriptionResponseResult try_modify_subscription_sync(
    ua::ModifySubscriptionRequest request) noexcept;

  // SetPublishingMode
  /// Result of a SetPublishingMode invocation: a @ref SetPublishingModeResponse, or an
  /// @ref ErrorDetail on failure.
  using SetPublishingModeResponseResult = ua::Result<ua::SetPublishingModeResponse>;
  /// Callback receiving the outcome of @ref set_publishing_mode_async.
  using SetPublishingModeCallback = std::function<void(SetPublishingModeResponseResult)>;

  /// Enables or disables sending of NotificationMessages for one or more subscriptions.
  ///
  /// Posts the request and completes asynchronously; the callback runs on an
  /// unspecified worker thread, so do not block it. A per-subscription status is
  /// carried in the response's results - a successful Result indicates only that
  /// the service request itself completed.
  ///
  /// @param request  The SetPublishingMode request listing the target subscriptions.
  ///                 Consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref SetPublishingModeResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see set_publishing_mode_sync, try_set_publishing_mode_sync
  void set_publishing_mode_async(
    ua::SetPublishingModeRequest request, SetPublishingModeCallback callback) noexcept;

  /// Enables or disables NotificationMessage sending for subscriptions, blocking until complete.
  ///
  /// @param request The SetPublishingMode request listing the target subscriptions.
  ///                Consumed by value.
  /// @return The service response.
  /// @throws UaException if the service request fails.
  /// @see set_publishing_mode_async, try_set_publishing_mode_sync
  /// A Good subcode on the answer is not returned; try_set_publishing_mode_sync() returns it.
  ua::SetPublishingModeResponse set_publishing_mode_sync(ua::SetPublishingModeRequest request);

  /// Enables or disables NotificationMessage sending for subscriptions, blocking until complete.
  ///
  /// @param request The SetPublishingMode request listing the target subscriptions.
  ///                Consumed by value.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see set_publishing_mode_async, set_publishing_mode_sync
  SetPublishingModeResponseResult try_set_publishing_mode_sync(ua::SetPublishingModeRequest request) noexcept;

  // Publish
  /// Result of a Publish invocation: a @ref PublishResponse, or an @ref ErrorDetail on failure.
  using PublishResponseResult = ua::Result<ua::PublishResponse>;
  /// Callback receiving the outcome of @ref publish_async.
  using PublishCallback = std::function<void(PublishResponseResult)>;

  /// Acknowledges prior NotificationMessages and requests the next one via the Publish service.
  ///
  /// Posts the request and completes asynchronously; the callback runs on an
  /// unspecified worker thread, so do not block it. The server queues the request
  /// and answers it when a NotificationMessage or keep-alive is due, so the
  /// callback may fire well after the call returns.
  ///
  /// @param request  The Publish request carrying acknowledgements for previously
  ///                 received messages. Consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref PublishResponse; on failure it carries an @ref ErrorDetail.
  ///                 This overload never throws.
  /// @see publish_sync, try_publish_sync
  void publish_async(ua::PublishRequest request, PublishCallback callback) noexcept;

  /// Acknowledges prior NotificationMessages and requests the next one, blocking until complete.
  ///
  /// @param request The Publish request carrying acknowledgements. Consumed by value.
  /// @return The service response.
  /// @throws UaException if the service request fails.
  /// @see publish_async, try_publish_sync
  /// A Good subcode on the answer is not returned; try_publish_sync() returns it.
  ua::PublishResponse publish_sync(ua::PublishRequest request);

  /// Acknowledges prior NotificationMessages and requests the next one, blocking until complete.
  ///
  /// @param request The Publish request carrying acknowledgements. Consumed by value.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see publish_async, publish_sync
  PublishResponseResult try_publish_sync(ua::PublishRequest request) noexcept;

  // Republish
  /// Result of a Republish invocation: a @ref RepublishResponse, or an @ref ErrorDetail on failure.
  using RepublishResponseResult = ua::Result<ua::RepublishResponse>;
  /// Callback receiving the outcome of @ref republish_async.
  using RepublishCallback = std::function<void(RepublishResponseResult)>;

  /// Requests a specific NotificationMessage be re-sent from a subscription's retransmission queue.
  ///
  /// Posts the request and completes asynchronously; the callback runs on an
  /// unspecified worker thread, so do not block it. Used to recover a message
  /// identified by its sequence number after a gap is detected.
  ///
  /// @param request  The Republish request naming the subscription and sequence number.
  ///                 Consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref RepublishResponse; on failure it carries an @ref ErrorDetail.
  ///                 This overload never throws.
  /// @see republish_sync, try_republish_sync
  void republish_async(ua::RepublishRequest request, RepublishCallback callback) noexcept;

  /// Requests a specific NotificationMessage be re-sent, blocking until complete.
  ///
  /// @param request The Republish request naming the subscription and sequence number.
  ///                Consumed by value.
  /// @return The service response.
  /// @throws UaException if the service request fails.
  /// @see republish_async, try_republish_sync
  /// A Good subcode on the answer is not returned; try_republish_sync() returns it.
  ua::RepublishResponse republish_sync(ua::RepublishRequest request);

  /// Requests a specific NotificationMessage be re-sent, blocking until complete.
  ///
  /// @param request The Republish request naming the subscription and sequence number.
  ///                Consumed by value.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see republish_async, republish_sync
  RepublishResponseResult try_republish_sync(ua::RepublishRequest request) noexcept;

  // TransferSubscriptions
  /// Result of a TransferSubscriptions invocation: a @ref TransferSubscriptionsResponse, or an
  /// @ref ErrorDetail on failure.
  using TransferSubscriptionsResponseResult = ua::Result<ua::TransferSubscriptionsResponse>;
  /// Callback receiving the outcome of @ref transfer_subscriptions_async.
  using TransferSubscriptionsCallback = std::function<void(TransferSubscriptionsResponseResult)>;

  /// Transfers one or more subscriptions to this session via the TransferSubscriptions service.
  ///
  /// Posts the request and completes asynchronously; the callback runs on an
  /// unspecified worker thread, so do not block it. A per-subscription status is
  /// carried in the response's results - a successful Result indicates only that
  /// the service request itself completed.
  ///
  /// @param request  The TransferSubscriptions request listing the subscriptions to
  ///                 transfer. Consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref TransferSubscriptionsResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see transfer_subscriptions_sync, try_transfer_subscriptions_sync
  void transfer_subscriptions_async(
    ua::TransferSubscriptionsRequest request, TransferSubscriptionsCallback callback) noexcept;

  /// Transfers one or more subscriptions to this session, blocking until complete.
  ///
  /// @param request The TransferSubscriptions request listing the subscriptions to
  ///                transfer. Consumed by value.
  /// @return The service response.
  /// @throws UaException if the service request fails.
  /// @see transfer_subscriptions_async, try_transfer_subscriptions_sync
  /// A Good subcode on the answer is not returned; try_transfer_subscriptions_sync() returns it.
  ua::TransferSubscriptionsResponse transfer_subscriptions_sync(ua::TransferSubscriptionsRequest request);

  /// Transfers one or more subscriptions to this session, blocking until complete.
  ///
  /// @param request The TransferSubscriptions request listing the subscriptions to
  ///                transfer. Consumed by value.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see transfer_subscriptions_async, transfer_subscriptions_sync
  TransferSubscriptionsResponseResult try_transfer_subscriptions_sync(
    ua::TransferSubscriptionsRequest request) noexcept;

  // DeleteSubscriptions
  /// Result of a DeleteSubscriptions invocation: a @ref DeleteSubscriptionsResponse, or an
  /// @ref ErrorDetail on failure.
  using DeleteSubscriptionsResponseResult = ua::Result<ua::DeleteSubscriptionsResponse>;
  /// Callback receiving the outcome of @ref delete_subscriptions_async.
  using DeleteSubscriptionsCallback = std::function<void(DeleteSubscriptionsResponseResult)>;

  /// Deletes one or more subscriptions and their MonitoredItems via the DeleteSubscriptions service.
  ///
  /// Posts the request and completes asynchronously; the callback runs on an
  /// unspecified worker thread, so do not block it. A per-subscription status is
  /// carried in the response's results - a successful Result indicates only that
  /// the service request itself completed.
  ///
  /// @param request  The DeleteSubscriptions request listing the subscriptions to
  ///                 delete. Consumed by value.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref DeleteSubscriptionsResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see delete_subscriptions_sync, try_delete_subscriptions_sync
  void delete_subscriptions_async(
    ua::DeleteSubscriptionsRequest request, DeleteSubscriptionsCallback callback) noexcept;

  /// Deletes one or more subscriptions and their MonitoredItems, blocking until complete.
  ///
  /// @param request The DeleteSubscriptions request listing the subscriptions to
  ///                delete. Consumed by value.
  /// @return The service response.
  /// @throws UaException if the service request fails.
  /// @see delete_subscriptions_async, try_delete_subscriptions_sync
  /// A Good subcode on the answer is not returned; try_delete_subscriptions_sync() returns it.
  ua::DeleteSubscriptionsResponse delete_subscriptions_sync(ua::DeleteSubscriptionsRequest request);

  /// Deletes one or more subscriptions and their MonitoredItems, blocking until complete.
  ///
  /// @param request The DeleteSubscriptions request listing the subscriptions to
  ///                delete. Consumed by value.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see delete_subscriptions_async, delete_subscriptions_sync
  DeleteSubscriptionsResponseResult try_delete_subscriptions_sync(
    ua::DeleteSubscriptionsRequest request) noexcept;

private:
  friend class Session;
  explicit SessionSubscriptionServices(std::weak_ptr<SessionImpl> impl);

  std::weak_ptr<SessionImpl> mImpl;
};

}  // namespace ua::client

#endif  // !UA_SESSION_SUBSCRIPTION_SERVICES_H
