// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Client-side accessor for the OPC UA Attribute Service Set (Read, Write, History).
/// @ingroup client

#ifndef UA_SESSION_ATTRIBUTE_SERVICES_H
#define UA_SESSION_ATTRIBUTE_SERVICES_H

#include "ua_history_read_request.h"
#include "ua_history_read_response.h"
#include "ua_history_update_request.h"
#include "ua_history_update_response.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_result.h"
#include "ua_write_request.h"
#include "ua_write_response.h"

#include <functional>
#include <memory>

namespace ua::client
{

class Session;
class SessionImpl;

/// Non-owning accessor for the OPC UA Attribute Service Set on a Session.
///
/// Exposes the Read, HistoryRead, Write, and HistoryUpdate services as a
/// callback-canonical `*_async` method plus throwing `*_sync` and non-throwing
/// `try_*_sync` convenience wrappers. The accessor holds only a weak reference
/// to its owning session: it never keeps the session alive, and operations
/// invoked after the session is destroyed complete with an @ref ErrorDetail
/// rather than dereferencing a dangling owner. Obtain instances from a
/// @ref Session; do not construct directly.
/// @ingroup client
class SessionAttributeServices
{
public:
  // Read

  /// Result of a Read service call: a @ref ReadResponse or an @ref ErrorDetail.
  using ReadResponseResult = ua::Result<ua::ReadResponse>;
  /// Completion callback for read_async, receiving the @ref ReadResponseResult.
  using ReadCallback = std::function<void(ReadResponseResult)>;

  /// Reads node attributes via the OPC UA Read service.
  ///
  /// Sends the request asynchronously and completes via the callback, which runs
  /// on an unspecified worker thread - do not block it. A non-fault response is
  /// delivered as a success @ref ReadResponse even when individual operation
  /// results within it carry per-node failures.
  ///
  /// @param request  Nodes and attributes to read.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref ReadResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see read_sync, try_read_sync
  void read_async(ua::ReadRequest request, ReadCallback callback) noexcept;

  /// Reads node attributes via the OPC UA Read service, blocking until complete.
  ///
  /// @param request Nodes and attributes to read.
  /// @return The service response.
  /// @throws UaException if the request fails at the service level.
  /// @see read_async, try_read_sync
  /// A Good subcode on the answer is not returned; try_read_sync() returns it.
  ua::ReadResponse read_sync(ua::ReadRequest request);

  /// Reads node attributes via the OPC UA Read service, blocking until complete.
  ///
  /// @param request Nodes and attributes to read.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see read_async, read_sync
  ReadResponseResult try_read_sync(ua::ReadRequest request) noexcept;

  // HistoryRead

  /// Result of a HistoryRead call: a @ref HistoryReadResponse or an @ref ErrorDetail.
  using HistoryReadResponseResult = ua::Result<ua::HistoryReadResponse>;
  /// Completion callback for history_read_async, receiving the @ref HistoryReadResponseResult.
  using HistoryReadCallback = std::function<void(HistoryReadResponseResult)>;

  /// Reads historical values or events via the OPC UA HistoryRead service.
  ///
  /// Sends the request asynchronously and completes via the callback, which runs
  /// on an unspecified worker thread - do not block it. A continuation point in
  /// the response indicates more data is available and must be passed back on a
  /// subsequent call to retrieve it.
  ///
  /// @param request  History read details, nodes, and any continuation points.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref HistoryReadResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see history_read_sync, try_history_read_sync
  void history_read_async(ua::HistoryReadRequest request, HistoryReadCallback callback) noexcept;

  /// Reads history via the OPC UA HistoryRead service, blocking until complete.
  ///
  /// @param request History read details, nodes, and any continuation points.
  /// @return The service response.
  /// @throws UaException if the request fails at the service level.
  /// @see history_read_async, try_history_read_sync
  /// A Good subcode on the answer is not returned; try_history_read_sync() returns it.
  ua::HistoryReadResponse history_read_sync(ua::HistoryReadRequest request);

  /// Reads history via the OPC UA HistoryRead service, blocking until complete.
  ///
  /// @param request History read details, nodes, and any continuation points.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see history_read_async, history_read_sync
  HistoryReadResponseResult try_history_read_sync(ua::HistoryReadRequest request) noexcept;

  // Write

  /// Result of a Write service call: a @ref WriteResponse or an @ref ErrorDetail.
  using WriteResponseResult = ua::Result<ua::WriteResponse>;
  /// Completion callback for write_async, receiving the @ref WriteResponseResult.
  using WriteCallback = std::function<void(WriteResponseResult)>;

  /// Writes node attribute values via the OPC UA Write service.
  ///
  /// Sends the request asynchronously and completes via the callback, which runs
  /// on an unspecified worker thread - do not block it. A non-fault response is
  /// delivered as a success @ref WriteResponse even when individual write
  /// operations within it carry per-node failures.
  ///
  /// @param request  Nodes, attributes, and values to write.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref WriteResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see write_sync, try_write_sync
  void write_async(ua::WriteRequest request, WriteCallback callback) noexcept;

  /// Writes node attribute values via the OPC UA Write service, blocking until complete.
  ///
  /// @param request Nodes, attributes, and values to write.
  /// @return The service response.
  /// @throws UaException if the request fails at the service level.
  /// @see write_async, try_write_sync
  /// A Good subcode on the answer is not returned; try_write_sync() returns it.
  ua::WriteResponse write_sync(ua::WriteRequest request);

  /// Writes node attribute values via the OPC UA Write service, blocking until complete.
  ///
  /// @param request Nodes, attributes, and values to write.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see write_async, write_sync
  WriteResponseResult try_write_sync(ua::WriteRequest request) noexcept;

  // HistoryUpdate

  /// Result of a HistoryUpdate call: a @ref HistoryUpdateResponse or an @ref ErrorDetail.
  using HistoryUpdateResponseResult = ua::Result<ua::HistoryUpdateResponse>;
  /// Completion callback for history_update_async, receiving the @ref HistoryUpdateResponseResult.
  using HistoryUpdateCallback = std::function<void(HistoryUpdateResponseResult)>;

  /// Inserts, replaces, or deletes history via the OPC UA HistoryUpdate service.
  ///
  /// Sends the request asynchronously and completes via the callback, which runs
  /// on an unspecified worker thread - do not block it. A non-fault response is
  /// delivered as a success @ref HistoryUpdateResponse even when individual
  /// update operations within it carry per-node failures.
  ///
  /// @param request  History update details describing the modifications to apply.
  /// @param callback Receives the outcome: on success the Result holds the
  ///                 @ref HistoryUpdateResponse; on failure it carries an
  ///                 @ref ErrorDetail. This overload never throws.
  /// @see history_update_sync, try_history_update_sync
  void history_update_async(ua::HistoryUpdateRequest request, HistoryUpdateCallback callback) noexcept;

  /// Updates history via the OPC UA HistoryUpdate service, blocking until complete.
  ///
  /// @param request History update details describing the modifications to apply.
  /// @return The service response.
  /// @throws UaException if the request fails at the service level.
  /// @see history_update_async, try_history_update_sync
  /// A Good subcode on the answer is not returned; try_history_update_sync() returns it.
  ua::HistoryUpdateResponse history_update_sync(ua::HistoryUpdateRequest request);

  /// Updates history via the OPC UA HistoryUpdate service, blocking until complete.
  ///
  /// @param request History update details describing the modifications to apply.
  /// @return The service response, or an @ref ErrorDetail on failure. Never throws.
  /// @see history_update_async, history_update_sync
  HistoryUpdateResponseResult try_history_update_sync(ua::HistoryUpdateRequest request) noexcept;

private:
  friend class Session;
  explicit SessionAttributeServices(std::weak_ptr<SessionImpl> impl);

  std::weak_ptr<SessionImpl> mImpl;
};

}  // namespace ua::client

#endif  // !UA_SESSION_ATTRIBUTE_SERVICES_H
