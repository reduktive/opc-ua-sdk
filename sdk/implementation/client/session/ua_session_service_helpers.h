// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SESSION_SERVICE_HELPERS_H
#define UA_SESSION_SERVICE_HELPERS_H

#include "ua_sync_wait.h"
#include "ua_client_session_impl.h"

#include "ua_data_value.h"  // Required: completes DataValue before generated request/response types that use Array<Variant>.
#include "ua_date_time.h"
#include "ua_add_nodes_request.h"
#include "ua_add_references_request.h"
#include "ua_call_request.h"
#include "ua_cancel_request.h"
#include "ua_delete_nodes_request.h"
#include "ua_delete_references_request.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_history_update_request.h"
#include "ua_to_result.h"
#include "ua_transfer_subscriptions_request.h"
#include "ua_write_request.h"

#include <future>
#include <memory>
#include <type_traits>

namespace ua::client::detail
{

template<typename RequestT>
inline constexpr bool is_auditable_session_service_request =
  std::is_same_v<RequestT, ua::CancelRequest> || std::is_same_v<RequestT, ua::AddNodesRequest> ||
  std::is_same_v<RequestT, ua::AddReferencesRequest> || std::is_same_v<RequestT, ua::DeleteNodesRequest> ||
  std::is_same_v<RequestT, ua::DeleteReferencesRequest> || std::is_same_v<RequestT, ua::WriteRequest> ||
  std::is_same_v<RequestT, ua::HistoryUpdateRequest> || std::is_same_v<RequestT, ua::CallRequest> ||
  std::is_same_v<RequestT, ua::TransferSubscriptionsRequest>;

/// Send a typed request through the session impl and downcast the response.
/// Stamps the authentication token on the request header before type-erasing.
template<typename ResponseT, typename RequestT>
void typed_request_async(std::shared_ptr<SessionImpl> impl, RequestT request,
  std::function<void(ua::Result<ResponseT>)> callback) noexcept
{
  using SRR = SessionImpl::ServiceResponseResult;
  using ResultT = ua::Result<ResponseT>;

  try
  {
    // Part 4 7.33 defines timeoutHint as the Client telling the Server how long it will wait, and 0
    // as "no timeout". Sending 0 while enforcing a local deadline tells the Server nothing and leaves
    // it completing work the Client has already abandoned - so the configured default is stamped on
    // the outbound header and drives the local deadline below from that same value.
    auto timeoutMs = impl->timeout_hint_for(request.request_header().timeout_hint());
    request.request_header().timeout_hint() = timeoutMs;
    // Part 4 section 7.33: populate the current UTC send time for every typed service.
    request.request_header().timestamp() = ua::DateTime::now();
    request.request_header().authentication_token() = impl->authentication_token();
    if constexpr (is_auditable_session_service_request<RequestT>)
    {
      if (request.request_header().audit_entry_id().empty())
      {
        request.request_header().audit_entry_id() = impl->next_audit_entry_id();
      }
    }
    request.request_header().return_diagnostics() =
      impl->return_diagnostics_for(request.request_header().return_diagnostics());
    auto erased = std::make_shared<RequestT>(std::move(request));

    impl->send_request(
      std::move(erased),
      [impl, callback = std::move(callback)](SRR response) mutable
      {
        if (!response)
        {
          if (!impl->wrap_tier0())
          {
            callback(ResultT{response.status_code()});
            return;
          }
          const ua::StatusCode cause = response.status_code();
          auto detail = ua::ErrorDetail::build(
            "Tier0ServiceFailure", "A tier-0 Session service call failed", "client.tier0.session.service");
          detail.cause(cause);
          std::shared_ptr<const ua::ErrorDetail> outer = std::move(detail);
          callback(ResultT{ua::StatusCode{cause.as_uint32(), std::move(outer)}});
          return;
        }
        auto* typed = dynamic_cast<ResponseT*>(response.value().get());
        if (!typed)
        {
          callback(ResultT{ua::Status::BadDecodingError});
          return;
        }
        callback(ResultT{std::move(*typed)});
      },
      timeoutMs);
  }
  catch (const ua::UaException& exception)
  {
    callback(ResultT{exception.status_code(), exception.take_detail()});
  }
  catch (const std::exception&)
  {
    callback(ResultT{ua::Status::BadInternalError,
      std::shared_ptr<const ua::ErrorDetail>{ua::make_error_detail("RequestHeaderProviderException",
        "A RequestHeader provider threw an exception",
        "client.session.typed_request")}});
  }
  catch (...)
  {
    callback(ResultT{ua::Status::BadInternalError,
      std::shared_ptr<const ua::ErrorDetail>{ua::make_error_detail("RequestHeaderProviderException",
        "A RequestHeader provider threw a non-standard exception",
        "client.session.typed_request")}});
  }
}

template<typename ResponseT, typename RequestT>
ua::Result<ResponseT> typed_request_try_sync(std::shared_ptr<SessionImpl> impl, RequestT request) noexcept
{
  using ResultT = ua::Result<ResponseT>;
  // Refused with Bad_WouldBlock before anything is sent when called on the executor that would deliver
  // the response (public API review item D8).
  const auto executor = impl ? impl->executor() : boost::asio::any_io_executor{};
  return ua::async::detail::blocking_call<ResultT>(executor,
    [&impl, &request](std::function<void(ResultT)> complete)
    { typed_request_async<ResponseT>(impl, std::move(request), std::move(complete)); });
}

}  // namespace ua::client::detail

#endif  // !UA_SESSION_SERVICE_HELPERS_H
