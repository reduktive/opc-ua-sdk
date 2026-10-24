// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_service_set.h"

#include "ua_sync_wait.h"
#include "ua_connection_impl.h"
#include "ua_status.h"

#include <utility>

namespace ua::client
{

namespace
{

/// The status a forwarding call completes with when the handle has been moved-from (null pimpl). A
/// programming error (using a moved-from handle), distinct from a runtime `Bad_ConnectionClosed`.
constexpr ua::Status emptyHandleStatus = ua::Status::BadInvalidState;

}  // namespace

ServiceSet::ServiceSet(std::shared_ptr<detail::ConnectionImpl> impl) : mImpl(std::move(impl))
{}

// Each *_async forwards straight to the matching ConnectionImpl wire-op funnel entry point (which applies
// the single tier-1 gate + NamespaceTable remap + ErrorDetail wrap exactly once). A moved-from handle
// (null mImpl) fast-fails on the caller's thread with Bad_InvalidState. Each *_sync / try_*_sync is the
// blocking_call over the *_async (see ua_sync_wait.h).

// --- Read ---

void ServiceSet::read_async(
  ua::ReadRequest request, std::function<void(ua::Result<ua::ReadResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::ReadResponse>{emptyHandleStatus});
    return;
  }
  mImpl->read_async(std::move(request), std::move(callback));
}

ua::ReadResponse ServiceSet::read_sync(ua::ReadRequest request)
{
  return ua::detail::good_value(try_read_sync(std::move(request)));
}

ua::Result<ua::ReadResponse> ServiceSet::try_read_sync(ua::ReadRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::ReadResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { read_async(std::move(request), std::move(completion)); });
}

// --- Write ---

void ServiceSet::write_async(
  ua::WriteRequest request, std::function<void(ua::Result<ua::WriteResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::WriteResponse>{emptyHandleStatus});
    return;
  }
  mImpl->write_async(std::move(request), std::move(callback));
}

ua::WriteResponse ServiceSet::write_sync(ua::WriteRequest request)
{
  return ua::detail::good_value(try_write_sync(std::move(request)));
}

ua::Result<ua::WriteResponse> ServiceSet::try_write_sync(ua::WriteRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::WriteResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { write_async(std::move(request), std::move(completion)); });
}

// --- Browse ---

void ServiceSet::browse_async(
  ua::BrowseRequest request, std::function<void(ua::Result<ua::BrowseResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::BrowseResponse>{emptyHandleStatus});
    return;
  }
  mImpl->browse_async(std::move(request), std::move(callback));
}

ua::BrowseResponse ServiceSet::browse_sync(ua::BrowseRequest request)
{
  return ua::detail::good_value(try_browse_sync(std::move(request)));
}

ua::Result<ua::BrowseResponse> ServiceSet::try_browse_sync(ua::BrowseRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::BrowseResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { browse_async(std::move(request), std::move(completion)); });
}

// --- BrowseNext ---

void ServiceSet::browse_next_async(
  ua::BrowseNextRequest request, std::function<void(ua::Result<ua::BrowseNextResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::BrowseNextResponse>{emptyHandleStatus});
    return;
  }
  mImpl->browse_next_async(std::move(request), std::move(callback));
}

ua::BrowseNextResponse ServiceSet::browse_next_sync(ua::BrowseNextRequest request)
{
  return ua::detail::good_value(try_browse_next_sync(std::move(request)));
}

ua::Result<ua::BrowseNextResponse> ServiceSet::try_browse_next_sync(ua::BrowseNextRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::BrowseNextResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { browse_next_async(std::move(request), std::move(completion)); });
}

// --- TranslateBrowsePathsToNodeIds ---

void ServiceSet::translate_browse_paths_async(ua::TranslateBrowsePathsToNodeIdsRequest request,
  std::function<void(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>{emptyHandleStatus});
    return;
  }
  mImpl->translate_browse_paths_async(std::move(request), std::move(callback));
}

ua::TranslateBrowsePathsToNodeIdsResponse ServiceSet::translate_browse_paths_sync(
  ua::TranslateBrowsePathsToNodeIdsRequest request)
{
  return ua::detail::good_value(try_translate_browse_paths_sync(std::move(request)));
}

ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse> ServiceSet::try_translate_browse_paths_sync(
  ua::TranslateBrowsePathsToNodeIdsRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { translate_browse_paths_async(std::move(request), std::move(completion)); });
}

// --- Call ---

void ServiceSet::call_async(
  ua::CallRequest request, std::function<void(ua::Result<ua::CallResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::CallResponse>{emptyHandleStatus});
    return;
  }
  mImpl->call_async(std::move(request), std::move(callback));
}

ua::CallResponse ServiceSet::call_sync(ua::CallRequest request)
{
  return ua::detail::good_value(try_call_sync(std::move(request)));
}

ua::Result<ua::CallResponse> ServiceSet::try_call_sync(ua::CallRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::CallResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { call_async(std::move(request), std::move(completion)); });
}

// --- RegisterNodes ---

void ServiceSet::register_nodes_async(ua::RegisterNodesRequest request,
  std::function<void(ua::Result<ua::RegisterNodesResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::RegisterNodesResponse>{emptyHandleStatus});
    return;
  }
  mImpl->register_nodes_async(std::move(request), std::move(callback));
}

ua::RegisterNodesResponse ServiceSet::register_nodes_sync(ua::RegisterNodesRequest request)
{
  return ua::detail::good_value(try_register_nodes_sync(std::move(request)));
}

ua::Result<ua::RegisterNodesResponse> ServiceSet::try_register_nodes_sync(
  ua::RegisterNodesRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::RegisterNodesResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { register_nodes_async(std::move(request), std::move(completion)); });
}

// --- UnregisterNodes ---

void ServiceSet::unregister_nodes_async(ua::UnregisterNodesRequest request,
  std::function<void(ua::Result<ua::UnregisterNodesResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::UnregisterNodesResponse>{emptyHandleStatus});
    return;
  }
  mImpl->unregister_nodes_async(std::move(request), std::move(callback));
}

ua::UnregisterNodesResponse ServiceSet::unregister_nodes_sync(ua::UnregisterNodesRequest request)
{
  return ua::detail::good_value(try_unregister_nodes_sync(std::move(request)));
}

ua::Result<ua::UnregisterNodesResponse> ServiceSet::try_unregister_nodes_sync(
  ua::UnregisterNodesRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::UnregisterNodesResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { unregister_nodes_async(std::move(request), std::move(completion)); });
}

// --- HistoryRead ---

void ServiceSet::history_read_async(
  ua::HistoryReadRequest request, std::function<void(ua::Result<ua::HistoryReadResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::HistoryReadResponse>{emptyHandleStatus});
    return;
  }
  mImpl->history_read_async(std::move(request), std::move(callback));
}

ua::HistoryReadResponse ServiceSet::history_read_sync(ua::HistoryReadRequest request)
{
  return ua::detail::good_value(try_history_read_sync(std::move(request)));
}

ua::Result<ua::HistoryReadResponse> ServiceSet::try_history_read_sync(ua::HistoryReadRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::HistoryReadResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { history_read_async(std::move(request), std::move(completion)); });
}

// --- HistoryUpdate ---

void ServiceSet::history_update_async(ua::HistoryUpdateRequest request,
  std::function<void(ua::Result<ua::HistoryUpdateResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::HistoryUpdateResponse>{emptyHandleStatus});
    return;
  }
  mImpl->history_update_async(std::move(request), std::move(callback));
}

ua::HistoryUpdateResponse ServiceSet::history_update_sync(ua::HistoryUpdateRequest request)
{
  return ua::detail::good_value(try_history_update_sync(std::move(request)));
}

ua::Result<ua::HistoryUpdateResponse> ServiceSet::try_history_update_sync(
  ua::HistoryUpdateRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::HistoryUpdateResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { history_update_async(std::move(request), std::move(completion)); });
}

// --- QueryFirst ---

void ServiceSet::query_first_async(
  ua::QueryFirstRequest request, std::function<void(ua::Result<ua::QueryFirstResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::QueryFirstResponse>{emptyHandleStatus});
    return;
  }
  mImpl->query_first_async(std::move(request), std::move(callback));
}

ua::QueryFirstResponse ServiceSet::query_first_sync(ua::QueryFirstRequest request)
{
  return ua::detail::good_value(try_query_first_sync(std::move(request)));
}

ua::Result<ua::QueryFirstResponse> ServiceSet::try_query_first_sync(ua::QueryFirstRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::QueryFirstResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { query_first_async(std::move(request), std::move(completion)); });
}

// --- QueryNext ---

void ServiceSet::query_next_async(
  ua::QueryNextRequest request, std::function<void(ua::Result<ua::QueryNextResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::QueryNextResponse>{emptyHandleStatus});
    return;
  }
  mImpl->query_next_async(std::move(request), std::move(callback));
}

ua::QueryNextResponse ServiceSet::query_next_sync(ua::QueryNextRequest request)
{
  return ua::detail::good_value(try_query_next_sync(std::move(request)));
}

ua::Result<ua::QueryNextResponse> ServiceSet::try_query_next_sync(ua::QueryNextRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::QueryNextResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { query_next_async(std::move(request), std::move(completion)); });
}

// --- AddNodes ---

void ServiceSet::add_nodes_async(
  ua::AddNodesRequest request, std::function<void(ua::Result<ua::AddNodesResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::AddNodesResponse>{emptyHandleStatus});
    return;
  }
  mImpl->add_nodes_async(std::move(request), std::move(callback));
}

ua::AddNodesResponse ServiceSet::add_nodes_sync(ua::AddNodesRequest request)
{
  return ua::detail::good_value(try_add_nodes_sync(std::move(request)));
}

ua::Result<ua::AddNodesResponse> ServiceSet::try_add_nodes_sync(ua::AddNodesRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::AddNodesResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { add_nodes_async(std::move(request), std::move(completion)); });
}

// --- AddReferences ---

void ServiceSet::add_references_async(ua::AddReferencesRequest request,
  std::function<void(ua::Result<ua::AddReferencesResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::AddReferencesResponse>{emptyHandleStatus});
    return;
  }
  mImpl->add_references_async(std::move(request), std::move(callback));
}

ua::AddReferencesResponse ServiceSet::add_references_sync(ua::AddReferencesRequest request)
{
  return ua::detail::good_value(try_add_references_sync(std::move(request)));
}

ua::Result<ua::AddReferencesResponse> ServiceSet::try_add_references_sync(
  ua::AddReferencesRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::AddReferencesResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { add_references_async(std::move(request), std::move(completion)); });
}

// --- DeleteNodes ---

void ServiceSet::delete_nodes_async(
  ua::DeleteNodesRequest request, std::function<void(ua::Result<ua::DeleteNodesResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::DeleteNodesResponse>{emptyHandleStatus});
    return;
  }
  mImpl->delete_nodes_async(std::move(request), std::move(callback));
}

ua::DeleteNodesResponse ServiceSet::delete_nodes_sync(ua::DeleteNodesRequest request)
{
  return ua::detail::good_value(try_delete_nodes_sync(std::move(request)));
}

ua::Result<ua::DeleteNodesResponse> ServiceSet::try_delete_nodes_sync(ua::DeleteNodesRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::DeleteNodesResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { delete_nodes_async(std::move(request), std::move(completion)); });
}

// --- DeleteReferences ---

void ServiceSet::delete_references_async(ua::DeleteReferencesRequest request,
  std::function<void(ua::Result<ua::DeleteReferencesResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::DeleteReferencesResponse>{emptyHandleStatus});
    return;
  }
  mImpl->delete_references_async(std::move(request), std::move(callback));
}

ua::DeleteReferencesResponse ServiceSet::delete_references_sync(ua::DeleteReferencesRequest request)
{
  return ua::detail::good_value(try_delete_references_sync(std::move(request)));
}

ua::Result<ua::DeleteReferencesResponse> ServiceSet::try_delete_references_sync(
  ua::DeleteReferencesRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::DeleteReferencesResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { delete_references_async(std::move(request), std::move(completion)); });
}

// --- Cancel ---

void ServiceSet::cancel_async(
  ua::CancelRequest request, std::function<void(ua::Result<ua::CancelResponse>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::CancelResponse>{emptyHandleStatus});
    return;
  }
  mImpl->cancel_async(std::move(request), std::move(callback));
}

ua::CancelResponse ServiceSet::cancel_sync(ua::CancelRequest request)
{
  return ua::detail::good_value(try_cancel_sync(std::move(request)));
}

ua::Result<ua::CancelResponse> ServiceSet::try_cancel_sync(ua::CancelRequest request) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::CancelResponse>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, request = std::move(request)](auto completion) mutable
    { cancel_async(std::move(request), std::move(completion)); });
}

}  // namespace ua::client
