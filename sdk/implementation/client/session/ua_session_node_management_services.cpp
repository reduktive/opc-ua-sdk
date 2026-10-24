// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_session_node_management_services.h"
#include "ua_session_service_helpers.h"

namespace ua::client
{

SessionNodeManagementServices::SessionNodeManagementServices(std::weak_ptr<SessionImpl> impl)
  : mImpl(std::move(impl))
{}

// --- AddNodes ---

void SessionNodeManagementServices::add_nodes_async(
  ua::AddNodesRequest request, AddNodesCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(AddNodesResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::AddNodesResponse>(std::move(impl), std::move(request), std::move(callback));
}

ua::AddNodesResponse SessionNodeManagementServices::add_nodes_sync(ua::AddNodesRequest request)
{
  return ua::detail::good_value(try_add_nodes_sync(std::move(request)));
}

SessionNodeManagementServices::AddNodesResponseResult SessionNodeManagementServices::try_add_nodes_sync(
  ua::AddNodesRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return AddNodesResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::AddNodesResponse>(std::move(impl), std::move(request));
}

// --- AddReferences ---

void SessionNodeManagementServices::add_references_async(
  ua::AddReferencesRequest request, AddReferencesCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(AddReferencesResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::AddReferencesResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::AddReferencesResponse SessionNodeManagementServices::add_references_sync(ua::AddReferencesRequest request)
{
  return ua::detail::good_value(try_add_references_sync(std::move(request)));
}

SessionNodeManagementServices::AddReferencesResponseResult
  SessionNodeManagementServices::try_add_references_sync(ua::AddReferencesRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return AddReferencesResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::AddReferencesResponse>(std::move(impl), std::move(request));
}

// --- DeleteNodes ---

void SessionNodeManagementServices::delete_nodes_async(
  ua::DeleteNodesRequest request, DeleteNodesCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(DeleteNodesResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::DeleteNodesResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::DeleteNodesResponse SessionNodeManagementServices::delete_nodes_sync(ua::DeleteNodesRequest request)
{
  return ua::detail::good_value(try_delete_nodes_sync(std::move(request)));
}

SessionNodeManagementServices::DeleteNodesResponseResult SessionNodeManagementServices::try_delete_nodes_sync(
  ua::DeleteNodesRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return DeleteNodesResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::DeleteNodesResponse>(std::move(impl), std::move(request));
}

// --- DeleteReferences ---

void SessionNodeManagementServices::delete_references_async(
  ua::DeleteReferencesRequest request, DeleteReferencesCallback callback) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
  {
    callback(DeleteReferencesResponseResult{ua::Status::BadSessionIdInvalid});
    return;
  }
  detail::typed_request_async<ua::DeleteReferencesResponse>(
    std::move(impl), std::move(request), std::move(callback));
}

ua::DeleteReferencesResponse SessionNodeManagementServices::delete_references_sync(
  ua::DeleteReferencesRequest request)
{
  return ua::detail::good_value(try_delete_references_sync(std::move(request)));
}

SessionNodeManagementServices::DeleteReferencesResponseResult
  SessionNodeManagementServices::try_delete_references_sync(ua::DeleteReferencesRequest request) noexcept
{
  auto impl = mImpl.lock();
  if (!impl)
    return DeleteReferencesResponseResult{ua::Status::BadSessionIdInvalid};
  return detail::typed_request_try_sync<ua::DeleteReferencesResponse>(std::move(impl), std::move(request));
}

}  // namespace ua::client
