// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_certificate_group_folder.h"

#include "ua_instance_utils.h"
#include "ua_sync_wait.h"
#include "ua_to_result.h"
#include "ua_weak_address_space.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <tuple>

#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"

namespace ua
{
namespace
{

struct CertificateGroupFolderTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::CertificateGroupFolderType};
  }

  static QualifiedName default_application_group_browse_name()
  {
    return QualifiedName{0, "DefaultApplicationGroup"};
  }

  static QualifiedName default_https_group_browse_name()
  {
    return QualifiedName{0, "DefaultHttpsGroup"};
  }

  static QualifiedName default_user_token_group_browse_name()
  {
    return QualifiedName{0, "DefaultUserTokenGroup"};
  }
};

}  // namespace

CertificateGroupFolder::CertificateGroupFolder(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void CertificateGroupFolder::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    CertificateGroupFolderTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(CertificateGroupFolderResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(CertificateGroupFolderResult{
        CertificateGroupFolder{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

CertificateGroupFolderResult CertificateGroupFolder::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CertificateGroupFolderResult>(addressSpace.executor(),
      [&](std::function<void(CertificateGroupFolderResult)> complete)
      {
        CertificateGroupFolder::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

CertificateGroupFolder CertificateGroupFolder::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void CertificateGroupFolder::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void CertificateGroupFolder::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // CertificateGroupFolderType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    CertificateGroupFolderTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(CertificateGroupFolderResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(CertificateGroupFolderResult{::ua::detail::address_space_gone("CertificateGroupFolder")});
        return;
      }
      complete(
        CertificateGroupFolder{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

CertificateGroupFolderResult CertificateGroupFolder::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CertificateGroupFolderResult>(addressSpace.executor(),
      [&](std::function<void(CertificateGroupFolderResult)> complete)
      {
        CertificateGroupFolder::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

CertificateGroupFolder CertificateGroupFolder::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void CertificateGroupFolder::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Child-object accessors ---

void CertificateGroupFolder::default_application_group_async(
  std::function<void(CertificateGroupResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(CertificateGroupResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<CertificateGroup>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    CertificateGroupFolderTypeTraits::default_application_group_browse_name(),
    "CertificateGroupFolder",
    std::move(complete));
}

CertificateGroupResult CertificateGroupFolder::try_default_application_group_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CertificateGroupResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(CertificateGroupResult)> complete)
      { default_application_group_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

CertificateGroup CertificateGroupFolder::default_application_group_sync() const
{
  return ::ua::detail::good_value(try_default_application_group_sync());
}

void CertificateGroupFolder::default_https_group_async(
  std::function<void(CertificateGroupResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(CertificateGroupResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<CertificateGroup>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    CertificateGroupFolderTypeTraits::default_https_group_browse_name(),
    "CertificateGroupFolder",
    std::move(complete));
}

CertificateGroupResult CertificateGroupFolder::try_default_https_group_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CertificateGroupResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(CertificateGroupResult)> complete)
      { default_https_group_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

CertificateGroup CertificateGroupFolder::default_https_group_sync() const
{
  return ::ua::detail::good_value(try_default_https_group_sync());
}

void CertificateGroupFolder::default_user_token_group_async(
  std::function<void(CertificateGroupResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(CertificateGroupResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<CertificateGroup>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasComponent},
    CertificateGroupFolderTypeTraits::default_user_token_group_browse_name(),
    "CertificateGroupFolder",
    std::move(complete));
}

CertificateGroupResult CertificateGroupFolder::try_default_user_token_group_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<CertificateGroupResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(CertificateGroupResult)> complete)
      { default_user_token_group_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

CertificateGroup CertificateGroupFolder::default_user_token_group_sync() const
{
  return ::ua::detail::good_value(try_default_user_token_group_sync());
}

}  // namespace ua
