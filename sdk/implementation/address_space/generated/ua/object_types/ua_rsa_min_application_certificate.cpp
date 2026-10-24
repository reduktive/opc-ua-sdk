// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_rsa_min_application_certificate.h"

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

struct RsaMinApplicationCertificateTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::RsaMinApplicationCertificateType};
  }
};

}  // namespace

RsaMinApplicationCertificate::RsaMinApplicationCertificate(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void RsaMinApplicationCertificate::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    RsaMinApplicationCertificateTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(RsaMinApplicationCertificateResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(RsaMinApplicationCertificateResult{
        RsaMinApplicationCertificate{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

RsaMinApplicationCertificateResult RsaMinApplicationCertificate::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<RsaMinApplicationCertificateResult>(addressSpace.executor(),
      [&](std::function<void(RsaMinApplicationCertificateResult)> complete)
      {
        RsaMinApplicationCertificate::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

RsaMinApplicationCertificate RsaMinApplicationCertificate::create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void RsaMinApplicationCertificate::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void RsaMinApplicationCertificate::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // RsaMinApplicationCertificateType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    RsaMinApplicationCertificateTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(RsaMinApplicationCertificateResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(RsaMinApplicationCertificateResult{
          ::ua::detail::address_space_gone("RsaMinApplicationCertificate")});
        return;
      }
      complete(RsaMinApplicationCertificate{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

RsaMinApplicationCertificateResult RsaMinApplicationCertificate::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<RsaMinApplicationCertificateResult>(addressSpace.executor(),
      [&](std::function<void(RsaMinApplicationCertificateResult)> complete)
      {
        RsaMinApplicationCertificate::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

RsaMinApplicationCertificate RsaMinApplicationCertificate::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void RsaMinApplicationCertificate::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

}  // namespace ua
