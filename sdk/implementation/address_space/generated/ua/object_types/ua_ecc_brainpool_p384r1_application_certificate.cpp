// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_ecc_brainpool_p384r1_application_certificate.h"

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

struct EccBrainpoolP384r1ApplicationCertificateTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::EccBrainpoolP384r1ApplicationCertificateType};
  }
};

}  // namespace

EccBrainpoolP384r1ApplicationCertificate::EccBrainpoolP384r1ApplicationCertificate(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void EccBrainpoolP384r1ApplicationCertificate::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    EccBrainpoolP384r1ApplicationCertificateTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(EccBrainpoolP384r1ApplicationCertificateResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(EccBrainpoolP384r1ApplicationCertificateResult{
        EccBrainpoolP384r1ApplicationCertificate{
          std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

EccBrainpoolP384r1ApplicationCertificateResult EccBrainpoolP384r1ApplicationCertificate::try_create_sync(
  AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<EccBrainpoolP384r1ApplicationCertificateResult>(
      addressSpace.executor(),
      [&](std::function<void(EccBrainpoolP384r1ApplicationCertificateResult)> complete)
      {
        EccBrainpoolP384r1ApplicationCertificate::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

EccBrainpoolP384r1ApplicationCertificate EccBrainpoolP384r1ApplicationCertificate::create_sync(
  AddressSpace addressSpace, const NodeId& parent, const QualifiedName& browseName,
  const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void EccBrainpoolP384r1ApplicationCertificate::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void EccBrainpoolP384r1ApplicationCertificate::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // EccBrainpoolP384r1ApplicationCertificateType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    EccBrainpoolP384r1ApplicationCertificateTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(EccBrainpoolP384r1ApplicationCertificateResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(EccBrainpoolP384r1ApplicationCertificateResult{
          ::ua::detail::address_space_gone("EccBrainpoolP384r1ApplicationCertificate")});
        return;
      }
      complete(EccBrainpoolP384r1ApplicationCertificate{
        std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

EccBrainpoolP384r1ApplicationCertificateResult EccBrainpoolP384r1ApplicationCertificate::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<EccBrainpoolP384r1ApplicationCertificateResult>(
      addressSpace.executor(),
      [&](std::function<void(EccBrainpoolP384r1ApplicationCertificateResult)> complete)
      {
        EccBrainpoolP384r1ApplicationCertificate::attach_async(
          std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

EccBrainpoolP384r1ApplicationCertificate EccBrainpoolP384r1ApplicationCertificate::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void EccBrainpoolP384r1ApplicationCertificate::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

}  // namespace ua
