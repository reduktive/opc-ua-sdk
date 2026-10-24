// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_syntax_reference_entry.h"

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

struct SyntaxReferenceEntryTypeTraits
{
  static NodeId type_definition_id()
  {
    return NodeId{ObjectTypeId::SyntaxReferenceEntryType};
  }

  static QualifiedName common_name_browse_name()
  {
    return QualifiedName{0, "CommonName"};
  }
};

}  // namespace

SyntaxReferenceEntry::SyntaxReferenceEntry(
  AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned)
  : BaseObject(std::move(addressSpace), std::move(nodeId), std::move(owned))
{}

void SyntaxReferenceEntry::create_impl_async(AddressSpace addressSpace, NodeId parent,
  QualifiedName browseName, InstantiationOptions options, CreateCompleteCallback complete) noexcept
{
  create_object_impl_async(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    SyntaxReferenceEntryTypeTraits::type_definition_id(),
    std::move(options),
    [complete = std::move(complete)](BaseObject::CreateResult r) mutable
    {
      if (!r.has_value())
      {
        complete(SyntaxReferenceEntryResult{r.status_code(), r.shared_detail()});
        return;
      }
      const StatusCode code = r.status_code();
      auto data = std::move(r).value();
      complete(SyntaxReferenceEntryResult{
        SyntaxReferenceEntry{std::move(data.addressSpace), std::move(data.nodeId), std::move(data.subtree)},
        code});
    });
}

SyntaxReferenceEntryResult SyntaxReferenceEntry::try_create_sync(AddressSpace addressSpace,
  const NodeId& parent, const QualifiedName& browseName, const InstantiationOptions& options) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<SyntaxReferenceEntryResult>(addressSpace.executor(),
      [&](std::function<void(SyntaxReferenceEntryResult)> complete)
      {
        SyntaxReferenceEntry::create_async(
          std::move(addressSpace), parent, browseName, options, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

SyntaxReferenceEntry SyntaxReferenceEntry::create_sync(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options)
{
  return ::ua::detail::good_value(try_create_sync(std::move(addressSpace), parent, browseName, options));
}

void SyntaxReferenceEntry::create_async(AddressSpace addressSpace, const NodeId& parent,
  const QualifiedName& browseName, const InstantiationOptions& options,
  CreateCompleteCallback complete) noexcept
{
  create_impl_async(std::move(addressSpace),
    NodeId{parent},
    QualifiedName{browseName},
    InstantiationOptions{options},
    std::move(complete));
}

void SyntaxReferenceEntry::attach_impl_async(
  AddressSpace addressSpace, NodeId existingInstance, AttachCompleteCallback complete) noexcept
{
  // SyntaxReferenceEntryType is final - exact match.
  instance_utils::attach_exact_async(addressSpace,
    existingInstance,
    SyntaxReferenceEntryTypeTraits::type_definition_id(),
    [weakAddressSpace = addressSpace.weak(), existingInstance, complete = std::move(complete)](
      VoidResult st) mutable
    {
      if (!st.is_good())
      {
        complete(SyntaxReferenceEntryResult{st.status_code(), st.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(SyntaxReferenceEntryResult{::ua::detail::address_space_gone("SyntaxReferenceEntry")});
        return;
      }
      complete(
        SyntaxReferenceEntry{std::move(*lockedAddressSpace), std::move(existingInstance), std::nullopt});
    });
}

SyntaxReferenceEntryResult SyntaxReferenceEntry::try_attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance) noexcept
{
  try
  {
    return ua::async::detail::blocking_call<SyntaxReferenceEntryResult>(addressSpace.executor(),
      [&](std::function<void(SyntaxReferenceEntryResult)> complete)
      {
        SyntaxReferenceEntry::attach_async(std::move(addressSpace), existingInstance, std::move(complete));
      });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

SyntaxReferenceEntry SyntaxReferenceEntry::attach_sync(
  AddressSpace addressSpace, const NodeId& existingInstance)
{
  return ::ua::detail::good_value(try_attach_sync(std::move(addressSpace), existingInstance));
}

void SyntaxReferenceEntry::attach_async(
  AddressSpace addressSpace, const NodeId& existingInstance, AttachCompleteCallback complete) noexcept
{
  attach_impl_async(std::move(addressSpace), NodeId{existingInstance}, std::move(complete));
}

// --- Common property helper ---

void SyntaxReferenceEntry::find_property_async(
  QualifiedName browseName, std::function<void(PropertyResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::attach_child_async<Property>(*mAddressSpace,
    mNodeId,
    NodeId{ReferenceTypeId::HasProperty},
    std::move(browseName),
    "SyntaxReferenceEntry",
    std::move(complete));
}

// --- Property accessors ---

void SyntaxReferenceEntry::common_name_property_async(PropertyCompleteCallback complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(PropertyResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  find_property_async(SyntaxReferenceEntryTypeTraits::common_name_browse_name(), std::move(complete));
}

PropertyResult SyntaxReferenceEntry::try_common_name_property_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<PropertyResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(PropertyResult)> complete) { common_name_property_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

Property SyntaxReferenceEntry::common_name_property_sync() const
{
  return ::ua::detail::good_value(try_common_name_property_sync());
}

// --- Typed value read shortcuts ---

void SyntaxReferenceEntry::read_common_name_async(std::function<void(StringResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(StringResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::read_property_value_async<String>(*mAddressSpace,
    mNodeId,
    SyntaxReferenceEntryTypeTraits::common_name_browse_name(),
    &Variant::is_string,
    {"SyntaxReferenceEntry", "common_name", "SyntaxReferenceEntry::read_common_name_async"},
    std::move(complete));
}

StringResult SyntaxReferenceEntry::try_read_common_name_sync() const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<StringResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(StringResult)> complete) { read_common_name_async(std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

String SyntaxReferenceEntry::read_common_name_sync() const
{
  return ::ua::detail::good_value(try_read_common_name_sync());
}

// --- Typed value write shortcuts ---

void SyntaxReferenceEntry::write_common_name_async(
  String value, std::function<void(VoidResult)> complete) const noexcept
{
  if (!mAddressSpace)
  {
    complete(VoidResult{StatusCode{Status::BadInvalidState}});
    return;
  }
  instance_utils::detail::write_property_value_async(*mAddressSpace,
    mNodeId,
    SyntaxReferenceEntryTypeTraits::common_name_browse_name(),
    "SyntaxReferenceEntry",
    Variant{std::move(value)},
    std::move(complete));
}

VoidResult SyntaxReferenceEntry::try_write_common_name_sync(String value) const noexcept
{
  try
  {
    return ua::async::detail::blocking_call<VoidResult>(
      mAddressSpace ? mAddressSpace->executor() : boost::asio::any_io_executor{},
      [&](std::function<void(VoidResult)> complete) { write_common_name_async(value, std::move(complete)); });
  }
  catch (...)
  {
    return ::ua::exception_to_status_code(std::current_exception());
  }
}

void SyntaxReferenceEntry::write_common_name_sync(String value) const
{
  try_write_common_name_sync(value).value();
}

}  // namespace ua
