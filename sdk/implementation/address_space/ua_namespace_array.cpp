// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_array.h"

#include "ua_address_space.h"
#include "ua_error_detail.h"

namespace ua
{

namespace uri_array_details
{

template<>
String get_uri(const shared_ptr<Namespace>& t)
{
  return t->uri();
}

}  // namespace uri_array_details

shared_ptr<Namespace> NamespaceArray::get_namespace(uint16_t index) const
{
  try
  {
    return mUriArray.get_element(index);
  }
  catch (const UaException&)
  {
    return {};
  }
}

shared_ptr<Namespace> NamespaceArray::get_namespace(string_view uri) const
{
  return mUriArray.get_element(uri);
}

uint16_t NamespaceArray::get_namespace_index(string_view uri) const
{
  return mUriArray.get_index(uri);
}

String NamespaceArray::get_namespace_uri(uint16_t index) const
{
  return mUriArray.get_uri(index);
}

Array<String> NamespaceArray::get_namespace_array() const
{
  return mUriArray.get_uri_array();
}

namespace namespace_array_utils
{

std::function<uint16_t(string_view)> get_index_lookup_function(AddressSpace addressSpace)
{
  return [addressSpace](string_view uri) mutable -> uint16_t
  {
    return addressSpace.namespace_array().get_namespace_index(uri);
  };
}

std::function<uint16_t(string_view)> get_index_lookup_function(WeakAddressSpace addressSpace)
{
  return [addressSpace](string_view uri) mutable -> uint16_t
  {
    auto as = addressSpace.lock();
    if (!as)
    {
      throw UaException{Status::BadInvalidState,
        ErrorDetail::build("NamespaceNotFound",
          "Address space has been destroyed; cannot look up namespace URI",
          "NamespaceArray")
          .context(ua::ContextKeys::namespaceUri, std::string(uri))};
    }
    return as->namespace_array().get_namespace_index(uri);
  };
}

}  // namespace namespace_array_utils

}  // namespace ua
