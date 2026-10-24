// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <new>
#include <exception>
#include "ua_error_detail_keys.h"
#include "ua_error_detail.h"
#include "ua_unknown_structure.h"

#include "ua_array.h"
#include "ua_binary_codec.h"
#include "ua_byte_string.h"
#include "ua_exceptions.h"
#include "ua_memory_stream.h"
#include "ua_ref_structure.h"
#include "ua_to_result.h"
#include "ua_variant.h"
#include "ua_xml_codec.h"

#include <algorithm>
#include <vector>

namespace ua
{

namespace
{

// Re-decodes a preserved binary body (the structure's field content) into `instance`.
void reify_binary(Structure& instance, const ByteString& body, const StructureResolver& resolver,
  const EncodingLimits& limits, const CodecNamespaceContext& ns)
{
  memory_stream_device::Dynamic device;
  MemoryStream stream{device};
  stream.write_all(std::as_bytes(span<const uint8_t>{body}));
  stream.seek_from_start(0);

  UaBinaryDecoder decoder{resolver, stream, limits, ns};
  decoder.decode(limits.stack_depth(), instance);
}

// Re-decodes a preserved XML body (the whole <Body> subtree) into `instance`.
void reify_xml(Structure& instance, const ByteString& body, const StructureResolver& resolver,
  const CodecNamespaceContext& ns, const EncodingLimits& limits)
{
  std::vector<char> writable(body.size() + 1);
  std::copy(body.begin(), body.end(), writable.begin());
  writable[body.size()] = '\0';

  // Three XML levels per ExtensionObject nesting level (TypeId / Body / the type element) plus the
  // envelope, so the decoder's own depth limit is what bounds the document.
  auto context = xml::parse(writable.data(), 3 * limits.execution.decodeRecursionDepthLimit + 8);
  auto bodyElement = context.xml_element().get_first_child();  // <Body>
  if (!bodyElement)
  {
    return;
  }
  auto payload = bodyElement->get_first_child();  // the type element, e.g. <Argument>
  if (!payload)
  {
    return;
  }

  XmlDecoder decoder{resolver, *payload, limits, ns};
  decoder.decode(limits.stack_depth(), instance.type_name(), false, instance);
}

}  // namespace

Result<unique_ptr<Structure>> decode_unknown(const UnknownStructure& opaque,
  const StructureResolver& resolver, const EncodingLimits& limits, const CodecNamespaceContext& ns)
{
  // Without a resolver, or when the resolver still does not know the encoding id, the value remains
  // opaque - return an unchanged clone.
  if (!resolver)
  {
    return opaque.clone();
  }
  auto instance = resolver(opaque.encoding_id());
  if (!instance)
  {
    return opaque.clone();
  }

  const ByteString& body = opaque.encoded_data();
  if (body.empty())
  {
    // Resolved but empty body - a default-constructed instance is the faithful result.
    return instance;
  }

  try
  {
    if (opaque.body_encoding() == UnknownStructure::BodyEncoding::Binary)
    {
      reify_binary(*instance, body, resolver, limits, ns);
    }
    else
    {
      reify_xml(*instance, body, resolver, ns, limits);
    }
  }
  catch (...)
  {
    // A decoder refusal keeps its own status and an allocation failure is Bad_OutOfMemory. The XML parser
    // reports a malformed body with its own exception type, which converts to Bad_InternalError; Part 6
    // section 5.2.2.8 has the decoder report Bad_DecodingError and leave the value opaque rather than
    // abort the stream, with the parser's reason as its cause.
    const StatusCode caught = exception_to_status_code(std::current_exception());
    if (caught.as_status() != Status::BadInternalError)
    {
      return Result<unique_ptr<Structure>>{caught};
    }
    return Result<unique_ptr<Structure>>{StatusCode{Status::BadDecodingError,
      ErrorDetail::build("ExtensionObjectBodyDecodeFailed",
        "The ExtensionObject body could not be decoded into its resolved type",
        "StructureReify")
        .cause(caught)}};
  }

  return instance;
}

void decode_unknowns_in_place(Variant& value, const StructureResolver& resolver, const EncodingLimits& limits,
  const CodecNamespaceContext& ns)
{
  if (!resolver)
  {
    return;
  }

  const auto reifyIfOpaque = [&](Structure& candidate) -> unique_ptr<Structure>
  {
    const auto* opaque = dynamic_cast<const UnknownStructure*>(&candidate);
    if (opaque == nullptr)
    {
      return nullptr;
    }
    auto result = decode_unknown(*opaque, resolver, limits, ns);
    if (!result.is_good())
    {
      return nullptr;
    }
    // Only adopt the result if it actually resolved to a concrete type; a still-opaque result means
    // the type is not yet known, so leave the original in place (keeps this idempotent).
    if (dynamic_cast<const UnknownStructure*>(result.value().get()) != nullptr)
    {
      return nullptr;
    }
    return std::move(result.value());
  };

  if (value.is_structure())
  {
    if (auto reified = reifyIfOpaque(value.as<Structure>()))
    {
      value = std::move(reified);
    }
  }
  else if (value.is_array_of_structure())
  {
    auto& array = value.as<Array<RefStructure<Structure>>>();
    for (auto& reference : array.payload())
    {
      if (auto reified = reifyIfOpaque(*reference))
      {
        reference = std::move(reified);
      }
    }
  }
}

}  // namespace ua
