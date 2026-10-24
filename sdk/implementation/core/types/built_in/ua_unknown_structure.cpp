// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_unknown_structure.h"
#include "ua_error_detail.h"
#include "ua_to_string.h"

namespace ua
{

UnknownStructure::UnknownStructure(const NodeId& encodingId) : mEncodingId(encodingId)
{}

UnknownStructure::UnknownStructure(NodeId encodingId, BodyEncoding bodyEncoding, ByteString body)
  : mEncodingId(std::move(encodingId)), mBodyEncoding(bodyEncoding), mBody(std::move(body))
{}

bool UnknownStructure::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  UA_UNUSED(ns);
  UA_UNUSED(dataTypeId);
  // The DataType id is unknown, so an unknown structure can never positively match a queried type.
  return false;
}

NodeId UnknownStructure::type_id(const CodecNamespaceContext& ns) const
{
  UA_UNUSED(ns);
  throw UaException(Status::BadNotSupported,
    ErrorDetail::build("UnknownStructureError",
      "type_id(ns) not supported on UnknownStructure - only the encoding id is known",
      "UnknownStructure")
      .context(ua::ContextKeys::nodeId, ua::to_string(mEncodingId)));
}

ExpandedNodeId UnknownStructure::type_id() const
{
  throw UaException(Status::BadNotSupported,
    ErrorDetail::build("UnknownStructureError",
      "type_id() not supported on UnknownStructure - only the encoding id is known",
      "UnknownStructure")
      .context(ua::ContextKeys::nodeId, ua::to_string(mEncodingId)));
}

String UnknownStructure::type_name() const
{
  return "Unknown";
}

void UnknownStructure::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{
  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
  // Made functional in the codec framing phase (P2): writes mEncodingId.
  throw UaException(Status::BadNotSupported,
    ErrorDetail::build(
      "UnknownStructureError", "encode_id() not yet supported on UnknownStructure", "UnknownStructure")
      .context(ua::ContextKeys::nodeId, ua::to_string(mEncodingId)));
}

void UnknownStructure::encode(StackDepth limit, Encoder& encoder) const
{
  UA_UNUSED(limit);
  UA_UNUSED(encoder);
  // Made functional in the codec framing phase (P2): writes the preserved body.
  throw UaException(Status::BadNotSupported,
    make_error_detail(
      "DecodingFailed", "encode() not yet supported on UnknownStructure", "UnknownStructure"));
}

void UnknownStructure::decode(StackDepth limit, Decoder& decoder)
{
  UA_UNUSED(limit);
  UA_UNUSED(decoder);
  // Never invoked by the decode framing - the framing constructs an UnknownStructure fully populated
  // from the raw body. Direct decode into an UnknownStructure is a programming error.
  throw UaException(Status::BadNotSupported,
    ErrorDetail::build("DecodingFailed", "decode() not supported on UnknownStructure", "UnknownStructure")
      .context(ua::ContextKeys::nodeId, ua::to_string(mEncodingId)));
}

unique_ptr<Structure> UnknownStructure::clone() const
{
  return make_unique<UnknownStructure>(*this);
}

std::string UnknownStructure::to_string(int indent) const
{
  const string_view encodingName = (mBodyEncoding == BodyEncoding::Xml) ? "Xml" : "Binary";

  std::string body = "UnknownStructure{encodingId=";
  body += mEncodingId.as_definition();
  body += ", bodyEncoding=";
  body += encodingName;
  body += ", bodySize=";
  body += std::to_string(mBody.size());
  body += "}";

  if (indent > 0)
  {
    return std::string(numeric_cast<size_t>(indent), ' ') + body;
  }
  return body;
}

const NodeId& UnknownStructure::encoding_id() const
{
  return mEncodingId;
}

UnknownStructure::BodyEncoding UnknownStructure::body_encoding() const
{
  return mBodyEncoding;
}

const ByteString& UnknownStructure::encoded_data() const
{
  return mBody;
}

}  // namespace ua
