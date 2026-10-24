// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_BINARY_CODEC_H
#define UA_BINARY_CODEC_H

#include "ua_codec.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_stream.h"
#include "ua_array_base.h"
#include "ua_ref_structure.h"
#include "ua_array.h"
#include "ua_node_id.h"
#include "ua_unknown_structure.h"
#include "ua_structure_factory.h"
#include "ua_structure.h"
#include "fmt/format.h"

#include <algorithm>
#include <type_traits>

namespace ua
{

class UaBinaryEncoder
{
public:
  UaBinaryEncoder(const CodecNamespaceContext& namespaceConfig, Stream& stream);

  Stream& stream();

  void encode(StackDepth limit, bool element);

  void encode(StackDepth limit, uint8_t element);

  void encode(StackDepth limit, int8_t element);

  void encode(StackDepth limit, uint16_t element);

  void encode(StackDepth limit, int16_t element);

  void encode(StackDepth limit, uint32_t element);

  void encode(StackDepth limit, int32_t element);

  void encode(StackDepth limit, uint64_t element);

  void encode(StackDepth limit, int64_t element);

  void encode(StackDepth limit, float element);

  void encode(StackDepth limit, double element);

  void encode(StackDepth limit, string_view element);

  void encode(StackDepth limit, const DateTime& element);

  void encode(StackDepth limit, const Guid& element);

  void encode(StackDepth limit, const ByteString& element);

  void encode(StackDepth limit, const NodeId& element);

  void encode(StackDepth limit, const ExpandedNodeId& element);

  void encode(StackDepth limit, const StatusCode& element);

  void encode(StackDepth limit, const QualifiedName& element);

  void encode(StackDepth limit, const LocalizedText& element);

  void encode(StackDepth limit, const Decimal& element);

  void encode(StackDepth limit, const DataValue& element);

  void encode(StackDepth limit, const DiagnosticInfo& element);

  void encode(StackDepth limit, const Structure& element);

  void encode(StackDepth limit, const Structure* element);

  void encode(StackDepth limit, const Variant& element);

  template<typename T>
  void encode(StackDepth limit, const Array<T>& element, bool encodeAsOneDimensional = true);

  template<typename T>
    requires IsEnum<T>
  void encode(StackDepth limit, const Array<T>& element, bool encodeAsOneDimensional = true);

  template<typename T>
  void encode(StackDepth limit, const Array<RefStructure<T>>& element, bool encodeAsOneDimensional = true);

private:
  CodecNamespaceContext mNamespaceConfig;
  Stream& mStream;

  void encode_number(auto value);

  void encode_node_id(StackDepth limit, const NodeId& nodeId, string_view namespaceUri, uint32_t serverIndex);

  void encode_byte_string(span<const byte> element);

  void encode(StackDepth limit, const ArrayBase& element, bool encodeAsOneDimensional);
};

template<typename T>
void UaBinaryEncoder::encode(
  StackDepth limit, const Array<T>& element, bool encodeAsOneDimensional /*= true*/)
{
  encode(limit, static_cast<const ArrayBase&>(element), encodeAsOneDimensional);

  for (const auto& item : element.payload())
  {
    encode(limit, item);
  }
}

template<typename T>
  requires IsEnum<T>
void UaBinaryEncoder::encode(
  StackDepth limit, const Array<T>& element, bool encodeAsOneDimensional /*= true*/)
{
  encode(limit, static_cast<const ArrayBase&>(element), encodeAsOneDimensional);

  for (const auto& item : element.payload())
  {
    encode(limit, utils::to_underlying(item));
  }
}

template<typename T>
void UaBinaryEncoder::encode(
  StackDepth limit, const Array<RefStructure<T>>& element, bool encodeAsOneDimensional /*= true*/)
{
  encode(limit, static_cast<const ArrayBase&>(element), encodeAsOneDimensional);

  for (const auto& item : element.payload())
  {
    encode(limit, item.get());
  }
}

class StructureFactory;

class UaBinaryDecoder
{
public:
  UaBinaryDecoder(StructureResolver structureResolver, Stream& stream, const EncodingLimits& encodingLimits,
    CodecNamespaceContext namespaceConfig = {});
  UaBinaryDecoder(const UaBinaryDecoder& other) = delete;
  UaBinaryDecoder(UaBinaryDecoder&& other) noexcept = delete;
  UaBinaryDecoder& operator=(const UaBinaryDecoder& other) = delete;
  UaBinaryDecoder& operator=(UaBinaryDecoder&& other) noexcept = delete;
  ~UaBinaryDecoder() = default;

  const Stream& stream() const;

  void decode(StackDepth limit, bool& element);

  void decode(StackDepth limit, uint8_t& element);

  void decode(StackDepth limit, int8_t& element);

  void decode(StackDepth limit, uint16_t& element);

  void decode(StackDepth limit, int16_t& element);

  void decode(StackDepth limit, uint32_t& element);

  void decode(StackDepth limit, int32_t& element);

  void decode(StackDepth limit, uint64_t& element);

  void decode(StackDepth limit, int64_t& element);

  void decode(StackDepth limit, float& element);

  void decode(StackDepth limit, double& element);

  void decode(StackDepth limit, String& element);

  void decode(StackDepth limit, std::string& element);

  void decode(StackDepth limit, DateTime& element);

  void decode(StackDepth limit, XmlElement& element);

  void decode(StackDepth limit, Guid& element) const;

  void decode(StackDepth limit, ByteString& element);

  void decode(StackDepth limit, NodeId& element);

  void decode(StackDepth limit, ExpandedNodeId& element);

  void decode(StackDepth limit, StatusCode& element);

  void decode(StackDepth limit, QualifiedName& element);

  void decode(StackDepth limit, LocalizedText& element);

  void decode(StackDepth limit, DataValue& element);

  void decode(StackDepth limit, DiagnosticInfo& element);

  void decode(StackDepth limit, Decimal& element);

  void decode(StackDepth limit, Variant& element);

  void decode(StackDepth limit, Structure& element);

  template<typename T>
    requires IsStructure<T>
  void decode(StackDepth limit, unique_ptr<T>& element);

  template<typename T>
  void decode(StackDepth limit, Array<T>& element);

  template<typename T>
    requires IsEnum<T>
  void decode(StackDepth limit, Array<T>& element);

  template<typename T>
  void decode(StackDepth limit, Array<RefStructure<T>>& element);

  template<typename T>
  void decode_matrix(StackDepth limit, Array<T>& element);

  /// The configured maximum array length (@ref EncodingLimits::maxArrayLength).
  ///
  /// Exposed so manual length-prefixed decode paths (e.g. the dynamic-structure field codec, which
  /// hand-rolls its array loop rather than going through `decode(Array<T>&)`) can enforce the SAME
  /// allocation cap before resizing to an attacker-supplied element count. Without it, those paths
  /// would pre-allocate up to INT32_MAX elements from a few wire bytes (unbounded-allocation DoS).
  [[nodiscard]] size_t max_array_length() const
  {
    return mEncodingLimits.maxArrayLength;
  }

  /// Refuses a declared length the rest of the message cannot hold, before anything is allocated for it.
  ///
  /// Every encoded value takes at least one byte, so an array of @p count elements needs at least
  /// @p count bytes (and a String or ByteString of @p count bytes exactly that many). Without this check
  /// a length prefix is trusted up to the configured maximum and the storage is allocated and constructed
  /// before the first element is read: a Variant holding an Array of 65535 Variants, each the first of
  /// another such array, allocates megabytes per nesting level from a few bytes on the wire.
  ///
  /// @param count The number of bytes the declared value needs at least.
  /// @throws UaException Bad_DecodingError when fewer than @p count bytes remain in the stream.
  void require_remaining_bytes(size_t count) const;

  /// Elements an aggregate array reserves before decoding its first one. An array whose elements can
  /// nest further arrays constructs each element only when it decodes it, so trailing bytes cannot
  /// justify allocations at every ancestor; reserving this many keeps the common small array to one
  /// allocation while bounding what one nesting level reserves ahead of its decoded elements.
  static constexpr size_t aggregateArrayReserve{64};

private:
  CodecNamespaceContext mNamespaceConfig;
  const Stream& mStream;
  StructureResolver mStructureResolver;
  const EncodingLimits mEncodingLimits;

  /// Reads exactly `destination.size()` bytes; a short read is reported as Bad_DecodingError.
  void read_exact(span<byte> destination) const;

  void decode_number(auto& value);

  // Reads `length` raw ExtensionObject body bytes (length already validated > 0) into a ByteString,
  // enforcing the ByteString length limit. Used to preserve an unresolved body verbatim.
  ByteString read_extension_object_body(int32_t length);

  void decode_array_variant(StackDepth limit, BuiltInTypeId typeId, bool hasDims, Variant& element);

  void decode_scalar_variant(StackDepth limit, BuiltInTypeId typeId, Variant& element);

  template<typename T>
  void decode_scalar_variant_value(StackDepth limit, Variant& result);

  template<typename T>
  void decode_array_variant_value(StackDepth limit, Variant& result);

  void decode_node_id(StackDepth limit, NodeId& nodeId, String& namespaceUri, uint32_t& serverIndex);

  void decode_dimensions(StackDepth limit, Dimensions& dimensions);
};

template<typename T>
  requires IsStructure<T>
void UaBinaryDecoder::decode(StackDepth limit, unique_ptr<T>& element)
{
  NodeId encodingId;
  decode(limit, encodingId);

  uint8_t encoding{0};
  decode(limit, encoding);

  if (encoding == 0)
  {
    // An empty extension object
    return;
  }

  int32_t length{0};
  decode(limit, length);
  if (length <= 0)
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("DecodingFailed", "Extension object body length is invalid", "BinaryCodec")
        .context(ua::ContextKeys::length, std::to_string(length)));
  }

  if (encoding == 2)
  {
    // An XML-encoded body. We cannot decode it into a binary-codec structure, but when the target is
    // the base Structure we preserve it verbatim (tagged Xml) so it round-trips and can be reified
    // later; for a statically-typed field we cannot represent it, so skip.
    if constexpr (std::is_same_v<T, Structure>)
    {
      element = make_unique<UnknownStructure>(
        encodingId, UnknownStructure::BodyEncoding::Xml, read_extension_object_body(length));
    }
    else
    {
      mStream.seek(length);
    }
    return;
  }

  if (encoding != 1)
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("InvalidEncoding", "Extension object encoding byte is invalid", "BinaryCodec")
        .context(ua::ContextKeys::actual, std::to_string(encoding))
        .context(ua::ContextKeys::expected, "1"));
  }

  unique_ptr<Structure> structure = mStructureResolver ? mStructureResolver(encodingId) : nullptr;
  if (!structure)
  {
    // Unresolved type. Preserve the raw body verbatim (tagged Binary) when the target is the base
    // Structure so it round-trips / can be reified once the type is known; otherwise skip.
    if constexpr (std::is_same_v<T, Structure>)
    {
      element = make_unique<UnknownStructure>(
        encodingId, UnknownStructure::BodyEncoding::Binary, read_extension_object_body(length));
    }
    else
    {
      mStream.seek(length);
    }
    return;
  }

  const size_t startPosition = mStream.get_position();
  // Charge the structural descent here as decode(StackDepth, Structure&) does: a typed field is the
  // same nesting lever (a structure whose field is an ExtensionObject holding a structure ...), and the
  // work budget alone bounds it at a depth far beyond the native stack.
  const auto depthGuard = limit.enter_recursion();
  Decoder decoder(*this);
  structure->decode(limit, decoder);

  const size_t endPosition = mStream.get_position();
  if (endPosition != startPosition + numeric_cast<size_t>(length))
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "DecodingFailed", "Decoded structure length does not match expected length", "BinaryCodec")
        .context(ua::ContextKeys::sizeActual, std::to_string(endPosition - startPosition))
        .context(ua::ContextKeys::sizeExpected, std::to_string(length)));
  }

  // dynamic_cast on a pointer never throws: a mismatch yields null, so check before releasing
  // ownership or the decoded object would leak and the field would silently become null.
  auto* typed = dynamic_cast<T*>(structure.get());
  if (typed == nullptr)
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "DecodingFailed", "Decoded structure type does not match expected type", "BinaryCodec")
        .context(ua::ContextKeys::nodeId, encodingId.as_definition()));
  }
  (void)structure.release();
  element.reset(typed);
}

template<typename T>
void UaBinaryDecoder::decode(StackDepth limit, Array<T>& element)
{
  int32_t length{0};
  decode(limit, length);

  if (length <= 0)
  {
    element.clear();
  }
  else
  {
    if (numeric_cast<size_t>(length) > mEncodingLimits.maxArrayLength)
    {
      throw UaException(Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("EncodingLimitExceeded", "Array length exceeds maximum", "BinaryCodec")
          .context(ua::ContextKeys::sizeActual, std::to_string(length))
          .context(ua::ContextKeys::sizeMax, std::to_string(mEncodingLimits.maxArrayLength)));
    }
    if constexpr (std::is_arithmetic_v<T>)
    {
      // A number cannot nest: its encoding is its size, so the bytes it needs are known up front.
      require_remaining_bytes(numeric_cast<size_t>(length) * sizeof(T));
      element.resize(numeric_cast<size_t>(length));
      for (auto& item : element.payload())
      {
        decode(limit, item);
      }
    }
    else
    {
      require_remaining_bytes(numeric_cast<size_t>(length));
      // A nested child can consume the remaining bytes. Construct each element only as it is decoded,
      // so the same trailing bytes cannot justify eager allocations at every ancestor.
      element.payload().clear();
      element.payload().reserve(std::min(numeric_cast<size_t>(length), aggregateArrayReserve));
      for (int32_t i = 0; i < length; ++i)
      {
        decode(limit, element.payload().emplace_back());
      }
    }
  }
}

template<typename T>
  requires IsEnum<T>
void UaBinaryDecoder::decode(StackDepth limit, Array<T>& element)
{
  int32_t length{0};
  decode(limit, length);

  if (length <= 0)
  {
    element.clear();
  }
  else
  {
    if (numeric_cast<size_t>(length) > mEncodingLimits.maxArrayLength)
    {
      throw UaException(Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("EncodingLimitExceeded", "Array length exceeds maximum", "BinaryCodec")
          .context(ua::ContextKeys::sizeActual, std::to_string(length))
          .context(ua::ContextKeys::sizeMax, std::to_string(mEncodingLimits.maxArrayLength)));
    }
    require_remaining_bytes(numeric_cast<size_t>(length));
    element.resize(numeric_cast<size_t>(length));
    for (auto& item : element.payload())
    {
      int32_t enumVal{};
      decode(limit, enumVal);
      item = utils::from_underlying<T>(enumVal);
    }
  }
}

template<>
void UaBinaryDecoder::decode(StackDepth limit, Array<bool>& element);

template<typename T>
void UaBinaryDecoder::decode(StackDepth limit, Array<RefStructure<T>>& element)
{
  int32_t length{0};
  decode(limit, length);

  if (length <= 0)
  {
    element.clear();
  }
  else
  {
    if (numeric_cast<size_t>(length) > mEncodingLimits.maxArrayLength)
    {
      throw UaException(Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("EncodingLimitExceeded", "Array length exceeds maximum", "BinaryCodec")
          .context(ua::ContextKeys::sizeActual, std::to_string(length))
          .context(ua::ContextKeys::sizeMax, std::to_string(mEncodingLimits.maxArrayLength)));
    }
    require_remaining_bytes(numeric_cast<size_t>(length));
    // A structure body can hold further arrays: construct each element only as it is decoded.
    element.payload().clear();
    element.payload().reserve(std::min(numeric_cast<size_t>(length), aggregateArrayReserve));
    for (int32_t i = 0; i < length; ++i)
    {
      decode(limit, element.payload().emplace_back().inner_unique_ptr());
    }
  }
}

// template<typename T>
// void UaBinaryDecoder::decode_matrix(StackDepth limit, Array<T>& element)
//{
//   encode(limit, static_cast<ArrayBase&>(element), encodeAsOneDimensional);
//
//   for (auto item : element.payload())
//   {
//     encode(item);
//   }
// }

}  // namespace ua

#endif  //! UA_BINARY_CODEC_H
