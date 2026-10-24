// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <bit>
#include <bitset>
#include <assert.h>
#include "ua_binary_codec.h"
#include "ua_error_detail.h"
#include "ua_utilities.h"
#include "ua_string.h"
#include "ua_byte_string.h"
#include "ua_xml_element.h"
#include "ua_variant.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_decimal.h"
#include "ua_diagnostic_info.h"
#include "ua_expanded_node_id.h"
#include "ua_guid.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_status_code.h"
#include "ua_structure.h"
#include "ua_array.h"
#include "fmt/format.h"

namespace ua
{

static_assert(
  std::numeric_limits<float>::is_iec559, "Platform does not support IEEE754 floating point representation");

static_assert(
  std::numeric_limits<double>::is_iec559, "Platform does not support IEEE754 floating point representation");

class NodeIdEncoding
{
public:
  enum
  {
    ValueTwoByte = 0x00,
    ValueFourByte = 0x01,
    ValueNumeric = 0x02,
    ValueString = 0x03,
    ValueGuid = 0x04,
    ValueByteString = 0x05,
    BitNamespaceUriFlag = 0x80,
    BitServerIndexFlag = 0x40
  };

  static const uint8_t valueMask{0x0F};
  static const uint8_t flagMask{0xF0};

  static bool is_two_byte(uint8_t value)
  {
    return ((value & valueMask) == 0);
  }

  static bool is_four_byte(uint8_t value)
  {
    return ((value & valueMask) == ValueFourByte);
  }

  static bool is_numeric(uint8_t value)
  {
    return ((value & valueMask) == ValueNumeric);
  }

  static bool is_string(uint8_t value)
  {
    return ((value & valueMask) == ValueString);
  }

  static bool is_guid(uint8_t value)
  {
    return ((value & valueMask) == ValueGuid);
  }

  static bool is_byte_string(uint8_t value)
  {
    return ((value & valueMask) == ValueByteString);
  }

  static bool has_namespace_uri(uint8_t value)
  {
    return ((value & flagMask) & BitNamespaceUriFlag);
  }

  static bool has_server_index(uint8_t value)
  {
    return ((value & flagMask) & BitServerIndexFlag);
  }
};

class LocalizedTextEncoding
{
public:
  using UnderlyingType = uint8_t;
  using BitSet = std::bitset<utils::no_of_bits<UnderlyingType>()>;

  enum class Bit : UnderlyingType
  {
    Locale = 0,
    Text = 1
  };

  LocalizedTextEncoding() = default;

  explicit LocalizedTextEncoding(UnderlyingType value) : mValue(value)
  {}

  void set(Bit bit)
  {
    mValue.set(utils::to_underlying(bit));
  }

  void reset(Bit bit)
  {
    mValue.reset(utils::to_underlying(bit));
  }

  bool test(Bit bit) const
  {
    return mValue.test(utils::to_underlying(bit));
  }

  UnderlyingType as_underlying_type() const
  {
    return numeric_cast<UnderlyingType>(mValue.to_ullong());
  }

  BitSet value() const
  {
    return mValue;
  }

private:
  BitSet mValue;
};

class DataValueEncoding
{
public:
  using UnderlyingType = uint8_t;
  using BitSet = std::bitset<utils::no_of_bits<UnderlyingType>()>;

  enum class Bit : UnderlyingType
  {
    Value = 0,
    StatusCode = 1,
    SourceTimestamp = 2,
    ServerTimestamp = 3,
    SourcePicoSeconds = 4,
    ServerPicoSeconds = 5
  };

  DataValueEncoding() = default;

  explicit DataValueEncoding(UnderlyingType value) : mValue(value)
  {}

  void set(Bit bit)
  {
    mValue.set(utils::to_underlying(bit));
  }

  void reset(Bit bit)
  {
    mValue.reset(utils::to_underlying(bit));
  }

  bool test(Bit bit) const
  {
    return mValue.test(utils::to_underlying(bit));
  }

  UnderlyingType as_underlying_type() const
  {
    return numeric_cast<UnderlyingType>(mValue.to_ullong());
  }

  BitSet value() const
  {
    return mValue;
  }

private:
  BitSet mValue;
};

class DiagnosticInfoEncoding
{
public:
  using UnderlyingType = uint8_t;
  using BitSet = std::bitset<utils::no_of_bits<UnderlyingType>()>;

  enum class Bit : UnderlyingType
  {
    SymbolicId = 0,
    Namespace = 1,
    LocalizedText = 2,
    Locale = 3,
    AdditionalInfo = 4,
    InnerStatusCode = 5,
    InnerDiagnosticInfo = 6
  };

  DiagnosticInfoEncoding() = default;

  explicit DiagnosticInfoEncoding(UnderlyingType value) : mValue(value)
  {}

  void set(Bit bit)
  {
    mValue.set(utils::to_underlying(bit));
  }

  void reset(Bit bit)
  {
    mValue.reset(utils::to_underlying(bit));
  }

  bool test(Bit bit) const
  {
    return mValue.test(utils::to_underlying(bit));
  }

  UnderlyingType as_underlying_type() const
  {
    return numeric_cast<UnderlyingType>(mValue.to_ullong());
  }

  BitSet value() const
  {
    return mValue;
  }

private:
  BitSet mValue;
};

class VariantEncoding
{
public:
  static const uint8_t typeMask = 0x3F;

  using UnderlyingType = uint8_t;
  using BitSet = std::bitset<utils::no_of_bits<UnderlyingType>()>;

  enum class Bit : UnderlyingType
  {
    ArrayDimensions = 6,
    ArrayOfValues = 7
  };

  VariantEncoding() = default;

  explicit VariantEncoding(UnderlyingType value) : mValue(value)
  {}

  void set(Bit bit)
  {
    mValue.set(utils::to_underlying(bit));
  }

  void reset(Bit bit)
  {
    mValue.reset(utils::to_underlying(bit));
  }

  bool test(Bit bit) const
  {
    return mValue.test(utils::to_underlying(bit));
  }

  UnderlyingType as_underlying_type() const
  {
    return numeric_cast<UnderlyingType>(mValue.to_ullong());
  }

  BitSet value() const
  {
    return mValue;
  }

private:
  BitSet mValue;
};

template<typename T>
static span<byte> as_bytes(T& value)
{
  return span<byte>(reinterpret_cast<byte*>(&value), sizeof(T));
}

UaBinaryEncoder::UaBinaryEncoder(const CodecNamespaceContext& namespaceConfig, Stream& stream)
  : mNamespaceConfig(namespaceConfig), mStream(stream)
{}

Stream& UaBinaryEncoder::stream()
{
  return mStream;
}

void UaBinaryEncoder::encode(StackDepth limit, bool element)
{
  limit.consume_edge();

  uint8_t value{0};
  if (element)
  {
    value = 1;
  }

  return encode_number(value);
}

void UaBinaryEncoder::encode(StackDepth limit, uint8_t element)
{
  limit.consume_edge();

  return encode_number(element);
}

void UaBinaryEncoder::encode(StackDepth limit, int8_t element)
{
  limit.consume_edge();

  return encode_number(element);
}

void UaBinaryEncoder::encode(StackDepth limit, uint16_t element)
{
  limit.consume_edge();

  return encode_number(element);
}

void UaBinaryEncoder::encode(StackDepth limit, int16_t element)
{
  limit.consume_edge();

  return encode_number(element);
}

void UaBinaryEncoder::encode(StackDepth limit, uint32_t element)
{
  limit.consume_edge();

  return encode_number(element);
}

void UaBinaryEncoder::encode(StackDepth limit, int32_t element)
{
  limit.consume_edge();

  return encode_number(element);
}

void UaBinaryEncoder::encode(StackDepth limit, uint64_t element)
{
  limit.consume_edge();

  return encode_number(element);
}

void UaBinaryEncoder::encode(StackDepth limit, int64_t element)
{
  limit.consume_edge();

  return encode_number(element);
}

void UaBinaryEncoder::encode(StackDepth limit, float element)
{
  limit.consume_edge();

  return encode_number(element);
}

void UaBinaryEncoder::encode(StackDepth limit, double element)
{
  limit.consume_edge();

  return encode_number(element);
}

void UaBinaryEncoder::encode(StackDepth limit, string_view element)
{
  limit.consume_edge();

  const span<const byte> bytes(reinterpret_cast<const byte*>(element.data()), element.size());
  return encode_byte_string(bytes);
}

void UaBinaryEncoder::encode(StackDepth limit, const DateTime& element)
{
  using namespace std::chrono;

  limit.consume_edge();

  int64_t encodedValue{0};
  auto platformValue = element.value();
  if (platformValue > DateTime::min())
  {
    if (platformValue >= DateTime::max())
    {
      encodedValue = std::numeric_limits<int64_t>::max();
    }
    else
    {
      encodedValue = (platformValue - DateTime::min()) / datetime::OneHundredNanoSeconds{1};
    }
  }

  return encode_number(encodedValue);
}

void UaBinaryEncoder::encode(StackDepth limit, const Guid& element)
{
  limit.consume_edge();

  auto bytes = element.as_ua_binary();
  mStream.write_all(bytes);
}

void UaBinaryEncoder::encode(StackDepth limit, const ByteString& element)
{
  limit.consume_edge();

  encode_byte_string(element);
}

void UaBinaryEncoder::encode(StackDepth limit, const NodeId& element)
{
  limit.consume_edge();

  NodeId value = element;
  if (mNamespaceConfig.translateNodeId)
  {
    mNamespaceConfig.translateNodeId(value);
  }

  const std::string namespaceUri;
  const uint32_t serverIndex{0};

  encode_node_id(limit, value, namespaceUri, serverIndex);
}

void UaBinaryEncoder::encode(StackDepth limit, const ExpandedNodeId& element)
{
  limit.consume_edge();

  ExpandedNodeId value = element;
  if (mNamespaceConfig.translateExpandedNodeId)
  {
    mNamespaceConfig.translateExpandedNodeId(value);
  }

  encode_node_id(limit, value.node_id(), value.namespace_uri(), value.server_index());
}

void UaBinaryEncoder::encode(StackDepth limit, const StatusCode& element)
{
  limit.consume_edge();

  return encode_number(element.as_uint32());
}

void UaBinaryEncoder::encode(StackDepth limit, const QualifiedName& element)
{
  QualifiedName value = element;
  if (mNamespaceConfig.translateQualifiedName)
  {
    mNamespaceConfig.translateQualifiedName(value);
  }

  encode(limit, value.namespace_index());
  encode(limit, value.name());
}

void UaBinaryEncoder::encode(StackDepth limit, const LocalizedText& element)
{
  LocalizedTextEncoding encodingMask;
  if (!element.locale().empty())
  {
    encodingMask.set(LocalizedTextEncoding::Bit::Locale);
  }
  if (!element.text().empty())
  {
    encodingMask.set(LocalizedTextEncoding::Bit::Text);
  }

  encode(limit, encodingMask.as_underlying_type());

  if (encodingMask.test(LocalizedTextEncoding::Bit::Locale))
  {
    encode(limit, element.locale());
  }
  if (encodingMask.test(LocalizedTextEncoding::Bit::Text))
  {
    encode(limit, element.text());
  }
}

void UaBinaryEncoder::encode(StackDepth limit, const DataValue& element)
{
  DataValueEncoding encodingMask;
  if (!element.value().empty())
  {
    encodingMask.set(DataValueEncoding::Bit::Value);
  }
  if (element.status())
  {
    encodingMask.set(DataValueEncoding::Bit::StatusCode);
  }
  if (element.source_timestamp())
  {
    encodingMask.set(DataValueEncoding::Bit::SourceTimestamp);
  }
  if (element.server_timestamp())
  {
    encodingMask.set(DataValueEncoding::Bit::ServerTimestamp);
  }
  if (element.source_pico_seconds())
  {
    encodingMask.set(DataValueEncoding::Bit::SourcePicoSeconds);
  }
  if (element.server_pico_seconds())
  {
    encodingMask.set(DataValueEncoding::Bit::ServerPicoSeconds);
  }

  encode(limit, encodingMask.as_underlying_type());

  if (!element.value().empty())
  {
    encode(limit, element.value());
  }
  if (const auto& status = element.status())
  {
    encode(limit, status.value());
  }
  if (const auto& sourceTimestamp = element.source_timestamp())
  {
    encode(limit, sourceTimestamp.value());
  }
  if (const auto& sourcePicoSeconds = element.source_pico_seconds())
  {
    encode(limit, sourcePicoSeconds.value());
  }
  if (const auto& serverTimestamp = element.server_timestamp())
  {
    encode(limit, serverTimestamp.value());
  }
  if (const auto& serverPicoSeconds = element.server_pico_seconds())
  {
    encode(limit, serverPicoSeconds.value());
  }
}

void UaBinaryEncoder::encode(StackDepth limit, const DiagnosticInfo& element)
{
  DiagnosticInfoEncoding encodingMask;
  if (element.symbolic_id())
  {
    encodingMask.set(DiagnosticInfoEncoding::Bit::SymbolicId);
  }
  if (element.namespace_uri())
  {
    encodingMask.set(DiagnosticInfoEncoding::Bit::Namespace);
  }
  if (element.localized_text())
  {
    encodingMask.set(DiagnosticInfoEncoding::Bit::LocalizedText);
  }
  if (element.locale())
  {
    encodingMask.set(DiagnosticInfoEncoding::Bit::Locale);
  }
  if (element.additional_info())
  {
    encodingMask.set(DiagnosticInfoEncoding::Bit::AdditionalInfo);
  }
  if (element.inner_status_code())
  {
    encodingMask.set(DiagnosticInfoEncoding::Bit::InnerStatusCode);
  }
  if (element.inner_diagnostic_info())
  {
    encodingMask.set(DiagnosticInfoEncoding::Bit::InnerDiagnosticInfo);
  }

  encode(limit, encodingMask.as_underlying_type());

  if (const auto& symbolicId = element.symbolic_id())
  {
    encode(limit, symbolicId.value());
  }
  if (const auto& namespaceUri = element.namespace_uri())
  {
    encode(limit, namespaceUri.value());
  }
  if (const auto& locale = element.locale())
  {
    encode(limit, locale.value());
  }
  if (const auto& localizedText = element.localized_text())
  {
    encode(limit, localizedText.value());
  }
  if (const auto& additionalInfo = element.additional_info())
  {
    encode(limit, string_view{additionalInfo.value()});
  }
  if (const auto& innerStatusCode = element.inner_status_code())
  {
    encode(limit, innerStatusCode.value());
  }
  if (element.inner_diagnostic_info())
  {
    encode(limit, *element.inner_diagnostic_info());
  }
}

void UaBinaryEncoder::encode(StackDepth limit, const Decimal& element)
{
  const NodeId typeId(ObjectId::DecimalDataType_Encoding_DefaultBinary);
  encode(limit, typeId);

  const uint8_t encoding{1};
  encode(limit, encoding);

  const size_t length = sizeof(element.scale()) + element.value().size();

  encode(limit, numeric_cast<int32_t>(length));

  encode(limit, element.scale());

  if (!element.value().empty())
  {
    mStream.write_all(element.value());
  }
}

void UaBinaryEncoder::encode(StackDepth limit, const Structure& element)
{
  Encoder encoder(*this);
  element.encode(limit, encoder);
}

void UaBinaryEncoder::encode(StackDepth limit, const Structure* element)
{
  if (!element)
  {
    encode(limit, NodeId());

    const uint8_t encoding{0};
    encode(limit, encoding);
  }
  else if (const auto* unknown = dynamic_cast<const UnknownStructure*>(element))
  {
    // Re-emit a preserved (unresolved) body verbatim. The encoding byte matches the codec the body
    // was captured from: a binary body stays binary (1); an XML body rides a binary ExtensionObject
    // as an XmlElement body (2). Either way the captured encoding id is the correct TypeId - we never
    // transcode (that would need the other codec's encoding id, which we do not hold).
    encode(limit, unknown->encoding_id());

    const ByteString& body = unknown->encoded_data();
    if (body.empty())
    {
      // Nothing to carry - emit as an empty ExtensionObject.
      const uint8_t encoding{0};
      encode(limit, encoding);
    }
    else
    {
      const uint8_t encoding =
        (unknown->body_encoding() == UnknownStructure::BodyEncoding::Xml) ? uint8_t{2} : uint8_t{1};
      encode(limit, encoding);

      const int32_t length = numeric_cast<int32_t>(body.size());
      encode(limit, length);
      mStream.write_all(std::as_bytes(span<const uint8_t>{body}));
    }
  }
  else
  {
    Encoder encoder(*this);
    element->encode_id(limit, mNamespaceConfig, encoder);

    const uint8_t encoding{1};
    encode(limit, encoding);

    const size_t lengthPosition = mStream.get_position();
    int32_t length{0};
    encode(limit, length);

    element->encode(limit, encoder);

    const size_t endPosition = mStream.get_position();
    assert(endPosition > lengthPosition);

    length = numeric_cast<int32_t>(endPosition - lengthPosition - sizeof(int32_t));
    mStream.seek_from_start(lengthPosition);
    encode(limit, length);
    mStream.seek_from_start(endPosition);
  }
}

void UaBinaryEncoder::encode_number(auto value)
{
  auto bytes = as_bytes(value);

  if constexpr (std::endian::native == std::endian::big)
  {
    std::reverse(bytes.begin(), bytes.end());
  }
  else
  {
    static_assert(std::endian::native == std::endian::little, "Endianness of platform unknown");
  }

  mStream.write_all(bytes);
}

void UaBinaryEncoder::encode_node_id(
  StackDepth limit, const NodeId& nodeId, string_view namespaceUri, uint32_t serverIndex)
{
  uint8_t encodingMask = 0;

  uint16_t namespaceIndex{0};
  if (namespaceUri.empty())
  {
    namespaceIndex = nodeId.namespace_index();
  }

  if (!namespaceUri.empty())
  {
    encodingMask |= NodeIdEncoding::BitNamespaceUriFlag;
  }
  if (serverIndex != 0)
  {
    encodingMask |= NodeIdEncoding::BitServerIndexFlag;
  }
  const IdType identifierType = nodeId.id_type();
  switch (identifierType)
  {
  case IdType::Numeric:
  {
    const uint32_t numericId = nodeId.identifier().get_numeric();
    bool nodeIdEncodingComplete = false;

    if (namespaceUri.empty())
    {
      if ((namespaceIndex == 0) && (numericId <= std::numeric_limits<uint8_t>::max()))
      {
        encode(limit, encodingMask);

        const uint8_t identifier = numeric_cast<uint8_t>(numericId);
        encode(limit, identifier);

        nodeIdEncodingComplete = true;
      }
      else if ((namespaceIndex <= std::numeric_limits<uint8_t>::max()) &&
               (numericId <= std::numeric_limits<uint16_t>::max()))
      {
        encodingMask |= NodeIdEncoding::ValueFourByte;

        encode(limit, encodingMask);

        const uint8_t nsi = numeric_cast<uint8_t>(namespaceIndex);
        encode(limit, nsi);

        const uint16_t identifier = numeric_cast<uint16_t>(numericId);
        encode(limit, identifier);

        nodeIdEncodingComplete = true;
      }
    }

    if (!nodeIdEncodingComplete)
    {
      encodingMask |= NodeIdEncoding::ValueNumeric;

      encode(limit, encodingMask);
      encode(limit, namespaceIndex);
      encode(limit, numericId);
    }
  }
  break;

  case IdType::String:
  {
    encodingMask |= NodeIdEncoding::ValueString;

    encode(limit, encodingMask);
    encode(limit, namespaceIndex);
    encode(limit, nodeId.identifier().get_string());
  }
  break;

  case IdType::Opaque:
  {
    encodingMask |= NodeIdEncoding::ValueByteString;

    encode(limit, encodingMask);
    encode(limit, namespaceIndex);
    encode(limit, nodeId.identifier().get_opaque());
  }
  break;

  case IdType::Guid:
  {
    encodingMask |= NodeIdEncoding::ValueGuid;

    encode(limit, encodingMask);
    encode(limit, namespaceIndex);
    encode(limit, nodeId.identifier().get_guid());
  }
  break;

  default:
    throw UaException(Status::BadEncodingError,
      make_error_detail("InvalidEncoding", "Unexpected NodeId identifier type", "BinaryCodec"));
  }

  if (!namespaceUri.empty())
  {
    encode(limit, namespaceUri);
  }

  if (serverIndex > 0)
  {
    encode(limit, serverIndex);
  }
}

void UaBinaryEncoder::encode(StackDepth limit, const Variant& element)
{
  VariantEncoding mask;

  // Bound to the engaged dimensions only when multi-dimensional encoding applies; this keeps the
  // later encode block provably non-null (the bound reference, not a re-fetched optional).
  const Dimensions* arrayDimensions{nullptr};

  if (element.empty())
  {
    const uint8_t encoding{0};
    encode(limit, encoding);
    return;
  }
  else if (element.is_array())
  {
    mask.set(VariantEncoding::Bit::ArrayOfValues);

    const auto& dimensions = element.get_array_base().dimensions();
    if (dimensions && (dimensions->size() > 1))
    {
      mask.set(VariantEncoding::Bit::ArrayDimensions);
      arrayDimensions = &dimensions.value();
    }
  }

  const uint8_t typeId = utils::to_underlying(element.get_built_in_type());
  if (typeId == utils::to_underlying(BuiltInTypeId::DiagnosticInfo))
  {
    throw UaException(Status::BadEncodingError,
      make_error_detail("UnsupportedEncoding", "Variant cannot contain DiagnosticInfo", "BinaryCodec"));
  }

  uint8_t encodingMask = mask.as_underlying_type();
  encodingMask |= typeId;
  encode(limit, encodingMask);

  element.encode(limit, *this);

  if (mask.test(VariantEncoding::Bit::ArrayDimensions))
  {
    const std::vector<int32_t>& dims = *arrayDimensions;
    encode(limit, numeric_cast<int32_t>(dims.size()));

    for (size_t i = 0; i < dims.size(); ++i)
    {
      encode(limit, dims[i]);
    }
  }
}

void UaBinaryEncoder::encode_byte_string(span<const byte> element)
{
  if (element.size() > numeric_cast<size_t>(std::numeric_limits<int32_t>::max()))
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("EncodingLimitExceeded", "ByteString length exceeds int32 maximum", "BinaryCodec")
        .context(ua::ContextKeys::sizeActual, std::to_string(element.size()))
        .context(ua::ContextKeys::sizeMax, std::to_string(std::numeric_limits<int32_t>::max())));
  }

  int32_t length = numeric_cast<int32_t>(element.size());
  if (length == 0)
  {
    length = -1;
  }
  encode_number(length);

  if (length > 0)
  {
    mStream.write_all(element);
  }
}

void UaBinaryEncoder::encode(StackDepth limit, const ArrayBase& element, bool encodeAsOneDimensional)
{
  const size_t size = element.size();
  // value_rank() returns 1 exactly when no dimensions are set, so the multi-dimensional arm below is
  // reached only when dimensions() is engaged; bind it once and deref through the bound reference.
  const auto& dimensions = element.dimensions();
  if (size == 0)
  {
    encode(limit, int32_t{-1});
    return;
  }
  else if ((element.value_rank() == 1) || encodeAsOneDimensional || !dimensions)
  {
    encode(limit, numeric_cast<int32_t>(element.size()));
  }
  else
  {
    const std::vector<int32_t>& dims = dimensions.value();
    const size_t dimsSize = dims.size();
    encode(limit, numeric_cast<int32_t>(dimsSize));

    for (size_t i = 0; i < dimsSize; ++i)
    {
      encode(limit, dims[i]);
    }
  }
}

const Stream& UaBinaryDecoder::stream() const
{
  return mStream;
}

void UaBinaryDecoder::decode(StackDepth limit, bool& element)
{
  limit.consume_edge();

  element = false;

  uint8_t value{0};
  decode(limit, value);
  if (value)
  {
    element = true;
  }
}

void UaBinaryDecoder::decode(StackDepth limit, uint8_t& element)
{
  limit.consume_edge();
  decode_number(element);
}

void UaBinaryDecoder::decode(StackDepth limit, int8_t& element)
{
  limit.consume_edge();
  decode_number(element);
}

void UaBinaryDecoder::decode(StackDepth limit, uint16_t& element)
{
  limit.consume_edge();
  decode_number(element);
}

void UaBinaryDecoder::decode(StackDepth limit, int16_t& element)
{
  limit.consume_edge();
  decode_number(element);
}

void UaBinaryDecoder::decode(StackDepth limit, uint32_t& element)
{
  limit.consume_edge();
  decode_number(element);
}

void UaBinaryDecoder::decode(StackDepth limit, int32_t& element)
{
  limit.consume_edge();
  decode_number(element);
}

void UaBinaryDecoder::decode(StackDepth limit, uint64_t& element)
{
  limit.consume_edge();
  decode_number(element);
}

void UaBinaryDecoder::decode(StackDepth limit, int64_t& element)
{
  limit.consume_edge();
  decode_number(element);
}

void UaBinaryDecoder::decode(StackDepth limit, float& element)
{
  limit.consume_edge();
  decode_number(element);
}

void UaBinaryDecoder::decode(StackDepth limit, double& element)
{
  limit.consume_edge();
  decode_number(element);
}

void UaBinaryDecoder::decode(StackDepth limit, String& element)
{
  ByteString temp;
  decode(limit, temp);

  if (temp.size() > mEncodingLimits.maxStringLength)
  {
    throw UaException(Status::BadEncodingLimitsExceeded,
      ErrorDetail::build("StringLengthExceeded", "String length exceeds maximum", "BinaryCodec")
        .context(ua::ContextKeys::sizeActual, std::to_string(temp.size()))
        .context(ua::ContextKeys::sizeMax, std::to_string(mEncodingLimits.maxStringLength)));
  }

  const string_view value{utils::bytes_to_chars(temp.data()), temp.size()};
  element = value;
}

void UaBinaryDecoder::decode(StackDepth limit, std::string& element)
{
  limit.consume_edge();

  int32_t length{0};
  auto lengthAsBytes = as_bytes(length);

  read_exact(lengthAsBytes);
  if (length <= 0)
  {
    element.clear();
  }
  else
  {
    if (numeric_cast<size_t>(length) > mEncodingLimits.maxStringLength)
    {
      throw UaException(Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("StringLengthExceeded", "String length exceeds maximum", "BinaryCodec")
          .context(ua::ContextKeys::sizeActual, std::to_string(length))
          .context(ua::ContextKeys::sizeMax, std::to_string(mEncodingLimits.maxStringLength)));
    }
    require_remaining_bytes(numeric_cast<size_t>(length));
    element.assign(numeric_cast<size_t>(length), ' ');
    read_exact(span<byte>{utils::chars_to_bytes(element.data()), element.size()});
  }
}

void UaBinaryDecoder::decode(StackDepth limit, DateTime& element)
{
  limit.consume_edge();

  using namespace std::chrono;

  int64_t encodedValue{0};
  decode_number(encodedValue);

  const auto latestPlatformValue = (DateTime::max() - DateTime::min()) / datetime::OneHundredNanoSeconds{1};

  // Part 6 section 5.2.2.5: wire values outside the platform range decode to the nearest bound.
  // Compare before adding the 1601 epoch offset so hostile int64 values cannot overflow chrono.
  if (encodedValue <= 0)
  {
    element.value() = DateTime::min();
  }
  else if (encodedValue >= latestPlatformValue)
  {
    element.value() = DateTime::max();
  }
  else
  {
    const sys_time<datetime::OneHundredNanoSeconds> decodedValue = sys_time<datetime::OneHundredNanoSeconds>{
      datetime::OneHundredNanoSeconds{encodedValue} + DateTime::min().time_since_epoch()};
    element.value() = decodedValue;
  }
}

void UaBinaryDecoder::decode(StackDepth limit, Guid& element) const
{
  limit.consume_edge();

  std::array<byte, Guid::length> buffer{};
  read_exact(buffer);
  element.from_ua_binary(buffer);
}

void UaBinaryDecoder::decode(StackDepth limit, ByteString& element)
{
  limit.consume_edge();

  int32_t length{0};
  auto lengthAsBytes = as_bytes(length);

  read_exact(lengthAsBytes);
  if (length <= 0)
  {
    element.clear();
  }
  else
  {
    if (numeric_cast<size_t>(length) > mEncodingLimits.maxByteStringLength)
    {
      throw UaException(Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("EncodingLimitExceeded", "ByteString length exceeds maximum", "BinaryCodec")
          .context(ua::ContextKeys::sizeActual, std::to_string(length))
          .context(ua::ContextKeys::sizeMax, std::to_string(mEncodingLimits.maxByteStringLength)));
    }
    require_remaining_bytes(numeric_cast<size_t>(length));
    std::vector<byte> temp;
    // length > 0 (enclosing else-branch) and bounded above by mMaxByteStringLength; match sibling style.
    temp.resize(numeric_cast<size_t>(length));
    read_exact(temp);
    element = ByteString{span<const byte>{temp}};
  }
}

ByteString UaBinaryDecoder::read_extension_object_body(int32_t length)
{
  // `length` is validated > 0 by the caller; bound it by the ByteString limit before allocating.
  if (numeric_cast<size_t>(length) > mEncodingLimits.maxByteStringLength)
  {
    throw UaException(Status::BadEncodingLimitsExceeded,
      ErrorDetail::build(
        "EncodingLimitExceeded", "Extension object body length exceeds maximum", "BinaryCodec")
        .context(ua::ContextKeys::sizeActual, std::to_string(length))
        .context(ua::ContextKeys::sizeMax, std::to_string(mEncodingLimits.maxByteStringLength)));
  }

  require_remaining_bytes(numeric_cast<size_t>(length));
  std::vector<byte> temp;
  temp.resize(numeric_cast<size_t>(length));
  read_exact(temp);
  return ByteString{span<const byte>{temp}};
}

void UaBinaryDecoder::decode(StackDepth limit, XmlElement& element)
{
  ByteString temp;
  decode(limit, temp);

  if (temp.size() > mEncodingLimits.maxStringLength)
  {
    throw UaException(Status::BadEncodingLimitsExceeded,
      ErrorDetail::build("StringLengthExceeded", "XmlElement length exceeds maximum", "BinaryCodec")
        .context(ua::ContextKeys::sizeActual, std::to_string(temp.size()))
        .context(ua::ContextKeys::sizeMax, std::to_string(mEncodingLimits.maxStringLength)));
  }

  const string_view value{utils::bytes_to_chars(temp.data()), temp.size()};
  element = value;
}

void UaBinaryDecoder::decode(StackDepth limit, NodeId& element)
{
  String namespaceUri;
  uint32_t serverIndex{0};

  decode_node_id(limit, element, namespaceUri, serverIndex);
  if (!namespaceUri.empty())
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("InvalidEncoding", "NodeId contained unexpected namespaceUri", "BinaryCodec")
        .context(ua::ContextKeys::namespaceUri, static_cast<std::string>(namespaceUri)));
  }
  if (serverIndex)
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("InvalidEncoding", "NodeId contained unexpected serverIndex", "BinaryCodec")
        .context(ua::ContextKeys::serverIndex, std::to_string(serverIndex)));
  }

  if (mNamespaceConfig.translateNodeId)
  {
    mNamespaceConfig.translateNodeId(element);
  }
}

void UaBinaryDecoder::decode(StackDepth limit, ExpandedNodeId& element)
{
  decode_node_id(limit, element.node_id(), element.namespace_uri(), element.server_index());

  if (mNamespaceConfig.translateExpandedNodeId)
  {
    mNamespaceConfig.translateExpandedNodeId(element);
  }
}

void UaBinaryDecoder::decode(StackDepth limit, StatusCode& element)
{
  uint32_t value{0};
  decode(limit, value);
  element = StatusCode(value);
}

void UaBinaryDecoder::decode(StackDepth limit, QualifiedName& element)
{
  decode(limit, element.namespace_index());
  decode(limit, element.name());

  if (mNamespaceConfig.translateQualifiedName)
  {
    mNamespaceConfig.translateQualifiedName(element);
  }
}

void UaBinaryDecoder::decode(StackDepth limit, LocalizedText& element)
{
  element = LocalizedText{};

  uint8_t mask{0};
  decode(limit, mask);

  const LocalizedTextEncoding encodingMask{mask};
  if (encodingMask.test(LocalizedTextEncoding::Bit::Locale))
  {
    decode(limit, element.locale());
  }

  if (encodingMask.test(LocalizedTextEncoding::Bit::Text))
  {
    decode(limit, element.text());
  }
}

void UaBinaryDecoder::decode(StackDepth limit, DataValue& element)
{
  // Charge the structural-descent: a DataValue carries a Variant (which may nest). Released on unwind.
  const auto depthGuard = limit.enter_recursion();
  element.clear();

  uint8_t mask = 0;
  decode(limit, mask);
  const DataValueEncoding encodingMask(mask);

  if (encodingMask.test(DataValueEncoding::Bit::Value))
  {
    decode(limit, element.value());
  }

  if (encodingMask.test(DataValueEncoding::Bit::StatusCode))
  {
    StatusCode status;
    decode(limit, status);
    element.status() = status;
  }

  if (encodingMask.test(DataValueEncoding::Bit::SourceTimestamp))
  {
    DateTime timestamp;
    decode(limit, timestamp);
    element.source_timestamp() = timestamp;
  }

  if (encodingMask.test(DataValueEncoding::Bit::SourcePicoSeconds))
  {
    uint16_t picoSeconds{0};
    decode(limit, picoSeconds);
    element.source_pico_seconds() = picoSeconds;
  }

  if (encodingMask.test(DataValueEncoding::Bit::ServerTimestamp))
  {
    DateTime timestamp;
    decode(limit, timestamp);
    element.server_timestamp() = timestamp;
  }

  if (encodingMask.test(DataValueEncoding::Bit::ServerPicoSeconds))
  {
    uint16_t picoSeconds{0};
    decode(limit, picoSeconds);
    element.server_pico_seconds() = picoSeconds;
  }
}

void UaBinaryDecoder::decode(StackDepth limit, DiagnosticInfo& element)
{
  // Charge the structural-descent: nested InnerDiagnosticInfo recurses here, so bound the live
  // recursion depth (the work budget alone cannot - it allows ~maxWork^2 levels, far past the
  // native stack). Released as this frame unwinds.
  const auto depthGuard = limit.enter_recursion();
  uint8_t encodingMask = 0;
  decode(limit, encodingMask);

  const DiagnosticInfoEncoding mask(encodingMask);

  if (mask.test(DiagnosticInfoEncoding::Bit::SymbolicId))
  {
    int32_t symbolicId{0};
    decode(limit, symbolicId);
    element.symbolic_id() = symbolicId;
  }
  else
  {
    element.symbolic_id().reset();
  }

  if (mask.test(DiagnosticInfoEncoding::Bit::Namespace))
  {
    int32_t nameSpace{0};
    decode(limit, nameSpace);
    element.namespace_uri() = nameSpace;
  }
  else
  {
    element.namespace_uri().reset();
  }

  if (mask.test(DiagnosticInfoEncoding::Bit::Locale))
  {
    int32_t locale{0};
    decode(limit, locale);
    element.locale() = locale;
  }
  else
  {
    element.locale().reset();
  }

  if (mask.test(DiagnosticInfoEncoding::Bit::LocalizedText))
  {
    int32_t localizedText{0};
    decode(limit, localizedText);
    element.localized_text() = localizedText;
  }
  else
  {
    element.localized_text().reset();
  }

  if (mask.test(DiagnosticInfoEncoding::Bit::AdditionalInfo))
  {
    std::string additionalInfo;
    decode(limit, additionalInfo);
    element.additional_info().emplace(std::move(additionalInfo));
  }
  else
  {
    element.additional_info().reset();
  }

  if (mask.test(DiagnosticInfoEncoding::Bit::InnerStatusCode))
  {
    StatusCode status;
    decode(limit, status);
    element.inner_status_code() = status;
  }
  else
  {
    element.inner_status_code().reset();
  }

  if (mask.test(DiagnosticInfoEncoding::Bit::InnerDiagnosticInfo))
  {
    auto innerDiagnosticInfo = make_unique<DiagnosticInfo>();
    decode(limit, *innerDiagnosticInfo);
    element.inner_diagnostic_info() = std::move(innerDiagnosticInfo);
  }
}

void UaBinaryDecoder::decode(StackDepth limit, Decimal& element)
{
  NodeId typeId;
  decode(limit, typeId);

  const NodeId decimalEncodingId(ObjectId::DecimalDataType_Encoding_DefaultBinary);
  if (typeId != decimalEncodingId)
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("DecodingFailed", "Decimal extension object typeId not recognised", "BinaryCodec")
        .context(ua::ContextKeys::actual, typeId.as_definition())
        .context(ua::ContextKeys::expected, decimalEncodingId.as_definition()));
  }

  uint8_t encoding{0};
  decode(limit, encoding);
  // The ExtensionObject body-encoding byte must indicate a binary body (1); 0 = no body,
  // 2 = XML. The encoder always writes 1 (see encode(Decimal)).
  if (encoding != 1)
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("InvalidEncoding", "Decimal extension object encoding is not binary", "BinaryCodec")
        .context(ua::ContextKeys::value, std::to_string(encoding)));
  }

  int32_t length{0};
  decode(limit, length);
  if (length > 0 && numeric_cast<size_t>(length) > mEncodingLimits.maxByteStringLength)
  {
    throw UaException(Status::BadEncodingLimitsExceeded,
      ErrorDetail::build("EncodingLimitExceeded", "Decimal body length exceeds maximum", "BinaryCodec")
        .context(ua::ContextKeys::sizeActual, std::to_string(length))
        .context(ua::ContextKeys::sizeMax, std::to_string(mEncodingLimits.maxByteStringLength)));
  }
  if (length <= static_cast<int32_t>(sizeof(int16_t)))
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("DecodingFailed", "Decimal body length is too short", "BinaryCodec")
        .context(ua::ContextKeys::sizeActual, std::to_string(length))
        .context(ua::ContextKeys::sizeMin, std::to_string(sizeof(int16_t) + 1)));
  }

  decode(limit, element.scale());
  const size_t lengthOfValue = numeric_cast<size_t>(length) - sizeof(int16_t);

  std::vector<byte> decimalBytes(lengthOfValue);
  read_exact(decimalBytes);
  element.value() = ByteString{span<const byte>{decimalBytes}};
}

// void UaBinaryDecoder::decode(StackDepth limit, Enumeration& element)
//{
//   int32_t value{0};
//   decode(limit, value);
//   element.set_from_int32(value);
// }

void UaBinaryDecoder::decode(StackDepth limit, Variant& element)
{
  // Charge the structural-descent: a Variant can nest Variants / ExtensionObjects / arrays, so bound
  // the live recursion depth here (released as this frame unwinds; width is unaffected).
  const auto depthGuard = limit.enter_recursion();
  uint8_t encodingMask{0};
  decode(limit, encodingMask);

  const VariantEncoding mask(encodingMask);

  const bool isArray = mask.test(VariantEncoding::Bit::ArrayOfValues);
  const bool hasDims = mask.test(VariantEncoding::Bit::ArrayDimensions);
  const uint8_t typeId = (encodingMask & VariantEncoding::typeMask);

  if (!isArray && hasDims)
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "InvalidEncoding", "Variant encoding mask has dimensions flag set without array flag", "BinaryCodec")
        .context(ua::ContextKeys::value, std::to_string(encodingMask)));
  }

  // Built-in type-ids 26-63 are reserved (OPC UA Part 6 5.2.2.16). from_underlying is an unchecked
  // cast, so a reserved value would otherwise fall through the dispatch switches' default arms and
  // silently produce Null while leaving the array/scalar body unread (stream desync). Reject it here
  // at the single dispatch site so malformed wire input surfaces as a clean BadDecodingError.
  if (typeId > utils::to_underlying(BuiltInTypeId::DiagnosticInfo))
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("InvalidEncoding", "Variant built-in type id is reserved", "BinaryCodec")
        .context(ua::ContextKeys::typeId, std::to_string(typeId)));
  }

  const BuiltInTypeId builtInTypeId = utils::from_underlying<BuiltInTypeId>(typeId);
  if (builtInTypeId == BuiltInTypeId::Null)
  {
    element.clear();
    return;
  }

  if (isArray)
  {
    decode_array_variant(limit, builtInTypeId, hasDims, element);
  }
  else
  {
    decode_scalar_variant(limit, builtInTypeId, element);
  }
}

void UaBinaryDecoder::decode_node_id(
  StackDepth limit, NodeId& nodeId, String& namespaceUri, uint32_t& serverIndex)
{
  uint8_t encoding{0};
  decode(limit, encoding);

  if (NodeIdEncoding::is_two_byte(encoding))
  {
    uint8_t identifier{0};
    decode(limit, identifier);
    nodeId.namespace_index() = 0;
    nodeId.identifier() = identifier;
  }
  else if (NodeIdEncoding::is_four_byte(encoding))
  {
    uint8_t namespaceIndex{0};
    decode(limit, namespaceIndex);

    uint16_t identifier{0};
    decode(limit, identifier);

    nodeId.namespace_index() = namespaceIndex;
    nodeId.identifier() = identifier;
  }
  else
  {
    uint16_t namespaceIndex{0};
    decode(limit, namespaceIndex);
    nodeId.namespace_index() = namespaceIndex;

    if (NodeIdEncoding::is_numeric(encoding))
    {
      uint32_t identifier{0};
      decode(limit, identifier);
      nodeId.identifier() = identifier;
    }
    else if (NodeIdEncoding::is_string(encoding))
    {
      std::string identifier;
      decode(limit, identifier);
      nodeId.identifier() = identifier;
    }
    else if (NodeIdEncoding::is_byte_string(encoding))
    {
      ByteString identifier;
      decode(limit, identifier);
      nodeId.identifier() = identifier;
    }
    else if (NodeIdEncoding::is_guid(encoding))
    {
      Guid identifier;
      decode(limit, identifier);
      nodeId.identifier() = identifier;
    }
    else
    {
      throw UaException(Status::BadDecodingError,
        ErrorDetail::build("InvalidEncoding", "NodeId encoding byte is invalid", "BinaryCodec")
          .context(ua::ContextKeys::value, std::to_string(encoding)));
    }
  }

  if (NodeIdEncoding::has_namespace_uri(encoding))
  {
    decode(limit, namespaceUri);
  }

  if (NodeIdEncoding::has_server_index(encoding))
  {
    decode(limit, serverIndex);
  }
}

template<typename T>
void UaBinaryDecoder::decode_scalar_variant_value(StackDepth limit, Variant& result)
{
  T element;
  decode(limit, element);
  result = std::move(element);
}

template<>
void UaBinaryDecoder::decode_scalar_variant_value<Structure>(StackDepth limit, Variant& result)
{
  unique_ptr<Structure> element;
  decode(limit, element);
  result = std::move(element);
}

void UaBinaryDecoder::decode_scalar_variant(
  ua::StackDepth limit, ua::BuiltInTypeId typeId, ua::Variant& element)
{
  switch (typeId)
  {
  case BuiltInTypeId::Boolean:
    return decode_scalar_variant_value<bool>(limit, element);

  case BuiltInTypeId::SByte:
    return decode_scalar_variant_value<int8_t>(limit, element);

  case BuiltInTypeId::Byte:
    return decode_scalar_variant_value<uint8_t>(limit, element);

  case BuiltInTypeId::Int16:
    return decode_scalar_variant_value<int16_t>(limit, element);

  case BuiltInTypeId::UInt16:
    return decode_scalar_variant_value<uint16_t>(limit, element);

  case BuiltInTypeId::Int32:
    return decode_scalar_variant_value<int32_t>(limit, element);

  case BuiltInTypeId::UInt32:
    return decode_scalar_variant_value<uint32_t>(limit, element);

  case BuiltInTypeId::Int64:
    return decode_scalar_variant_value<int64_t>(limit, element);

  case BuiltInTypeId::UInt64:
    return decode_scalar_variant_value<uint64_t>(limit, element);

  case BuiltInTypeId::Float:
    return decode_scalar_variant_value<float>(limit, element);

  case BuiltInTypeId::Double:
    return decode_scalar_variant_value<double>(limit, element);

  case BuiltInTypeId::String:
    return decode_scalar_variant_value<String>(limit, element);

  case BuiltInTypeId::DateTime:
    return decode_scalar_variant_value<DateTime>(limit, element);

  case BuiltInTypeId::Guid:
    return decode_scalar_variant_value<Guid>(limit, element);

  case BuiltInTypeId::ByteString:
    return decode_scalar_variant_value<ByteString>(limit, element);

  case BuiltInTypeId::XmlElement:
    return decode_scalar_variant_value<XmlElement>(limit, element);

  case BuiltInTypeId::NodeId:
    return decode_scalar_variant_value<NodeId>(limit, element);

  case BuiltInTypeId::ExpandedNodeId:
    return decode_scalar_variant_value<ExpandedNodeId>(limit, element);

  case BuiltInTypeId::StatusCode:
    return decode_scalar_variant_value<StatusCode>(limit, element);

  case BuiltInTypeId::QualifiedName:
    return decode_scalar_variant_value<QualifiedName>(limit, element);

  case BuiltInTypeId::LocalizedText:
    return decode_scalar_variant_value<LocalizedText>(limit, element);

  case BuiltInTypeId::ExtensionObject:
    return decode_scalar_variant_value<Structure>(limit, element);

  case BuiltInTypeId::DataValue:
    return decode_scalar_variant_value<DataValue>(limit, element);

  case BuiltInTypeId::Variant:
  case BuiltInTypeId::DiagnosticInfo:
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "UnsupportedEncoding", "Variant cannot contain scalar Variant or DiagnosticInfo", "BinaryCodec")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(typeId))));
    break;

  default:
    // Reserved type-ids (26-63) are rejected up-front in decode(StackDepth, Variant&); this arm is
    // unreachable for valid input, but throw defensively so the helper is correct in isolation.
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("InvalidEncoding", "Variant scalar built-in type id is reserved", "BinaryCodec")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(typeId))));
  }
}

template<typename T>
void UaBinaryDecoder::decode_array_variant_value(StackDepth limit, Variant& result)
{
  Array<T> element;
  decode(limit, element);
  result = std::move(element);
}

void UaBinaryDecoder::decode_array_variant(
  ua::StackDepth limit, ua::BuiltInTypeId typeId, bool hasDims, ua::Variant& element)
{
  switch (typeId)
  {
  case BuiltInTypeId::Boolean:
    decode_array_variant_value<bool>(limit, element);
    break;

  case BuiltInTypeId::SByte:
    decode_array_variant_value<int8_t>(limit, element);
    break;

  case BuiltInTypeId::Byte:
    decode_array_variant_value<uint8_t>(limit, element);
    break;

  case BuiltInTypeId::Int16:
    decode_array_variant_value<int16_t>(limit, element);
    break;

  case BuiltInTypeId::UInt16:
    decode_array_variant_value<uint16_t>(limit, element);
    break;

  case BuiltInTypeId::Int32:
    decode_array_variant_value<int32_t>(limit, element);
    break;

  case BuiltInTypeId::UInt32:
    decode_array_variant_value<uint32_t>(limit, element);
    break;

  case BuiltInTypeId::Int64:
    decode_array_variant_value<int64_t>(limit, element);
    break;

  case BuiltInTypeId::UInt64:
    decode_array_variant_value<uint64_t>(limit, element);
    break;

  case BuiltInTypeId::Float:
    decode_array_variant_value<float>(limit, element);
    break;

  case BuiltInTypeId::Double:
    decode_array_variant_value<double>(limit, element);
    break;

  case BuiltInTypeId::String:
    decode_array_variant_value<String>(limit, element);
    break;

  case BuiltInTypeId::DateTime:
    decode_array_variant_value<DateTime>(limit, element);
    break;

  case BuiltInTypeId::Guid:
    decode_array_variant_value<Guid>(limit, element);
    break;

  case BuiltInTypeId::ByteString:
    decode_array_variant_value<ByteString>(limit, element);
    break;

  case BuiltInTypeId::XmlElement:
    decode_array_variant_value<XmlElement>(limit, element);
    break;

  case BuiltInTypeId::NodeId:
    decode_array_variant_value<NodeId>(limit, element);
    break;

  case BuiltInTypeId::ExpandedNodeId:
    decode_array_variant_value<ExpandedNodeId>(limit, element);
    break;

  case BuiltInTypeId::StatusCode:
    decode_array_variant_value<StatusCode>(limit, element);
    break;

  case BuiltInTypeId::QualifiedName:
    decode_array_variant_value<QualifiedName>(limit, element);
    break;

  case BuiltInTypeId::LocalizedText:
    decode_array_variant_value<LocalizedText>(limit, element);
    break;

  case BuiltInTypeId::ExtensionObject:
    decode_array_variant_value<RefStructure<Structure>>(limit, element);
    break;

  case BuiltInTypeId::DataValue:
    decode_array_variant_value<DataValue>(limit, element);
    break;

  case BuiltInTypeId::Variant:
    decode_array_variant_value<Variant>(limit, element);
    break;

  case BuiltInTypeId::DiagnosticInfo:
    throw UaException(Status::BadDecodingError,
      make_error_detail(
        "UnsupportedEncoding", "Variant cannot contain array of DiagnosticInfo", "BinaryCodec"));
    break;

  default:
    // Reserved type-ids (26-63) are rejected up-front in decode(StackDepth, Variant&); this arm is
    // unreachable for valid input, but throw defensively so the helper is correct in isolation.
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("InvalidEncoding", "Variant array built-in type id is reserved", "BinaryCodec")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(typeId))));
  }

  if (hasDims)
  {
    Dimensions dimensions;
    decode_dimensions(limit, dimensions);
    try
    {
      element.get_array_base().add_and_validate_dimensions(std::move(dimensions));
    }
    catch (const UaException& exception)
    {
      // Part 6 section 5.2.2.16: ArrayDimensions inconsistent with the array length stop decoding
      // with Bad_DecodingError. The array's own status describes the inconsistency; it is the cause.
      throw UaException(Status::BadDecodingError,
        ErrorDetail::build(
          "DecodingFailed", "Array dimensions are inconsistent with the array", "BinaryCodec")
          .cause(exception.take_detail()));
    }
  }
}

void UaBinaryDecoder::decode_dimensions(ua::StackDepth limit, ua::Dimensions& dimensions)
{
  int32_t length{0};
  decode(limit, length);
  if (length <= 1)
  {
    dimensions.clear();
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "ArrayDimensionMismatch", "Array dimensions length is less than the minimum of 2", "BinaryCodec")
        .context(ua::ContextKeys::sizeActual, std::to_string(length))
        .context(ua::ContextKeys::sizeMin, std::string{"2"}));
  }

  // Cap the declared dimension count before allocating, otherwise a hostile length field is a
  // remotely-triggerable allocation bomb. The bound applied is mMaxArrayLength, the element-count
  // cap: array rank is bounded far smaller than element count in practice, so this is deliberately
  // conservative rather than tight, and a rank far below the cap is still rejected downstream by the
  // dimension/length agreement check.
  if (numeric_cast<size_t>(length) > mEncodingLimits.maxArrayLength)
  {
    dimensions.clear();
    throw UaException(Status::BadEncodingLimitsExceeded,
      ErrorDetail::build("EncodingLimitExceeded", "Array dimensions count exceeds maximum", "BinaryCodec")
        .context(ua::ContextKeys::sizeActual, std::to_string(length))
        .context(ua::ContextKeys::sizeMax, std::to_string(mEncodingLimits.maxArrayLength)));
  }

  require_remaining_bytes(numeric_cast<size_t>(length));
  dimensions.resize(numeric_cast<size_t>(length));
  for (auto& dim : dimensions)
  {
    decode(limit, dim);
  }
}

UaBinaryDecoder::UaBinaryDecoder(StructureResolver structureResolver, Stream& stream,
  const EncodingLimits& encodingLimits, CodecNamespaceContext namespaceConfig)
  : mNamespaceConfig(std::move(namespaceConfig)), mStream(stream),
    mStructureResolver(std::move(structureResolver)), mEncodingLimits{encodingLimits}
{}

void UaBinaryDecoder::require_remaining_bytes(size_t count) const
{
  const size_t length = mStream.get_length();
  const size_t position = mStream.get_position();
  const size_t remaining = position < length ? length - position : 0;
  if (count > remaining)
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("DecodingFailed",
        "A declared length needs more bytes than remain in the encoded value",
        "BinaryCodec")
        .context(ua::ContextKeys::sizeActual, std::to_string(remaining))
        .context(ua::ContextKeys::sizeMin, std::to_string(count)));
  }
}

void UaBinaryDecoder::read_exact(span<byte> destination) const
{
  // Stream::read_all reports a short read as Bad_EndOfStream (a stream fact); at the decoder it is a
  // malformed encoding (Part 6 section 5.2), reported as Bad_DecodingError with the stream's detail as
  // the cause.
  try
  {
    mStream.read_all(destination);
  }
  catch (const UaException& exception)
  {
    if (exception.status() != Status::BadEndOfStream)
    {
      throw;
    }
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "DecodingFailed", "Encoded value is cut short by the end of the stream", "BinaryCodec")
        .cause(exception.take_detail()));
  }
}

void UaBinaryDecoder::decode_number(auto& value)
{
  auto bytes = as_bytes(value);

  read_exact(bytes);

  if constexpr (std::endian::native == std::endian::big)
  {
    std::reverse(bytes.begin(), bytes.end());
  }
  else
  {
    static_assert(std::endian::native == std::endian::little, "Endianness of platform unknown");
  }
}

void UaBinaryDecoder::decode(StackDepth limit, Structure& element)
{
  // Charge the structural-descent: an ExtensionObject/struct body may nest further structures, so
  // bound the live recursion depth at this chokepoint (released as this frame unwinds).
  const auto depthGuard = limit.enter_recursion();
  Decoder decoder(*this);
  element.decode(limit, decoder);
}

template<>
void UaBinaryDecoder::decode(StackDepth limit, Array<bool>& element)
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
    for (int32_t i = 0; i < length; ++i)
    {
      bool item{false};
      decode(limit, item);
      // 0 <= i < length proven by the loop bound; index is non-negative.
      element.payload()[static_cast<size_t>(i)] = item;
    }
  }
}

}  // namespace ua
