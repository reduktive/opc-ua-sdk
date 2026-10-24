// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_XML_CODEC_H
#define UA_XML_CODEC_H

#include "ua_includes.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_codec.h"
#include "ua_resource_budgets.h"
#include "ua_array_base.h"
#include "ua_xml_parser.h"
#include "ua_array.h"
#include "ua_node_id.h"
#include "ua_structure_factory.h"
#include "ua_xml_parser.h"
#include "ua_structure.h"
#include "ua_encoding_limits.h"

namespace ua
{

class Stream;
class NamespaceArray;

namespace xml_codec_details
{

bool check_element_presence(string_view elementName, const optional<xml::Element>& element, bool isOptional);

}

class XmlEncoder
{
public:
  XmlEncoder(const CodecNamespaceContext& namespaceConfig, Stream& stream);

  void encode(StackDepth limit, string_view elementName, bool value);

  void encode(StackDepth limit, string_view elementName, uint8_t value);

  void encode(StackDepth limit, string_view elementName, int8_t value);

  void encode(StackDepth limit, string_view elementName, uint16_t value);

  void encode(StackDepth limit, string_view elementName, int16_t value);

  void encode(StackDepth limit, string_view elementName, uint32_t value);

  void encode(StackDepth limit, string_view elementName, int32_t value);

  void encode(StackDepth limit, string_view elementName, uint64_t value);

  void encode(StackDepth limit, string_view elementName, int64_t value);

  void encode(StackDepth limit, string_view elementName, float value);

  void encode(StackDepth limit, string_view elementName, double value);

  void encode(StackDepth limit, string_view elementName, string_view value);

  void encode(StackDepth limit, string_view elementName, const String& value);

  void encode(StackDepth limit, string_view elementName, const DateTime& value);

  void encode(StackDepth limit, string_view elementName, const Guid& value);

  void encode(StackDepth limit, string_view elementName, const ByteString& value);

  void encode(StackDepth limit, string_view elementName, const NodeId& value);

  void encode(StackDepth limit, string_view elementName, const ExpandedNodeId& value);

  void encode(StackDepth limit, string_view elementName, const StatusCode& value);

  void encode(StackDepth limit, string_view elementName, const QualifiedName& value);

  void encode(StackDepth limit, string_view elementName, const LocalizedText& value);

  void encode(StackDepth limit, string_view elementName, const XmlElement& value);

  void encode(StackDepth limit, string_view elementName, const DataValue& value);

  void encode(StackDepth limit, string_view elementName, const DiagnosticInfo& value);

  void encode(StackDepth limit, string_view elementName, const Variant& value);

  void encode(StackDepth limit, string_view elementName, const Decimal& value);

  void encode(StackDepth limit, string_view elementName, const Structure& value);

  void encode(StackDepth limit, string_view elementName, const Structure* value);

  template<typename T>
  void encode(
    StackDepth limit, string_view elementName, const Array<T>& value, bool encodeAsOneDimensional = true);

  // Array-of-enum: enums have no scalar XML encode overload (the scalar codegen
  // converts via `utils::as_int32`), so project to `Array<int32_t>` and delegate
  // to the generic array encode. Mirrors the binary codec's `IsEnum<T>` overload.
  template<typename T>
    requires IsEnum<T>
  void encode(
    StackDepth limit, string_view elementName, const Array<T>& value, bool encodeAsOneDimensional = true);

  template<typename T>
  void encode(StackDepth limit, string_view elementName, const Array<RefStructure<T>>& value,
    bool encodeAsOneDimensional = true);

private:
  // RAII helper to guarantee end tag emission
  class ElementScope
  {
  public:
    ElementScope(XmlEncoder& encoder, string_view name, string_view xmlnsUri = {})
      : mEncoder(encoder), mName(name), mActive(!name.empty())
    {
      if (mActive)
      {
        mEncoder.write_start_element(mName, xmlnsUri);
      }
    }

    ~ElementScope()
    {
      if (mActive)
      {
        mEncoder.write_end_element(mName);
      }
    }

    ElementScope(const ElementScope&) = delete;
    ElementScope& operator=(const ElementScope&) = delete;
    ElementScope(ElementScope&&) = delete;
    ElementScope& operator=(ElementScope&&) = delete;

  private:
    XmlEncoder& mEncoder;
    string_view mName;
    bool mActive{false};
  };

  CodecNamespaceContext mNamespaceConfig;
  Stream& mStream;

  // Writes a start tag. When `xmlnsUri` is non-empty it is emitted as a default-namespace
  // declaration: `<name xmlns="uri">`. Used to wrap an ExtensionObject body in its type element.
  void write_start_element(string_view name, string_view xmlnsUri = {});
  void write_end_element(string_view name);
  void write_text(string_view text);

  template<typename T>
  void write_number(string_view name, T value);
};

template<typename T>
void XmlEncoder::encode(StackDepth limit, string_view elementName, const Array<T>& value,
  bool /*encodeAsOneDimensional*/ /*= true*/)
{
  if (elementName.empty())
  {
    for (const auto& item : value)
    {
      encode(limit, get_typename<T>(), item);
    }
  }
  else
  {
    const ElementScope scope(*this, elementName);
    for (const auto& item : value)
    {
      encode(limit, get_typename<T>(), item);
    }
  }
}

template<typename T>
  requires IsEnum<T>
void XmlEncoder::encode(
  StackDepth limit, string_view elementName, const Array<T>& value, bool encodeAsOneDimensional /*= true*/)
{
  Array<int32_t> raw;
  raw.payload().reserve(value.payload().size());
  for (const auto& item : value.payload())
  {
    raw.payload().push_back(utils::as_int32(item));
  }
  encode(limit, elementName, raw, encodeAsOneDimensional);
}

template<typename T>
void XmlEncoder::encode(StackDepth limit, string_view elementName, const Array<RefStructure<T>>& value,
  bool /*encodeAsOneDimensional*/ /*= true*/)
{
  auto emitItem = [&](const RefStructure<T>& item)
  {
    if (item)
    {
      // Encode as ExtensionObject with TypeId/Body
      encode(limit, get_typename<T>(), item.get());
    }
    else
    {
      // Preserve array rank by emitting an empty placeholder element
      // Decoder will interpret `<ExtensionObject/>` (or appropriate typename) as a null value
      const ElementScope placeholder(*this, get_typename<T>());
      UA_UNUSED(placeholder);
    }
  };

  if (elementName.empty())
  {
    for (const auto& item : value)
    {
      emitItem(item);
    }
  }
  else
  {
    const ElementScope scope(*this, elementName);
    for (const auto& item : value)
    {
      emitItem(item);
    }
  }
}

class StructureFactory;

class XmlDecoder
{
public:
  // Resolver form (canonical): ExtensionObject bodies are instantiated by `structureResolver`.
  // An empty resolver means "no custom types" - an unrecognised ExtensionObject decodes via the
  // UnknownStructure path (which reports BadNotSupported for a non-empty body) rather than being
  // silently mis-decoded. `encodingLimits` bounds the decode as it bounds UaBinaryDecoder: the element count
  // of any one decoded array, and of a matrix's Dimensions, is capped at
  // `EncodingLimits::maxArrayLength`, and a longer array is Bad_EncodingLimitsExceeded (cost: one
  // comparison per decoded element).
  XmlDecoder(StructureResolver structureResolver, xml::Element xmlElement,
    const EncodingLimits& encodingLimits, CodecNamespaceContext namespaceConfig = {});
  // Convenience: build the resolver from a StructureFactory. The factory must outlive this decoder
  // (and any NodeSet that stores the derived resolver). `encodingLimits` defaults to the `EncodingLimits`
  // defaults because the committed generated round-trip tests construct this form without limits.
  XmlDecoder(const StructureFactory& structureFactory, xml::Element xmlElement,
    const EncodingLimits& encodingLimits, CodecNamespaceContext namespaceConfig = {});
  XmlDecoder(const XmlDecoder& other) = delete;
  XmlDecoder(XmlDecoder&& other) noexcept = delete;
  XmlDecoder& operator=(const XmlDecoder& other) = delete;
  XmlDecoder& operator=(XmlDecoder&& other) noexcept = delete;
  ~XmlDecoder() = default;

  void decode(StackDepth limit, string_view elementName, bool isOptional, bool& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, uint8_t& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, int8_t& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, uint16_t& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, int16_t& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, uint32_t& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, int32_t& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, uint64_t& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, int64_t& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, float& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, double& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, String& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, DateTime& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, XmlElement& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, Guid& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, ByteString& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, NodeId& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, ExpandedNodeId& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, StatusCode& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, QualifiedName& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, LocalizedText& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, DataValue& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, Decimal& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, DiagnosticInfo& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, Variant& value);

  void decode_matrix(StackDepth limit, string_view elementName, Variant& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, Structure& value);

  void decode(StackDepth limit, string_view elementName, bool isOptional, unique_ptr<Structure>& value);

  template<typename T>
    requires IsStructure<T>
  void decode(StackDepth limit, string_view elementName, bool isOptional, RefStructure<T>& value);

  template<typename T>
    requires IsStructure<T>
  void decode(StackDepth limit, string_view elementName, bool isOptional, unique_ptr<T>& value);

  template<typename T>
  void decode(StackDepth limit, string_view elementName, bool isOptional, Array<T>& value);

  // Array-of-enum: decode as `Array<int32_t>` (enums have no scalar XML decode
  // overload) and project back, mirroring the scalar enum codegen / binary codec.
  template<typename T>
    requires IsEnum<T>
  void decode(StackDepth limit, string_view elementName, bool isOptional, Array<T>& value);

private:
  // Throws Bad_EncodingLimitsExceeded when an array would hold `count` elements, more than the cap.
  void check_array_length(size_t count) const;

  CodecNamespaceContext mNamespaceConfig;
  StructureResolver mStructureResolver;
  optional<xml::Element> mXmlNextElement;
  const EncodingLimits mEncodingLimits;

  template<typename T>
  void decode_one_dim_array(StackDepth limit, string_view elementName, Array<T>& value);

  template<typename T>
  void decode_matrix(StackDepth limit, string_view elementName, Array<T>& value);

  void decode_variant_value(StackDepth limit, BuiltInTypeId typeId, bool isArray, Variant& value);

  std::tuple<BuiltInTypeId, bool, bool> get_variant_details(const xml::Element& xmlElement) const;

  static BuiltInTypeId get_built_in_type_id(string_view typeName);
};

template<typename T>
  requires IsStructure<T>
void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, RefStructure<T>& value)
{
  return decode(limit, elementName, isOptional, value.inner_unique_ptr());
}

template<typename T>
  requires IsStructure<T>
void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, unique_ptr<T>& value)
{
  unique_ptr<Structure> structure;
  decode(limit, elementName, isOptional, structure);
  if (structure)
  {
    if (dynamic_cast<T*>(structure.get()) != nullptr)
    {
      // Type confirmed by the dynamic_cast above; take ownership of the released pointer. reset() is
      // noexcept and nothing throws between release() and reset(), so there is no leak window.
      value.reset(static_cast<T*>(structure.release()));
    }
  }
}

template<typename T>
void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, Array<T>& value)
{
  using namespace xml_codec_details;

  // check_element_presence returns true only when mXmlNextElement is engaged; the
  // redundant `&& mXmlNextElement` makes that provable to the static analyser.
  if (check_element_presence(elementName, mXmlNextElement, isOptional) && mXmlNextElement)
  {
    if (auto dimensionsElement = mXmlNextElement->get_first_child("Dimensions"))
    {
      decode_matrix(limit, elementName, value);
    }
    else
    {
      decode_one_dim_array(limit, elementName, value);
    }
  }
}

template<typename T>
  requires IsEnum<T>
void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, Array<T>& value)
{
  Array<int32_t> raw;
  decode(limit, elementName, isOptional, raw);
  value.payload().clear();
  value.payload().reserve(raw.payload().size());
  for (const auto element : raw.payload())
  {
    value.payload().push_back(utils::from_underlying<T>(element));
  }
}

template<typename T>
void XmlDecoder::decode_one_dim_array(StackDepth limit, string_view elementName, Array<T>& value)
{
  using namespace xml_codec_details;

  // check_element_presence(..., false) throws unless mXmlNextElement is engaged; the redundant
  // `if (mXmlNextElement)` makes that engagement provable to the static analyser without changing
  // behaviour. Bind the engaged element to a local so the cursor's array root survives the
  // advances below.
  check_element_presence(elementName, mXmlNextElement, false);
  if (mXmlNextElement)
  {
    const xml::Element arrayXmlElement = *mXmlNextElement;

    // Decode each element through *this (not a throwaway sub-decoder). Every decode() advances
    // mXmlNextElement to the next sibling, so it doubles as the loop cursor - exactly as the
    // Structure decode path works. This also makes namespace-index translation transitive: the
    // mapper applied in decode(NodeId&)/decode(QualifiedName&)/decode(ExpandedNodeId&) reaches
    // array elements without any per-container wiring.
    mXmlNextElement = arrayXmlElement.get_first_child();
    while (mXmlNextElement)
    {
      check_array_length(value.payload().size() + 1);
      T val;
      decode(limit, mXmlNextElement->get_name(), false, val);
      value.payload().emplace_back(std::move(val));
    }

    mXmlNextElement = arrayXmlElement.get_next();
  }
}

template<typename T>
void XmlDecoder::decode_matrix(StackDepth limit, string_view elementName, Array<T>& value)
{
  using namespace xml_codec_details;

  // check_element_presence(..., false) throws unless mXmlNextElement is engaged; the redundant
  // `if (mXmlNextElement)` makes that engagement provable to the static analyser without changing
  // behaviour.
  check_element_presence(elementName, mXmlNextElement, false);
  if (!mXmlNextElement)
  {
    return;
  }

  // Bind the engaged array root to a local value so it survives the cursor advances below.
  const xml::Element arrayXmlElement = *mXmlNextElement;

  auto dimensionsElement = arrayXmlElement.get_first_child("Dimensions");
  check(dimensionsElement, Status::BadDecodingError);

  Dimensions dimensions;

  // `dimensionsElement` was just asserted engaged by `check`; the redundant `if` makes the deref
  // provable to the static analyser.
  if (dimensionsElement)
  {
    const xml::Element dimensionsXmlElement = *dimensionsElement;

    // Decode through *this so the cursor advance and (where relevant) translation flow naturally;
    // see decode_one_dim_array.
    mXmlNextElement = dimensionsXmlElement.get_first_child();
    while (mXmlNextElement)
    {
      check_array_length(dimensions.size() + 1);
      int32_t dim = 0;
      decode(limit, mXmlNextElement->get_name(), false, dim);
      dimensions.emplace_back(dim);
    }
  }

  const std::string wrapperTag = fmt::format("ListOf{}", get_typename<T>());
  auto matrixLocalName = [](string_view name) -> string_view
  {
    if (auto pos = name.find(':'); pos != string_view::npos)
    {
      return name.substr(pos + 1);
    }
    return name;
  };
  mXmlNextElement = arrayXmlElement.get_first_child();
  while (mXmlNextElement && matrixLocalName(mXmlNextElement->get_name()) != wrapperTag &&
         matrixLocalName(mXmlNextElement->get_name()) != "Elements")
  {
    mXmlNextElement = mXmlNextElement->get_next();
  }
  check(mXmlNextElement, Status::BadDecodingError);

  // `mXmlNextElement` was just asserted engaged by `check`; the redundant `if` makes the deref
  // provable to the static analyser.
  if (mXmlNextElement)
  {
    const xml::Element elementsWrapper = *mXmlNextElement;
    mXmlNextElement = elementsWrapper.get_first_child(get_typename<T>());
    while (mXmlNextElement)
    {
      check_array_length(value.payload().size() + 1);
      T val;
      decode(limit, mXmlNextElement->get_name(), false, val);
      value.payload().emplace_back(std::move(val));
    }
  }

  value.add_and_validate_dimensions(std::move(dimensions));

  mXmlNextElement = arrayXmlElement.get_next();
}

// template<typename T>
//   requires IsStructure<T>
// void XmlDecoder::decode_extension_object(StackDepth limit, string_view elementName, unique_ptr<T>& value)
// {
//   element.reset();
//
//   NodeId encodingId;
//   auto child = mXmlNextElement->get_first_child("TypeId");
//   if (child)
//   {
//     xml_codec_details::parse_element_value(limit, child, encodingId);
//   }
//
//   if (encodingId.is_null())
//   {
//     return;
//   }
//
//   unique_ptr<Structure> structure = mStructureFactory.create_instance(encodingId);
//   if (!structure)
//   {
//     throw UaException(Status::BadDecodingError, "Structure not found in factory");
//   }
//
//   mXmlNextElement = mXmlNextElement->get_first_child("Body");
//   if (!mXmlNextElement)
//   {
//     throw UaException(Status::BadDecodingError, "Structure encoded body not found");
//   }
//
//   Decoder decoder(*this);
//   structure->decode(limit, decoder);
//
//   try
//   {
//     unique_ptr<T> temp{dynamic_cast<T*>(structure.release())};
//     element = std::move(temp);
//   }
//   catch (const std::exception&)
//   {
//     throw UaException(Status::BadDecodingError, "Type mismatch");
//   }
// }

// template<>
// void XmlDecoder::decode(StackDepth limit, Array<bool>& value);
//
// template<typename T>
// void XmlDecoder::decode(StackDepth limit, Array<RefStructure<T>>& value)
// {
//   int32_t length{0};
//   decode(limit, length);
//
//   if (length <= 0)
//   {
//     element.clear();
//   }
//   else
//   {
//     element.resize(numeric_cast<size_t>(length));
//     for (auto& item : element.payload())
//     {
//       decode_extension_object(limit, item.inner_unique_ptr());
//     }
//   }
// }

// template<typename T>
// void XmlDecoder::decode_matrix(StackDepth limit, Array<T>& value)
//{
//   encode(limit, static_cast<ArrayBase&>(value), encodeAsOneDimensional);
//
//   for (auto item : element.payload())
//   {
//     encode(item);
//   }
// }

}  // namespace ua

#endif  //! UA_XML_CODEC_H
