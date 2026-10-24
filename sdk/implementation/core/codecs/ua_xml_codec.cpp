// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <map>
#include <type_traits>
#include <cmath>
#include <charconv>
#include <algorithm>
#include <vector>
#include <cstdint>
#include "ua_xml_codec.h"
#include "ua_error_detail.h"
#include "ua_decimal.h"
#include "ua_guid.h"
#include "ua_string.h"
#include "ua_xml_element.h"
#include "ua_date_time.h"
#include "ua_node_id.h"
#include "ua_to_string.h"
#include "ua_expanded_node_id.h"
#include "ua_qualified_name.h"
#include "ua_localized_text.h"
#include "ua_data_value.h"
#include "ua_diagnostic_info.h"
#include "ua_decimal.h"
#include "ua_variant.h"
#include "ua_structure.h"
#include "ua_structure_factory.h"
#include "ua_unknown_structure.h"
#include "ua_byte_string.h"
#include "ua_memory_stream.h"
#include "ua_xml_escape.h"
#include "ua_to_result.h"
#include "fmt/format.h"

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:4100)
#endif
#include "rapidxml/rapidxml.hpp"
#ifdef _WIN32
#pragma warning(pop)
#endif

using namespace rapidxml;

namespace ua
{

namespace
{

// Writes an element subtree exactly as the source spelled it. The document was parsed without entity
// translation, so every text and attribute value still holds its source escapes (`&amp;` stays
// `&amp;`); rapidxml's printer would escape them again and a preserved body would come back as
// `&amp;amp;` (security review XML-10). Bounded by the parser's nesting bound.
void serialize_node_verbatim(std::string& out, const rapidxml::xml_node<>* node, std::size_t depth)
{
  if (depth > xml::defaultMaxXmlElementDepth)
  {
    throw UaException(Status::BadEncodingLimitsExceeded,
      ErrorDetail::build(
        "XmlNestingTooDeep", "XML element nesting exceeds the depth the codec admits", "XmlCodec"));
  }
  switch (node->type())
  {
  case rapidxml::node_element:
    out.push_back('<');
    out.append(node->name(), node->name_size());
    for (const auto* attribute = node->first_attribute(); attribute; attribute = attribute->next_attribute())
    {
      out.push_back(' ');
      out.append(attribute->name(), attribute->name_size());
      // The value is written as the source spelled it (escapes untranslated). A source value
      // delimited by apostrophes may hold a raw quotation mark, so it keeps its apostrophes; a raw
      // apostrophe can only occur in a value that was delimited by quotation marks.
      const string_view value{attribute->value(), attribute->value_size()};
      const char quote = value.find('"') == string_view::npos ? '"' : '\'';
      out.push_back('=');
      out.push_back(quote);
      out.append(value.data(), value.size());
      out.push_back(quote);
    }
    if (!node->first_node())
    {
      out.append("/>", 2);
      return;
    }
    out.push_back('>');
    for (const auto* child = node->first_node(); child; child = child->next_sibling())
    {
      serialize_node_verbatim(out, child, depth + 1);
    }
    out.append("</", 2);
    out.append(node->name(), node->name_size());
    out.push_back('>');
    return;
  case rapidxml::node_data:
    out.append(node->value(), node->value_size());
    return;
  case rapidxml::node_cdata:
    out.append("<![CDATA[", 9);
    out.append(node->value(), node->value_size());
    out.append("]]>", 3);
    return;
  case rapidxml::node_comment:
    out.append("<!--", 4);
    out.append(node->value(), node->value_size());
    out.append("-->", 3);
    return;
  case rapidxml::node_pi:
    out.append("<?", 2);
    out.append(node->name(), node->name_size());
    out.push_back(' ');
    out.append(node->value(), node->value_size());
    out.append("?>", 2);
    return;
  default:
    return;
  }
}

std::string serialize_subtree_verbatim(const xml::Element& element)
{
  std::string out;
  serialize_node_verbatim(out, reinterpret_cast<const rapidxml::xml_node<>*>(element.handle()), 0);
  return out;
}

}  // namespace

using ua::xml_detail::write_raw;
using ua::xml_detail::xml_escape;

namespace xml_codec_details
{

bool check_element_presence(string_view elementName, const optional<xml::Element>& element, bool isOptional)
{
  auto localName = [](string_view name) -> string_view
  {
    if (auto pos = name.find(':'); pos != string_view::npos)
    {
      return name.substr(pos + 1);
    }
    return name;
  };

  bool elementPresent{false};
  if (element)
  {
    if (!elementName.empty())
    {
      if (localName(elementName) == localName(element->get_name()))
      {
        elementPresent = true;
      }
    }
    else
    {
      elementPresent = true;
    }
  }

  if (!elementPresent)
  {
    if (isOptional)
    {
      return false;
    }
    else
    {
      throw UaException(Status::BadDecodingError,
        ErrorDetail::build("DecodingFailed", "Required XML element not present", "XmlCodec")
          .context(ua::ContextKeys::fieldName, std::string(elementName)));
    }
  }

  return true;
}

static void parse_element_value(const xml::Element& element, auto& value)
{
  xml::parser::parse(element.get_value(), value);
}

static void decode_element(
  optional<xml::Element>& element, string_view elementName, bool isOptional, auto& value)
{
  // check_element_presence returns true only when `element` is engaged (it throws or
  // returns false otherwise); the redundant `if (element)` makes that provable to the
  // static analyser without changing behaviour.
  if (check_element_presence(elementName, element, isOptional) && element)
  {
    parse_element_value(*element, value);
    element = element->get_next();
  }
}

template<typename T>
static void decode_value(StackDepth limit, XmlDecoder& decoder, bool isArray, Variant& value)
{
  if (isArray)
  {
    Array<T> result;
    decoder.decode(limit, "", false, result);
    value = std::move(result);
  }
  else
  {
    T result;
    decoder.decode(limit, "", false, result);
    value = std::move(result);
  }
}

template<>
void decode_value<Variant>(StackDepth limit, XmlDecoder& decoder, bool isArray, Variant& value)
{
  if (isArray)
  {
    Array<Variant> result;
    decoder.decode(limit, "", false, result);
    value = std::move(result);
  }
  else
  {
    throw UaException(Status::BadNotSupported,
      make_error_detail("UnsupportedEncoding", "A Variant cannot contain a scalar Variant", "XmlCodec"));
  }
}

template<>
void decode_value<Structure>(StackDepth limit, XmlDecoder& decoder, bool isArray, Variant& value)
{
  if (isArray)
  {
    Array<RefStructure<Structure>> result;
    decoder.decode(limit, "", false, result);
    value = std::move(result);
  }
  else
  {
    unique_ptr<Structure> result;
    decoder.decode(limit, "", false, result);
    value = std::move(result);
  }
}

}  // namespace xml_codec_details

using namespace xml_codec_details;

XmlEncoder::XmlEncoder(const CodecNamespaceContext& namespaceConfig, Stream& stream)
  : mNamespaceConfig(namespaceConfig), mStream(stream)
{}

void XmlEncoder::write_start_element(string_view name, string_view xmlnsUri)
{
  write_raw(mStream, "<");
  write_raw(mStream, name);
  if (!xmlnsUri.empty())
  {
    write_raw(mStream, " xmlns=\"");
    write_raw(mStream, xml_escape(xmlnsUri, /*attribute*/ true));
    write_raw(mStream, "\"");
  }
  write_raw(mStream, ">");
}

void XmlEncoder::write_end_element(string_view name)
{
  write_raw(mStream, "</");
  write_raw(mStream, name);
  write_raw(mStream, ">");
}

void XmlEncoder::write_text(string_view text)
{
  auto escaped = xml_escape(text);
  write_raw(mStream, escaped);
}

template<typename T>
void XmlEncoder::write_number(string_view name, T value)
{
  UA_UNUSED(mNamespaceConfig);
  const ElementScope scope(*this, name);
  if constexpr (std::is_floating_point_v<T>)
  {
    // Part 6 5.3.1.4 maps Float and Double to xs:float and xs:double, whose lexical forms for the
    // special values are NaN, INF and -INF; the formatter would write nan and inf (security review
    // XML-11). The reader accepts both spellings.
    if (std::isnan(value))
    {
      write_text("NaN");
      return;
    }
    if (std::isinf(value))
    {
      write_text(value > 0 ? "INF" : "-INF");
      return;
    }
  }
  auto s = fmt::format("{}", value);
  write_text(s);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, bool value)
{
  limit.consume_edge();
  const ElementScope scope(*this, elementName);
  write_text(value ? "true" : "false");
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, uint8_t value)
{
  limit.consume_edge();
  write_number(elementName, +value);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, int8_t value)
{
  limit.consume_edge();
  write_number(elementName, +value);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, uint16_t value)
{
  limit.consume_edge();
  write_number(elementName, value);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, int16_t value)
{
  limit.consume_edge();
  write_number(elementName, value);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, uint32_t value)
{
  limit.consume_edge();
  write_number(elementName, value);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, int32_t value)
{
  limit.consume_edge();
  write_number(elementName, value);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, uint64_t value)
{
  limit.consume_edge();
  write_number(elementName, value);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, int64_t value)
{
  limit.consume_edge();
  write_number(elementName, value);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, float value)
{
  limit.consume_edge();
  write_number(elementName, value);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, double value)
{
  limit.consume_edge();
  write_number(elementName, value);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, string_view value)
{
  limit.consume_edge();
  if (!value.empty())
  {
    const ElementScope scope(*this, elementName);
    write_text(value);
  }
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const String& value)
{
  limit.consume_edge();
  const ElementScope scope(*this, elementName);
  write_text(static_cast<string_view>(value));
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const DateTime& value)
{
  limit.consume_edge();
  write_start_element(elementName);
  write_text(value.as_iso_string());
  write_end_element(elementName);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const Guid& value)
{
  limit.consume_edge();
  if (!value.is_null())
  {
    write_start_element(elementName);
    write_text(value.as_string());
    write_end_element(elementName);
  }
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const ByteString& value)
{
  limit.consume_edge();
  write_start_element(elementName);
  if (!value.empty())
  {
    write_text(utils::base64_encode(value));
  }
  write_end_element(elementName);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const NodeId& value)
{
  limit.consume_edge();
  NodeId translated = value;
  if (mNamespaceConfig.translateNodeId)
  {
    mNamespaceConfig.translateNodeId(translated);
  }

  write_start_element(elementName);
  if (!translated.is_null())
  {
    std::string definition;
    switch (translated.id_type())
    {
    case IdType::Numeric:
      definition = fmt::format("i={}", translated.identifier().get_numeric());
      break;
    case IdType::String:
      definition = fmt::format("s={}", static_cast<string_view>(translated.identifier().get_string()));
      break;
    case IdType::Guid:
      definition = fmt::format("g={}", translated.identifier().get_guid().as_string());
      break;
    case IdType::Opaque:
      definition = fmt::format("b={}", utils::base64_encode(translated.identifier().get_opaque()));
      break;
    }

    if (translated.namespace_index() != 0)
    {
      definition = fmt::format("ns={};{}", translated.namespace_index(), definition);
    }

    write_start_element("Identifier");
    write_text(definition);
    write_end_element("Identifier");
  }
  write_end_element(elementName);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const ExpandedNodeId& value)
{
  // OPC UA Part 6 says ExpandedNodeId is encoded as NodeId plus optional NamespaceUri and ServerIndex
  limit.consume_edge();
  ExpandedNodeId translated = value;
  if (mNamespaceConfig.translateExpandedNodeId)
  {
    mNamespaceConfig.translateExpandedNodeId(translated);
  }

  write_start_element(elementName);
  if (!translated.is_null())
  {
    encode(limit, "NodeId", translated.node_id());
    if (!translated.namespace_uri().empty())
    {
      encode(limit, "NamespaceUri", static_cast<string_view>(translated.namespace_uri()));
    }
    if (translated.server_index() != 0)
    {
      encode(limit, "ServerIndex", translated.server_index());
    }
  }
  write_end_element(elementName);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const StatusCode& value)
{
  limit.consume_edge();
  write_number(elementName, value.as_uint32());
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const QualifiedName& value)
{
  limit.consume_edge();
  QualifiedName translated = value;
  if (mNamespaceConfig.translateQualifiedName)
  {
    mNamespaceConfig.translateQualifiedName(translated);
  }

  write_start_element(elementName);
  if (translated.namespace_index() != 0)
  {
    write_number("NamespaceIndex", translated.namespace_index());
  }
  encode(limit, "Name", static_cast<string_view>(translated.name()));
  write_end_element(elementName);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const LocalizedText& value)
{
  limit.consume_edge();
  const ElementScope scope(*this, elementName);
  if (!value.locale().empty())
  {
    encode(limit, "Locale", static_cast<string_view>(value.locale()));
  }
  if (!value.text().empty())
  {
    encode(limit, "Text", static_cast<string_view>(value.text()));
  }
}

namespace
{

// A raw XML payload (an XmlElement value, a preserved opaque body) is written into the document
// verbatim, so it must be exactly one well-formed element: a payload holding a stray closing tag,
// a second top-level element or bare text would end the enclosing element and author nodes of its
// own in the export (security review XML-3). Scanned once for the XML 1.0 rules and the default
// nesting bound together (xml::parse_well_formed_payload), then parsed once, non-destructively.
// Cost: one scan and one parse of the payload per emission; the payload is peer-supplied text that is
// emitted only on export.
void require_single_well_formed_element(string_view payload, const char* what)
{
  if (payload.empty())
  {
    return;
  }
  const std::string terminated{payload};
  const char* violation = nullptr;
  try
  {
    const xml::WellFormedPayload scanned =
      xml::parse_well_formed_payload(terminated, xml::defaultMaxXmlElementDepth);
    violation = scanned.violation;
    if (scanned.context.has_value())
    {
      // `xml_element()` is the document node; the payload's elements are its children. Declarations,
      // comments and processing instructions are not kept as nodes and bare text at document level is
      // a parse error, so the children are the payload's top-level elements.
      const auto root = scanned.context->xml_element().get_first_child();
      if (!root.has_value() || root->get_next().has_value())
      {
        throw UaException(Status::BadEncodingError,
          ErrorDetail::build(
            "XmlPayloadNotOneElement", "A raw XML payload must be exactly one element", "XmlCodec")
            .context(ua::ContextKeys::fieldName, what));
      }
    }
  }
  catch (...)
  {
    // The nesting bound keeps its own status; any other refusal by the parser (an unbalanced close tag
    // among them, or the parser's own exception type) is this encoder's Bad_EncodingError, with the
    // parser's reason as its cause.
    const StatusCode error = ua::exception_to_status_code(std::current_exception());
    const auto& errorDetail = error.shared_detail();
    if (error.as_status() == Status::BadEncodingLimitsExceeded ||
        (errorDetail != nullptr && errorDetail->code == "XmlPayloadNotOneElement"))
    {
      throw;
    }
    throw UaException(Status::BadEncodingError,
      ErrorDetail::build("XmlPayloadNotWellFormed", "A raw XML payload is not well-formed XML", "XmlCodec")
        .context(ua::ContextKeys::fieldName, what)
        .cause(error));
  }
  if (violation != nullptr)
  {
    throw UaException(Status::BadEncodingError,
      ErrorDetail::build("XmlPayloadNotWellFormed", "A raw XML payload is not well-formed XML", "XmlCodec")
        .context(ua::ContextKeys::fieldName, what)
        .context(ua::ContextKeys::errorMessage, violation));
  }
}

}  // namespace

void XmlEncoder::encode(StackDepth limit, string_view elementName, const XmlElement& value)
{
  limit.consume_edge();
  const ElementScope scope(*this, elementName);
  // XmlElement payload is already serialized XML: embed verbatim, no re-escaping, once it is known
  // to be one well-formed element.
  require_single_well_formed_element(value.value(), "XmlElement");
  write_raw(mStream, value.value());
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const DataValue& value)
{
  limit.consume_edge();
  const ElementScope scope(*this, elementName);
  // DataValue has multiple optional fields
  if (!value.value().empty())
  {
    encode(limit, "Value", value.value());
  }
  if (const auto& status = value.status(); status)
  {
    encode(limit, "StatusCode", *status);
  }
  if (const auto& sourceTimestamp = value.source_timestamp(); sourceTimestamp)
  {
    encode(limit, "SourceTimestamp", *sourceTimestamp);
  }
  if (const auto& sourcePicoSeconds = value.source_pico_seconds(); sourcePicoSeconds)
  {
    encode(limit, "SourcePicoseconds", *sourcePicoSeconds);
  }
  if (const auto& serverTimestamp = value.server_timestamp(); serverTimestamp)
  {
    encode(limit, "ServerTimestamp", *serverTimestamp);
  }
  if (const auto& serverPicoSeconds = value.server_pico_seconds(); serverPicoSeconds)
  {
    encode(limit, "ServerPicoseconds", *serverPicoSeconds);
  }
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const DiagnosticInfo& value)
{
  limit.consume_edge();
  const ElementScope scope(*this, elementName);
  if (const auto& symbolicId = value.symbolic_id(); symbolicId)
    encode(limit, "SymbolicId", *symbolicId);
  if (const auto& namespaceUri = value.namespace_uri(); namespaceUri)
    encode(limit, "NamespaceUri", *namespaceUri);
  if (const auto& locale = value.locale(); locale)
    encode(limit, "Locale", *locale);
  if (const auto& localizedText = value.localized_text(); localizedText)
    encode(limit, "LocalizedText", *localizedText);
  if (const auto& additionalInfo = value.additional_info(); additionalInfo)
    encode(limit, "AdditionalInfo", static_cast<string_view>(*additionalInfo));
  if (const auto& innerStatusCode = value.inner_status_code(); innerStatusCode)
    encode(limit, "InnerStatusCode", *innerStatusCode);
  if (value.inner_diagnostic_info())
    encode(limit, "InnerDiagnosticInfo", *value.inner_diagnostic_info());
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const Variant& value)
{
  const ElementScope outer(*this, elementName);

  if (value.empty())
  {
    return;
  }

  const bool isArray = value.is_array();
  string_view typeName = get_typename<Variant>();
  const BuiltInTypeId typeId = value.get_built_in_type();

  // Matrix wrapper must outlive the ListOfT emission, thus use a heap-held scope
  std::unique_ptr<ElementScope> matrixScope;
  if (isArray)
  {
    if (const auto& arrayDimensions = value.get_array_base().dimensions(); arrayDimensions.has_value())
    {
      matrixScope = std::make_unique<ElementScope>(*this, "Matrix");
      {
        const ElementScope dims(*this, "Dimensions");
        for (auto dim : *arrayDimensions)
        {
          encode(limit, "Int32", dim);
        }
      }
    }
    // Elements tag is NOT used in Part 6 XML encoding for Matrix.
    // It just follows Dimensions with the ListOfT tag.
  }

  switch (typeId)
  {
  case BuiltInTypeId::Boolean:
    typeName = get_typename<bool>();
    break;
  case BuiltInTypeId::SByte:
    typeName = get_typename<int8_t>();
    break;
  case BuiltInTypeId::Byte:
    typeName = get_typename<uint8_t>();
    break;
  case BuiltInTypeId::Int16:
    typeName = get_typename<int16_t>();
    break;
  case BuiltInTypeId::UInt16:
    typeName = get_typename<uint16_t>();
    break;
  case BuiltInTypeId::Int32:
    typeName = get_typename<int32_t>();
    break;
  case BuiltInTypeId::UInt32:
    typeName = get_typename<uint32_t>();
    break;
  case BuiltInTypeId::Int64:
    typeName = get_typename<int64_t>();
    break;
  case BuiltInTypeId::UInt64:
    typeName = get_typename<uint64_t>();
    break;
  case BuiltInTypeId::Float:
    typeName = get_typename<float>();
    break;
  case BuiltInTypeId::Double:
    typeName = get_typename<double>();
    break;
  case BuiltInTypeId::String:
    typeName = get_typename<String>();
    break;
  case BuiltInTypeId::DateTime:
    typeName = get_typename<DateTime>();
    break;
  case BuiltInTypeId::Guid:
    typeName = get_typename<Guid>();
    break;
  case BuiltInTypeId::ByteString:
    typeName = get_typename<ByteString>();
    break;
  case BuiltInTypeId::XmlElement:
    typeName = get_typename<XmlElement>();
    break;
  case BuiltInTypeId::NodeId:
    typeName = get_typename<NodeId>();
    break;
  case BuiltInTypeId::ExpandedNodeId:
    typeName = get_typename<ExpandedNodeId>();
    break;
  case BuiltInTypeId::StatusCode:
    typeName = get_typename<StatusCode>();
    break;
  case BuiltInTypeId::QualifiedName:
    typeName = get_typename<QualifiedName>();
    break;
  case BuiltInTypeId::LocalizedText:
    typeName = get_typename<LocalizedText>();
    break;
  case BuiltInTypeId::ExtensionObject:
    typeName = "ExtensionObject";
    break;
  case BuiltInTypeId::DataValue:
    typeName = get_typename<DataValue>();
    break;
  case BuiltInTypeId::Variant:
    typeName = get_typename<Variant>();
    break;
  default:
    break;
  }

  const std::string wrapperTag = fmt::format("ListOf{}", typeName);
  if (isArray)
  {
    switch (typeId)
    {
    case BuiltInTypeId::Boolean:
      encode(limit, wrapperTag, value.as<Array<bool>>());
      break;
    case BuiltInTypeId::SByte:
      encode(limit, wrapperTag, value.as<Array<int8_t>>());
      break;
    case BuiltInTypeId::Byte:
      encode(limit, wrapperTag, value.as<Array<uint8_t>>());
      break;
    case BuiltInTypeId::Int16:
      encode(limit, wrapperTag, value.as<Array<int16_t>>());
      break;
    case BuiltInTypeId::UInt16:
      encode(limit, wrapperTag, value.as<Array<uint16_t>>());
      break;
    case BuiltInTypeId::Int32:
      encode(limit, wrapperTag, value.as<Array<int32_t>>());
      break;
    case BuiltInTypeId::UInt32:
      encode(limit, wrapperTag, value.as<Array<uint32_t>>());
      break;
    case BuiltInTypeId::Int64:
      encode(limit, wrapperTag, value.as<Array<int64_t>>());
      break;
    case BuiltInTypeId::UInt64:
      encode(limit, wrapperTag, value.as<Array<uint64_t>>());
      break;
    case BuiltInTypeId::Float:
      encode(limit, wrapperTag, value.as<Array<float>>());
      break;
    case BuiltInTypeId::Double:
      encode(limit, wrapperTag, value.as<Array<double>>());
      break;
    case BuiltInTypeId::String:
      encode(limit, wrapperTag, value.as<Array<String>>());
      break;
    case BuiltInTypeId::DateTime:
      encode(limit, wrapperTag, value.as<Array<DateTime>>());
      break;
    case BuiltInTypeId::Guid:
      encode(limit, wrapperTag, value.as<Array<Guid>>());
      break;
    case BuiltInTypeId::ByteString:
      encode(limit, wrapperTag, value.as<Array<ByteString>>());
      break;
    case BuiltInTypeId::XmlElement:
      encode(limit, wrapperTag, value.as<Array<XmlElement>>());
      break;
    case BuiltInTypeId::NodeId:
      encode(limit, wrapperTag, value.as<Array<NodeId>>());
      break;
    case BuiltInTypeId::ExpandedNodeId:
      encode(limit, wrapperTag, value.as<Array<ExpandedNodeId>>());
      break;
    case BuiltInTypeId::StatusCode:
      encode(limit, wrapperTag, value.as<Array<StatusCode>>());
      break;
    case BuiltInTypeId::QualifiedName:
      encode(limit, wrapperTag, value.as<Array<QualifiedName>>());
      break;
    case BuiltInTypeId::LocalizedText:
      encode(limit, wrapperTag, value.as<Array<LocalizedText>>());
      break;
    case BuiltInTypeId::ExtensionObject:
      encode(limit, wrapperTag, value.as<Array<RefStructure<Structure>>>());
      break;
    case BuiltInTypeId::DataValue:
      encode(limit, wrapperTag, value.as<Array<DataValue>>());
      break;
    case BuiltInTypeId::Variant:
      encode(limit, wrapperTag, value.as<Array<Variant>>());
      break;
    default:
      break;
    }
  }
  else
  {
    switch (typeId)
    {
    case BuiltInTypeId::Boolean:
      encode(limit, typeName, value.as<bool>());
      break;
    case BuiltInTypeId::SByte:
      encode(limit, typeName, value.as<int8_t>());
      break;
    case BuiltInTypeId::Byte:
      encode(limit, typeName, value.as<uint8_t>());
      break;
    case BuiltInTypeId::Int16:
      encode(limit, typeName, value.as<int16_t>());
      break;
    case BuiltInTypeId::UInt16:
      encode(limit, typeName, value.as<uint16_t>());
      break;
    case BuiltInTypeId::Int32:
      encode(limit, typeName, value.as<int32_t>());
      break;
    case BuiltInTypeId::UInt32:
      encode(limit, typeName, value.as<uint32_t>());
      break;
    case BuiltInTypeId::Int64:
      encode(limit, typeName, value.as<int64_t>());
      break;
    case BuiltInTypeId::UInt64:
      encode(limit, typeName, value.as<uint64_t>());
      break;
    case BuiltInTypeId::Float:
      encode(limit, typeName, value.as<float>());
      break;
    case BuiltInTypeId::Double:
      encode(limit, typeName, value.as<double>());
      break;
    case BuiltInTypeId::String:
      encode(limit, typeName, value.as<String>());
      break;
    case BuiltInTypeId::DateTime:
      encode(limit, typeName, value.as<DateTime>());
      break;
    case BuiltInTypeId::Guid:
      encode(limit, typeName, value.as<Guid>());
      break;
    case BuiltInTypeId::ByteString:
      encode(limit, typeName, value.as<ByteString>());
      break;
    case BuiltInTypeId::XmlElement:
      encode(limit, typeName, value.as<XmlElement>());
      break;
    case BuiltInTypeId::NodeId:
      encode(limit, typeName, value.as<NodeId>());
      break;
    case BuiltInTypeId::ExpandedNodeId:
      encode(limit, typeName, value.as<ExpandedNodeId>());
      break;
    case BuiltInTypeId::StatusCode:
      encode(limit, typeName, value.as<StatusCode>());
      break;
    case BuiltInTypeId::QualifiedName:
      encode(limit, typeName, value.as<QualifiedName>());
      break;
    case BuiltInTypeId::LocalizedText:
      encode(limit, typeName, value.as<LocalizedText>());
      break;
    case BuiltInTypeId::ExtensionObject:
    {
      // Route through the full ExtensionObject form (TypeId + Body + type-named wrapper). The bare
      // `const Structure&` overload omits TypeId/Body and would lose the type identity on round-trip.
      const auto& ref = value.as<RefStructure<Structure>>();
      encode(limit, typeName, ref.get());
      break;
    }
    case BuiltInTypeId::DataValue:
      encode(limit, typeName, value.as<DataValue>());
      break;
    case BuiltInTypeId::Variant:
      encode(limit, typeName, value.as<Variant>());
      break;
    default:
      break;
    }
  }
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const Decimal& value)
{
  const ElementScope scope(*this, elementName);
  encode(limit, "Scale", value.scale());
  encode(limit, "Value", value.value());
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, Decimal& value)
{
  limit.consume_edge();
  // check_element_presence returns true only when mXmlNextElement is engaged; the
  // redundant `&& mXmlNextElement` makes that provable to the static analyser.
  if (check_element_presence(elementName, mXmlNextElement, isOptional) && mXmlNextElement)
  {
    if (auto element = mXmlNextElement->get_first_child("Scale"))
    {
      parse_element_value(*element, value.scale());
    }
    if (auto element = mXmlNextElement->get_first_child("Value"))
    {
      parse_element_value(*element, value.value());
    }
    mXmlNextElement = mXmlNextElement->get_next();
  }
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const Structure& value)
{
  const ElementScope scope(*this, elementName);
  Encoder encoder(*this);
  value.encode(limit, encoder);
}

void XmlEncoder::encode(StackDepth limit, string_view elementName, const Structure* value)
{
  if (const auto* unknown = dynamic_cast<const UnknownStructure*>(value))
  {
    // Re-emit a preserved (unresolved) body. Only an XML-sourced body can be written here verbatim;
    // a binary-sourced body cannot be re-encoded as XML (we do not hold the XML encoding id and
    // cannot transcode the bytes), so fail loudly rather than fabricate.
    if (unknown->body_encoding() != UnknownStructure::BodyEncoding::Xml)
    {
      throw UaException(Status::BadNotSupported,
        ErrorDetail::build("UnknownStructureError",
          "Cannot re-encode a binary-sourced opaque ExtensionObject as XML",
          "XmlCodec")
          .context(ua::ContextKeys::nodeId, ua::to_string(unknown->encoding_id())));
    }

    const ElementScope outer(*this, elementName);
    encode(limit, "TypeId", unknown->encoding_id());

    // The preserved bytes are the entire <Body> subtree, so write them raw - do not wrap again -
    // once they are known to be one well-formed element.
    const ByteString& raw = unknown->encoded_data();
    if (!raw.empty())
    {
      const string_view body{utils::bytes_to_chars(raw.data()), raw.size()};
      require_single_well_formed_element(body, "ExtensionObject.Body");
      write_raw(mStream, body);
    }
    return;
  }

  // Open the ExtensionObject element for both the resolved and the null cases. A null value yields
  // an empty `<ExtensionObject/>` (no TypeId), which the decoder reads back as a null placeholder.
  const ElementScope outer(*this, elementName);
  if (value)
  {
    // Write the encoding id (DefaultXmlEncodingId) as the TypeId.
    Encoder encoder(*this);
    value->encode_id(limit, mNamespaceConfig, encoder);

    // Write the body. The fields are wrapped in an element named after the structure type, with the
    // type's namespace URI declared as the default xmlns. Generated structure encode() methods emit
    // unprefixed field elements, so they inherit this default namespace - and the decoder's resolved
    // path reads the body's first child as exactly this wrapper. `typeId`/`wrapperName` are held in
    // named locals so the string_views the ElementScope retains stay valid for its lifetime.
    const ElementScope body(*this, "Body");
    const ExpandedNodeId typeId = value->type_id();
    const String wrapperName = value->type_name();
    const ElementScope wrapper(
      *this, static_cast<string_view>(wrapperName), static_cast<string_view>(typeId.namespace_uri()));
    value->encode(limit, encoder);
  }
}

XmlDecoder::XmlDecoder(StructureResolver structureResolver, xml::Element xmlElement,
  const EncodingLimits& encodingLimits, CodecNamespaceContext namespaceConfig)
  : mNamespaceConfig(std::move(namespaceConfig)), mStructureResolver(std::move(structureResolver)),
    mXmlNextElement(xmlElement), mEncodingLimits(encodingLimits)
{}

XmlDecoder::XmlDecoder(const StructureFactory& structureFactory, xml::Element xmlElement,
  const EncodingLimits& encodingLimits, CodecNamespaceContext namespaceConfig)
  : XmlDecoder(structureFactory.resolver(), xmlElement, encodingLimits, std::move(namespaceConfig))
{}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, bool& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::check_array_length(size_t count) const
{
  if (count > mEncodingLimits.maxArrayLength)
  {
    throw UaException(Status::BadEncodingLimitsExceeded,
      ErrorDetail::build(
        "XmlArrayTooLong", "An XML array holds more elements than the maximum array length", "XmlCodec")
        .context(ua::ContextKeys::max, std::to_string(mEncodingLimits.maxArrayLength)));
  }
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, uint8_t& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, int8_t& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, uint16_t& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, int16_t& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, uint64_t& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, int64_t& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, float& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, double& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, DateTime& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, XmlElement& value)
{
  limit.consume_edge();
  // check_element_presence returns true only when mXmlNextElement is engaged; the
  // redundant `&& mXmlNextElement` makes that provable to the static analyser.
  if (check_element_presence(elementName, mXmlNextElement, isOptional) && mXmlNextElement)
  {
    value = string_view{serialize_subtree_verbatim(*mXmlNextElement)};
    mXmlNextElement = mXmlNextElement->get_next();
  }
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, Guid& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, ByteString& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, ExpandedNodeId& value)
{
  limit.consume_edge();
  // check_element_presence returns true only when mXmlNextElement is engaged; the
  // redundant `&& mXmlNextElement` makes that provable to the static analyser.
  if (check_element_presence(elementName, mXmlNextElement, isOptional) && mXmlNextElement)
  {
    if (auto element = mXmlNextElement->get_first_child("NodeId"))
    {
      auto current = mXmlNextElement;
      mXmlNextElement = element;
      decode(limit, "NodeId", false, value.node_id());
      mXmlNextElement = current;
    }
    if (auto element = mXmlNextElement->get_first_child("NamespaceUri"))
    {
      parse_element_value(*element, value.namespace_uri());
    }
    if (auto element = mXmlNextElement->get_first_child("ServerIndex"))
    {
      parse_element_value(*element, value.server_index());
    }

    if (mNamespaceConfig.translateExpandedNodeId)
    {
      mNamespaceConfig.translateExpandedNodeId(value);
    }

    mXmlNextElement = mXmlNextElement->get_next();
  }
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, StatusCode& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, QualifiedName& value)
{
  limit.consume_edge();
  // check_element_presence returns true only when mXmlNextElement is engaged; the
  // redundant `&& mXmlNextElement` makes that provable to the static analyser.
  if (check_element_presence(elementName, mXmlNextElement, isOptional) && mXmlNextElement)
  {
    if (auto element = mXmlNextElement->get_first_child("NamespaceIndex"))
    {
      parse_element_value(*element, value.namespace_index());
    }
    if (auto element = mXmlNextElement->get_first_child("Name"))
    {
      parse_element_value(*element, value.name());
    }

    if (mNamespaceConfig.translateQualifiedName)
    {
      mNamespaceConfig.translateQualifiedName(value);
    }

    mXmlNextElement = mXmlNextElement->get_next();
  }
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, DataValue& value)
{
  // Bound the structural-descent (a DataValue carries a Variant that may nest); released on unwind.
  const auto depthGuard = limit.enter_recursion();
  limit.consume_edge();
  // check_element_presence returns true only when mXmlNextElement is engaged; the
  // redundant `&& mXmlNextElement` makes that provable to the static analyser.
  if (check_element_presence(elementName, mXmlNextElement, isOptional) && mXmlNextElement)
  {
    if (auto element = mXmlNextElement->get_first_child("Value"))
    {
      auto dataValueElement = mXmlNextElement;
      mXmlNextElement = element;
      check(mXmlNextElement);
      decode(limit, "", false, value.value());
      mXmlNextElement = dataValueElement;
    }
    if (auto element = mXmlNextElement->get_first_child("StatusCode"))
    {
      StatusCode statusCode;
      parse_element_value(*element, statusCode);
      value.status() = statusCode;
    }
    if (auto element = mXmlNextElement->get_first_child("SourceTimestamp"))
    {
      DateTime timestamp;
      parse_element_value(*element, timestamp);
      value.source_timestamp() = timestamp;
    }
    if (auto element = mXmlNextElement->get_first_child("SourcePicoseconds"))
    {
      uint16_t picoseconds = 0;
      parse_element_value(*element, picoseconds);
      value.source_pico_seconds() = picoseconds;
    }
    if (auto element = mXmlNextElement->get_first_child("ServerTimestamp"))
    {
      DateTime timestamp;
      parse_element_value(*element, timestamp);
      value.server_timestamp() = timestamp;
    }
    if (auto element = mXmlNextElement->get_first_child("ServerPicoseconds"))
    {
      uint16_t picoseconds = 0;
      parse_element_value(*element, picoseconds);
      value.server_pico_seconds() = picoseconds;
    }
    mXmlNextElement = mXmlNextElement->get_next();
  }
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, DiagnosticInfo& value)
{
  // Bound the structural-descent (nested InnerDiagnosticInfo recurses here); released on unwind.
  const auto depthGuard = limit.enter_recursion();
  limit.consume_edge();
  // check_element_presence returns true only when mXmlNextElement is engaged; the
  // redundant `&& mXmlNextElement` makes that provable to the static analyser.
  if (check_element_presence(elementName, mXmlNextElement, isOptional) && mXmlNextElement)
  {
    if (auto element = mXmlNextElement->get_first_child("SymbolicId"))
    {
      int32_t id = 0;
      parse_element_value(*element, id);
      value.symbolic_id() = id;
    }
    if (auto element = mXmlNextElement->get_first_child("NamespaceUri"))
    {
      int32_t id = 0;
      parse_element_value(*element, id);
      value.namespace_uri() = id;
    }
    if (auto element = mXmlNextElement->get_first_child("Locale"))
    {
      int32_t id = 0;
      parse_element_value(*element, id);
      value.locale() = id;
    }
    if (auto element = mXmlNextElement->get_first_child("LocalizedText"))
    {
      int32_t id = 0;
      parse_element_value(*element, id);
      value.localized_text() = id;
    }
    if (auto element = mXmlNextElement->get_first_child("AdditionalInfo"))
    {
      String info;
      parse_element_value(*element, info);
      value.additional_info() = info;
    }
    if (auto element = mXmlNextElement->get_first_child("InnerStatusCode"))
    {
      StatusCode statusCode;
      parse_element_value(*element, statusCode);
      value.inner_status_code() = statusCode;
    }
    if (auto element = mXmlNextElement->get_first_child("InnerDiagnosticInfo"))
    {
      auto diagnosticInfoElement = mXmlNextElement;
      mXmlNextElement = element;
      auto diagnosticInfo = make_unique<DiagnosticInfo>();
      decode(limit, "", false, *diagnosticInfo);
      value.inner_diagnostic_info() = std::move(diagnosticInfo);
      mXmlNextElement = diagnosticInfoElement;
    }
    mXmlNextElement = mXmlNextElement->get_next();
  }
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, uint32_t& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, int32_t& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, String& value)
{
  limit.consume_edge();
  decode_element(mXmlNextElement, elementName, isOptional, value);
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, NodeId& value)
{
  limit.consume_edge();
  // check_element_presence returns true only when mXmlNextElement is engaged; the
  // redundant `&& mXmlNextElement` makes that provable to the static analyser.
  if (check_element_presence(elementName, mXmlNextElement, isOptional) && mXmlNextElement)
  {
    if (auto identifier = mXmlNextElement->get_first_child("Identifier"))
    {
      parse_element_value(*identifier, value);
    }
    else if (!mXmlNextElement->get_value().empty())
    {
      // Some encodings (including NodeSet `<Value>` representations) encode NodeId directly as text,
      // e.g. `<uax:NodeId>ns=1;i=5001</uax:NodeId>`.
      parse_element_value(*mXmlNextElement, value);
    }
    else
    {
      value = NodeId{};
    }

    if (mNamespaceConfig.translateNodeId)
    {
      mNamespaceConfig.translateNodeId(value);
    }

    mXmlNextElement = mXmlNextElement->get_next();
  }
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, LocalizedText& value)
{
  limit.consume_edge();
  // check_element_presence returns true only when mXmlNextElement is engaged; the
  // redundant `&& mXmlNextElement` makes that provable to the static analyser.
  if (check_element_presence(elementName, mXmlNextElement, isOptional) && mXmlNextElement)
  {
    value = LocalizedText{};
    if (auto localeElement = mXmlNextElement->get_first_child("Locale"))
    {
      parse_element_value(*localeElement, value.locale());
    }
    if (auto textElement = mXmlNextElement->get_first_child("Text"))
    {
      parse_element_value(*textElement, value.text());
    }
    mXmlNextElement = mXmlNextElement->get_next();
  }
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, Variant& value)
{
  // Bound the structural-descent (a Variant can nest Variants / structures); released on unwind.
  const auto depthGuard = limit.enter_recursion();
  // check_element_presence returns true only when mXmlNextElement is engaged; the
  // redundant `&& mXmlNextElement` makes that provable to the static analyser.
  if (check_element_presence(elementName, mXmlNextElement, isOptional) && mXmlNextElement)
  {
    auto variantXmlElement = mXmlNextElement;
    check(mXmlNextElement);
    auto innerElement = mXmlNextElement->get_first_child();

    if (innerElement)
    {
      auto [builtInTypeId, isArray, isMatrix] = get_variant_details(*innerElement);

      // Descend into the inner element; the restore below uses variantXmlElement.
      mXmlNextElement = innerElement;

      if (isMatrix)
      {
        decode_matrix(limit, "", value);
      }
      else
      {
        decode_variant_value(limit, builtInTypeId, isArray, value);
      }
    }
    else
    {
      // Null variant - just leave the value as initialized (empty)
      value = Variant{};
    }

    // Restore and advance
    mXmlNextElement = variantXmlElement->get_next();
  }
}

std::tuple<BuiltInTypeId, bool, bool> XmlDecoder::get_variant_details(const xml::Element& xmlElement) const
{
  bool isArray{false};
  bool isMatrix{false};

  const string_view listOfPrefix{"ListOf"};

  // Companion-spec value contents bind the Types.xsd URI to a prefix (e.g.
  // `<uax:ListOfDouble>`/`<uax:Matrix>`), which is namespace-identical to the
  // unprefixed default-namespace form NS0 emits. Strip the prefix so the
  // `Matrix`/`ListOf` structural checks below are prefix-insensitive.
  auto localName = [](string_view name) -> string_view
  {
    if (auto pos = name.find(':'); pos != string_view::npos)
    {
      return name.substr(pos + 1);
    }
    return name;
  };

  auto typeName = localName(xmlElement.get_name());
  if (typeName == "Matrix")
  {
    isMatrix = true;
    auto dimensions = xmlElement.get_first_child("Dimensions");
    if (!dimensions)
    {
      throw_empty_optional_check(Status::BadDecodingError);
    }

    auto listElement = dimensions->get_next();
    if (!listElement)
    {
      throw_empty_optional_check(Status::BadDecodingError);
    }

    typeName = localName(listElement->get_name());
    if (typeName.starts_with(listOfPrefix))
    {
      typeName.remove_prefix(listOfPrefix.size());
      isArray = true;
    }
  }
  else if (typeName.starts_with(listOfPrefix))
  {
    typeName.remove_prefix(listOfPrefix.size());
    isArray = true;
  }

  auto typeId = get_built_in_type_id(typeName);

  return {typeId, isArray, isMatrix};
}

BuiltInTypeId XmlDecoder::get_built_in_type_id(string_view typeName)
{
  // NodeSet XML (and other XML encodings) may prefix built-in type names, e.g. `uax:NodeId`.
  // Normalize to the local name so built-ins can be recognized reliably.
  if (auto pos = typeName.find(':'); pos != string_view::npos)
  {
    typeName = typeName.substr(pos + 1);
  }

  if (typeName == get_typename<bool>())
  {
    return built_in_type<bool>();
  }
  if (typeName == get_typename<int8_t>())
  {
    return built_in_type<int8_t>();
  }
  if (typeName == get_typename<uint8_t>())
  {
    return built_in_type<uint8_t>();
  }
  if (typeName == get_typename<int16_t>())
  {
    return built_in_type<int16_t>();
  }
  if (typeName == get_typename<uint16_t>())
  {
    return built_in_type<uint16_t>();
  }
  if (typeName == get_typename<int32_t>())
  {
    return built_in_type<int32_t>();
  }
  if (typeName == get_typename<uint32_t>())
  {
    return built_in_type<uint32_t>();
  }
  if (typeName == get_typename<int64_t>())
  {
    return built_in_type<int64_t>();
  }
  if (typeName == get_typename<uint64_t>())
  {
    return built_in_type<uint64_t>();
  }
  if (typeName == get_typename<float>())
  {
    return built_in_type<float>();
  }
  if (typeName == get_typename<double>())
  {
    return built_in_type<double>();
  }
  if (typeName == get_typename<String>())
  {
    return built_in_type<String>();
  }
  if (typeName == get_typename<DateTime>())
  {
    return built_in_type<DateTime>();
  }
  if (typeName == get_typename<Guid>())
  {
    return built_in_type<Guid>();
  }
  if (typeName == get_typename<ByteString>())
  {
    return built_in_type<ByteString>();
  }
  if (typeName == get_typename<XmlElement>())
  {
    return built_in_type<XmlElement>();
  }
  if (typeName == get_typename<NodeId>())
  {
    return built_in_type<NodeId>();
  }
  if (typeName == get_typename<ExpandedNodeId>())
  {
    return built_in_type<ExpandedNodeId>();
  }
  if (typeName == get_typename<StatusCode>())
  {
    return built_in_type<StatusCode>();
  }
  if (typeName == get_typename<QualifiedName>())
  {
    return built_in_type<QualifiedName>();
  }
  if (typeName == get_typename<LocalizedText>())
  {
    return built_in_type<LocalizedText>();
  }
  if (typeName == get_typename<Structure>())
  {
    return built_in_type<Structure>();
  }
  if (typeName == get_typename<DataValue>())
  {
    return built_in_type<DataValue>();
  }
  if (typeName == get_typename<Decimal>())
  {
    return built_in_type<Decimal>();
  }
  if (typeName == get_typename<Variant>())
  {
    return built_in_type<Variant>();
  }
  if (typeName == get_typename<DiagnosticInfo>())
  {
    throw UaException(Status::BadDecodingError,
      make_error_detail("UnsupportedEncoding", "A Variant cannot contain a DiagnosticInfo", "XmlCodec"));
  }
  throw UaException(Status::BadDecodingError,
    ErrorDetail::build("DecodingFailed", "Unknown type name", "XmlCodec")
      .context(ua::ContextKeys::typeName, std::string(typeName)));
}

void XmlDecoder::decode_variant_value(StackDepth limit, BuiltInTypeId typeId, bool isArray, Variant& value)
{
  switch (typeId)
  {
  case BuiltInTypeId::Boolean:
    decode_value<bool>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::SByte:
    decode_value<int8_t>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::Byte:
    decode_value<uint8_t>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::Int16:
    decode_value<int16_t>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::UInt16:
    decode_value<uint16_t>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::Int32:
    decode_value<int32_t>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::UInt32:
    decode_value<uint32_t>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::Int64:
    decode_value<int64_t>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::UInt64:
    decode_value<uint64_t>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::Float:
    decode_value<float>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::Double:
    decode_value<double>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::String:
    decode_value<String>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::DateTime:
    decode_value<DateTime>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::Guid:
    decode_value<Guid>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::ByteString:
    decode_value<ByteString>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::XmlElement:
    decode_value<XmlElement>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::NodeId:
    decode_value<NodeId>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::ExpandedNodeId:
    decode_value<ExpandedNodeId>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::StatusCode:
    decode_value<StatusCode>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::QualifiedName:
    decode_value<QualifiedName>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::LocalizedText:
    decode_value<LocalizedText>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::ExtensionObject:
    decode_value<Structure>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::DataValue:
    decode_value<DataValue>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::Variant:
    decode_value<Variant>(limit, *this, isArray, value);
    break;

  case BuiltInTypeId::DiagnosticInfo:
    throw UaException(Status::BadDecodingError,
      make_error_detail("UnsupportedEncoding", "A Variant cannot contain a DiagnosticInfo", "XmlCodec"));
    break;

  default:
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("DecodingFailed", "Unsupported built-in type id in Variant", "XmlCodec")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(typeId))));
  }
}

void XmlDecoder::decode_matrix(StackDepth limit, string_view elementName, Variant& value)
{
  using namespace xml_codec_details;
  UA_UNUSED(elementName);
  // Throw (rather than `check`) so the static analyser can prove the dereferences below
  // are reached only when mXmlNextElement is engaged.
  if (!mXmlNextElement)
  {
    throw_empty_optional_check(Status::BadDecodingError);
  }
  auto variantXmlElement = mXmlNextElement;

  auto [builtInTypeId, isArray, isMatrix] = get_variant_details(*mXmlNextElement);
  UA_UNUSED(isArray);
  UA_UNUSED(isMatrix);

  switch (builtInTypeId)
  {
  case BuiltInTypeId::Boolean:
  {
    Array<bool> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::SByte:
  {
    Array<int8_t> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::Byte:
  {
    Array<uint8_t> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::Int16:
  {
    Array<int16_t> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::UInt16:
  {
    Array<uint16_t> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::Int32:
  {
    Array<int32_t> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::UInt32:
  {
    Array<uint32_t> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::Int64:
  {
    Array<int64_t> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::UInt64:
  {
    Array<uint64_t> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::Float:
  {
    Array<float> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::Double:
  {
    Array<double> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::String:
  {
    Array<String> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::DateTime:
  {
    Array<DateTime> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::Guid:
  {
    Array<Guid> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::ByteString:
  {
    Array<ByteString> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::XmlElement:
  {
    Array<XmlElement> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::NodeId:
  {
    Array<NodeId> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::ExpandedNodeId:
  {
    Array<ExpandedNodeId> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::StatusCode:
  {
    Array<StatusCode> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::QualifiedName:
  {
    Array<QualifiedName> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::LocalizedText:
  {
    Array<LocalizedText> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::ExtensionObject:
  {
    Array<RefStructure<Structure>> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::DataValue:
  {
    Array<DataValue> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  case BuiltInTypeId::Variant:
  {
    Array<Variant> arr;
    decode(limit, "", false, arr);
    value = std::move(arr);
    break;
  }
  default:
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("DecodingFailed", "Unsupported built-in type id in Variant matrix", "XmlCodec")
        .context(ua::ContextKeys::typeId, std::to_string(utils::to_underlying(builtInTypeId))));
  }
  mXmlNextElement = variantXmlElement->get_next();
}

void XmlDecoder::decode(StackDepth limit, string_view elementName, bool isOptional, Structure& value)
{
  // Bound the structural-descent (a struct body may nest further structures); released on unwind.
  const auto depthGuard = limit.enter_recursion();
  // check_element_presence returns true only when mXmlNextElement is engaged; the
  // redundant `&& mXmlNextElement` makes that provable to the static analyser.
  if (check_element_presence(elementName, mXmlNextElement, isOptional) && mXmlNextElement)
  {
    auto structureXmlElement = mXmlNextElement;
    mXmlNextElement = mXmlNextElement->get_first_child();

    Decoder decoder(*this);
    value.decode(limit, decoder);

    mXmlNextElement = structureXmlElement->get_next();
  }
}

namespace
{

// Serializes an XML element subtree to its raw bytes, used to preserve an unresolved ExtensionObject
// body verbatim. Mirrors the serialization the XmlElement decode performs.
ByteString serialize_xml_subtree(const xml::Element& element)
{
  const auto text = serialize_subtree_verbatim(element);
  return ByteString{span<const byte>{reinterpret_cast<const byte*>(text.data()), text.size()}};
}

}  // namespace

void XmlDecoder::decode(
  StackDepth limit, string_view elementName, bool isOptional, unique_ptr<Structure>& value)
{
  // check_element_presence returns true only when mXmlNextElement is engaged; the
  // redundant `&& mXmlNextElement` makes that provable to the static analyser.
  if (check_element_presence(elementName, mXmlNextElement, isOptional) && mXmlNextElement)
  {
    auto extObjectElement = mXmlNextElement;

    // Read TypeId (optional for null placeholder)
    if (auto typeIdElement = extObjectElement->get_first_child("TypeId"))
    {
      mXmlNextElement = typeIdElement;

      NodeId typeId;
      decode(limit, "", false, typeId);

      unique_ptr<Structure> instance;
      if (!typeId.is_null())
      {
        unique_ptr<Structure> resolved = mStructureResolver ? mStructureResolver(typeId) : nullptr;
        if (resolved)
        {
          instance = std::move(resolved);

          // Decode body - the first child of <Body> is the structure element itself.
          if (auto bodyElement = extObjectElement->get_first_child("Body"))
          {
            if (auto payload = bodyElement->get_first_child())
            {
              mXmlNextElement = payload;
              decode(limit, instance->type_name(), false, *instance);
            }
          }
        }
        else
        {
          // Unresolved type - preserve the whole <Body> subtree verbatim (tagged Xml) so the value
          // round-trips and can be reified later once the type becomes known, rather than failing the
          // decode. The body wraps the fields in a single type-named element; capturing the entire
          // <Body> (not just its first child) preserves that wrapper for a later resolved re-decode.
          ByteString body;
          if (auto bodyElement = extObjectElement->get_first_child("Body"))
          {
            body = serialize_xml_subtree(*bodyElement);
          }
          instance =
            make_unique<UnknownStructure>(typeId, UnknownStructure::BodyEncoding::Xml, std::move(body));
        }
      }

      value = std::move(instance);
    }
    else
    {
      // No TypeId -> treat as null ExtensionObject placeholder
      value.reset();
    }

    // Advance to next sibling of the ExtensionObject element
    mXmlNextElement = extObjectElement->get_next();
  }
}

}  // namespace ua
