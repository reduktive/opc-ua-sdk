// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <charconv>
#include <exception>
#include <optional>
#include <boost/container_hash/hash.hpp>
#include "ua_to_result.h"
#include "ua_node_id.h"
#include "ua_node_id_validation.h"
#include "ua_utilities.h"
#include "ua_codec.h"
#include "ua_expanded_node_id.h"
#include "ua_byte_string.h"
#include "ua_error_detail.h"
#include "ua_to_string.h"
#include "fmt/format.h"

namespace ua
{

namespace
{

bool is_utf8_continuation(uint8_t codeUnit) noexcept
{
  return (codeUnit & uint8_t{0xC0}) == uint8_t{0x80};
}

std::optional<size_t> validated_utf8_character_count(string_view value) noexcept
{
  size_t characterCount{0};
  size_t offset{0};
  while (offset < value.size())
  {
    const auto first = static_cast<uint8_t>(value[offset]);
    size_t sequenceLength{0};
    if (first <= uint8_t{0x7F})
    {
      sequenceLength = 1;
    }
    else if (first >= uint8_t{0xC2} && first <= uint8_t{0xDF})
    {
      sequenceLength = 2;
    }
    else if (first >= uint8_t{0xE0} && first <= uint8_t{0xEF})
    {
      sequenceLength = 3;
    }
    else if (first >= uint8_t{0xF0} && first <= uint8_t{0xF4})
    {
      sequenceLength = 4;
    }
    else
    {
      return std::nullopt;
    }

    if (sequenceLength > value.size() - offset)
    {
      return std::nullopt;
    }
    for (size_t continuationOffset = 1; continuationOffset < sequenceLength; ++continuationOffset)
    {
      if (!is_utf8_continuation(static_cast<uint8_t>(value[offset + continuationOffset])))
      {
        return std::nullopt;
      }
    }

    if (sequenceLength == 3)
    {
      const auto second = static_cast<uint8_t>(value[offset + 1]);
      if ((first == uint8_t{0xE0} && second < uint8_t{0xA0}) ||
          (first == uint8_t{0xED} && second > uint8_t{0x9F}))
      {
        return std::nullopt;
      }
    }
    else if (sequenceLength == 4)
    {
      const auto second = static_cast<uint8_t>(value[offset + 1]);
      if ((first == uint8_t{0xF0} && second < uint8_t{0x90}) ||
          (first == uint8_t{0xF4} && second > uint8_t{0x8F}))
      {
        return std::nullopt;
      }
    }

    offset += sequenceLength;
    ++characterCount;
  }
  return characterCount;
}

}  // namespace

NodeId::NodeId(uint32_t identifier) : mIdentifier(identifier)
{}

NodeId::NodeId(uint16_t namespaceIndex, uint32_t identifier)
  : mNamespaceIndex(namespaceIndex), mIdentifier(identifier)
{}

NodeId::NodeId(DataTypeId identifier) : mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(uint16_t namespaceIndex, DataTypeId identifier)
  : mNamespaceIndex(namespaceIndex), mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(ObjectTypeId identifier) : mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(uint16_t namespaceIndex, ObjectTypeId identifier)
  : mNamespaceIndex(namespaceIndex), mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(ObjectId identifier) : mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(uint16_t namespaceIndex, ObjectId identifier)
  : mNamespaceIndex(namespaceIndex), mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(VariableTypeId identifier) : mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(uint16_t namespaceIndex, VariableTypeId identifier)
  : mNamespaceIndex(namespaceIndex), mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(VariableId identifier) : mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(uint16_t namespaceIndex, VariableId identifier)
  : mNamespaceIndex(namespaceIndex), mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(ReferenceTypeId identifier) : mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(uint16_t namespaceIndex, ReferenceTypeId identifier)
  : mNamespaceIndex(namespaceIndex), mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(MethodId identifier) : mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(uint16_t namespaceIndex, MethodId identifier)
  : mNamespaceIndex(namespaceIndex), mIdentifier(utils::to_underlying(identifier))
{}

NodeId::NodeId(uint16_t namespaceIndex, string_view identifier)
  : mNamespaceIndex(namespaceIndex), mIdentifier(identifier)
{}

NodeId::NodeId(const Guid& identifier) : mIdentifier(identifier)
{}

NodeId::NodeId(uint16_t namespaceIndex, const Guid& identifier)
  : mNamespaceIndex(namespaceIndex), mIdentifier(identifier)
{}

NodeId::NodeId(const ByteString& identifier) : mIdentifier(identifier)
{}

NodeId::NodeId(uint16_t namespaceIndex, const ByteString& identifier)
  : mNamespaceIndex(namespaceIndex), mIdentifier(identifier)
{}

NodeId::NodeId(const NodeId& obj) : mNamespaceIndex(obj.mNamespaceIndex), mIdentifier(obj.mIdentifier)
{}

NodeId::NodeId(const ExpandedNodeId& obj) : NodeId(obj.node_id())
{
  if (obj.is_not_index_based() || obj.is_remote())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidNodeId", "ExpandedNodeId cannot be converted to a NodeId (URI-based or remote)", "NodeId")
        .context(ua::ContextKeys::nodeId, ua::to_string(obj)));
  }
}

NodeId::NodeId(ExpandedNodeId&& obj)
{
  if (obj.is_not_index_based() || obj.is_remote())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build(
        "InvalidNodeId", "ExpandedNodeId cannot be converted to a NodeId (URI-based or remote)", "NodeId")
        .context(ua::ContextKeys::nodeId, ua::to_string(obj)));
  }
  mNamespaceIndex = obj.node_id().namespace_index();
  mIdentifier = std::move(obj.node_id().identifier());
}

NodeId& NodeId::operator=(const NodeId& other)
{
  mNamespaceIndex = other.mNamespaceIndex;
  mIdentifier = other.mIdentifier;
  return *this;
}

bool NodeId::is_null() const
{
  // The null NodeId lives at NamespaceIndex 0 (OPC 10000-3 section 8.2.4, Table 23: the canonical null and
  // every alternative null value are defined "at NamespaceIndex 0"). A NodeId in any other namespace with an
  // otherwise-null identifier (e.g. ns=1,i=0 or ns=1,"") is an ordinary reference to that namespace, NOT the
  // null NodeId  -  so it must not short-circuit as null. (CL-ADDRSP-003.)
  if (mNamespaceIndex != 0)
  {
    return false;
  }

  // A NodeId is null when its identifier is the null value for its identifier type
  // (OPC 10000-6 5.2.2.9): numeric 0, a null/empty String, a null Guid, or a null/empty
  // ByteString. All four encodings denote the same null NodeId.
  switch (mIdentifier.type())
  {
  case IdType::Numeric:
    return mIdentifier.get_numeric() == 0;
  case IdType::String:
    return mIdentifier.get_string().is_null() || mIdentifier.get_string().empty();
  case IdType::Guid:
    return mIdentifier.get_guid().is_null();
  case IdType::Opaque:
    return mIdentifier.get_opaque().is_null() || mIdentifier.get_opaque().empty();
  }
  return false;
}

detail::NodeIdStructuralValidation detail::validate_node_id_structure(const NodeId& nodeId) noexcept
{
  switch (nodeId.identifier().type())
  {
  case IdType::Numeric:
  case IdType::Guid:
    return {};
  case IdType::String:
  {
    const auto characterCount = validated_utf8_character_count(string_view{nodeId.identifier().get_string()});
    if (!characterCount)
    {
      return NodeIdStructuralValidation{.isValid = false, .encodingIsValid = false};
    }
    return NodeIdStructuralValidation{.isValid = *characterCount <= maxNodeIdStringIdentifierLength,
      .encodingIsValid = true,
      .identifierLength = *characterCount,
      .maximumIdentifierLength = maxNodeIdStringIdentifierLength};
  }
  case IdType::Opaque:
  {
    const size_t byteCount = nodeId.identifier().get_opaque().size();
    return NodeIdStructuralValidation{.isValid = byteCount <= maxNodeIdOpaqueIdentifierLength,
      .encodingIsValid = true,
      .identifierLength = byteCount,
      .maximumIdentifierLength = maxNodeIdOpaqueIdentifierLength};
  }
  }
  return NodeIdStructuralValidation{.isValid = false, .encodingIsValid = false};
}

bool NodeId::is_structurally_valid() const noexcept
{
  return detail::validate_node_id_structure(*this).isValid;
}

bool NodeId::is_numeric() const
{
  return mIdentifier.is_numeric();
}

bool NodeId::is_string() const
{
  return mIdentifier.is_string();
}

bool NodeId::is_guid() const
{
  return mIdentifier.is_guid();
}

bool NodeId::is_opaque() const
{
  return mIdentifier.is_opaque();
}

IdType NodeId::id_type() const
{
  return mIdentifier.type();
}

uint16_t NodeId::namespace_index() const
{
  return mNamespaceIndex;
}

uint16_t& NodeId::namespace_index()
{
  return mNamespaceIndex;
}

NodeId NodeId::parse(string_view text)
{
  return parse_definition(text, true);
}

NodeIdResult NodeId::try_parse(string_view text) noexcept
{
  try
  {
    return parse(text);
  }
  catch (...)
  {
    return NodeIdResult{exception_to_status_code(std::current_exception())};
  }
}

NodeId NodeId::parse_definition(string_view text, bool namespaceIndexAllowed)
{
  NodeId id;
  id.assign_definition(text, namespaceIndexAllowed);
  return id;
}

void NodeId::assign_definition(string_view definition, bool namespaceIndexAllowed)
{
  clear();

  // Parse namespace
  const string_view nsPrefix{"ns="};

  if (definition.starts_with(nsPrefix))
  {
    if (!namespaceIndexAllowed)
    {
      throw UaException(Status::BadDecodingError,
        ErrorDetail::build("NodeIdParseFailed", "Namespace index not permitted in this context", "NodeId")
          .context(ua::ContextKeys::actual, std::string{definition}));
    }

    auto temp{definition};
    temp.remove_prefix(nsPrefix.size());

    uint16_t nsi{0};
    auto re = ::std::from_chars(temp.data(), temp.data() + temp.size(), nsi);
    // The index runs up to its ';' and no further: "ns=2x;i=1" is not index 2 (security review
    // XML-11).
    if (re.ec != ::std::errc{} || re.ptr == temp.data() + temp.size() || *re.ptr != ';')
    {
      throw UaException(Status::BadDecodingError,
        ErrorDetail::build("NodeIdParseFailed", "Could not parse namespace index from definition", "NodeId")
          .context(ua::ContextKeys::actual, std::string{temp}));
    }

    if (nsi == 0)
    {
      throw UaException(Status::BadDecodingError,
        ErrorDetail::build("NodeIdParseFailed", "ns= format cannot be used for namespace zero", "NodeId")
          .context(ua::ContextKeys::actual, std::string{temp}));
    }

    mNamespaceIndex = nsi;

    const size_t end = definition.find(';');
    if (end == string_view ::npos)
    {
      throw UaException(Status::BadDecodingError,
        ErrorDetail::build(
          "NodeIdParseFailed", "Namespace definition not terminated with semicolon", "NodeId")
          .context(ua::ContextKeys::actual, std::string{definition}));
    }

    definition = definition.substr(end + 1);
  }

  // Parse identifier
  const string_view numericPrefix{"i="};
  const string_view stringPrefix{"s="};
  const string_view guidPrefix{"g="};
  const string_view opaquePrefix{"b="};

  if (definition.starts_with(numericPrefix))
  {
    auto temp{definition};
    temp.remove_prefix(numericPrefix.size());

    uint32_t id{0};
    auto re = ::std::from_chars(temp.data(), temp.data() + temp.size(), id);
    // The identifier is the whole remainder: "i=5abc" is not i=5 (security review XML-11).
    if (re.ec != ::std::errc{} || re.ptr != temp.data() + temp.size())
    {
      throw UaException(Status::BadDecodingError,
        ErrorDetail::build(
          "NodeIdParseFailed", "Could not parse numeric identifier from definition", "NodeId")
          .context(ua::ContextKeys::actual, std::string{temp}));
    }

    mIdentifier = id;
  }
  else if (definition.starts_with(stringPrefix))
  {
    auto temp{definition};
    temp.remove_prefix(stringPrefix.size());

    mIdentifier = temp;
  }
  else if (definition.starts_with(guidPrefix))
  {
    auto temp{definition};
    temp.remove_prefix(guidPrefix.size());

    mIdentifier = Guid::parse(temp);
  }
  else if (definition.starts_with(opaquePrefix))
  {
    auto temp{definition};
    temp.remove_prefix(opaquePrefix.size());

    mIdentifier = utils::base64_decode(temp);
  }
  else
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "NodeIdParseFailed", "Identifier definition not found (no i=/s=/g=/b= prefix)", "NodeId")
        .context(ua::ContextKeys::actual, std::string{definition}));
  }
}

std::string NodeId::as_definition() const
{
  std::string nameSpace;
  if (mNamespaceIndex != 0)
  {
    nameSpace = fmt::format("ns={};", mNamespaceIndex);
  }

  std::string identifierText;
  switch (mIdentifier.type())
  {
  case IdType::Numeric:
    identifierText = fmt::format("i={}", mIdentifier.get_numeric());
    break;

  case IdType::String:
    identifierText = fmt::format("s={}", string_view{mIdentifier.get_string()});
    break;

  case IdType::Opaque:
    // Part 6 5.3.1.10: an opaque (ByteString) identifier is encoded as "b=<base64>", the inverse of
    // the "b=" parse branch above.
    identifierText = fmt::format("b={}", utils::base64_encode(mIdentifier.get_opaque()));
    break;

  case IdType::Guid:
    identifierText = fmt::format("g={}", mIdentifier.get_guid().as_string());
    break;

  default:
    throw UaException(Status::BadNodeIdInvalid,
      make_error_detail("InvalidNodeId", "Unknown identifier type in as_definition()", "NodeId"));
  }

  return nameSpace + identifierText;
}

void NodeId::clear()
{
  mNamespaceIndex = 0;
  mIdentifier = uint32_t{0};
}

bool NodeId::operator==(const NodeId& obj) const
{
  if ((mNamespaceIndex != obj.mNamespaceIndex) || (mIdentifier != obj.mIdentifier))
  {
    return false;
  }

  return true;
}

std::strong_ordering NodeId::operator<=>(const NodeId& other) const
{
  if (auto cmp = mNamespaceIndex <=> other.mNamespaceIndex; cmp != 0)
  {
    return cmp;
  }
  return mIdentifier <=> other.mIdentifier;
}

const NodeId::Identifier& NodeId::identifier() const
{
  return mIdentifier;
}

NodeId::Identifier& NodeId::identifier()
{
  return mIdentifier;
}

BuiltInTypeId NodeId::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::NodeId};
}

size_t NodeId::hash() const
{
  size_t seed{0};
  boost::hash_combine(seed, mNamespaceIndex);
  boost::hash_combine(seed, mIdentifier.hash());
  return seed;
}

NodeId::Identifier::Identifier() : mValue(uint32_t{0})
{}

NodeId::Identifier::Identifier(uint32_t identifier) : mValue(identifier)
{}

NodeId::Identifier::Identifier(DataTypeId identifier) : mValue(utils::to_underlying(identifier))
{}

NodeId::Identifier::Identifier(ObjectTypeId identifier) : mValue(utils::to_underlying(identifier))
{}

NodeId::Identifier::Identifier(ObjectId identifier) : mValue(utils::to_underlying(identifier))
{}

NodeId::Identifier::Identifier(VariableTypeId identifier) : mValue(utils::to_underlying(identifier))
{}

NodeId::Identifier::Identifier(VariableId identifier) : mValue(utils::to_underlying(identifier))
{}

NodeId::Identifier::Identifier(ReferenceTypeId identifier) : mValue(utils::to_underlying(identifier))
{}

NodeId::Identifier::Identifier(MethodId identifier) : mValue(utils::to_underlying(identifier))
{}

NodeId::Identifier::Identifier(string_view identifier) : mValue(identifier)
{}

NodeId::Identifier::Identifier(const Guid& identifier) : mValue(identifier)
{}

NodeId::Identifier::Identifier(Guid&& identifier) : mValue(identifier)
{}

NodeId::Identifier::Identifier(const ByteString& identifier) : mValue(identifier)
{}

// The pointer form predates by-value storage and is kept so callers need not change; it takes
// ownership by moving the pointee out. A null pointer denotes an empty opaque identifier.
NodeId::Identifier::Identifier(unique_ptr<ByteString> identifier)
  : mValue(identifier ? std::move(*identifier) : ByteString{})
{}

NodeId::Identifier& NodeId::Identifier::operator=(uint32_t value)
{
  mValue = value;
  return *this;
}

NodeId::Identifier& NodeId::Identifier::operator=(string_view value)
{
  mValue = value;
  return *this;
}

NodeId::Identifier& NodeId::Identifier::operator=(const Guid& value)
{
  mValue = value;
  return *this;
}

NodeId::Identifier& NodeId::Identifier::operator=(Guid&& value)
{
  mValue = value;
  return *this;
}

NodeId::Identifier& NodeId::Identifier::operator=(const ByteString& value)
{
  mValue = value;
  return *this;
}

NodeId::Identifier& NodeId::Identifier::operator=(unique_ptr<ByteString> value)
{
  mValue = value ? std::move(*value) : ByteString{};
  return *this;
}

bool NodeId::Identifier::operator==(const NodeId::Identifier& obj) const
{
  const IdType id{type()};
  if (id != obj.type())
  {
    return false;
  }

  switch (id)
  {
  case IdType::Numeric:
  case IdType::String:
  case IdType::Guid:
    return (mValue == obj.mValue);

  case IdType::Opaque:
    return (get_opaque() == obj.get_opaque());

  default:
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("UnsupportedNodeIdType", "Invalid identifier type in equality comparison", "NodeId"));
  }
}

std::strong_ordering NodeId::Identifier::operator<=>(const NodeId::Identifier& other) const
{
  auto lhsType = type();
  auto rhsType = other.type();
  if (auto cmp = lhsType <=> rhsType; cmp != 0)
  {
    return cmp;
  }

  switch (lhsType)
  {
  case IdType::Numeric:
    return get_numeric() <=> other.get_numeric();

  case IdType::String:
    return get_string() <=> other.get_string();

  case IdType::Guid:
    return get_guid() <=> other.get_guid();

  case IdType::Opaque:
    return get_opaque() <=> other.get_opaque();

  default:
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("UnsupportedNodeIdType", "Invalid identifier type in comparison", "NodeId"));
  }
}

const String& NodeId::Identifier::get_string() const
{
  try
  {
    return std::get<String>(mValue);
  }
  catch (const std::bad_variant_access&)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("InvalidNodeId", "NodeId does not contain a string identifier", "NodeId")
        .context(ua::ContextKeys::typeName, std::to_string(static_cast<int>(type()))));
  }
}

const Guid& NodeId::Identifier::get_guid() const
{
  try
  {
    return std::get<Guid>(mValue);
  }
  catch (const std::bad_variant_access&)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("InvalidNodeId", "NodeId does not contain a guid identifier", "NodeId")
        .context(ua::ContextKeys::typeName, std::to_string(static_cast<int>(type()))));
  }
}

const ByteString& NodeId::Identifier::get_opaque() const
{
  if (const auto* opaque = std::get_if<ByteString>(&mValue))
  {
    return *opaque;
  }
  throw UaException(Status::BadInvalidState,
    ErrorDetail::build("InvalidNodeId", "NodeId does not contain an opaque identifier", "NodeId")
      .context(ua::ContextKeys::typeName, std::to_string(static_cast<int>(type()))));
}

void NodeId::Identifier::throw_not_numeric() const
{
  throw UaException(Status::BadInvalidState,
    ErrorDetail::build("InvalidNodeId", "NodeId does not contain a numeric identifier", "NodeId")
      .context(ua::ContextKeys::typeName, std::to_string(static_cast<int>(type()))));
}

size_t NodeId::Identifier::hash() const
{
  switch (type())
  {
  case IdType::Numeric:
    return std::hash<size_t>{}(get_numeric());

  case IdType::Guid:
    return get_guid().hash();

  case IdType::String:
    return std::hash<String>{}(get_string());

  case IdType::Opaque:
  {
    auto opaque = get_opaque();
    size_t seed{0};
    boost::hash_range(seed, opaque.begin(), opaque.end());
    return seed;
  }

  default:
    throw UaException(Status::BadInvalidArgument,
      make_error_detail("UnsupportedNodeIdType", "Invalid identifier type in hash()", "NodeId"));
  }
}

}  // namespace ua
