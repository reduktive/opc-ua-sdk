// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_nodeset_parser.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_codec_namespace_context.h"
#include "ua_xml_codec.h"
#include "ua_xml_parser.h"
#include "ua_stream.h"
#include "ua_encoding_limits.h"
#include "ua_event_notifier_type.h"
#include "ua_access_level_ex_type.h"
#include "ua_qualified_name.h"
#include "ua_variant.h"
#include "ua_data_value.h"
#include <algorithm>
#include <ranges>

namespace ua::xml::nodeset
{

namespace
{

// A missing or invalid required NodeSet attribute is a decoding failure.
template<typename T>
T require_node_attribute(std::optional<T> value, std::string_view attributeName)
{
  if (!value)
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build(
        "InvalidNodesetXml", "UANode has a missing or invalid required attribute", "XmlNodesetParser")
        .context(ua::ContextKeys::fieldName, std::string{attributeName})};
  }
  return std::move(*value);
}

optional<NodeId> check_for_alias(const NodeSet& nodeSet, string_view alias)
{
  optional<NodeId> result;

  if (alias.find('=') == string_view::npos)
  {
    auto& aliases = nodeSet.aliases();
    if (aliases)
    {
      result = aliases->find_raw_node_id(alias);
    }
  }

  return result;
}

template<typename T>
auto get_element_value(const NodeSet& nodeSet, xml::Element element) -> T
{
  UA_UNUSED(nodeSet);

  T result{};
  xml::parser::parse(element.get_value(), result);

  return result;
}

template<>
NodeId get_element_value<NodeId>(const NodeSet& nodeSet, xml::Element element)
{
  NodeId result;
  try
  {
    auto aliased = check_for_alias(nodeSet, element.get_value());
    if (aliased)
    {
      result = aliased.value();
    }
    else
    {
      xml::parser::parse(element.get_value(), result);
    }
  }
  catch (...)
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build(
        "InvalidNodesetXml", "Failed to decode NodeId from element value", "XmlNodesetParser")
        .context(ua::ContextKeys::nodeId, std::string(element.get_value()))
        .context(ua::ContextKeys::sourceLocation, nodeSet.locate(element).to_string())};
  }

  return result;
}

Variant decode_variant_with_config(const NodeSet& nodeSet, xml::Element element,
  const StructureResolver& resolver, const CodecNamespaceContext& namespaceConfig)
{
  // For some consumers (e.g. type generators) we only need the type graph / definitions and not the
  // values, so decoding `Variant` is optional.
  if (!nodeSet.decode_variant_values())
  {
    return {};
  }

  Variant result;
  XmlDecoder decoder{resolver, element, nodeSet.encoding_limits(), namespaceConfig};
  decoder.decode(nodeSet.encoding_limits().stack_depth(), "", true, result);

  return result;
}

template<typename T>
auto get_child_element_value(
  const NodeSet& nodeSet, xml::Element parent, string_view elementName) -> optional<T>
{
  optional<T> result;

  auto child = parent.get_first_child(elementName);
  if (child)
  {
    result = get_element_value<T>(nodeSet, child.value());
  }

  return result;
}

optional<string_view> get_attribute_value_text(xml::Element element, string_view attributeName)
{
  return element.get_first_attribute_value(attributeName);
}

template<typename T>
auto get_attribute_value(
  const NodeSet& nodeSet, xml::Element element, string_view attributeName) -> optional<T>
{
  UA_UNUSED(nodeSet);

  optional<T> result;
  auto text = get_attribute_value_text(element, attributeName);
  if (text)
  {
    T temp{};
    xml::parser::parse(text.value(), temp);
    result = temp;
  }

  return result;
}

template<>
optional<NodeId> get_attribute_value<NodeId>(
  const NodeSet& nodeSet, xml::Element element, string_view attributeName)
{
  optional<NodeId> result;
  auto text = get_attribute_value_text(element, attributeName);
  if (text)
  {
    NodeId nodeId;

    try
    {
      auto aliased = check_for_alias(nodeSet, text.value());
      if (aliased)
      {
        nodeId = aliased.value();
      }
      else
      {
        xml::parser::parse(text.value(), nodeId);
      }
    }
    catch (...)  // nosemgrep: catch-all-empty-body
    {
      // INTENTIONAL leniency - this is a GENERAL NodeId-attribute getter, also used for attributes that
      // can legitimately carry a non-prefixed standard reference-type NAME (e.g. ReferenceType=
      // "Organizes"/"HasTypeDefinition"), which is neither a fixture-defined alias nor a prefixed NodeId,
      // so xml::parser::parse throws BadDecodingError. Swallowing leaves nodeId null -> the optional
      // result is empty -> the caller falls back to resolving the reference by its standard name.
      // Rejecting here breaks legitimate NodeSet imports (XmlNodeSetImporterTranslationTests). The
      // empty body is deliberate: "not a resolvable NodeId at this layer" is a valid, non-error outcome.
      ua::detail::ignore_expected_exception();
    }

    if (!nodeId.is_null())
    {
      result = std::move(nodeId);
    }
  }

  return result;
}

std::vector<RolePermissionType> get_role_permissions(const NodeSet& nodeSet, xml::Element element)
{
  std::vector<RolePermissionType> result;

  auto rolePermissions = element.get_first_child("RolePermissions");
  if (rolePermissions)
  {
    auto rolePermission = rolePermissions->get_first_child("RolePermission");
    while (rolePermission)
    {
      RolePermissionType entry;

      auto rolePermissionText = get_element_value<String>(nodeSet, rolePermission.value());
      try
      {
        xml::parser::parse(rolePermissionText, entry.role_id());
      }
      catch (...)
      {
        // The RolePermission's own text is the alias (the node element's text, used before, is
        // whitespace, and an absent alias is a decode error, not a bad_optional_access escaping the
        // parser: security review XML-7).
        const auto aliased = check_for_alias(nodeSet, static_cast<string_view>(rolePermissionText));
        if (!aliased)
        {
          throw UaException(Status::BadDecodingError,
            ErrorDetail::build("RolePermissionRoleIdInvalid",
              "A RolePermission names neither a NodeId nor a declared alias",
              "XmlNodesetParser")
              .context(ua::ContextKeys::value, std::string{static_cast<string_view>(rolePermissionText)}));
        }
        entry.role_id() = *aliased;
      }

      // `Permissions` carries a schema `default="0"`, so the attribute is optional; an absent
      // attribute means "no permissions granted", not a decode error.
      entry.permissions() = PermissionType{
        get_attribute_value<PermissionType::UnderlyingType>(nodeSet, rolePermission.value(), "Permissions")
          .value_or(0)};

      result.push_back(std::move(entry));

      // Advance to the next sibling of the current <RolePermission>, not the
      // container's sibling - otherwise only the first entry is ever read
      // (exposed by UA-1.05.06, the first NodeSet shipping multi-entry
      // RolePermissions on the well-known Role nodes).
      rolePermission = rolePermission->get_next("RolePermission");
    }
  }

  return result;
}

std::vector<LocalizedText> get_localized_text(
  const NodeSet& nodeSet, xml::Element element, string_view elementName)
{
  std::vector<LocalizedText> result;

  auto child = element.get_first_child(elementName);
  while (child)
  {
    LocalizedText entry;
    auto locale = get_attribute_value_text(child.value(), "Locale");
    if (locale)
    {
      entry.locale() = locale.value();
    }
    entry.text() = get_element_value<String>(nodeSet, child.value());
    result.push_back(std::move(entry));

    child = child->get_next(elementName);
  }

  return result;
}

Dimensions parse_array_dimensions_attribute(string_view input)
{
  Dimensions result;

  std::stringstream stream(std::string{input});
  while (!stream.eof())
  {
    std::string part;
    std::getline(stream, part, ',');
    if (!part.empty())
    {
      int32_t dimension{};
      xml::parser::parse(part, dimension);
      result.push_back(dimension);
    }
  }

  return result;
}

TranslationType parse_translation(const NodeSet& nodeSet, xml::Element element)
{
  TranslationType result;

  auto textElement = element.get_first_child("Text");
  if (textElement)
  {
    result.text = get_localized_text(nodeSet, element, "Text");
  }
  else
  {
    auto fieldElement = element.get_first_child("Field");
    while (fieldElement)
    {
      TranslationType::StructureField field;
      field.name = require_node_attribute(get_attribute_value_text(fieldElement.value(), "Name"), "Name");
      field.text = get_localized_text(nodeSet, fieldElement.value(), "Text");
      result.fields.push_back(std::move(field));

      fieldElement = element.get_next("Field");
    }
  }

  return result;
}

bool create_inverse_reference(const NodeId& referenceType)
{
  if ((referenceType == NodeId{ReferenceTypeId::HasTypeDefinition}) ||
      (referenceType == NodeId{ReferenceTypeId::HasModellingRule}))
  {
    return false;
  }
  return true;
}

}  // namespace

NodeId Node::node_id() const
{
  return require_node_attribute(get_attribute_value<NodeId>(*mNodeSet, mXmlElement, "NodeId"), "NodeId");
}

QualifiedName Node::browse_name() const
{
  QualifiedName result;

  const auto text = require_node_attribute(get_attribute_value_text(mXmlElement, "BrowseName"), "BrowseName");
  xml::parser::parse(text, result);

  return result;
}

optional<AttributeWriteMask> Node::write_mask() const
{
  optional<AttributeWriteMask> result;

  auto rawWriteMask =
    get_attribute_value<AttributeWriteMask::UnderlyingType>(*mNodeSet, mXmlElement, "WriteMask");
  if (rawWriteMask)
  {
    result = AttributeWriteMask{rawWriteMask.value()};
  }

  return result;
}

optional<AccessRestrictionType> Node::access_restrictions() const
{
  optional<AccessRestrictionType> result;

  auto value =
    get_attribute_value<AccessRestrictionType::UnderlyingType>(*mNodeSet, mXmlElement, "AccessRestrictions");
  if (value)
  {
    result = AccessRestrictionType{value.value()};
  }
  return result;
}

String Node::symbolic_name() const
{
  String result;
  auto text = get_attribute_value_text(mXmlElement, "SymbolicName");
  if (text)
  {
    result = text.value();
  }
  return result;
}

optional<Node::ReleaseStatus> Node::release_status() const
{
  optional<Node::ReleaseStatus> result;
  auto text = get_attribute_value_text(mXmlElement, "ReleaseStatus");
  if (text)
  {
    if (text.value() == "Released")
    {
      result = ReleaseStatus::Released;
    }
    else if (text.value() == "Draft")
    {
      result = ReleaseStatus::Draft;
    }
    else if (text.value() == "Deprecated")
    {
      result = ReleaseStatus::Deprecated;
    }
    else
    {
      throw UaException{Status::BadDecodingError,
        ErrorDetail::build("InvalidNodesetXml", "Unknown ReleaseStatus attribute value", "XmlNodesetParser")
          .context(ua::ContextKeys::nodeAttribute, "ReleaseStatus")
          .context(ua::ContextKeys::actual, std::string(text.value()))};
    }
  }
  return result;
}

std::vector<LocalizedText> Node::display_name() const
{
  return get_localized_text(*mNodeSet, mXmlElement, "DisplayName");
}

std::vector<LocalizedText> Node::description() const
{
  return get_localized_text(*mNodeSet, mXmlElement, "Description");
}

optional<String> Node::category() const
{
  return get_child_element_value<String>(*mNodeSet, mXmlElement, "Category");
}

optional<String> Node::documentation() const
{
  // `<Documentation>` is an optional child element (schema `minOccurs="0"`); a missing element yields
  // an empty optional. The old `.value()` threw `bad_optional_access` on the common no-documentation
  // case - return the optional directly so absence is reported as `nullopt`, matching `category()`.
  return get_child_element_value<String>(*mNodeSet, mXmlElement, "Documentation");
}

std::vector<RolePermissionType> Node::role_permissions() const
{
  return get_role_permissions(*mNodeSet, mXmlElement);
}

bool Node::has_no_permissions() const
{
  // Most nodes carry no <HasNoPermissions> element; the optional is then empty and "no element"
  // means "permissions unspecified" (false), not an error. Calling .value() here would throw.
  return get_child_element_value<bool>(*mNodeSet, mXmlElement, "HasNoPermissions").value_or(false);
}

optional<xml::Element> Node::extensions() const
{
  return mXmlElement.get_first_child("Extensions");
}

optional<XmlElement> Node::extensions_xml() const
{
  // Preserve the node's `<Extensions>` block verbatim as the OPC-UA built-in `XmlElement` (a string)
  // - the XML-free form for the public `NodeView::extensions()` accessor (D-N). Not interpreted.
  auto extensionsElement = mXmlElement.get_first_child("Extensions");
  if (!extensionsElement)
  {
    return {};
  }
  XmlDecoder decoder{mNodeSet->structure_resolver(), *extensionsElement, mNodeSet->encoding_limits()};
  XmlElement decoded;
  decoder.decode(mNodeSet->encoding_limits().stack_depth(), "", false, decoded);
  return decoded;
}

std::vector<RawReference> Node::raw_references() const
{
  std::vector<RawReference> result;

  auto referencesElement = mXmlElement.get_first_child("References");
  if (referencesElement)
  {
    auto reference = referencesElement->get_first_child("Reference");
    while (reference)
    {
      result.emplace_back(RawReference{reference.value(), *mNodeSet});
      reference = reference->get_next("Reference");
    }
  }

  return result;
}

std::span<const Node::Reference> Node::references() const
{
  return mReferences;
}

std::vector<Node::Reference>& Node::references()
{
  return mReferences;
}

Node::Node(xml::Element xmlElement, NodeSet& nodeSet) : Element(xmlElement, nodeSet)
{}

bool Type::is_abstract() const
{
  bool result{false};

  auto isAbstract = get_attribute_value<bool>(*mNodeSet, mXmlElement, "IsAbstract");
  if (isAbstract)
  {
    result = isAbstract.value();
  }

  return result;
}

Type::Type(xml::Element xmlElement, NodeSet& nodeSet) : Node(xmlElement, nodeSet)
{}

NodeId Instance::parent_node_id() const
{
  // Many instance nodes (e.g. regular address space instances) do not have a `ParentNodeId`.
  // Callers that need it (e.g. type-child filtering) should treat the absence as "no parent".
  // ParentNodeId is an XML attribute (not a child element) in the OPC UA NodeSet2 schema.
  const auto parent = get_attribute_value<NodeId>(*mNodeSet, mXmlElement, "ParentNodeId");
  return parent.value_or(NodeId{});
}

Instance::Instance(xml::Element xmlElement, NodeSet& nodeSet) : Node(xmlElement, nodeSet)
{}

NodeSet::NodeSet(ua::EncodingLimits limits, std::vector<byte>&& ownedXml, span<const byte> sourceView,
  xml::Context&& xmlParserContext, xml::Element xmlElement, StructureResolver structureResolver,
  std::vector<std::size_t> newlineOffsets, ParserOptions options)
  : Element(xmlElement, *this), mLimits(limits), mOptions(options), mOwnedXml(std::move(ownedXml)),
    mXmlParserContext(std::move(xmlParserContext)), mStructureResolver(std::move(structureResolver)),
    mNewlineOffsets(std::move(newlineOffsets))
{
  // Resolve the source view AFTER moving `ownedXml` into place: when we own the buffer, the view must
  // refer to the final (post-move) storage, not the caller's now-moved-from vector. When we don't own
  // it (zero-copy), the caller's external view is used as-is. Set before any `locate` use below.
  mSourceXml = mOwnedXml.empty() ? sourceView : span<const byte>{mOwnedXml.data(), mOwnedXml.size()};

  auto namespaceUris = mXmlElement.get_first_child("NamespaceUris");
  if (namespaceUris)
  {
    mNamespaceUris.emplace(UriTable{namespaceUris.value(), *this});
  }

  auto serverUris = mXmlElement.get_first_child("ServerUris");
  if (serverUris)
  {
    mServerUris.emplace(UriTable{serverUris.value(), *this});
  }

  auto modelsElement = mXmlElement.get_first_child("Models");
  if (modelsElement)
  {
    const string_view modelName{"Model"};
    auto model = modelsElement->get_first_child(modelName);
    while (model)
    {
      mModels.emplace_back(ModelTableEntry{model.value(), *this});

      model = model->get_next(modelName);
    }
  }

  auto aliasesElement = mXmlElement.get_first_child("Aliases");
  if (aliasesElement)
  {
    mAliases.emplace(AliasTable{aliasesElement.value(), *this});
  }

  auto extensionsElement = mXmlElement.get_first_child("Extensions");
  if (extensionsElement)
  {
    XmlDecoder decoder{structure_resolver(), *extensionsElement, encoding_limits()};
    XmlElement decoded;
    decoder.decode(mLimits.stack_depth(), "", false, decoded);
    mExtensions = std::move(decoded);
  }

  add_nodes();

  // `LastModified` is an XML ATTRIBUTE of <UANodeSet> in the OPC UA NodeSet2 schema (like
  // ParentNodeId), not a child element. Reading it as a child never matched a real file.
  if (auto lastModified = get_attribute_value<DateTime>(*this, mXmlElement, "LastModified"))
  {
    mLastModified = *lastModified;
  }
}

const ua::EncodingLimits& NodeSet::encoding_limits() const
{
  return mLimits;
}

template<typename T>
void NodeSet::add_nodes(string_view typeName)
{
  auto child = mXmlElement.get_first_child(typeName);
  while (child)
  {
    auto node = make_unique<T>(child.value(), *this);

    auto nodeId = node->node_id();
    mNodes.insert(std::make_pair(std::move(nodeId), std::move(node)));

    child = child->get_next(typeName);
  }
}

void NodeSet::add_nodes()
{
  add_nodes<ObjectType>("UAObjectType");
  add_nodes<VariableType>("UAVariableType");
  add_nodes<DataType>("UADataType");
  add_nodes<ReferenceType>("UAReferenceType");
  add_nodes<Object>("UAObject");
  add_nodes<Variable>("UAVariable");
  add_nodes<Method>("UAMethod");
  add_nodes<View>("UAView");
}

optional<UriTable>& NodeSet::namespace_uris()
{
  return mNamespaceUris;
}

const optional<UriTable>& NodeSet::namespace_uris() const
{
  return mNamespaceUris;
}

optional<UriTable>& NodeSet::server_uris()
{
  return mServerUris;
}

const optional<UriTable>& NodeSet::server_uris() const
{
  return mServerUris;
}

span<const ModelTableEntry> NodeSet::models() const
{
  return mModels;
}

optional<AliasTable>& NodeSet::aliases()
{
  return mAliases;
}

const optional<AliasTable>& NodeSet::aliases() const
{
  return mAliases;
}

XmlElement& NodeSet::extensions()
{
  return mExtensions;
}

const XmlElement& NodeSet::extensions() const
{
  return mExtensions;
}

DateTime NodeSet::last_modified() const
{
  return mLastModified;
}

Node* NodeSet::find_node(const NodeId& nodeId)
{
  auto result = mNodes.find(nodeId);
  if (result != mNodes.end())
  {
    return result->second.get();
  }
  else
  {
    return nullptr;
  }
}

const StructureResolver& NodeSet::structure_resolver() const
{
  return mStructureResolver;
}

std::string SourceLocation::to_string() const
{
  if (!valid)
  {
    return {};
  }
  return std::to_string(line) + ":" + std::to_string(column);
}

SourceLocation NodeSet::locate(const xml::Element& element) const
{
  const auto name = element.get_name();
  if (name.data() == nullptr || mSourceXml.empty())
  {
    return {};
  }

  const char* base = reinterpret_cast<const char*>(mSourceXml.data());
  const char* pointer = name.data();
  if (pointer < base || pointer >= base + mSourceXml.size())
  {
    return {};
  }

  const auto offset = numeric_cast<std::size_t>(pointer - base);
  // Number of newlines strictly before `offset` == zero-based line => 1-based line is +1.
  const auto after = std::upper_bound(mNewlineOffsets.begin(), mNewlineOffsets.end(), offset);
  const auto line = numeric_cast<uint32_t>(std::distance(mNewlineOffsets.begin(), after)) + 1;
  const std::size_t lineStart = (after == mNewlineOffsets.begin()) ? 0 : (*(after - 1) + 1);
  const auto column = numeric_cast<uint32_t>(offset - lineStart) + 1;
  return SourceLocation{line, column, true};
}

SourceLocation Element::source_location() const
{
  if (mNodeSet == nullptr)
  {
    return {};
  }
  return mNodeSet->locate(mXmlElement);
}

const std::unordered_map<NodeId, unique_ptr<Node>>& NodeSet::nodes() const
{
  return mNodes;
}

std::unordered_map<NodeId, unique_ptr<Node>>& NodeSet::nodes()
{
  return mNodes;
}

UriTable::UriTable(xml::Element xmlElement, NodeSet& nodeSet) : Element(xmlElement, nodeSet)
{}

std::vector<String> UriTable::uris() const
{
  check(mNodeSet);
  XmlDecoder decoder{mNodeSet->structure_resolver(), mXmlElement, mNodeSet->encoding_limits()};
  Array<String> uris;
  check(mNodeSet);
  decoder.decode(mNodeSet->encoding_limits().stack_depth(), "", false, uris);
  return std::move(uris.payload());
}

ModelTableEntry::ModelTableEntry(xml::Element xmlElement, NodeSet& nodeSet) : Element(xmlElement, nodeSet)
{}

String ModelTableEntry::model_uri() const
{
  // `ModelUri` is a schema `use="required"` attribute; surface a missing value as a decode error.
  return require_node_attribute(get_attribute_value_text(mXmlElement, "ModelUri"), "ModelUri");
}

String ModelTableEntry::xml_schema_uri() const
{
  // `XmlSchemaUri` is `use="optional"`; an absent attribute yields an empty string, not an error.
  return String{get_attribute_value_text(mXmlElement, "XmlSchemaUri").value_or(string_view{})};
}

String ModelTableEntry::version() const
{
  // `Version` has no schema `use`/`default`, so it defaults to optional; absent yields an empty string.
  return String{get_attribute_value_text(mXmlElement, "Version").value_or(string_view{})};
}

DateTime ModelTableEntry::publication_date() const
{
  return require_node_attribute(
    get_attribute_value<DateTime>(*mNodeSet, mXmlElement, "PublicationDate"), "PublicationDate");
}

std::vector<RolePermissionType> ModelTableEntry::role_permissions() const
{
  return get_role_permissions(*mNodeSet, mXmlElement);
}

AccessRestrictionType ModelTableEntry::access_restrictions() const
{
  // `AccessRestrictions` carries a schema `default="0"`, so the attribute is optional; an absent
  // attribute means "no restrictions" (0), not a decode error.
  return AccessRestrictionType{
    get_attribute_value<AccessRestrictionType::UnderlyingType>(*mNodeSet, mXmlElement, "AccessRestrictions")
      .value_or(0)};
}

std::vector<ModelTableEntry> ModelTableEntry::required_models() const
{
  std::vector<ModelTableEntry> result;

  auto model = mXmlElement.get_first_child("RequiredModel");
  while (model)
  {
    result.emplace_back(model.value(), *mNodeSet);

    // Sibling iteration must advance from the current <RequiredModel>, not the
    // parent element (same class of bug as the RolePermissions loop above).
    model = model->get_next("RequiredModel");
  }

  return result;
}

AliasTable::AliasTable(xml::Element xmlElement, NodeSet& nodeSet) : Element(xmlElement, nodeSet)
{
  const string_view name{"Alias"};
  auto child = mXmlElement.get_first_child(name);
  while (child)
  {
    if (auto attributeText = get_attribute_value_text(child.value(), name))
    {
      mIndex.emplace(*attributeText, *child);
    }
    child = child->get_next(name);
  }
}

optional<NodeId> AliasTable::find_raw_node_id(string_view alias) const
{
  const auto found = mIndex.find(alias);
  if (found == mIndex.end())
  {
    return {};
  }
  NodeId nodeId;
  xml::parser::parse(found->second.get_value(), nodeId);
  return nodeId;
}

ObjectType::ObjectType(xml::Element xmlElement, NodeSet& nodeSet) : Type(xmlElement, nodeSet)
{}

ua::NodeClass ObjectType::node_class() const
{
  return ua::NodeClass::ObjectType;
}

VariableType::VariableType(xml::Element xmlElement, NodeSet& nodeSet) : Type(xmlElement, nodeSet)
{}

Variant VariableType::value() const
{
  check(mNodeSet);
  return value(mNodeSet->structure_resolver(), CodecNamespaceContext{});
}

Variant VariableType::value(const CodecNamespaceContext& namespaceConfig) const
{
  check(mNodeSet);
  return value(mNodeSet->structure_resolver(), namespaceConfig);
}

Variant VariableType::value(
  const StructureResolver& resolver, const CodecNamespaceContext& namespaceConfig) const
{
  Variant result;
  auto valueElement = mXmlElement.get_first_child("Value");
  if (valueElement)
  {
    check(mNodeSet);
    XmlDecoder decoder{resolver, mXmlElement, mNodeSet->encoding_limits(), namespaceConfig};
    decoder.decode(mNodeSet->encoding_limits().stack_depth(), "", false, result);
  }
  return result;
}

NodeId VariableType::data_type() const
{
  auto dataType = get_attribute_value<NodeId>(*mNodeSet, mXmlElement, "DataType");
  if (!dataType)
  {
    dataType = NodeId{DataTypeId::BaseDataType};
  }

  return dataType.value();
}

int32_t VariableType::value_rank() const
{
  auto valueRank = get_attribute_value<int32_t>(*mNodeSet, mXmlElement, "ValueRank");
  if (!valueRank)
  {
    valueRank = -1;
  }

  return valueRank.value();
}

Dimensions VariableType::array_dimensions() const
{
  Dimensions result;

  auto attributeText = get_attribute_value_text(mXmlElement, "ArrayDimensions");
  if (attributeText)
  {
    result = parse_array_dimensions_attribute(attributeText.value());
  }

  return result;
}

ua::NodeClass VariableType::node_class() const
{
  return ua::NodeClass::VariableType;
}

DataType::DataType(xml::Element xmlElement, NodeSet& nodeSet) : Type(xmlElement, nodeSet)
{}

optional<DataTypeDefinition> DataType::definition() const
{
  optional<DataTypeDefinition> result;
  auto temp = mXmlElement.get_first_child("Definition");
  if (temp)
  {
    result.emplace(DataTypeDefinition{temp.value(), *mNodeSet});
  }
  return result;
}

DataType::DataTypePurpose DataType::purpose() const
{
  DataType::DataTypePurpose result{DataTypePurpose::Normal};

  auto text = get_attribute_value_text(mXmlElement, "Purpose");
  if (text)
  {
    if (text.value() == "Normal")
    {
      result = DataTypePurpose::Normal;
    }
    else if (text.value() == "ServicesOnly")
    {
      result = DataTypePurpose::ServicesOnly;
    }
    else if (text.value() == "CodeGenerator")
    {
      result = DataTypePurpose::CodeGenerator;
    }
    else
    {
      throw UaException{Status::BadDecodingError,
        ErrorDetail::build(
          "InvalidNodesetXml", "Unknown DataType Purpose attribute value", "XmlNodesetParser")
          .context(ua::ContextKeys::nodeAttribute, "Purpose")
          .context(ua::ContextKeys::actual, std::string(text.value()))};
    }
  }
  return result;
}

ua::NodeClass DataType::node_class() const
{
  return ua::NodeClass::DataType;
}

ReferenceType::ReferenceType(xml::Element xmlElement, NodeSet& nodeSet) : Type(xmlElement, nodeSet)
{}

std::vector<LocalizedText> ReferenceType::inverse_name() const
{
  return get_localized_text(*mNodeSet, mXmlElement, "InverseName");
}

bool ReferenceType::symmetric() const
{
  auto symmetric = get_attribute_value<bool>(*mNodeSet, mXmlElement, "Symmetric");
  if (!symmetric)
  {
    symmetric = false;
  }

  return symmetric.value();
}

ua::NodeClass ReferenceType::node_class() const
{
  return ua::NodeClass::ReferenceType;
}

Object::Object(xml::Element xmlElement, NodeSet& nodeSet) : Instance(xmlElement, nodeSet)
{}

EventNotifierType Object::event_notifier() const
{
  EventNotifierType result;
  auto value =
    get_attribute_value<EventNotifierType::UnderlyingType>(*mNodeSet, mXmlElement, "EventNotifier");
  if (value)
  {
    result = EventNotifierType{value.value()};
  }

  return result;
}

ua::NodeClass Object::node_class() const
{
  return ua::NodeClass::Object;
}

Variable::Variable(xml::Element xmlElement, NodeSet& nodeSet) : Instance(xmlElement, nodeSet)
{}

Variant Variable::value() const
{
  return value(mNodeSet->structure_resolver(), CodecNamespaceContext{});
}

Variant Variable::value(const CodecNamespaceContext& namespaceConfig) const
{
  return value(mNodeSet->structure_resolver(), namespaceConfig);
}

Variant Variable::value(const StructureResolver& resolver, const CodecNamespaceContext& namespaceConfig) const
{
  Variant result;

  if (auto valueElement = mXmlElement.get_first_child("Value"))
  {
    result = decode_variant_with_config(*mNodeSet, *valueElement, resolver, namespaceConfig);
  }

  return result;
}

std::vector<TranslationType> Variable::translation() const
{
  std::vector<TranslationType> result;

  const string_view translationName{"Translation"};
  auto translation = mXmlElement.get_first_child(translationName);
  while (translation)
  {
    result.push_back(parse_translation(*mNodeSet, translation.value()));

    translation = mXmlElement.get_next(translationName);
  }

  return result;
}

NodeId Variable::data_type() const
{
  auto dataType = get_attribute_value<NodeId>(*mNodeSet, mXmlElement, "DataType");
  if (!dataType)
  {
    dataType = NodeId{DataTypeId::BaseDataType};
  }

  return dataType.value();
}

int32_t Variable::value_rank() const
{
  auto valueRank = get_attribute_value<int32_t>(*mNodeSet, mXmlElement, "ValueRank");
  if (!valueRank)
  {
    valueRank = -1;
  }

  return valueRank.value();
}

Dimensions Variable::array_dimensions() const
{
  Dimensions result;

  auto attributeText = get_attribute_value_text(mXmlElement, "ArrayDimensions");
  if (attributeText)
  {
    result = parse_array_dimensions_attribute(attributeText.value());
  }

  return result;
}

AccessLevelExType Variable::access_level() const
{
  AccessLevelExType result;
  result.set(AccessLevelExType::Bit::CurrentRead);

  auto accessLevel =
    get_attribute_value<AccessLevelExType::UnderlyingType>(*mNodeSet, mXmlElement, "AccessLevel");
  if (accessLevel)
  {
    result.from_underlying_type(accessLevel.value());
  }

  return result;
}

Duration Variable::minimum_sampling_interval() const
{
  Duration result{0};

  auto msi = get_attribute_value<double>(*mNodeSet, mXmlElement, "MinimumSamplingInterval");
  if (msi)
  {
    result = msi.value();
  }

  return result;
}

bool Variable::historizing() const
{
  bool result{false};

  auto historizing = get_attribute_value<bool>(*mNodeSet, mXmlElement, "Historizing");
  if (historizing)
  {
    result = historizing.value();
  }

  return result;
}

ua::NodeClass Variable::node_class() const
{
  return ua::NodeClass::Variable;
}

Method::Method(xml::Element xmlElement, NodeSet& nodeSet) : Instance(xmlElement, nodeSet)
{}

std::vector<MethodArgument> Method::argument_descriptions() const
{
  std::vector<MethodArgument> result;

  const string_view name{"ArgumentDescription"};
  auto argumentDescription = mXmlElement.get_first_child(name);
  while (argumentDescription)
  {
    MethodArgument entry;

    auto value = get_child_element_value<String>(*mNodeSet, argumentDescription.value(), "Name");
    if (value)
    {
      entry.name = std::move(value.value());
    }

    auto descriptionElement = argumentDescription->get_first_child("Description");
    while (descriptionElement)
    {
      LocalizedText localizedText;
      check(mNodeSet);
      XmlDecoder decoder{mNodeSet->structure_resolver(), mXmlElement, mNodeSet->encoding_limits()};
      decoder.decode(mNodeSet->encoding_limits().stack_depth(), "", false, localizedText);

      entry.description.push_back(std::move(localizedText));

      descriptionElement = descriptionElement->get_next(name);
    }

    result.push_back(std::move(entry));

    argumentDescription = argumentDescription->get_next(name);
  }

  return result;
}

NodeId Method::method_declaration_id() const
{
  NodeId result;

  auto value = get_attribute_value<NodeId>(*mNodeSet, mXmlElement, "MethodDeclarationId");
  if (value)
  {
    result = std::move(value.value());
  }

  return result;
}

ua::NodeClass Method::node_class() const
{
  return ua::NodeClass::Method;
}

View::View(xml::Element xmlElement, NodeSet& nodeSet) : Instance(xmlElement, nodeSet)
{}

bool View::contains_no_loops() const
{
  bool result{false};

  auto value = get_attribute_value<bool>(*mNodeSet, mXmlElement, "ContainsNoLoops");
  if (value)
  {
    result = value.value();
  }

  return result;
}

EventNotifierType View::event_notifier() const
{
  EventNotifierType result;

  auto value =
    get_attribute_value<EventNotifierType::UnderlyingType>(*mNodeSet, mXmlElement, "EventNotifier");
  if (value)
  {
    result = EventNotifierType{value.value()};
  }

  return result;
}

ua::NodeClass View::node_class() const
{
  return ua::NodeClass::View;
}

DataTypeField::DataTypeField(xml::Element xmlElement, NodeSet& nodeSet) : Element(xmlElement, nodeSet)
{}

DataTypeField::DataTypeField(const DataTypeField& other) : DataTypeField(other.mXmlElement, *other.mNodeSet)
{}

DataTypeField& DataTypeField::operator=(const DataTypeField& other)
{
  mXmlElement = other.mXmlElement;
  mNodeSet = other.mNodeSet;
  return *this;
}

DataTypeField& DataTypeField::operator=(DataTypeField&& other)
{
  return operator=(static_cast<const DataTypeField&>(other));
}

std::vector<LocalizedText> DataTypeField::display_name() const
{
  std::vector<LocalizedText> result;

  auto displayName = get_localized_text(*mNodeSet, mXmlElement, "DisplayName");
  if (!displayName.empty())
  {
    result = std::move(displayName);
  }

  return result;
}

std::vector<LocalizedText> DataTypeField::description() const
{
  std::vector<LocalizedText> result;

  auto descriptionText = get_localized_text(*mNodeSet, mXmlElement, "Description");
  if (!descriptionText.empty())
  {
    result = std::move(descriptionText);
  }

  return result;
}

String DataTypeField::name() const
{
  String result;

  auto nameText = get_attribute_value_text(mXmlElement, "Name");
  if (nameText)
  {
    result = nameText.value();
  }

  return result;
}

String DataTypeField::symbolic_name() const
{
  String result;

  auto symbolicNameText = get_attribute_value_text(mXmlElement, "SymbolicName");
  if (symbolicNameText)
  {
    result = symbolicNameText.value();
  }

  return result;
}

NodeId DataTypeField::data_type() const
{
  NodeId result;

  auto dataTypeId = get_attribute_value<NodeId>(*mNodeSet, mXmlElement, "DataType");
  if (dataTypeId)
  {
    result = dataTypeId.value();
  }
  else
  {
    result = NodeId{DataTypeId::BaseDataType};
  }

  return result;
}

int32_t DataTypeField::value_rank() const
{
  int32_t result{-1};

  auto valueRank = get_attribute_value<int32_t>(*mNodeSet, mXmlElement, "ValueRank");
  if (valueRank)
  {
    result = valueRank.value();
  }

  return result;
}

Dimensions DataTypeField::array_dimensions() const
{
  Dimensions result;

  auto text = get_attribute_value_text(mXmlElement, "ArrayDimensions");
  if (text)
  {
    result = parse_array_dimensions_attribute(text.value());
  }

  return result;
}

uint32_t DataTypeField::max_string_length() const
{
  uint32_t result{0};

  auto maxStringLength = get_attribute_value<uint32_t>(*mNodeSet, mXmlElement, "MaxStringLength");
  if (maxStringLength)
  {
    result = maxStringLength.value();
  }

  return result;
}

optional<int32_t> DataTypeField::value() const
{
  return get_attribute_value<int32_t>(*mNodeSet, mXmlElement, "Value");
}

bool DataTypeField::is_optional() const
{
  bool result{false};

  auto isOptional = get_attribute_value<bool>(*mNodeSet, mXmlElement, "IsOptional");
  if (isOptional)
  {
    result = isOptional.value();
  }

  return result;
}

bool DataTypeField::allow_sub_types() const
{
  bool result{false};

  auto allowSubTypes = get_attribute_value<bool>(*mNodeSet, mXmlElement, "AllowSubTypes");
  if (allowSubTypes)
  {
    result = allowSubTypes.value();
  }

  return result;
}

DataTypeDefinition::DataTypeDefinition(xml::Element xmlElement, NodeSet& nodeSet)
  : Element(xmlElement, nodeSet)
{}

std::vector<DataTypeField> DataTypeDefinition::fields() const
{
  std::vector<DataTypeField> result;

  const string_view fieldElementName{"Field"};
  auto field = mXmlElement.get_first_child(fieldElementName);
  while (field)
  {
    result.emplace_back(field.value(), *mNodeSet);

    field = field->get_next(fieldElementName);
  }

  return result;
}

String DataTypeDefinition::name() const
{
  String result;

  auto value = get_attribute_value_text(mXmlElement, "Name");
  if (value)
  {
    result = value.value();
  }

  return result;
}

String DataTypeDefinition::symbolic_name() const
{
  String result;

  auto value = get_attribute_value_text(mXmlElement, "SymbolicName");
  if (value)
  {
    result = value.value();
  }

  return result;
}

bool DataTypeDefinition::is_union() const
{
  bool result{false};

  auto value = get_attribute_value<bool>(*mNodeSet, mXmlElement, "IsUnion");
  if (value)
  {
    result = value.value();
  }

  return result;
}

bool DataTypeDefinition::is_option_set() const
{
  bool result{false};

  auto value = get_attribute_value<bool>(*mNodeSet, mXmlElement, "IsOptionSet");
  if (value)
  {
    result = value.value();
  }

  return result;
}

QualifiedName DataTypeDefinition::base_type() const
{
  QualifiedName result;

  // `BaseType` is obsolete and carries a schema `default=""`, so the attribute is optional; an absent
  // attribute leaves the default-constructed (empty) QualifiedName, rather than throwing.
  if (const auto text = get_attribute_value_text(mXmlElement, "BaseType"))
  {
    xml::parser::parse(text.value(), result);
  }

  return result;
}

RawReference::RawReference(xml::Element xmlElement, NodeSet& nodeSet) : Element(xmlElement, nodeSet)
{}

NodeId RawReference::target_id() const
{
  return get_element_value<NodeId>(*mNodeSet, mXmlElement);
}

NodeId RawReference::type_id() const
{
  NodeId result;

  auto value = get_attribute_value<NodeId>(*mNodeSet, mXmlElement, "ReferenceType");
  if (value)
  {
    result = value.value();
  }
  else
  {
    result = NodeId{DataTypeId::BaseDataType};
  }

  return result;
}

bool RawReference::is_forward() const
{
  bool result{true};

  auto value = get_attribute_value<bool>(*mNodeSet, mXmlElement, "IsForward");
  if (value)
  {
    result = value.value();
  }

  return result;
}

Element::Element(xml::Element xmlElement, NodeSet& nodeSet) : mXmlElement(xmlElement), mNodeSet(&nodeSet)
{}

void Parser::populate_references(NodeSets nodeSets)
{
  for (auto& nodeSet : nodeSets)
  {
    if (nodeSet)
    {
      for (auto& node : nodeSet->nodes() | std::views::values)
      {
        check(node);

        auto nodeId = node->node_id();

        // Bind the parsed optional once: `release_status()` returns by value, so the guard and the
        // dereference must observe the same instance for the checker to prove engagement.
        const auto releaseStatus = node->release_status();
        if (!releaseStatus || (*releaseStatus == Node::ReleaseStatus::Released))
        {
          for (auto& ref : node->raw_references())
          {
            auto isForward = ref.is_forward();
            auto targetId = ref.target_id();
            auto typeId = ref.type_id();

            node->references().emplace_back(Node::Reference{typeId, targetId, isForward});

            if (create_inverse_reference(typeId))
            {
              if (auto target = utilities::find_node(nodeSets, targetId))
              {
                auto& refs = target->references();

                auto test = [&typeId, &nodeId, isForward](const Node::Reference& reference) -> bool
                {
                  return ((typeId == reference.typeId) && (nodeId == reference.targetId) &&
                          (!isForward == reference.isForward));
                };

                if (std::ranges::find_if(refs, test) == refs.end())
                {
                  refs.push_back({typeId, nodeId, !isForward});
                }
              }
            }
          }
        }
      }
    }
  }
}

void Parser::load_nodeset(ua::EncodingLimits limits, StackDepth limit, const Stream& inputStream,
  const StructureResolver& structureResolver, const NamespaceArray& namespaceArray, ServerArray& serverArray,
  GetDependentModelCallback getDependentModelCallback, ParserOptions options,
  std::vector<shared_ptr<NodeSet>>& nodeSets)
{
  const auto inputSize = inputStream.get_length();

  // Prefer parsing the source in place. A stream backed by externally-owned, immutable, contiguous,
  // NUL-terminated storage (e.g. the const NS0 .rodata array) exposes a contiguous_view(); rapidxml's
  // non-destructive mode never writes to it, so we skip the ~4 MB read-all copy entirely. Otherwise
  // (sockets, writable buffers, non-terminated views) fall back to an owned, NUL-terminated copy.
  std::vector<byte> ownedXml;
  span<const byte> sourceXml;
  if (const auto view = inputStream.contiguous_view(); view && !view->empty() && view->back() == byte{'\0'})
  {
    sourceXml = *view;
  }
  else
  {
    ownedXml.resize(inputSize + 1);
    const span<byte> destination{ownedXml.begin(), inputSize};
    inputStream.read_all(destination);
    ownedXml.back() = byte{'\0'};
    sourceXml = ownedXml;
  }

  // Index newline offsets - source positions for diagnostics are byte offsets into the parsed buffer.
  // (Historically this had to run before parsing because rapidxml overwrote delimiters in place; the
  // non-destructive parse no longer mutates the buffer, but the offsets are still indexed here.) The
  // final NUL sentinel is excluded.
  std::vector<std::size_t> newlineOffsets;
  for (std::size_t i = 0; i + 1 < sourceXml.size(); ++i)
  {
    if (sourceXml[i] == byte{'\n'})
    {
      newlineOffsets.push_back(i);
    }
  }

  // Parsing untrusted NodeSet XML: the low-level XML parser throws
  // rapidxml::parse_error (a std::exception, NOT a UaException) on malformed
  // input. Convert it to the decode-error contract so a bad document is a clean
  // failure, not an uncaught exception that terminates the process. Found by the
  // Phase 2 decode fuzzer (fuzz_nodeset_parse).
  auto xmlContext = [&]
  {
    try
    {
      // The document's element nesting is bounded by the decoder's depth limit (three XML levels per
      // nested value plus the NodeSet envelope) before the parser recurses into it.
      return xml::parse(
        utils::bytes_to_chars(sourceXml.data()), 3 * limits.execution.decodeRecursionDepthLimit + 16);
    }
    catch (const UaException&)
    {
      throw;
    }
    catch (const std::exception& parseError)
    {
      throw UaException{Status::BadDecodingError,
        ErrorDetail::build("InvalidNodesetXml", "NodeSet XML is not well-formed", "XmlNodesetParser")
          .context(ua::ContextKeys::errorMessage, parseError.what())};
    }
  }();

  auto nodeSetElement = xmlContext.xml_element().get_first_child("UANodeSet");
  // A missing UANodeSet root is a decoding failure.
  if (!nodeSetElement)
  {
    throw UaException{Status::BadDecodingError,
      ErrorDetail::build(
        "InvalidNodesetXml", "NodeSet document has no <UANodeSet> root element", "XmlNodesetParser")};
  }

  auto nodeSet = make_shared<NodeSet>(limits,
    std::move(ownedXml),
    sourceXml,
    std::move(xmlContext),
    nodeSetElement.value(),
    structureResolver,
    std::move(newlineOffsets),
    options);

  auto models = nodeSet->models();

  // Push before the RequiredModel walk so isAlreadyLoaded() sees this nodeset (cycle-safe).
  nodeSets.push_back(nodeSet);

  // Load dependent <RequiredModel> closure - cycle-safe, deduped, bounded, null-safe (D-K). The
  // previous recursive loader was none of these: a dependency cycle (A<->B) recursed forever, a
  // diamond (A->B,C; B,C->D) loaded D twice, the closure was unbounded, and a null stream from the
  // callback was dereferenced. `<RequiredModel>` graphs come from untrusted external files, so all
  // four are hardened here.
  static constexpr std::size_t maxNodeSetClosure = 256;

  // A dependent is "already loaded" if some loaded nodeset declares it as its own model URI. This
  // makes the walk both deduped (diamond) and cycle-safe (a cycle means the URI is already present).
  auto isAlreadyLoaded = [&nodeSets](const String& modelUri) -> bool
  {
    for (const auto& loaded : nodeSets)
    {
      for (const auto& declaredModel : loaded->models())
      {
        if (declaredModel.model_uri() == modelUri)
        {
          return true;
        }
      }
    }
    return false;
  };

  for (auto& model : models)
  {
    auto dependantModels = model.required_models();
    for (auto& dependantModel : dependantModels)
    {
      if (isAlreadyLoaded(dependantModel.model_uri()))
      {
        continue;  // dedup + cycle-safe: this model (or one mid-cycle) is already loaded
      }
      if (nodeSets.size() >= maxNodeSetClosure)
      {
        throw UaException{Status::BadInternalError,
          ErrorDetail::build(
            "NodesetClosureTooLarge", "RequiredModel closure exceeded its bound", "XmlNodesetParser")
            .context(ua::ContextKeys::sizeMax, std::to_string(maxNodeSetClosure))
            .context(ua::ContextKeys::sizeActual, std::to_string(nodeSets.size()))};
      }
      // Guard the callback: an empty resolver (no dependency resolution requested) must surface the
      // unresolved dependency as a clean Result error, exactly as a resolver that returns no stream -
      // never as a std::bad_function_call from invoking an empty std::function.
      unique_ptr<Stream> stream =
        getDependentModelCallback ? getDependentModelCallback(dependantModel) : unique_ptr<Stream>{};
      if (!stream)
      {
        throw UaException{Status::BadNotFound,
          ErrorDetail::build(
            "MissingRequiredModel", "No stream was provided for the RequiredModel", "XmlNodesetParser")
            .context(ua::ContextKeys::namespaceUri, std::string(dependantModel.model_uri()))};
      }
      load_nodeset(limits,
        limit,
        *stream,
        structureResolver,
        namespaceArray,
        serverArray,
        getDependentModelCallback,
        options,
        nodeSets);
    }
  }
}

namespace utilities
{

Node* find_node(NodeSets nodeSets, const NodeId& nodeId)
{
  Node* result{nullptr};
  for (const auto& nodeSet : nodeSets)
  {
    check(nodeSet);
    result = nodeSet->find_node(nodeId);
    if (result)
    {
      break;
    }
  }
  return result;
}

const Node* get_parent(NodeSets nodeSets, const Node& dataType)
{
  return get_target(nodeSets, dataType, NodeId{ReferenceTypeId::HasSubtype}, false);
}

const DataType* get_parent(NodeSets nodeSets, const DataType& dataType)
{
  return get_target(nodeSets, dataType, NodeId{ReferenceTypeId::HasSubtype}, false);
}

std::vector<DataTypeField> aggregate_fields(NodeSets nodeSets, const DataType& type)
{
  std::vector<DataTypeField> result;

  const DataType* node = &type;
  while (node)
  {
    // Bind the parsed optional once: `definition()` returns by value, so the guard and the
    // dereference must observe the same instance for the checker to prove engagement.
    if (const auto definition = node->definition())
    {
      auto fields = definition->fields();
      result.insert(result.begin(), fields.begin(), fields.end());
    }

    node = get_parent(nodeSets, *node);
  }

  return result;
}

bool is_a_child_of(
  const ua::EncodingLimits& limits, NodeSets nodeSets, const Node& child, const NodeId& ancestorId)
{
  const NodeId baseDataTypeId{DataTypeId::BaseDataType};

  const Node* node = &child;

  LoopLimit loopLimit{limits.execution.loopLimit};
  while (true)
  {
    loopLimit.consume_iteration();
    auto parent = get_parent(nodeSets, *node);
    if (!parent || (parent->node_id() == baseDataTypeId))
    {
      break;
    }

    if (parent->node_id() == ancestorId)
    {
      return true;
    }

    node = parent;
  }

  return false;
}

bool is_a_structure(const ua::EncodingLimits& limits, NodeSets nodeSets, const Node& dataType)
{
  return is_a_child_of(limits, nodeSets, dataType, NodeId{DataTypeId::Structure});
}

bool is_an_enumeration(const ua::EncodingLimits& limits, NodeSets nodeSets, const Node& dataType)
{
  return is_a_child_of(limits, nodeSets, dataType, NodeId{DataTypeId::Enumeration});
}

bool is_hierarchical_reference(const ua::EncodingLimits& limits, NodeSets nodeSets, const NodeId& refTypeId)
{
  bool result{false};

  const Node* typeNode = find_node(nodeSets, refTypeId);
  if (typeNode)
  {
    result = is_a_child_of(limits, nodeSets, *typeNode, NodeId{ReferenceTypeId::HierarchicalReferences});
  }
  return result;
}

}  // namespace utilities

std::vector<shared_ptr<NodeSet>> Parser::parse(ua::EncodingLimits limits, const Stream& inputStream,
  StructureResolver structureResolver, const NamespaceArray& namespaceArray, ServerArray& serverArray,
  GetDependentModelCallback getDependentModelCallback, ParserOptions options)
{
  std::vector<shared_ptr<NodeSet>> result;
  load_nodeset(limits,
    limits.stack_depth(),
    inputStream,
    structureResolver,
    namespaceArray,
    serverArray,
    std::move(getDependentModelCallback),
    options,
    result);

  populate_references(result);

  return result;
}

std::vector<shared_ptr<NodeSet>> Parser::parse(ua::EncodingLimits limits, const Stream& inputStream,
  const StructureFactory& structureFactory, const NamespaceArray& namespaceArray, ServerArray& serverArray,
  GetDependentModelCallback getDependentModelCallback, ParserOptions options)
{
  return parse(limits,
    inputStream,
    structureFactory.resolver(),
    namespaceArray,
    serverArray,
    std::move(getDependentModelCallback),
    options);
}

}  // namespace ua::xml::nodeset
