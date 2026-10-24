// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NODESET_PARSER_H
#define UA_NODESET_PARSER_H

#include "ua_built_in_types_fwd_decl.h"
#include "ua_string.h"
#include "ua_localized_text.h"
#include "ua_role_permission_type.h"
#include "ua_access_restriction_type.h"
#include "ua_attribute_write_mask.h"
#include "ua_duration.h"
#include "ua_xml_parser.h"
#include "ua_node_class.h"
#include "ua_access_level_type.h"
#include "ua_server_array.h"
#include "ua_date_time.h"
#include "ua_xml_element.h"
#include "ua_encoding_limits.h"
#include "ua_structure_factory.h"

#include <unordered_map>

namespace ua
{

class Stream;
class NamespaceArray;
class StructureFactory;
struct CodecNamespaceContext;

class EventNotifierType;
class AccessLevelExType;

namespace xml::nodeset
{

struct ParserOptions
{
  // When false, `Variant` values found in the NodeSet are not decoded during parsing.
  // This is useful for tooling that only needs type definitions and the reference graph.
  bool decodeVariantValues{true};
};

class ModelTableEntry;
class NodeSet;

using NodeSets = std::span<shared_ptr<NodeSet>>;

// 1-based source position of an element within the original NodeSet file. `valid` is false when
// the position could not be determined (e.g. the element does not map into the source buffer).
struct SourceLocation
{
  uint32_t line{0};
  uint32_t column{0};
  bool valid{false};

  // Formats as "line:col" (e.g. "148:21"), or "" when not valid. Intended for ErrorDetail::detail.
  std::string to_string() const;
};

class Element
{
public:
  Element() = delete;
  Element(const Element&) = delete;
  Element(Element&& object) noexcept = default;
  Element& operator=(const Element&) = delete;
  Element& operator=(Element&&) noexcept = delete;

  virtual ~Element(){};

  // Source position of this element in the original file, for diagnostics.
  SourceLocation source_location() const;

protected:
  xml::Element mXmlElement;
  NodeSet* mNodeSet;

  Element(xml::Element xmlElement, NodeSet& nodeSet);
};

struct TranslationType
{
  struct StructureField
  {
    String name;
    std::vector<LocalizedText> text;
  };

  std::vector<LocalizedText> text;
  std::vector<StructureField> fields;
};

class UriTable : public Element
{
public:
  UriTable(xml::Element xmlElement, NodeSet& nodeSet);

  std::vector<String> uris() const;
};

class ModelTableEntry : public Element
{
public:
  ModelTableEntry(xml::Element xmlElement, NodeSet& nodeSet);

  String model_uri() const;

  String xml_schema_uri() const;

  String version() const;

  DateTime publication_date() const;

  std::vector<RolePermissionType> role_permissions() const;

  AccessRestrictionType access_restrictions() const;

  std::vector<ModelTableEntry> required_models() const;
};

class AliasTable : public Element
{
public:
  AliasTable(xml::Element xmlElement, NodeSet& nodeSet);

  optional<NodeId> find_raw_node_id(string_view alias) const;

private:
  // Alias name -> its <Alias> element, built once so a lookup is O(1) rather than a scan of every
  // alias per reference (security review XML-11). The names view the NodeSet's own XML buffer, which
  // outlives the table; the element text is parsed on lookup, as before, so an unused malformed alias
  // still fails nothing. The first declaration of a repeated name wins, as the scan did.
  std::unordered_map<string_view, xml::Element> mIndex;
};

class RawReference : public Element
{
public:
  RawReference(xml::Element xmlElement, NodeSet& nodeSet);

  NodeId target_id() const;

  NodeId type_id() const;

  bool is_forward() const;
};

class Node : public Element
{
public:
  enum class ReleaseStatus
  {
    Released = 0,
    Draft = 1,
    Deprecated = 2
  };

  struct Reference
  {
    NodeId typeId;
    NodeId targetId;
    bool isForward;
  };

  Node(xml::Element xmlElement, NodeSet& nodeSet);

  virtual NodeClass node_class() const = 0;

  NodeId node_id() const;

  QualifiedName browse_name() const;

  optional<AttributeWriteMask> write_mask() const;

  optional<AccessRestrictionType> access_restrictions() const;

  String symbolic_name() const;

  optional<ReleaseStatus> release_status() const;

  std::vector<LocalizedText> display_name() const;

  std::vector<LocalizedText> description() const;

  optional<String> category() const;

  optional<String> documentation() const;

  std::vector<RawReference> raw_references() const;

  std::span<const Reference> references() const;

  std::vector<Reference>& references();

  std::vector<RolePermissionType> role_permissions() const;

  bool has_no_permissions() const;

  optional<xml::Element> extensions() const;

  // The node's `<Extensions>` block decoded into a raw `XmlElement` (the OPC-UA built-in string
  // scalar), preserved verbatim (D-N). Empty when the node has no `<Extensions>` element. This is
  // the XML-free form suitable for the public `NodeView::extensions()` accessor.
  optional<XmlElement> extensions_xml() const;

private:
  std::vector<Reference> mReferences;
};

class Type : public Node
{
public:
  Type(xml::Element xmlElement, NodeSet& nodeSet);

  bool is_abstract() const;
};

class ObjectType : public Type
{
public:
  ObjectType(xml::Element xmlElement, NodeSet& nodeSet);

  NodeClass node_class() const override;
};

class VariableType : public Type
{
public:
  VariableType(xml::Element xmlElement, NodeSet& nodeSet);

  NodeClass node_class() const override;

  Variant value() const;

  // Decode the value with namespace-index translation applied at source. Embedded
  // NodeId/QualifiedName/ExpandedNodeId values (including those nested inside structure
  // fields and arrays) are translated as they are decoded.
  Variant value(const CodecNamespaceContext& namespaceConfig) const;

  // As above, but decode with the supplied StructureResolver instead of the NodeSet's parse-time
  // one (D-H 6): lets an import realize the value into the target frame with the target's types,
  // so the same parsed document resolves per-target. The other overloads use the NodeSet's resolver.
  Variant value(const StructureResolver& resolver, const CodecNamespaceContext& namespaceConfig) const;

  NodeId data_type() const;

  int32_t value_rank() const;

  Dimensions array_dimensions() const;
};

class DataTypeField : public Element
{
public:
  DataTypeField(xml::Element xmlElement, NodeSet& nodeSet);
  // Assignments rebind the borrowed XML element and NodeSet. Rvalue assignment uses the same
  // operation as copy assignment; neither takes ownership of the underlying document.
  DataTypeField(const DataTypeField& other);
  DataTypeField& operator=(const DataTypeField& other);
  DataTypeField(DataTypeField&&) noexcept = default;
  DataTypeField& operator=(DataTypeField&& other);
  ~DataTypeField() = default;

  std::vector<LocalizedText> display_name() const;

  std::vector<LocalizedText> description() const;

  String name() const;

  String symbolic_name() const;

  NodeId data_type() const;

  int32_t value_rank() const;

  Dimensions array_dimensions() const;

  uint32_t max_string_length() const;

  optional<int32_t> value() const;

  bool is_optional() const;

  bool allow_sub_types() const;
};

class DataTypeDefinition : public Element
{
public:
  DataTypeDefinition(xml::Element xmlElement, NodeSet& nodeSet);

  std::vector<DataTypeField> fields() const;

  String name() const;

  String symbolic_name() const;

  bool is_union() const;

  bool is_option_set() const;

  QualifiedName base_type() const;
};

class DataType : public Type
{
public:
  enum class DataTypePurpose
  {
    Normal = 0,
    ServicesOnly = 1,
    CodeGenerator = 2
  };

  DataType(xml::Element xmlElement, NodeSet& nodeSet);

  NodeClass node_class() const override;

  optional<DataTypeDefinition> definition() const;

  DataTypePurpose purpose() const;
};

class ReferenceType : public Type
{
public:
  ReferenceType(xml::Element xmlElement, NodeSet& nodeSet);

  NodeClass node_class() const override;

  std::vector<LocalizedText> inverse_name() const;

  bool symmetric() const;
};

class Instance : public Node
{
public:
  Instance(xml::Element xmlElement, NodeSet& nodeSet);

  NodeId parent_node_id() const;
};

class Object : public Instance
{
public:
  Object(xml::Element xmlElement, NodeSet& nodeSet);

  NodeClass node_class() const override;

  EventNotifierType event_notifier() const;
};

class Variable : public Instance
{
public:
  Variable(xml::Element xmlElement, NodeSet& nodeSet);

  NodeClass node_class() const override;

  Variant value() const;

  // Decode the value with namespace-index translation applied at source. Embedded
  // NodeId/QualifiedName/ExpandedNodeId values (including those nested inside structure
  // fields and arrays) are translated as they are decoded.
  Variant value(const CodecNamespaceContext& namespaceConfig) const;

  // As above, but decode with the supplied StructureResolver instead of the NodeSet's parse-time
  // one (D-H 6): lets an import realize the value into the target frame with the target's types,
  // so the same parsed document resolves per-target. The other overloads use the NodeSet's resolver.
  Variant value(const StructureResolver& resolver, const CodecNamespaceContext& namespaceConfig) const;

  std::vector<TranslationType> translation() const;

  NodeId data_type() const;

  int32_t value_rank() const;

  Dimensions array_dimensions() const;

  AccessLevelExType access_level() const;

  Duration minimum_sampling_interval() const;

  bool historizing() const;
};

struct MethodArgument
{
  String name;
  std::vector<LocalizedText> description;
};

class Method : public Instance
{
public:
  Method(xml::Element xmlElement, NodeSet& nodeSet);

  NodeClass node_class() const override;

  std::vector<MethodArgument> argument_descriptions() const;

  NodeId method_declaration_id() const;
};

class View : public Instance
{
public:
  View(xml::Element xmlElement, NodeSet& nodeSet);

  NodeClass node_class() const override;

  bool contains_no_loops() const;

  EventNotifierType event_notifier() const;
};

class NodeSet : public Element
{
public:
  NodeSet() = delete;
  NodeSet(const NodeSet&) = delete;
  NodeSet(NodeSet&& object) noexcept = delete;
  NodeSet& operator=(const NodeSet&) = delete;
  NodeSet& operator=(NodeSet&&) noexcept = delete;
  ~NodeSet() = default;

  // @param ownedXml   Owns the source buffer when it was copied out of the input stream; empty when
  //                   the buffer was parsed in place (zero-copy) from external read-only storage.
  // @param sourceView View of the parsed buffer (base + size) used to map node pointers back to
  //                   source offsets; points into @p ownedXml when owned, else into external storage.
  NodeSet(ua::EncodingLimits limits, std::vector<byte>&& ownedXml, span<const byte> sourceView,
    xml::Context&& xmlParserContext, xml::Element xmlElement, StructureResolver structureResolver,
    std::vector<std::size_t> newlineOffsets, ParserOptions options = {});

  [[nodiscard]] const ua::EncodingLimits& encoding_limits() const;

  // Maps an element back to its 1-based line/column in the original source buffer (using the
  // pre-parse newline index). Returns an invalid SourceLocation if the element does not map into
  // this NodeSet's buffer.
  SourceLocation locate(const xml::Element& element) const;

  // Resolver used to instantiate ExtensionObject values during decode. May be empty (no custom
  // types), in which case unrecognised ExtensionObjects take the UnknownStructure path.
  const StructureResolver& structure_resolver() const;

  [[nodiscard]] bool decode_variant_values() const
  {
    return mOptions.decodeVariantValues;
  }

  optional<UriTable>& namespace_uris();

  const optional<UriTable>& namespace_uris() const;

  optional<UriTable>& server_uris();

  const optional<UriTable>& server_uris() const;

  span<const ModelTableEntry> models() const;

  optional<AliasTable>& aliases();

  const optional<AliasTable>& aliases() const;

  XmlElement& extensions();

  const XmlElement& extensions() const;

  DateTime last_modified() const;

  const std::unordered_map<NodeId, unique_ptr<Node>>& nodes() const;

  std::unordered_map<NodeId, unique_ptr<Node>>& nodes();

  Node* find_node(const NodeId& nodeId);

  template<typename T>
  auto find_node(const NodeId& nodeId) -> T*
  {
    Node* baseNode = find_node(nodeId);
    T* node{nullptr};
    if (baseNode)
    {
      node = dynamic_cast<T*>(baseNode);
    }

    return node;
  }

private:
  const ua::EncodingLimits mLimits;
  const ParserOptions mOptions;
  // Owns the source buffer for the copy path; empty when the buffer was parsed in place. `mSourceXml`
  // is the buffer actually parsed (base + size for `locate`): it points into `mOwnedXml` when owned,
  // otherwise into external read-only storage that the caller guarantees outlives this NodeSet.
  std::vector<byte> mOwnedXml;
  span<const byte> mSourceXml;
  xml::Context mXmlParserContext;
  StructureResolver mStructureResolver;
  // Byte offsets of '\n' in the original (pre-parse) buffer, ascending; powers `locate`.
  std::vector<std::size_t> mNewlineOffsets;

  optional<UriTable> mNamespaceUris;
  optional<UriTable> mServerUris;
  std::vector<ModelTableEntry> mModels;
  optional<AliasTable> mAliases;
  XmlElement mExtensions;
  DateTime mLastModified;

  std::unordered_map<NodeId, unique_ptr<Node>> mNodes;

  void add_nodes();

  template<typename T>
  void add_nodes(string_view typeName);
};

class Parser
{
public:
  using GetDependentModelCallback = std::function<unique_ptr<Stream>(const ModelTableEntry& model)>;

  // Canonical: value decode resolves ExtensionObject types via `structureResolver` (may be empty).
  static std::vector<shared_ptr<NodeSet>> parse(ua::EncodingLimits limits, const Stream& inputStream,
    StructureResolver structureResolver, const NamespaceArray& namespaceArray, ServerArray& serverArray,
    GetDependentModelCallback getDependentModelCallback, ParserOptions options = {});

  // Convenience: resolve via a StructureFactory (must outlive the returned NodeSets).
  static std::vector<shared_ptr<NodeSet>> parse(ua::EncodingLimits limits, const Stream& inputStream,
    const StructureFactory& structureFactory, const NamespaceArray& namespaceArray, ServerArray& serverArray,
    GetDependentModelCallback getDependentModelCallback, ParserOptions options = {});

private:
  Parser()
  {}

  static void populate_references(NodeSets nodeSets);

  static void load_nodeset(ua::EncodingLimits limits, StackDepth limit, const Stream& inputStream,
    const StructureResolver& structureResolver, const NamespaceArray& namespaceArray,
    ServerArray& serverArray, GetDependentModelCallback getDependentModelCallback, ParserOptions options,
    std::vector<shared_ptr<NodeSet>>& nodeSets);
};

namespace utilities
{

Node* find_node(NodeSets nodeSets, const NodeId& nodeId);

template<typename T>
auto get_target(NodeSets nodeSets, const T& source, const NodeId& refTypeId, bool isForward) -> const T*
{
  const T* result{nullptr};

  for (const auto& reference : source.references())
  {
    if ((reference.typeId == refTypeId) && (reference.isForward == isForward))
    {
      auto node = find_node(nodeSets, reference.targetId);
      result = dynamic_cast<T*>(node);
      break;
    }
  }

  return result;
}

const Node* get_parent(NodeSets nodeSets, const Node& dataType);

const DataType* get_parent(NodeSets nodeSets, const DataType& dataType);

std::vector<DataTypeField> aggregate_fields(NodeSets nodeSets, const DataType& type);

bool is_a_child_of(
  const ua::EncodingLimits& limits, NodeSets nodeSets, const Node& child, const NodeId& ancestorId);

bool is_a_structure(const ua::EncodingLimits& limits, NodeSets nodeSets, const Node& dataType);

bool is_an_enumeration(const ua::EncodingLimits& limits, NodeSets nodeSets, const Node& dataType);

bool is_hierarchical_reference(const ua::EncodingLimits& limits, NodeSets nodeSets, const NodeId& refTypeId);

}  // namespace utilities

}  // namespace xml::nodeset

}  // namespace ua

#endif  //! UA_NODESET_PARSER_H
