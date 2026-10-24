// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NODESET_WRITER_H
#define UA_NODESET_WRITER_H

#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ua_codec_namespace_context.h"
#include "ua_data_type_definition.h"
#include "ua_date_time.h"
#include "ua_encoding_limits.h"
#include "ua_expanded_node_id.h"
#include "ua_localized_text.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_string.h"
#include "ua_variant.h"
#include "ua_xml_writer.h"

namespace ua
{
class Stream;
}

namespace ua::xml::nodeset
{

// One reference to emit on a node. Ids carry SERVER namespace indices; the writer remaps them to
// file-local indices at emit time.
struct ExportedReference
{
  NodeId referenceTypeId;
  ExpandedNodeId targetId;
  bool isForward{true};
};

// A node's exportable state, in SERVER namespace indices. The read pass (ExportEngine, phase 4b)
// fills these from the live AddressSpace; `NodeSetWriter` serializes them. Optional members are
// emitted only when present; empty `std::vector` members are omitted.
//
// Scope (phase 4a): base + the common per-class attributes, references, and a Variable/VariableType
// Value. DataType `<Definition>` and Method argument metadata are a follow-up.
struct ExportedNode
{
  NodeId nodeId;
  NodeClass nodeClass{NodeClass::Unspecified};
  QualifiedName browseName;
  std::vector<LocalizedText> displayName;
  std::vector<LocalizedText> description;
  optional<uint32_t> writeMask;

  // Types (ObjectType / VariableType / DataType / ReferenceType).
  optional<bool> isAbstract;

  // ReferenceType.
  optional<bool> symmetric;
  std::vector<LocalizedText> inverseName;

  // Variable / VariableType.
  optional<NodeId> dataType;
  optional<int32_t> valueRank;
  std::vector<int32_t> arrayDimensions;
  optional<Variant> value;

  // DataType `<Definition>` (Structure or Enum). Null when the node carries no DataTypeDefinition
  // attribute (most NS0 leaf types and all non-DataType classes).
  shared_ptr<const DataTypeDefinition> dataTypeDefinition;

  // Variable.
  optional<uint8_t> accessLevel;
  optional<double> minimumSamplingInterval;
  optional<bool> historizing;

  // Object / View.
  optional<uint8_t> eventNotifier;

  // View.
  optional<bool> containsNoLoops;

  // Method.
  optional<bool> executable;

  std::vector<ExportedReference> references;
};

// One `<RequiredModel>` dependency of a `<Model>`.
struct NodeSetRequiredModel
{
  String modelUri;
  String version;
  DateTime publicationDate;
};

// One `<Model>` entry for the document header, with its declared `<RequiredModel>` dependencies.
struct NodeSetModel
{
  String modelUri;
  String version;
  DateTime publicationDate;
  std::vector<NodeSetRequiredModel> requiredModels;
};

// Configuration for a `NodeSetWriter`.
struct NodeSetWriterOptions
{
  // The non-NS0 namespace URIs, in file order: `namespaceUris[i]` is the URI for file index (i + 1).
  // Emitted verbatim into `<NamespaceUris>`.
  std::vector<String> namespaceUris;

  // Maps a SERVER namespace index to its FILE-local index. Must map server index 0 (NS0) to file
  // index 0 (which is implicit and not listed in `<NamespaceUris>`).
  std::function<uint16_t(uint16_t)> serverToFileIndex;

  // Optional `<Models>` entries.
  std::vector<NodeSetModel> models;

  // Optional `LastModified` timestamp, emitted as an attribute on `<UANodeSet>` when set.
  optional<DateTime> lastModified;

  // Symbolic aliases for frequently-referenced reference/data types: each entry maps a SERVER NodeId
  // to the unprefixed alias name. Emitted as `<Aliases>` (in this order) and substituted for the
  // corresponding ReferenceType / DataType ids in node markup. Empty disables aliasing.
  std::vector<std::pair<NodeId, String>> aliases;

  // Namespace-translation context applied to ids embedded inside a `<Value>` (server -> file). The
  // default leaves embedded ids untranslated, which is correct for values with no embedded ids.
  CodecNamespaceContext valueContext;

  // When a `<Value>` cannot be transcoded to XML (an unresolved opaque binary-bodied ExtensionObject),
  // `true` propagates the failure so the document is not produced; `false` omits that `<Value>` and
  // keeps the rest of the node. Mirrors the importer's OnUnknownStructure disposition.
  bool failOnUnencodableStructure{true};
};

// Synchronous serializer that emits an OPC UA NodeSet2 document from `ExportedNode` records. The
// envelope (root, `<NamespaceUris>`, `<Models>`, per-class node elements, `<References>`) is written
// via `XmlWriter`; a node's `<Value>` is delegated to `XmlEncoder` (wrapped in a `<Value>` whose
// default `xmlns` is the OPC UA Types.xsd namespace, so the value content is correctly namespaced
// without a codec change). Stateless across documents apart from the underlying stream cursor.
class NodeSetWriter
{
public:
  NodeSetWriter(Stream& stream, EncodingLimits limits, NodeSetWriterOptions options);

  // Writes the XML declaration, the `<UANodeSet>` start tag with namespace declarations, and the
  // `<NamespaceUris>` / `<Models>` header blocks.
  void begin_document();

  // Emits one node element (`<UAObject>` / `<UAVariable>` / ...) with its attributes and children.
  void write_node(const ExportedNode& node);

  // Closes the `<UANodeSet>` element.
  void end_document();

private:
  std::string file_node_id(const NodeId& nodeId) const;
  std::string file_node_id(const ExpandedNodeId& nodeId) const;
  std::string file_qualified_name(const QualifiedName& browseName) const;
  // The alias name for a reference/data type id when one is configured, else its file NodeId.
  std::string file_id_or_alias(const NodeId& nodeId) const;

  void write_localized_texts(string_view element, const std::vector<LocalizedText>& texts);
  void write_references(const std::vector<ExportedReference>& references);
  void write_value(const Variant& value);
  void write_definition(const ExportedNode& node);

  static string_view element_for_class(NodeClass nodeClass);

  Stream& mStream;
  EncodingLimits mLimits;
  NodeSetWriterOptions mOptions;
  XmlWriter mWriter;
  // Server NodeId -> alias name lookup, built from mOptions.aliases at construction.
  std::unordered_map<NodeId, String> mAliasByServerId;
};

}  // namespace ua::xml::nodeset

#endif  // !UA_NODESET_WRITER_H
