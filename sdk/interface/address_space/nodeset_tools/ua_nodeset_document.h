// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_NODESET_DOCUMENT_H
#define UA_NODESET_DOCUMENT_H

/// @file
/// @brief XML-free read model of a parsed NodeSet and its inspection API.
/// @ingroup address_space

#include "ua_includes.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_node_class.h"
#include "ua_string.h"
#include "ua_result.h"
#include "ua_structure_factory.h"
#include "ua_xml_element.h"
#include "ua_date_time.h"

// Forward declaration of the private parse-tree node. Its full definition lives in the (private)
// XML parser header; the read model deliberately keeps rapidxml and the parse-tree out of this
// public header, so a forward declaration is all the view types need to hold a typed pointer.
namespace ua::xml::nodeset
{
class Node;
}

namespace ua
{

class Stream;

class NodeSetDocumentImpl;

// =============================================================================
// Public NodeSet parse + inspection API (tier b) - XML-free facade.
//
// `parse_nodeset` produces an immutable, XML-free read model of a NodeSet (and
// its resolved dependencies) that customers can walk - to build validators or
// tooling - before, or instead of, importing it. The XML backend, the internal
// parse-tree, and the importer machinery are all confined to `implementation/`;
// none of them appear here. Failures are reported through `Result<T>` /
// `ErrorDetail` rather than thrown out of the `try_*` form.
//
// Importing a parsed document into an AddressSpace is a separate concern: see
// `ua_nodeset_import.h`. The document itself exposes no import method (D-G).
// =============================================================================

/// Immutable, XML-free view of a single reference, passed to `reference_filter`.
/// @ingroup address_space
class ReferenceView
{
public:
  /// Constructs a view over one reference.
  ///
  /// @param referenceTypeId File-local NodeId of the reference type.
  /// @param targetId        File-local NodeId of the referenced (target) node.
  /// @param isForward       True for a forward reference, false for an inverse one.
  ReferenceView(NodeId referenceTypeId, NodeId targetId, bool isForward)
    : mReferenceTypeId(std::move(referenceTypeId)), mTargetId(std::move(targetId)), mIsForward(isForward)
  {}

  /// File-local NodeId of the reference type.
  ///
  /// @return The file-local NodeId of the reference type.
  const NodeId& reference_type_id() const
  {
    return mReferenceTypeId;
  }

  /// File-local NodeId of the referenced (target) node.
  ///
  /// @return The file-local NodeId of the referenced (target) node.
  const NodeId& target_id() const
  {
    return mTargetId;
  }

  /// True if the reference points forward, false if it is inverse.
  ///
  /// @return True if the reference points forward, false if it is inverse.
  bool is_forward() const
  {
    return mIsForward;
  }

private:
  NodeId mReferenceTypeId;
  NodeId mTargetId;
  bool mIsForward;
};

class DataTypeView;
class VariableView;

/// @ingroup address_space
/// A node's `<ReleaseStatus>` annotation.
///
/// Drives release-status filtering: by default an import skips Draft/Deprecated nodes, and a
/// `node_filter` can inspect this to decide otherwise.
enum class NodeReleaseStatus
{
  Released,  ///< The node is released for production use.
  Draft,  ///< The node is provisional; skipped by the default import filter.
  Deprecated  ///< The node is deprecated; skipped by the default import filter.
};

/// Immutable, XML-free view of a single node.
///
/// Backed by the (private) parse-tree node via a non-owning typed pointer; the accessors below are
/// the only surface customers see. Ids and names are in the file's own (document-local) namespace,
/// matching what a `node_filter` decides about before any server-side translation. The richer
/// accessors (`references`, `as_data_type`, `as_variable`) require a parsed `NodeSetDocument`
/// context; in a bare `node_filter` they return empty.
/// @ingroup address_space
class NodeView
{
public:
  /// Constructs a view over a parse-tree node, with an optional document context.
  ///
  /// Internal: invoked by the import / parse machinery. Customers receive a `NodeView`; they never
  /// construct one.
  ///
  /// @param node     Non-owning pointer to the private parse-tree node.
  /// @param document Non-owning pointer to the owning document context, or nullptr when the view is
  ///                 supplied to a bare `node_filter` (richer accessors then return empty).
  explicit NodeView(const ua::xml::nodeset::Node* node, const NodeSetDocumentImpl* document = nullptr)
    : mNode(node), mDocument(document)
  {}

  /// File-local NodeId of this node.
  ///
  /// @return This node's file-local NodeId.
  NodeId node_id() const;

  /// File-local browse name of this node.
  ///
  /// @return This node's file-local browse name.
  QualifiedName browse_name() const;

  /// NodeClass of this node.
  ///
  /// @return This node's NodeClass.
  NodeClass node_class() const;

  /// The node's `Category` annotation, or empty if absent. Powers category-based filtering.
  ///
  /// @return The node's `Category` annotation, or empty if the node has none.
  optional<String> category() const;

  /// The node's `<ReleaseStatus>` annotation, or empty if unspecified.
  ///
  /// An empty value is treated as Released by the default import filter. Exposed so a `node_filter`
  /// can act on it.
  ///
  /// @return The node's release status, or empty if the annotation is unspecified.
  optional<NodeReleaseStatus> release_status() const;

  /// The node's raw `<Extensions>` block, or empty if absent.
  ///
  /// Preserved verbatim as an `XmlElement` (the OPC-UA built-in string scalar); not interpreted.
  ///
  /// @return The node's raw `<Extensions>` block, or empty if absent.
  optional<XmlElement> extensions() const;

  /// This node's outgoing references, with file-local ids.
  ///
  /// @return This node's outgoing references, with file-local ids.
  std::vector<ReferenceView> references() const;

  /// DataType-specific detail, or empty if this node is not a DataType.
  ///
  /// Requires a document context; returns empty when the view carries none or on a class mismatch.
  ///
  /// @return DataType-specific detail, or empty if this node is not a DataType or carries no document
  ///         context.
  optional<DataTypeView> as_data_type() const;

  /// Variable-specific detail, or empty if this node is not a Variable.
  ///
  /// Requires a document context; returns empty when the view carries none or on a class mismatch.
  ///
  /// @return Variable-specific detail, or empty if this node is not a Variable or carries no document
  ///         context.
  optional<VariableView> as_variable() const;

private:
  const ua::xml::nodeset::Node* mNode;
  const NodeSetDocumentImpl* mDocument;
};

/// One field of an (aggregated) DataType structure/enum definition.
/// @ingroup address_space
struct DataTypeFieldView
{
  String name;  ///< Field name.
  NodeId dataType;  ///< File-local NodeId of the field's DataType.
  int32_t valueRank{-1};  ///< Value rank: -1 for a scalar, >= 0 for an array of that dimension.
  bool isOptional{false};  ///< True if the field is optional in the structure.
};

/// DataType-specific view: abstractness, structure/enum kind, and the aggregated field list.
///
/// The field list includes base-type fields, resolved across the parsed document.
/// @ingroup address_space
class DataTypeView
{
public:
  /// Constructs a DataType view over a parse-tree node and its document context.
  ///
  /// Internal: invoked by the parse machinery. Customers obtain one via `NodeView::as_data_type`.
  ///
  /// @param node     Non-owning pointer to the private parse-tree node.
  /// @param document Non-owning pointer to the owning document context.
  explicit DataTypeView(const ua::xml::nodeset::Node* node, const NodeSetDocumentImpl* document)
    : mNode(node), mDocument(document)
  {}

  /// True if the DataType is abstract.
  ///
  /// @return True if the DataType is abstract.
  bool is_abstract() const;

  /// True if the DataType is a structure.
  ///
  /// @return True if the DataType is a structure.
  bool is_structure() const;

  /// True if the DataType is an enumeration.
  ///
  /// @return True if the DataType is an enumeration.
  bool is_enumeration() const;

  /// The aggregated field list, including inherited base-type fields.
  ///
  /// @return The aggregated field list, including inherited base-type fields.
  std::vector<DataTypeFieldView> fields() const;

private:
  const ua::xml::nodeset::Node* mNode;
  const NodeSetDocumentImpl* mDocument;
};

/// Variable-specific view: the variable's DataType and value rank.
/// @ingroup address_space
class VariableView
{
public:
  /// Constructs a Variable view over a parse-tree node.
  ///
  /// Internal: invoked by the parse machinery. Customers obtain one via `NodeView::as_variable`.
  ///
  /// @param node Non-owning pointer to the private parse-tree node.
  explicit VariableView(const ua::xml::nodeset::Node* node) : mNode(node)
  {}

  /// File-local NodeId of the variable's DataType.
  ///
  /// @return The file-local NodeId of the variable's DataType.
  NodeId data_type() const;

  /// Value rank: -1 for a scalar, >= 0 for an array of that dimension.
  ///
  /// @return The variable's value rank: -1 for a scalar, >= 0 for an array of that dimension.
  int32_t value_rank() const;

private:
  const ua::xml::nodeset::Node* mNode;
};

/// One server namespace slot allocated (or resolved) for a URI the file declared.
/// @ingroup address_space
struct NamespaceMapping
{
  String uri;  ///< Declared namespace URI.
  uint16_t serverIndex{};  ///< File-local namespace index for the URI.
};

/// A reference to a dependent model declared via `<RequiredModel>`.
/// @ingroup address_space
struct ModelRef
{
  String uri;  ///< Model namespace URI.
  String version;  ///< Required model version string.
};

/// Options controlling how a NodeSet stream is parsed into a `NodeSetDocument`.
/// @ingroup address_space
struct NodeSetParseOptions
{
  /// Resolves `<RequiredModel>` dependencies to their NodeSet streams.
  ///
  /// Invoked once per declared dependency; returns the dependency's stream, or nullptr to leave it
  /// unresolved. Empty by default (no dependency resolution).
  std::function<std::unique_ptr<Stream>(const ModelRef&)> resolveRequiredModel;

  /// Resolves custom ExtensionObject value types.
  ///
  /// @see NodeSetImportOptions::structure_resolver
  StructureResolver structureResolver;

  /// When false, `Variant` values are not decoded (type-graph-only inspection). Defaults to true.
  bool decodeValues{true};
};

class NodeSetDocumentImpl;

/// Immutable, owned read model of a parsed NodeSet (and its resolved dependencies).
///
/// Produced by `try_parse_nodeset_sync`; move-only and not copyable. The document exposes no import
/// method - importing it into an AddressSpace is a separate free-function concern (see
/// `ua_nodeset_import.h`).
///
/// @ingroup address_space
/// @see try_parse_nodeset_sync
class NodeSetDocument
{
public:
  /// Constructs a document from its private implementation.
  ///
  /// Internal: invoked by the parse machinery. Customers obtain a document via
  /// `try_parse_nodeset_sync`, not this constructor.
  ///
  /// @param impl Owned implementation backing the read model.
  explicit NodeSetDocument(std::unique_ptr<NodeSetDocumentImpl> impl);

  /// Move-constructs, transferring ownership of the read model.
  NodeSetDocument(NodeSetDocument&&) noexcept;

  /// Move-assigns, transferring ownership of the read model.
  ///
  /// @return Reference to this document.
  NodeSetDocument& operator=(NodeSetDocument&&) noexcept;

  NodeSetDocument(const NodeSetDocument&) = delete;
  NodeSetDocument& operator=(const NodeSetDocument&) = delete;

  ~NodeSetDocument();

  /// Namespaces the file declares, in file-local order.
  ///
  /// Each entry's `server_index` is the file-local namespace index. The span is owned by the
  /// document and valid for its lifetime.
  ///
  /// @return The namespaces the file declares, in file-local order.
  std::span<const NamespaceMapping> declared_namespaces() const;

  /// The `<RequiredModel>` dependencies declared by the file.
  ///
  /// The span is owned by the document and valid for its lifetime.
  ///
  /// @return The `<RequiredModel>` dependencies declared by the file.
  std::span<const ModelRef> required_models() const;

  /// All parsed nodes, as file-local views.
  ///
  /// @return All parsed nodes, as file-local views.
  std::vector<NodeView> nodes() const;

  /// Finds a parsed node by its file-local NodeId.
  ///
  /// @param nodeId File-local NodeId to look up.
  /// @return The matching node view, or empty if no node has that id.
  optional<NodeView> find(const NodeId& nodeId) const;

  /// The NodeSet-level `<Extensions>` block describing the primary nodeset, or empty if absent.
  ///
  /// Preserved verbatim as a raw `XmlElement`; not interpreted.
  ///
  /// @return The NodeSet-level `<Extensions>` block, or empty if absent.
  optional<XmlElement> extensions() const;

  /// The primary nodeset's `LastModified` timestamp.
  ///
  /// @return The timestamp, or a default-constructed (epoch) `DateTime` when the attribute is
  ///         absent.
  DateTime last_modified() const;

private:
  std::unique_ptr<NodeSetDocumentImpl> mImpl;

  // Grants the (private, same-TU) import engine adapter read access to the parse model. The read
  // model deliberately exposes no import method (D-G); import is a free function over the document.
  friend const NodeSetDocumentImpl& nodeset_document_impl(const NodeSetDocument&);
};

/// Parses a NodeSet stream into a shared, immutable inspection model.
///
/// The result is shared so it can be handed to an async import (which outlives the call) while the
/// caller keeps it for inspection or re-import. Parsing is synchronous; the stream is read in full
/// before returning.
///
/// @param nodeset The NodeSet stream to parse. Borrowed for the duration of the call only.
/// @param options Parse options, including dependency and structure resolution.
/// @return The parsed document on success, or an `ErrorDetail` on failure. Never throws.
Result<shared_ptr<const NodeSetDocument>> try_parse_nodeset_sync(
  const Stream& nodeset, NodeSetParseOptions options);

}  // namespace ua

#endif  // !UA_NODESET_DOCUMENT_H
