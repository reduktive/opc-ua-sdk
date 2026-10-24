// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_nodeset_document.h"
#include "ua_callback_safety.h"
#include "ua_nodeset_import.h"

#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_namespace_array.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor.h"
#include "ua_objecttype_id.h"
#include "ua_weak_address_space.h"
#include "ua_referencetype_id.h"
#include "ua_server_array.h"
#include "ua_nodeset_import_engine.h"
#include "ua_stream.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include "ua_nodeset_parser.h"

#include <boost/asio/post.hpp>

#include <future>
#include <string>
#include <unordered_set>

namespace ua
{

namespace ns = ua::xml::nodeset;

// Owned, immutable parse result behind NodeSetDocument's PIMPL.
class NodeSetDocumentImpl
{
public:
  std::vector<shared_ptr<ns::NodeSet>> nodeSets;
  EncodingLimits limits;
  std::vector<NamespaceMapping> declaredNamespaces;
  std::vector<ModelRef> requiredModels;

  // Non-const span for the (non-mutating) ns::utilities helpers, which take a mutable span.
  ns::NodeSets node_sets() const
  {
    return ns::NodeSets{const_cast<shared_ptr<ns::NodeSet>*>(nodeSets.data()), nodeSets.size()};
  }
};

namespace
{

class NamespaceSubsetMarker final : public std::enable_shared_from_this<NamespaceSubsetMarker>
{
public:
  NamespaceSubsetMarker(
    WeakAddressSpace addressSpace, std::vector<NodeId> properties, std::function<void(VoidResult)> complete)
    : mAddressSpace(std::move(addressSpace)), mProperties(std::move(properties)),
      mComplete(std::move(complete))
  {}

  void start()
  {
    mark_next();
  }

private:
  void mark_next()
  {
    if (mIndex == mProperties.size())
    {
      auto complete = std::move(mComplete);
      complete(VoidResult{});
      return;
    }
    // Held weakly, and locked for each lookup only (CALLS-21 rule 1).
    auto owner = mAddressSpace.lock();
    if (!owner)
    {
      finish(VoidResult{::ua::detail::address_space_gone("NodeSetImport")});
      return;
    }
    const auto self = shared_from_this();
    owner->find_node_async(
      mProperties[mIndex], [self](NodeAccessorResult result) mutable { self->on_node(std::move(result)); });
  }

  void on_node(NodeAccessorResult result)
  {
    if (!result.is_good())
    {
      if (result.status_code().equivalent(StatusCode{Status::BadNodeIdUnknown}))
      {
        ++mIndex;
        mark_next();
        return;
      }
      finish(
        VoidResult{::ua::detail::lookup_failure(mProperties[mIndex], result.status_code(), "NodeSetImport")});
      return;
    }
    auto variable = result.value().as<VariableAccessor>();
    if (!variable)
    {
      finish(VoidResult{StatusCode{Status::BadTypeMismatch,
        ErrorDetail::build(
          "NamespaceSubsetPropertyWrongType", "IsNamespaceSubset is not a Variable", "NodeSetImport")
          .context(ContextKeys::nodeId, to_string(mProperties[mIndex]))}});
      return;
    }
    DataValue raised;
    raised.value() = Variant{true};
    variable->write_value_async(std::move(raised),
      [self = shared_from_this()](VoidResult written) mutable { self->on_written(std::move(written)); });
  }

  void on_written(VoidResult result)
  {
    if (result.is_bad())
    {
      finish(std::move(result));
      return;
    }
    ++mIndex;
    mark_next();
  }

  void finish(VoidResult result)
  {
    auto complete = std::move(mComplete);
    complete(std::move(result));
  }

  WeakAddressSpace mAddressSpace;
  std::vector<NodeId> mProperties;
  std::function<void(VoidResult)> mComplete;
  size_t mIndex{0};
};

void raise_namespace_subset_async(
  WeakAddressSpace addressSpace, std::vector<NodeId> properties, std::function<void(VoidResult)> complete)
{
  auto marker = std::make_shared<NamespaceSubsetMarker>(
    std::move(addressSpace), std::move(properties), std::move(complete));
  marker->start();
}

}  // namespace

// --- NodeView ---------------------------------------------------------------------------------

NodeId NodeView::node_id() const
{
  return mNode->node_id();
}

QualifiedName NodeView::browse_name() const
{
  return mNode->browse_name();
}

NodeClass NodeView::node_class() const
{
  return mNode->node_class();
}

optional<String> NodeView::category() const
{
  return mNode->category();
}

std::vector<ReferenceView> NodeView::references() const
{
  std::vector<ReferenceView> result;
  for (const auto& reference : mNode->references())
  {
    result.emplace_back(reference.typeId, reference.targetId, reference.isForward);
  }
  return result;
}

optional<NodeReleaseStatus> NodeView::release_status() const
{
  auto status = mNode->release_status();
  if (!status)
  {
    return {};
  }
  switch (*status)
  {
  case ns::Node::ReleaseStatus::Released:
    return NodeReleaseStatus::Released;
  case ns::Node::ReleaseStatus::Draft:
    return NodeReleaseStatus::Draft;
  case ns::Node::ReleaseStatus::Deprecated:
    return NodeReleaseStatus::Deprecated;
  }
  return {};
}

optional<XmlElement> NodeView::extensions() const
{
  return mNode->extensions_xml();
}

optional<DataTypeView> NodeView::as_data_type() const
{
  if (mDocument == nullptr || mNode->node_class() != NodeClass::DataType)
  {
    return {};
  }
  return DataTypeView{mNode, mDocument};
}

optional<VariableView> NodeView::as_variable() const
{
  if (mNode->node_class() != NodeClass::Variable)
  {
    return {};
  }
  return VariableView{mNode};
}

// --- DataTypeView -----------------------------------------------------------------------------

bool DataTypeView::is_abstract() const
{
  return dynamic_cast<const ns::DataType&>(*mNode).is_abstract();
}

bool DataTypeView::is_structure() const
{
  const auto& impl = *mDocument;
  return ns::utilities::is_a_structure(impl.limits, impl.node_sets(), *mNode);
}

bool DataTypeView::is_enumeration() const
{
  const auto& impl = *mDocument;
  return ns::utilities::is_an_enumeration(impl.limits, impl.node_sets(), *mNode);
}

std::vector<DataTypeFieldView> DataTypeView::fields() const
{
  const auto& impl = *mDocument;
  const auto& dataType = dynamic_cast<const ns::DataType&>(*mNode);

  std::vector<DataTypeFieldView> result;
  for (const auto& field : ns::utilities::aggregate_fields(impl.node_sets(), dataType))
  {
    result.push_back(
      DataTypeFieldView{field.name(), field.data_type(), field.value_rank(), field.is_optional()});
  }
  return result;
}

// --- VariableView -----------------------------------------------------------------------------

NodeId VariableView::data_type() const
{
  return dynamic_cast<const ns::Variable&>(*mNode).data_type();
}

int32_t VariableView::value_rank() const
{
  return dynamic_cast<const ns::Variable&>(*mNode).value_rank();
}

namespace
{

// Probes whether `uri` already maps to a (non-zero) server namespace index. Declared file URIs are
// never the UA namespace (index 0), so a 0 / not-found result means "not yet present".
optional<uint16_t> mapped_index(const NamespaceArray& namespaceArray, string_view uri)
{
  try
  {
    auto index = namespaceArray.get_namespace_index(uri);
    if (index != 0)
    {
      return index;
    }
  }
  catch (...)
  {
    // get_namespace_index may throw for an unknown URI - treat as not present.
    ua::detail::ignore_expected_exception();
  }
  return {};
}

// Adapts NodeSetImportOptions::resolve_required_model to the parser's GetDependentModelCallback.
ns::Parser::GetDependentModelCallback adapt_dependency_resolver(
  std::function<std::unique_ptr<Stream>(const ModelRef&)> resolveRequiredModel)
{
  if (!resolveRequiredModel)
  {
    return {};
  }
  return [resolveRequiredModel = std::move(resolveRequiredModel)](
           const ns::ModelTableEntry& model) -> unique_ptr<Stream>
  {
    const ModelRef ref{model.model_uri(), model.version()};
    return resolveRequiredModel(ref);
  };
}

// Adapt the public NodeView/ReferenceView filters to the engine's parse-tree predicates. An empty
// public filter => empty optional ("include all"). The filters are copied (owned) so they remain
// valid across the async chain. A bare NodeView (no document context) is sufficient for filtering -
// node_filter inspects node_id/browse_name/node_class/category only.
optional<ns::ImportEngine::ImportNodePredicate> adapt_node_filter(
  std::function<bool(const NodeView&)> filter, const shared_ptr<bool>& contentIsPartial)
{
  if (!filter)
  {
    return {};
  }
  return [filter = std::move(filter), contentIsPartial](const ns::Node& node) -> bool
  {
    const bool included = filter(NodeView{&node});
    if (!included)
    {
      *contentIsPartial = true;
    }
    return included;
  };
}

optional<ns::ImportEngine::ImportReferencePredicate> adapt_reference_filter(
  std::function<bool(const ReferenceView&)> filter, const shared_ptr<bool>& contentIsPartial)
{
  if (!filter)
  {
    return {};
  }
  return [filter = std::move(filter), contentIsPartial](
           const ns::Node&, const ns::Node::Reference& reference) -> bool
  {
    const bool included = filter(ReferenceView{reference.typeId, reference.targetId, reference.isForward});
    if (!included)
    {
      *contentIsPartial = true;
    }
    return included;
  };
}

// Common error funnel: convert any exception into a Result<T> error preserving ErrorDetail.
template<typename T, typename Fn>
Result<T> to_result(Fn&& fn)
{
  try
  {
    return std::forward<Fn>(fn)();
  }
  catch (const UaException& exception)
  {
    return Result<T>{exception.status_code()};
  }
  catch (const std::exception& exception)
  {
    return Result<T>{StatusCode{Status::BadInternalError},
      ErrorDetail::build("NodeSetImportFailed", "NodeSet import failed", "NodeSetImport")
        .context(ua::ContextKeys::errorMessage, exception.what())};
  }
}

}  // namespace

// --- NodeSetDocument --------------------------------------------------------------------------

NodeSetDocument::NodeSetDocument(std::unique_ptr<NodeSetDocumentImpl> impl) : mImpl(std::move(impl))
{}

NodeSetDocument::NodeSetDocument(NodeSetDocument&&) noexcept = default;
NodeSetDocument& NodeSetDocument::operator=(NodeSetDocument&&) noexcept = default;
NodeSetDocument::~NodeSetDocument() = default;

std::span<const NamespaceMapping> NodeSetDocument::declared_namespaces() const
{
  return mImpl->declaredNamespaces;
}

std::span<const ModelRef> NodeSetDocument::required_models() const
{
  return mImpl->requiredModels;
}

optional<XmlElement> NodeSetDocument::extensions() const
{
  // NodeSet-level `<Extensions>`, preserved verbatim on the primary nodeset (D-N). An absent element
  // is stored as an empty XmlElement by the parser, which we surface as "no extensions".
  if (mImpl->nodeSets.empty())
  {
    return {};
  }
  const auto& extensions = mImpl->nodeSets.front()->extensions();
  if (extensions.empty())
  {
    return {};
  }
  return extensions;
}

DateTime NodeSetDocument::last_modified() const
{
  if (mImpl->nodeSets.empty())
  {
    return DateTime{};
  }
  return mImpl->nodeSets.front()->last_modified();
}

std::vector<NodeView> NodeSetDocument::nodes() const
{
  std::vector<NodeView> result;
  for (const auto& nodeSet : mImpl->nodeSets)
  {
    for (const auto& [id, node] : nodeSet->nodes())
    {
      result.emplace_back(node.get(), mImpl.get());
    }
  }
  return result;
}

optional<NodeView> NodeSetDocument::find(const NodeId& nodeId) const
{
  if (const auto* node = ns::utilities::find_node(mImpl->node_sets(), nodeId))
  {
    return NodeView{node, mImpl.get()};
  }
  return {};
}

// Friend accessor: grants the (same-TU) import free functions read access to the parse model
// without exposing it on the public read-model surface (D-G).
const NodeSetDocumentImpl& nodeset_document_impl(const NodeSetDocument& document)
{
  return *document.mImpl;
}

// --- Free functions ---------------------------------------------------------------------------

Result<shared_ptr<const NodeSetDocument>> try_parse_nodeset_sync(
  const Stream& nodeset, NodeSetParseOptions options)
{
  return to_result<shared_ptr<const NodeSetDocument>>(
    [&]() -> shared_ptr<const NodeSetDocument>
    {
      // Trusted local input: a NodeSet document is an operator-supplied local file, not remote wire
      // input, so lift the size caps (the bounded-floor defaults guard hostile network input). The
      // limits are stored on the document and reused for the subsequent import (see limits).
      const auto limits = make_trusted_local_encoding_limits(ApplicationConfig::load_default());

      // The namespace/server arrays are not consumed by parsing (the importer performs namespace
      // resolution against its target AddressSpace), so standalone parse uses local instances.
      NamespaceArray namespaceArray;
      ServerArray serverArray;

      const ns::ParserOptions parserOptions{.decodeVariantValues = options.decodeValues};
      auto nodeSets = ns::Parser::parse(limits,
        nodeset,
        options.structureResolver,
        namespaceArray,
        serverArray,
        adapt_dependency_resolver(std::move(options.resolveRequiredModel)),
        parserOptions);

      auto impl = std::make_unique<NodeSetDocumentImpl>();
      impl->limits = limits;
      impl->nodeSets = std::move(nodeSets);

      // declared_namespaces / required_models are reported from the primary (first) NodeSet.
      if (!impl->nodeSets.empty())
      {
        const auto& primary = *impl->nodeSets.front();
        if (const auto& uriTable = primary.namespace_uris())
        {
          uint16_t fileLocalIndex = 1;  // index 0 is always the UA namespace
          for (auto& uri : uriTable->uris())
          {
            impl->declaredNamespaces.push_back(NamespaceMapping{uri, fileLocalIndex++});
          }
        }
        for (auto& model : impl->nodeSets.front()->models())
        {
          for (auto& dependency : model.required_models())
          {
            impl->requiredModels.push_back(ModelRef{dependency.model_uri(), dependency.version()});
          }
        }
      }

      return shared_ptr<const NodeSetDocument>{make_shared<NodeSetDocument>(std::move(impl))};
    });
}

void import_nodeset_async(AddressSpace addressSpace, shared_ptr<const NodeSetDocument> document,
  NodeSetImportOptions options, std::function<void(Result<NodeSetImportSummary>)> completion)
{
  if (!document)
  {
    completion(Result<NodeSetImportSummary>{StatusCode{Status::BadInvalidArgument},
      make_error_detail(
        "NodesetImportFailed", "import_nodeset_async called with a null document", "NodeSetImport")});
    return;
  }

  const auto& impl = nodeset_document_impl(*document);

  // Snapshot the declared URIs and which the server already knows BEFORE the import, so the summary
  // reports exactly the namespaces this import newly allocated.
  auto declaredUris = make_shared<std::vector<String>>();
  for (const auto& nodeSet : impl.nodeSets)
  {
    if (const auto& uriTable = nodeSet->namespace_uris())
    {
      for (auto& uri : uriTable->uris())
      {
        declaredUris->push_back(uri);
      }
    }
  }
  auto knownBeforeImport = make_shared<std::unordered_set<std::string>>();
  for (const auto& uri : *declaredUris)
  {
    if (mapped_index(addressSpace.namespace_array(), uri))
    {
      knownBeforeImport->insert(std::string{uri});
    }
  }

  // D-R: NamespaceFactory and the engine's NamespaceAllocator are now the same callable shape, so
  // the option is passed straight through (no abstract-class adapter).
  auto engine = ns::ImportEngine::create(impl.limits, addressSpace, impl.nodeSets, options.namespaceFactory);
  engine->set_fail_on_unknown_structure(
    options.onUnknownStructure == NodeSetImportOptions::OnUnknownStructure::Fail);
  // D-H 6: realize values into the target frame with the import's resolver. When supplied, this
  // overrides the document's parse-time resolver - so one parsed document resolves per-target, and a
  // resolver set here is honoured on the document overload (previously it was silently ignored).
  if (options.structureResolver)
  {
    engine->set_structure_resolver(options.structureResolver);
  }

  auto contentIsKnownPartial =
    std::make_shared<bool>(options.scope == NodeSetImportOptions::Scope::TypeDefinitionsOnly);
  auto nodePredicate = adapt_node_filter(std::move(options.nodeFilter), contentIsKnownPartial);
  auto refPredicate = adapt_reference_filter(std::move(options.referenceFilter), contentIsKnownPartial);

  // The completion captures the document (keeps the parse model alive), the engine (commit
  // counters) and the snapshots. The address space, needed to compute the namespace diff, is held
  // weakly (CALLS-21 rule 1): one gone by then answers AddressSpaceGone.
  auto finish = [weakAddressSpace = addressSpace.weak(),
                  document,
                  engine,
                  declaredUris,
                  knownBeforeImport,
                  contentIsKnownPartial,
                  completion = std::move(completion)](VoidResult result) mutable
  {
    if (result.is_bad())
    {
      completion(Result<NodeSetImportSummary>{result.status_code(), result.shared_detail()});
      return;
    }
    auto owner = weakAddressSpace.lock();
    if (!owner)
    {
      completion(Result<NodeSetImportSummary>{::ua::detail::address_space_gone("NodeSetImport")});
      return;
    }
    NodeSetImportSummary summary;
    summary.nodesImported = engine->nodes_imported();
    summary.referencesImported = engine->references_imported();
    for (const auto& uri : *declaredUris)
    {
      if (knownBeforeImport->count(std::string{uri}))
      {
        continue;
      }
      if (auto index = mapped_index(owner->namespace_array(), uri))
      {
        summary.namespacesAllocated.push_back(NamespaceMapping{uri, *index});
      }
    }
    if (!*contentIsKnownPartial)
    {
      completion(Result<NodeSetImportSummary>{std::move(summary)});
      return;
    }

    const auto documentNodes = document->nodes();
    std::unordered_set<NodeId> metadataObjects;
    for (const auto& node : documentNodes)
    {
      for (const auto& reference : node.references())
      {
        if (reference.is_forward() &&
            reference.reference_type_id() == NodeId{ReferenceTypeId::HasTypeDefinition} &&
            reference.target_id() == NodeId{ObjectTypeId::NamespaceMetadataType})
        {
          metadataObjects.insert(node.node_id());
          break;
        }
      }
    }

    std::vector<NodeId> subsetProperties;
    for (const auto& node : documentNodes)
    {
      if (static_cast<string_view>(node.browse_name().name()) != "IsNamespaceSubset")
      {
        continue;
      }
      bool belongsToMetadata = false;
      for (const auto& reference : node.references())
      {
        if (!reference.is_forward() &&
            reference.reference_type_id() == NodeId{ReferenceTypeId::HasProperty} &&
            metadataObjects.contains(reference.target_id()))
        {
          belongsToMetadata = true;
          break;
        }
      }
      if (!belongsToMetadata)
      {
        for (const auto& metadata : documentNodes)
        {
          if (!metadataObjects.contains(metadata.node_id()))
          {
            continue;
          }
          for (const auto& reference : metadata.references())
          {
            if (reference.is_forward() &&
                reference.reference_type_id() == NodeId{ReferenceTypeId::HasProperty} &&
                reference.target_id() == node.node_id())
            {
              belongsToMetadata = true;
              break;
            }
          }
          if (belongsToMetadata)
          {
            break;
          }
        }
      }
      if (belongsToMetadata)
      {
        auto translated = engine->translated_node_id(node.node_id());
        if (!translated.is_good())
        {
          completion(Result<NodeSetImportSummary>{translated.status_code(), translated.shared_detail()});
          return;
        }
        subsetProperties.push_back(std::move(translated).value());
      }
    }
    raise_namespace_subset_async(weakAddressSpace,
      std::move(subsetProperties),
      [summary = std::move(summary), completion = std::move(completion)](VoidResult raised) mutable
      {
        if (raised.is_bad())
        {
          completion(Result<NodeSetImportSummary>{raised.status_code(), raised.shared_detail()});
          return;
        }
        completion(Result<NodeSetImportSummary>{std::move(summary)});
      });
  };

  if (options.scope == NodeSetImportOptions::Scope::TypeDefinitionsOnly)
  {
    engine->import_type_definitions_only_async(
      "", std::move(nodePredicate), std::move(refPredicate), std::move(finish));
  }
  else
  {
    engine->import_all_async(std::move(nodePredicate), std::move(refPredicate), std::move(finish));
  }
}

Result<NodeSetImportSummary> try_import_nodeset_sync(
  AddressSpace addressSpace, shared_ptr<const NodeSetDocument> document, NodeSetImportOptions options)
{
  // External-convenience bridge: block on the CALLER's thread (never the AS executor). The promise
  // is a local; the documented sync-wrapper exception permits referencing it.
  try
  {
    return ua::async::detail::blocking_call<Result<NodeSetImportSummary>>(addressSpace.executor(),
      [&](std::function<void(Result<NodeSetImportSummary>)> complete)
      {
        import_nodeset_async(
          std::move(addressSpace), std::move(document), std::move(options), std::move(complete));
      });
  }
  catch (...)
  {
    return Result<NodeSetImportSummary>{ua::exception_to_status_code(std::current_exception())};
  }
}

Result<NodeSetImportSummary> try_import_nodeset_sync(
  AddressSpace addressSpace, const Stream& nodeset, NodeSetImportOptions options)
{
  // Stream convenience: parse inline (synchronous), then import the parsed document.
  NodeSetParseOptions parseOptions;
  parseOptions.resolveRequiredModel = options.resolveRequiredModel;
  parseOptions.structureResolver = options.structureResolver;

  auto document = try_parse_nodeset_sync(nodeset, std::move(parseOptions));
  if (!document.is_good())
  {
    return Result<NodeSetImportSummary>{document.status_code()};
  }
  return try_import_nodeset_sync(std::move(addressSpace), document.value(), std::move(options));
}

NodeSetImportSummary import_nodeset_sync(
  AddressSpace addressSpace, shared_ptr<const NodeSetDocument> document, NodeSetImportOptions options)
{
  return ua::detail::good_value(
    try_import_nodeset_sync(std::move(addressSpace), std::move(document), std::move(options)));
}

NodeSetImportSummary import_nodeset_sync(
  AddressSpace addressSpace, const Stream& nodeset, NodeSetImportOptions options)
{
  return ua::detail::good_value(
    try_import_nodeset_sync(std::move(addressSpace), nodeset, std::move(options)));
}

}  // namespace ua
