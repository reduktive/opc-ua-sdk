// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"
#include "ua_nodeset_export.h"

#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_memory_stream.h"
#include "ua_namespace_route.h"
#include "ua_nodeset_export_engine.h"
#include "ua_status.h"
#include "ua_stream.h"
#include "ua_to_result.h"

#include <future>
#include <utility>

namespace ua
{

namespace ns = ua::xml::nodeset;

namespace
{

// Adapts the public, view-based node filter to the engine's ExportedNode predicate. An empty public
// filter maps to an empty engine predicate ("include all"). The view carries the live node's
// identity + browse name, which is what an export node filter decides on.
ns::ExportEngine::ExportNodePredicate adapt_node_filter(std::function<bool(const ExportNodeView&)> filter)
{
  if (!filter)
  {
    return {};
  }
  return [filter = std::move(filter)](const ns::ExportedNode& node) -> bool
  {
    return filter(ExportNodeView{node.nodeId, node.nodeClass, node.browseName});
  };
}

// Adapts the public ReferenceView filter to the engine's ExportedReference predicate. The export
// reference carries an ExpandedNodeId target; a local target's inner NodeId is what a filter inspects.
ns::ExportEngine::ExportReferencePredicate adapt_reference_filter(
  std::function<bool(const ReferenceView&)> filter)
{
  if (!filter)
  {
    return {};
  }
  return [filter = std::move(filter)](const ns::ExportedReference& reference) -> bool
  {
    return filter(
      ReferenceView{reference.referenceTypeId, reference.targetId.node_id(), reference.isForward});
  };
}

std::vector<ns::NodeSetModel> convert_models(const std::vector<NodeSetExportModel>& models)
{
  std::vector<ns::NodeSetModel> converted;
  converted.reserve(models.size());
  for (const auto& model : models)
  {
    ns::NodeSetModel out;
    out.modelUri = model.uri;
    out.version = model.version;
    out.publicationDate = model.publicationDate;
    out.requiredModels.reserve(model.requiredModels.size());
    for (const auto& required : model.requiredModels)
    {
      out.requiredModels.push_back(
        ns::NodeSetRequiredModel{required.uri, required.version, required.publicationDate});
    }
    converted.push_back(std::move(out));
  }
  return converted;
}

ns::ExportEngine::ExportSettings make_settings(NodeSetExportOptions options)
{
  ns::ExportEngine::ExportSettings settings;
  settings.targetNamespaceIndices = std::move(options.namespaces);
  settings.models = convert_models(options.models);
  settings.lastModified = options.lastModified;
  settings.nodeFilter = adapt_node_filter(std::move(options.nodeFilter));
  settings.referenceFilter = adapt_reference_filter(std::move(options.referenceFilter));
  settings.scope = options.scope == NodeSetExportOptions::Scope::TypeDefinitionsOnly
                     ? ns::ExportEngine::ExportScope::TypeDefinitionsOnly
                     : ns::ExportEngine::ExportScope::Full;
  settings.emitAliases = options.emitAliases;
  settings.failOnUnencodableStructure =
    options.onUnencodableStructure == NodeSetExportOptions::OnUnencodableStructure::Fail;
  settings.structureResolver = std::move(options.structureResolver);
  return settings;
}

NodeSetExportSummary to_summary(ns::ExportEngine::ExportSummary& engineSummary)
{
  NodeSetExportSummary summary;
  summary.namespacesWritten = std::move(engineSummary.namespacesWritten);
  summary.nodesExported = engineSummary.nodesExported;
  summary.referencesExported = engineSummary.referencesExported;
  return summary;
}

}  // namespace

void export_nodeset_async(AddressSpace addressSpace, shared_ptr<Stream> out, NodeSetExportOptions options,
  std::function<void(Result<NodeSetExportSummary>)> completion)
{
  // Setup (config load + engine creation) can throw; deliver any failure through the completion so
  // this entry point genuinely never throws (per its contract).
  shared_ptr<ns::ExportEngine> engine;
  ns::ExportEngine::ExportSettings settings;
  try
  {
    const auto limits = make_encoding_limits(ApplicationConfig::load_default());
    engine = ns::ExportEngine::create(limits, std::move(addressSpace));
    settings = make_settings(std::move(options));
  }
  catch (...)
  {
    completion(Result<NodeSetExportSummary>{ua::exception_to_status_code(std::current_exception())});
    return;
  }

  // The engine serialises directly into `out` (co-owned for the op's lifetime); the completion
  // captures the engine so it outlives the async chain.
  engine->export_async(std::move(settings),
    std::move(out),
    [engine, completion = std::move(completion)](Result<ns::ExportEngine::ExportSummary> result) mutable
    {
      if (!result.has_value())
      {
        completion(Result<NodeSetExportSummary>{result.status_code()});
        return;
      }
      completion(Result<NodeSetExportSummary>{to_summary(result.value()), result.status_code()});
    });
}

void export_nodeset_async(AddressSpace addressSpace, NodeSetExportOptions options,
  std::function<void(Result<NodeSetExportResult>)> completion)
{
  // Buffer convenience: export into an internal MemoryStream (kept alive via the completion capture),
  // then materialise its bytes. Wraps the canonical Stream form.
  auto device = make_shared<memory_stream_device::Dynamic>();
  auto stream = make_shared<MemoryStream<memory_stream_device::Dynamic>>(*device);
  export_nodeset_async(std::move(addressSpace),
    stream,
    std::move(options),
    [device, stream, completion = std::move(completion)](Result<NodeSetExportSummary> result) mutable
    {
      if (!result.has_value())
      {
        completion(Result<NodeSetExportResult>{result.status_code()});
        return;
      }
      const auto data = device->get_data();
      std::vector<byte> bytes{data.begin(), data.end()};
      const StatusCode answered = result.status_code();
      completion(
        Result<NodeSetExportResult>{std::make_pair(std::move(bytes), std::move(result.value())), answered});
    });
}

Result<NodeSetExportSummary> try_export_nodeset_sync(
  AddressSpace addressSpace, Stream& out, NodeSetExportOptions options)
{
  // Sync wraps async. The call blocks until the export completes, so `out` outlives the operation -
  // hand the engine a NON-OWNING shared_ptr (aliasing ctor, no deleter) referencing it.
  try
  {
    shared_ptr<Stream> outHandle{shared_ptr<void>{}, &out};
    return ua::async::detail::blocking_call<Result<NodeSetExportSummary>>(addressSpace.executor(),
      [&](std::function<void(Result<NodeSetExportSummary>)> complete)
      {
        export_nodeset_async(
          std::move(addressSpace), std::move(outHandle), std::move(options), std::move(complete));
      });
  }
  catch (...)
  {
    return Result<NodeSetExportSummary>{ua::exception_to_status_code(std::current_exception())};
  }
}

Result<NodeSetExportResult> try_export_nodeset_sync(AddressSpace addressSpace, NodeSetExportOptions options)
{
  // Sync wraps the buffer-convenience async; block on the CALLER's thread (never the AS executor).
  try
  {
    return ua::async::detail::blocking_call<Result<NodeSetExportResult>>(addressSpace.executor(),
      [&](std::function<void(Result<NodeSetExportResult>)> complete)
      { export_nodeset_async(std::move(addressSpace), std::move(options), std::move(complete)); });
  }
  catch (...)
  {
    return Result<NodeSetExportResult>{ua::exception_to_status_code(std::current_exception())};
  }
}

NodeSetExportSummary export_nodeset_sync(AddressSpace addressSpace, Stream& out, NodeSetExportOptions options)
{
  return ua::detail::good_value(try_export_nodeset_sync(std::move(addressSpace), out, std::move(options)));
}

AddressSpaceFile::ExportNamespaceAsyncHandler make_export_namespace_handler(
  AddressSpace addressSpace, NodeSetExportOptions options, NodeSetStreamProvider openOutput)
{
  // Capture the address space WEAKLY. This handler is installed on the AddressSpaceFile's
  // ExportNamespace method node, which lives IN the address space - so a strong capture makes
  // AddressSpace -> method node -> handler -> AddressSpace a self-cycle that pins the entire node
  // graph for the server's lifetime (it never frees; LeakSanitizer reports the whole namespace
  // leaked). The method is only ever invoked while the server (hence the address space) is alive,
  // so lock() succeeds on every real call; a call racing teardown fails cleanly with BadShutdown.
  return
    [weakAddressSpace = addressSpace.weak(),
      options = std::move(options),
      openOutput = std::move(openOutput)](const MethodCall& call, MethodResultCallback<> complete) mutable
  {
    const auto& context = ::ua::detail::MethodCallAccess::shared_context(call);
    if (!openOutput)
    {
      complete(VoidResult{StatusCode{Status::BadInvalidArgument},
        make_error_detail("ExportNamespaceNoStreamProvider",
          "ExportNamespace handler was created without a stream provider",
          "NodeSetExport")});
      return;
    }

    // Ask for a fresh destination stream for this invocation; a bad Result (e.g. a file-open failure)
    // fails the call cleanly. The export writes into the stream, so an Uncertain answer, with or without
    // a stream, is refused.
    Result<shared_ptr<Stream>> streamResult = openOutput(context);
    if (!streamResult.is_good())
    {
      complete(VoidResult{
        ::ua::detail::answer_failure(streamResult.status_code(), "AnswerUncertain", "NodeSetExport")});
      return;
    }
    const shared_ptr<Stream> out = std::move(streamResult).value();
    if (!out)
    {
      complete(VoidResult{StatusCode{Status::BadInvalidArgument},
        make_error_detail("ExportNamespaceNullStream",
          "ExportNamespace stream provider returned a null stream",
          "NodeSetExport")});
      return;
    }

    auto lockedAddressSpace = weakAddressSpace.lock();
    if (!lockedAddressSpace)
    {
      complete(VoidResult{StatusCode{Status::BadShutdown},
        make_error_detail("ExportNamespaceAddressSpaceGone",
          "ExportNamespace was invoked after its address space was destroyed",
          "NodeSetExport")});
      return;
    }
    // `options` is passed by lvalue so the captured copy survives repeated calls; the locked address
    // space is held only for this call (export_nodeset_async re-weakens it internally, and the live
    // server keeps it alive across the async run). `out` is captured so it stays alive to be flushed.
    export_nodeset_async(*lockedAddressSpace,
      out,
      options,
      [out, complete = std::move(complete)](Result<NodeSetExportSummary> result) mutable
      {
        if (result.is_bad())
        {
          complete(VoidResult{result.status_code()});
          return;
        }
        // Flush so the document is durable before the method reports success (a client may Open/Read
        // it next). flush() can throw; contain it into the VoidResult.
        try
        {
          out->flush();
        }
        catch (...)
        {
          complete(VoidResult{ua::exception_to_status_code(std::current_exception())});
          return;
        }
        complete(VoidResult{});
      });
  };
}

}  // namespace ua
