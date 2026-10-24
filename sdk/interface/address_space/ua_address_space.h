// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Root container of the server's node/reference graph and entry point for node access.
/// @ingroup address_space

#ifndef UA_ADDRESS_SPACE_H
#define UA_ADDRESS_SPACE_H

#include "ua_codec_namespace_context.h"
#include "ua_error_detail.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_logger.h"
#include "ua_namespace_array.h"
#include "ua_namespace_metadata_options.h"
#include "ua_reference_halves.h"
#include "ua_result.h"
#include "ua_server_array.h"
#include "ua_execution_limits.h"
#include "ua_service_operation_limits.h"
#include "ua_weak_address_space.h"
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace ua
{

class AddressSpaceImpl;
class WeakAddressSpace;

namespace test_helpers
{
class NamespaceRegistrationCoordinatorTestAccess;
}

namespace detail
{
class AddressSpaceSessionEvents;
class AddressSpaceFileHandles;
class AddressSpaceNamespaceLifecycle;
class NamespaceRegistrationCoordinator;
struct NamespaceRegistrationRoute;
class AddressSpaceChangeEvents;
}  // namespace detail

/// The server's node/reference graph and the entry point for node access.
///
/// An AddressSpace owns a set of @ref Namespace instances (indexed by the
/// @ref NamespaceArray) and routes node operations to the namespace that owns
/// the target @ref NodeId. It is a cheap-to-copy value handle (Pimpl) over a
/// shared implementation: copies share the same underlying graph, and the graph
/// stays alive while any copy (or a locked @ref WeakAddressSpace) exists.
///
/// Each namespace serializes its own mutable state on a private strand; the
/// `*_async` methods post work there and complete on an unspecified worker
/// thread, while the `*_sync` / `try_*_sync` variants block the calling thread
/// until that work completes.
/// @ingroup address_space
class AddressSpace
{
public:
  /// Creates an AddressSpace with namespace 0 (and the application namespace) initialised.
  ///
  /// The returned handle owns a fresh node graph bound to @p executor; all async
  /// node work and namespace strands run on that executor.
  ///
  /// @param applicationUri Application URI seeded into namespace 1 and the @ref ServerArray.
  /// @param executor       Executor on which namespace strands and async completions run.
  /// @return A handle to the newly created address space.
  static AddressSpace create(String applicationUri, boost::asio::any_io_executor executor);

  /// Returns the per-operation execution budgets applied while a single operation runs.
  ///
  /// These bound encode/decode work and nesting, instantiation descent, and loop iterations; a
  /// breach fails the operation with @ref Status::BadEncodingLimitsExceeded. They are **not** the
  /// per-service node counts a client sees: the maximum nodes per Read, Browse, Write, Call and the
  /// rest live in `ServerConfig::ServerCapabilities::operationLimits`.
  ///
  /// @return The current execution budgets.
  /// @see set_limits, ExecutionLimits
  const ExecutionLimits& limits() const;

  /// Sets the per-operation execution budgets applied while a single operation runs.
  ///
  /// @param limits New budgets to apply to subsequent operations. Every field must be greater than
  ///        zero. See @ref limits for what these do and do not bound.
  /// @see limits
  void set_limits(ExecutionLimits limits);

  /// Sets the per-service operation limits that bound each call this address space makes to a namespace.
  ///
  /// A namespace's part of a batch is sent as consecutive calls of at most the matching limit, each started
  /// when the previous one has completed, while different namespaces still work concurrently: a lookup of
  /// Nodes is bounded by `maxNodesPerRead`. A limit left `nullopt` sends a namespace's part as one call, and
  /// so does an address space whose limits were never set. The server passes its configured
  /// `ServerConfig::ServerCapabilities::operationLimits`.
  ///
  /// Called by the owner before the address space serves requests, so no synchronisation is needed. Mirrors
  /// @ref set_limits.
  ///
  /// @param limits The limits to apply to later calls. A limit that is set must be greater than zero (OPC
  /// 10000-5
  ///        6.3.11).
  /// @throws UaException `Bad_InvalidArgument` (ErrorDetail `OperationLimitZero`, naming the field) when a
  /// limit is 0;
  ///         the limits in force are then unchanged.
  /// @see ServiceOperationLimits
  void set_operation_limits(ServiceOperationLimits limits);

  /// Returns the executor on which this address space's async work runs.
  ///
  /// @return The bound I/O executor.
  boost::asio::any_io_executor executor() const;

  /// Returns the logger for async work done on this address space's behalf.
  ///
  /// Components that drive multi-step async work over this address space (the instantiation flows,
  /// the read/browse adapters, the nodeset engines) read this alongside @ref executor() to hand the
  /// post helpers a strand/executor + a logger. A @ref ua::Logger is a value handle that survives
  /// teardown; a default-constructed one is a silent no-op (the address space is usable without a
  /// logger having been seeded).
  ///
  /// @return The bound logger, or a no-op logger if none was seeded.
  /// @see set_logger
  ua::Logger logger() const;

  /// Returns the monotonic generation of the address space's model: its Nodes, their References, and their
  /// BrowseNames and DataTypes.
  ///
  /// Caches derived from the AddressSpace may reuse entries only while this value is unchanged.
  /// It advances when a create, a delete, a Reference add or remove, or a BrowseName or DataType write
  /// completes through the address space with a change, in any namespace, and when a namespace reports a
  /// change it made to its own Nodes or References (`NamespaceContext::model_changed`). Writes of other
  /// Attributes leave it unchanged.
  /// The read is lock-free and does not retain any graph object.
  ///
  /// @return The model changes counted so far. The value never decreases, and it SATURATES at
  ///         `UINT64_MAX` rather than wrapping - so a cache comparing a stored generation against this
  ///         one can never be fooled into reusing a stale entry by wrap-around, at the cost of ceasing
  ///         to invalidate once saturated.
  uint64_t model_generation() const noexcept;

  /// Checks that the event-source graph of every namespace is loop-free and legal.
  ///
  /// OPC 10000-3 7.17 is a `shall`: following `HasEventSource` references or their subtypes from a Node,
  /// it must never be possible to return to it. Meeting it is the **server implementer's** obligation -
  /// conformance is a property of the product, not of a library, and only the implementer knows when a
  /// build is finished. This is how to discharge it: import your NodeSets, add your nodes, then call this
  /// once. The SDK does not call it.
  ///
  /// The check reads every namespace through its batched members, so a namespace of any kind is checked:
  /// each namespace's Nodes from @ref Namespace::enumerate_nodes_async; their References with
  /// `HasEventSource` and `HasNotifier` as the hint; the supertypes of an application ReferenceType, to
  /// know whether it is one of theirs; and the NodeClass and EventNotifier of the References' ends. A
  /// namespace that declines to enumerate is read by following event-family References into it from the
  /// Server Object and every Node listed. Cost per call: one enumeration per namespace, one lookup and one
  /// References read per `maxNodesPerBrowse` Nodes, and a lookup of the ends not already read. It belongs
  /// at the end of a build, not on any common path.
  ///
  /// It is deliberately NOT called on every reference mutation. It was, and it cost a snapshot of every
  /// node plus a walk of every reference on every `HasSubtype` change: 721 of them during one NS0 load at
  /// about 2.6 ms each, and 12 ms per deleted node, in a debug build.
  ///
  /// What the SDK guarantees whether or not you call this is that a cycle cannot be catastrophic: the
  /// event bus's notifier climb keeps a visited set, so a cycle can neither loop it nor deliver one event
  /// twice, and a traversal budget bounds how much of the address space a single event may walk. A cyclic
  /// graph makes a server non-conformant; it does not make it hang.
  ///
  /// @param complete Called once, on a thread of this address space's executor, with: Good; or the first
  ///                 violation found, `Bad_ReferenceNotAllowed` with the ErrorDetail that names it -
  ///                 `EventReferenceCycle` for a loop, `EventReferenceEndpointUnavailable`,
  ///                 `EventReferenceSourceUnavailable` or `EventReferenceTargetUnavailable` for an end that
  ///                 does not resolve, or `EventReferenceSourceNotSubscribable` or
  ///                 `EventReferenceTargetNotSubscribable` for an illegal source or target; or, when no
  ///                 violation was found but part of the graph could not be read,
  ///                 `Uncertain_NotAllNodesAvailable` with the ErrorDetail `EventGraphNotFullyChecked`,
  ///                 naming the namespaces that declined to enumerate and caused by the first lookup,
  ///                 References read or ReferenceType walk that failed; or `Bad_Shutdown`
  ///                 (`AddressSpaceGone`) when this address space goes during the check.
  void validate_event_graph_async(std::function<void(VoidResult)> complete) const noexcept;

  /// @ref validate_event_graph_async, waiting for its answer.
  ///
  /// @return The answer of @ref validate_event_graph_async; or `Bad_WouldBlock` on a thread of this
  ///         address space's executor, where the check is not started because its answer may need that
  ///         thread. Never throws.
  [[nodiscard]] VoidResult try_validate_event_graph_sync() const noexcept;

  /// @ref try_validate_event_graph_sync, throwing for any answer other than Good.
  ///
  /// @throws UaException carrying the answer and its ErrorDetail: a violation, `Bad_WouldBlock` on a thread
  ///         of this address space's executor, and `Uncertain_NotAllNodesAvailable` too, since a graph only
  ///         partly read has not been shown to conform.
  void validate_event_graph_sync() const;

  /// Seeds the logger returned by @ref logger().
  ///
  /// Called once by the owner (the server) immediately after construction, before any async work
  /// runs, so no synchronisation is needed. Mirrors @ref set_limits.
  ///
  /// @param logger The logger to bind (a value handle; copied).
  /// @see logger
  void set_logger(ua::Logger logger);

  /// Creates a new in-memory namespace with declarative access-control defaults.
  ///
  /// This is the public configuration path for the standard Role model. It avoids exposing or
  /// downcasting to the SDK's concrete in-memory Namespace solely to configure its defaults. A node
  /// without its own `RolePermissions` inherits @p rolePermissions; a node-level array replaces the
  /// complete default rather than merging with it.
  ///
  /// @param uri                Namespace URI.
  /// @param rolePermissions    Engaged Role-model default. An empty vector grants nothing.
  /// @param accessRestrictions Optional channel restriction inherited by undecorated nodes.
  /// @return Shared ownership of the configured namespace; never null.
  /// @note Register the returned namespace through @ref add_namespace_async or an external sync wrapper.
  shared_ptr<Namespace> create_namespace(string_view uri, std::vector<RolePermissionType> rolePermissions,
    std::optional<AccessRestrictionType> accessRestrictions = std::nullopt);

  /// Completion of @ref find_node_async "find_node_async": an accessor for the Node, or why there is none.
  using FindNodeCompleteCallback = std::function<void(NodeAccessorResult)>;

  /// Completion of @ref find_nodes_async "find_nodes_async": one accessor result per NodeId, in request
  /// order.
  using FindNodesCompleteCallback = std::function<void(BatchResult<NodeAccessorResult>)>;

  /// Completion of @ref enumerate_nodes_async "enumerate_nodes_async": the namespace's NodeIds, or why it
  /// cannot list them.
  using EnumerateNodesCallback = std::function<void(Result<std::vector<NodeId>>)>;

  /// Completion of @ref create_node_async "create_node_async": an accessor for the created Node, or why it
  /// was not created.
  using CreateNodeCompleteCallback = std::function<void(NodeAccessorResult)>;

  /// Callback receiving the permanent index assigned by asynchronous namespace registration.
  using AddNamespaceCallback = std::function<void(Result<uint16_t>)>;

  /// Registers @p namespaceToAdd through the address-space lifecycle coordinator.
  ///
  /// This is the canonical mutation path for host code and internal SDK flows. It serializes fallible
  /// lifecycle preparation before one permanent append and may be called before or after server
  /// startup, including while Sessions are connected. The candidate is absent from @ref
  /// namespace_array until the callback succeeds. The callback runs on the address-space executor and
  /// is invoked exactly once; this method never blocks and never throws.
  ///
  /// @param namespaceToAdd Candidate namespace. Must be non-null, have a non-empty unique URI and fit
  ///                       in the remaining UInt16 namespace-index space.
  /// @param callback       Receives the permanent dense index, or a rich validation, preparation or
  ///                       shutdown failure.
  /// @see try_add_namespace_sync, add_namespace_sync
  void add_namespace_async(shared_ptr<Namespace> namespaceToAdd, AddNamespaceCallback callback) noexcept;

  /// Registers @p namespaceToAdd, stating what metadata is to be published for it.
  ///
  /// Identical to the two-argument overload except that @p metadata replaces the default publication
  /// intent. A namespace declaring the standard Role model may not suppress publication, and one
  /// asked to publish must be able to supply or accept a metadata Object; either inconsistency is
  /// refused through @p callback with a cause naming the namespace and its remedies.
  ///
  /// @param namespaceToAdd Candidate namespace, as above.
  /// @param metadata       Publication intent and the descriptive facts to publish.
  /// @param callback       Receives the permanent dense index, or a rich failure.
  void add_namespace_async(shared_ptr<Namespace> namespaceToAdd, NamespaceMetadataOptions metadata,
    AddNamespaceCallback callback) noexcept;

  /// Registers a namespace and blocks the external caller until the canonical async flow completes.
  ///
  /// Refuses with `BadWouldBlock` before launching work when called from the address-space executor.
  /// Internal SDK code shall use @ref add_namespace_async instead.
  ///
  /// @param namespaceToAdd The namespace to register.
  /// @param metadata Publication intent and descriptive facts; defaults to ordinary publication.
  /// @return The permanent index, or the async operation's exact StatusCode and ErrorDetail.
  ///         Never throws.
  /// @see add_namespace_async, add_namespace_sync
  Result<uint16_t> try_add_namespace_sync(
    shared_ptr<Namespace> namespaceToAdd, NamespaceMetadataOptions metadata = {}) noexcept;

  /// Registers a namespace and blocks the external caller until the canonical async flow completes.
  ///
  /// A Good subcode on the answer is not returned; try_add_namespace_sync() returns it.
  ///
  /// @param namespaceToAdd The namespace to register.
  /// @param metadata Publication intent and descriptive facts; defaults to ordinary publication.
  /// @return The permanent dense index.
  /// @throws UaException carrying the exact registration failure, including `BadWouldBlock` on an
  ///         address-space executor thread; also for an answer that is not Good.
  /// @see add_namespace_async, try_add_namespace_sync
  uint16_t add_namespace_sync(shared_ptr<Namespace> namespaceToAdd, NamespaceMetadataOptions metadata = {});

  /// Looks up the node identified by @p nodeId, completing asynchronously.
  ///
  /// Routes to the namespace that owns @p nodeId and posts the lookup to that
  /// namespace's strand; @p callback runs on an unspecified worker thread once
  /// the lookup completes - do not block it.
  ///
  /// On success the owning namespace makes the node's full static attribute set
  /// resident (the @ref Namespace::find_node caching contract, invariant I2), so
  /// every subsequent synchronous getter on the returned @ref NodeAccessor is a
  /// guaranteed local hit; a Variable's live value stays on the asynchronous
  /// read-value path.
  ///
  /// The namespace's code reaches @p callback: a Good subcode with the accessor, and an Uncertain code with
  /// the accessor when the namespace answered one with its Node. The SDK's own callers do not act on an
  /// Uncertain lookup; an application that does tests `has_value()` rather than `is_good()`.
  ///
  /// @param nodeId   Node to look up.
  /// @param callback Receives the outcome: a @ref NodeAccessor for the node with the namespace's code; on
  ///                 failure it carries an @ref ErrorDetail (e.g. `BadNodeIdUnknown` when the
  ///                 namespace index is unknown). This overload never throws.
  /// @see find_node_sync, try_find_node_sync, find_async
  void find_node_async(const NodeId& nodeId, FindNodeCompleteCallback callback) noexcept;

  /// Resolves a batch of nodes, grouping by owning namespace, completing asynchronously.
  ///
  /// Groups @p nodeIds by their namespace index and issues one @ref Namespace::find_nodes_async call per
  /// owning namespace, so a remote/caching namespace collapses its cold-cache N round-trips into one;
  /// the per-item caching contract (invariant I2) applies to every node resolved. Results are
  /// reassembled in request order. @p callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param nodeIds  Nodes to resolve, viewed but not owned by the callee. The span need only stay
  ///                 valid for the synchronous portion of the call.
  /// @param callback Receives a @ref BatchResult with one @ref NodeAccessorResult per input id, in
  ///                 request order (an accessor with the namespace's code, as @ref find_node_async gives
  ///                 it, or a status carrying any @ref ErrorDetail - e.g. `BadNodeIdUnknown` for an
  ///                 unknown namespace index). The batch status is good whenever per-item results were
  ///                 produced. Never throws.
  /// @see find_node_async
  void find_nodes_async(std::span<const NodeId> nodeIds, FindNodesCompleteCallback callback) noexcept;

  /// Enumerates the NodeIds of every node owned by the namespace at @p namespaceIndex.
  ///
  /// Routes to the owning namespace and delegates to @ref Namespace::enumerate_nodes_async - an optional
  /// capability used by tooling (e.g. NodeSet export) that needs the full node set; NOT on any hot
  /// path. @p callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param namespaceIndex Index of the namespace whose nodes are enumerated.
  /// @param callback       Receives a @ref Result holding the owned NodeIds on success, or a bad
  ///                       @ref StatusCode carrying any @ref ErrorDetail (`BadNodeIdUnknown` for an
  ///                       unknown index; `BadNotSupported` if the namespace cannot enumerate). This
  ///                       overload never throws.
  void enumerate_nodes_async(uint16_t namespaceIndex, EnumerateNodesCallback callback) noexcept;

  /// Looks up the node identified by @p nodeId, blocking until complete.
  ///
  /// @param nodeId Node to look up.
  /// @return A @ref NodeAccessor with the namespace's code, as @ref find_node_async gives it, or an
  ///         @ref ErrorDetail on failure. Never throws.
  ///         Bad_WouldBlock when called on a thread of this address space's executor, which may be
  ///         the thread that would run the answer: use the *_async overload there.
  /// @see find_node_async, find_node_sync
  NodeAccessorResult try_find_node_sync(const NodeId& nodeId) noexcept;

  /// Looks up the node identified by @p nodeId, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; try_find_node_sync() returns it.
  ///
  /// @param nodeId Node to look up.
  /// @return A @ref NodeAccessor for the node.
  /// @throws UaException unless the lookup is answered Good, an Uncertain answer included.
  /// @see find_node_async, try_find_node_sync
  NodeAccessor find_node_sync(const NodeId& nodeId);

  /// Looks up @p nodeId and downcasts the accessor to @p T, blocking until complete.
  ///
  /// @tparam T Concrete @ref NodeAccessor subtype expected for the node.
  /// @param nodeId Node to look up.
  /// @return The node accessor as @p T with the lookup's code (a Good subcode, or an Uncertain code with
  ///         the accessor), an `ErrorDetail` with `BadNodeClassInvalid` if the node is not a @p T, or the
  ///         lookup's own failure detail. Never throws.
  /// @see find_sync, find_async
  template<typename T>
  Result<T> try_find_sync(const NodeId& nodeId) noexcept
  {
    return try_find_node_sync(nodeId).and_then(
      [](NodeAccessor accessor) -> Result<T>
      {
        if (auto typed = accessor.template as<T>())
          return std::move(*typed);
        return StatusCode{Status::BadNodeClassInvalid};
      });
  }

  /// Looks up @p nodeId and downcasts the accessor to @p T, blocking until complete.
  ///
  /// @tparam T Concrete @ref NodeAccessor subtype expected for the node.
  /// A Good subcode on the answer is not returned; try_find_sync() returns it.
  ///
  /// @param nodeId Node to look up.
  /// @return The node accessor as @p T.
  /// @throws UaException if the node cannot be found or is not a @p T, or the lookup is not answered Good.
  /// @see try_find_sync, find_async
  template<typename T>
  T find_sync(const NodeId& nodeId)
  {
    return ua::detail::good_value(try_find_sync<T>(nodeId));
  }

  /// Looks up @p nodeId and downcasts the accessor to @p T, completing asynchronously.
  ///
  /// Posts the lookup to the owning namespace's strand; @p callback runs on an
  /// unspecified worker thread - do not block it.
  ///
  /// @tparam T Concrete @ref NodeAccessor subtype expected for the node.
  /// @param nodeId   Node to look up.
  /// @param callback Receives the outcome: the accessor as @p T with the lookup's code (a Good subcode, or
  ///                 an Uncertain code with the accessor), an `ErrorDetail` with `BadNodeClassInvalid` if
  ///                 the node is not a @p T, or the lookup's own failure detail. This overload never
  ///                 throws.
  /// @see try_find_sync, find_sync
  template<typename T>
  void find_async(const NodeId& nodeId, std::function<void(Result<T>)> callback) noexcept
  {
    find_node_async(nodeId,

      [callback](NodeAccessorResult result)
      {
        if (result.has_value())
        {
          if (auto typed = result.value().template as<T>())
            callback(Result<T>{std::move(*typed), result.status_code()});
          else
            callback(StatusCode{Status::BadNodeClassInvalid});
        }
        else
        {
          callback(Result<T>{result.status_code(), result.shared_detail()});
        }
      });
  }

  /// Creates a node of @p nodeClass at @p nodeId, completing asynchronously.
  ///
  /// Sends the node as one item of the `Namespace::create_nodes_async` of the namespace that owns
  /// @p nodeId; @p callback runs on an unspecified worker thread - do not block it.
  ///
  /// @param nodeId            Identifier for the new node; its namespace index selects the owner.
  /// @param nodeClass         Node class to create (Object, Variable, Method, ...).
  /// @param initialAttributes Standard attributes to apply atomically at creation (interface refactor
  ///                          5.2); may be empty for a bare node.
  /// @param callback          Receives the outcome: a @ref NodeAccessor for the new node with the
  ///                          namespace's code (a Good subcode, or an Uncertain code with the
  ///                          accessor, is kept); on failure an @ref ErrorDetail (e.g.
  ///                          `BadNodeIdUnknown` for an unknown namespace). This
  ///                          overload never throws.
  /// @see create_node_sync, try_create_node_sync, create_async
  void create_node_async(const NodeId& nodeId, NodeClass nodeClass, InitialAttributes initialAttributes,
    CreateNodeCompleteCallback callback) noexcept;

  /// Creates a bare node of @p nodeClass at @p nodeId, completing asynchronously.
  ///
  /// Convenience overload of @ref create_node_async with no initial attributes - equivalent to
  /// passing an empty attribute set. Attributes are then set one write at a time, through the
  /// accessor's attribute writes; bulk construction should prefer the initial-attribute overload
  /// (interface refactor 5.2).
  ///
  /// @param nodeId     Identifier for the new node; its namespace index selects the owner.
  /// @param nodeClass  Node class to create (Object, Variable, Method, ...).
  /// @param callback   Receives the outcome, exactly as the initial-attribute overload. Never throws.
  /// @see create_node_sync, try_create_node_sync, create_async
  void create_node_async(
    const NodeId& nodeId, NodeClass nodeClass, CreateNodeCompleteCallback callback) noexcept;

  /// Creates a node of @p nodeClass at @p nodeId, blocking until complete.
  ///
  /// @param nodeId            Identifier for the new node.
  /// @param nodeClass         Node class to create.
  /// @param initialAttributes Standard attributes to apply atomically at creation; may be empty.
  /// @return A @ref NodeAccessor for the new node with the namespace's code, as @ref create_node_async
  ///         gives it, or an @ref ErrorDetail on failure. Never throws.
  ///         Bad_WouldBlock when called on a thread of this address space's executor, which may be
  ///         the thread that would run the answer: use the *_async overload there.
  /// @see create_node_async, create_node_sync
  NodeAccessorResult try_create_node_sync(
    const NodeId& nodeId, NodeClass nodeClass, InitialAttributes initialAttributes = {}) noexcept;

  /// Creates a node of @p nodeClass at @p nodeId, blocking until complete.
  ///
  /// @param nodeId            Identifier for the new node.
  /// @param nodeClass         Node class to create.
  /// @param initialAttributes Standard attributes to apply atomically at creation; defaults to none.
  ///
  /// A Good subcode on the answer is not returned; try_create_node_sync() returns it.
  /// @return A @ref NodeAccessor for the new node.
  /// @throws UaException if creation fails or is not answered Good, an Uncertain answer included.
  /// @see create_node_async, try_create_node_sync
  NodeAccessor create_node_sync(
    const NodeId& nodeId, NodeClass nodeClass, InitialAttributes initialAttributes = {});

  /// Creates a node and downcasts the accessor to @p T, blocking until complete.
  ///
  /// @tparam T Concrete @ref NodeAccessor subtype expected for @p nodeClass.
  /// @param nodeId            Identifier for the new node.
  /// @param nodeClass         Node class to create.
  /// @param initialAttributes Standard attributes to apply atomically at creation; defaults to none.
  /// @return The new node's accessor as @p T with the creation's code (a Good subcode, or an Uncertain
  ///         code with the accessor), an `ErrorDetail` with `BadNodeClassInvalid` if it is not a @p T, or
  ///         the creation's own failure detail. Never throws.
  /// @see create_sync, create_async
  template<typename T>
  Result<T> try_create_sync(
    const NodeId& nodeId, NodeClass nodeClass, InitialAttributes initialAttributes = {}) noexcept
  {
    return try_create_node_sync(nodeId, nodeClass, std::move(initialAttributes))
      .and_then(
        [](NodeAccessor accessor) -> Result<T>
        {
          if (auto typed = accessor.template as<T>())
            return std::move(*typed);
          return StatusCode{Status::BadNodeClassInvalid};
        });
  }

  /// Creates a node and downcasts the accessor to @p T, blocking until complete.
  ///
  /// @tparam T Concrete @ref NodeAccessor subtype expected for @p nodeClass.
  /// @param nodeId            Identifier for the new node.
  /// @param nodeClass         Node class to create.
  /// @param initialAttributes Standard attributes to apply atomically at creation; defaults to none.
  ///
  /// A Good subcode on the answer is not returned; try_create_sync() returns it.
  /// @return The new node's accessor as @p T.
  /// @throws UaException if creation fails, is not answered Good, or the node is not a @p T.
  /// @see try_create_sync, create_async
  template<typename T>
  T create_sync(const NodeId& nodeId, NodeClass nodeClass, InitialAttributes initialAttributes = {})
  {
    return ua::detail::good_value(try_create_sync<T>(nodeId, nodeClass, std::move(initialAttributes)));
  }

  /// Creates a node and downcasts the accessor to @p T, completing asynchronously.
  ///
  /// Posts the creation to the owning namespace's strand; @p callback runs on an
  /// unspecified worker thread - do not block it.
  ///
  /// @tparam T Concrete @ref NodeAccessor subtype expected for @p nodeClass.
  /// @param nodeId            Identifier for the new node.
  /// @param nodeClass         Node class to create.
  /// @param initialAttributes Standard attributes to apply atomically at creation; may be empty.
  /// @param callback          Receives the outcome: the new node's accessor as @p T with the
  ///                          creation's code (a Good subcode, or an Uncertain code with the
  ///                          accessor), an `ErrorDetail` with `BadNodeClassInvalid` if it
  ///                          is not a @p T, or the creation's own failure detail. This
  ///                          overload never throws.
  /// @see try_create_sync, create_sync
  template<typename T>
  void create_async(const NodeId& nodeId, NodeClass nodeClass, InitialAttributes initialAttributes,
    std::function<void(Result<T>)> callback) noexcept
  {
    create_node_async(nodeId,
      nodeClass,
      std::move(initialAttributes),

      [callback](NodeAccessorResult result)
      {
        if (result.has_value())
        {
          if (auto typed = result.value().template as<T>())
            callback(Result<T>{std::move(*typed), result.status_code()});
          else
            callback(StatusCode{Status::BadNodeClassInvalid});
        }
        else
        {
          callback(Result<T>{result.status_code(), result.shared_detail()});
        }
      });
  }

  /// Creates a bare node and downcasts the accessor to @p T, completing asynchronously.
  ///
  /// Convenience overload of @ref create_async with no initial attributes - equivalent to passing
  /// an empty attribute set.
  ///
  /// @tparam T Concrete @ref NodeAccessor subtype expected for @p nodeClass.
  /// @param nodeId     Identifier for the new node.
  /// @param nodeClass  Node class to create.
  /// @param callback   Receives the outcome, exactly as the initial-attribute overload. Never throws.
  /// @see try_create_sync, create_sync
  template<typename T>
  void create_async(
    const NodeId& nodeId, NodeClass nodeClass, std::function<void(Result<T>)> callback) noexcept
  {
    create_async<T>(nodeId, nodeClass, {}, std::move(callback));
  }

  /// Callback receiving the outcome of an asynchronous node deletion.
  using DeleteNodeCompleteCallback = std::function<void(VoidResult)>;

  /// Deletes the node identified by @p nodeId, completing asynchronously.
  ///
  /// Deletes through `Namespace::delete_nodes_async`, one call per owning namespace (for a subtree, per
  /// level, the deepest level first), passing @p halves on. With `ReferenceHalves::Both` it then removes
  /// the halves that other namespaces hold of the deleted nodes' References with one
  /// `Namespace::remove_references_async` per namespace. @p callback runs on an unspecified worker
  /// thread - do not block it. An address space released while the delete runs ends it with
  /// `Bad_Shutdown`.
  ///
  /// @param nodeId                                  Node to delete.
  /// @param deleteForwardHierarchicallyReferencedNodes If true, recursively delete
  ///                                      the whole subtree: @p nodeId and every node
  ///                                      reachable from it via forward hierarchical
  ///                                      references (any subtype of
  ///                                      `HierarchicalReferences`, in any namespace).
  ///                                      Descendants are deleted before their parents;
  ///                                      cycles and shared nodes are deleted once. If
  ///                                      false, only @p nodeId is deleted (the
  ///                                      spec-aligned single-node DeleteNodes).
  /// @param halves                       Which halves of the deleted nodes' References
  ///                                     go. `Both` (DeleteNodes' `deleteTargetReferences`
  ///                                     TRUE): the deleted nodes, the halves they hold,
  ///                                     and the halves every other node of this address
  ///                                     space holds of a Reference to a deleted node.
  ///                                     `ThisHalfOnly` (`deleteTargetReferences` FALSE,
  ///                                     OPC 10000-4 5.7.4.2): the deleted nodes and the
  ///                                     halves they hold; every other node keeps its half
  ///                                     of a Reference to a deleted node, which is left
  ///                                     unresolved (5.7.4.1; OPC 10000-3 4.3.4 allows a
  ///                                     Reference to a node that does not exist). Its
  ///                                     NodeVersion does not advance and no
  ///                                     ModelChangeEvent lists it.
  /// @param callback                     Receives the outcome: success, or an
  ///                                     @ref ErrorDetail on failure (e.g.
  ///                                     `BadNodeIdUnknown`). With `Both` it answers once
  ///                                     every other namespace has answered the removal of
  ///                                     its half of a Reference to a deleted node;
  ///                                     when one could not remove it, the nodes are
  ///                                     deleted and the answer is
  ///                                     `Uncertain_ReferenceNotDeleted` (Part 4
  ///                                     5.7.4.4). A success carries the Good code
  ///                                     the namespaces answered the deletes with,
  ///                                     combined by `detail::combined_status`, so
  ///                                     a Good subcode is not lost. A References read
  ///                                     or lookup of a subtree's Node answered
  ///                                     Uncertain is not acted on: it is answered
  ///                                     `Bad_InternalError`
  ///                                     (`ReferencesAnswerUncertain` or
  ///                                     `LookupAnswerUncertain`). This overload never
  ///                                     throws.
  /// @see delete_node_sync, try_delete_node_sync
  void delete_node_async(const NodeId& nodeId, bool deleteForwardHierarchicallyReferencedNodes,
    ReferenceHalves halves, DeleteNodeCompleteCallback callback) noexcept;

  /// Deletes the node identified by @p nodeId, blocking until complete.
  ///
  /// @param nodeId                                  Node to delete.
  /// @param deleteForwardHierarchicallyReferencedNodes If true, recursively delete the
  ///                                      whole forward-hierarchical subtree (see
  ///                                      @ref delete_node_async); if false, only
  ///                                      @p nodeId.
  /// @param halves                       Which halves of the deleted nodes' References
  ///                                     go, as for @ref delete_node_async "delete_node_async": by default
  ///                                     the halves every other node holds too.
  /// @return Success, or an @ref ErrorDetail on failure; `Uncertain_ReferenceNotDeleted` as for
  ///         @ref delete_node_async. Never throws.
  ///         Bad_WouldBlock when called on a thread of this address space's executor, which may be
  ///         the thread that would run the answer: use the *_async overload there.
  /// @see delete_node_async, delete_node_sync
  VoidResult try_delete_node_sync(const NodeId& nodeId, bool deleteForwardHierarchicallyReferencedNodes,
    ReferenceHalves halves = ReferenceHalves::Both) noexcept;

  /// Deletes the node identified by @p nodeId, blocking until complete.
  ///
  /// @param nodeId                                  Node to delete.
  /// @param deleteForwardHierarchicallyReferencedNodes If true, recursively delete the
  ///                                      whole forward-hierarchical subtree (see
  ///                                      @ref delete_node_async); if false, only
  ///                                      @p nodeId.
  /// @param halves                       Which halves of the deleted nodes' References
  ///                                     go, as for @ref delete_node_async "delete_node_async": by default
  ///                                     the halves every other node holds too.
  /// @throws UaException if the deletion fails, and with `Uncertain_ReferenceNotDeleted` when the nodes
  ///         were deleted but a Reference to one was left in another namespace (see
  ///         @ref delete_node_async).
  /// @see delete_node_async, try_delete_node_sync
  void delete_node_sync(const NodeId& nodeId, bool deleteForwardHierarchicallyReferencedNodes,
    ReferenceHalves halves = ReferenceHalves::Both);

  /// Stops the background work every registered namespace is running.
  ///
  /// Shuts down the monitoring helper of every registration (`NamespaceContext::monitoring`), and
  /// calls each namespace's @ref ua::Namespace::shutdown_async once its own registration's helper has
  /// finished; completes when the last namespace reports. Called during server shutdown, BEFORE the
  /// executor is joined: a sampling timer still armed keeps that executor alive, and joining it never
  /// returns.
  ///
  /// A namespace's helper goes before the namespace. The helper stops its sampling timers and starts
  /// no tick; a tick in flight that has not stored its values for the push when shutdown begins pushes
  /// nothing; and the helper answers once the ticks it had in flight have finished, so no tick reads a
  /// Node of a namespace that has already been shut down. Each namespace waits for its own helper
  /// only, so a helper whose tick waits on a slow read holds back only its own namespace.
  ///
  /// Namespaces are asked to stop concurrently rather than in sequence - they are independent,
  /// and one slow namespace should not delay the others. A namespace that reports a failure does
  /// not stop the fan-out; the first failure is returned once every namespace has answered, so a
  /// single bad namespace cannot strand the rest.
  ///
  /// Safe to call twice: the second call asks namespaces that have already stopped, which is a
  /// no-op for them.
  ///
  /// @param callback Invoked exactly once when every namespace has stopped. Runs on an
  ///                 unspecified worker thread. Never throws.
  void shutdown_async(std::function<void(VoidResult)> callback) noexcept;

  /// Returns the array mapping namespace indices to namespace URIs.
  ///
  /// This projection is permanently append-only and exposes no mutation primitive. Register through
  /// @ref add_namespace_async so metadata, monitoring and shutdown state cannot be bypassed.
  ///
  /// @return Read-only reference to the committed namespace array.
  const NamespaceArray& namespace_array() const;

  /// Returns the array of server URIs known to this address space.
  ///
  /// @return Mutable reference to the server array.
  ServerArray& server_array();

  /// Returns the array of server URIs known to this address space.
  ///
  /// @return Read-only reference to the server array.
  const ServerArray& server_array() const;

  /// Returns a codec namespace context whose resolver reads namespace indexes from this address space.
  ///
  /// The resolver holds only a weak reference, so it neither keeps the address space alive nor blocks
  /// shutdown; if the address space is gone when it runs, that resolution fails rather than extending the
  /// lifetime. This replaces `CodecNamespaceContext::for_address_space`, so the core codec names no
  /// address-space type (public API review D5).
  ///
  /// @return A @ref CodecNamespaceContext bound to this address space.
  [[nodiscard]] CodecNamespaceContext codec_namespace_context() const;

  /// Returns a non-owning weak handle to this address space.
  ///
  /// @return A @ref WeakAddressSpace that does not keep the graph alive and must
  ///         be `lock()`-ed before use.
  /// @see WeakAddressSpace
  WeakAddressSpace weak() const;

private:
  shared_ptr<AddressSpaceImpl> mImpl;
  shared_ptr<const detail::NamespaceRegistrationRoute> mRegistrationRoute;

  explicit AddressSpace(shared_ptr<AddressSpaceImpl> impl,
    shared_ptr<const detail::NamespaceRegistrationRoute> registrationRoute = nullptr);

  friend class WeakAddressSpace;
  friend class detail::AddressSpaceNamespaceLifecycle;
  friend class detail::NamespaceRegistrationCoordinator;
  friend class test_helpers::NamespaceRegistrationCoordinatorTestAccess;

  /// Internal interface carrying Session-lifetime notifications into the address space
  /// (`ua_address_space_session_events.h`). Not part of the supported API: a Session close releases
  /// the state Sessions own, so the authority to declare one belongs to the server that ends them,
  /// not to every holder of an address-space handle.
  friend class detail::AddressSpaceSessionEvents;
  friend class detail::AddressSpaceChangeEvents;
  /// Internal access to the FileType handle budget (`ua_file_handle_budget.h`), whose limits the server
  /// sets from its ResourceLimits. Not part of the supported API.
  friend class detail::AddressSpaceFileHandles;
};

}  // namespace ua

#endif  // UA_ADDRESS_SPACE_H
