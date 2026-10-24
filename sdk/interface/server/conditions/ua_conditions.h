// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Server-level registry and lifecycle manager for OPC UA condition instances.
/// @ingroup server

#ifndef UA_CONDITIONS_H
#define UA_CONDITIONS_H

#include "ua_address_space.h"
#include "ua_condition_alarm_metrics.h"
#include "ua_condition_instance.h"
#include "ua_condition_logic.h"
#include "ua_sinks.h"
#include "ua_node_id.h"
#include "ua_string.h"
#include "ua_timer.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ua::server
{
class EventBus;
class ServerImpl;
}  // namespace ua::server

namespace ua
{

/// Test interface for the shutdown methods, which are otherwise the owning server's alone.
struct ConditionsTestAccess;

/// Factory that constructs a fresh `ConditionLogic` for a condition type.
///
/// Registered per ObjectType `NodeId` so the server can auto-create condition
/// instances for known types (for example when discovering imported NodeSet
/// objects). Each invocation returns sole ownership of a new logic object.
using ConditionFactory = std::function<std::unique_ptr<ConditionLogic>()>;

/// Result of a condition-instance creation or lookup: a shared `ConditionInstance`.
///
/// On failure carries the originating `ErrorDetail` via its `StatusCode`.
using ConditionInstanceResult = Result<std::shared_ptr<ConditionInstance>>;

/// Server-level registry of all live condition instances and their factories.
///
/// Owns the set of @ref ConditionInstance objects the server exposes, the
/// per-type @ref ConditionFactory map, and the ConditionRefresh / HasEffect
/// machinery that drives alarm-and-condition behaviour (OPC UA Part 9).
///
/// This is a strand-serialized component: all mutable state (the condition
/// registry, the factory map, the in-progress refresh and discover guards, and
/// the shutting-down flag) is owned by an internal strand. Every public
/// `*_async` method posts entry onto that strand internally, so callers may
/// invoke from any thread. The component holds the registry by `shared_ptr`
/// (`enable_shared_from_this`) and captures itself weakly across async hops, so
/// it is safe to destroy concurrently with in-flight work.
///
/// The public surface follows the canonical async trio:
/// - `*_async` - callback-canonical; the callback receives a @ref Result (or
///   @ref VoidResult) carrying any @ref ErrorDetail on failure. Never throws.
/// - `*_sync` - blocks and returns the bare value (or `void`); throws
///   @ref UaException on a bad status. External convenience only.
/// - `try_*_sync` - blocks and returns a @ref Result (or @ref VoidResult);
///   never throws. External convenience only.
///
/// Lookup methods (`find_condition_*`, `find_factory_*`) treat a missing key as
/// success: the @ref Result is Good with a null payload. Only a real failure
/// (the component is shutting down) yields a Bad status.
///
/// @note `*_sync` and `try_*_sync` block the calling thread; never call them
///       from inside the SDK. Internal callers use the `*_async` variants.
/// @see ConditionInstance, ConditionFactory, server::EventBus
/// @ingroup server
class Conditions : public std::enable_shared_from_this<Conditions>
{
  /// Construction token. A registry is owned by whoever creates it, and the only
  /// sanctioned owner is the server: `Server::conditions()` hands out a reference to the
  /// instance `ServerImpl` created and tears down. Naming this type is restricted to that
  /// owner and - for a fixture that stands up a registry of its own - to
  /// `ConditionsTestAccess`, which keeps `make_shared` usable without leaving the
  /// constructors callable by an application. An application that built its own registry
  /// would hold conditions no client can browse or subscribe to, and would then face the
  /// shutdown problem the owner already solves.
  struct ConstructionKey
  {
    explicit ConstructionKey() = default;
  };

  friend class ua::server::ServerImpl;
  friend struct ConditionsTestAccess;

public:
  /// Constructs a registry without address space integration.
  ///
  /// Conditions created through this instance live only in the in-memory map; no
  /// nodes are instantiated, so no client can browse them or subscribe to their
  /// events. This is a fixture shape, reached through `ConditionsTestAccess`;
  /// a server's own registry is the address-space-integrated overload below.
  ///
  /// @param executor  Executor whose strand serializes all registry state. The
  ///                  component does not take ownership of the underlying
  ///                  io_context; it must outlive the registry.
  /// @param eventSink Sink that retained condition events are emitted through.
  ///                  Held weakly; may expire without invalidating the registry.
  Conditions(ConstructionKey, boost::asio::any_io_executor executor, std::weak_ptr<EventSink> eventSink);

  /// Constructs an address-space-integrated registry and installs the default factories.
  ///
  /// Conditions created through this instance are instantiated as objects in the
  /// supplied @ref AddressSpace. The default NS0 condition factories are
  /// registered during construction, before the `shared_ptr` is publicly
  /// reachable.
  ///
  /// @param executor     Executor whose strand serializes all registry state; it
  ///                     must outlive the registry.
  /// @param eventSink    Sink that retained condition events are emitted through.
  ///                     Held weakly.
  /// @param addressSpace Address space the condition objects are instantiated in.
  Conditions(ConstructionKey, boost::asio::any_io_executor executor, std::weak_ptr<EventSink> eventSink,
    AddressSpace addressSpace);

  // --- Create (AS-integrated) ---

  /// Receives the outcome of a condition-creation request.
  using CreateConditionCallback = std::function<void(ConditionInstanceResult)>;

  /// Creates a condition instance and integrates it into the address space.
  ///
  /// Instantiates the condition object in the address space, wires its component
  /// variables, registers its methods, and adds it to the registry. Posts to the
  /// registry strand and completes asynchronously.
  ///
  /// @param conditionId    NodeId the condition object is created under.
  /// @param sourceNode     Node the condition reports about (its source).
  /// @param sourceName     Human-readable name of the source node.
  /// @param logic          Behaviour for the condition; ownership transfers in.
  /// @param typeDefinition ObjectType the condition is instantiated from.
  /// @param callback       Receives the created @ref ConditionInstance on
  ///                       success, or an @ref ErrorDetail on failure. This
  ///                       overload never throws.
  /// @see create_condition_sync, try_create_condition_sync
  void create_condition_async(NodeId conditionId, NodeId sourceNode, String sourceName,
    std::unique_ptr<ConditionLogic> logic, NodeId typeDefinition, CreateConditionCallback callback);

  /// Creates an address-space-integrated condition, blocking until complete.
  ///
  /// @param conditionId    NodeId the condition object is created under.
  /// @param sourceNode     Node the condition reports about (its source).
  /// @param sourceName     Human-readable name of the source node.
  /// @param logic          Behaviour for the condition; ownership transfers in.
  /// @param typeDefinition ObjectType the condition is instantiated from.
  /// @return The created condition instance.
  /// @throws UaException if creation fails.
  /// @see create_condition_async
  std::shared_ptr<ConditionInstance> create_condition_sync(NodeId conditionId, NodeId sourceNode,
    String sourceName, std::unique_ptr<ConditionLogic> logic, NodeId typeDefinition);

  /// Creates an address-space-integrated condition, blocking until complete.
  ///
  /// @param conditionId    NodeId the condition object is created under.
  /// @param sourceNode     Node the condition reports about (its source).
  /// @param sourceName     Human-readable name of the source node.
  /// @param logic          Behaviour for the condition; ownership transfers in.
  /// @param typeDefinition ObjectType the condition is instantiated from.
  /// @return The created condition instance, or an @ref ErrorDetail on failure.
  ///         Never throws.
  /// @see create_condition_async
  ConditionInstanceResult try_create_condition_sync(NodeId conditionId, NodeId sourceNode, String sourceName,
    std::unique_ptr<ConditionLogic> logic, NodeId typeDefinition) noexcept;

  // --- Create (logic-only, no AS integration) ---

  /// Creates a condition instance without address space integration.
  ///
  /// The instance is only added to the in-memory registry; no nodes are
  /// instantiated. Useful for tests and for embedding pre-wired conditions whose
  /// address-space state is managed externally. Posts to the registry strand and
  /// completes asynchronously.
  ///
  /// @param conditionId NodeId the condition is registered under.
  /// @param sourceNode  Node the condition reports about.
  /// @param sourceName  Human-readable name of the source node.
  /// @param logic       Behaviour for the condition; ownership transfers in.
  /// @param callback    Receives the created @ref ConditionInstance on success,
  ///                    or an @ref ErrorDetail on failure. This overload never
  ///                    throws.
  /// @see create_condition_sync, try_create_condition_sync
  void create_condition_async(NodeId conditionId, NodeId sourceNode, String sourceName,
    std::unique_ptr<ConditionLogic> logic, CreateConditionCallback callback);

  /// Creates a logic-only condition, blocking until complete.
  ///
  /// @param conditionId NodeId the condition is registered under.
  /// @param sourceNode  Node the condition reports about.
  /// @param sourceName  Human-readable name of the source node.
  /// @param logic       Behaviour for the condition; ownership transfers in.
  /// @return The created condition instance.
  /// @throws UaException if creation fails.
  /// @see create_condition_async
  std::shared_ptr<ConditionInstance> create_condition_sync(
    NodeId conditionId, NodeId sourceNode, String sourceName, std::unique_ptr<ConditionLogic> logic);

  /// Creates a logic-only condition, blocking until complete.
  ///
  /// @param conditionId NodeId the condition is registered under.
  /// @param sourceNode  Node the condition reports about.
  /// @param sourceName  Human-readable name of the source node.
  /// @param logic       Behaviour for the condition; ownership transfers in.
  /// @return The created condition instance, or an @ref ErrorDetail on failure.
  ///         Never throws.
  /// @see create_condition_async
  ConditionInstanceResult try_create_condition_sync(
    NodeId conditionId, NodeId sourceNode, String sourceName, std::unique_ptr<ConditionLogic> logic) noexcept;

  // --- Registry ---

  /// Registers a pre-created condition instance.
  ///
  /// Posts to the registry strand and completes asynchronously.
  ///
  /// @param instance Condition to register, keyed by its conditionId.
  /// @param callback Receives success, or an @ref ErrorDetail on failure
  ///                 (`BadAlreadyExists` if a different instance is already
  ///                 registered under the same conditionId). Never throws.
  /// @see register_condition_sync, try_register_condition_sync
  void register_condition_async(
    std::shared_ptr<ConditionInstance> instance, std::function<void(VoidResult)> callback);

  /// Registers a pre-created condition instance, blocking until complete.
  /// @param instance Condition to register, keyed by its conditionId.
  /// @throws UaException if registration fails (including `BadAlreadyExists`).
  /// @see register_condition_async
  void register_condition_sync(std::shared_ptr<ConditionInstance> instance);

  /// Registers a pre-created condition instance, blocking until complete.
  /// @param instance Condition to register, keyed by its conditionId.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see register_condition_async
  VoidResult try_register_condition_sync(std::shared_ptr<ConditionInstance> instance) noexcept;

  /// Removes a condition from the registry by its conditionId.
  ///
  /// A no-op when no condition is registered under @p conditionId. Posts to the
  /// registry strand and completes asynchronously.
  ///
  /// @param conditionId Key of the condition to remove.
  /// @param callback    Receives success, or an @ref ErrorDetail on failure.
  ///                    Never throws.
  /// @see deregister_condition_sync, try_deregister_condition_sync
  void deregister_condition_async(NodeId conditionId, std::function<void(VoidResult)> callback);

  /// Removes a condition by its conditionId, blocking until complete.
  /// @param conditionId Key of the condition to remove.
  /// @throws UaException if the operation fails.
  /// @see deregister_condition_async
  void deregister_condition_sync(NodeId conditionId);

  /// Removes a condition by its conditionId, blocking until complete.
  /// @param conditionId Key of the condition to remove.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see deregister_condition_async
  VoidResult try_deregister_condition_sync(NodeId conditionId) noexcept;

  /// Looks up a registered condition by its conditionId.
  ///
  /// Posts to the registry strand and completes asynchronously.
  ///
  /// @param conditionId Key to look up.
  /// @param callback    Receives the @ref ConditionInstance, a Good result with
  ///                    a null payload if @p conditionId is not registered, or a
  ///                    Bad status (`Shutdown`) if the component is shutting
  ///                    down. Carries an @ref ErrorDetail on failure. Never
  ///                    throws.
  /// @see find_condition_sync, try_find_condition_sync
  void find_condition_async(
    NodeId conditionId, std::function<void(Result<std::shared_ptr<ConditionInstance>>)> callback);

  /// Looks up a registered condition by its conditionId, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; @ref try_find_condition_sync returns it.
  /// @param conditionId Key to look up.
  /// @return The condition instance, or null if not registered.
  /// @throws UaException if the component is shutting down, or when the answer is not Good.
  /// @see find_condition_async
  std::shared_ptr<ConditionInstance> find_condition_sync(NodeId conditionId);

  /// Looks up a registered condition by its conditionId, blocking until complete.
  /// @param conditionId Key to look up.
  /// @return The condition instance (null if not registered), or an
  ///         @ref ErrorDetail on failure. Never throws.
  /// @see find_condition_async
  Result<std::shared_ptr<ConditionInstance>> try_find_condition_sync(NodeId conditionId) noexcept;

  // --- Refresh ---

  /// Sink invoked once per event to deliver it during a refresh.
  using EmitFunction = std::function<void(BaseEvent&)>;

  /// Performs a ConditionRefresh: replays all retained condition events.
  ///
  /// Emits a RefreshStartEvent, re-emits every retained condition event, then
  /// emits a RefreshEndEvent through @p emitter. This overload delivers events
  /// to a caller-supplied emit function. Posts to the registry strand and
  /// completes asynchronously.
  ///
  /// @param emitter  Invoked once per event in refresh order.
  /// @param callback Receives success, or an @ref ErrorDetail on failure. Never
  ///                 throws.
  /// @see condition_refresh_sync, try_condition_refresh_sync, condition_refresh2_async
  void condition_refresh_async(EmitFunction emitter, std::function<void(VoidResult)> callback);

  /// Performs a ConditionRefresh, delivering events to an @ref EventSink.
  ///
  /// Equivalent to the @ref EmitFunction overload but routes events through
  /// @p sink. The sink must outlive the operation.
  ///
  /// @param sink     Sink the refresh events are emitted through.
  /// @param callback Receives success, or an @ref ErrorDetail on failure. Never
  ///                 throws.
  /// @see condition_refresh_sync, try_condition_refresh_sync
  void condition_refresh_async(EventSink& sink, std::function<void(VoidResult)> callback);

  /// Performs a ConditionRefresh via an emit function, blocking until complete.
  /// @param emitter Invoked once per event in refresh order.
  /// @throws UaException if the refresh fails.
  /// @see condition_refresh_async
  void condition_refresh_sync(EmitFunction emitter);

  /// Performs a ConditionRefresh via an @ref EventSink, blocking until complete.
  /// @param sink Sink the refresh events are emitted through.
  /// @throws UaException if the refresh fails.
  /// @see condition_refresh_async
  void condition_refresh_sync(EventSink& sink);

  /// Performs a ConditionRefresh via an emit function, blocking until complete.
  /// @param emitter Invoked once per event in refresh order.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see condition_refresh_async
  VoidResult try_condition_refresh_sync(EmitFunction emitter) noexcept;

  /// Performs a ConditionRefresh via an @ref EventSink, blocking until complete.
  /// @param sink Sink the refresh events are emitted through.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see condition_refresh_async
  VoidResult try_condition_refresh_sync(EventSink& sink) noexcept;

  /// Performs a ConditionRefresh2: refresh scoped to a single monitored node.
  ///
  /// Like @ref condition_refresh_async but replays only conditions whose source
  /// node matches @p monitoredNode (OPC UA Part 9 5.5.8). This overload
  /// delivers events to a caller-supplied emit function. Posts to the registry
  /// strand and completes asynchronously.
  ///
  /// @param emitter       Invoked once per event in refresh order.
  /// @param monitoredNode Source node the refresh is scoped to.
  /// @param callback      Receives success, or an @ref ErrorDetail on failure.
  ///                      Never throws.
  /// @see condition_refresh2_sync, try_condition_refresh2_sync, condition_refresh_async
  void condition_refresh2_async(
    EmitFunction emitter, NodeId monitoredNode, std::function<void(VoidResult)> callback);

  /// Performs a ConditionRefresh2, delivering events to an @ref EventSink.
  ///
  /// Equivalent to the @ref EmitFunction overload but routes events through
  /// @p sink. The sink must outlive the operation.
  ///
  /// @param sink          Sink the refresh events are emitted through.
  /// @param monitoredNode Source node the refresh is scoped to.
  /// @param callback      Receives success, or an @ref ErrorDetail on failure.
  ///                      Never throws.
  /// @see condition_refresh2_sync, try_condition_refresh2_sync
  void condition_refresh2_async(
    EventSink& sink, NodeId monitoredNode, std::function<void(VoidResult)> callback);

  /// Performs a ConditionRefresh2 via an emit function, blocking until complete.
  /// @param emitter       Invoked once per event in refresh order.
  /// @param monitoredNode Source node the refresh is scoped to.
  /// @throws UaException if the refresh fails.
  /// @see condition_refresh2_async
  void condition_refresh2_sync(EmitFunction emitter, NodeId monitoredNode);

  /// Performs a ConditionRefresh2 via an @ref EventSink, blocking until complete.
  /// @param sink          Sink the refresh events are emitted through.
  /// @param monitoredNode Source node the refresh is scoped to.
  /// @throws UaException if the refresh fails.
  /// @see condition_refresh2_async
  void condition_refresh2_sync(EventSink& sink, NodeId monitoredNode);

  /// Performs a ConditionRefresh2 via an emit function, blocking until complete.
  /// @param emitter       Invoked once per event in refresh order.
  /// @param monitoredNode Source node the refresh is scoped to.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see condition_refresh2_async
  VoidResult try_condition_refresh2_sync(EmitFunction emitter, NodeId monitoredNode) noexcept;

  /// Performs a ConditionRefresh2 via an @ref EventSink, blocking until complete.
  /// @param sink          Sink the refresh events are emitted through.
  /// @param monitoredNode Source node the refresh is scoped to.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see condition_refresh2_async
  VoidResult try_condition_refresh2_sync(EventSink& sink, NodeId monitoredNode) noexcept;

  // --- Factories ---

  /// Registers a @ref ConditionFactory for an ObjectType.
  ///
  /// Insert-or-assign: registering a factory for an already-registered
  /// @p objectTypeId silently overwrites the previous one. Posts to the registry
  /// strand and completes asynchronously.
  ///
  /// @param objectTypeId ObjectType NodeId the factory is keyed by.
  /// @param factory      Factory invoked to build logic for that type.
  /// @param callback     Receives success, or an @ref ErrorDetail on failure.
  ///                     Never throws.
  /// @see register_factory_sync, try_register_factory_sync
  void register_factory_async(
    NodeId objectTypeId, ConditionFactory factory, std::function<void(VoidResult)> callback);

  /// Registers a factory for an ObjectType, blocking until complete.
  /// @param objectTypeId ObjectType NodeId the factory is keyed by.
  /// @param factory      Factory invoked to build logic for that type.
  /// @throws UaException if registration fails.
  /// @see register_factory_async
  void register_factory_sync(NodeId objectTypeId, ConditionFactory factory);

  /// Sets the per-condition ConditionBranch retention cap applied to factory-created acknowledgeable
  /// condition logic (memory fail-safe). Intended for startup configuration before any condition is
  /// instantiated. Clamped to >= 1.
  /// @param maxBranches Maximum number of ConditionBranches retained per condition; clamped to >= 1.
  void set_max_branches_per_condition(size_t maxBranches);

  /// Registers a factory for an ObjectType, blocking until complete.
  /// @param objectTypeId ObjectType NodeId the factory is keyed by.
  /// @param factory      Factory invoked to build logic for that type.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see register_factory_async
  VoidResult try_register_factory_sync(NodeId objectTypeId, ConditionFactory factory) noexcept;

  /// Looks up a registered factory by ObjectType NodeId.
  ///
  /// Posts to the registry strand and completes asynchronously.
  ///
  /// @param objectTypeId ObjectType NodeId to look up.
  /// @param callback     Receives the @ref ConditionFactory, a Good result with
  ///                     an empty factory if @p objectTypeId is not registered,
  ///                     or a Bad status (`Shutdown`) if the component is
  ///                     shutting down. Never throws.
  /// @see find_factory_sync, try_find_factory_sync
  void find_factory_async(NodeId objectTypeId, std::function<void(Result<ConditionFactory>)> callback);

  /// Looks up a registered factory, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; @ref try_find_factory_sync returns it.
  /// @param objectTypeId ObjectType NodeId to look up.
  /// @return The factory, or an empty factory if not registered.
  /// @throws UaException if the component is shutting down, or when the answer is not Good.
  /// @see find_factory_async
  ConditionFactory find_factory_sync(NodeId objectTypeId);

  /// Looks up a registered factory, blocking until complete.
  /// @param objectTypeId ObjectType NodeId to look up.
  /// @return The factory (empty if not registered), or an @ref ErrorDetail on
  ///         failure. Never throws.
  /// @see find_factory_async
  Result<ConditionFactory> try_find_factory_sync(NodeId objectTypeId) noexcept;

  // --- Retained / metrics ---

  /// Snapshots all currently retained conditions.
  ///
  /// Posts to the registry strand and completes asynchronously.
  ///
  /// @param callback Receives the snapshot vector, or a Bad status (`Shutdown`)
  ///                 carrying an @ref ErrorDetail if the component is shutting
  ///                 down. Never throws.
  /// @see retained_conditions_sync, try_retained_conditions_sync
  void retained_conditions_async(
    std::function<void(Result<std::vector<std::shared_ptr<ConditionInstance>>>)> callback);

  /// Snapshots all currently retained conditions, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; @ref try_retained_conditions_sync returns it.
  /// @return The retained conditions.
  /// @throws UaException if the component is shutting down, or when the answer is not Good.
  /// @see retained_conditions_async
  std::vector<std::shared_ptr<ConditionInstance>> retained_conditions_sync();

  /// Snapshots all currently retained conditions, blocking until complete.
  /// @return The retained conditions, or an @ref ErrorDetail on failure. Never throws.
  /// @see retained_conditions_async
  Result<std::vector<std::shared_ptr<ConditionInstance>>> try_retained_conditions_sync() noexcept;

  /// Computes aggregate alarm metrics across all registered conditions.
  ///
  /// Posts to the registry strand and completes asynchronously.
  ///
  /// @param callback Receives the @ref ConditionAlarmMetrics, or a Bad status
  ///                 (`Shutdown`) carrying an @ref ErrorDetail if the component
  ///                 is shutting down. Never throws.
  /// @see compute_alarm_metrics_sync, try_compute_alarm_metrics_sync
  void compute_alarm_metrics_async(std::function<void(Result<ConditionAlarmMetrics>)> callback);

  /// Computes aggregate alarm metrics, blocking until complete.
  ///
  /// A Good subcode on the answer is not returned; @ref try_compute_alarm_metrics_sync returns it.
  /// @return The computed metrics.
  /// @throws UaException if the component is shutting down, or when the answer is not Good.
  /// @see compute_alarm_metrics_async
  ConditionAlarmMetrics compute_alarm_metrics_sync();

  /// Computes aggregate alarm metrics, blocking until complete.
  /// @return The computed metrics, or an @ref ErrorDetail on failure. Never throws.
  /// @see compute_alarm_metrics_async
  Result<ConditionAlarmMetrics> try_compute_alarm_metrics_sync() noexcept;

  // --- Discover ---

  /// Receives the outcome of a discover-existing-conditions scan.
  using DiscoverExistingConditionsCallback = std::function<void(VoidResult)>;

  /// Scans the address space for condition-typed objects and attaches them.
  ///
  /// Walks the address space, wraps each object whose type derives from
  /// ConditionType in a @ref ConditionInstance, and registers it. Typically run
  /// once after NodeSet import to adopt imported conditions. Posts to the
  /// registry strand and completes asynchronously.
  ///
  /// @param callback Receives success, or an @ref ErrorDetail on failure. Never
  ///                 throws.
  /// @see discover_existing_conditions_sync, try_discover_existing_conditions_sync
  void discover_existing_conditions_async(DiscoverExistingConditionsCallback callback);

  /// Scans for and attaches existing conditions, blocking until complete.
  /// @throws UaException if the scan fails.
  /// @see discover_existing_conditions_async
  void discover_existing_conditions_sync();

  /// Scans for and attaches existing conditions, blocking until complete.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see discover_existing_conditions_async
  VoidResult try_discover_existing_conditions_sync() noexcept;

  // --- Refresh method registration (bootstrap) ---

  /// Predicate that tests whether a subscription belongs to a given session.
  ///
  /// Returns `true` when the subscription identified by `subscriptionId` is owned
  /// by the session identified by `callerSessionId`.
  using SubscriptionValidator = std::function<bool(uint32_t subscriptionId, const NodeId& callerSessionId)>;

  /// Resolves the monitored NodeId of an event MonitoredItem.
  ///
  /// Invoked by the ConditionRefresh2 handler (OPC UA Part 9 5.5.8) to scope a
  /// refresh to the single MonitoredItem identified by `(subscriptionId,
  /// monitoredItemId)`. The completion callback receives the monitored NodeId, or
  /// `std::nullopt` when no such event MonitoredItem is registered (a normal
  /// "not found" outcome, not an error). The resolver may complete
  /// asynchronously.
  using MonitoredItemNodeResolver = std::function<void(
    uint32_t subscriptionId, uint32_t monitoredItemId, std::function<void(std::optional<NodeId>)> callback)>;

  /// Installs the ConditionRefresh and ConditionRefresh2 method handlers.
  ///
  /// Registers handlers for ConditionRefresh (`i=3875`) and ConditionRefresh2
  /// (`i=12912`) on the NS0 ConditionType method nodes so clients can invoke them
  /// via the Call service. Call once during server initialization, after NS0 is
  /// loaded.
  ///
  /// @param eventBus         Weak handle to the server EventBus the refresh handlers emit refreshed
  ///                         Condition events through. Weak (not a raw reference) because the emit runs
  ///                         across async hops on a pool thread and the bus can be torn down
  ///                         (~ServerImpl) while a refresh is in flight; each emit locks it and is
  ///                         skipped if the bus is gone.
  /// @param validator        Confirms the caller owns the target subscription.
  /// @param itemNodeResolver Resolves a ConditionRefresh2 MonitoredItemId to its
  ///                         monitored NodeId so the refresh is scoped to that one
  ///                         MonitoredItem (Part 9 5.5.8). When null,
  ///                         ConditionRefresh2 cannot resolve any MonitoredItem
  ///                         and reports `BadMonitoredItemIdInvalid`.
  void register_refresh_methods(std::weak_ptr<server::EventBus> eventBus, SubscriptionValidator validator,
    MonitoredItemNodeResolver itemNodeResolver);

  /// Installs the standard Condition method handlers on the NS0 type method nodes.
  ///
  /// Registers handlers for Enable (`i=9027`), Disable (`i=9028`), AddComment
  /// (`i=9029`), Acknowledge (`i=9111`) and Confirm (`i=9113`) on the NS0
  /// ConditionType / AcknowledgeableConditionType method nodes. OPC UA clients
  /// (including UACTT) invoke these standard methods using the *type* method-node
  /// id with the condition *instance* as the object, so the type nodes need
  /// handlers that resolve the object to its registered @ref ConditionInstance and
  /// delegate to its `call_*_async` entry points. Without this, a call to a type
  /// method node hits a handlerless method node and fails with `BadNotSupported`.
  ///
  /// Call once during server initialization, after NS0 is loaded - alongside
  /// @ref register_refresh_methods.
  void register_condition_methods();

  // --- HasEffect ---

  /// Receives the outcome of HasEffect reference processing.
  using ProcessHasEffectReferencesCallback = std::function<void(VoidResult)>;

  /// Applies HasEffect references emanating from a transition node.
  ///
  /// Browses @p transitionNodeId for HasEffectDisable, HasEffectEnable,
  /// HasEffectSuppressed and HasEffectUnsuppressed references and applies the
  /// corresponding operation to each target condition instance. Posts to the
  /// registry strand and completes asynchronously.
  ///
  /// @param transitionNodeId Transition node whose HasEffect references are
  ///                         processed.
  /// @param callback         Receives success, or an @ref ErrorDetail on failure.
  ///                         Never throws.
  /// @see process_has_effect_references_sync, try_process_has_effect_references_sync
  void process_has_effect_references_async(
    NodeId transitionNodeId, ProcessHasEffectReferencesCallback callback);

  /// Applies a transition node's HasEffect references, blocking until complete.
  /// @param transitionNodeId Transition node whose HasEffect references are processed.
  /// @throws UaException if processing fails.
  /// @see process_has_effect_references_async
  void process_has_effect_references_sync(NodeId transitionNodeId);

  /// Applies a transition node's HasEffect references, blocking until complete.
  /// @param transitionNodeId Transition node whose HasEffect references are processed.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  /// @see process_has_effect_references_async
  VoidResult try_process_has_effect_references_sync(NodeId transitionNodeId) noexcept;

private:
  // --- Shutdown ---
  //
  // Closing belongs to the owner, not to a holder of a borrowed reference. `Server::conditions()`
  // hands out a reference to the instance ServerImpl created and destroys; the server closes it as
  // part of its own shutdown, and an application calling close on that instance mid-run would
  // silently stop every alarm in its address space. A component built independently - as the test
  // fixtures do - reaches these through ConditionsTestAccess.
  friend class ua::server::ServerImpl;
  friend struct ConditionsTestAccess;

  /// Coroutine-shaped operations defined in the .cpp. Each owns itself for the length of one
  /// request and reaches this component's strand, logger and on-strand helpers.
  friend class ProcessHasEffectReferencesOperation;
  friend class ConditionRefreshOperation;
  friend class CreateConditionOperation;
  friend class DiscoverExistingConditionsOperation;

  /// Closes every registered condition instance and shuts the registry down.
  ///
  /// Marks the component as shutting down, snapshots and clears the registry,
  /// then closes each instance and waits for all completions before invoking
  /// @p callback. After this, lookup methods report a `Shutdown` status.
  /// Idempotent: a second close invokes the callback immediately. Posts to the
  /// registry strand and completes asynchronously.
  ///
  /// @param callback Receives success, or an @ref ErrorDetail on failure. Never
  ///                 throws.
  void close_async(std::function<void(VoidResult)> callback);

  /// Closes all conditions and shuts down, blocking until complete.
  /// @throws UaException if shutdown fails.
  void close_sync();

  /// Closes all conditions and shuts down, blocking until complete.
  /// @return Success, or an @ref ErrorDetail on failure. Never throws.
  VoidResult try_close_sync() noexcept;

  /// Strand serializing all registry state. Private: the post helpers
  /// (`ua::async::post_borrowing` / `post_owning`) take the strand as an
  /// argument read from this member at each internal call site, so - unlike the
  /// removed `on_strand` helper, which required a public `mStrand` - it is never
  /// exposed on the public API surface. Callers use the public `*_async`
  /// methods, which post to it internally.
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  /// Register default NS0 condition factories. Called from the AS-enabled
  /// constructor BEFORE the shared_ptr is publicly reachable - writes
  /// directly into mFactories without a strand hop. This is the one
  /// permitted pre-publication registry write.
  void register_default_factories();

  // On-strand helpers (no Result wrapper; internal hot path for continuations
  // that already run on mStrand). Caller must guarantee on-strand execution.
  std::shared_ptr<ConditionInstance> find_condition_on_strand(const NodeId& conditionId) const;
  ConditionFactory find_factory_on_strand(const NodeId& objectTypeId) const;

  // --- Per-flow continuation state. Definitions in .cpp. ---
  struct SuppressionGroupScan;

  // --- Continuation entry points; each flow's per-step continuations are file-static
  //     in the .cpp to keep the header surface small. ---
  /// Build the weak-only observer installed on each managed ConditionInstance.
  ConditionInstance::InputCommunicationObserver make_input_communication_observer();

  /// Update the failed-condition set for one bound input and synchronize its communication alarm.
  void on_input_communication_status(NodeId conditionId, NodeId inputNode, StatusCode status);

  /// Create the one SystemOffNormalAlarm instance associated with @p inputNode.
  void create_input_communication_alarm(NodeId inputNode);

  /// Drive an existing communication alarm active iff its input still has failed dependants.
  void synchronize_input_communication_alarm(const NodeId& inputNode);

  // AlarmSuppressionGroup monitoring. The fixed-grid timer and every continuation run on mStrand;
  // the scan itself uses only callback-canonical AddressSpace and ConditionInstance operations.
  void ensure_suppression_group_monitoring();
  void begin_suppression_group_scan();
  void suppression_scan_next_condition();
  void on_suppression_condition_resolved(NodeAccessorResult result);
  void on_suppression_condition_references(Result<References> result);
  void suppression_scan_next_group();
  void on_suppression_group_resolved(NodeAccessorResult result);
  void on_suppression_group_references(Result<References> result);
  void suppression_scan_next_member();
  void on_suppression_member_resolved(NodeAccessorResult result);
  void on_suppression_member_value(DataValueResult result);
  void apply_suppression_group_state(bool active, bool hasReferencedGroups);
  void on_suppression_state_applied(VoidResult result);
  void fail_suppression_group_scan(StatusCode status);
  void advance_suppression_group_scan();

  // --- Members ---
  // Immutable after construction.
  std::weak_ptr<EventSink> mEventSink;
  std::optional<AddressSpace> mAddressSpace;
  /// Logger for async continuations, sourced from mAddressSpace at construction (a no-op Logger for
  /// the logic-only constructor with no address space). A value handle that survives teardown;
  /// passed into the post helpers at each call site.
  ua::Logger mLogger;
  // Per-condition ConditionBranch retention cap, applied to factory-created acknowledgeable logic.
  // Set once at startup (effectively const thereafter); read on mStrand at logic creation.
  size_t mMaxBranchesPerCondition{100};

  // Strand-owned state. No mutex - single sync strategy (Rule 4).
  std::unordered_map<NodeId, std::shared_ptr<ConditionInstance>> mConditions;
  std::unordered_map<NodeId, ConditionFactory> mFactories;
  std::unordered_map<NodeId, std::unordered_set<NodeId>> mFailedConditionsByInput;
  std::unordered_map<NodeId, std::shared_ptr<ConditionInstance>> mInputCommunicationAlarms;
  std::unordered_set<NodeId> mInputCommunicationAlarmCreates;
  std::unordered_set<uint32_t> mRefreshInProgress;  // Per-subscription guard (COND-136)
  Timer mSuppressionGroupTimer;
  std::shared_ptr<SuppressionGroupScan> mSuppressionGroupScan;
  std::unordered_map<NodeId, bool> mSuppressionGroupStates;
  bool mShuttingDown{false};
  bool mDiscoverInProgress{false};
};

}  // namespace ua

#endif  // !UA_CONDITIONS_H
