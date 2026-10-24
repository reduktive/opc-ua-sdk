// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ADDRESS_SPACE_CACHE_H
#define UA_ADDRESS_SPACE_CACHE_H

/// @file
/// @brief The optional per-Connection client-side address-space cache (client design section 8.7): alias
///        substitution (RegisterNodes), static-attribute pre-flight cache, and Browse-result cache.
/// @ingroup client

#include "ua_address_space_cache_policy.h"
#include "ua_browse_direction.h"
#include "ua_logger.h"
#include "ua_lru_map.h"
#include "ua_node_id.h"
#include "ua_reference_description.h"
#include "ua_result.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace ua::client::detail
{

class WireOps;
struct AddressSpaceCacheTestAccess;

/// The cached RegisterNodes alias for one user-facing NodeId (CL-VIEW-009).
struct AliasEntry
{
  ua::NodeId registered;  ///< the server-assigned numeric handle to substitute at request-build time
  std::uint64_t sessionGeneration = 0;  ///< the `mSessionGeneration` at install (stale entries skip lookup)
};

/// The static attributes tier-2 pre-flights against, cached from an observed Read (section 8.7).
///
/// The five *server-intrinsic* attributes {`accessLevel`, `accessLevelEx`, `dataType`, `valueRank`,
/// `arrayDimensions`} are stable for the NodeId and survive a same-server reconnect (section 9.8 override 3);
/// `userAccessLevel` is Session-dependent (it reflects the identity used in ActivateSession) and is
/// flushed on every Session change.
struct AttributeEntry
{
  std::optional<std::uint8_t> accessLevel;
  std::optional<std::uint32_t> accessLevelEx;
  std::optional<ua::NodeId> dataType;
  std::optional<std::int32_t> valueRank;
  std::optional<std::vector<std::uint32_t>> arrayDimensions;
  std::optional<std::uint8_t> userAccessLevel;  ///< Session-dependent: flushed on Session change
};

/// The key for one cached Browse result (a start node plus EVERY browse parameter that shapes the wire
/// BrowseDescription  -  so only a byte-equivalent browse hits the same entry). `includeSubtypes` is part of
/// the key because it changes which references the server returns (a subtype walk is a strict superset), so a
/// page cached for `includeSubtypes=false` must NOT satisfy an `includeSubtypes=true` walk (a wrong-shape
/// hit). The remaining shape fields  -  `direction`, `referenceTypeId`, `nodeClassMask`, `resultMask`  -
/// mirror the other `BrowseDescription` fields `make_browse_request` sends (`ua_browse_cursor.cpp`).
struct CachedBrowseKey
{
  ua::NodeId node;
  ua::BrowseDirection direction = ua::BrowseDirection::Forward;
  std::optional<ua::NodeId> referenceTypeId;
  bool includeSubtypes = false;
  std::uint32_t nodeClassMask = 0;
  std::uint32_t resultMask = 0;

  bool operator==(const CachedBrowseKey& other) const = default;
};

/// Hash for @ref CachedBrowseKey (combines the node hash with the shape parameters).
struct CachedBrowseKeyHash
{
  std::size_t operator()(const CachedBrowseKey& key) const
  {
    std::size_t hash = std::hash<ua::NodeId>{}(key.node);
    const auto mix = [&hash](std::size_t value)
    {
      hash = hash * 1000003U + value;
    };
    mix(static_cast<std::size_t>(static_cast<std::int32_t>(key.direction)));
    mix(key.referenceTypeId ? std::hash<ua::NodeId>{}(*key.referenceTypeId) : 0U);
    mix(key.includeSubtypes ? 1U : 0U);
    mix(key.nodeClassMask);
    mix(key.resultMask);
    return hash;
  }
};

/// One cached Browse result: the references plus the install time driving the idle TTL.
struct BrowseEntry
{
  std::vector<ua::ReferenceDescription> references;
  std::chrono::steady_clock::time_point installedAt = std::chrono::steady_clock::now();
};

/// A single address-space change the cache invalidates against (CL-EVT-003).
enum class ModelChangeVerb
{
  NodeAdded,
  NodeDeleted,
  ReferenceAdded,
  ReferenceDeleted,
  DataTypeChanged,
};

/// One change entry from a GeneralModelChangeEvent (the wire `ModelChangeStructureDataType` mapped to the
/// SDK-internal shape at the EventSubscriber boundary).
struct ModelChange
{
  ua::NodeId affected;  ///< the node the change concerns
  ModelChangeVerb verb = ModelChangeVerb::NodeAdded;
};

/// A model-change notification routed into the cache by EventSubscriber (CL-EVT-003).
struct ModelChangeNotification
{
  /// General = a `GeneralModelChangeEvent` carrying per-node @ref changes; Base = a `BaseModelChangeEvent`
  /// for a View (full flush, section 9.6.19.4).
  enum class Kind
  {
    General,
    Base,
  };

  Kind kind = Kind::General;
  ua::NodeId view;  ///< the changed View (when @ref kind == Base)
  std::vector<ModelChange> changes;  ///< the per-node changes (when @ref kind == General)
};

/// The optional per-Connection client-side address-space cache (section 8.7).
///
/// A strand-serialized component: alias substitution (RegisterNodes, CL-VIEW-009), a static-attribute
/// pre-flight cache (CL-ATTR-009 / WriteFullArrayOnly), and a Browse-result cache for `BrowseCursor`
/// repeated walks. Opt-in via @ref AddressSpaceCachePolicy::enabled  -  when disabled every method is a
/// clean pass-through no-op and tier-2 goes wire-direct.
///
/// Lifetime (section 9.8.3 UAF fix): the cache is held by `shared_ptr` and derives from
/// `enable_shared_from_this`, so every internal async completion (the unregister-batch coalesce timer,
/// the UnregisterNodes response, the shutdown drain) is armed with `post_borrowing`  -  it weak-captures
/// the cache and no-ops if the cache is gone, and it locks the weak @ref WireOps interface and bails if the
/// Connection behind it is gone, rather than dereferencing a raw owner across an async boundary (the
/// "destructor ordering guarantees liveness" rationale is false across such a boundary).
class AddressSpaceCache : public std::enable_shared_from_this<AddressSpaceCache>
{
public:
  /// Creates the cache over the upward @ref WireOps interface (section 8.2A.13).
  ///
  /// @param strand   `ConnectionImpl`'s strand  -  the cache has **no private strand** (section 8.7: it lives
  /// on
  ///                 ConnectionImpl's strand). The injected strand is the single serialization domain shared
  ///                 by the synchronous caller-on-strand methods and the marshalled async ones, so both
  ///                 mutate the LruMaps and the coalesce timer under one serialization. The coalesce timer is
  ///                 constructed on it too. The cache never fabricates a strand of its own.
  /// @param wireOps  The wire interface used to issue UnregisterNodes (held WEAK; locked per op, bail if gone).
  /// @param policy   The per-Connection cache knobs (sizes, TTL, batch, enable switch).
  /// @param logger   Logger for the guarded async boundaries and advisory diagnostics.
  /// @return A shared cache.
  [[nodiscard]] static std::shared_ptr<AddressSpaceCache> create(
    boost::asio::strand<boost::asio::any_io_executor> strand, std::weak_ptr<WireOps> wireOps,
    AddressSpaceCachePolicy policy, ua::Logger logger);

  AddressSpaceCache(const AddressSpaceCache&) = delete;
  AddressSpaceCache& operator=(const AddressSpaceCache&) = delete;
  AddressSpaceCache(AddressSpaceCache&&) = delete;
  AddressSpaceCache& operator=(AddressSpaceCache&&) = delete;
  ~AddressSpaceCache() = default;

  /// @return True iff the cache is enabled by policy (else every method is a no-op pass-through).
  [[nodiscard]] bool enabled() const noexcept
  {
    return mPolicy.enabled;
  }

  // -------- Alias substitution (CL-VIEW-009); synchronous, caller-on-strand --------

  /// Returns the wire-NodeId to send for @p userFacing: the cached, current-Session alias on a hit, or
  /// @p userFacing verbatim on a miss / stale-generation / disabled cache.
  [[nodiscard]] ua::NodeId lookup_for_request(const ua::NodeId& userFacing) const noexcept;

  /// Applies a RegisterNodes result (paired @p originals -> @p registered) to the alias cache. A no-op when
  /// disabled. LRU eviction past `maxRegisteredNodes` queues the evicted node for UnregisterNodes.
  void install_aliases(std::vector<ua::NodeId> originals, std::vector<ua::NodeId> registered);

  // -------- Attribute pre-flight cache; synchronous, caller-on-strand --------

  /// Caches the static @p attributes observed for @p userFacing (a no-op when disabled).
  void install_attributes(const ua::NodeId& userFacing, AttributeEntry attributes);

  /// @return The cached attribute entry for @p userFacing, or `nullopt` on a miss / disabled cache.
  [[nodiscard]] std::optional<AttributeEntry> lookup_attributes(const ua::NodeId& userFacing) const noexcept;

  // -------- Browse-result cache (BrowseCursor); synchronous, caller-on-strand --------

  /// @return The cached Browse result for @p key, or `nullopt` on a miss, a TTL-expired entry (dropped),
  ///         or a disabled cache.
  [[nodiscard]] std::optional<BrowseEntry> lookup_browse(const CachedBrowseKey& key) const noexcept;

  /// Caches a Browse result under @p key (a no-op when disabled).
  void install_browse(CachedBrowseKey key, BrowseEntry entry);

  // -------- Eviction / release / invalidation / shutdown; async, marshalled onto the strand --------

  /// Explicit user release of a cached node: drops it from every sub-cache and queues an UnregisterNodes
  /// (CL-VIEW-010). Idempotent. @p cb fires Good on the executor.
  void release_async(ua::NodeId userFacing, std::function<void(ua::VoidResult)> cb);

  /// Session-recreate reconnect (CL-VIEW-011): clears the alias cache and bumps the generation. When
  /// @p serverIdentityPreserved AND the namespace indices are stable (@p namespaceArrayChanged false) the
  /// attribute cache is retained but each entry's `userAccessLevel` is flushed (section 9.8 override 3); the
  /// browse cache is flushed on every reconnect (section 9.6.19.3). When not preserved (redundancy switch) OR
  /// the server renumbered its NamespaceArray (@p namespaceArrayChanged true) all attributes clear  -  the
  /// sub-caches are keyed by a namespace-INDEX NodeId, so a renumber would otherwise turn a retained entry
  /// into a mis-keyed stale hit (CL-SESS-028 fallback; see the note in the .cpp). @p cb fires on the
  /// executor.
  void on_session_changed_async(
    bool serverIdentityPreserved, bool namespaceArrayChanged, std::function<void()> cb);

  /// Model-change invalidation (CL-EVT-003): per-verb invalidation for a GeneralModelChangeEvent, full
  /// flush for a BaseModelChangeEvent. @p cb fires on the executor.
  void on_model_change_async(ModelChangeNotification notification, std::function<void()> cb);

  /// Shutdown drain (CL-VIEW-010): best-effort UnregisterNodes for the union of live aliases + the pending
  /// batch, then clears. Failures are advisory. @p cb fires on the executor.
  void drain_async(std::function<void()> cb);

private:
  AddressSpaceCache(boost::asio::strand<boost::asio::any_io_executor> strand, std::weak_ptr<WireOps> wireOps,
    AddressSpaceCachePolicy policy, ua::Logger logger);

  friend struct AddressSpaceCacheTestAccess;

  // --- on-strand helpers ---
  void queue_unregister(const ua::NodeId& node);  // append to the batch + flush-on-threshold / arm timer
  void arm_unregister_timer();
  void flush_unregister_batch();  // issue one UnregisterNodes for the pending batch (weak-lock the interface)
  void issue_unregister(std::vector<ua::NodeId> nodes);
  void invalidate_node(const ua::NodeId& node);  // drop from every sub-cache (no UnregisterNodes)
  void remove_browse_entries_for_node(const ua::NodeId& node);  // drop browse entries starting at node

  // Adapts a user completion so it fires on the executor (off the strand) and satisfies the
  // completion-owning `post_borrowing` overload (which delivers a VoidResult on both the alive and the
  // cache-gone path, so the owed callback fires exactly once).
  [[nodiscard]] std::function<void(ua::VoidResult)> on_executor(std::function<void(ua::VoidResult)> cb) const;
  [[nodiscard]] std::function<void(ua::VoidResult)> on_executor(std::function<void()> cb) const;

  // mStrand is declared first so mExecutor can be initialised from its inner executor (section 8.7: the cache
  // never fabricates its own strand  -  this is ConnectionImpl's, injected at construction).
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  boost::asio::any_io_executor mExecutor;
  std::weak_ptr<WireOps> mWireOps;
  AddressSpaceCachePolicy mPolicy;
  ua::Logger mLogger;

  // The sub-caches are `mutable` so the const lookup methods can reorder (LRU) / drop a TTL-expired entry.
  mutable ua::LruMap<ua::NodeId, AliasEntry> mAliasCache;
  mutable ua::LruMap<ua::NodeId, AttributeEntry> mAttributeCache;
  mutable ua::LruMap<CachedBrowseKey, BrowseEntry, CachedBrowseKeyHash> mBrowseCache;
  std::vector<ua::NodeId> mPendingUnregisterBatch;
  boost::asio::steady_timer mPendingUnregisterTimer;
  std::uint64_t mSessionGeneration = 0;
};

}  // namespace ua::client::detail

#endif  // UA_ADDRESS_SPACE_CACHE_H
