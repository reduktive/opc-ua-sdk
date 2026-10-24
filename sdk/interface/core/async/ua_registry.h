// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REGISTRY_H
#define UA_REGISTRY_H

/// @file
/// @brief Generic thread-safe registry of long-lived shared components keyed by id.
/// @ingroup async

// Generic registry template for long-lived components: a shared_mutex-guarded
// wrapper around std::unordered_map<Id, std::shared_ptr<T>> with insert /
// lookup / remove /
// enumerate and no other behaviour. Domain logic (eviction policy, telemetry,
// dispatch) belongs on the layer that holds the registry alias, never on the
// registry itself; per-component subclassing is not used.

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ua::async
{

/// A thread-safe registry of long-lived shared components keyed by id.
///
/// Wraps a `std::unordered_map<Id, std::shared_ptr<T>>` behind a
/// `std::shared_mutex`, offering only insert / lookup / remove / enumerate. It
/// is the canonical container for long-lived components. Domain logic
/// (eviction policy, telemetry, dispatch) belongs on the layer that owns the
/// registry, never on the registry itself; per-component subclassing is not
/// used.
///
/// All member functions are safe to call concurrently from any thread:
/// mutating operations take a unique lock and lookups/enumeration take a shared
/// lock. Entries are held by `shared_ptr`, so a value obtained from @ref lookup
/// or @ref enumerate stays alive even after it is removed from the registry.
///
/// @tparam Id Key type. Must be hashable (`std::hash<Id>`) and equality-comparable.
/// @tparam T  Mapped component type; stored and handed out as `std::shared_ptr<T>`.
/// @ingroup async
template<class Id, class T>
class Registry
{
public:
  /// Constructs an empty registry.
  Registry() = default;

  Registry(const Registry&) = delete;
  Registry& operator=(const Registry&) = delete;
  Registry(Registry&&) = delete;
  Registry& operator=(Registry&&) = delete;

  /// Inserts an entry under @p id unless @p id is already present.
  ///
  /// Mirrors `std::unordered_map::try_emplace`: if @p id was absent, @p entry is
  /// stored; if @p id was already present, the existing entry is kept and
  /// @p entry is discarded. Detect a collision by comparing the returned
  /// pointer against the one passed in - they are equal only on a fresh insert.
  ///
  /// @param id    Key to insert under; moved from.
  /// @param entry Component to store; moved from. Discarded on collision.
  /// @return The entry stored at @p id after the call - the just-inserted
  ///         @p entry on success, or the pre-existing entry on collision.
  std::shared_ptr<T> insert(Id id, std::shared_ptr<T> entry)
  {
    std::unique_lock lock(mMutex);
    auto [it, inserted] = mEntries.try_emplace(std::move(id), std::move(entry));
    return it->second;
  }

  /// Returns the entry stored at @p id, or `nullptr` if absent.
  ///
  /// The returned `shared_ptr` shares ownership and keeps the entry alive
  /// independent of subsequent @ref remove calls.
  ///
  /// @param id Key to look up.
  /// @return The entry stored at @p id, or `nullptr` if none is present.
  std::shared_ptr<T> lookup(const Id& id) const
  {
    std::shared_lock lock(mMutex);
    auto it = mEntries.find(id);
    return it == mEntries.end() ? nullptr : it->second;
  }

  /// Removes the entry at @p id; a no-op if @p id is absent.
  ///
  /// Any outstanding `shared_ptr` from @ref lookup or @ref enumerate keeps the
  /// removed entry alive until it too is released.
  ///
  /// @param id Key whose entry to remove.
  void remove(const Id& id)
  {
    std::unique_lock lock(mMutex);
    mEntries.erase(id);
  }

  /// Returns a snapshot of all entries in unspecified order.
  ///
  /// The returned vector shares ownership of each entry, so callers may iterate
  /// it without holding any lock on the registry; entries removed after the
  /// snapshot is taken remain valid through it.
  ///
  /// @return Every entry present at the moment the snapshot was taken.
  std::vector<std::shared_ptr<T>> enumerate() const
  {
    std::shared_lock lock(mMutex);
    std::vector<std::shared_ptr<T>> snapshot;
    snapshot.reserve(mEntries.size());
    for (const auto& [_, entry] : mEntries)
      snapshot.push_back(entry);
    return snapshot;
  }

private:
  mutable std::shared_mutex mMutex;
  std::unordered_map<Id, std::shared_ptr<T>> mEntries;
};

}  // namespace ua::async

#endif  // UA_REGISTRY_H
