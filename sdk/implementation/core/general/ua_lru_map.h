// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_LRU_MAP_H
#define UA_LRU_MAP_H

/// @file
/// @brief A small, header-only least-recently-used (LRU) map: a capacity-bounded key/value store that
///        evicts the least-recently-used entry when it would exceed its capacity.
/// @ingroup core

#include <cstddef>
#include <functional>
#include <list>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ua
{

/// A capacity-bounded key/value store that evicts the least-recently-used entry on overflow.
///
/// Backed by a `std::list` (most-recently-used at the front) plus a `std::unordered_map` from key to list
/// node, so lookup, insert, and eviction are all amortised O(1). @ref get and @ref put move the touched
/// entry to the front; @ref peek does not reorder (a read that must not count as a use). @ref put returns
/// the entry it evicted (if any) so a caller can react to the eviction (e.g. queue a resource release).
///
/// This container is not thread-safe: a caller that shares one across threads must serialise access
/// externally (the SDK's strand-serialised components do exactly this).
///
/// @tparam Key      The key type (must be hashable by @p Hash and comparable by @p KeyEqual).
/// @tparam Value    The mapped value type.
/// @tparam Hash     The key hash (defaults to `std::hash<Key>`).
/// @tparam KeyEqual The key equality (defaults to `std::equal_to<Key>`).
template<class Key, class Value, class Hash = std::hash<Key>, class KeyEqual = std::equal_to<Key>>
class LruMap
{
public:
  /// One stored entry: its key and mapped value.
  using Entry = std::pair<Key, Value>;

  /// Constructs an LRU map bounded to at most @p capacity entries.
  ///
  /// @param capacity The maximum number of entries retained; the least-recently-used entry is evicted
  ///                 when an insert would exceed it. A capacity of 0 means every inserted entry is
  ///                 immediately evicted (a degenerate but well-defined pass-through).
  explicit LruMap(std::size_t capacity) : mCapacity(capacity)
  {}

  /// @return The number of entries currently held.
  [[nodiscard]] std::size_t size() const noexcept
  {
    return mIndex.size();
  }

  /// @return True iff no entries are held.
  [[nodiscard]] bool empty() const noexcept
  {
    return mIndex.empty();
  }

  /// @return The maximum number of entries retained before eviction.
  [[nodiscard]] std::size_t capacity() const noexcept
  {
    return mCapacity;
  }

  /// @param key The key to test.
  /// @return True iff @p key is present. Does not reorder.
  [[nodiscard]] bool contains(const Key& key) const
  {
    return mIndex.find(key) != mIndex.end();
  }

  /// Looks up @p key, promoting it to most-recently-used on a hit.
  ///
  /// @param key The key to look up.
  /// @return A pointer to the mapped value (valid until the next mutating call), or `nullptr` on a miss.
  [[nodiscard]] Value* get(const Key& key)
  {
    auto found = mIndex.find(key);
    if (found == mIndex.end())
    {
      return nullptr;
    }
    mEntries.splice(mEntries.begin(), mEntries, found->second);
    return &found->second->second;
  }

  /// Looks up @p key WITHOUT reordering (a read that must not count as a use, e.g. a TTL probe).
  ///
  /// @param key The key to look up.
  /// @return A pointer to the mapped value, or `nullptr` on a miss.
  [[nodiscard]] const Value* peek(const Key& key) const
  {
    auto found = mIndex.find(key);
    if (found == mIndex.end())
    {
      return nullptr;
    }
    return &found->second->second;
  }

  /// Inserts or updates @p key with @p value, promoting it to most-recently-used.
  ///
  /// @param key   The key to insert or update.
  /// @param value The value to store.
  /// @return The entry evicted to make room (the least-recently-used), or `std::nullopt` if none was.
  std::optional<Entry> put(Key key, Value value)
  {
    auto found = mIndex.find(key);
    if (found != mIndex.end())
    {
      found->second->second = std::move(value);
      mEntries.splice(mEntries.begin(), mEntries, found->second);
      return std::nullopt;
    }
    mEntries.emplace_front(key, std::move(value));
    mIndex.emplace(std::move(key), mEntries.begin());
    if (mIndex.size() <= mCapacity)
    {
      return std::nullopt;
    }
    Entry evicted = std::move(mEntries.back());
    mIndex.erase(evicted.first);
    mEntries.pop_back();
    return evicted;
  }

  /// Removes @p key if present.
  ///
  /// @param key The key to remove.
  /// @return True iff an entry was removed.
  bool erase(const Key& key)
  {
    auto found = mIndex.find(key);
    if (found == mIndex.end())
    {
      return false;
    }
    mEntries.erase(found->second);
    mIndex.erase(found);
    return true;
  }

  /// Removes every entry.
  void clear() noexcept
  {
    mEntries.clear();
    mIndex.clear();
  }

  /// @return A snapshot of every currently-held key, most-recently-used first.
  [[nodiscard]] std::vector<Key> keys() const
  {
    std::vector<Key> result;
    result.reserve(mEntries.size());
    for (const auto& entry : mEntries)
    {
      result.push_back(entry.first);
    }
    return result;
  }

  /// Invokes @p visitor for every entry (order unspecified). @p visitor receives `(const Key&, Value&)`.
  ///
  /// @tparam Visitor A callable `void(const Key&, Value&)`.
  /// @param visitor The per-entry visitor; may mutate the mapped value (not the key or the ordering).
  template<class Visitor>
  void for_each(Visitor&& visitor)
  {
    for (auto& entry : mEntries)
    {
      visitor(entry.first, entry.second);
    }
  }

private:
  std::size_t mCapacity;
  // Most-recently-used at the front; the back is the eviction victim.
  std::list<Entry> mEntries;
  std::unordered_map<Key, typename std::list<Entry>::iterator, Hash, KeyEqual> mIndex;
};

}  // namespace ua

#endif  // UA_LRU_MAP_H
