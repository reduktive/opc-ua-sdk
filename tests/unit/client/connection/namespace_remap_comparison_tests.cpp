// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief `compare_namespace_tables` - the NamespaceArray remap detection behind
///        `ConnectionObserver::on_namespace_remap` (CL-ADDRSP-004).
///
/// The hook is public and its contract is specific: it "fires only when the array contents actually
/// changed, so persisted-NodeId consumers can re-anchor". It had never fired. `ObserverSink::
/// fire_namespace_remap` forwarded correctly to every registered observer, and its ONLY caller in the
/// repository was a test - nothing in production called it, and nothing computed `sizeChanged` or
/// `indexShifted`, which appeared nowhere but the sink's own signature.
///
/// That is worse than a missing notification. A NodeId encodes a namespace INDEX, not a URI. A client
/// that persists NodeIds and reconnects to a server whose array has changed will use index N to mean
/// whatever now sits at N - reading and writing the wrong nodes, with no error anywhere. `indexShifted`
/// is the flag that says "your persisted identifiers are no longer valid".
///
/// These pin the comparison itself. Each case is one the notification must distinguish, and each would
/// pass silently under a naive implementation that only compared sizes.

#include "ua_connection_impl.h"
#include "ua_namespace_table.h"
#include "ua_namespace_uri.h"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

namespace
{

using ua::client::NamespaceTable;
using ua::client::detail::compare_namespace_tables;

/// A snapshot with NS0 at index 0 (which `create` requires) followed by @p rest, in order.
std::shared_ptr<const NamespaceTable> table(std::vector<std::string> rest, std::uint64_t generation = 1)
{
  std::vector<std::string> uris{std::string{ua::specNamespaceUri}};
  uris.insert(uris.end(), rest.begin(), rest.end());
  return NamespaceTable::create(std::move(uris), std::nullopt, generation).value();
}

}  // namespace

TEST(NamespaceRemapComparison, BootstrapIsNotARemap)
{
  // The first table replaces nothing, so there is no change to report. Firing here would tell every
  // observer to re-anchor on a perfectly ordinary connect.
  const auto remap = compare_namespace_tables(nullptr, table({"urn:a", "urn:b"}));
  EXPECT_FALSE(remap.contentsChanged);
  EXPECT_FALSE(remap.sizeChanged);
  EXPECT_FALSE(remap.indexShifted);
}

TEST(NamespaceRemapComparison, IdenticalTableIsNotARemap)
{
  // The common reconnect case: the server's array is unchanged. The contract says the hook fires ONLY
  // on a real change, so a reconnect against a stable server must be silent.
  const auto remap = compare_namespace_tables(table({"urn:a", "urn:b"}), table({"urn:a", "urn:b"}, 2));
  EXPECT_FALSE(remap.contentsChanged);
  EXPECT_FALSE(remap.sizeChanged);
  EXPECT_FALSE(remap.indexShifted);
}

TEST(NamespaceRemapComparison, AppendedNamespaceChangesSizeWithoutShiftingAnyIndex)
{
  // A server that ADDS a namespace at the end leaves every existing index intact, so persisted NodeIds
  // remain valid. Reporting indexShifted here would send consumers re-anchoring for nothing.
  const auto remap = compare_namespace_tables(table({"urn:a"}), table({"urn:a", "urn:b"}, 2));
  EXPECT_TRUE(remap.contentsChanged);
  EXPECT_TRUE(remap.sizeChanged);
  EXPECT_FALSE(remap.indexShifted) << "appending must not be reported as a shift";
}

TEST(NamespaceRemapComparison, UriMovedToAnotherIndexIsAShift)
{
  // THE case the hook exists for. Both URIs are still present and the size is unchanged, so a
  // size-only comparison sees nothing - yet every persisted NodeId carrying index 1 or 2 now names a
  // different namespace.
  const auto remap = compare_namespace_tables(table({"urn:a", "urn:b"}), table({"urn:b", "urn:a"}, 2));
  EXPECT_TRUE(remap.contentsChanged);
  EXPECT_FALSE(remap.sizeChanged) << "the array is the same length; only the order changed";
  EXPECT_TRUE(remap.indexShifted) << "a URI present in both tables at a DIFFERENT index is the hazard";
}

TEST(NamespaceRemapComparison, InsertionShiftsEverythingAfterIt)
{
  // Inserting at index 1 pushes every later namespace along by one - the shape the reconnect
  // re-read produces when a server registers a new namespace ahead of existing ones.
  const auto remap =
    compare_namespace_tables(table({"urn:a", "urn:b"}), table({"urn:new", "urn:a", "urn:b"}, 2));
  EXPECT_TRUE(remap.contentsChanged);
  EXPECT_TRUE(remap.sizeChanged);
  EXPECT_TRUE(remap.indexShifted);
}

TEST(NamespaceRemapComparison, DroppedUriIsAContentChangeButNotAShift)
{
  // A URI that is GONE cannot have moved. Persisted NodeIds naming it are invalid either way, but the
  // distinction matters to a consumer deciding whether to re-anchor or to give up on those ids.
  const auto remap = compare_namespace_tables(table({"urn:a", "urn:b"}), table({"urn:a"}, 2));
  EXPECT_TRUE(remap.contentsChanged);
  EXPECT_TRUE(remap.sizeChanged);
  EXPECT_FALSE(remap.indexShifted) << "urn:b is absent from the new table, so nothing moved";
}
