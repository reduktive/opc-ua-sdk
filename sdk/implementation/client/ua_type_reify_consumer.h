// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TYPE_REIFY_CONSUMER_H
#define UA_TYPE_REIFY_CONSUMER_H

/// @file
/// @brief The gated-lazy application-data reify consumer (client design section 9.2 / Slice T1 Phase A2).
///
/// The wire decoder leaves a structured value whose encoding it cannot resolve as a @ref
/// ua::UnknownStructure placeholder that preserves the raw body. This consumer runs a **post-decode**
/// reify pass over already-decoded APPLICATION-DATA Variants (Read values, Call outputs) and upgrades each
/// resolvable placeholder to its concrete typed @ref ua::Structure using the per-Connection @ref
/// ua::client::detail::TypeResolver's @ref TypeRegistry. It is deliberately confined to application data  -
/// it never touches the secure-channel handshake / security-body decode path (section 9.2 eligibility
/// boundary).
///
/// The orchestration is a free function over a small @ref ReifySupport interface so it is unit-testable
/// without a live wire: a unit test supplies a fake support; production wraps the real resolver with @ref
/// ResolverReifySupport.
/// @ingroup client

#include "ua_encoding_limits.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_type_defer_gate.h"

#include <cstddef>
#include <functional>
#include <memory>
#include <unordered_set>
#include <vector>

namespace ua
{
class Variant;
}  // namespace ua

namespace ua::client
{
class NamespaceTable;
}  // namespace ua::client

namespace ua::client::detail
{

class TypeResolver;
class TypeRegistry;

/// The minimal resolution surface the reify consumer depends on (client design section 9.2).
///
/// An interface so the gated-lazy orchestration is unit-testable without a live wire / a real @ref
/// TypeResolver. Production supplies @ref ResolverReifySupport (forwards to the resolver); a unit test
/// supplies a fake.
class ReifySupport
{
public:
  virtual ~ReifySupport() = default;

  /// The decode-and-defer gate for an APPLICATION-DATA message carrying @p distinctUnresolvedCount distinct
  /// unknown encodings. `Defer` -> resolve + reify; `Placeholder` / `StrictFail` -> deliver as-is.
  [[nodiscard]] virtual DeferDecision classify(std::size_t distinctUnresolvedCount) const noexcept = 0;

  /// Drives resolution of one encoding. @p done fires (on the Connection executor) once resolution settles.
  /// A Bad @p done is NON-FATAL to the reify pass: the type stays opaque, the read/call still succeeds.
  virtual void resolve_async(ua::NodeId encodingId, std::function<void(ua::VoidResult)> done) = 0;

  /// Whether delivery WAITS for every distinct unknown encoding to settle before reifying
  /// (`TypeResolutionPolicy::tier2WaitForResolution`). False delivers the placeholders immediately and
  /// resolves in the background, so a later read of the same type finds a warm registry.
  [[nodiscard]] virtual bool wait_for_resolution() const noexcept = 0;

  /// Whether the in-place re-decode pass at zero-based @p passIndex is within
  /// `TypeDeferPolicy::maxReDecodePasses`. A budget of zero permits no pass, so a resolved placeholder is
  /// delivered opaque rather than upgraded.
  [[nodiscard]] virtual bool may_redecode(std::size_t passIndex) const noexcept = 0;

  /// The current immutable registry snapshot, loaded AFTER resolution, used to build the reify resolver.
  [[nodiscard]] virtual std::shared_ptr<const TypeRegistry> registry() const = 0;

protected:
  ReifySupport() = default;
  ReifySupport(const ReifySupport&) = default;
  ReifySupport& operator=(const ReifySupport&) = default;
  ReifySupport(ReifySupport&&) = default;
  ReifySupport& operator=(ReifySupport&&) = default;
};

/// Production @ref ReifySupport: forwards to a live @ref TypeResolver against a fixed NamespaceTable
/// snapshot. Holds the resolver by `shared_ptr` for the duration of one reify job, so an in-flight
/// resolution cannot outlive its resolver (section 9.8.3).
class ResolverReifySupport : public ReifySupport
{
public:
  /// @param resolver           The live resolver this support forwards to.
  /// @param namespaces         The NamespaceTable snapshot resolution runs against.
  /// @param waitForResolution  Whether delivery blocks on resolution. A tier-2 typed read passes the
  ///                           Connection's `TypeResolutionPolicy::tier2WaitForResolution`; the tier-1
  ///                           MonitoredItem delivery path always passes true, because its contract is to
  ///                           hand the subscriber a value that has already had its one re-decode pass.
  ResolverReifySupport(std::shared_ptr<TypeResolver> resolver,
    std::shared_ptr<const ua::client::NamespaceTable> namespaces, bool waitForResolution) noexcept;

  [[nodiscard]] DeferDecision classify(std::size_t distinctUnresolvedCount) const noexcept override;
  void resolve_async(ua::NodeId encodingId, std::function<void(ua::VoidResult)> done) override;
  [[nodiscard]] bool wait_for_resolution() const noexcept override;
  [[nodiscard]] bool may_redecode(std::size_t passIndex) const noexcept override;
  [[nodiscard]] std::shared_ptr<const TypeRegistry> registry() const override;

private:
  std::shared_ptr<TypeResolver> mResolver;
  std::shared_ptr<const ua::client::NamespaceTable> mNamespaces;
  bool mWaitForResolution;
};

/// @return true iff @p value holds (as a scalar, or as any element of a structure array) at least one
///         @ref ua::UnknownStructure placeholder. Pure, allocation-free  -  the reify fast-path predicate.
[[nodiscard]] bool variant_has_unknown_structure(const ua::Variant& value);

/// Inserts the DISTINCT unresolved encoding NodeIds carried by @p value's placeholders into @p out (an
/// unordered_set for O(1) dedup  -  the encoding ids are attacker-controlled and an array Variant may carry
/// up to MaxArrayLength placeholders, so a linear-scan dedup would be quadratic; section 3.1). Handles both a
/// scalar structure and an array of structures.
void collect_unknown_encodings(const ua::Variant& value, std::unordered_set<ua::NodeId>& out);

/// Runs the gated-lazy reify pass over @p values, then invokes @p deliver EXACTLY ONCE.
///
/// @p values are raw pointers into caller-owned storage that MUST stay valid (and stable) until @p deliver
/// runs  -  the caller keeps that storage alive by capturing it in @p deliver.
///
/// Paths (all invoke @p deliver exactly once):
///  - **Fast path**: no placeholder in any Variant -> deliver immediately, zero @p support interaction.
///  - **Resolver gone**: @p support is null -> deliver the values un-reified (never dropped).
///  - **Gated skip**: @p support->classify(...) is not `Defer` (over budget) -> deliver as-is.
///  - **Non-blocking**: @p support->wait_for_resolution() is false -> start resolution for every distinct
///    encoding, then deliver the placeholders without waiting. These values stay opaque; the warmed registry
///    serves the next read of the same type.
///  - **Resolve then reify**: resolve every distinct encoding (barrier), rebuild the resolver from the
///    updated registry, run the re-decode pass in place, then deliver. A failed resolve leaves that type
///    opaque and never fails the whole operation, and a zero re-decode budget skips the pass altogether.
///
/// @param values   Pointers to the Variants to reify in place (delivery-stable, caller-owned).
/// @param support  The resolution interface (may be null: resolver gone -> deliver un-reified).
/// @param limits   Encoding limits applied during each in-place re-decode.
/// @param deliver  The user-delivery continuation; co-owns @p values' backing storage; invoked once.
void reify_and_deliver(std::vector<ua::Variant*> values, std::shared_ptr<ReifySupport> support,
  ua::EncodingLimits limits, std::function<void()> deliver);

}  // namespace ua::client::detail

#endif  // UA_TYPE_REIFY_CONSUMER_H
