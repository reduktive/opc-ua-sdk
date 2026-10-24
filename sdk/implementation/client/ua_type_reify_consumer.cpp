// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_type_reify_consumer.h"

#include "ua_array.h"
#include "ua_callback_safety.h"
#include "ua_namespace_table.h"
#include "ua_ref_structure.h"
#include "ua_structure.h"
#include "ua_structure_factory.h"
#include "ua_type_registry.h"
#include "ua_type_resolver.h"
#include "ua_unknown_structure.h"
#include "ua_variant.h"

#include <atomic>
#include <memory>
#include <unordered_set>
#include <utility>

namespace ua::client::detail
{

namespace
{

/// @return The contained value as an @ref UnknownStructure placeholder, or nullptr if @p candidate is a
///         concrete (already-resolved) structure.
const ua::UnknownStructure* as_unknown(const ua::Structure& candidate)
{
  return dynamic_cast<const ua::UnknownStructure*>(&candidate);
}

/// Builds the core @ref ua::StructureResolver the in-place re-decode consults: clone the registry's decode
/// prototype for the encoding, or nullptr when unknown / prototype-less (server-discovered types install a
/// null decoder this slice, so they correctly stay opaque  -  CL-ADDRSP-013 / Slice T1(b)).
ua::StructureResolver make_registry_resolver(std::shared_ptr<const TypeRegistry> registry)
{
  return [registry = std::move(registry)](const ua::NodeId& encoding) -> std::unique_ptr<ua::Structure>
  {
    if (!registry)
    {
      return nullptr;
    }
    const StructureType* entry = registry->find_by_encoding(encoding);
    return entry != nullptr && entry->decoder ? entry->decoder->clone() : nullptr;
  };
}

/// The owned state of one in-flight reify operation (the async continuation state). Held by `shared_ptr`
/// and captured strong by each resolve completion, so the operation's state outlives the fan-out barrier.
struct ReifyJob
{
  std::vector<ua::Variant*> values;  ///< delivery-stable pointers into caller-owned storage
  std::shared_ptr<ReifySupport> support;  ///< the resolution interface (non-null on this path)
  ua::EncodingLimits limits;  ///< re-decode limits
  std::function<void()> deliver;  ///< the user-delivery continuation; invoked exactly once
  std::atomic<std::size_t> remaining{0};  ///< resolve-barrier counter (last to zero finalizes)
};

/// Runs the bounded in-place re-decode over every Variant, then delivers. Reached only after the resolve
/// barrier has drained, so `registry()` is the post-resolution snapshot. A zero re-decode budget skips the
/// pass entirely and delivers the placeholders as they arrived.
void finalize_job(const std::shared_ptr<ReifyJob>& job)
{
  // The delivery is the one thing this function owes the caller. It is taken out first and fired
  // last, outside every try: a value that cannot be re-decoded (a malformed body from a hostile
  // server, a throwing prototype) leaves that value opaque and the read, call or notification is
  // still delivered exactly once (the guaranteed-delivery invariant).
  auto deliver = std::exchange(job->deliver, nullptr);
  bool redecode = false;
  try
  {
    redecode = job->support->may_redecode(0);
  }
  catch (...)
  {
    redecode = false;
  }
  if (redecode)
  {
    ua::StructureResolver resolver;
    try
    {
      resolver = make_registry_resolver(job->support->registry());
    }
    catch (...)
    {
      resolver = nullptr;
    }
    if (resolver)
    {
      for (ua::Variant* value : job->values)
      {
        // Idempotent + leaves still-opaque results in place: a resolve that failed keeps that type opaque
        // and the read/call STILL succeeds (best-effort reify  -  never turn a resolution failure into a
        // failed read). The per-encoding resolution ErrorDetail is not surfaced on this path by design
        // (the value is delivered, not dropped); logging the resolution failure reason belongs at the
        // resolver boundary (batched follow-up).
        try
        {
          ua::decode_unknowns_in_place(*value, resolver, job->limits);
        }
        catch (...)
        {
          // This value stays opaque; the others are still tried.
          ::ua::detail::ignore_expected_exception();
        }
      }
    }
  }
  if (deliver)
  {
    deliver();
  }
}

}  // namespace

ResolverReifySupport::ResolverReifySupport(std::shared_ptr<TypeResolver> resolver,
  std::shared_ptr<const ua::client::NamespaceTable> namespaces, bool waitForResolution) noexcept
  : mResolver(std::move(resolver)), mNamespaces(std::move(namespaces)), mWaitForResolution(waitForResolution)
{}

DeferDecision ResolverReifySupport::classify(std::size_t distinctUnresolvedCount) const noexcept
{
  return mResolver->classify_message(MessageClass::ApplicationData, distinctUnresolvedCount);
}

bool ResolverReifySupport::wait_for_resolution() const noexcept
{
  return mWaitForResolution;
}

bool ResolverReifySupport::may_redecode(std::size_t passIndex) const noexcept
{
  return mResolver->may_redecode(passIndex);
}

void ResolverReifySupport::resolve_async(ua::NodeId encodingId, std::function<void(ua::VoidResult)> done)
{
  mResolver->resolve_async(std::move(encodingId), mNamespaces, std::move(done));
}

std::shared_ptr<const TypeRegistry> ResolverReifySupport::registry() const
{
  return mResolver->registry();
}

bool variant_has_unknown_structure(const ua::Variant& value)
{
  if (value.is_structure())
  {
    return as_unknown(value.as<ua::Structure>()) != nullptr;
  }
  if (value.is_array_of_structure())
  {
    const auto& array = value.as<ua::Array<ua::RefStructure<ua::Structure>>>();
    for (const auto& reference : array.payload())
    {
      if (reference && as_unknown(*reference) != nullptr)
      {
        return true;
      }
    }
  }
  return false;
}

void collect_unknown_encodings(const ua::Variant& value, std::unordered_set<ua::NodeId>& out)
{
  if (value.is_structure())
  {
    if (const ua::UnknownStructure* unknown = as_unknown(value.as<ua::Structure>()))
    {
      out.insert(
        unknown->encoding_id());  // O(1) dedup  -  a hostile all-distinct array must not go quadratic
    }
    return;
  }
  if (value.is_array_of_structure())
  {
    const auto& array = value.as<ua::Array<ua::RefStructure<ua::Structure>>>();
    for (const auto& reference : array.payload())
    {
      if (!reference)
      {
        continue;
      }
      if (const ua::UnknownStructure* unknown = as_unknown(*reference))
      {
        out.insert(unknown->encoding_id());
      }
    }
  }
}

void reify_and_deliver(std::vector<ua::Variant*> values, std::shared_ptr<ReifySupport> support,
  ua::EncodingLimits limits, std::function<void()> deliver)
{
  // FAST PATH (must short-circuit): a scan with no allocation and no `support` access. The overwhelmingly
  // common case is a response with no opaque structure  -  deliver immediately, zero added latency.
  bool anyUnknown = false;
  for (const ua::Variant* value : values)
  {
    if (value != nullptr && variant_has_unknown_structure(*value))
    {
      anyUnknown = true;
      break;
    }
  }
  if (!anyUnknown)
  {
    deliver();
    return;
  }

  // Resolver gone (the Connection is being torn down): deliver the values un-reified  -  never drop the data.
  if (!support)
  {
    deliver();
    return;
  }

  // Collect the DISTINCT unknown encodings across every Variant. A hash set (O(1) insert/dedup), NOT a
  // linear-scanned vector: the encoding ids are attacker-controlled and one Variant can be an array of up to
  // MaxArrayLength placeholders, so an O(N) dedup per element would be O(N^2)  -  a remote CPU-amplification
  // DoS on the shared executor thread that runs BEFORE the budget gate can reject the message (section 3.1).
  std::unordered_set<ua::NodeId> distinct;
  for (const ua::Variant* value : values)
  {
    if (value != nullptr)
    {
      collect_unknown_encodings(*value, distinct);
    }
  }

  // Gate (section 9.2): only application-data WITHIN budget defers. Over budget / not eligible -> deliver
  // AS-IS (placeholders preserved), never reify.
  if (support->classify(distinct.size()) != DeferDecision::Defer)
  {
    deliver();
    return;
  }

  // Non-blocking delivery: hand the caller its placeholders now and resolve in the background, so the cost
  // of discovering a type is paid once and a later read of it finds a warm registry. THIS operation's values
  // stay opaque - the caller asked not to wait for them - so nothing may reference `values` afterwards.
  if (!support->wait_for_resolution())
  {
    for (const ua::NodeId& encoding : distinct)
    {
      support->resolve_async(encoding, [](ua::VoidResult) {});
    }
    deliver();  // last: it may free the storage behind `values` and run user code
    return;
  }

  auto job = std::make_shared<ReifyJob>();
  job->values = std::move(values);
  job->support = std::move(support);
  job->limits = std::move(limits);
  job->deliver = std::move(deliver);
  // Pre-set the barrier to the full count BEFORE dispatching any resolve so an inline/early completion can
  // never reach zero prematurely; the completion that drives it to zero (whenever it lands) finalizes.
  job->remaining.store(distinct.size(), std::memory_order_relaxed);

  for (const ua::NodeId& encoding : distinct)
  {
    // Strong-capture the job: it IS this operation's owned continuation state, so it must outlive the
    // fan-out. A resolve failure is NON-FATAL  -  the barrier still drains and the type stays opaque.
    job->support->resolve_async(encoding,
      [job](ua::VoidResult) mutable
      {
        if (job->remaining.fetch_sub(1, std::memory_order_acq_rel) == 1)
        {
          finalize_job(job);
        }
      });
  }
}

}  // namespace ua::client::detail
