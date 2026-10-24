// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_model_change_step.h"

#include "ua_address_space_impl.h"
#include "ua_callback_safety.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_node_accessor.h"
#include "ua_node_accessor_route.h"
#include "ua_qualified_name.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_request_info.h"

#include <algorithm>
#include <optional>
#include <unordered_set>
#include <utility>

namespace ua::detail
{

namespace
{

// The closing caller's continuation, which does not throw into the step.
void run(std::function<void()>& done) noexcept
{
  if (!done)
  {
    return;
  }
  try
  {
    done();
  }
  catch (...)
  {
    ignore_expected_exception();
  }
}

uint8_t node_added() noexcept
{
  return static_cast<uint8_t>(static_cast<int32_t>(ModelChangeStructureVerbMask::NodeAdded));
}

// The check of the Nodes an operation created that their namespaces reported as versioned (NR-63 rule 2),
// made once every Reference of the operation is in place: a created Node is listed only when it then holds a
// NodeVersion of its own, a HasProperty target of its namespace named 0:NodeVersion with no HasModellingRule
// (NR-36 rule 2). During the operation such a Property can be reported before the HasModellingRule that makes
// it an InstanceDeclaration arrives in a later call. A Node the check cannot decide, because a lookup or a
// read of References failed, stays listed as its namespace reported it.
struct CreatedCheck
{
  weak_ptr<AddressSpaceImpl> space;
  shared_ptr<AddressSpaceImpl::PostedSteps> posted;
  Logger logger;
  AddressSpaceChange change;
  std::function<void()> done;
  /// The created Nodes, each listed with NodeAdded.
  std::vector<NodeId> created;

  std::mutex mutex;
  /// Per created Node, its HasProperty targets of its own namespace.
  std::vector<std::vector<NodeId>> properties;
  /// Per created Node, whether it stays listed.
  std::vector<bool> kept;
  /// The reads not yet answered, and one held by the loop that starts them.
  std::size_t remaining{0};
};

void keep_every_created(CreatedCheck& check) noexcept
{
  const std::lock_guard lock{check.mutex};
  std::fill(check.kept.begin(), check.kept.end(), true);
}

// Drops the created Nodes the check did not keep, raises what remains, then ends the counted step.
void finish_check(const shared_ptr<CreatedCheck>& check) noexcept
{
  try
  {
    std::unordered_set<NodeId> dropped;
    for (std::size_t i = 0; i < check->created.size(); ++i)
    {
      if (!check->kept[i])
      {
        dropped.insert(check->created[i]);
      }
    }
    std::erase_if(check->change.changes,
      [&dropped](const ModelChangeEntry& entry) { return dropped.contains(entry.affected); });
  }
  catch (...)
  {
    // Nothing is dropped: every Node is listed as its namespace reported it.
    ignore_expected_exception();
  }
  const auto space = check->space.lock();
  if (space && (!check->change.changes.empty() || check->change.unspecified))
  {
    space->raise_model_change(std::move(check->change), std::move(check->done));
  }
  else
  {
    // No Node remains to list, or the address space is gone.
    run(check->done);
  }
  check->posted->finish(check->logger);
}

// Ends one read of a stage; the last runs @p next.
void read_ended(const shared_ptr<CreatedCheck>& check, void (*next)(const shared_ptr<CreatedCheck>&)) noexcept
{
  bool last = false;
  {
    const std::lock_guard lock{check->mutex};
    last = --check->remaining == 0;
  }
  if (last)
  {
    next(check);
  }
}

// Stage 3: whether each created Node's NodeVersion Properties carry a HasModellingRule.
void read_declarations(const shared_ptr<CreatedCheck>& check, const std::vector<std::size_t>& owners,
  BatchResult<NodeAccessorResult> found) noexcept
{
  {
    const std::lock_guard lock{check->mutex};
    check->remaining = 1;
  }
  try
  {
    if (found.batchStatus.is_bad() || found.items.size() != owners.size())
    {
      keep_every_created(*check);
      read_ended(check, finish_check);
      return;
    }
    const QualifiedName nodeVersion{0, "NodeVersion"};
    for (std::size_t k = 0; k < owners.size(); ++k)
    {
      const std::size_t owner = owners[k];
      try
      {
        // A Property that cannot be looked up, or whose lookup is Uncertain, is tolerated: its owner stays
        // listed as its namespace reported it, so the check removes only a listing it has confirmed.
        if (!found.items[k].is_good())
        {
          const std::lock_guard lock{check->mutex};
          check->kept[owner] = true;
          continue;
        }
        const NodeAccessor property = std::move(found.items[k]).value();
        if (property.get_browse_name() != nodeVersion)
        {
          continue;
        }
        {
          const std::lock_guard lock{check->mutex};
          ++check->remaining;
        }
        property.get_references_async(
          [check, owner](NodeAccessor::ReferencesResult read)
          {
            const NodeId hasModellingRule{ReferenceTypeId::HasModellingRule};
            bool declaration = false;
            if (read.is_good())
            {
              for (const Reference& reference : read.value())
              {
                declaration =
                  declaration || (reference.is_forward() && reference.type_id() == hasModellingRule);
              }
            }
            {
              const std::lock_guard lock{check->mutex};
              if (read.is_bad() || !declaration)
              {
                check->kept[owner] = true;
              }
            }
            read_ended(check, finish_check);
          });
      }
      catch (...)
      {
        ignore_expected_exception();
        const std::lock_guard lock{check->mutex};
        check->kept[owner] = true;
      }
    }
  }
  catch (...)
  {
    ignore_expected_exception();
    keep_every_created(*check);
  }
  read_ended(check, finish_check);
}

// Stage 2: the created Nodes' Properties of their own namespace, looked up in one call.
void look_up_properties(const shared_ptr<CreatedCheck>& check) noexcept
{
  const auto space = check->space.lock();
  if (!space)
  {
    finish_check(check);
    return;
  }
  try
  {
    std::vector<LookupItem> lookups;
    std::vector<std::size_t> owners;
    for (std::size_t i = 0; i < check->created.size(); ++i)
    {
      if (check->kept[i])
      {
        continue;
      }
      for (const NodeId& property : check->properties[i])
      {
        lookups.push_back(LookupItem{property, std::nullopt});
        owners.push_back(i);
      }
    }
    if (lookups.empty())
    {
      finish_check(check);
      return;
    }
    space->find_nodes_async(RequestInfo{},
      lookups,
      [check, owners = std::move(owners)](BatchResult<NodeAccessorResult> found)
      { read_declarations(check, owners, std::move(found)); });
  }
  catch (...)
  {
    ignore_expected_exception();
    keep_every_created(*check);
    finish_check(check);
  }
}

// Stage 1: each created Node's HasProperty targets.
void read_properties(const shared_ptr<CreatedCheck>& check, BatchResult<NodeAccessorResult> found) noexcept
{
  {
    const std::lock_guard lock{check->mutex};
    check->remaining = 1;
  }
  try
  {
    if (found.batchStatus.is_bad() || found.items.size() != check->created.size())
    {
      keep_every_created(*check);
      read_ended(check, look_up_properties);
      return;
    }
    for (std::size_t i = 0; i < check->created.size(); ++i)
    {
      try
      {
        // A created Node that cannot be looked up, or whose lookup is Uncertain, is tolerated: it stays
        // listed as its namespace reported it, so the check removes only a listing it has confirmed.
        if (!found.items[i].is_good())
        {
          const std::lock_guard lock{check->mutex};
          check->kept[i] = true;
          continue;
        }
        const NodeAccessor node = std::move(found.items[i]).value();
        {
          const std::lock_guard lock{check->mutex};
          ++check->remaining;
        }
        node.get_properties_async(
          [check, i](NodeAccessor::ReferencesResult read)
          {
            {
              const std::lock_guard lock{check->mutex};
              try
              {
                if (!read.is_good())
                {
                  check->kept[i] = true;
                }
                else
                {
                  const uint16_t own = check->created[i].namespace_index();
                  for (const Reference& reference : read.value())
                  {
                    if (reference.is_forward() && reference.target_id().is_local() &&
                        reference.target_id().node_id().namespace_index() == own)
                    {
                      check->properties[i].push_back(reference.target_id().node_id());
                    }
                  }
                }
              }
              catch (...)
              {
                ignore_expected_exception();
                check->kept[i] = true;
              }
            }
            read_ended(check, look_up_properties);
          });
      }
      catch (...)
      {
        ignore_expected_exception();
        const std::lock_guard lock{check->mutex};
        check->kept[i] = true;
      }
    }
  }
  catch (...)
  {
    ignore_expected_exception();
    keep_every_created(*check);
  }
  read_ended(check, look_up_properties);
}

// Raises @p change through @p space once its created Nodes are checked; counted as a step the address space's
// shutdown waits for (NR-67 step 2). The change is raised unchecked when the check cannot start.
void check_created_then_raise(
  const shared_ptr<AddressSpaceImpl>& space, AddressSpaceChange change, std::function<void()> done) noexcept
{
  shared_ptr<CreatedCheck> createdCheck;
  std::vector<LookupItem> lookups;
  try
  {
    createdCheck = std::make_shared<CreatedCheck>();
    for (const ModelChangeEntry& entry : change.changes)
    {
      if ((entry.verbs & node_added()) != 0)
      {
        createdCheck->created.push_back(entry.affected);
        lookups.push_back(LookupItem{entry.affected, std::nullopt});
      }
    }
    createdCheck->properties.resize(createdCheck->created.size());
    createdCheck->kept.assign(createdCheck->created.size(), false);
    createdCheck->logger = space->logger();
  }
  catch (...)
  {
    ignore_expected_exception();
    space->raise_model_change(std::move(change), std::move(done));
    return;
  }
  createdCheck->space = space;
  createdCheck->change = std::move(change);
  createdCheck->done = std::move(done);
  createdCheck->posted = space->start_posted_step();
  space->find_nodes_async(RequestInfo{},
    lookups,
    [createdCheck](BatchResult<NodeAccessorResult> found)
    { read_properties(createdCheck, std::move(found)); });
}

}  // namespace

ModelChangeStep::Call::Call(shared_ptr<ModelChangeStep> step) noexcept : mStep(std::move(step))
{}

ModelChangeStep::Call::~Call()
{
  end();
}

void ModelChangeStep::Call::end() noexcept
{
  if (!mEnded.exchange(true, std::memory_order_acq_rel))
  {
    mStep->call_ended();
  }
}

ModelChangeStep::ModelChangeStep(weak_ptr<AddressSpaceImpl> addressSpace) noexcept
  : mAddressSpace(std::move(addressSpace))
{}

ModelChangeStep::~ModelChangeStep()
{
  // No call is outstanding: each holds the step. Raising reads only this object's members.
  {
    const std::lock_guard lock{mMutex};
    mClosed = true;
  }
  raise_if_done();
}

shared_ptr<ModelChangeStep> ModelChangeStep::create(weak_ptr<AddressSpaceImpl> addressSpace)
{
  return std::make_shared<ModelChangeStep>(std::move(addressSpace));
}

shared_ptr<ModelChangeStep::Call> ModelChangeStep::call()
{
  {
    const std::lock_guard lock{mMutex};
    ++mOutstanding;
  }
  try
  {
    return std::make_shared<Call>(shared_from_this());
  }
  catch (...)
  {
    call_ended();
    throw;
  }
}

void ModelChangeStep::record(std::span<const VersionedNode> nodes, uint8_t verbs) noexcept
{
  record(nodes, [verbs](const NodeId&) { return verbs; });
}

void ModelChangeStep::record(
  std::span<const VersionedNode> nodes, const std::function<uint8_t(const NodeId&)>& verbsOf) noexcept
{
  if (nodes.empty())
  {
    return;
  }
  try
  {
    const std::lock_guard lock{mMutex};
    for (const VersionedNode& node : nodes)
    {
      const uint8_t verbs = verbsOf(node.node);
      if (verbs == 0)
      {
        // A NodeVersion that changed for a change no verb names.
        mUnspecified = true;
        continue;
      }
      auto [entry, added] = mEntryOf.try_emplace(node.node, mEntries.size());
      if (added)
      {
        mEntries.push_back(ModelChangeEntry{node.node, node.affectedType, verbs});
        continue;
      }
      ModelChangeEntry& existingEntry = mEntries[entry->second];
      existingEntry.verbs = static_cast<uint8_t>(existingEntry.verbs | verbs);
      if (existingEntry.affectedType.is_null())
      {
        existingEntry.affectedType = node.affectedType;
      }
    }
  }
  catch (...)
  {
    // A change that cannot be held is reported as one no verb names: the event still tells the clients that
    // the model changed (Part 3 9.32.5).
    ignore_expected_exception();
    const std::lock_guard lock{mMutex};
    mUnspecified = true;
  }
}

void ModelChangeStep::record_unspecified() noexcept
{
  const std::lock_guard lock{mMutex};
  mUnspecified = true;
}

void ModelChangeStep::type_definition_sent(const NodeId& node, const NodeId& typeDefinition) noexcept
{
  try
  {
    const std::lock_guard lock{mMutex};
    mTypeDefinitions.insert_or_assign(node, typeDefinition);
  }
  catch (...)
  {
    ignore_expected_exception();
  }
}

void ModelChangeStep::close(std::function<void()> done) noexcept
{
  {
    const std::lock_guard lock{mMutex};
    mClosed = true;
    mDone = std::move(done);
  }
  raise_if_done();
}

void ModelChangeStep::call_ended() noexcept
{
  {
    const std::lock_guard lock{mMutex};
    --mOutstanding;
  }
  raise_if_done();
}

void ModelChangeStep::raise_if_done() noexcept
{
  AddressSpaceChange change;
  std::function<void()> done;
  // Whether the operation changed a versioned Node: an operation that changed none raises nothing (Part
  // 3 9.32.2).
  bool changed{false};
  {
    const std::lock_guard lock{mMutex};
    if (!mClosed || mOutstanding != 0 || mRaised)
    {
      return;
    }
    mRaised = true;
    done = std::move(mDone);
    changed = !mEntries.empty() || mUnspecified;
    if (changed)
    {
      change.kind = AddressSpaceChangeKind::Model;
      change.unspecified = mUnspecified;
      for (auto& entry : mEntries)
      {
        if (entry.affectedType.is_null())
        {
          if (const auto sent = mTypeDefinitions.find(entry.affected); sent != mTypeDefinitions.end())
          {
            entry.affectedType = sent->second;
          }
        }
      }
      change.changes = std::move(mEntries);
    }
  }
  if (!changed)
  {
    run(done);
    return;
  }
  if (const auto space = mAddressSpace.lock())
  {
    // A created Node is listed only when it holds a NodeVersion of its own once the operation has ended.
    if (std::ranges::any_of(
          change.changes, [](const ModelChangeEntry& entry) { return (entry.verbs & node_added()) != 0; }))
    {
      check_created_then_raise(space, std::move(change), std::move(done));
      return;
    }
    space->raise_model_change(std::move(change), std::move(done));
    return;
  }
  // The address space is gone: there is no executor and no event sink to raise the event through.
  run(done);
}

}  // namespace ua::detail
