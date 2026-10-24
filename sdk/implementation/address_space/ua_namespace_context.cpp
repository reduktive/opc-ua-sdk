// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_context.h"

#include "ua_address_space_change_events.h"
#include "ua_address_space_impl.h"
#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_instance_utils.h"
#include "ua_model_change_step.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_namespace_context_state.h"
#include "ua_namespace_items.h"
#include "ua_namespace_route.h"
#include "ua_namespace_registration_coordinator.h"
#include "ua_node_accessor.h"
#include "ua_object_id.h"
#include "ua_on_strand.h"
#include "ua_referencetype_id.h"

#include <boost/asio/post.hpp>

#include <algorithm>
#include <chrono>
#include <limits>
#include <utility>

namespace ua
{

namespace
{

constexpr const char* advanceSource = "NamespaceContext";

/// The current time as a VersionTime: seconds since 2000-01-01 00:00 UTC (OPC 10000-4 7.44).
uint32_t version_time_now() noexcept
{
  using namespace std::chrono;
  constexpr int64_t versionTimeEpochInUnixSeconds = 946684800;
  const auto seconds = duration_cast<std::chrono::seconds>(system_clock::now().time_since_epoch()).count() -
                       versionTimeEpochInUnixSeconds;
  return static_cast<uint32_t>(std::clamp<int64_t>(seconds, 1, std::numeric_limits<uint32_t>::max()));
}

using Advances = detail::NamespaceContextState::VersionAdvances;
using PostedSteps = AddressSpaceImpl::PostedSteps;

/// One run of NR-40's advance for one namespace. It covers the changes whose completions were waiting when it
/// started, and starts the next run when more arrived meanwhile; the last run ends the counted step.
class VersionAdvance final : public std::enable_shared_from_this<VersionAdvance>
{
public:
  VersionAdvance(weak_ptr<AddressSpaceImpl> addressSpace, uint16_t index, shared_ptr<Advances> advances,
    shared_ptr<PostedSteps> steps, Logger logger)
    : mAddressSpace(std::move(addressSpace)), mIndex(index), mAdvances(std::move(advances)),
      mSteps(std::move(steps)), mLogger(std::move(logger))
  {}

  /// Runs on the address space's executor.
  void run() noexcept
  {
    try
    {
      {
        const std::lock_guard lock{mAdvances->mutex};
        mCovered.swap(mAdvances->waiting);
      }
      const auto space = mAddressSpace.lock();
      if (!space)
      {
        finish(VoidResult{Status::BadShutdown,
          ErrorDetail::build("AddressSpaceGone",
            "The address space was gone before ConfigurationVersion could be advanced",
            advanceSource)});
        return;
      }
      const auto nameSpace = space->namespace_array().get_namespace(mIndex);
      if (!nameSpace)
      {
        finish(VoidResult{});
        return;
      }
      const auto declared = nameSpace->metadata_object();
      if (declared)
      {
        find_version(*declared);
        return;
      }
      instance_utils::find_child_id_by_browse_name_async(
        detail::NamespaceRegistrationCoordinator::handle(space),
        NodeId{ObjectId::Server_Namespaces},
        NodeId{ReferenceTypeId::HasComponent},
        QualifiedName{mIndex, nameSpace->uri()},
        [self = shared_from_this()](NodeIdResult metadata)
        {
          if (!metadata.is_good())
          {
            self->finish_missing(metadata.status_code(), metadata.shared_detail());
            return;
          }
          self->find_version(metadata.value());
        });
    }
    catch (...)
    {
      finish(VoidResult{ua::exception_to_status_code(std::current_exception())});
    }
  }

private:
  void find_version(const NodeId& metadata)
  {
    const auto space = mAddressSpace.lock();
    if (!space)
    {
      finish(VoidResult{Status::BadShutdown});
      return;
    }
    instance_utils::find_child_by_browse_name_async(detail::NamespaceRegistrationCoordinator::handle(space),
      metadata,
      NodeId{ReferenceTypeId::HasProperty},
      QualifiedName{0, "ConfigurationVersion"},
      [self = shared_from_this()](NodeAccessorResult found)
      {
        // The SDK advances the Property it finds, so it does not act on an Uncertain lookup.
        if (!found.is_good())
        {
          const StatusCode refused =
            detail::answer_failure(found.status_code(), "LookupAnswerUncertain", advanceSource);
          self->finish_missing(refused, refused.shared_detail());
          return;
        }
        auto version = found.value().as<VariableAccessor>();
        if (!version)
        {
          self->finish(VoidResult{Status::BadTypeMismatch,
            ErrorDetail::build("ConfigurationVersionTypeMismatch",
              "The namespace's ConfigurationVersion is not a Variable",
              advanceSource)});
          return;
        }
        self->advance(std::move(*version));
      });
  }

  void advance(VariableAccessor version)
  {
    ReadValueId read;
    read.attribute_id() = utils::to_underlying(AttributeId::Value);
    version.read_value_async(0.0,
      false,
      read,
      nullptr,
      [self = shared_from_this(), version](DataValueResult current) mutable
      {
        if (!current.is_good())
        {
          self->finish(VoidResult{detail::read_failure(current.status_code(), advanceSource)});
          return;
        }
        const auto* value = current.value().value().try_as<uint32_t>();
        if (value == nullptr)
        {
          self->finish(VoidResult{Status::BadTypeMismatch,
            ErrorDetail::build("ConfigurationVersionTypeMismatch",
              "The namespace's ConfigurationVersion does not hold a VersionTime",
              advanceSource)});
          return;
        }
        if (*value == std::numeric_limits<uint32_t>::max())
        {
          self->finish(VoidResult{Status::BadOutOfRange,
            ErrorDetail::build("ConfigurationVersionExhausted",
              "The namespace's ConfigurationVersion cannot advance beyond the largest UInt32",
              advanceSource)});
          return;
        }
        DataValue next;
        next.value() = Variant{std::max(version_time_now(), *value + 1U)};
        version.write_value_async(
          std::move(next), [self](VoidResult written) mutable { self->finish(std::move(written)); });
      });
  }

  /// A metadata Object or ConfigurationVersion that is not found is not an error (NR-40 rule 3).
  void finish_missing(const StatusCode& status, shared_ptr<const ErrorDetail> detail)
  {
    if (status.equivalent(StatusCode{Status::BadNodeIdUnknown}))
    {
      finish(VoidResult{});
      return;
    }
    finish(VoidResult{status, std::move(detail)});
  }

  void finish(const VoidResult& result) noexcept
  {
    for (auto& completion : mCovered)
    {
      detail::invoke_user_callback(mLogger, completion, VoidResult{result});
    }
    mCovered.clear();
    bool again = false;
    {
      const std::lock_guard lock{mAdvances->mutex};
      again = !mAdvances->waiting.empty();
      mAdvances->running = again;
    }
    if (!again)
    {
      mSteps->finish(mLogger);
      return;
    }
    // Changes reported during this run: the next run reads ConfigurationVersion again.
    const auto space = mAddressSpace.lock();
    if (!space)
    {
      run();
      return;
    }
    try
    {
      ua::async::post_owning(this, space->executor(), mLogger, [](VersionAdvance& self) { self.run(); })();
    }
    catch (...)
    {
      detail::ignore_expected_exception();
      run();
    }
  }

  weak_ptr<AddressSpaceImpl> mAddressSpace;
  uint16_t mIndex;
  shared_ptr<Advances> mAdvances;
  shared_ptr<PostedSteps> mSteps;
  Logger mLogger;
  std::vector<std::function<void(VoidResult)>> mCovered;
};

StatusCode context_closed()
{
  return StatusCode{Status::BadShutdown,
    ErrorDetail::build("NamespaceContextClosed",
      "The namespace is not attached, its registration failed, or the address space shut down or is gone",
      advanceSource)};
}

}  // namespace

NamespaceContext::NamespaceContext(shared_ptr<const detail::NamespaceContextState> state) noexcept
  : mState(std::move(state))
{}

Logger detail::NamespaceContextAccess::logger(const NamespaceContext& context)
{
  const auto space = context.mState->addressSpace.lock();
  return space ? space->logger() : Logger{};
}

uint16_t NamespaceContext::index() const noexcept
{
  return mState->index;
}

default_ns::NamespaceMonitoringSupport& NamespaceContext::monitoring() const noexcept
{
  return *mState->monitoring;
}

void NamespaceContext::model_changed(std::span<const ModelChangeReport> changes) const noexcept
{
  if (mState->closed.load(std::memory_order_acquire))
  {
    return;
  }
  const auto space = mState->addressSpace.lock();
  if (!space)
  {
    return;
  }
  space->model_changed();
  if (changes.empty())
  {
    return;
  }
  try
  {
    const auto verb = [](ModelChangeStructureVerbMask mask)
    {
      return static_cast<uint8_t>(static_cast<int32_t>(mask));
    };
    auto step = detail::ModelChangeStep::create(space);
    for (const ModelChangeReport& change : changes)
    {
      uint8_t verbs = 0;
      switch (change.kind)
      {
      case ModelChangeReport::Kind::NodeAdded:
        verbs = verb(ModelChangeStructureVerbMask::NodeAdded);
        break;
      case ModelChangeReport::Kind::NodeDeleted:
        verbs = verb(ModelChangeStructureVerbMask::NodeDeleted);
        break;
      case ModelChangeReport::Kind::ReferenceAdded:
        verbs = verb(ModelChangeStructureVerbMask::ReferenceAdded);
        break;
      case ModelChangeReport::Kind::ReferenceDeleted:
        verbs = verb(ModelChangeStructureVerbMask::ReferenceDeleted);
        break;
      case ModelChangeReport::Kind::DataTypeChanged:
        verbs = verb(ModelChangeStructureVerbMask::DataTypeChanged);
        break;
      case ModelChangeReport::Kind::ValueRankChanged:
      case ModelChangeReport::Kind::ArrayDimensionsChanged:
        step->record_unspecified();
        continue;
      case ModelChangeReport::Kind::ViewContentChanged:
        continue;
      }
      const VersionedNode node{change.affected, change.affectedType};
      step->record(std::span<const VersionedNode>{&node, 1}, verbs);
    }
    // Raised on the address space's executor: nothing here calls a namespace (NR-39 rule 6).
    step->close(nullptr);
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

void NamespaceContext::semantics_changed(std::span<const SemanticChangeReport> changes) const noexcept
{
  if (changes.empty() || mState->closed.load(std::memory_order_acquire))
  {
    return;
  }
  const auto space = mState->addressSpace.lock();
  if (!space)
  {
    return;
  }
  try
  {
    detail::AddressSpaceChange change;
    change.kind = detail::AddressSpaceChangeKind::Semantic;
    change.changes.reserve(changes.size());
    for (const SemanticChangeReport& report : changes)
    {
      change.changes.push_back(detail::ModelChangeEntry{report.affected, report.affectedType, 0});
    }
    // Raised on the address space's executor: nothing here calls a namespace (NR-39 rule 6).
    space->raise_model_change(std::move(change), nullptr);
  }
  catch (...)
  {
    detail::ignore_expected_exception();
  }
}

VoidResult NamespaceContext::constant_values_changed(
  std::function<void(VoidResult)> completion) const noexcept
{
  if (mState->closed.load(std::memory_order_acquire))
  {
    return VoidResult{context_closed()};
  }
  const auto space = mState->addressSpace.lock();
  if (!space)
  {
    return VoidResult{context_closed()};
  }
  try
  {
    const auto& advances = mState->advances;
    {
      const std::lock_guard lock{advances->mutex};
      advances->waiting.push_back(std::move(completion));
      if (advances->running)
      {
        // The running advance read ConfigurationVersion before this change, or has not read it yet: either
        // way the next run, or this one, covers it.
        return VoidResult{};
      }
      advances->running = true;
    }
    auto logger = space->logger().with_category("namespace");
    auto steps = space->start_posted_step();
    try
    {
      auto run = std::make_shared<VersionAdvance>(space, mState->index, advances, steps, logger);
      boost::asio::post(space->executor(), ua::async::guarded(logger, [run] { run->run(); }));
    }
    catch (...)
    {
      // Nothing was posted. The queue held only this change, since no advance was running: it is emptied, so
      // that a later call starts one again.
      const VoidResult failed{ua::exception_to_status_code(std::current_exception())};
      {
        const std::lock_guard lock{advances->mutex};
        advances->running = false;
        advances->waiting.clear();
      }
      steps->finish(logger);
      return failed;
    }
    return VoidResult{};
  }
  catch (...)
  {
    return VoidResult{ua::exception_to_status_code(std::current_exception())};
  }
}

}  // namespace ua
