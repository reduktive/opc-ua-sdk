// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Implementation of the strand-bearing @ref ua::client::detail::RedundancyManagerImpl (client design
///        section 8.11): the section 8.11.4 monitoring FSM, hysteresis (ring + window), the reactive
///        `ScoringBackups` probe fanout + scoring function, the `RedundancySwitch.*` failover kick, and the
///        RecoveryWindow anti-thrash gate. Plus the public @ref ua::client::RedundancyManager move-only pimpl
///        forwarding.

#include "ua_redundancy_manager_impl.h"

#include "ua_application_description.h"
#include "ua_array.h"
#include "ua_attribute_id.h"
#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_on_strand.h"
#include "ua_read_value_id.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_variable_id.h"

#include <boost/asio/post.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace ua::client::detail
{

namespace
{

using ua::Result;
using ua::Status;
using ua::StatusCode;
using ua::VoidResult;

// Source-tag prefix (CL-DIAG-002 / CL-DIAG-015). Every advisory / Bad path carries
// `client.tier1.redundancy.*`.
constexpr std::string_view srcDiscoveryRsRead =
  "client.tier1.redundancy.discovery_redundancysupport_read_failed";
constexpr std::string_view srcDiscoveryUriRead =
  "client.tier1.redundancy.discovery_serveruriarray_read_failed";
constexpr std::string_view srcServerUriEmpty = "client.tier1.redundancy.server_uri_array_empty";
constexpr std::string_view srcServerUriMissingSelf = "client.tier1.redundancy.server_uri_array_missing_self";
constexpr std::string_view srcFindServers = "client.tier1.redundancy.findservers_read_failed";
constexpr std::string_view srcMiInstall = "client.tier1.redundancy.servicelevel_mi_install_failed";
// W10: the authoritative transition table (the design specification:11612) names the no-eligible advisory
// `no_eligible_candidate` (was `scoring`).
constexpr std::string_view srcNoEligible = "client.tier1.redundancy.no_eligible_candidate";
constexpr std::string_view srcProbeTimeout = "client.tier1.redundancy.probe_timeout";
constexpr std::string_view srcProbeFailed = "client.tier1.redundancy.probe_failed";
constexpr std::string_view srcTransportFatalNoBackup = "client.tier1.redundancy.transport_fatal_no_backup";
constexpr std::string_view srcFailover = "client.tier1.redundancy.failover";
constexpr std::string_view srcForceUnknown = "client.tier1.redundancy.force_switch_unknown";
constexpr std::string_view srcForceRecovery = "client.tier1.redundancy.force_switch_during_recovery_window";
constexpr std::string_view srcForceInvalid = "client.tier1.redundancy.force_switch_invalid_state";
constexpr std::string_view srcModeChanged = "client.tier1.redundancy.redundancy_mode_changed";

// The three NS0 variables the discovery pass reads (Part 5).
ua::ReadValueId make_value_read(ua::VariableId id)
{
  ua::ReadValueId read;
  read.node_id() = ua::NodeId{id};
  read.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
  return read;
}

// The manager decides its mode, its redundant set and its failover on these values itself, so only a Good
// value is used; an Uncertain one counts as unusable, as a Bad one does.
bool data_value_not_good(const ua::DataValue& value)
{
  const auto& valueStatus = value.status();
  return valueStatus.has_value() && !valueStatus.value().is_good();
}

// Decodes the Int32-encoded RedundancySupport enum; false on a status that is not Good / type mismatch /
// unknown enumerator.
bool decode_redundancy_support(const ua::DataValue& value, ua::RedundancySupport& out)
{
  if (data_value_not_good(value))
  {
    return false;
  }
  const Result<std::int32_t> raw = value.value().to<std::int32_t>();
  if (!raw.is_good())
  {
    return false;
  }
  const auto candidate = static_cast<ua::RedundancySupport>(raw.value());
  if (!ua::is_valid(candidate))
  {
    return false;
  }
  out = candidate;
  return true;
}

// Decodes the Byte-encoded ServiceLevel; false on a status that is not Good / type mismatch.
bool decode_service_level(const ua::DataValue& value, std::uint8_t& out)
{
  if (data_value_not_good(value))
  {
    return false;
  }
  const Result<std::uint8_t> raw = value.value().to<std::uint8_t>();
  if (!raw.is_good())
  {
    return false;
  }
  out = raw.value();
  return true;
}

// The degrade cause maps to a wire StatusCode threaded into the FSM kick (diagnostics only).
ua::Status degrade_status(RedundancyDegradeReason reason)
{
  switch (reason)
  {
  case RedundancyDegradeReason::ServiceLevelBelowHealthy:
    return ua::Status::BadDeviceFailure;
  case RedundancyDegradeReason::ServiceLevelInaccessible:
    return ua::Status::BadNoCommunication;  // section 3.1 defensive: a ServiceLevel MI gone Bad is a comms
                                            // loss
  case RedundancyDegradeReason::TransportFatalWithBackups:
    return ua::Status::BadConnectionClosed;
  case RedundancyDegradeReason::ForceSwitchRequested:
    return ua::Status::BadNothingToDo;
  }
  return ua::Status::BadDeviceFailure;
}

std::string_view reason_name(RedundancyDegradeReason reason)
{
  switch (reason)
  {
  case RedundancyDegradeReason::ServiceLevelBelowHealthy:
    return "ServiceLevelBelowHealthy";
  case RedundancyDegradeReason::ServiceLevelInaccessible:
    return "ServiceLevelInaccessible";
  case RedundancyDegradeReason::TransportFatalWithBackups:
    return "TransportFatalWithBackups";
  case RedundancyDegradeReason::ForceSwitchRequested:
    return "ForceSwitchRequested";
  }
  return "Unknown";
}

// Scoring tier (section 8.11.4). Ordered Healthy > Degraded > Unknown for argmax.
enum class Tier : int
{
  Unknown = 0,
  Degraded = 1,
  Healthy = 2
};

Tier tier_of(const RedundantCandidate& candidate, std::uint8_t healthyThreshold)
{
  if (candidate.lastServiceLevel.has_value())
  {
    return *candidate.lastServiceLevel >= healthyThreshold ? Tier::Healthy : Tier::Degraded;
  }
  return Tier::Unknown;
}

}  // namespace

std::shared_ptr<RedundancyManagerImpl> RedundancyManagerImpl::create(boost::asio::any_io_executor executor,
  std::shared_ptr<RedundancyManagerHost> host, ua::Logger logger, RedundancyPolicy policy)
{
  return std::shared_ptr<RedundancyManagerImpl>(
    new RedundancyManagerImpl(std::move(executor), std::move(host), std::move(logger), std::move(policy)));
}

RedundancyManagerImpl::RedundancyManagerImpl(boost::asio::any_io_executor executor,
  std::shared_ptr<RedundancyManagerHost> host, ua::Logger logger, RedundancyPolicy policy)
  : mExecutor(std::move(executor)), mStrand(boost::asio::make_strand(mExecutor)), mHost(std::move(host)),
    mLogger(std::move(logger)), mPolicy(std::move(policy)), mRecoveryWindowTimer(mStrand),
    mProbeDeadlineTimer(mStrand), mInaccessibleTimer(mStrand)
{
  publish_snapshot();
}

// ---- cross-strand reads (Rule 4; lock-free) ----

std::shared_ptr<const RedundancyInfo> RedundancyManagerImpl::redundancy_info() const noexcept
{
  return mInfoSnapshot.load(std::memory_order_acquire);
}

std::optional<std::string> RedundancyManagerImpl::current_active_endpoint() const noexcept
{
  const std::shared_ptr<const RedundancyInfo> snapshot = mInfoSnapshot.load(std::memory_order_acquire);
  if (!snapshot)
  {
    return std::nullopt;
  }
  for (const RedundantCandidate& candidate : snapshot->candidates)
  {
    if (candidate.isActive)
    {
      return candidate.serverUri;
    }
  }
  return std::nullopt;
}

// ---- consumer / lifecycle entry points (all hop to mStrand) ----

void RedundancyManagerImpl::force_switch_async(
  std::string targetServerUri, std::function<void(VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{StatusCode{Status::BadConnectionClosed}},
    [targetServerUri = std::move(targetServerUri)](
      RedundancyManagerImpl& self, std::function<void(VoidResult)> cb) mutable
    { self.do_force_switch(std::move(targetServerUri), std::move(cb)); })();
}

void RedundancyManagerImpl::close_async(std::function<void(VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{},
    [](RedundancyManagerImpl& self, std::function<void(VoidResult)> cb) { self.do_close(std::move(cb)); })();
}

void RedundancyManagerImpl::on_session_active_async(
  ua::NodeId /*sessionId*/, std::function<void(VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{},
    [](RedundancyManagerImpl& self, std::function<void(VoidResult)> cb)
    {
      if (self.mState == RedundancyManagerState::Closed)
      {
        self.deliver_void(std::move(cb), VoidResult{});
        return;
      }
      self.start_discovery(std::move(cb));
    })();
}

void RedundancyManagerImpl::on_session_closed_async(std::function<void(VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{},
    [](RedundancyManagerImpl& self, std::function<void(VoidResult)> cb)
    {
      // The session (and its MI) is gone. Drop the stale handle and fall back to Dormant so the next
      // Session-Active / reconnect re-runs discovery. Terminal / in-flight-failover states are left alone.
      if (self.mState == RedundancyManagerState::Closed || self.mState == RedundancyManagerState::FailingOver)
      {
        self.deliver_void(std::move(cb), VoidResult{});
        return;
      }
      // H2: bump the generation (matching start_discovery / do_close) so an in-flight discovery reply
      // captured at the pre-close generation is dropped by is_current()  -  otherwise it would drive the
      // closed session into Monitoring with a spurious on_redundancy_recovered.
      ++self.mGeneration;
      self.mInaccessibleTimer.cancel();
      self.mServiceLevelHandle.reset();
      self.mServiceLevelHistory.clear();
      self.mServiceLevelBadSince.reset();
      if (self.mState != RedundancyManagerState::RecoveryWindow)
      {
        self.set_state(RedundancyManagerState::Dormant);
      }
      self.publish_snapshot();
      self.deliver_void(std::move(cb), VoidResult{});
    })();
}

void RedundancyManagerImpl::on_reconnect_completed_async(
  ua::client::ReconnectOutcome outcome, std::function<void(VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{},
    [outcome = std::move(outcome)](RedundancyManagerImpl& self, std::function<void(VoidResult)> cb) mutable
    {
      if (self.mState == RedundancyManagerState::Closed)
      {
        self.deliver_void(std::move(cb), VoidResult{});
        return;
      }
      if (self.mState == RedundancyManagerState::FailingOver)
      {
        // W11: only treat this completion as OUR redundancy switch when the outcome says so. A
        // non-RedundancySwitch reconnect that merely completed while we were FailingOver must NOT
        // phantom-swap the active  -  re-run discovery instead. A silent outcome (no cause reported) trusts
        // our own kick (mFailoverTarget); a RedundancySwitch outcome trusts the server we ACTUALLY landed on
        // (RedundancySwitchInfo::toUri), which a fallback may have diverged from the requested target.
        std::optional<std::string> switchTarget;
        bool redundancySwitch = true;
        if (outcome.cause.has_value())
        {
          if (const auto* info = std::get_if<ua::client::RedundancySwitchInfo>(&*outcome.cause))
          {
            if (!info->toUri.empty())
            {
              switchTarget = info->toUri;
            }
          }
          else
          {
            redundancySwitch = false;
          }
        }
        if (!redundancySwitch)
        {
          self.mFailoverTarget.reset();
          self.start_discovery(std::move(cb));
          return;
        }
        // Manager-originated RedundancySwitch.* succeeded: swap the active flag, bump counters, enter the
        // RecoveryWindow (anti-thrash), complete a pending force_switch Good.
        const std::string target = switchTarget.value_or(self.mFailoverTarget.value_or(std::string{}));
        if (!self.mActiveUri.empty())
        {
          auto previous = self.mCandidates.find(self.mActiveUri);
          if (previous != self.mCandidates.end())
          {
            previous->second.isActive = false;
          }
        }
        if (!target.empty())
        {
          auto& candidate = self.mCandidates[target];
          candidate.serverUri = target;
          candidate.isActive = true;
          self.mActiveUri = target;
        }
        self.mFailoverTarget.reset();
        ++self.mFailoverCount;
        self.mLastFailoverAt = self.mNowFn();
        self.mLastFailoverError.reset();
        self.set_state(RedundancyManagerState::RecoveryWindow);
        self.arm_recovery_window(self.mGeneration);
        self.mHost->fire_observer_redundancy_failover_completed(self.mActiveUri, std::move(outcome));
        if (self.mForceSwitchPending.has_value())
        {
          self.deliver_void(std::move(self.mForceSwitchPending->callback), VoidResult{});
          self.mForceSwitchPending.reset();
        }
        self.publish_snapshot();
        self.deliver_void(std::move(cb), VoidResult{});
        return;
      }
      // Regular reconnect (server may have changed ServerUriArray / mode)  -  re-run discovery. The ack fires
      // when discovery reaches its terminal step.
      self.start_discovery(std::move(cb));
    })();
}

void RedundancyManagerImpl::on_transport_fatal_async(ua::StatusCode reason,
  std::shared_ptr<const ua::ErrorDetail> chain, std::function<void(VoidResult)> callback) noexcept
{
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{},
    [reason, chain = std::move(chain)](
      RedundancyManagerImpl& self, std::function<void(VoidResult)> cb) mutable
    {
      const bool hasBackup = std::any_of(self.mCandidates.begin(),
        self.mCandidates.end(),
        [](const auto& entry) { return !entry.second.isActive; });
      if (self.mState == RedundancyManagerState::Monitoring && hasBackup)
      {
        // H5: thread the transport-fatal reason + chain into the failover degrade detail (as the inner
        // cause), not a fresh root.
        self.enter_scoring(
          RedundancyDegradeReason::TransportFatalWithBackups, std::nullopt, std::move(chain), reason);
      }
      else if (!hasBackup)
      {
        // H5: the no-backup branch used to be totally silent  -  surface the fatal cause as an advisory that
        // chains the incoming transport chain.
        self.advisory(
          std::shared_ptr<const ua::ErrorDetail>{ua::make_error_detail("REDUNDANCY_TRANSPORT_FATAL_NO_BACKUP",
            "transport fatally dropped with no cached backup to fail over to",
            std::string{srcTransportFatalNoBackup},
            std::move(chain))});
      }
      self.deliver_void(std::move(cb), VoidResult{});
    })();
}

// ---- discovery (section 8.11.3 / section 8.11.4) ----

void RedundancyManagerImpl::start_discovery(std::function<void(VoidResult)> ack)
{
  if (mDiscoveryAck)
  {
    deliver_void(std::move(mDiscoveryAck), VoidResult{});  // superseded  -  release the prior waiter
  }
  mDiscoveryAck = std::move(ack);

  const std::uint64_t generation = ++mGeneration;  // drop stale MI / step callbacks from a prior pass

  if (mServiceLevelHandle.has_value())
  {
    mHost->cancel_monitored_item_async(*mServiceLevelHandle, [](VoidResult) {});
    mServiceLevelHandle.reset();
  }
  mServiceLevelHistory.clear();
  mServiceLevelBadSince.reset();
  mActiveUri = mHost->current_application_uri();

  run_discovery(generation);
}

void RedundancyManagerImpl::run_discovery(std::uint64_t generation)
{
  set_state(RedundancyManagerState::Discovering);
  discovery_read_redundancy_support(generation);
}

void RedundancyManagerImpl::discovery_read_redundancy_support(std::uint64_t generation)
{
  mHost->read_attributes_async({make_value_read(ua::VariableId::Server_ServerRedundancy_RedundancySupport)},
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation](RedundancyManagerImpl& self, Result<std::vector<ua::DataValue>> result)
      {
        if (!self.is_current(generation))
        {
          return;
        }
        ua::RedundancySupport support = ua::RedundancySupport::None;
        // The manager acts on this answer, so an Uncertain one counts as a failed read.
        if (!result.is_good() || result.value().empty() ||
            !decode_redundancy_support(result.value().front(), support))
        {
          self.advisory("REDUNDANCY_SUPPORT_READ_FAILED",
            "reading Server.ServerRedundancy.RedundancySupport failed",
            std::string{srcDiscoveryRsRead});
          self.set_state(RedundancyManagerState::Dormant);
          self.fire_discovery_ack(VoidResult{});
          return;
        }

        if (support == ua::RedundancySupport::None || support == ua::RedundancySupport::Transparent)
        {
          self.mRedundancySupport = support;
          self.mEffectiveMode = support;
          self.set_state(RedundancyManagerState::Dormant);
          self.fire_discovery_ack(VoidResult{});
          return;
        }

        const ua::RedundancySupport previousMode = self.mEffectiveMode;
        self.mRedundancySupport = support;
        self.mEffectiveMode = self.derive_effective_mode(support);
        if (previousMode != ua::RedundancySupport::None && previousMode != self.mEffectiveMode)
        {
          self.advisory("REDUNDANCY_MODE_CHANGED",
            "redundancy mode changed to " + ua::to_string(self.mEffectiveMode),
            std::string{srcModeChanged});
        }
        self.discovery_read_server_uri_array(generation);
      }));
}

void RedundancyManagerImpl::discovery_read_server_uri_array(std::uint64_t generation)
{
  mHost->read_attributes_async({make_value_read(ua::VariableId::Server_ServerRedundancy_ServerUriArray)},
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation](RedundancyManagerImpl& self, Result<std::vector<ua::DataValue>> result)
      {
        if (!self.is_current(generation))
        {
          return;
        }
        // The manager acts on this answer, so an Uncertain one counts as a failed read.
        if (!result.is_good() || result.value().empty())
        {
          self.advisory("REDUNDANCY_SERVERURIARRAY_READ_FAILED",
            "reading Server.ServerRedundancy.ServerUriArray failed",
            std::string{srcDiscoveryUriRead});
          self.set_state(RedundancyManagerState::Dormant);
          self.fire_discovery_ack(VoidResult{});
          return;
        }

        std::vector<std::string> uris;
        const ua::DataValue& value = result.value().front();
        if (!data_value_not_good(value) && value.value().is_array_of_string())
        {
          const auto& array = value.value().as<ua::Array<ua::String>>();
          uris.reserve(array.size());
          for (const auto& uri : array)
          {
            uris.emplace_back(static_cast<std::string_view>(uri));
          }
        }

        const bool arrayWasEmpty = uris.empty();
        if (arrayWasEmpty)
        {
          // Spec mandates the active server appear in the array; a server bug that omits it is a "redundant
          // set of one"  -  advisory, monitor the active only (CL-REDUN-002).
          self.advisory("REDUNDANCY_SERVERURIARRAY_EMPTY",
            "Server.ServerRedundancy.ServerUriArray is empty",
            std::string{srcServerUriEmpty});
        }
        self.mServerUriArray = std::move(uris);
        if (!self.mActiveUri.empty() &&
            std::find(self.mServerUriArray.begin(), self.mServerUriArray.end(), self.mActiveUri) ==
              self.mServerUriArray.end())
        {
          if (!arrayWasEmpty)
          {
            // Defensive: the array was non-empty but omitted the active server (a spec violation)  -  advise
            // separately from the fully-empty case, then still append the active so it is monitored.
            self.advisory("REDUNDANCY_SERVERURIARRAY_MISSING_SELF",
              "the active server is absent from a non-empty Server.ServerRedundancy.ServerUriArray",
              std::string{srcServerUriMissingSelf});
          }
          self.mServerUriArray.push_back(self.mActiveUri);
        }
        self.discovery_find_servers(generation);
      }));
}

void RedundancyManagerImpl::discovery_find_servers(std::uint64_t generation)
{
  mHost->find_servers_async(ua::client::FindServersOptions{},
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation](RedundancyManagerImpl& self, RedundancyManagerHost::FindServersResult result)
      {
        if (!self.is_current(generation))
        {
          return;
        }

        // Merge-not-replace (CL-REDUN-006): ensure every array URI has a candidate; keep existing entries.
        for (const std::string& uri : self.mServerUriArray)
        {
          auto& candidate = self.mCandidates[uri];
          candidate.serverUri = uri;
        }

        if (result.is_good())
        {
          for (const ua::ApplicationDescription& description : result.value())
          {
            const std::string appUri = static_cast<std::string>(description.application_uri());
            auto found = self.mCandidates.find(appUri);
            if (found == self.mCandidates.end())
            {
              continue;  // a server not in our array (CL-REDUN-003 matches applicationUri against the array)
            }
            found->second.applicationDescription = description;
            for (const auto& url : description.discovery_urls())
            {
              const std::string discoveryUrl = static_cast<std::string>(url);
              auto& urls = found->second.discoveryUrls;
              if (std::find(urls.begin(), urls.end(), discoveryUrl) == urls.end())
              {
                urls.push_back(discoveryUrl);  // union; a partial FindServers never drops a cached URL
              }
            }
          }
        }
        else
        {
          self.advisory(
            "REDUNDANCY_FINDSERVERS_FAILED", "FindServers translation failed", std::string{srcFindServers});
        }

        for (auto& entry : self.mCandidates)
        {
          entry.second.isActive = (entry.first == self.mActiveUri);
        }
        // H4: evict candidates whose URI left the current ServerUriArray  -  a server rotating its array each
        // reconnect would otherwise accrete candidates without bound. The active is always kept (even if the
        // server omitted it, it was re-appended above).
        for (auto it = self.mCandidates.begin(); it != self.mCandidates.end();)
        {
          const bool inArray =
            std::find(self.mServerUriArray.begin(), self.mServerUriArray.end(), it->first) !=
            self.mServerUriArray.end();
          if (!inArray && it->first != self.mActiveUri)
          {
            it = self.mCandidates.erase(it);
          }
          else
          {
            ++it;
          }
        }
        self.discovery_install_monitor(generation, 0);
      }));
}

void RedundancyManagerImpl::discovery_install_monitor(std::uint64_t generation, int attempt)
{
  ua::client::MonitorRequest request;
  request.nodeId = ua::NodeId{ua::VariableId::Server_ServiceLevel};
  request.attribute = ua::AttributeId::Value;
  request.samplingIntervalMs = 0.0;

  ua::client::DataChangeCallback onData = ua::async::post_borrowing_repeating(this,
    mStrand,
    mLogger,
    [generation](RedundancyManagerImpl& self, ua::client::DataChangeEvent event)
    { self.on_servicelevel_sample(generation, event); });

  mHost->monitor_attribute_async(std::move(request),
    std::move(onData),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation, attempt](RedundancyManagerImpl& self, Result<ua::client::MonitoredItem> result)
      {
        if (!self.is_current(generation))
        {
          // Superseded mid-install (a reconnect / new discovery / session-close landed while the
          // CreateMonitoredItems round-trip was in flight): CANCEL the MonitoredItem we just created rather
          // than drop it  -  a dropped stale MI orphans a MonitoredItem on the transfer-surviving
          // ServiceLevel Subscription (section 8.11.6). The `&& mHost` guard is required: is_current() is
          // ALSO false once mState == Closed, and do_close() resets mHost to null (line ~1188)  -  so on a
          // close-during-install race mHost is gone here. In that Closed case the just-created MI is
          // reclaimed by the connection/session teardown anyway, so skipping the cancel is the correct
          // best-effort (matches the other mHost sites' `if (mHost)` guard and the do_close "no post-close
          // handler touches mHost" invariant).
          if (result.has_value() && self.mHost)
          {
            self.mHost->cancel_monitored_item_async(result.value(), [](VoidResult) {});
          }
          return;
        }
        // A MonitoredItem created with a Good subcode or an Uncertain code exists on the server and is kept;
        // each ServiceLevel sample is judged by its own status.
        if (!result.has_value())
        {
          if (attempt == 0)
          {
            self.discovery_install_monitor(generation, 1);  // one retry (section 8.11.6)
            return;
          }
          self.advisory("REDUNDANCY_SERVICELEVEL_MI_INSTALL_FAILED",
            "installing the active Server.ServiceLevel MonitoredItem failed",
            std::string{srcMiInstall});
          self.set_state(RedundancyManagerState::Dormant);
          self.fire_discovery_ack(VoidResult{});
          return;
        }
        self.mServiceLevelHandle = result.value();
        self.mServiceLevelHistory.clear();
        self.mServiceLevelBadSince.reset();
        self.enter_monitoring(generation);
      }));
}

void RedundancyManagerImpl::enter_monitoring(std::uint64_t /*generation*/)
{
  mDegradedNotified = false;  // M7: a fresh monitoring epoch starts a new degrade episode
  set_state(RedundancyManagerState::Monitoring);
  mHost->fire_observer_redundancy_recovered(mActiveUri);
  fire_discovery_ack(VoidResult{});
}

// ---- monitoring / hysteresis (section 8.11.4) ----

void RedundancyManagerImpl::on_servicelevel_sample(
  std::uint64_t generation, const ua::client::DataChangeEvent& event)
{
  if (!is_current(generation))
  {
    return;  // stale MI from a superseded discovery / mode flip
  }

  std::uint8_t level = 0;
  const bool good = decode_service_level(event.value, level);

  if (!good)
  {
    if (!mServiceLevelBadSince.has_value())
    {
      mServiceLevelBadSince = mNowFn();
      // H3: an OPC-UA MonitoredItem is change-only  -  a stays-Bad active delivers Bad once then goes silent.
      // Arm a one-shot window timer so the "MI Bad for hysteresisWindow" degrade fires even without a second
      // delivery. Cancelled on the next Good delivery (below) / close.
      if (mState == RedundancyManagerState::Monitoring)
      {
        arm_inaccessible_window(generation);
      }
    }
    publish_snapshot();
    return;
  }

  mServiceLevelBadSince.reset();
  mInaccessibleTimer.cancel();  // H3: a fresh Good delivery ends the Bad window
  if (level >= mPolicy.healthyThreshold)
  {
    mDegradedNotified =
      false;  // M7: the active is healthy again  -  a future degrade may fire on its own edge
  }
  if (!mActiveUri.empty())
  {
    auto& candidate = mCandidates[mActiveUri];
    candidate.serverUri = mActiveUri;
    candidate.isActive = true;
    candidate.lastServiceLevel = level;
    candidate.lastProbeAt = mNowFn();
  }
  // M9: with hysteresisRingCapacity == 0 the ring is disabled; do NOT accumulate history (it would otherwise
  // grow without bound as the deque is never trimmed).
  if (mPolicy.hysteresisRingCapacity > 0)
  {
    mServiceLevelHistory.push_back(ServiceLevelSample{mNowFn(), level});
    while (mServiceLevelHistory.size() > mPolicy.hysteresisRingCapacity)
    {
      mServiceLevelHistory.pop_front();
    }
  }
  publish_snapshot();

  if (mState == RedundancyManagerState::Monitoring && mPolicy.hysteresisRingCapacity > 0 &&
      mServiceLevelHistory.size() >= mPolicy.hysteresisRingCapacity)
  {
    const bool allBelow = std::all_of(mServiceLevelHistory.begin(),
      mServiceLevelHistory.end(),
      [this](const ServiceLevelSample& sample) { return sample.level < mPolicy.healthyThreshold; });
    if (allBelow)
    {
      enter_scoring(RedundancyDegradeReason::ServiceLevelBelowHealthy, std::nullopt);
    }
  }
}

// ---- scoring / failover (section 8.11.4) ----

void RedundancyManagerImpl::enter_scoring(RedundancyDegradeReason reason,
  std::optional<std::string> manualTarget, std::shared_ptr<const ua::ErrorDetail> causeChain,
  std::optional<ua::StatusCode> reasonCode)
{
  mCurrentDegradeReason = reason;
  // H5: remember the inner cause + reason for begin_failover. Reset on every entry (null for the
  // ServiceLevel-driven paths) so a prior transport-fatal chain never leaks into a later degrade.
  mDegradeCauseChain = std::move(causeChain);
  mDegradeReasonCode = reasonCode;

  // M6: a ServiceLevel MI gone inaccessible leaves the active's cached lastServiceLevel at its last GOOD
  // value; if left stale-high, scoring's Degraded/Unknown fallback branches can never abandon the dead
  // active. Reset it so activeLevel becomes 0 and a strictly-better (even Degraded) backup can be selected.
  if (reason == RedundancyDegradeReason::ServiceLevelInaccessible && !mActiveUri.empty())
  {
    auto active = mCandidates.find(mActiveUri);
    if (active != mCandidates.end())
    {
      active->second.lastServiceLevel = std::nullopt;
    }
  }

  set_state(RedundancyManagerState::ScoringBackups);
  // M7: fire on_redundancy_degraded only on the Monitoring to ScoringBackups edge  -  not on an immediate
  // re-entry from a no-eligible return within the same unresolved degrade episode (that would storm the
  // observer).
  if (!mDegradedNotified)
  {
    mHost->fire_observer_redundancy_degraded(mActiveUri, reason);
    mDegradedNotified = true;
  }

  if (manualTarget.has_value())
  {
    begin_failover(std::move(*manualTarget), reason);  // force_switch: skip probes
    return;
  }
  probe_fanout(mGeneration);
}

void RedundancyManagerImpl::probe_fanout(std::uint64_t generation)
{
  mPendingProbes.clear();

  // Rank non-active, probable candidates by lastProbeAt ascending (oldest / never-probed first).
  std::vector<std::string> probable;
  for (const auto& entry : mCandidates)
  {
    if (!entry.second.isActive && !entry.second.discoveryUrls.empty())
    {
      probable.push_back(entry.first);
    }
  }
  std::sort(probable.begin(),
    probable.end(),
    [this](const std::string& lhs, const std::string& rhs)
    {
      const auto& left = mCandidates.at(lhs).lastProbeAt;
      const auto& right = mCandidates.at(rhs).lastProbeAt;
      if (left.has_value() != right.has_value())
      {
        return !left.has_value();  // never-probed sorts first
      }
      if (left.has_value() && right.has_value() && left->value() != right->value())
      {
        return left->value() < right->value();
      }
      return lhs < rhs;  // deterministic
    });
  if (probable.size() > mPolicy.probeFanout)
  {
    probable.resize(mPolicy.probeFanout);
  }

  for (const std::string& uri : probable)
  {
    mPendingProbes.insert(uri);
  }

  if (mPendingProbes.empty())
  {
    run_scoring();  // nothing probable  -  score on whatever cached data exists
    return;
  }

  // H1: bound the fanout so a backup whose probe never calls back cannot pin the FSM in ScoringBackups.
  arm_probe_deadline(generation);

  for (const std::string& uri : probable)
  {
    const std::string discoveryUrl = mCandidates.at(uri).discoveryUrls.front();
    mHost->probe_backup_servicelevel_async(discoveryUrl,
      ua::async::post_borrowing(this,
        mStrand,
        mLogger,
        [generation, uri](RedundancyManagerImpl& self, Result<std::uint8_t> result)
        { self.on_probe_reply(generation, uri, std::move(result)); }));
  }
}

void RedundancyManagerImpl::on_probe_reply(
  std::uint64_t generation, std::string serverUri, Result<std::uint8_t> result)
{
  if (!is_current(generation) || mState != RedundancyManagerState::ScoringBackups)
  {
    return;
  }
  auto& candidate = mCandidates[serverUri];
  candidate.serverUri = serverUri;
  candidate.lastProbeAt = mNowFn();
  candidate.lastServiceLevel = result.is_good() ? std::optional<std::uint8_t>{result.value()} : std::nullopt;
  if (result.is_bad())
  {
    // M8: a per-backup probe failure is plausibly benign (a backup being unreachable is expected) but must
    // not be dropped silently  -  surface it as an advisory chaining the probe's own ErrorDetail.
    advisory(std::shared_ptr<const ua::ErrorDetail>{ua::ErrorDetail::build(
      "REDUNDANCY_PROBE_FAILED", "Backup ServiceLevel probe failed", std::string{srcProbeFailed})
                                                      .context(ua::ContextKeys::uri, serverUri)
                                                      .cause(result.status_code())});
  }
  mPendingProbes.erase(serverUri);
  publish_snapshot();

  if (mPendingProbes.empty())
  {
    mProbeDeadlineTimer.cancel();  // H1: all probes replied before the deadline
    run_scoring();
  }
}

void RedundancyManagerImpl::run_scoring()
{
  if (mState != RedundancyManagerState::ScoringBackups)
  {
    return;
  }

  const std::uint8_t activeLevel = active_service_level_or_zero();

  const RedundantCandidate* best = nullptr;
  for (const auto& entry : mCandidates)
  {
    const RedundantCandidate& candidate = entry.second;
    if (candidate.isActive)
    {
      continue;
    }
    if (best == nullptr)
    {
      best = &candidate;
      continue;
    }
    // argmax_lex on (tier, serviceLevel, lastProbeAt [newer wins], serverUri [smaller wins]).
    const Tier candidateTier = tier_of(candidate, mPolicy.healthyThreshold);
    const Tier bestTier = tier_of(*best, mPolicy.healthyThreshold);
    if (candidateTier != bestTier)
    {
      if (candidateTier > bestTier)
      {
        best = &candidate;
      }
      continue;
    }
    const std::uint8_t candidateLevel = candidate.lastServiceLevel.value_or(0);
    const std::uint8_t bestLevel = best->lastServiceLevel.value_or(0);
    if (candidateLevel != bestLevel)
    {
      if (candidateLevel > bestLevel)
      {
        best = &candidate;
      }
      continue;
    }
    const bool candidateNewer =
      candidate.lastProbeAt.has_value() &&
      (!best->lastProbeAt.has_value() || candidate.lastProbeAt->value() > best->lastProbeAt->value());
    const bool sameProbeAt =
      candidate.lastProbeAt.has_value() == best->lastProbeAt.has_value() &&
      (!candidate.lastProbeAt.has_value() || candidate.lastProbeAt->value() == best->lastProbeAt->value());
    if (candidateNewer)
    {
      best = &candidate;
    }
    else if (sameProbeAt && candidate.serverUri < best->serverUri)
    {
      best = &candidate;
    }
  }

  bool eligible = false;
  std::string bestUri;
  std::uint8_t bestLevel = 0;
  if (best != nullptr)
  {
    bestUri = best->serverUri;
    bestLevel = best->lastServiceLevel.value_or(0);
    const Tier bestTier = tier_of(*best, mPolicy.healthyThreshold);
    if (bestTier == Tier::Healthy)
    {
      eligible = true;
    }
    else if (bestTier == Tier::Degraded)
    {
      eligible = mPolicy.fallbackToDegraded && best->lastServiceLevel.value_or(0) > activeLevel;
    }
    else  // Unknown
    {
      eligible = mPolicy.fallbackToDegraded && activeLevel == 0;
    }
  }

  if (best == nullptr || !eligible)
  {
    // The best_candidate / best_level / active_level facts are carried in the summary string rather
    // than as structured ErrorDetail::context() keys. Section 8.11.5's structured form awaits a
    // ContextKey-vocabulary decision, the enum being potentially closed.
    advisory("REDUNDANCY_NO_ELIGIBLE_CANDIDATE",
      "no eligible failover candidate (best=" + (best == nullptr ? std::string{"<none>"} : bestUri) +
        ", best_level=" + std::to_string(bestLevel) + ", active_level=" + std::to_string(activeLevel) + ")",
      std::string{srcNoEligible});
    // M7: require a FRESH full ring before re-entering scoring  -  otherwise every subsequent below-healthy
    // sample would immediately re-enter (and re-probe) here. mDegradedNotified stays set: this is still the
    // same unresolved degrade episode, so on_redundancy_degraded must not re-fire on the next scoring pass.
    mServiceLevelHistory.clear();
    set_state(RedundancyManagerState::Monitoring);
    return;
  }

  begin_failover(bestUri, mCurrentDegradeReason);
}

void RedundancyManagerImpl::begin_failover(std::string targetUri, RedundancyDegradeReason reason)
{
  const std::string fromUri = mActiveUri;
  const std::string toUri = targetUri;
  mFailoverTarget = targetUri;
  set_state(RedundancyManagerState::FailingOver);

  ua::client::ReconnectCause cause = ua::client::RedundancySwitchInfo{mEffectiveMode, fromUri, toUri};
  mHost->fire_observer_redundancy_failover_started(fromUri, toUri, cause);

  // H5: thread the reason + inner cause captured at enter_scoring (e.g. the transport-fatal chain) into the
  // degrade detail. For the ServiceLevel-driven paths both are absent  to  mapped status + null cause (root).
  const StatusCode degradeCode = mDegradeReasonCode.value_or(StatusCode{degrade_status(reason)});
  std::shared_ptr<const ua::ErrorDetail> degradeChain = ua::make_error_detail(
    "REDUNDANCY_FAILOVER", "redundancy failover initiated", std::string{srcFailover}, mDegradeCauseChain);

  const std::uint64_t generation = mGeneration;
  const ua::RedundancySupport mode = mEffectiveMode;
  const std::uint64_t failoverCountAtKick = mFailoverCount;

  mHost->trigger_reconnect_async(std::move(cause),
    degradeCode,
    std::move(degradeChain),
    ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [generation, reason, mode, fromUri, toUri, failoverCountAtKick](
        RedundancyManagerImpl& self, VoidResult result)
      {
        if (!self.is_current(generation) || self.mState != RedundancyManagerState::FailingOver)
        {
          return;
        }
        if (result.is_good())
        {
          return;  // FSM reached Active  -  RecoveryWindow is driven by on_reconnect_completed_async
        }

        // Terminal: FSM exhausted maxAttempts (section 8.11.5 error-chain shape).
        const std::string summary = "Failover to " + toUri + " failed: FSM exhausted (from=" + fromUri +
                                    ", mode=" + ua::to_string(mode) +
                                    ", reason=" + std::string{reason_name(reason)} +
                                    ", failover_count=" + std::to_string(failoverCountAtKick) + ")";
        std::shared_ptr<const ua::ErrorDetail> chain = ua::ErrorDetail::build(
          "REDUNDANCY_FAILOVER_FAILED", "Redundancy failover failed", std::string{srcFailover})
                                                         .context(ua::ContextKeys::errorMessage, summary)
                                                         .cause(result.status_code());
        self.mLastFailoverError = chain;
        self.set_state(RedundancyManagerState::Monitoring);
        if (self.mForceSwitchPending.has_value())
        {
          self.deliver_void(std::move(self.mForceSwitchPending->callback),
            VoidResult{StatusCode{Status::BadConnectionClosed, chain}});
          self.mForceSwitchPending.reset();
        }
        self.publish_snapshot();
      }));
}

void RedundancyManagerImpl::arm_recovery_window(std::uint64_t generation)
{
  mRecoveryWindowTimer.expires_after(mPolicy.recoveryWindow);
  mRecoveryWindowTimer.async_wait(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](RedundancyManagerImpl& self, const boost::system::error_code& error)
    {
      if (error)
      {
        return;  // operation_aborted (close / re-arm)
      }
      if (!self.is_current(generation) || self.mState != RedundancyManagerState::RecoveryWindow)
      {
        return;
      }
      self.start_discovery({});  // re-run discovery against the new active (may detect a mode change)
    }));
}

void RedundancyManagerImpl::arm_probe_deadline(std::uint64_t generation)
{
  // H1: on expiry, every probe still outstanding is treated as timed-out (level  to  unknown) and scoring
  // runs on whatever replied  -  so a hung backup cannot pin the FSM in ScoringBackups. Bound to mStrand;
  // weak-captured and generation-guarded.
  mProbeDeadlineTimer.expires_after(mPolicy.probeTimeout);
  mProbeDeadlineTimer.async_wait(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](RedundancyManagerImpl& self, const boost::system::error_code& error)
    {
      if (error)
      {
        return;  // operation_aborted (probes replied / re-armed / close)
      }
      if (!self.is_current(generation) || self.mState != RedundancyManagerState::ScoringBackups)
      {
        return;
      }
      for (const std::string& uri : self.mPendingProbes)
      {
        auto& candidate = self.mCandidates[uri];
        candidate.serverUri = uri;
        candidate.lastServiceLevel = std::nullopt;
        candidate.lastProbeAt = self.mNowFn();
      }
      self.advisory(std::shared_ptr<const ua::ErrorDetail>{
        ua::ErrorDetail::build("REDUNDANCY_PROBE_TIMEOUT",
          "Backup ServiceLevel probes exceeded their timeout in milliseconds",
          std::string{srcProbeTimeout})
          .context(ua::ContextKeys::limit, self.mPolicy.probeTimeout.count())
          .cause(ua::StatusCode{ua::Status::BadTimeout})});
      self.mPendingProbes.clear();
      self.run_scoring();
    }));
}

void RedundancyManagerImpl::arm_inaccessible_window(std::uint64_t generation)
{
  // H3: fires once the active's ServiceLevel MI has been Bad for hysteresisWindow, even if the change-only MI
  // never delivers a second Bad. Bound to mStrand; weak-captured and generation-guarded; cancelled on the
  // next Good delivery / close.
  mInaccessibleTimer.expires_after(mPolicy.hysteresisWindow);
  mInaccessibleTimer.async_wait(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [generation](RedundancyManagerImpl& self, const boost::system::error_code& error)
    {
      if (error)
      {
        return;  // operation_aborted (recovered / re-armed / close)
      }
      if (!self.is_current(generation) || self.mState != RedundancyManagerState::Monitoring ||
          !self.mServiceLevelBadSince.has_value())
      {
        return;  // recovered, superseded, or no longer monitoring
      }
      self.enter_scoring(RedundancyDegradeReason::ServiceLevelInaccessible, std::nullopt);
    }));
}

// ---- force_switch / close (section 8.11.4) ----

void RedundancyManagerImpl::do_force_switch(
  std::string targetServerUri, std::function<void(VoidResult)> callback)
{
  if (mState == RedundancyManagerState::RecoveryWindow)
  {
    deliver_void(std::move(callback),
      VoidResult{StatusCode{Status::BadInvalidState,
        ua::make_error_detail("REDUNDANCY_FORCE_SWITCH_RECOVERY_WINDOW",
          "force_switch rejected during the post-failover RecoveryWindow",
          std::string{srcForceRecovery})}});
    return;
  }
  if (targetServerUri == mActiveUri)
  {
    deliver_void(std::move(callback), VoidResult{});  // already active  -  no-op Good
    return;
  }
  if (std::find(mServerUriArray.begin(), mServerUriArray.end(), targetServerUri) == mServerUriArray.end())
  {
    deliver_void(std::move(callback),
      VoidResult{StatusCode{Status::BadNotFound,
        ua::make_error_detail("REDUNDANCY_FORCE_SWITCH_UNKNOWN",
          "force_switch target is not in the server-uri array",
          std::string{srcForceUnknown})}});
    return;
  }
  if (mState != RedundancyManagerState::Monitoring)
  {
    deliver_void(std::move(callback),
      VoidResult{StatusCode{Status::BadInvalidState,
        ua::make_error_detail("REDUNDANCY_FORCE_SWITCH_INVALID_STATE",
          "force_switch is only valid while Monitoring",
          std::string{srcForceInvalid})}});
    return;
  }

  mForceSwitchPending = PendingForceSwitch{targetServerUri, std::move(callback)};
  enter_scoring(RedundancyDegradeReason::ForceSwitchRequested, std::move(targetServerUri));
}

void RedundancyManagerImpl::do_close(std::function<void(VoidResult)> callback)
{
  if (mState == RedundancyManagerState::Closed)
  {
    // Idempotent: the host has already been released (below); a second close must not touch it. A teardown
    // that races an earlier close is still a successful close.
    deliver_void(std::move(callback), VoidResult{});
    return;
  }
  ++mGeneration;  // invalidate every in-flight tier-1 callback
  mRecoveryWindowTimer.cancel();
  mProbeDeadlineTimer.cancel();
  mInaccessibleTimer.cancel();
  mPendingProbes.clear();
  if (mForceSwitchPending.has_value())
  {
    deliver_void(
      std::move(mForceSwitchPending->callback), VoidResult{StatusCode{Status::BadRequestCancelledByClient}});
    mForceSwitchPending.reset();
  }
  if (mServiceLevelHandle.has_value())
  {
    mHost->cancel_monitored_item_async(*mServiceLevelHandle, [](VoidResult) {});
    mServiceLevelHandle.reset();
  }
  if (mDiscoveryAck)
  {
    deliver_void(std::move(mDiscoveryAck), VoidResult{});
  }
  set_state(RedundancyManagerState::Closed);  // final publish through mHost
  deliver_void(std::move(callback), VoidResult{});
  // Defensive: release the host after the final Closed publish  -  structurally closes the latent host and
  // manager cycle regardless of the deferred shim's ref shape. Every post-close handler early-returns via
  // is_current() (Closed) before it would touch mHost, and a second close short-circuits above.
  mHost.reset();
}

// ---- helpers ----

bool RedundancyManagerImpl::is_current(std::uint64_t generation) const noexcept
{
  return mGeneration == generation && mState != RedundancyManagerState::Closed;
}

ua::RedundancySupport RedundancyManagerImpl::derive_effective_mode(ua::RedundancySupport advertised) const
{
  if (!mPolicy.overrideMode.has_value())
  {
    return advertised;
  }
  if (advertised == ua::RedundancySupport::HotAndMirrored)
  {
    return ua::RedundancySupport::HotAndMirrored;  // sticky  -  override ignored (CL-REDUN-007)
  }

  // Downgrade-only on the Cold(1) <= Warm(2) <= Hot(3) <= HotAndMirrored(4) scale.
  auto rank = [](ua::RedundancySupport mode) -> int
  {
    switch (mode)
    {
    case ua::RedundancySupport::Cold:
      return 1;
    case ua::RedundancySupport::Warm:
      return 2;
    case ua::RedundancySupport::Hot:
      return 3;
    case ua::RedundancySupport::HotAndMirrored:
      return 4;
    default:
      return 0;  // None / Transparent are off-scale
    }
  };
  const ua::RedundancySupport override = *mPolicy.overrideMode;
  if (rank(override) >= 1 && rank(override) <= rank(advertised))
  {
    return override;
  }
  return advertised;  // upgrade attempt / off-scale override silently ignored
}

void RedundancyManagerImpl::set_state(RedundancyManagerState state)
{
  mState = state;
  publish_snapshot();
}

void RedundancyManagerImpl::publish_snapshot()
{
  auto info = std::make_shared<RedundancyInfo>();
  info->mode = mEffectiveMode;
  info->candidates.reserve(mCandidates.size());
  for (const auto& entry : mCandidates)
  {
    info->candidates.push_back(entry.second);
  }
  if (auto active = mCandidates.find(mActiveUri); active != mCandidates.end())
  {
    info->activeServiceLevel = active->second.lastServiceLevel;
  }
  info->lastFailoverAt = mLastFailoverAt;
  info->failoverCount = mFailoverCount;
  info->state = mState;
  info->lastFailoverError = mLastFailoverError;

  std::shared_ptr<const RedundancyInfo> shared = std::move(info);
  mInfoSnapshot.store(shared, std::memory_order_release);
  if (mHost)  // defensive: the host is released after the final Closed publish (do_close)
  {
    mHost->publish_info_snapshot(shared);
  }
}

void RedundancyManagerImpl::deliver_void(std::function<void(VoidResult)> callback, VoidResult result)
{
  if (!callback)
  {
    return;
  }
  boost::asio::post(mExecutor,
    ua::async::guarded(mLogger,
      [callback = std::move(callback), result = std::move(result)]() mutable
      { callback(std::move(result)); }));
}

void RedundancyManagerImpl::advisory(std::string code, std::string summary, std::string source)
{
  advisory(std::shared_ptr<const ua::ErrorDetail>{
    ua::ErrorDetail::build(std::move(code), "Redundancy manager advisory", std::move(source))
      .context(ua::ContextKeys::errorMessage, summary)});
}

void RedundancyManagerImpl::advisory(std::shared_ptr<const ua::ErrorDetail> detail)
{
  if (mHost)  // defensive: the host is released after the final Closed publish (do_close)
  {
    mHost->fire_observer_advisory_diagnostic(std::move(detail));
  }
}

std::uint8_t RedundancyManagerImpl::active_service_level_or_zero() const
{
  if (auto active = mCandidates.find(mActiveUri); active != mCandidates.end())
  {
    return active->second.lastServiceLevel.value_or(0);
  }
  return 0;
}

void RedundancyManagerImpl::fire_discovery_ack(VoidResult result)
{
  if (mDiscoveryAck)
  {
    deliver_void(std::move(mDiscoveryAck), std::move(result));
    mDiscoveryAck = nullptr;
  }
}

}  // namespace ua::client::detail

// ---- public RedundancyManager move-only pimpl facade (section 8.11.1) ----

namespace ua::client
{

RedundancyManager::RedundancyManager(std::shared_ptr<detail::RedundancyManagerImpl> impl) noexcept
  : mImpl(std::move(impl))
{}

RedundancyManager::RedundancyManager(RedundancyManager&&) noexcept = default;
RedundancyManager& RedundancyManager::operator=(RedundancyManager&&) noexcept = default;
RedundancyManager::~RedundancyManager() = default;

std::shared_ptr<const RedundancyInfo> RedundancyManager::redundancy_info() const noexcept
{
  if (!mImpl)
  {
    return std::make_shared<const RedundancyInfo>();
  }
  return mImpl->redundancy_info();
}

std::optional<std::string> RedundancyManager::current_active_endpoint() const noexcept
{
  if (!mImpl)
  {
    return std::nullopt;
  }
  return mImpl->current_active_endpoint();
}

void RedundancyManager::force_switch_async(
  std::string targetServerUri, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    if (callback)
    {
      callback(ua::VoidResult{ua::StatusCode{ua::Status::BadConnectionClosed}});
    }
    return;
  }
  mImpl->force_switch_async(std::move(targetServerUri), std::move(callback));
}

void RedundancyManager::close_async(std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    if (callback)
    {
      callback(ua::VoidResult{});
    }
    return;
  }
  mImpl->close_async(std::move(callback));
}

}  // namespace ua::client
