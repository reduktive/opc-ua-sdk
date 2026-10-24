// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fuzz_types.h"

namespace fuzz
{

FindingSeverity default_severity(FindingClass cls)
{
  switch (cls)
  {
  case FindingClass::SecurityCrash:
  case FindingClass::SecurityAsanViolation:
  case FindingClass::SecurityAuthBypass:
  case FindingClass::SecurityPrivEscalation:
    return FindingSeverity::Critical;

  case FindingClass::SecurityHang:
  case FindingClass::SecurityUnexpectedDisconnect:
  case FindingClass::SecurityDosDegradation:
  case FindingClass::SecurityStateMachineViolation:
  case FindingClass::SecurityReplayAccepted:
  case FindingClass::MemoryLeak:
    return FindingSeverity::High;

  case FindingClass::BehaviourUnexpectedStatus:
  case FindingClass::BehaviourNondeterministic:
  case FindingClass::BehaviourSpecViolation:
  case FindingClass::BehaviourMalformedResponse:
  case FindingClass::BehaviourUnhandledException:
  case FindingClass::MemoryLeakSlow:
  case FindingClass::ResourceLeakSession:
  case FindingClass::ResourceLeakChannel:
  case FindingClass::ResourceLeakSubscription:
  case FindingClass::ResourceLeakFd:
    return FindingSeverity::Medium;

  case FindingClass::PerfLatencySpike:
  case FindingClass::PerfLatencyDrift:
  case FindingClass::PerfThroughputDegradation:
  case FindingClass::PerfSlowHandshake:
    return FindingSeverity::Low;
  }
  return FindingSeverity::Medium;
}

const char* to_string(FuzzLayer layer)
{
  switch (layer)
  {
  case FuzzLayer::Raw:
    return "raw";
  case FuzzLayer::TransportFraming:
    return "transport";
  case FuzzLayer::SecureChannel:
    return "channel";
  case FuzzLayer::MessageEncoding:
    return "message";
  case FuzzLayer::Service:
    return "service";
  }
  return "unknown";
}

const char* to_string(FuzzService service)
{
  switch (service)
  {
  case FuzzService::Read:
    return "Read";
  case FuzzService::Browse:
    return "Browse";
  case FuzzService::BrowseNext:
    return "BrowseNext";
  case FuzzService::Write:
    return "Write";
  case FuzzService::Call:
    return "Call";
  case FuzzService::TranslateBrowsePaths:
    return "TranslateBrowsePaths";
  case FuzzService::RegisterNodes:
    return "RegisterNodes";
  case FuzzService::UnregisterNodes:
    return "UnregisterNodes";
  case FuzzService::CreateSubscription:
    return "CreateSubscription";
  case FuzzService::ModifySubscription:
    return "ModifySubscription";
  case FuzzService::DeleteSubscriptions:
    return "DeleteSubscriptions";
  case FuzzService::SetPublishingMode:
    return "SetPublishingMode";
  case FuzzService::CreateMonitoredItems:
    return "CreateMonitoredItems";
  case FuzzService::ModifyMonitoredItems:
    return "ModifyMonitoredItems";
  case FuzzService::DeleteMonitoredItems:
    return "DeleteMonitoredItems";
  case FuzzService::SetMonitoringMode:
    return "SetMonitoringMode";
  case FuzzService::AddNodes:
    return "AddNodes";
  case FuzzService::AddReferences:
    return "AddReferences";
  case FuzzService::DeleteNodes:
    return "DeleteNodes";
  case FuzzService::DeleteReferences:
    return "DeleteReferences";
  case FuzzService::FindServers:
    return "FindServers";
  case FuzzService::GetEndpoints:
    return "GetEndpoints";
  }
  return "Unknown";
}

const char* to_string(MutationStrategy strategy)
{
  switch (strategy)
  {
  case MutationStrategy::BitFlip:
    return "BitFlip";
  case MutationStrategy::ByteFlip:
    return "ByteFlip";
  case MutationStrategy::BoundaryCorrupt:
    return "BoundaryCorrupt";
  case MutationStrategy::LengthTamper:
    return "LengthTamper";
  case MutationStrategy::EdgeIntegerInject:
    return "EdgeIntegerInject";
  case MutationStrategy::EdgeInt16Inject:
    return "EdgeInt16Inject";
  case MutationStrategy::BlockDelete:
    return "BlockDelete";
  case MutationStrategy::BlockDuplicate:
    return "BlockDuplicate";
  case MutationStrategy::BlockShuffle:
    return "BlockShuffle";
  case MutationStrategy::NullRun:
    return "NullRun";
  case MutationStrategy::HighByteRun:
    return "HighByteRun";
  case MutationStrategy::FormatStringInject:
    return "FormatStringInject";
  case MutationStrategy::EncodingPrefixSwap:
    return "EncodingPrefixSwap";
  }
  return "Unknown";
}

const char* to_string(FindingClass cls)
{
  switch (cls)
  {
  case FindingClass::SecurityCrash:
    return "SECURITY_CRASH";
  case FindingClass::SecurityHang:
    return "SECURITY_HANG";
  case FindingClass::SecurityUnexpectedDisconnect:
    return "SECURITY_UNEXPECTED_DISCONNECT";
  case FindingClass::SecurityAsanViolation:
    return "SECURITY_ASAN_VIOLATION";
  case FindingClass::SecurityAuthBypass:
    return "SECURITY_AUTH_BYPASS";
  case FindingClass::SecurityPrivEscalation:
    return "SECURITY_PRIV_ESCALATION";
  case FindingClass::SecurityDosDegradation:
    return "SECURITY_DOS_DEGRADATION";
  case FindingClass::SecurityStateMachineViolation:
    return "SECURITY_STATE_MACHINE_VIOLATION";
  case FindingClass::SecurityReplayAccepted:
    return "SECURITY_REPLAY_ACCEPTED";
  case FindingClass::BehaviourUnexpectedStatus:
    return "BEHAVIOUR_UNEXPECTED_STATUS";
  case FindingClass::BehaviourNondeterministic:
    return "BEHAVIOUR_NONDETERMINISTIC";
  case FindingClass::BehaviourSpecViolation:
    return "BEHAVIOUR_SPEC_VIOLATION";
  case FindingClass::BehaviourMalformedResponse:
    return "BEHAVIOUR_MALFORMED_RESPONSE";
  case FindingClass::BehaviourUnhandledException:
    return "BEHAVIOUR_UNHANDLED_EXCEPTION";
  case FindingClass::PerfLatencySpike:
    return "PERF_LATENCY_SPIKE";
  case FindingClass::PerfLatencyDrift:
    return "PERF_LATENCY_DRIFT";
  case FindingClass::PerfThroughputDegradation:
    return "PERF_THROUGHPUT_DEGRADATION";
  case FindingClass::PerfSlowHandshake:
    return "PERF_SLOW_HANDSHAKE";
  case FindingClass::MemoryLeak:
    return "MEMORY_LEAK";
  case FindingClass::MemoryLeakSlow:
    return "MEMORY_LEAK_SLOW";
  case FindingClass::ResourceLeakSession:
    return "RESOURCE_LEAK_SESSION";
  case FindingClass::ResourceLeakChannel:
    return "RESOURCE_LEAK_CHANNEL";
  case FindingClass::ResourceLeakSubscription:
    return "RESOURCE_LEAK_SUBSCRIPTION";
  case FindingClass::ResourceLeakFd:
    return "RESOURCE_LEAK_FD";
  }
  return "UNKNOWN";
}

const char* to_string(FindingSeverity severity)
{
  switch (severity)
  {
  case FindingSeverity::Critical:
    return "critical";
  case FindingSeverity::High:
    return "high";
  case FindingSeverity::Medium:
    return "medium";
  case FindingSeverity::Low:
    return "low";
  }
  return "unknown";
}

}  // namespace fuzz
