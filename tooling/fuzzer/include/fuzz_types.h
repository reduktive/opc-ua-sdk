// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_TYPES_H
#define FUZZ_TYPES_H

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace fuzz
{

// --- Layer and service enums ---

enum class FuzzLayer
{
  Raw,  // Layer 1: raw TCP bytes
  TransportFraming,  // Layer 2: HEL/ACK/MSG framing
  SecureChannel,  // Layer 3: OPN handshake, token negotiation
  MessageEncoding,  // Layer 4: encoded service request bytes
  Service  // Layer 5: public session API with fuzzed args
};

enum class FuzzService
{
  Read,
  Browse,
  BrowseNext,
  Write,
  Call,
  TranslateBrowsePaths,
  RegisterNodes,
  UnregisterNodes,
  CreateSubscription,
  ModifySubscription,
  DeleteSubscriptions,
  SetPublishingMode,
  CreateMonitoredItems,
  ModifyMonitoredItems,
  DeleteMonitoredItems,
  SetMonitoringMode,
  AddNodes,
  AddReferences,
  DeleteNodes,
  DeleteReferences,
  FindServers,
  GetEndpoints
};

// --- Mutation strategies ---

enum class MutationStrategy
{
  BitFlip,
  ByteFlip,
  BoundaryCorrupt,
  LengthTamper,
  EdgeIntegerInject,
  EdgeInt16Inject,
  BlockDelete,
  BlockDuplicate,
  BlockShuffle,
  NullRun,
  HighByteRun,
  FormatStringInject,
  EncodingPrefixSwap
};

// --- Finding classification ---

enum class FindingClass
{
  // Security
  SecurityCrash,
  SecurityHang,
  SecurityUnexpectedDisconnect,
  SecurityAsanViolation,
  SecurityAuthBypass,
  SecurityPrivEscalation,
  SecurityDosDegradation,
  SecurityStateMachineViolation,
  SecurityReplayAccepted,

  // Behavioural
  BehaviourUnexpectedStatus,
  BehaviourNondeterministic,
  BehaviourSpecViolation,
  BehaviourMalformedResponse,
  BehaviourUnhandledException,

  // Performance
  PerfLatencySpike,
  PerfLatencyDrift,
  PerfThroughputDegradation,
  PerfSlowHandshake,

  // Memory & resource
  MemoryLeak,
  MemoryLeakSlow,
  ResourceLeakSession,
  ResourceLeakChannel,
  ResourceLeakSubscription,
  ResourceLeakFd
};

enum class FindingSeverity
{
  Critical,
  High,
  Medium,
  Low
};

FindingSeverity default_severity(FindingClass cls);

const char* to_string(FuzzLayer layer);
const char* to_string(FuzzService service);
const char* to_string(MutationStrategy strategy);
const char* to_string(FindingClass cls);
const char* to_string(FindingSeverity severity);

// --- Core data structures ---

struct Finding
{
  uint32_t id{0};
  FindingClass findingClass{FindingClass::BehaviourUnexpectedStatus};
  FindingSeverity severity{FindingSeverity::Medium};
  FuzzLayer layer{FuzzLayer::Service};
  FuzzService service{FuzzService::Read};
  MutationStrategy strategy{MutationStrategy::BitFlip};
  std::string description;
  uint64_t caseNumber{0};
  std::chrono::system_clock::time_point timestamp;
  uint64_t latencyUs{0};
  bool connectionDropped{false};
  std::vector<uint8_t> triggerBytes;
};

struct FuzzResult
{
  uint32_t securityFindings{0};
  uint32_t memoryLeaks{0};
  uint32_t resourceLeaks{0};
  uint32_t crashes{0};
  uint32_t criticalBehaviour{0};
  uint32_t perfFindings{0};
  uint64_t totalCases{0};
  /// Mutated cases the SDK answered with a Good status (R13). `crashes` and `securityFindings`
  /// measure robustness; these two measure REJECTION, which is the property a fuzz oracle owes.
  uint64_t acceptedMutations{0};
  uint64_t rejectedMutations{0};
  double elapsedSeconds{0.0};
  double casesPerSecond{0.0};
  std::string findingsDir;
};

struct FuzzCase
{
  FuzzLayer layer{FuzzLayer::Service};
  FuzzService service{FuzzService::Read};
  uint64_t caseNumber{0};
  std::vector<uint8_t> bytes;
  MutationStrategy mutationStrategy{MutationStrategy::BitFlip};
};

}  // namespace fuzz

#endif  // !FUZZ_TYPES_H
