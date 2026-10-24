// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZER_CONFIG_H
#define FUZZER_CONFIG_H

#include "fuzz_types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace fuzz
{

struct FuzzerConfig
{
  struct Target
  {
    std::string endpoint{"opc.tcp://127.0.0.1:4840"};
    uint32_t timeoutMs{5000};
    bool outOfProcess{false};
  } target;

  struct Campaign
  {
    uint64_t maxCases{0};  // 0 = run forever
    std::vector<FuzzLayer> layers{FuzzLayer::Service};
    std::vector<FuzzService> services;  // empty = all
    std::string seedCorpusDir{"./corpus"};
    uint64_t rngSeed{0};  // 0 = random seed
  } campaign;

  struct Limits
  {
    uint32_t maxMessageSize{16 * 1024 * 1024};
    uint32_t maxStringLen{65535};
    uint32_t maxArrayLen{10000};
    uint32_t maxNestingDepth{32};
  } limits;

  struct Baseline
  {
    uint32_t samples{200};
    double latencyAlertMul{10.0};
    double latencyWarnMul{3.0};
  } baseline;

  struct Performance
  {
    uint32_t soakDurationS{3600};
    /// Raise the per-IP connection limits on a server started here.
    ///
    /// A load generator connects many times from one address, which is what the
    /// throttle exists to stop. Leaving it at its default caps any measurement at
    /// 29 connections per minute, so capacity runs set this deliberately - and the
    /// run records that they did, because it changes what the figures describe.
    bool relaxConnectionThrottling{false};
    /// Set the two per-IP throttle limits independently; 0 leaves the default.
    /// Needed to tell the concurrent cap and the attempt-rate limit apart, since
    /// raising both together cannot say which one refused a connection.
    uint32_t throttleMaxConnsPerIp{0};
    /// Node the load generator reads. A published throughput figure has to name
    /// the node it was taken against, and the default is not readable by every
    /// session, so this must be selectable.
    /// Admission ceilings for a capacity run; 0 leaves the shipped default.
    /// Raising these changes what a figure describes, so each is recorded in the
    /// results next to the numbers it made possible.
    uint32_t maxConnections{0};
    uint32_t maxSecureChannels{0};
    uint32_t maxSessions{0};
    uint16_t readNodeNs{0};
    uint32_t readNodeId{2258};
    /// Optional pool of nodes, one assigned per session round-robin. Reading a
    /// single node from every session serialises on that node's own reader-writer
    /// mutex, so a shared-node figure and a distinct-node figure measure different
    /// things and both must be taken to tell them apart.
    std::vector<uint32_t> readNodeIds;
    /// Generate this many simple scalar Int32 Variable nodes in namespace 1 at
    /// startup, numbered from generatedNodeBase. Cheap to read: a stored scalar
    /// with no external source, so the measurement is of the request path rather
    /// than of value production.
    uint32_t generateNodes{0};
    /// NodesToRead per Read request. OPC UA's Read service takes an array, and a
    /// real client batches; reading one attribute per request measures protocol and
    /// syscall overhead rather than read throughput.
    uint32_t nodesPerRead{1};
    /// Replace the default namespace with a lock-free array of immutable scalars, for measuring
    /// what the read path costs when the address space costs nothing. 0 = off; 1 = one shared_ptr
    /// control block per node; 2 = every identifier resolving to ONE node, which puts all reference
    /// counting on a single cache line deliberately. See `static_array_namespace.h`.
    uint32_t staticNamespace{0};
    /// Namespace index the load generator reads from. The static namespace is added after the
    /// server's own, so it does not land at 1 and the generator has to be told.
    uint16_t readNamespace{1};
    uint32_t throttleAttemptsPerMin{0};
    /// When set, no server is started in-process: the load generator drives an
    /// already-running server at this URL. This is how the client and the server
    /// end up on different machines.
    std::string attachEndpoint;
    /// Bind address used by --perf-serve.
    std::string listenAddress{"127.0.0.1:0"};
    /// Threads in the server's executor pool. 0 means hardware_concurrency().
    /// Sweeping this is how the core-scaling curve is produced: pool size is the
    /// only concurrency dial the SDK exposes.
    uint32_t serverThreads{0};
    std::vector<uint32_t> concurrencySteps{10, 50, 100};
    uint32_t loadSteps{10};
    std::vector<uint32_t> throughputConcurrency{1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100};

    uint32_t subscriptionSessionCount{5};
    uint32_t subscriptionsPerSession{10};
    uint32_t monitoredItemsPerSubscription{100};
    uint32_t subscriptionSoakDurationS{30};
    bool subscriptionChurnEnabled{true};
    /// Publishing interval in milliseconds; 0 keeps the rotating default set.
    /// Drives the message and transport rate.
    double subPublishingIntervalMs{0.0};
    /// Sampling interval in milliseconds; 0 means "same as the publishing interval",
    /// which is what the harness used to hardcode. Drives the polling rate, which is
    /// a different quantity from the publishing rate and has to be settable
    /// independently before either can be attributed.
    double subSamplingIntervalMs{0.0};
    /// Monitor the generated scalar nodes, one per item round-robin, instead of the
    /// single hardcoded Server_ServerStatus_CurrentTime. Generated nodes are static,
    /// so this also separates sampling cost from notification cost: the server samples
    /// them and nothing changes.
    bool subUseGeneratedNodes{false};
    /// MonitoredItem admission ceilings for a capacity run; 0 leaves the shipped
    /// default. The defaults (1000 per subscription, 1000 per call, 10000 per
    /// server) bound the item count well below what the sampling engine can
    /// plausibly sustain, so characterising the engine means raising them - and
    /// recording that the run did.
    uint32_t maxMonitoredItems{0};
    uint32_t maxMonitoredItemsPerSub{0};
    uint32_t maxMonitoredItemsPerCall{0};
    /// Sampling intervals rotated across subscriptions, one per subscription. The
    /// sampling engine buckets items by interval and ticks each bucket on its own
    /// strand, so spreading items over several intervals is the difference between
    /// one serialised tick and several concurrent ones. Empty uses
    /// subSamplingIntervalMs for every subscription.
    std::vector<double> subIntervalSet;
    /// MaxNotificationsPerPublish sent on CreateSubscription; 0 is the protocol's "unlimited",
    /// which is what the campaign ran with throughout. D19 showed an unlimited response can
    /// exceed the encoding limit and be lost, so this exists to test whether the protocol's own
    /// splitting mechanism avoids it.
    uint32_t subMaxNotificationsPerPublish{0};
    /// Measure notification delivery latency: DataValue::server_timestamp() against the client's
    /// receive time, corrected by a measured clock offset between the two hosts. One sample per
    /// Publish response rather than per data change, so the measurement cost does not scale with
    /// the notification rate.
    bool subMeasureLatency{false};
  } performance;

  // Single-threaded-server sync-blocking detection. When serverThreads == 1 the harness runs
  // the server on one executor thread; with detectSyncBlock a LivenessWatchdog heartbeats that
  // thread and fails the run if a handler blocks it synchronously (see liveness_watchdog.h).
  struct SyncBlock
  {
    int serverThreads{0};  // 0 = hardware concurrency; 1 = single-threaded server
    bool detectSyncBlock{false};  // enable the liveness watchdog
    uint32_t livenessDeadlineMs{2000};  // a heartbeat must be serviced within this
    uint32_t heartbeatIntervalMs{100};  // gap between successful heartbeats
  } syncBlock;

  struct Reporting
  {
    bool console{true};
    bool file{true};
    std::string outputDir{"./findings"};
    std::string corpusOutDir{"./corpus_out"};
    bool logAllResponses{false};
    bool saveAllCases{false};
    uint32_t consoleUpdateHz{2};
  } reporting;
};

/// Load config from a JSON file. Fields not present use defaults.
FuzzerConfig load_config(const std::string& path);

/// Print config to stdout for --print-config.
void print_config(const FuzzerConfig& config);

}  // namespace fuzz

#endif  // !FUZZER_CONFIG_H
