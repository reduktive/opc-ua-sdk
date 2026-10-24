# OPC UA Server Fuzzer — Product Specification v2.0

A security, behavioural, and performance fuzzing framework for the SDK's OPC UA server. Integrates directly with the
SDK's client stack at each protocol layer, so fuzzing at any layer gets all layers below it for free.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Fuzzing Layers](#3-fuzzing-layers)
4. [Input Generation & Mutation](#4-input-generation--mutation)
5. [Baseline Mode](#5-baseline-mode)
6. [Performance Testing](#6-performance-testing)
7. [In-Process Mode & Memory Leak Detection](#7-in-process-mode--memory-leak-detection)
8. [Test Framework Integration](#8-test-framework-integration)
9. [Finding Classes](#9-finding-classes)
10. [CLI Reference](#10-cli-reference)
11. [Configuration File](#11-configuration-file)
12. [Reporting & Output Files](#12-reporting--output-files)
13. [Service Coverage](#13-service-coverage)
14. [Source File Structure](#14-source-file-structure)
15. [Build & Dependencies](#15-build--dependencies)
16. [Client Stack Changes Required](#16-client-stack-changes-required)

---

## 1. Overview

The OPC UA Server Fuzzer probes the SDK's server for security vulnerabilities, behavioural defects, specification
non-compliance, and performance anomalies. It hooks directly into the SDK's client stack at five protocol layers —
from raw TCP up to the public service API — so that fuzzing at any layer reuses the real client implementation for
everything below it.

### 1.1 Design Goals

- **Layered hook points** — fuzz at any layer; the SDK client handles everything below
- **No parallel protocol implementation** — reuses the SDK's types, codecs, transport, and client API directly
- **Service-layer fuzzing is just API calls** — call `session.read()` with fuzzed arguments, no custom encoding
- **In-process by default** — `ua::Server` instantiated directly, ASan/LSan integration, resource tracking
- **CI-friendly** — embeds in Google Test, deterministic replay of every finding
- **Performance testing** — throughput, latency profiling, degradation detection, soak testing

### 1.2 Non-Goals

- Does not support fuzzing third-party OPC UA servers or clients (SDK-specific)
- Does not support OPC UA XML or HTTPS transport (Binary TCP only)
- Does not perform network-level fuzzing below TCP
- Does not replace a full OPC UA conformance test suite

---

## 2. Architecture

### 2.1 Layered Hook Points

The fuzzer hooks into the SDK's client stack at each layer boundary. Fuzzing at layer N uses the real client
implementation for layers 1 through N-1:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 5 — Service API                                      │
│  session.read(fuzzed_args), session.browse(fuzzed_args)     │
│  Hook: public ua::client::Session API                       │
│  Gets for free: session, channel, transport, TCP            │
├─────────────────────────────────────────────────────────────┤
│  Layer 4 — Message Encoding                                 │
│  Encode valid request with UaBinaryCodec, mutate the bytes  │
│  Hook: SecureChannelImpl::send_message (pre-sign/encrypt)   │
│  Gets for free: channel state, transport, TCP               │
├─────────────────────────────────────────────────────────────┤
│  Layer 3 — SecureChannel                                    │
│  Fuzz OPN handshake, token negotiation, sequence numbers    │
│  Hook: ConnectionProtocol send_message_chunk                │
│  Gets for free: transport framing, TCP                      │
├─────────────────────────────────────────────────────────────┤
│  Layer 2 — Transport Framing                                │
│  Fuzz HEL/ACK, chunk headers, message sizes                 │
│  Hook: TcpTransportConnection::async_write                  │
│  Gets for free: TCP connection                              │
├─────────────────────────────────────────────────────────────┤
│  Layer 1 — Raw TCP                                          │
│  Inject arbitrary bytes into the TCP stream                 │
│  Hook: raw socket (bypass SDK entirely)                     │
│  Gets for free: nothing                                     │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Key Insight: No Parallel Protocol Implementation

The original spec proposed a generation engine that builds complete OPC UA messages from scratch — essentially
reimplementing the SDK's codec and type system. This is unnecessary:

- **Service-layer fuzzing** is just calling the public API (`session.read()`, `session.browse()`, etc.) with
  fuzzed arguments. The SDK handles encoding, framing, signing, and sending. No custom message construction needed.
- **Message-layer fuzzing** encodes a valid request using `UaBinaryCodec`, then applies byte-level mutations to
  the encoded buffer before it hits the wire. The SDK provides the valid starting point.
- **Lower layers** similarly leverage the SDK's real implementation and mutate at the appropriate boundary.

### 2.3 Component Overview

```
┌──────────────────────────────────────────────────────┐
│                 Fuzzer Orchestrator                   │
│   (campaign management, seed scheduling,             │
│    baseline loading, stopping conditions)             │
└──────┬──────────────────────────────────┬────────────┘
       │                                  │
  ┌────▼──────────┐              ┌────────▼────────┐
  │ Input          │              │ Mutation         │
  │ Generators     │              │ Strategies       │
  │ (per-layer)    │              │ (byte-level)     │
  └────┬──────────┘              └────────┬────────┘
       └──────────────┬───────────────────┘
                ┌─────▼──────┐
                │ Layer Hook │ ← hooks into SDK client
                │ Selector   │   at the target layer
                └─────┬──────┘
                      │
                ┌─────▼──────┐
                │ SDK Client │ ← real client stack
                │ Stack      │   (Session/Channel/
                └─────┬──────┘    Transport/TCP)
                      │ opc.tcp://
                ┌─────▼──────┐
                │ ua::Server │ ← target (in-process)
                └────────────┘
```

### 2.4 Operating Mode

**In-Process (Primary)** — The server is instantiated as `ua::Server` directly inside the fuzzer process. The fuzzer
uses the SDK's `ua::client::Client` to connect. This enables:

- ASan/UBSan/LSan integration for memory safety detection
- Signal handling (SIGSEGV, SIGABRT) for crash detection
- Direct access to server state for resource leak detection
- Server reset between cases for clean state
- 500–5000 cases/sec throughput

**Out-of-Process (Optional)** — The server runs as a separate process. The fuzzer connects via TCP using the SDK
client. All observation is external. Useful for testing deployed server binaries. Lower layers (1-2) can also
operate out-of-process via raw TCP sockets without the SDK client. Throughput is lower (50–100 cases/sec).

---

## 3. Fuzzing Layers

### 3.1 Layer 1 — Raw TCP

Sends arbitrary bytes over a raw TCP socket, completely bypassing the SDK client stack. Tests the server's
lowest-level input handling.

**Targets:**

- Message type bytes — invalid, unknown, reversed type codes
- Partial / truncated data — send N bytes then stall or drop
- Oversized payloads — exceed any reasonable buffer size
- Non-OPC-UA data — HTTP requests, TLS ClientHello, random binary

**Hook:** Raw `boost::asio::ip::tcp::socket` (no SDK client involvement).

### 3.2 Layer 2 — Transport Framing

Uses a TCP connection but injects malformed OPC UA transport frames. The TCP connection is established normally;
fuzzing targets the HEL/ACK/MSG framing layer.

**Targets:**

- **Message header corruption** — invalid MessageType, bad MessageSize (zero, 1, 7, UINT32_MAX, mismatch with payload)
- **Chunk sequencing** — wrong sequence numbers, gaps, reuse, out-of-order intermediate chunks
- **Chunk type byte** — all byte values for the chunk type field, not just F/C/A
- **Type interleaving** — MSG before OPN, HEL twice, CLO mid-stream
- **Oversized messages** — exceed MaxMessageSize negotiated during Hello

**Hook:** Intercept at `TcpTransportConnection::async_write` — replace or mutate the outgoing frame bytes after
the connection protocol has constructed them, or inject raw frames directly.

### 3.3 Layer 3 — SecureChannel / Session Establishment

Uses a valid TCP connection with transport framing. Fuzzes the secure channel handshake and session lifecycle
state machine.

**Targets:**

- **Replayed SecurityTokens** — reuse expired or previously-closed channel IDs
- **Timestamp attacks** — expired tokens, not-yet-valid tokens, epoch zero, far future
- **SecureChannelId mismatches** — wrong ID on subsequent messages after OPN
- **SequenceNumber manipulation** — gaps, reuse, backward jumps, UINT32_MAX rollover
- **SecurityMode combinations** — invalid modes (0, 4+), mismatched PolicyUri and SecurityMode
- **CreateSession attacks** — malformed ClientNonce, invalid certificate references
- **ActivateSession attacks** — all UserIdentityToken types with invalid content
- **Rapid open/close cycling** — stress channel allocation with high-frequency OPN/CLO pairs

**Hook:** Intercept at `ConnectionProtocol::send_message_chunk` — the transport framing is valid, but the
message content (OPN request body, session creation parameters) is mutated or replaced.

### 3.4 Layer 4 — Message Encoding

Uses a valid session (HEL/ACK + OPN + CreateSession + ActivateSession all completed successfully via the SDK
client). Fuzzes the encoded service request bytes after serialization but before signing/encryption.

**Targets:**

- **NodeId encoding variants** — all 6 forms in unexpected contexts
- **Variant type confusion** — all 27 built-in types, mismatched type prefix, nested structures
- **ExtensionObject attacks** — unknown TypeIds, body length mismatch, truncated body
- **Deep nesting** — recursively nested arrays, DiagnosticInfo with all bits set
- **String field attacks** — embedded nulls, non-UTF-8, 0-length, UINT32_MAX length
- **RequestHeader attacks** — null AuthenticationToken, expired Timestamp, zero RequestHandle
- **Length field tampering** — overstate/understate array lengths, string lengths, body lengths

**How it works:**

1. Construct a valid service request using SDK types (e.g. `ReadRequest`)
2. Encode it using `UaBinaryCodec` into a byte buffer
3. Apply mutation strategies to the encoded bytes
4. Inject the mutated buffer through the channel's send path (bypassing re-encoding)

**Hook:** Intercept at `SecureChannelImpl` after encoding but before signing/encryption — the message is a valid
encoded byte buffer that gets mutated before going on the wire.

### 3.5 Layer 5 — Service API

Uses the SDK's public `ua::client::Session` API directly. Calls service methods with fuzzed arguments — weird
NodeIds, out-of-range enums, massive arrays, boundary values. The entire client stack handles encoding, framing,
signing, and transport. This layer tests how the server handles semantically invalid but structurally well-formed
requests.

**Targets:**

- **Browse** — nonexistent NodeIds, BrowseDirection outside enum range, MaxReferencesPerNode = 0 / UINT32_MAX
- **Read** — non-readable attributes on system nodes, wrong AttributeId for node class, all 22 AttributeIds
- **Write** — write to read-only nodes, wrong DataType, wrong ArrayDimensions, null Value
- **TranslateBrowsePaths** — malformed relative paths, circular references, empty path, max-depth paths
- **Method calls** — wrong argument count, wrong argument types, null InputArguments
- **Subscription stress** — extreme PublishingInterval (0, -1, UINT32_MAX), MaxNotificationsPerPublish extremes
- **MonitoredItems** — negative SamplingInterval, all DeadbandType variants
- **Node management** — AddNodes with invalid parent, DeleteNodes on protected nodes
- **All services** — see Section 13 for full coverage matrix

**Hook:** None needed — uses the public API directly:

```cpp
// Service-layer fuzzing is just API calls with fuzzed inputs
auto read_result = co_await session.read_coro(strand, generate_fuzzed_read_request());
auto browse_result = co_await session.browse_coro(strand, generate_fuzzed_browse_request());
```

---

## 4. Input Generation & Mutation

### 4.1 Input Generation (Per-Layer)

Each layer has its own input generators that produce values appropriate for that layer's abstraction level.

**Layer 5 — Service API Generators**

Generate fuzzed SDK types that are passed directly to the public API. No encoding involved.

| Generator                    | Produces                | Examples                                                    |
|------------------------------|-------------------------|-------------------------------------------------------------|
| `NodeIdGenerator`            | `ua::NodeId`            | Null, namespace 65535, max numeric ID, very long string IDs |
| `VariantGenerator`           | `ua::Variant`           | All 27 built-in types, scalar/array/matrix, deeply nested   |
| `AttributeIdGenerator`       | `ua::AttributeId`       | All 22 valid IDs plus out-of-range values                   |
| `BrowseDescriptionGenerator` | `ua::BrowseDescription` | Boundary directions, reference types, masks                 |
| `WriteValueGenerator`        | `ua::WriteValue`        | Type mismatches, null values, wrong dimensions              |
| `CallMethodRequestGenerator` | `ua::CallMethodRequest` | Wrong argument counts/types                                 |
| `TimestampGenerator`         | `ua::DateTime`          | Epoch zero, negative, INT64_MAX, far future                 |
| `StringGenerator`            | `std::string`           | Empty, max length, embedded nulls, non-UTF-8                |
| `ArrayGenerator<T>`          | `ua::Array<T>`          | Empty, single element, very large, nested                   |

Three generation modes: **random**, **boundary-focused** (edge values only), and **adversarial** (syntactically valid
but logically contradictory — e.g. Write with correct DataType but wrong ArrayDimensions).

**Layer 4 — Encoded Message Generators**

Produce valid encoded byte buffers (via SDK types + `UaBinaryCodec`) that are then mutated:

1. Generate a valid service request using Layer 5 generators
2. Encode it with `UaBinaryCodec` into a byte buffer
3. Return the buffer for mutation (see §4.2)

**Layers 1–3 — Low-Level Generators**

| Layer   | Generator                   | Produces                                             |
|---------|-----------------------------|------------------------------------------------------|
| Layer 3 | `OPNRequestGenerator`       | Valid/invalid OPN request bodies for channel fuzzing |
| Layer 3 | `SessionHandshakeGenerator` | CreateSession/ActivateSession with fuzzed parameters |
| Layer 2 | `FrameHeaderGenerator`      | OPC UA message headers with fuzzed type/size fields  |
| Layer 2 | `ChunkSequenceGenerator`    | Valid/invalid chunk sequences                        |
| Layer 1 | `RawByteGenerator`          | Random bytes, protocol-shaped noise                  |

### 4.2 Mutation Strategies (Byte-Level)

Applied to encoded message bytes (Layer 4) or raw frame bytes (Layers 1–3). Not used at Layer 5 — service-layer
fuzzing operates on SDK types, not bytes.

| Strategy             | Description                                               | Target                   |
|----------------------|-----------------------------------------------------------|--------------------------|
| `BitFlip`            | Flip 1–8 random bits                                      | Any byte                 |
| `ByteFlip`           | Flip an entire random byte                                | Any byte                 |
| `BoundaryCorrupt`    | Corrupt bytes at 4-byte aligned offsets                   | Field boundaries         |
| `LengthTamper`       | Identify plausible length fields and over/understate them | uint16/uint32 fields     |
| `EdgeIntegerInject`  | Replace a 4-byte field with 0, 1, -1, INT_MAX, UINT_MAX   | uint32/int32 fields      |
| `EdgeInt16Inject`    | Replace a 2-byte field with edge values                   | uint16/int16 fields      |
| `BlockDelete`        | Remove a random contiguous slice                          | Any region               |
| `BlockDuplicate`     | Duplicate a slice and append it                           | Any region               |
| `BlockShuffle`       | Swap two random equal-length slices                       | Any region               |
| `NullRun`            | Overwrite a slice with 0x00                               | String/ByteString fields |
| `HighByteRun`        | Overwrite a slice with 0xFF                               | Any region               |
| `FormatStringInject` | Insert `%s%n%x%p` into likely string fields               | String fields            |
| `EncodingPrefixSwap` | Change NodeId or Variant type prefix byte                 | Type prefix bytes        |

### 4.3 Seed Corpus

A seed corpus of valid captured messages from normal client operation is maintained for mutation-based fuzzing
at Layers 1–4. Seeds are captured by recording the byte output at each layer during normal SDK client operation.

For Layer 5, the "corpus" is a set of valid service request configurations (known-good `ReadRequest` parameters,
`BrowseDescription` values, etc.) that the generators use as starting points for adversarial variation.

### 4.4 Scheduling

The orchestrator maintains a weighted random selection over generators, mutation strategies, and layers:

- Seeds/generators that produced a finding in the last 1000 cases receive 3× weight
- Strategies that produced a finding in the last 1000 cases receive 2× weight
- Layers that have received fewer than 5% of total cases are rebalanced upward
- A 10% random exploration budget is maintained to avoid premature convergence

---

## 5. Baseline Mode

Before fuzzing begins, baseline mode profiles the server's normal behaviour to create a personalised reference
fingerprint. Makes anomaly detection accurate for that specific server configuration.

### 5.1 What Baseline Measures

| Metric                    | Method                                                        | Stored As                               |
|---------------------------|---------------------------------------------------------------|-----------------------------------------|
| Latency per service       | Send each service N times via SDK client, record distribution | min, mean, p95, p99, stddev per service |
| Response code consistency | Verify same input returns same StatusCode                     | Expected StatusCode per request type    |
| Handshake timing          | Time full `Client::open_channel` → `Session::activate`        | mean and p99 in microseconds            |
| Throughput ceiling        | Ramp request rate until queuing is detected                   | Sustained RPS, saturation RPS           |
| Resource stability        | N open/close cycles for sessions and channels                 | Latency trend slope (leak indicator)    |

### 5.2 Baseline Output

Saved to `baseline.json` in the output directory:

```json
{
  "recorded_at": "2026-03-10T14:22:01Z",
  "server_endpoint": "opc.tcp://127.0.0.1:4840",
  "samples_per_service": 200,
  "services": {
    "Read": {
      "latency_us": { "min": 210, "mean": 480, "p95": 890, "p99": 1400, "stddev": 95 },
      "expected_status": "0x00000000",
      "alert_threshold_us": 4800,
      "warn_threshold_us": 1440
    }
  },
  "throughput": { "sustained_rps": 312, "saturation_rps": 580 },
  "connection": { "handshake_mean_us": 1200, "handshake_p99_us": 3100 }
}
```

### 5.3 Anomaly Detection During Fuzzing

| Observation            | Comparison                                | Finding Class                    |
|------------------------|-------------------------------------------|----------------------------------|
| Response latency       | > p99 × `latency_alert_mul`               | `PERF_LATENCY_SPIKE`             |
| Response latency trend | Rising slope over last 100 cases          | `PERF_LATENCY_DRIFT`             |
| Requests/sec           | Drops below 50% of baseline sustained RPS | `PERF_THROUGHPUT_DEGRADATION`    |
| StatusCode returned    | Different from baseline expected code     | `BEHAVIOUR_UNEXPECTED_STATUS`    |
| TCP closed without ERR | vs. normal teardown pattern               | `SECURITY_UNEXPECTED_DISCONNECT` |
| No response in timeout | vs. baseline p99 latency                  | `SECURITY_HANG`                  |
| Handshake time         | > baseline handshake p99 × 5              | `PERF_SLOW_HANDSHAKE`            |
| Heap growth per case   | Delta persists after reset                | `MEMORY_LEAK`                    |

### 5.4 Baseline Reuse

If `baseline.json` already exists for the target endpoint, the fuzzer reuses it. `--force-baseline` forces
re-profiling. Baselines are invalidated automatically if the server configuration changes.

---

## 6. Performance Testing

Performance testing is a first-class mode alongside security and behavioural fuzzing. Can be run standalone
(`--perf`) or enabled during a fuzz campaign.

### 6.1 Performance Test Modes

All performance tests use the SDK's public client API — they are real OPC UA operations, not synthetic benchmarks.

**Throughput Test** — Measures maximum sustainable request rate per service. Ramps from 10% of estimated capacity
to 200%, identifies the saturation point, and measures behaviour at saturation (queue depth, latency curve, error
rate).

**Latency Profile** — Sends N requests of each service at a controlled low rate (10% of saturation) and records
the full latency distribution. Identifies outliers, bimodal distributions, and p99/p99.9 latency.

**Soak Test** — Runs a mixed workload at 70% of saturation for a configurable duration (default 1 hour). Measures
latency drift, connection stability, and memory growth over time. Outputs `latency_over_time.csv`.

**Concurrency Test** — Opens N simultaneous `ua::client::Session` instances and issues concurrent requests. Measures
per-session latency degradation, identifies session-count thresholds, and detects deadlock symptoms.

**Subscription Stress Test** — Creates N subscriptions with M monitored items each via the SDK's subscription API.
Measures PublishResponse latency and notification delivery consistency under load.

### 6.2 Performance Metrics

| Metric                        | Description                                        | Reported As                  |
|-------------------------------|----------------------------------------------------|------------------------------|
| Throughput                    | Requests processed per second                      | req/sec per service, overall |
| Latency p50/p95/p99/p99.9     | Response time distribution                         | Microseconds per service     |
| Latency under load            | Latency at 50%, 80%, 100%, 120% of saturation      | Latency vs. load curve       |
| Saturation point              | RPS where latency begins to grow non-linearly      | req/sec                      |
| Error rate under load         | Non-Good StatusCodes at each load level            | % per service                |
| Connection establishment time | `Client::open_channel` → `Session::activate`       | Microseconds p50/p99         |
| Memory growth                 | Heap delta over N requests (in-process)            | Bytes per 1000 requests      |
| Latency drift                 | Change in p50 latency from start to end of soak    | Microseconds/hour            |
| Session overhead              | Latency increase per additional concurrent session | Microseconds/session         |

### 6.3 Performance Report Output

| File                    | Contents                                              |
|-------------------------|-------------------------------------------------------|
| `perf_summary.json`     | All metrics in structured JSON for CI ingestion       |
| `latency_profile.csv`   | Raw per-request latency samples for all services      |
| `latency_over_time.csv` | p50/p95/p99 sampled every 10 seconds during soak test |
| `throughput_curve.csv`  | Throughput and p99 latency at each load step          |
| `perf_report.txt`       | Human-readable summary for console or CI log          |

---

## 7. In-Process Mode & Memory Leak Detection

### 7.1 Server Lifecycle

The fuzzer instantiates `ua::Server` directly. No wrapper interface is needed — the server's public API provides
everything required:

```cpp
// Setup
auto server = ua::Server::create(config);
server.start_sync();

// Between fuzz cases — reconnect the client to get clean session state.
// The server maintains its own lifecycle; channel/session cleanup happens
// via normal protocol teardown or server-side timeout.

// Teardown
server.stop();
```

For resource leak detection, the fuzzer monitors server-observable state:

| Resource         | Detection Method                                                                        |
|------------------|-----------------------------------------------------------------------------------------|
| Heap memory      | Track process heap via `malloc_usable_size` / ASan allocator queries                    |
| Sessions         | Connect a diagnostic client, read `Server_ServerDiagnosticsSummary_CurrentSessionCount` |
| Channels         | Read `Server_ServerDiagnosticsSummary_CurrentChannelCount` (if exposed)                 |
| Subscriptions    | Read `Server_ServerDiagnosticsSummary_CurrentSubscriptionCount`                         |
| File descriptors | Count `/proc/self/fd` entries (Linux)                                                   |

### 7.2 Memory Leak Detection Mechanisms

**1. Heap Delta Tracking** — Before each fuzz case, heap allocation is recorded. After the case and after the
client disconnects cleanly, it is recorded again. A monotonically rising allocation curve over 50+ cases confirms
a leak.

```
case 1001: heap before=2.4MB  after=2.4MB  delta=0       OK
case 1002: heap before=2.4MB  after=2.5MB  delta=+104KB  CANDIDATE
case 1003: heap before=2.5MB  after=2.6MB  delta=+104KB  LEAK CONFIRMED
finding: MEMORY_LEAK  trigger=case_1002.bin  rate=+104KB/case
```

**2. AddressSanitizer / LeakSanitizer** — Build with `-fsanitize=address,leak`. ASan violations trigger `abort()`,
which the fuzzer catches via signal handler. The triggering case is saved, the server is restarted, and fuzzing
continues. LeakSanitizer reports all unreachable heap at process exit.

**3. File Descriptor Tracking (Linux)** — Counts open file descriptors in `/proc/self/fd` before and after each
case. An upward trend indicates FD leaks in connection or socket handling.

### 7.3 Resource Leak Finding Classes

| Resource         | Detection Method                                               | Finding Class                |
|------------------|----------------------------------------------------------------|------------------------------|
| Heap memory      | Heap delta persists after clean disconnect                     | `MEMORY_LEAK`                |
| Heap trend       | Rising slope over 50 cases                                     | `MEMORY_LEAK_SLOW`           |
| Sessions         | Diagnostic node shows count > 0 after all clients disconnected | `RESOURCE_LEAK_SESSION`      |
| Channels         | Diagnostic node shows count > 0 after all clients disconnected | `RESOURCE_LEAK_CHANNEL`      |
| Subscriptions    | Diagnostic node shows count > 0 after all clients disconnected | `RESOURCE_LEAK_SUBSCRIPTION` |
| File descriptors | `/proc/self/fd` count delta (Linux)                            | `RESOURCE_LEAK_FD`           |
| ASan violation   | `abort()` signal caught                                        | `SECURITY_ASAN_VIOLATION`    |

### 7.4 Crash Isolation

In-process crashes do not terminate the fuzzer process:

- **SIGSEGV / SIGABRT** — signal handler records the triggering case, restarts the server, resumes fuzzing
- **std::exception** — caught at the case boundary, server is restarted, case saved as
  `BEHAVIOUR_UNHANDLED_EXCEPTION`
- **Hang detection** — each case runs with a watchdog timer; timeout kills the case and resets
- **Zombie prevention** — after any crash, the fuzzer verifies the fresh server responds to a health-check
  `read` via the SDK client before sending further cases

---

## 8. Test Framework Integration

The `FuzzSession` class is designed to be instantiated inside Google Test. Runs synchronously, returns a structured
`FuzzResult`, and saves findings to disk as CI artifacts.

### 8.1 Example — Google Test

```cpp
TEST(OpcUaServerFuzz, ServiceLayer_Read) {
    // Create and start the server
    auto server = ua::Server::create(make_test_server_config());
    server.start_sync();

    FuzzConfig cfg;
    cfg.campaign.layers      = { FuzzLayer::Service };
    cfg.campaign.services    = { FuzzService::Read, FuzzService::Browse };
    cfg.campaign.max_cases   = 10000;
    cfg.baseline.samples     = 50;       // lighter baseline in CI
    cfg.reporting.output_dir = "./fuzz_findings/service";

    FuzzSession session(cfg, server);
    auto result = session.run();

    EXPECT_EQ(result.security_findings,  0);
    EXPECT_EQ(result.memory_leaks,       0);
    EXPECT_EQ(result.crashes,            0);

    server.stop();
}

TEST(OpcUaServerFuzz, TransportFraming) {
    auto server = ua::Server::create(make_test_server_config());
    server.start_sync();

    FuzzConfig cfg;
    cfg.campaign.layers      = { FuzzLayer::TransportFraming };
    cfg.campaign.max_cases   = 5000;
    cfg.reporting.output_dir = "./fuzz_findings/transport";

    FuzzSession session(cfg, server);
    auto result = session.run();

    EXPECT_EQ(result.crashes, 0);
    EXPECT_EQ(result.security_findings, 0);

    server.stop();
}

TEST(OpcUaServerFuzz, MessageEncoding_AllServices) {
    auto server = ua::Server::create(make_test_server_config());
    server.start_sync();

    FuzzConfig cfg;
    cfg.campaign.layers    = { FuzzLayer::MessageEncoding };
    cfg.campaign.max_cases = 20000;
    cfg.reporting.output_dir = "./fuzz_findings/message";

    FuzzSession session(cfg, server);
    auto result = session.run();

    EXPECT_EQ(result.crashes, 0);
    EXPECT_EQ(result.security_findings, 0);

    server.stop();
}
```

### 8.2 FuzzResult Fields

| Field                | Type          | Description                                         |
|----------------------|---------------|-----------------------------------------------------|
| `security_findings`  | `uint32_t`    | Total findings in the `SECURITY_` category          |
| `memory_leaks`       | `uint32_t`    | Total `MEMORY_LEAK` and `MEMORY_LEAK_SLOW` findings |
| `resource_leaks`     | `uint32_t`    | Total `RESOURCE_LEAK_*` findings                    |
| `crashes`            | `uint32_t`    | Signal-caught crashes (ASan or segfault)            |
| `critical_behaviour` | `uint32_t`    | `BEHAVIOUR_*` findings rated critical               |
| `perf_findings`      | `uint32_t`    | Total `PERF_*` findings                             |
| `total_cases`        | `uint64_t`    | Number of fuzz cases executed                       |
| `elapsed_seconds`    | `double`      | Wall time of the run                                |
| `cases_per_second`   | `double`      | Average throughput                                  |
| `findings_dir`       | `std::string` | Absolute path to saved findings                     |

---

## 9. Finding Classes

### 9.1 Security Findings

| Class                              | Description                                                       |
|------------------------------------|-------------------------------------------------------------------|
| `SECURITY_CRASH`                   | Server process crashed (SIGSEGV, SIGABRT, or equivalent)          |
| `SECURITY_HANG`                    | Server stopped responding within timeout after a fuzz case        |
| `SECURITY_UNEXPECTED_DISCONNECT`   | Server closed TCP without sending an ERR message                  |
| `SECURITY_ASAN_VIOLATION`          | AddressSanitizer detected memory safety violation                 |
| `SECURITY_AUTH_BYPASS`             | Service succeeded with null or invalid AuthenticationToken        |
| `SECURITY_PRIV_ESCALATION`         | Anonymous session accessed nodes it should not have               |
| `SECURITY_DOS_DEGRADATION`         | Server became unresponsive to concurrent connections after a case |
| `SECURITY_STATE_MACHINE_VIOLATION` | Server accepted an out-of-order message it should have rejected   |
| `SECURITY_REPLAY_ACCEPTED`         | Reused RequestId or SecurityToken was accepted                    |

### 9.2 Behavioural Findings

| Class                           | Description                                                            |
|---------------------------------|------------------------------------------------------------------------|
| `BEHAVIOUR_UNEXPECTED_STATUS`   | Server returned a StatusCode different from the baseline expected code |
| `BEHAVIOUR_NONDETERMINISTIC`    | Same input produced different StatusCodes across two runs              |
| `BEHAVIOUR_SPEC_VIOLATION`      | Server returned Good for a request the spec mandates must be rejected  |
| `BEHAVIOUR_MALFORMED_RESPONSE`  | Server response failed to parse as valid OPC UA binary                 |
| `BEHAVIOUR_UNHANDLED_EXCEPTION` | Server threw an unhandled C++ exception                                |

### 9.3 Performance Findings

| Class                         | Description                                                      |
|-------------------------------|------------------------------------------------------------------|
| `PERF_LATENCY_SPIKE`          | Single response latency exceeded baseline p99 × alert multiplier |
| `PERF_LATENCY_DRIFT`          | Latency rising monotonically over the last 100 cases             |
| `PERF_THROUGHPUT_DEGRADATION` | Server throughput dropped below 50% of baseline sustained RPS    |
| `PERF_SLOW_HANDSHAKE`         | Connection establishment time exceeded baseline p99 × 5          |

### 9.4 Memory & Resource Findings

| Class                        | Description                                                    |
|------------------------------|----------------------------------------------------------------|
| `MEMORY_LEAK`                | Heap allocation delta persisted after clean client disconnect  |
| `MEMORY_LEAK_SLOW`           | Heap allocation rising monotonically over 50+ cases            |
| `RESOURCE_LEAK_SESSION`      | Session count > 0 after all clients disconnected               |
| `RESOURCE_LEAK_CHANNEL`      | Channel count > 0 after all clients disconnected               |
| `RESOURCE_LEAK_SUBSCRIPTION` | Subscription count > 0 after all clients disconnected          |
| `RESOURCE_LEAK_FD`           | File descriptor count increased after clean disconnect (Linux) |

---

## 10. CLI Reference

### 10.1 Primary Modes

```
opcua-fuzzer [mode] [options]

Modes:
  --fuzz            Run a fuzz campaign (default mode)
  --baseline        Profile the server and save baseline.json, then exit
  --perf            Run performance tests only, then exit
  --replay <file>   Replay a single finding .bin file
  --validate-config Validate fuzzer_config.toml and print the parsed config
  --print-config    Print the active configuration and exit
```

### 10.2 Target Options

```
  --endpoint <url>       Server endpoint (default: starts in-process server)
                           e.g. opc.tcp://192.168.1.100:4840
  --out-of-process       Connect to an external server instead of in-process
  --timeout <ms>         Connection timeout in milliseconds
```

### 10.3 Campaign Options

```
  --layers <list>        Comma-separated: raw,transport,channel,message,service
  --services <list>      Comma-separated service names (Layer 5 only):
                           read,browse,write,call,subscribe,... (default: all)
  --max-cases <n>        Stop after N cases (default: 0 = run forever)
  --seed-corpus <dir>    Path to seed corpus directory
  --rng-seed <n>         Fix the RNG seed for deterministic runs (default: random)
```

### 10.4 Baseline Options

```
  --skip-baseline        Skip baseline profiling, use hardcoded thresholds
  --force-baseline       Re-run baseline even if baseline.json already exists
  --baseline-file <f>    Use a specific baseline file
  --baseline-samples <n> Number of samples per service (default: 200)
```

### 10.5 Performance Test Options

```
  --perf-mode <mode>     throughput | latency | soak | concurrency | subscription | all
  --soak-duration <s>    Duration of soak test in seconds (default: 3600)
  --concurrency <n>      Comma-separated session counts e.g. --concurrency 10,50,100
  --load-steps <n>       Number of steps in throughput ramp (default: 10)
```

### 10.6 Reporting Options

```
  --output-dir <dir>     Directory for findings, corpus, and reports
  --log-all              Log every case, not just findings (verbose)
  --save-all-cases       Save raw bytes for every case, not just findings
  --no-console           Suppress console output (useful in CI)
  --no-file              Disable file output
```

### 10.7 In-Process Options

```
  --asan                 Enable AddressSanitizer signal handling
  --watchdog-ms <ms>     Per-case watchdog timeout (default: same as --timeout)
```

### 10.8 Usage Examples

```bash
# Profile the in-process server
opcua-fuzzer --baseline

# Full fuzz campaign — all layers, run forever
opcua-fuzzer --fuzz

# Fuzz service layer only, Read and Browse, 50,000 cases, fixed RNG seed
opcua-fuzzer --fuzz --layers service --services read,browse --max-cases 50000 --rng-seed 42

# Fuzz message encoding with mutations
opcua-fuzzer --fuzz --layers message --max-cases 20000

# Transport framing only
opcua-fuzzer --fuzz --layers transport --max-cases 10000

# Full performance test suite
opcua-fuzzer --perf --perf-mode all

# 2-hour soak test
opcua-fuzzer --perf --perf-mode soak --soak-duration 7200

# Replay a specific finding
opcua-fuzzer --replay ./findings/finding_042.bin

# Fuzz an external server
opcua-fuzzer --fuzz --out-of-process --endpoint opc.tcp://192.168.1.100:4840
```

---

## 11. Configuration File

All settings can be specified in `fuzzer_config.toml`. CLI flags override file values.

```toml
[target]
endpoint          = "opc.tcp://127.0.0.1:4840"
timeout_ms        = 5000
out_of_process    = false

[campaign]
max_cases         = 0               # 0 = run forever
layers            = ["all"]         # or ["raw","transport","channel","message","service"]
services          = ["all"]         # or ["read","browse","write","call",...]
seed_corpus_dir   = "./corpus"
rng_seed          = 0               # 0 = random seed each run

[limits]
max_message_size  = 16777216        # 16 MB
max_string_len    = 65535
max_array_len     = 10000
max_nesting_depth = 32

[baseline]
samples             = 200
latency_alert_mul   = 10.0
latency_warn_mul    = 3.0

[performance]
soak_duration_s   = 3600
concurrency_steps = [10, 50, 100]
load_steps        = 10

[reporting]
console             = true
file                = true
output_dir          = "./findings"
corpus_out_dir      = "./corpus_out"
log_all_responses   = false
save_all_cases      = false
console_update_hz   = 2
```

---

## 12. Reporting & Output Files

### 12.1 Console Output (Live)

```
[00:04:12] cases=14,322  rate=59/sec  findings=3  layer=service  server=ALIVE

[FIND #3] LAYER=message  CLASS=SECURITY_UNEXPECTED_DISCONNECT
          service=Read  mutation=LengthTamper@offset=12
          server_latency=0µs (connection dropped immediately)
          repro: opcua-fuzzer --replay ./findings/finding_003.bin
```

### 12.2 Output Directory Structure

```
findings/
├── baseline.json               # server behaviour baseline
├── run_summary.json            # overall campaign results
├── latency_profile.csv         # per-service latency distributions
├── latency_over_time.csv       # latency sampled every 10s (soak)
├── throughput_curve.csv        # throughput vs. load level
├── perf_summary.json           # structured performance results
├── corpus_out/                 # seeds that produced new behaviours
│   └── seed_NNN.bin
└── findings/
    ├── finding_001.bin         # raw bytes that triggered the finding
    ├── finding_001.meta.json   # class, layer, seed, mutation, response
    ├── finding_002.bin
    └── finding_002.meta.json
```

### 12.3 Finding Metadata (`finding_NNN.meta.json`)

```json
{
  "id": 3,
  "class": "SECURITY_UNEXPECTED_DISCONNECT",
  "layer": "message",
  "service": "Read",
  "strategy": "LengthTamper",
  "mutation_offset": 12,
  "seed_name": "read_request_001",
  "response_received": false,
  "connection_dropped": true,
  "latency_us": 0,
  "server_status_before": "ALIVE",
  "server_status_after": "DEAD",
  "timestamp": "2026-03-10T14:26:33Z",
  "case_number": 14322,
  "replay_cmd": "opcua-fuzzer --replay ./findings/finding_003.bin"
}
```

---

## 13. Service Coverage

Layer 5 (Service API) has dedicated input generators for each service. Layer 4 (Message Encoding) generates
valid requests for each service and then applies byte-level mutations.

| Service Group   | Services Covered                                                                                                          |
|-----------------|---------------------------------------------------------------------------------------------------------------------------|
| Discovery       | FindServers, GetEndpoints                                                                                                 |
| SecureChannel   | OpenSecureChannel, CloseSecureChannel                                                                                     |
| Session         | CreateSession, ActivateSession, CloseSession, Cancel                                                                      |
| Node Management | AddNodes, AddReferences, DeleteNodes, DeleteReferences                                                                    |
| View            | Browse, BrowseNext, TranslateBrowsePathsToNodeIds, RegisterNodes, UnregisterNodes                                         |
| Attribute       | Read, HistoryRead, Write, HistoryUpdate                                                                                   |
| Method          | Call                                                                                                                      |
| MonitoredItems  | CreateMonitoredItems, ModifyMonitoredItems, SetMonitoringMode, DeleteMonitoredItems                                       |
| Subscription    | CreateSubscription, ModifySubscription, SetPublishingMode, DeleteSubscriptions, Publish, Republish, TransferSubscriptions |
| Query           | QueryFirst, QueryNext                                                                                                     |

---

## 14. Source File Structure

```
tooling/fuzzer/
├── include/
│   ├── fuzzer_config.h            # FuzzerConfig struct and TOML loader
│   ├── fuzz_layer.h               # FuzzLayer enum, layer hook abstractions
│   ├── input_generators.h         # Per-layer input generators (SDK type generators)
│   ├── mutation_engine.h          # Byte-level mutation strategies
│   ├── baseline.h                 # BaselineProfiler, BaselineData
│   ├── monitor.h                  # Latency tracking, anomaly detection
│   ├── campaign.h                 # Orchestrator, scheduler, FuzzSession
│   ├── reporter.h                 # Console + file output, replay serialisation
│   └── perf_tester.h             # Performance test modes and metrics
├── src/
│   ├── fuzzer_config.cpp
│   ├── layer_hooks.cpp            # SDK client stack hook implementations
│   ├── input_generators.cpp       # Type generators using SDK types + codec
│   ├── mutation_engine.cpp
│   ├── baseline.cpp
│   ├── monitor.cpp
│   ├── campaign.cpp
│   ├── reporter.cpp
│   ├── perf_tester.cpp
│   └── main.cpp                   # CLI entry point
├── corpus/                        # Default seed corpus directory
├── findings/                      # Default output directory
├── fuzzer_config.toml             # Default configuration file
└── CMakeLists.txt
tests/
└── fuzz/
    ├── fuzz_service_layer_test.cpp
    ├── fuzz_message_layer_test.cpp
    ├── fuzz_transport_layer_test.cpp
    └── fuzz_channel_layer_test.cpp
```

---

## 15. Build & Dependencies

### 15.1 Requirements

| Dependency   | Version            | Purpose                                            |
|--------------|--------------------|----------------------------------------------------|
| SDK          | (this repo)        | Client stack, server, types, codecs — everything   |
| C++ compiler | C++20              | Core language features (coroutines for SDK client) |
| CMake        | 3.16+              | Build system                                       |
| toml++       | v3.x (header-only) | TOML config file parsing                           |

### 15.2 Optional Dependencies

| Dependency                   | Purpose                                    |
|------------------------------|--------------------------------------------|
| AddressSanitizer (Clang/GCC) | Memory safety violation detection          |
| LeakSanitizer (Clang/GCC)    | Heap leak detection at process exit        |
| Google Test                  | Test framework integration via FuzzSession |

### 15.3 CMake Build

```bash
# Standard build (links against SDK)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# With ASan (recommended):
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_ASAN=ON
cmake --build build
```

---

## 16. Client Stack Changes Required

This section describes the modifications needed in the SDK's client stack to support the fuzzer's layered hook
points. The goal is minimal, non-invasive changes that make the client's layer boundaries accessible without
compromising the normal API or adding fuzzer-specific code to production paths.

### 16.1 Current Client Stack Wiring

Today, `ClientImpl::open_channel_coro()` hardcodes the full pipeline:

```
parse URL → DNS resolve → TcpTransportConnector::create() → ConnectionProtocol::create()
          → SecureChannelImpl::create() → return SecureChannel
```

Each layer is created inline and immediately wired to the next. There is no way for external code to intercept
between layers without modifying `ClientImpl`.

**What's already injectable** (via constructor/factory parameters):

| Component                        | Injectable? | Mechanism                                                                       |
|----------------------------------|-------------|---------------------------------------------------------------------------------|
| `TransportConnection`            | Yes         | `ConnectionProtocol::create()` takes `shared_ptr<TransportConnection>`          |
| `ConnectionProtocolDependencies` | Yes         | `ConnectionProtocol::create()` takes `weak_ptr<ConnectionProtocolDependencies>` |
| `SecureChannelDependencies`      | Yes         | `SecureChannelImpl::create()` takes `weak_ptr<SecureChannelDependencies>`       |
| `SessionDependencies`            | Yes         | `SessionImpl::create()` takes `weak_ptr<SessionDependencies>`                   |
| `SecurityPolicy`                 | No          | Created internally by `SecureChannelImpl` from policy ID enum                   |

**What's hardcoded:**

- TCP transport creation (`TcpTransportConnector::create()` in `open_channel_coro`)
- `ConnectionProtocol` creation (inline in `open_channel_coro`)
- `SecureChannelImpl` creation (inline in `open_channel_coro`)
- `SessionImpl` creation (inline in `SecureChannelImpl::create_session_coro`)
- `SecurityPolicy` selection (by enum in `SecureChannelImpl::initialise`)

### 16.2 Design Approach: Intercepting TransportConnection

The cleanest hook point for Layers 1–4 is `TransportConnection`, which is already an abstract interface. A
**decorating wrapper** around `TransportConnection` can intercept, inspect, and mutate bytes flowing in both
directions without changing any other layer.

```cpp
/// Wraps a real TransportConnection and allows the fuzzer to intercept/mutate traffic.
class FuzzTransportConnection : public TransportConnection
{
public:
    explicit FuzzTransportConnection(std::shared_ptr<TransportConnection> inner, FuzzLayer targetLayer);

    // --- Write path (client → server) ---
    void async_write(std::vector<std::byte>&& data) override
    {
        if (mWriteInterceptor)
        {
            // Interceptor can mutate, drop, or replay the buffer.
            mWriteInterceptor(data, [this](std::vector<std::byte>&& mutated) {
                mInner->async_write(std::move(mutated));
            });
        }
        else
        {
            mInner->async_write(std::move(data));
        }
    }

    // --- Read path (server → client) ---
    // Wraps the inner connection's read callback to intercept incoming bytes.

    using WriteInterceptor = std::function<void(
        std::vector<std::byte>& data,
        std::function<void(std::vector<std::byte>&&)> forward)>;

    void set_write_interceptor(WriteInterceptor interceptor);

private:
    std::shared_ptr<TransportConnection> mInner;
};
```

This handles **Layer 2 (Transport Framing)** — the fuzzer wraps the real TCP connection and mutates outgoing
frames or injects arbitrary bytes. It also serves as the raw injection point for **Layer 1**.

However, Layers 3 and 4 require interception at higher points in the stack (after encoding, before
signing/encryption). The transport-level wrapper alone is insufficient because at that point the bytes are
already signed/encrypted and any mutation would be rejected by the server's security policy verification.

### 16.3 Design Approach: Intercepting SecurityPolicy

For **Layer 3 (SecureChannel)** and **Layer 4 (Message Encoding)**, the key interception point is the
`SecurityPolicy` encode/decode boundary. `SecurityPolicy` is already a fully abstract interface with virtual
`encode_message()` and `decode_message_chunk()` methods.

A **decorating wrapper** around `SecurityPolicy` can intercept the encoded (but not yet signed/encrypted)
message bytes:

```cpp
/// Wraps a real SecurityPolicy. Intercepts messages after encoding but before signing/encryption.
class FuzzSecurityPolicy : public SecurityPolicy
{
public:
    explicit FuzzSecurityPolicy(std::unique_ptr<SecurityPolicy> inner);

    // The encode path: message → encode → [INTERCEPT] → sign/encrypt → send
    Task<> encode_message(const SecurityContext& context, uint32_t requestId,
        const Structure& message, SendMessageChunkCallback sendChunk) override
    {
        if (mEncodeInterceptor)
        {
            // Delegate to inner with a wrapped sendChunk that lets the fuzzer
            // mutate the encoded bytes before they are signed/encrypted.
            co_await mInner->encode_message(context, requestId, message,
                [this, &sendChunk](std::vector<std::byte>&& chunk) {
                    mEncodeInterceptor(chunk);  // mutate in-place
                    sendChunk(std::move(chunk));
                });
        }
        else
        {
            co_await mInner->encode_message(context, requestId, message, std::move(sendChunk));
        }
    }

    // All other SecurityPolicy methods delegate to mInner unchanged.

    using EncodeInterceptor = std::function<void(std::vector<std::byte>& encodedChunk)>;
    void set_encode_interceptor(EncodeInterceptor interceptor);

private:
    std::unique_ptr<SecurityPolicy> mInner;
};
```

**Problem:** `SecureChannelImpl` currently creates its `SecurityPolicy` internally from the policy ID enum.
The fuzzer cannot inject a custom `SecurityPolicy` without a change to `SecureChannelImpl`.

### 16.4 Required Change: SecurityPolicy Factory Callback

Add an optional `SecurityPolicy` factory callback to `SecureChannelImpl::Config`:

```cpp
struct Config
{
    ua::MessageSecurityMode mSecurityMode{ua::MessageSecurityMode::None};
    ua::SecurityPolicyId securityPolicyId{ua::SecurityPolicyId::None};
    uint32_t mRequestedLifetimeMs{3600000};
    std::string mEndpointUrl;

    // NEW: optional factory override. If set, called instead of SecurityPolicy::create().
    // Allows wrapping or replacing the security policy (e.g. for fuzzing).
    using SecurityPolicyFactory = std::function<std::unique_ptr<SecurityPolicy>(SecurityPolicyId)>;
    SecurityPolicyFactory securityPolicyFactory;
};
```

In `SecureChannelImpl::initialise()`, where the security policy is currently created:

```cpp
// Before:
mSecurityPolicy = SecurityPolicy::create(mConfig.securityPolicyId);

// After:
if (mConfig.securityPolicyFactory)
{
    mSecurityPolicy = mConfig.securityPolicyFactory(mConfig.securityPolicyId);
}
else
{
    mSecurityPolicy = SecurityPolicy::create(mConfig.securityPolicyId);
}
```

The fuzzer uses this to inject a `FuzzSecurityPolicy` wrapper:

```cpp
scConfig.securityPolicyFactory = [&fuzzer](SecurityPolicyId id) {
    auto real = SecurityPolicy::create(id);
    return std::make_unique<FuzzSecurityPolicy>(std::move(real), fuzzer.encode_interceptor());
};
```

### 16.5 Required Change: Transport Decorator Callback

`ClientImpl::open_channel_coro()` hardcodes `TcpTransportConnector::create()`. Rather than replacing the
transport creation (which would leak ASIO types into the public API), add a **decorator callback** that
receives the already-connected `TransportConnection` and returns a (possibly wrapped) one:

```cpp
struct OpenChannelConfig
{
    std::string mEndpointUrl;
    ua::MessageSecurityMode mSecurityMode{ua::MessageSecurityMode::None};
    ua::SecurityPolicyId securityPolicyId{ua::SecurityPolicyId::None};
    uint32_t mRequestedLifetimeMs{3600000};

    // NEW: optional transport decorator. If set, called after TCP connect succeeds.
    // Receives the real TransportConnection; returns a (possibly wrapped) one.
    // Allows intercepting transport-level traffic without exposing ASIO types.
    using TransportDecorator = std::function<std::shared_ptr<TransportConnection>(
        std::shared_ptr<TransportConnection>)>;
    TransportDecorator transportDecorator;
};
```

In `open_channel_coro()`, immediately after the TCP connect succeeds:

```cpp
auto tcpConnection = std::move(tcpResult.value());

// NEW: apply decorator if provided.
if (config.transportDecorator)
{
    tcpConnection = config.transportDecorator(std::move(tcpConnection));
}

// Existing ConnectionProtocol creation continues with tcpConnection...
```

The fuzzer uses this to wrap the transport:

```cpp
channelConfig.transportDecorator = [&fuzzer](std::shared_ptr<TransportConnection> real) {
    auto wrapped = std::make_shared<FuzzTransportConnection>(std::move(real));
    fuzzer.set_transport(wrapped);
    return wrapped;
};
```

This keeps the public API free of any ASIO dependency — the callback only deals with the SDK's own
`TransportConnection` interface. The normal TCP connect path is unchanged; the decorator is applied
after the fact.

### 16.6 Layer 5 (Service API): No Client Changes Needed

Layer 5 fuzzing uses the public `ua::client::Session` API directly — `read_coro()`, `browse_coro()`, etc.
with fuzzed arguments. No interception or wrapping is needed. The fuzzer just calls the API:

```cpp
// Layer 5: just call the public API with fuzzed inputs.
auto session = co_await channel.create_session_coro(strand, sessionConfig);
co_await session.activate_coro(strand, activateConfig);

// Fuzz loop:
for (auto& fuzzCase : cases)
{
    auto result = co_await session.read_coro(strand, fuzzCase.generate_read_request());
    analyser.record(fuzzCase, result);
}
```

### 16.7 Summary of Required SDK Changes

| Change                                                     | Location                          | Complexity | Impact                                                      |
|------------------------------------------------------------|-----------------------------------|------------|-------------------------------------------------------------|
| Add `SecurityPolicyFactory` to `SecureChannelImpl::Config` | `ua_client_secure_channel_impl.h` | Small      | One optional field + 3-line branch in `initialise()`        |
| Add `TransportDecorator` to `Client::OpenChannelConfig`    | `ua_client.h`                     | Small      | One optional field + 2-line branch in `open_channel_coro()` |
| `FuzzTransportConnection` decorator                        | New file (fuzzer-only)            | Medium     | Implements `TransportConnection`, delegates to inner        |
| `FuzzSecurityPolicy` decorator                             | New file (fuzzer-only)            | Medium     | Implements `SecurityPolicy`, delegates to inner             |

**Total production code changes: 2 optional factory callbacks.** Everything else lives in the fuzzer.

The factory callback pattern is deliberately minimal — no new interfaces, no build flags, no conditional
compilation. The callbacks default to null, and the existing behaviour is unchanged when they are not set.
The fuzzer sets them; normal client code never touches them.

### 16.8 Hook Point Summary by Layer

| Layer                           | Hook Mechanism                                                                         | SDK Change Required                                             |
|---------------------------------|----------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| **Layer 1 — Raw TCP**           | Raw `boost::asio::ip::tcp::socket` (no SDK)                                            | None                                                            |
| **Layer 2 — Transport Framing** | `FuzzTransportConnection` wrapper via `TransportDecorator`                             | `TransportDecorator` callback on `OpenChannelConfig`            |
| **Layer 3 — SecureChannel**     | `FuzzSecurityPolicy` wrapper intercepts pre-sign message bytes                         | `SecurityPolicyFactory` callback on `SecureChannelImpl::Config` |
| **Layer 4 — Message Encoding**  | Same as Layer 3 — encode with SDK types, mutate encoded bytes via `FuzzSecurityPolicy` | Same as Layer 3                                                 |
| **Layer 5 — Service API**       | Public `ua::client::Session` API directly                                              | None                                                            |

Note: Layers 3 and 4 share the same hook mechanism (`FuzzSecurityPolicy`) but differ in what the fuzzer does
with the intercepted bytes. Layer 4 mutates the encoded service request body (flipping fields, corrupting
lengths). Layer 3 mutates the channel-level content (OPN parameters, sequence numbers, security tokens).

---

## Appendix — Capability Summary

| Capability                          | In-Process               | Out-of-Process      |
|-------------------------------------|--------------------------|---------------------|
| Layer 5 — Service API fuzzing       | ✓                        | ✓                   |
| Layer 4 — Message encoding fuzzing  | ✓                        | ✓                   |
| Layer 3 — SecureChannel fuzzing     | ✓                        | ✓                   |
| Layer 2 — Transport framing fuzzing | ✓                        | ✓                   |
| Layer 1 — Raw TCP fuzzing           | ✓                        | ✓                   |
| Crash detection                     | Exact (signal)           | Heuristic (timeout) |
| Hang detection                      | Watchdog thread          | Timeout-based       |
| Memory leak detection               | ✓                        | ✗                   |
| Resource leak detection             | ✓ (via diagnostic nodes) | ✗                   |
| ASan / LSan integration             | ✓                        | ✗                   |
| Test framework integration          | Native                   | Limited             |
| CI pipeline friendly                | ✓                        | Limited             |
| Throughput (approx.)                | 500–5000 cases/sec       | 50–100 cases/sec    |
| Baseline profiling                  | ✓                        | ✓                   |
| Performance testing                 | ✓ (+ internal metrics)   | ✓                   |
| Replay mode                         | ✓                        | ✓                   |
| Structured JSON findings            | ✓                        | ✓                   |
