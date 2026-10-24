// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_HELPERS_FAKE_TRANSPORT_CONNECTION_H
#define UA_TESTS_HELPERS_FAKE_TRANSPORT_CONNECTION_H

#include <boost/asio/ip/tcp.hpp>

#include "ua_connection_protocol.h"
#include "ua_transport_connection.h"

#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>

namespace ua::test_helpers
{

/**
 * @brief Scriptable `TransportConnection` for `ConnectionProtocol` tests.
 *
 * It supports the specific read/write patterns used by `ua::server::ConnectionProtocol`:
 * - Handshake (HEL/ACK/RHE): header via `async_read(header)`, body via `async_read(buffer, offset)`.
 * - After handshake: chunk header via `async_read(header)`, body via `async_read(buffer, offset)`.
 * - ERR frames: body fetched via legacy `bytes_available_to_read()` + sync `read(buffer)`.
 */
class FakeTransportConnection final : public ua::TransportConnection
{
public:
  void register_error_callback(ErrorCallback callback) override;
  void register_read_callback(ReadCompleteCallback callback) override;
  void register_write_callback(WriteCompleteCallback callback) override;

  asio::ip::tcp::endpoint get_local_endpoint() const override;

  void async_read(std::vector<byte>&& buffer, size_t offset = 0) override;

  size_t bytes_available_to_read() const override;
  StatusCode read(std::vector<byte>& buffer, size_t offset = 0) override;

  void async_write(std::vector<byte>&& buffer) override;
  void async_write(std::vector<byte>&& buffer, bool startsMessage) override;
  /// The startsMessage flag of every write, in order (the one-argument form records true).
  std::vector<bool> write_message_starts() const;
  /// An AfterPendingWrites close closes at once unless writes are held (hold_writes), in which case
  /// it waits for complete_held_writes, as a real transport waits for its queue to drain.
  void close_async(
    std::function<void(VoidResult)> callback = {}, CloseMode mode = CloseMode::Immediate) override;

  // Test API
  void enqueue_read_exact(std::vector<byte> bytes);
  void enqueue_read_error(StatusCode status, std::string description);
  void enqueue_hello_message(std::vector<byte> helloMessage);

  bool wait_for_write_count(size_t n, std::chrono::milliseconds timeout);
  std::vector<std::vector<byte>> writes() const;

  /// What peer_state() reports. Open (the default) defers to the transport default: DataWaiting while a
  /// served Hello remainder is unread, otherwise Open.
  void set_peer_state(PeerState state);
  PeerState peer_state() const override;

  /// The size of every synchronous read() served, in order.
  std::vector<size_t> sync_read_sizes() const;

  bool closed() const;
  size_t close_count() const;
  /// How many writes had been recorded when the first close happened (nullopt: not closed yet), so a
  /// test can tell which writes preceded the close.
  std::optional<size_t> writes_at_first_close() const;
  /// How many close_async calls asked for CloseMode::AfterPendingWrites.
  size_t close_after_writes_count() const;

  /// Hold write completions: later writes are recorded but their completion is withheld, so they
  /// count as still pending, until complete_held_writes() completes them (Good) in one batch.
  void hold_writes();
  void complete_held_writes();

  /// Enable stall mode: subsequent async_read calls store the callback
  /// without completing. Use complete_stalled_read() to deliver data later,
  /// or let the stalled read be abandoned (e.g. for timeout tests).
  void stall_reads();

  /// Check if there is a stalled read waiting.
  bool has_stalled_read() const;

  /// Wait for a close with timeout. Returns true if closed within timeout.
  bool wait_for_close(std::chrono::milliseconds timeout);

private:
  mutable std::mutex mMutex;
  std::condition_variable mCv;

  ErrorCallback mErrorCallback;
  ReadCompleteCallback mReadCallback;
  WriteCompleteCallback mWriteCallback;

  struct PendingRead
  {
    StatusCode status{Status::Good};
    std::string description;
    std::vector<byte> bytes;
  };

  std::queue<PendingRead> mPendingReads;

  // HEL remainder path.
  std::vector<byte> mHelloRemainder;
  bool mHelloRemainderAvailable{false};
  std::vector<size_t> mSyncReadSizes;
  PeerState mPeerState{PeerState::Open};

  bool mStallReads{false};

  // Deferred read: stored when async_read is called with no pending data.
  struct DeferredRead
  {
    std::vector<byte> buffer;
    size_t offset{0};
  };

  std::optional<DeferredRead> mDeferredRead;

  std::vector<std::vector<byte>> mWrites;
  std::vector<bool> mWriteMessageStarts;
  size_t mCloseCount{0};
  std::optional<size_t> mWritesAtFirstClose;
  size_t mCloseAfterWritesCount{0};
  bool mHoldWrites{false};
  size_t mHeldWrites{0};
  std::vector<std::function<void(VoidResult)>> mCloseAfterWritesCallbacks;
};

}  // namespace ua::test_helpers

#endif  // UA_TESTS_HELPERS_FAKE_TRANSPORT_CONNECTION_H
