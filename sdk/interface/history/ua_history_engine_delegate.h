// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_HISTORY_ENGINE_DELEGATE_H
#define UA_HISTORY_ENGINE_DELEGATE_H

#include "ua_history_store.h"

#include "ua_namespace_history_delegate.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include <memory>

namespace ua::history
{

/// @ingroup history
/// Canonical reference `NamespaceHistoryDelegate`. Owns a dedicated single-thread pool + strand so
/// the (potentially blocking) store I/O never runs on the server's async threads, and drives the
/// storage-agnostic `HistoryEngine` over an injected `HistoryStore`. The store is touched only from
/// the worker strand, so it needs no internal synchronisation.
///
/// The store is injected (dependency injection) rather than fixed at compile time to SQLite so one delegate
/// serves any backend, and so the engine can be exercised over an in-memory store in tests.
class HistoryEngineDelegate : public ua::NamespaceHistoryDelegate
{
public:
  /// Take ownership of `store`, the storage backend the wrapped `HistoryEngine` drives.
  /// @param store the storage backend that the wrapped `HistoryEngine` reads from and writes to.
  explicit HistoryEngineDelegate(std::unique_ptr<HistoryStore> store);

  Capabilities capabilities() const noexcept override;

  void read_raw_async(
    const ReadContext& context, std::vector<ReadRawItem> items, ReadRawCallback callback) noexcept override;

  void read_at_time_async(const ReadContext& context, std::vector<ReadAtTimeItem> items,
    ReadAtTimeCallback callback) noexcept override;

  void read_events_async(const ReadContext& context, std::vector<ReadEventsItem> items,
    ReadEventsCallback callback) noexcept override;

  void read_annotations_async(const ReadContext& context, std::vector<ReadAnnotationItem> items,
    ReadAnnotationCallback callback) noexcept override;

  void update_data_async(const UpdateContext& context, std::vector<UpdateDataItem> items,
    UpdateDataCallback callback) noexcept override;

  void update_events_async(const UpdateContext& context, std::vector<UpdateEventsItem> items,
    UpdateEventsCallback callback) noexcept override;

  void update_structure_data_async(const UpdateContext& context, std::vector<UpdateStructureDataItem> items,
    UpdateStructureDataCallback callback) noexcept override;

  void delete_raw_async(const UpdateContext& context, std::vector<DeleteRawItem> items,
    DeleteRawCallback callback) noexcept override;

  void delete_at_time_async(const UpdateContext& context, std::vector<DeleteAtTimeItem> items,
    DeleteAtTimeCallback callback) noexcept override;

  void delete_events_async(const UpdateContext& context, std::vector<DeleteEventsItem> items,
    DeleteEventsCallback callback) noexcept override;

private:
  // Destruction order: stop the pool (joins the worker) before the store it touches is destroyed.
  std::unique_ptr<HistoryStore> mStore;
  boost::asio::thread_pool mThreadPool;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
};

}  // namespace ua::history

#endif  // !UA_HISTORY_ENGINE_DELEGATE_H
