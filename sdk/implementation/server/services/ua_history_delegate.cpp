// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_history_delegate.h"

namespace ua
{

namespace
{

/// Build a BatchResult with per-item status = BadHistoryOperationUnsupported.
template<typename ResultT>
BatchResult<ResultT> unsupported_batch(size_t count)
{
  BatchResult<ResultT> batch;
  batch.items.reserve(count);
  for (size_t i = 0; i < count; ++i)
  {
    batch.items.emplace_back(StatusCode{Status::BadHistoryOperationUnsupported});
  }
  return batch;
}

}  // namespace

// --- Default implementations (return BadHistoryOperationUnsupported per item) ---

void NamespaceHistoryDelegate::read_raw_async(
  const ReadContext&, std::vector<ReadRawItem> items, ReadRawCallback callback) noexcept
{
  callback(unsupported_batch<ReadRawItemResult>(items.size()));
}

void NamespaceHistoryDelegate::read_at_time_async(
  const ReadContext&, std::vector<ReadAtTimeItem> items, ReadAtTimeCallback callback) noexcept
{
  callback(unsupported_batch<ReadAtTimeItemResult>(items.size()));
}

void NamespaceHistoryDelegate::read_processed_async(
  const ReadContext&, std::vector<ReadProcessedItem> items, ReadProcessedCallback callback) noexcept
{
  callback(unsupported_batch<ReadProcessedItemResult>(items.size()));
}

void NamespaceHistoryDelegate::read_annotations_async(
  const ReadContext&, std::vector<ReadAnnotationItem> items, ReadAnnotationCallback callback) noexcept
{
  callback(unsupported_batch<ReadAnnotationItemResult>(items.size()));
}

void NamespaceHistoryDelegate::read_events_async(
  const ReadContext&, std::vector<ReadEventsItem> items, ReadEventsCallback callback) noexcept
{
  callback(unsupported_batch<ReadEventsItemResult>(items.size()));
}

void NamespaceHistoryDelegate::update_data_async(
  const UpdateContext&, std::vector<UpdateDataItem> items, UpdateDataCallback callback) noexcept
{
  callback(unsupported_batch<UpdateDataItemResult>(items.size()));
}

void NamespaceHistoryDelegate::update_events_async(
  const UpdateContext&, std::vector<UpdateEventsItem> items, UpdateEventsCallback callback) noexcept
{
  callback(unsupported_batch<UpdateEventsItemResult>(items.size()));
}

void NamespaceHistoryDelegate::update_structure_data_async(const UpdateContext&,
  std::vector<UpdateStructureDataItem> items, UpdateStructureDataCallback callback) noexcept
{
  callback(unsupported_batch<UpdateStructureDataItemResult>(items.size()));
}

void NamespaceHistoryDelegate::delete_raw_async(
  const UpdateContext&, std::vector<DeleteRawItem> items, DeleteRawCallback callback) noexcept
{
  callback(unsupported_batch<DeleteItemResult>(items.size()));
}

void NamespaceHistoryDelegate::delete_at_time_async(
  const UpdateContext&, std::vector<DeleteAtTimeItem> items, DeleteAtTimeCallback callback) noexcept
{
  callback(unsupported_batch<DeleteItemResult>(items.size()));
}

void NamespaceHistoryDelegate::delete_events_async(
  const UpdateContext&, std::vector<DeleteEventsItem> items, DeleteEventsCallback callback) noexcept
{
  callback(unsupported_batch<DeleteItemResult>(items.size()));
}

}  // namespace ua
