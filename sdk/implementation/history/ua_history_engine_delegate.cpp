// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_history_engine_delegate.h"

#include "ua_history_engine.h"

#include "ua_to_result.h"

#include <boost/asio/post.hpp>

#include <exception>
#include <string>
#include <string_view>
#include <utility>
#include "ua_on_strand.h"

namespace ua::history
{

namespace
{

// Defence-in-depth backstop. The engine already converts store failures to error Results (via
// ua::detail::to_result), so nothing should escape  -  but every *_async method is `noexcept`, so any
// stray exception (a non-store throw, std::bad_alloc) must become an error item result rather than
// terminate the process. exception_to_status_code preserves a UaException's StatusCode + ErrorDetail.
template<typename ItemResult, typename Fn>
ItemResult guarded_item(Fn&& compute) noexcept
{
  try
  {
    return std::forward<Fn>(compute)();
  }
  catch (...)
  {
    return ItemResult{ua::exception_to_status_code(std::current_exception())};
  }
}

}  // namespace

HistoryEngineDelegate::HistoryEngineDelegate(std::unique_ptr<HistoryStore> store)
  : mStore(std::move(store)), mThreadPool(1), mStrand(boost::asio::make_strand(mThreadPool.get_executor()))
{}

ua::NamespaceHistoryDelegate::Capabilities HistoryEngineDelegate::capabilities() const noexcept
{
  Capabilities caps;
  caps.readRaw = true;
  caps.readModified = true;
  caps.readAtTime = true;
  caps.readEvents = true;
  caps.readAnnotations = true;
  caps.updateData = true;
  caps.updateEvent = true;
  caps.insertAnnotation = true;
  caps.deleteRaw = true;
  caps.deleteAtTime = true;
  caps.deleteEvents = true;
  return caps;
}

void HistoryEngineDelegate::read_raw_async(
  const ReadContext& /*context*/, std::vector<ReadRawItem> items, ReadRawCallback callback) noexcept
{
  boost::asio::post(mStrand,
    ua::async::guarded(ua::Logger{},
      [this, items = std::move(items), callback = std::move(callback)]() mutable
      {
        ua::BatchResult<ReadRawItemResult> batch;
        batch.items.reserve(items.size());
        for (auto& item : items)
          batch.items.push_back(
            guarded_item<ReadRawItemResult>([&] { return HistoryEngine::read_raw(*mStore, item); }));
        callback(std::move(batch));
      }));
}

void HistoryEngineDelegate::read_at_time_async(
  const ReadContext& /*context*/, std::vector<ReadAtTimeItem> items, ReadAtTimeCallback callback) noexcept
{
  boost::asio::post(mStrand,
    ua::async::guarded(ua::Logger{},
      [this, items = std::move(items), callback = std::move(callback)]() mutable
      {
        ua::BatchResult<ReadAtTimeItemResult> batch;
        batch.items.reserve(items.size());
        for (const auto& item : items)
          batch.items.push_back(
            guarded_item<ReadAtTimeItemResult>([&] { return HistoryEngine::read_at_time(*mStore, item); }));
        callback(std::move(batch));
      }));
}

void HistoryEngineDelegate::read_events_async(
  const ReadContext& /*context*/, std::vector<ReadEventsItem> items, ReadEventsCallback callback) noexcept
{
  boost::asio::post(mStrand,
    ua::async::guarded(ua::Logger{},
      [this, items = std::move(items), callback = std::move(callback)]() mutable
      {
        ua::BatchResult<ReadEventsItemResult> batch;
        batch.items.reserve(items.size());
        for (auto& item : items)
          batch.items.push_back(
            guarded_item<ReadEventsItemResult>([&] { return HistoryEngine::read_events(*mStore, item); }));
        callback(std::move(batch));
      }));
}

void HistoryEngineDelegate::read_annotations_async(const ReadContext& /*context*/,
  std::vector<ReadAnnotationItem> items, ReadAnnotationCallback callback) noexcept
{
  boost::asio::post(mStrand,
    ua::async::guarded(ua::Logger{},
      [this, items = std::move(items), callback = std::move(callback)]() mutable
      {
        ua::BatchResult<ReadAnnotationItemResult> batch;
        batch.items.reserve(items.size());
        for (const auto& item : items)
          batch.items.push_back(guarded_item<ReadAnnotationItemResult>(
            [&] { return HistoryEngine::read_annotations(*mStore, item); }));
        callback(std::move(batch));
      }));
}

void HistoryEngineDelegate::update_data_async(
  const UpdateContext& context, std::vector<UpdateDataItem> items, UpdateDataCallback callback) noexcept
{
  boost::asio::post(mStrand,
    ua::async::guarded(ua::Logger{},
      [this,
        items = std::move(items),
        callback = std::move(callback),
        userName = std::string{std::string_view{context.userName}}]() mutable
      {
        ua::BatchResult<UpdateDataItemResult> batch;
        batch.items.reserve(items.size());
        for (const auto& item : items)
          batch.items.push_back(guarded_item<UpdateDataItemResult>(
            [&] { return HistoryEngine::update_data(*mStore, item, userName); }));
        callback(std::move(batch));
      }));
}

void HistoryEngineDelegate::update_structure_data_async(const UpdateContext& /*context*/,
  std::vector<UpdateStructureDataItem> items, UpdateStructureDataCallback callback) noexcept
{
  boost::asio::post(mStrand,
    ua::async::guarded(ua::Logger{},
      [this, items = std::move(items), callback = std::move(callback)]() mutable
      {
        ua::BatchResult<UpdateStructureDataItemResult> batch;
        batch.items.reserve(items.size());
        for (const auto& item : items)
          batch.items.push_back(guarded_item<UpdateStructureDataItemResult>(
            [&] { return HistoryEngine::update_structure_data(*mStore, item); }));
        callback(std::move(batch));
      }));
}

void HistoryEngineDelegate::delete_raw_async(
  const UpdateContext& context, std::vector<DeleteRawItem> items, DeleteRawCallback callback) noexcept
{
  boost::asio::post(mStrand,
    ua::async::guarded(ua::Logger{},
      [this,
        items = std::move(items),
        callback = std::move(callback),
        userName = std::string{std::string_view{context.userName}}]() mutable
      {
        ua::BatchResult<DeleteItemResult> batch;
        batch.items.reserve(items.size());
        for (const auto& item : items)
          batch.items.push_back(guarded_item<DeleteItemResult>(
            [&] { return HistoryEngine::delete_raw(*mStore, item, userName); }));
        callback(std::move(batch));
      }));
}

void HistoryEngineDelegate::delete_at_time_async(
  const UpdateContext& context, std::vector<DeleteAtTimeItem> items, DeleteAtTimeCallback callback) noexcept
{
  boost::asio::post(mStrand,
    ua::async::guarded(ua::Logger{},
      [this,
        items = std::move(items),
        callback = std::move(callback),
        userName = std::string{std::string_view{context.userName}}]() mutable
      {
        ua::BatchResult<DeleteItemResult> batch;
        batch.items.reserve(items.size());
        for (const auto& item : items)
          batch.items.push_back(guarded_item<DeleteItemResult>(
            [&] { return HistoryEngine::delete_at_time(*mStore, item, userName); }));
        callback(std::move(batch));
      }));
}

void HistoryEngineDelegate::update_events_async(const UpdateContext& /*context*/,
  std::vector<UpdateEventsItem> items, UpdateEventsCallback callback) noexcept
{
  boost::asio::post(mStrand,
    ua::async::guarded(ua::Logger{},
      [this, items = std::move(items), callback = std::move(callback)]() mutable
      {
        ua::BatchResult<UpdateEventsItemResult> batch;
        batch.items.reserve(items.size());
        for (const auto& item : items)
          batch.items.push_back(guarded_item<UpdateEventsItemResult>(
            [&] { return HistoryEngine::update_events(*mStore, item); }));
        callback(std::move(batch));
      }));
}

void HistoryEngineDelegate::delete_events_async(const UpdateContext& /*context*/,
  std::vector<DeleteEventsItem> items, DeleteEventsCallback callback) noexcept
{
  boost::asio::post(mStrand,
    ua::async::guarded(ua::Logger{},
      [this, items = std::move(items), callback = std::move(callback)]() mutable
      {
        ua::BatchResult<DeleteItemResult> batch;
        batch.items.reserve(items.size());
        for (const auto& item : items)
          batch.items.push_back(
            guarded_item<DeleteItemResult>([&] { return HistoryEngine::delete_events(*mStore, item); }));
        callback(std::move(batch));
      }));
}

}  // namespace ua::history
