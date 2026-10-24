// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#pragma once

#include "ua_callback_safety.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_namespace.h"
#include "ua_request_info.h"
#include "ua_result.h"
#include "ua_to_result.h"

#include <atomic>
#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <mutex>
#include <span>
#include <type_traits>
#include <utility>

namespace ua::detail
{

/// The address space's entry for the subscription's monitoring calls (NR-45 rule 3).
///
/// Each member calls one namespace's batched monitoring member with the guards of NR-23 rule 4: a throw
/// answers every item of the call `Bad_InternalError` (`NamespaceCallThrew`), also after the first answer
/// given during the call, which is held until the member returns; a completion after the first is ignored; an
/// answer whose batch status is Good and whose item count differs from the call's answers every item
/// `Bad_InternalError` (`NamespaceItemCountMismatch`), since no answer can be matched to its item. The answer
/// handed on is therefore a Bad batch status or exactly one item per item asked, and it is handed on once the
/// member has returned. No lock is held while the namespace runs or while an answer is handed on. A create
/// answer the entry does not hand on (a second one, one of the wrong size, or one a throw overrides) goes to
/// the caller's release function, since no item holds its handles. No other route work applies to monitoring.
///
/// The completion and the release function are the caller's and must not throw; a throw from either is
/// dropped.
class MonitoringEntry
{
public:
  /// Calls @p nameSpace's `create_monitoring_async`.
  ///
  /// @param nameSpace The namespace that owns the items' Nodes.
  /// @param request   The request served.
  /// @param caller    The subscription's current caller, `sink->caller()`; valid until this returns.
  /// @param items     The items; valid until the namespace completes.
  /// @param complete  A Bad batch status, or one result per item; called once.
  /// @param release   Each answer not handed on, whose good handles no item holds; it may be called on the
  /// thread
  ///                  of a namespace's late answer, inside that answer, so it must not call the namespace
  ///                  back on it.
  static void create(const shared_ptr<Namespace>& nameSpace, const RequestInfo& request,
    const CallerInfo* caller, std::span<const MonitoringCreateItem> items,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> complete,
    std::function<void(BatchResult<MonitoringCreateItemResult>)> release) noexcept
  {
    call<MonitoringCreateItemResult>(
      items.size(),
      [&](std::function<void(BatchResult<MonitoringCreateItemResult>)> answer)
      { nameSpace->create_monitoring_async(request, caller, items, std::move(answer)); },
      std::move(complete),
      std::move(release));
  }

  /// Calls @p nameSpace's `modify_monitoring_async`.
  ///
  /// @param nameSpace The namespace that issued the handles.
  /// @param request   The request served.
  /// @param items     The modifications; valid until the namespace completes.
  /// @param complete  A Bad batch status, or one result per item.
  static void modify(const shared_ptr<Namespace>& nameSpace, const RequestInfo& request,
    std::span<const MonitoringModifyItem> items,
    std::function<void(BatchResult<MonitoringModifyItemResult>)> complete) noexcept
  {
    call<MonitoringModifyItemResult>(
      items.size(),
      [&](std::function<void(BatchResult<MonitoringModifyItemResult>)> answer)
      { nameSpace->modify_monitoring_async(request, items, std::move(answer)); },
      std::move(complete),
      [](BatchResult<MonitoringModifyItemResult>) noexcept {});
  }

  /// Calls @p nameSpace's `delete_monitoring_async`.
  ///
  /// @param nameSpace The namespace that issued the handles.
  /// @param request   The request served (the server's own: a release outlives its request).
  /// @param handles   The handles; valid until the namespace completes.
  /// @param complete  A Bad batch status, or one result per handle.
  static void remove(const shared_ptr<Namespace>& nameSpace, const RequestInfo& request,
    std::span<const MonitoringHandle> handles, std::function<void(BatchResult<VoidResult>)> complete) noexcept
  {
    call<VoidResult>(
      handles.size(),
      [&](std::function<void(BatchResult<VoidResult>)> answer)
      { nameSpace->delete_monitoring_async(request, handles, std::move(answer)); },
      std::move(complete),
      [](BatchResult<VoidResult>) noexcept {});
  }

private:
  template<typename Item>
  static BatchResult<Item> failed(StatusCode status)
  {
    BatchResult<Item> answer;
    answer.batchStatus = VoidResult{std::move(status)};
    return answer;
  }

  // One guarded call: @p invoke calls the namespace with the answer function; @p dropped receives each answer
  // that is not handed on. An answer given while the member runs is held until it returns, so that a throw
  // out of the member is the call's outcome even after an answer. Only the first pending answer is held;
  // later answers are released outside the mutex. An answer from another thread cannot precede the first.
  template<typename Item, typename Invoke>
  static void call(std::size_t expected, Invoke&& invoke, std::function<void(BatchResult<Item>)> complete,
    std::function<void(BatchResult<Item>)> dropped) noexcept
  {
    static_assert(std::is_nothrow_move_constructible_v<BatchResult<Item>>);

    struct Calling
    {
      std::mutex mutex;
      bool returned{false};
      std::optional<BatchResult<Item>> held;
      std::atomic<bool> answered{false};
      std::size_t expected{0};
      std::function<void(BatchResult<Item>)> complete;
      std::function<void(BatchResult<Item>)> dropped;

      // The first answer is handed on, checked for its size; every later one is dropped.
      void accept(BatchResult<Item> result) noexcept
      {
        try
        {
          if (answered.exchange(true, std::memory_order_acq_rel))
          {
            dropped(std::move(result));
            return;
          }
          if (result.batchStatus.is_good() && result.items.size() != expected)
          {
            const auto actual = result.items.size();
            dropped(std::move(result));
            complete(failed<Item>(StatusCode{Status::BadInternalError,
              ErrorDetail::build("NamespaceItemCountMismatch",
                "The namespace answered another number of items than it was asked for",
                "AddressSpace")
                .context(ContextKeys::sizeExpected, expected)
                .context(ContextKeys::sizeActual, actual)}));
            return;
          }
          complete(std::move(result));
        }
        catch (...)
        {
          // Out of memory while building the failure: the call stays unanswered.
          ignore_expected_exception();
        }
      }
    };

    shared_ptr<Calling> calling;
    try
    {
      calling = std::make_shared<Calling>();
    }
    catch (...)
    {
      complete(failed<Item>(StatusCode{Status::BadOutOfMemory}));
      return;
    }
    calling->expected = expected;
    calling->complete = std::move(complete);
    calling->dropped = std::move(dropped);
    const auto answer = [calling](BatchResult<Item> result)
    {
      try
      {
        bool returned;
        {
          const std::lock_guard lock{calling->mutex};
          returned = calling->returned;
          if (!returned && !calling->held)
          {
            calling->held.emplace(std::move(result));
            return;
          }
        }
        if (returned)
        {
          calling->accept(std::move(result));
        }
        else
        {
          calling->dropped(std::move(result));
        }
      }
      catch (...)
      {
        ignore_expected_exception();
      }
    };
    try
    {
      invoke(answer);
    }
    catch (...)
    {
      try
      {
        calling->accept(failed<Item>(StatusCode{Status::BadInternalError,
          ErrorDetail::build("NamespaceCallThrew", "The namespace's member threw", "AddressSpace")
            .cause(exception_to_status_code(std::current_exception()))}));
      }
      catch (...)
      {
        calling->accept(failed<Item>(StatusCode{Status::BadInternalError}));
      }
    }
    for (;;)
    {
      std::optional<BatchResult<Item>> retainedResult;
      {
        const std::lock_guard lock{calling->mutex};
        if (!calling->held)
        {
          calling->returned = true;
          break;
        }
        retainedResult.emplace(std::move(*calling->held));
        calling->held.reset();
      }
      calling->accept(std::move(*retainedResult));
    }
  }
};

}  // namespace ua::detail
