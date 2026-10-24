// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_sync_wait.h"

#include <boost/asio/detail/scheduler.hpp>
#include <boost/asio/execution/context.hpp>
#include <boost/asio/execution_context.hpp>
#include <boost/asio/query.hpp>
#if defined(BOOST_ASIO_HAS_IOCP)
#include <boost/asio/detail/win_iocp_io_context.hpp>
#endif

namespace ua::async::detail
{

bool on_executor_context(const boost::asio::any_io_executor& ex) noexcept
{
  // An empty (default-constructed or moved-from) executor targets nothing, so it is running nothing:
  // a blocking wait cannot deadlock on it, and we must not touch it. This guard is required for
  // the noexcept contract - boost::asio::query on an empty any_io_executor throws bad_executor, and a
  // throw crossing this noexcept boundary would std::terminate the process (adversarial review section 3.1).
  if (!ex)
  {
    return false;
  }
  try
  {
    // Querying the execution context is layer-independent: a strand reports the same context as its
    // underlying executor. `execution_context` is deliberately non-polymorphic, so downcasting it to
    // io_context is undefined for thread_pool/system_context. Instead ask the scheduler service already
    // registered in that context; `can_dispatch()` is the predicate exposed by io_context::executor_type
    // and thread_pool::executor_type as running_in_this_thread().
    auto& context = boost::asio::query(ex, boost::asio::execution::context);
#if defined(BOOST_ASIO_HAS_IOCP)
    if (boost::asio::has_service<boost::asio::detail::win_iocp_io_context>(context))
    {
      return boost::asio::use_service<boost::asio::detail::win_iocp_io_context>(context).can_dispatch();
    }
#endif
    if (boost::asio::has_service<boost::asio::detail::scheduler>(context))
    {
      return boost::asio::use_service<boost::asio::detail::scheduler>(context).can_dispatch();
    }

    // A foreign execution context cannot prove that it has another thread available to satisfy the
    // future. Refuse the blocking wait conservatively instead of guessing or invoking undefined behaviour.
    return true;
  }
  catch (...)
  {
    // The predicate is a noexcept safety gate. Failure to inspect a non-empty executor must fail closed:
    // BadWouldBlock is recoverable, while blocking on an unclassified execution thread may deadlock.
    return true;
  }
}

std::shared_ptr<const ua::ErrorDetail> would_block_detail()
{
  return ua::ErrorDetail::build("WouldBlock",
    "synchronous wait refused: the calling thread runs the io_context that must complete the "
    "operation, so blocking here would deadlock - call the *_async variant, or invoke *_sync from a "
    "thread that does not run the SDK's io_context",
    "async.sync_wait")
    .cause(ua::Status::BadWouldBlock);
}

}  // namespace ua::async::detail
