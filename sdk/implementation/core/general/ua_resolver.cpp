// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/lexical_cast.hpp>

#include "ua_sync_wait.h"
#include "ua_callback_safety.h"
#include "ua_resolver.h"
#include "ua_to_result.h"

#include <future>

namespace ua
{

Resolver::Resolver(boost::asio::any_io_executor executor, std::chrono::seconds defaultTimeout)
  : mDefaultTimeout(defaultTimeout), mExecutor(executor), mResolver{executor}
{}

std::chrono::seconds Resolver::calc_timeout(optional<std::chrono::seconds> timeout) const
{
  auto to = mDefaultTimeout;
  if (timeout.has_value())
  {
    to = timeout.value();
  }
  return to;
}

void Resolver::resolve_endpoints_async(string_view hostname, uint16_t port,
  optional<std::chrono::seconds> timeout, CompleteCallback callback) noexcept

{
  // Outcome to report synchronously (already-in-flight, or an arming failure). Resolved inside the
  // locked scope, then fired after the lock is released so the user callback never runs while this
  // object's mutex is held (the callback-safety golden rule). When the arming succeeds this stays
  // empty and the completion handlers own the eventual callback.
  optional<EndpointListResult> immediateResult;

  {
    const Lock lk(mMutex);
    if (mCallback)
    {
      immediateResult = EndpointListResult{StatusCode{Status::BadInvalidState}};
    }
    else
    {
      // Arm the timer and resolve. Both Timer::schedule_after and async_resolve construct/copy
      // completion handlers and may throw (e.g. bad_alloc); building the resolver arguments may also
      // throw. Guard the whole synchronous arming region so a throw cannot escape the noexcept
      // boundary, and so a partially-armed resolver is rewound and the failure is reported rather
      // than silently dropped.
      //
      // The original `callback` parameter is only ever copied (into mCallback), never moved, so it
      // remains callable below to report an arming failure exactly once (the queued work never ran).
      try
      {
        mCallback = callback;
        auto to = calc_timeout(timeout);
        auto me = weak_from_this();

        mTimeoutTimer = Timer::schedule_after(mExecutor,
          to,
          [me](boost::system::error_code ec)
          {
            if (ec)
            {
              return;
            }
            auto resolver = me.lock();
            if (resolver)
            {
              CompleteCallback timedOut;
              {
                const Lock innerLk(resolver->mMutex);
                resolver->mResolver.cancel();
                timedOut = std::move(resolver->mCallback);
                resolver->mCallback = nullptr;
              }
              // Fire outside the lock (the callback-safety golden rule).
              if (timedOut)
              {
                detail::invoke_user_callback(timedOut, EndpointListResult{StatusCode{Status::BadTimeout}});
              }
            }
          });

        mResolver.async_resolve(std::string{hostname},
          boost::lexical_cast<std::string>(port),
          asio::ip::resolver_base::flags::numeric_service,
          [me](boost::system::error_code ec, asio::ip::tcp::resolver::results_type results)
          {
            auto resolver = me.lock();
            if (resolver)
            {
              CompleteCallback done;
              EndpointListResult result{StatusCode{Status::BadInternalError}};
              {
                const Lock innerLk(resolver->mMutex);
                try
                {
                  resolver->mTimeoutTimer.cancel();

                  if (ec != boost::system::errc::success)
                  {
                    result = EndpointListResult{StatusCode{Status::BadTcpInternalError}};
                  }
                  else
                  {
                    std::vector<asio::ip::tcp::endpoint> endpoints;
                    endpoints.resize(results.size());
                    std::ranges::copy(results, endpoints.begin());
                    result = EndpointListResult{std::move(endpoints)};
                  }
                }
                catch (...)
                {
                  result = EndpointListResult{ua::exception_to_status_code(std::current_exception())};
                }
                done = std::move(resolver->mCallback);
                resolver->mCallback = nullptr;
              }
              // Fire outside the lock (the callback-safety golden rule).
              if (done)
              {
                detail::invoke_user_callback(done, std::move(result));
              }
            }
          });
      }
      catch (...)
      {
        // Arming failed mid-way (e.g. bad_alloc constructing a handler). Rewind any partial state so
        // the resolver is free for a later attempt, then report the failure below (outside the lock).
        immediateResult = EndpointListResult{ua::exception_to_status_code(std::current_exception())};
        mTimeoutTimer.cancel();
        mCallback = nullptr;
      }
    }
  }

  // Report any synchronous outcome with the lock released, through the safe invoker so a throwing
  // user callback cannot escape this noexcept boundary. `callback` survives here because it was only
  // copied into mCallback above, so the error is never silently dropped.
  if (immediateResult)
  {
    detail::invoke_user_callback(callback, std::move(*immediateResult));
  }
}

EndpointListResult Resolver::try_resolve_endpoints_sync(
  string_view hostname, uint16_t port, optional<std::chrono::seconds> timeout) noexcept
{
  // The resolve has its own timeout; the deadline is one second past it, for a completion that never
  // arrives. A late completion writes into the helper's shared state, never into this frame.
  const auto deadline = std::chrono::duration_cast<std::chrono::milliseconds>(calc_timeout(timeout) + 1s);
  return ua::async::detail::blocking_call<EndpointListResult>(
    mExecutor,
    [&](std::function<void(EndpointListResult)> complete)
    { resolve_endpoints_async(hostname, port, timeout, std::move(complete)); },
    deadline);
}

EndpointList Resolver::resolve_endpoints_sync(
  string_view hostname, uint16_t port, optional<std::chrono::seconds> timeout)
{
  return ua::detail::good_value(try_resolve_endpoints_sync(hostname, port, timeout));
}

shared_ptr<Resolver> Resolver::create(
  boost::asio::any_io_executor executor, optional<std::chrono::seconds> timeout)
{
  class Wrapper : public Resolver
  {
  public:
    Wrapper(boost::asio::any_io_executor executor, std::chrono::seconds defaultTimeout)
      : Resolver(executor, defaultTimeout)
    {}
  };

  auto to = 5s;
  if (timeout.has_value())
  {
    to = timeout.value();
  }

  return make_shared<Wrapper>(executor, to);
}

}  // namespace ua
