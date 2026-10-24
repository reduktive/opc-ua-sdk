// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_RUNTIME_H
#define UA_RUNTIME_H

#include "ua_logger.h"
#include "ua_exceptions.h"
#include "ua_to_string.h"
#include "ua_result.h"
#include "ua_timer.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace ua
{

/// How long a shutdown may advertise, and how long the runtime will wait for it.
///
/// Two different clocks, kept apart on purpose. @ref grace is a PROMISE TO CLIENTS - it becomes
/// the server's `secondsTillShutdown`, which connected clients watch count down - so the runtime
/// must not join its executor before it has elapsed. @ref drainBudget is the runtime's own
/// patience: how long it waits for the executor to drain once everything has been asked to stop,
/// before giving up and reporting what is still holding it.
///
/// @ingroup core_async
struct ShutdownPolicy
{
  /// Advertised grace period; becomes `ShutdownOptions::grace` for a server.
  ///
  /// Three states, not two. `std::nullopt` - the default - means THE ATTACHMENT DECIDES: the
  /// runtime states no period of its own and a server falls back to its configured
  /// `ServerConfig::defaultShutdownGracePeriodSeconds`. An explicit
  /// `std::chrono::seconds{0}` is a different statement - shut down immediately, overriding
  /// whatever the attachment was configured with. Any other value overrides it likewise.
  ///
  /// The distinction exists because a runtime that always states a period silently disables
  /// every attachment's own configuration, which is what a plain `seconds{0}` default did.
  std::optional<std::chrono::seconds> grace{};
  /// Reason given to clients, and logged.
  LocalizedText reason{"en", "Shutting down"};
  /// How long to wait for the executor to drain after everything has been asked to stop.
  std::chrono::milliseconds drainBudget{std::chrono::seconds{30}};
};

/// Everything a shutdown step is told about the shutdown it is part of.
///
/// @ingroup core_async
struct ShutdownContext
{
  /// The policy resolved for this attachment (per-call, then per-attachment, then runtime default).
  ShutdownPolicy policy;
  /// The instant by which this step should have finished. Advisory: a step that blocks past it is
  /// reported, not killed. Spans the policy's grace period plus its drain budget - or the drain
  /// budget alone when @ref ShutdownPolicy::grace is unset, because the attachment's own grace
  /// period is then unknown to the runtime.
  std::chrono::steady_clock::time_point deadline;
  /// The runtime's logger, so a step can say what it is doing.
  Logger logger;
};

/// Stops a @ref Timer as part of a runtime shutdown. Found by ADL from @ref Runtime::attach.
///
/// @param timer The timer being stopped.
inline void runtime_shutdown(Timer& timer, const ShutdownContext&)
{
  timer.cancel();
}

/// How a @ref Runtime is built.
///
/// @ingroup core_async
struct RuntimeConfig
{
  /// Worker threads. Zero asks the runtime to choose, which it does from the hardware concurrency
  /// the process actually sees.
  unsigned threads{0};
  /// Default shutdown policy, applied to every attachment that does not override it.
  ShutdownPolicy shutdown{};
  /// Logger for shutdown diagnostics - notably, naming what is still holding the executor.
  Logger logger{};
  /// Stop attachments concurrently rather than in reverse order.
  ///
  /// Reverse order is the default because it is the safe answer when attachments are entangled -
  /// an in-process client connected to an in-process server, say. It costs time: grace periods ADD
  /// UP, so eight servers advertising ten seconds each is eighty seconds of shutdown. Set this
  /// when you know your attachments are independent of one another.
  bool concurrentShutdown{false};
};

/// Owns an executor and everything running on it, so teardown order is not something to remember.
///
/// The rule this removes is "shut down everything that owns a timer, in the right order, before
/// joining the executor you handed it". Nothing in the type system could express it, the set of
/// things that own timers is not discoverable, and getting it wrong produces a process that never
/// exits with nothing in the log. Here there is one lifetime: attach what you create, and reverse
/// destruction does the rest.
///
/// @code
/// ua::Runtime runtime{{.threads = 4}};
/// auto server = runtime.attach(
///   ua::server::Server::create(runtime.executor(), cfg, crypto, store, hooks));
/// // ... application ...
/// // ~Runtime stops what it attached, newest first, then joins the pool.
/// @endcode
///
/// Not copyable and not movable: its whole value is being THE lifetime.
///
/// @ingroup core_async
class Runtime
{
public:
  /// Constructs the runtime and starts its worker threads.
  /// @param config Threads, default shutdown policy, logger.
  explicit Runtime(RuntimeConfig config = {})
    : mConfig(std::move(config)), mPool(resolve_threads(mConfig.threads))
  {}

  /// Shuts down every attachment and joins the executor. Never throws.
  ~Runtime()
  {
    const VoidResult result = shutdown();
    if (result.is_bad())
    {
      mConfig.logger.error(
        {{"status", ua::to_string(result.status_code())}}, "Runtime shutdown did not complete cleanly");
    }
  }

  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;
  Runtime(Runtime&&) = delete;
  Runtime& operator=(Runtime&&) = delete;

  /// Returns the executor to hand to everything you create.
  /// @return The runtime's executor.
  boost::asio::any_io_executor executor()
  {
    return mPool.get_executor();
  }

  /// Takes ownership of @p handle and returns a reference to it.
  ///
  /// The attachment is stopped during shutdown by calling `runtime_shutdown(T&, const
  /// ShutdownContext&)`, found by argument-dependent lookup. A type with no such overload is refused
  /// at the caller's line by this function's constraint, rather than being attached and silently
  /// never torn down. The SDK's overloads are declared beside their types (`ua_server.h`,
  /// `ua_client.h`, `ua_core_client.h`), so including the type's header is enough.
  ///
  /// LIFETIME, and it is one sentence: the returned reference is valid for as long as this
  /// Runtime object is. Shutdown STOPS an attachment; destruction destroys it. So a server that
  /// has been shut down is still there to be called - the call fails with a status, as calls on a
  /// shut-down server do - rather than being a dangling reference.
  ///
  /// @tparam T Handle type; must be movable and have a `runtime_shutdown` overload.
  /// @param handle The object to take ownership of.
  /// @param policy Optional per-attachment shutdown policy; the runtime default otherwise.
  /// @return A reference to the attached object, owned by this runtime.
  /// @throws UaException carrying `Bad_InvalidState` if the runtime has already shut down.
  template<class T>
    requires requires(T& attached, const ShutdownContext& context) { runtime_shutdown(attached, context); }
  T& attach(T handle, std::optional<ShutdownPolicy> policy = std::nullopt)
  {
    auto owned = std::make_shared<T>(std::move(handle));
    const std::lock_guard lock{mMutex};
    if (mShutdownStarted)
    {
      // Accepting work that will never be torn down is worse than refusing it, and there is no
      // such thing as a dead reference to hand back - so this fails loudly.
      throw UaException{StatusCode{Status::BadInvalidState,
        ErrorDetail::build("RuntimeAlreadyShutDown",
          "Cannot attach to a runtime that has already shut down",
          "Runtime::attach")}};
    }
    Attachment attachment;
    attachment.holder = owned;
    attachment.policy = policy.value_or(mConfig.shutdown);
    attachment.label = typeid(T).name();
    attachment.stop = [owned](const ShutdownContext& context)
    {
      runtime_shutdown(*owned, context);  // ADL
    };
    mAttachments.push_back(std::move(attachment));
    return *owned;
  }

  /// Takes an attachment back out of the runtime, so it can outlive it.
  ///
  /// The reference returned by @ref attach is invalid afterwards: the runtime no longer holds
  /// the object, the caller does.
  ///
  /// @tparam T Attached type.
  /// @param attached The reference returned by @ref attach.
  /// @return The object, or `std::nullopt` if it is not attached to this runtime.
  template<class T>
  std::optional<T> detach(T& attached)
  {
    const std::lock_guard lock{mMutex};
    for (auto it = mAttachments.begin(); it != mAttachments.end(); ++it)
    {
      if (it->holder.get() == static_cast<const void*>(std::addressof(attached)))
      {
        std::optional<T> taken{std::move(attached)};
        mAttachments.erase(it);
        return taken;
      }
    }
    return std::nullopt;
  }

  /// Stops every attachment and joins the executor.
  ///
  /// Idempotent: a second call returns success immediately, which is what lets the destructor call
  /// it unconditionally. Runs on the calling thread.
  ///
  /// @param policy Optional override of the runtime's default policy for this call.
  /// @return Good when everything stopped and the executor drained; otherwise the first failure,
  ///         or `Bad_Timeout` naming what is still holding the executor.
  VoidResult shutdown(std::optional<ShutdownPolicy> policy = std::nullopt) noexcept
  {
    // The attachments STAY. attach() handed out a reference to each, and that reference must
    // stay valid for as long as this Runtime object does - so shutdown STOPS them and
    // destruction destroys them. That is the whole rule a caller has to remember, and it is why
    // attach() can return a plain reference at all.
    std::vector<Attachment> attachments;
    {
      const std::lock_guard lock{mMutex};
      if (mShutdownStarted)
      {
        return VoidResult{};
      }
      mShutdownStarted = true;
      attachments = mAttachments;  // stop steps, in attachment order
    }

    const ShutdownPolicy resolved = policy.value_or(mConfig.shutdown);
    VoidResult firstFailure{};
    try
    {
      // Newest first. Reverse of attachment is the one ordering C++ gives for free, and it is the
      // safe answer when two attachments are entangled - a client attached after the server it
      // talks to is stopped before it.
      std::reverse(attachments.begin(), attachments.end());
      if (mConfig.concurrentShutdown)
      {
        run_concurrently(attachments, resolved, firstFailure);
      }
      else
      {
        for (auto& attachment : attachments)
        {
          const VoidResult stopped = stop_one(attachment, resolved);
          if (stopped.is_bad() && firstFailure.is_good())
          {
            firstFailure = stopped;
          }
        }
      }

      const VoidResult drained = join_within(resolved.drainBudget, attachments);
      if (drained.is_bad() && firstFailure.is_good())
      {
        firstFailure = drained;
      }
    }
    catch (...)
    {
      firstFailure = VoidResult{StatusCode{Status::BadInternalError}};
    }
    return firstFailure;
  }

private:
  struct Attachment
  {
    std::shared_ptr<void> holder;
    std::function<void(const ShutdownContext&)> stop;
    ShutdownPolicy policy;
    std::string label;
  };

  static unsigned resolve_threads(unsigned requested)
  {
    if (requested != 0)
    {
      return requested;
    }
    // What the process can actually run, not a hard-coded number.
    const unsigned detected = std::thread::hardware_concurrency();
    return detected == 0 ? 2u : detected;
  }

  VoidResult stop_one(Attachment& attachment, const ShutdownPolicy& fallback)
  {
    const ShutdownPolicy policy = attachment.policy.drainBudget.count() == 0 ? fallback : attachment.policy;
    // The deadline covers the grace period only when the policy names one. With grace unset the
    // attachment supplies its own period and the runtime does not know it, so the deadline spans
    // the drain budget alone and may fall EARLIER than the attachment actually finishes. It is
    // advisory - a step past it is reported, never killed - so this is stated rather than guessed.
    const std::chrono::steady_clock::duration grace = policy.grace.value_or(std::chrono::seconds{0});
    const ShutdownContext context{
      policy, std::chrono::steady_clock::now() + grace + policy.drainBudget, mConfig.logger};
    try
    {
      attachment.stop(context);
      return VoidResult{};
    }
    catch (const std::exception& failure)
    {
      mConfig.logger.error(
        {{"attachment", attachment.label}, {"reason", failure.what()}}, "An attachment failed to stop");
      return VoidResult{StatusCode{Status::BadInternalError}};
    }
    catch (...)
    {
      return VoidResult{StatusCode{Status::BadInternalError}};
    }
  }

  void run_concurrently(
    std::vector<Attachment>& attachments, const ShutdownPolicy& fallback, VoidResult& firstFailure)
  {
    std::mutex failureMutex;
    std::vector<std::thread> workers;
    workers.reserve(attachments.size());
    for (auto& attachment : attachments)
    {
      workers.emplace_back(
        [this, &attachment, &fallback, &firstFailure, &failureMutex]
        {
          const VoidResult stopped = stop_one(attachment, fallback);
          if (stopped.is_bad())
          {
            const std::lock_guard lock{failureMutex};
            if (firstFailure.is_good())
            {
              firstFailure = stopped;
            }
          }
        });
    }
    for (auto& worker : workers)
    {
      worker.join();
    }
  }

  /// Joins the pool, but not forever: a bounded wait is what turns "the process will not exit"
  /// into a log line naming what is still holding the executor.
  VoidResult join_within(std::chrono::milliseconds budget, const std::vector<Attachment>& attachments)
  {
    std::mutex doneMutex;
    std::condition_variable doneSignal;
    bool joined = false;

    std::thread joiner(
      [this, &doneMutex, &doneSignal, &joined]
      {
        mPool.join();
        {
          const std::lock_guard lock{doneMutex};
          joined = true;
        }
        doneSignal.notify_all();
      });

    // Take the ANSWER from wait_for, not from the flag afterwards: forcing the pool below makes
    // the join finish, so re-reading the flag at the end would report success every time.
    bool drained = false;
    {
      std::unique_lock lock{doneMutex};
      drained = doneSignal.wait_for(lock, budget, [&joined] { return joined; });
    }

    if (!drained)
    {
      std::string held;
      for (const auto& attachment : attachments)
      {
        held += (held.empty() ? "" : ", ") + attachment.label;
      }
      mConfig.logger.error({{"attachments", held}},
        "The executor did not drain within the budget: something attached is still running work");
      mPool.stop();  // abandon what is left rather than hang the process
    }
    joiner.join();
    return drained ? VoidResult{} : VoidResult{StatusCode{Status::BadTimeout}};
  }

  RuntimeConfig mConfig;
  boost::asio::thread_pool mPool;
  std::mutex mMutex;
  std::vector<Attachment> mAttachments;  // guarded by mMutex, in attachment order
  bool mShutdownStarted{false};  // guarded by mMutex
};

}  // namespace ua

#endif  // UA_RUNTIME_H
