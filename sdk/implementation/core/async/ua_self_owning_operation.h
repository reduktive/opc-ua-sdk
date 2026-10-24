// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SELF_OWNING_OPERATION_H
#define UA_SELF_OWNING_OPERATION_H

#include "ua_await_callback.h"
#include "ua_callback_safety.h"
#include "ua_coro.h"
#include "ua_logger.h"
#include "ua_on_strand.h"
#include "ua_to_result.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <memory>
#include <cstddef>
#include <type_traits>
#include <utility>

namespace ua::async
{

/// A root task owned by the work outstanding on it.
///
/// Most converted components hold their Task in a member of something that outlives it - a
/// request-scoped service the session owns, whose `weak_from_this()` is the owner every
/// @ref ua::async::await_callback names (R14). Some async work has no such home: a free function's
/// operation, or a per-REQUEST operation of a component that may have several in flight and so has no
/// single member slot to put one in. Because `await_callback` holds its owner WEAKLY by design, a
/// task started and left alone is destroyed before its first answer arrives.
///
/// So the operation is owned by the work outstanding on it. That is not a new idea here: it is
/// exactly what @ref ua::async::post_owning has always done for the callback chains this replaces -
/// the completion it returns holds a strong reference, so
///
///   - a collaborator holding the completion holds the operation;
///   - one that DROPS it unanswered drops the operation with it, which is the only thing that can end
///     a body waiting on an answer that will never come;
///   - one that answers moves the reference into the queued turn, so an executor torn down with that
///     turn still queued destroys the operation rather than stranding it;
///   - and because the handler is moved out on the first invocation, a collaborator that answers
///     twice does nothing the second time.
///
/// It also keeps the post per step that a callback chain had, so the strand goes back after every
/// answer and no body holds a thread for its whole length (R18).
///
/// @par How to use it
/// Derive with CRTP, give the derived type a `ua::async::Task<> run()` and a
/// `void fail_to_start(StatusCode)`, hand every collaborator @ref owned_completion, and start it with
/// @ref launch:
///
/// @code
/// class ResolveThing final : public ua::async::SelfOwningOperation<ResolveThing>
/// {
/// public:
///   static void start(AddressSpace space, Callback done)
///   {
///     launch(std::make_shared<ResolveThing>(std::move(space), std::move(done)));
///   }
/// private:
///   friend class ua::async::SelfOwningOperation<ResolveThing>;
///   ua::async::Task<> run();                      // the body
///   void fail_to_start(StatusCode status);        // answers if the frame could not be allocated
/// };
/// @endcode
///
/// @tparam Operation The derived operation type.
/// @ingroup async
template<typename Operation>
class SelfOwningOperation : public std::enable_shared_from_this<Operation>
{
public:
  SelfOwningOperation(const SelfOwningOperation&) = delete;
  SelfOwningOperation& operator=(const SelfOwningOperation&) = delete;
  SelfOwningOperation(SelfOwningOperation&&) = delete;
  SelfOwningOperation& operator=(SelfOwningOperation&&) = delete;

protected:
  /// @param strand The strand this operation's body runs and resumes on.
  ///
  /// A STRAND, not a bare executor. @ref ua::async::await_callback reads and writes the task's own
  /// state - its generation, its suspended handle - on whatever it is given, and a body on a
  /// multi-threaded executor would have the thread that suspends it and the thread that answers it
  /// touching that state at once. On a nested @ref ua::async::Task, whose continuation pointer has no
  /// lock at all, losing that race means the outer body is never resumed and the caller never
  /// answered. An operation that has no strand of its own should make one
  /// (`boost::asio::make_strand`); one that belongs to a component should use the component's.
  /// @param logger Logger for the posts this makes.
  SelfOwningOperation(boost::asio::strand<boost::asio::any_io_executor> strand, Logger logger)
    : mStrand(std::move(strand)), mLogger(std::move(logger))
  {}

  ~SelfOwningOperation() = default;

  /// Starts @p operation's body on its strand, and leaves it owned by the work outstanding on it.
  ///
  /// Posted rather than run here for two reasons, and the first is the sharper one.
  /// @ref ua::async::await_callback hands the collaborator its completion in `await_ready`, BEFORE
  /// `await_suspend` has written the task's suspended handle - so a body started on the caller's
  /// thread can have a collaborator answer from another thread into state the caller's thread is
  /// still writing (R5). And a caller that asked an asynchronous question should not be answered
  /// before it has finished asking, which is what a callback chain's own `start()`-style post gave it.
  /// Failure to enqueue answers through fail_to_start while this call still owns the operation.
  static void launch(const std::shared_ptr<Operation>& operation) noexcept
  {
    try
    {
      ua::async::post_owning(operation.get(),
        operation->mStrand,
        operation->mLogger,
        [](Operation& self)
        {
          try
          {
            self.mTask = self.run();
          }
          catch (...)
          {
            // The frame can fail allocation before its body has an exception boundary.
            self.fail_to_start(ua::exception_to_status_code(std::current_exception()));
          }
        })();
    }
    catch (...)
    {
      ::ua::detail::invoke_user_callback(
        operation->mLogger,
        [](Operation& self, StatusCode status) { self.fail_to_start(std::move(status)); },
        *operation,
        ua::exception_to_status_code(std::current_exception()));
    }
  }

  /// Hands a collaborator a completion that owns this operation while the answer is outstanding.
  ///
  /// @see SelfOwningOperation for what that ownership buys and why it is `post_owning` that provides
  ///      it.
  /// @param failure Optional handler(Operation&, StatusCode) for an enqueue or completion-invocation
  ///                failure. It may run on the producer's thread while the operation is pinned;
  ///                it must not access coroutine state or require the operation's strand.
  template<typename Completion, typename Failure = std::nullptr_t>
  auto owned_completion(Completion completion, Failure failure = nullptr)
  {
    auto posted = ua::async::post_owning(static_cast<Operation*>(this),
      mStrand,
      mLogger,
      [completion = std::move(completion), failure]([[maybe_unused]] Operation& self, auto&&... args) mutable
      {
        if constexpr (std::is_same_v<Failure, std::nullptr_t>)
        {
          completion(std::forward<decltype(args)>(args)...);
        }
        else
        {
          try
          {
            completion(std::forward<decltype(args)>(args)...);
          }
          catch (...)
          {
            ::ua::detail::invoke_user_callback(
              self.mLogger, failure, self, ua::exception_to_status_code(std::current_exception()));
          }
        }
      });
    if constexpr (std::is_same_v<Failure, std::nullptr_t>)
    {
      return posted;
    }
    else
    {
      return [weak = this->weak_from_this(), posted = std::move(posted), failure = std::move(failure)](
               auto&&... args) mutable noexcept
      {
        // Keep the operation alive if enqueue destroys the handler containing its last posted owner.
        auto owner = weak.lock();
        if (!owner)
        {
          return;
        }
        try
        {
          posted(std::forward<decltype(args)>(args)...);
        }
        catch (...)
        {
          ::ua::detail::invoke_user_callback(
            owner->mLogger, failure, *owner, ua::exception_to_status_code(std::current_exception()));
        }
      };
    }
  }

  /// Awaits one collaborator call, on this operation's strand and owning this operation until it
  /// answers.
  ///
  /// @tparam T        What the collaborator answers with.
  /// @tparam Initiate Invoked with the completion to hand the collaborator.
  /// @param failure Optional failure handler with the @ref owned_completion contract.
  template<typename T, typename Initiate, typename Failure = std::nullptr_t>
  auto await_step(Initiate&& initiate, Failure failure = nullptr)
  {
    return ua::async::await_callback<T>(mStrand,
      mLogger,
      this->weak_from_this(),
      [this, initiate = std::forward<Initiate>(initiate), failure = std::move(failure)](
        auto completion) mutable
      { initiate(this->owned_completion(std::move(completion), std::move(failure))); });
  }

  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  Logger mLogger;

private:
  /// The body. Destroyed with this operation, which happens when nothing is outstanding on it.
  ua::async::Task<> mTask;
};

}  // namespace ua::async

#endif  // !UA_SELF_OWNING_OPERATION_H
