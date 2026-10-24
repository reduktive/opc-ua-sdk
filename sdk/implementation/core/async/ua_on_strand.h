// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ON_STRAND_H
#define UA_ON_STRAND_H

/// @file
/// @brief Strand-hopping callback adapters with weak-lifetime safety.
/// @ingroup async

// post_borrowing / post_owning - the sanctioned ergonomic helpers for posting a
// continuation onto a component's strand (borrowing = weak lifetime) or its
// executor (owning = strong lifetime), routed through ua::async::guarded so an
// exception can never escape the Asio completion boundary into std::terminate.
// They supersede the earlier on_strand / on_strand_n weak-strand adapters (now
// removed): the strand and logger are passed in by the caller rather than read
// from a component's members, so no strand is ever exposed.
//
// guarded - the `noexcept` exception-consuming wrapper for our own async
// continuations - lives here too (folded in from the former ua_guarded.h, of
// which this header was the only non-test consumer).

#include "ua_logger.h"
#include "ua_callback_safety.h"
#include "ua_to_result.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cassert>
#include <functional>
#include <memory>
#include <optional>
#include <tuple>
#include <type_traits>
#include <utility>

namespace ua::async
{

namespace detail
{

/// Logs the exception currently being handled, then swallows it.
///
/// Out-of-line backend for @ref ua::async::guarded. Must be called only from
/// within an active `catch` block: it inspects `std::current_exception()` and
/// routes it through the shared, ErrorDetail-aware exception logger (so a
/// `UaException` is recorded as `{status, error}`, any other `std::exception`
/// as its `what()`, and an unknown throw as "unknown"). Declared here and
/// defined in `ua_guarded.cpp` so this header stays free of the heavy
/// `to_string` / `ErrorDetail` formatting machinery.
///
/// @param logger Destination for the record. A null @ref ua::Logger is a silent
///               no-op; a non-null one survives component teardown because a
///               @ref ua::Logger is a value handle, which is why @ref guarded
///               can require one even at full shutdown.
/// @param site   Stable label identifying the boundary, used as the log message.
/// @note `noexcept`: it is invoked at a `noexcept` Asio completion boundary, so
///       it must never itself propagate - any failure inside the logger is also
///       swallowed.
void report_guarded_exception(const Logger& logger, const char* site) noexcept;

// Canonical callbacks name their actual payload even when the supplied gone value is convertible
// to it (for example, StatusCode to VoidResult). A generic callable uses the supplied payload type.
template<class Completion, class Fallback>
struct PostCompletionPayload
{
  using Type = Fallback;
};

template<class Payload, class Fallback>
struct PostCompletionPayload<std::function<void(Payload)>, Fallback>
{
  using Type = Payload;
};

/// Statically enforces the single precondition the post helpers place on @p Self: that it derives
/// from `std::enable_shared_from_this<Self>`, so @ref ua::async::post_borrowing can take a
/// `weak_from_this()` and @ref ua::async::post_owning a `shared_from_this()`. The post target (a
/// strand or executor) and the @ref ua::Logger are passed in by the caller, so - unlike the old
/// `on_strand` - the helpers require no `mStrand` member, `logger()`, or `executor()` accessor, and
/// never touch a private strand of @p Self. Compiles to nothing; converts a misuse into a readable
/// error at the call site rather than deep in the wrapper instantiation.
template<class Self>
constexpr void post_helper_static_checks() noexcept
{
  // remove_cv so a `const Self` (e.g. a const member function posting `this`) still satisfies the
  // check; `shared_from_this()` / `weak_from_this()` have const overloads that yield the
  // corresponding `const`-qualified smart pointers.
  static_assert(
    std::is_base_of_v<std::enable_shared_from_this<std::remove_cv_t<Self>>, std::remove_cv_t<Self>>,
    "post_borrowing / post_owning require Self : public std::enable_shared_from_this<Self>");
}

}  // namespace detail

/// Wraps a continuation so any exception it throws is logged and consumed.
///
/// This is the SDK's own-code analogue of @ref ua::detail::invoke_user_callback.
/// It exists for *our* async continuations (the lambdas we post to strands and
/// executors), not for user-supplied callbacks. Asio completion handlers run at
/// a `noexcept` boundary, so an exception escaping one calls `std::terminate`.
/// In particular, weak/shared dependency accessors (e.g. a server-dependency
/// adapter whose backing object has been destroyed mid-drain) deliberately
/// throw; a continuation that touches such state after teardown would otherwise
/// abort the process. Routing every posted continuation through @ref guarded
/// converts that throw into a logged, swallowed failure - and makes the
/// discipline statically enforceable (the `no-raw-asio-post` gate).
///
/// The returned wrapper forwards whatever arguments the producer delivers to
/// @p handler inside a `try`/`catch(...)`. On any throw it calls
/// @ref detail::report_guarded_exception, which records the in-flight exception
/// with its @ref ua::StatusCode and @ref ua::ErrorDetail before discarding it.
/// The wrapper itself is `noexcept`.
///
/// @tparam Handler Continuation type, invocable with the producer's arguments
///                 (commonly none, or a single `Result`). Move-only handlers are
///                 supported; the wrapper is then move-only too.
/// @param logger   Logger used to record a swallowed exception. Captured by
///                 value - a @ref ua::Logger is a cheap, copyable value handle
///                 (shared sink + shared level + category) that outlives the
///                 component whose work this guards, so the requirement is
///                 satisfiable even during shutdown. A null logger drops the
///                 record silently but still consumes the throw.
/// @param handler  The continuation to run guarded. Invoked at most once with
///                 the forwarded producer arguments.
/// @return A `noexcept`, move-only callable suitable as an Asio completion
///         handler or as the body posted to a strand/executor.
template<class Handler>
auto guarded(Logger logger, Handler handler)
{
  return [logger = std::move(logger), handler = std::move(handler)](auto&&... args) mutable noexcept -> void
  {
    try
    {
      handler(std::forward<decltype(args)>(args)...);
    }
    catch (...)
    {
      detail::report_guarded_exception(logger, "guarded async continuation");
    }
  };
}

/// Posts a continuation onto a strand with **weak** lifetime, exception-guarded.
///
/// The default post helper. Returns a move-only callable to hand to a producer (`*_async`, an Asio
/// I/O op, ...); when that callable fires - on whatever thread the producer chose - it posts the work
/// to @p strand and re-checks lifetime before invoking @p handler, so the handler always runs
/// serialized on @p strand with @p self alive. Invoked with **no** producer arguments it is also a
/// plain "post this work onto that strand now" helper: `post_borrowing(this, mStrand, mLogger, h)()`.
///
/// The post target (@p strand) and the @p logger are passed in by value, read from the caller's own
/// members at the call site - the helper never touches a private strand of @p self, so a component's
/// strand stays private (it is never exposed via a public getter, and the helper is never a friend).
/// Asio strands/executors and @ref ua::Logger are cheap copyable handles; the captured copies survive
/// @p self's destruction, which is what lets @p logger record a swallowed exception during teardown.
///
/// Lifetime is captured weakly (`weak_from_this()`): if @p self is destroyed before the producer
/// fires, the post still happens but no-ops on its strand turn (the inner `weak.lock()` fails), so
/// @p handler never runs against a dead component and @p self's lifetime is not extended. The
/// strand-side invocation of @p handler is wrapped in @ref ua::async::guarded with @p logger, so an
/// exception thrown by @p handler - e.g. a dead-dependency accessor throwing during shutdown drain -
/// is logged and consumed instead of escaping the `noexcept` Asio boundary.
///
/// @tparam Self     Owning component type; must derive from `std::enable_shared_from_this<Self>`
///                  (enforced by `static_assert`).
/// @tparam Executor The strand/executor type to post onto (e.g. `boost::asio::strand<...>`).
/// @tparam Handler  Continuation invocable as `handler(Self&, Args...)`, where `Args...` are the
///                  producer's arguments (often none).
/// @param self      Non-owning pointer to the component; must be alive at this call. Only a weak
///                  reference is retained.
/// @param strand    The strand (or executor) to post the continuation onto; captured by value.
/// @param logger    Logger for @ref ua::async::guarded to record a swallowed exception; captured by
///                  value, so it survives @p self's destruction.
/// @param handler   Continuation invoked on @p strand with a live `Self&` followed by the producer's
///                  arguments.
/// @return A move-only callback suitable as a producer's completion handler (or invoked with `()` to
///         post immediately).
/// @see post_owning
/// @see ua::async::guarded
template<class Self, class Executor, class Handler>
auto post_borrowing(Self* self, Executor strand, Logger logger, Handler handler)
{
  detail::post_helper_static_checks<Self>();
  return [weak = self->weak_from_this(),
           strand = std::move(strand),
           logger = std::move(logger),
           handler = std::move(handler)](auto&&... args) mutable
  {
    auto packed = std::make_tuple(std::forward<decltype(args)>(args)...);
    boost::asio::post(strand,
      guarded(std::move(logger),
        [weak, handler = std::move(handler), packed = std::move(packed)]() mutable
        {
          auto s = weak.lock();
          if (!s)
            return;
          std::apply([&](auto&&... unpacked) { handler(*s, std::forward<decltype(unpacked)>(unpacked)...); },
            std::move(packed));
        }));
  };
}

/// `post_borrowing` for a continuation that **owns a completion it must fire exactly once** - even if
/// @p self is gone by the time the strand runs.
///
/// Plain @ref post_borrowing drops the work when @p self has expired; that is correct when the work
/// is just "advance my own flow", but wrong when the continuation owes a result to a user callback
/// (a service entry point that took a completion). This overload keeps that contract: the completion
/// is delivered on exactly one path -
///   - `handler(Self&, Completion, Args...)` when @p self is alive (the handler delivers the
///     completion as part of its work), or
///   - `completion(goneResult)` when @p self is gone by the time the strand turn runs.
///
/// @p goneResult is delivered when the owner is gone. A handler or enqueue failure delivers the
/// translated rich exception for Result/StatusCode payloads; other payloads receive @p goneResult
/// after the original exception is logged. A completion that already fired cannot fire again.
///
/// Construction allocates nothing of its own: the shared state, the completion relay and the queued work
/// are allocated when the callable runs, inside its exception boundary, where a failure answers the
/// completion. A `noexcept` entry point can therefore build it without a try. Construction throws only for
/// a null owner or when a copy the caller asks for (an lvalue completion or fallback) throws; the caller
/// then retains its original completion and fallback. Rvalues are transferred only by non-throwing moves;
/// throwing lvalue copies are staged before either original rvalue is consumed. A null owner is rejected
/// with BadInvalidArgument and NullPointer detail before either input moves. The returned callable is
/// single-use and `noexcept`. Invoke it once; concurrent invocations are not supported. Producer arguments
/// are stored in a tuple until the executor runs. Callers must supply values that own their referenced
/// storage: views and reference wrappers remain non-owning. Copy or move failures inside the callable
/// or queued handler complete with the translated exception. Argument evaluation and callback type
/// conversion before entering the callable remain the caller's exception-handling responsibility.
/// Executor shutdown may destroy queued work without running it, as for other post helpers.
///
/// @tparam Self       Owning component; derives from std::enable_shared_from_this<Self>.
/// @tparam Executor   The strand/executor type to post onto; non-throwing to move.
/// @tparam Completion Completion callable; its stored value must be non-throwing to move.
/// @tparam GoneResult Fallback value; conversion of an rvalue to the payload must not throw.
/// @tparam Handler    Invocable with Self&, a std::function accepting the completion's payload, and
///                    the forwarded producer arguments.
/// @param self        Non-owning pointer; alive at this call. Only a weak reference is retained.
/// @param strand      Strand to post onto; captured by value.
/// @param logger      Logger retained for exception reporting and user-callback containment.
/// @param completion  Non-empty completion, invoked at most once across all delivery paths.
/// @param goneResult  Result delivered when the owner is gone or a non-status payload cannot run.
/// @param handler     Continuation invoked on the executor with a live Self& and a completion relay.
/// @return A noexcept callable; invoke it once with the producer arguments (or () when there are none).
/// @see post_borrowing
template<class Self, class Executor, class Completion, class GoneResult, class Handler>
auto post_borrowing(Self* self, Executor strand, Logger logger, Completion&& completion,
  GoneResult&& goneResult, Handler handler)
{
  detail::post_helper_static_checks<Self>();
  check(self);
  using CompletionValue = std::decay_t<Completion>;
  using Payload = typename detail::PostCompletionPayload<CompletionValue, std::decay_t<GoneResult>>::Type;
  static_assert(std::is_nothrow_move_constructible_v<CompletionValue>);
  static_assert(std::is_nothrow_move_constructible_v<Payload>);
  if constexpr (::ua::detail::is_nullable_callback_v<CompletionValue>)
  {
    assert(completion && "completion-owning post_borrowing requires a non-empty completion");
  }

  static_assert(std::is_nothrow_move_constructible_v<Executor>);
  static_assert(std::is_nothrow_move_constructible_v<Logger>);

  // The state owns the original completion, but never its relay. The relay can therefore retain this
  // state without an ownership cycle, and survives reentrant destruction of the invoking callable. The
  // state, the relay and the queued work are allocated when the callable runs, inside its exception
  // boundary: building this helper allocates nothing, so a noexcept entry point needs no try around it.
  struct State
  {
    std::weak_ptr<Self> weak;
    Executor strand;
    const Logger logger;
    std::optional<CompletionValue> completion;
    std::optional<Payload> goneResult;
    std::atomic_bool fired{false};

    State(std::weak_ptr<Self>&& initialWeak, Executor&& initialStrand, Logger&& initialLogger,
      std::optional<CompletionValue>&& initialCompletion, std::optional<Payload>&& initialGoneResult) noexcept
      : weak(std::move(initialWeak)), strand(std::move(initialStrand)), logger(std::move(initialLogger)),
        completion(std::move(initialCompletion)), goneResult(std::move(initialGoneResult))
    {}

    static void deliver_to(
      const Logger& deliveryLogger, std::optional<CompletionValue>& target, Payload result) noexcept
    {
      if (!target)
      {
        assert(false && "completion-owning post_borrowing has no stored completion");
        return;
      }
      auto callback = std::move(*target);
      target.reset();
      ::ua::detail::invoke_user_callback(deliveryLogger, callback, std::move(result));
    }

    // Answers the exception in flight: its translated rich status for a Result or StatusCode payload,
    // otherwise the fallback, after logging it.
    static void fail_to(const Logger& failureLogger, std::optional<CompletionValue>& target,
      std::optional<Payload>& fallback) noexcept
    {
      const auto exception = std::current_exception();
      detail::report_guarded_exception(failureLogger, "completion-owning post_borrowing");
      if constexpr (::ua::is_result_v<Payload> || std::is_same_v<Payload, StatusCode>)
      {
        deliver_to(failureLogger, target, Payload{::ua::exception_to_status_code(exception)});
      }
      else if (fallback)
      {
        deliver_to(failureLogger, target, std::move(*fallback));
      }
      else
      {
        assert(false && "completion-owning post_borrowing has no stored fallback");
      }
    }

    // Only the path that claimed fired may consume the stored completion or fallback.
    void complete(Payload result) noexcept
    {
      if (!fired.exchange(true, std::memory_order_acq_rel))
      {
        deliver_to(logger, completion, std::move(result));
      }
    }

    void complete_gone() noexcept
    {
      if (fired.exchange(true, std::memory_order_acq_rel))
      {
        return;
      }
      if (goneResult)
      {
        deliver_to(logger, completion, std::move(*goneResult));
      }
      else
      {
        assert(false && "completion-owning post_borrowing has no stored fallback");
      }
    }

    void fail() noexcept
    {
      if (fired.exchange(true, std::memory_order_acq_rel))
      {
        detail::report_guarded_exception(logger, "completion-owning post_borrowing");
        return;
      }
      fail_to(logger, completion, goneResult);
    }
  };

  // Complete potentially throwing copies before the final, non-throwing transfer of either rvalue.
  std::optional<CompletionValue> copiedCompletion;
  std::optional<Payload> copiedGoneResult;
  if constexpr (std::is_lvalue_reference_v<Completion&&>)
  {
    copiedCompletion.emplace(completion);
  }
  if constexpr (std::is_lvalue_reference_v<GoneResult&&>)
  {
    copiedGoneResult.emplace(goneResult);
  }
  const auto takeCompletion = [&]() noexcept
  {
    if constexpr (std::is_lvalue_reference_v<Completion&&>)
    {
      return std::move(copiedCompletion);
    }
    else
    {
      static_assert(std::is_nothrow_constructible_v<CompletionValue, Completion&&>);
      return std::optional<CompletionValue>{std::in_place, std::forward<Completion>(completion)};
    }
  };
  const auto takeGoneResult = [&]() noexcept
  {
    if constexpr (std::is_lvalue_reference_v<GoneResult&&>)
    {
      return std::move(copiedGoneResult);
    }
    else
    {
      static_assert(std::is_nothrow_constructible_v<Payload, GoneResult&&>);
      return std::optional<Payload>{std::in_place, std::forward<GoneResult>(goneResult)};
    }
  };

  // One aggregate, so its members are initialized in declaration order: the Handler, whose move may throw,
  // moves before either rvalue of the caller's is consumed. A lambda's captures have no such order.
  struct Inputs
  {
    std::optional<Handler> handler;
    std::weak_ptr<Self> weak;
    Executor strand;
    Logger logger;
    std::optional<CompletionValue> completion;
    std::optional<Payload> goneResult;
  };

  return [inputs = Inputs{std::optional<Handler>{std::move(handler)},
            self->weak_from_this(),
            std::move(strand),
            std::move(logger),
            takeCompletion(),
            takeGoneResult()}](auto&&... arguments) mutable noexcept
  {
    if (!inputs.handler)
    {
      assert(false && "completion-owning post_borrowing callable must be invoked once");
      return;
    }
    std::shared_ptr<State> state;
    try
    {
      state = std::make_shared<State>(std::move(inputs.weak),
        std::move(inputs.strand),
        std::move(inputs.logger),
        std::move(inputs.completion),
        std::move(inputs.goneResult));
      std::function<void(Payload)> relay = [state](Payload result) noexcept
      {
        const auto retained = state;
        retained->complete(std::move(result));
      };
      auto packedArguments = std::make_tuple(std::forward<decltype(arguments)>(arguments)...);
      // Asio moves queued callables before entering guarded. Keep potentially throwing handler and
      // argument moves here or in the contained invocation, never in that executor-owned move.
      auto queued = std::make_shared<std::pair<Handler, decltype(packedArguments)>>(
        std::move(*inputs.handler), std::move(packedArguments));
      inputs.handler.reset();
      boost::asio::post(state->strand,
        guarded(state->logger,
          [state, relay = std::move(relay), queued = std::move(queued)]() mutable
          {
            try
            {
              auto owner = state->weak.lock();
              if (!owner)
              {
                state->complete_gone();
                return;
              }
              std::apply(
                [&](auto&&... unpackedArguments) {
                  queued->first(*owner,
                    std::move(relay),
                    std::forward<decltype(unpackedArguments)>(unpackedArguments)...);
                },
                std::move(queued->second));
            }
            catch (...)
            {
              state->fail();
            }
          }));
    }
    catch (...)
    {
      inputs.handler.reset();
      if (state)
      {
        state->fail();
      }
      else
      {
        // The state was never made, so this callable still holds the completion. It is answered from
        // locals because the completion may destroy this callable.
        auto failureLogger = std::move(inputs.logger);
        auto failureCompletion = std::move(inputs.completion);
        auto failureGoneResult = std::move(inputs.goneResult);
        State::fail_to(failureLogger, failureCompletion, failureGoneResult);
      }
    }
  };
}

/// Posts a continuation onto an executor with **strong** lifetime, exception-guarded.
///
/// The owning counterpart to @ref post_borrowing. It strong-captures `self->shared_from_this()`, so
/// @p self is kept alive across the hop. Use it for transient, self-owning flow objects that drive
/// their own multi-step async chain and must outlive each `*_async` continuation (the classic
/// "post my next step to the executor to break inline-completion recursion" pattern), and for the
/// `start()`-style "keep me alive until my first hop runs" post. For long-lived shared components
/// prefer @ref post_borrowing - a strong self-capture there would extend lifetime and risk an
/// ownership cycle.
///
/// As with @ref post_borrowing, the post target (@p executor) and @p logger are passed in by value
/// from the caller; the helper never touches a private member of @p self beyond `shared_from_this()`.
/// The invocation of @p handler is wrapped in @ref ua::async::guarded with @p logger, so an exception
/// cannot escape the `noexcept` Asio boundary. Because the capture is strong, @p handler always runs
/// against a live `Self&`.
///
/// @tparam Self     Owning component type; must derive from `std::enable_shared_from_this<Self>`
///                  (enforced by `static_assert`).
/// @tparam Executor The executor/strand type to post onto.
/// @tparam Handler  Continuation invocable as `handler(Self&, Args...)`.
/// @param self      Non-owning pointer to the component; must be alive at this call. A strong
///                  reference is taken and held until the continuation runs.
/// @param executor  The executor (or strand) to post the continuation onto; captured by value.
/// @param logger    Logger for @ref ua::async::guarded; captured by value.
/// @param handler   Continuation invoked on @p executor with a live `Self&` followed by the
///                  producer's arguments.
/// @return A move-only, single-shot callback suitable as a producer's completion handler (or invoked
///         with `()` to post immediately). Only its first call posts @p handler; a later call does
///         nothing, so a producer that answers twice cannot run the continuation again.
/// @see post_borrowing
/// @see ua::async::guarded
template<class Self, class Executor, class Handler>
auto post_owning(Self* self, Executor executor, Logger logger, Handler handler)
{
  detail::post_helper_static_checks<Self>();
  // nosemgrep: lambda-captures-shared-from-this (post_owning owns self by design; cf post_borrowing)
  return [strong = self->shared_from_this(),
           executor = std::move(executor),
           logger = std::move(logger),
           handler = std::move(handler)](auto&&... args) mutable
  {
    // The first call moves the strong reference and the handler into the posted turn, so a later
    // call finds the reference empty and posts nothing.
    if (!strong)
    {
      return;
    }
    auto packed = std::make_tuple(std::forward<decltype(args)>(args)...);
    boost::asio::post(executor,
      guarded(std::move(logger),
        [strong = std::move(strong), handler = std::move(handler), packed = std::move(packed)]() mutable
        {
          std::apply([&](auto&&... unpacked)
            { handler(*strong, std::forward<decltype(unpacked)>(unpacked)...); },
            std::move(packed));
        }));
  };
}

/// `post_borrowing` for a callback that is **invoked repeatedly** (a registered listener / per-event
/// delivery callback), rather than a one-shot producer completion.
///
/// @ref post_borrowing and @ref post_owning MOVE their handler into the posted work on the first
/// invocation, so the returned callable is single-shot: a second call runs a moved-from (empty)
/// handler and silently does nothing. That is correct for a producer completion (fired once), but
/// WRONG for a callback stored in a registry and fired once per event/sample - every delivery after
/// the first is lost. This helper instead COPIES the handler and logger on each invocation (its outer
/// lambda is non-`mutable` and never moves its captures out), so it can fire any number of times.
///
/// Weak lifetime, exactly like @ref post_borrowing. Each delivery re-locks `weak_from_this()` on
/// @p strand and drops if @p self is gone. The strand-side call is wrapped in @ref ua::async::guarded
/// with @p logger. Hand the returned callable to a registration API (`register_*`, `subscribe`, a
/// notifier setter) that keeps and re-invokes it.
///
/// @tparam Self     Owning component type; must derive from `std::enable_shared_from_this<Self>`
///                  (enforced by `static_assert`).
/// @tparam Executor The strand/executor type to post onto.
/// @tparam Handler  Continuation invocable as `handler(Self&, Args...)`, copyable (it is copied per
///                  delivery, so it must not be move-only).
/// @param self      Non-owning pointer to the component; alive at this call. Only a weak reference is
///                  retained.
/// @param strand    The strand to post each delivery onto; captured by value.
/// @param logger    Logger for @ref ua::async::guarded; captured by value, copied per delivery.
/// @param handler   Continuation invoked on @p strand with a live `Self&` and the delivery's
///                  arguments, once per invocation of the returned callable.
/// @return A reusable (multi-shot) callback to hand to a registration API.
/// @see post_borrowing
template<class Self, class Executor, class Handler>
auto post_borrowing_repeating(Self* self, Executor strand, Logger logger, Handler handler)
{
  detail::post_helper_static_checks<Self>();
  return [weak = self->weak_from_this(),
           strand = std::move(strand),
           logger = std::move(logger),
           handler = std::move(handler)](auto&&... args)
  {
    // Non-mutable outer lambda: `logger` and `handler` are COPIED (into guarded / the inner lambda)
    // on every invocation, never moved out, so the returned callable is reusable across deliveries.
    auto packed = std::make_tuple(std::forward<decltype(args)>(args)...);
    boost::asio::post(strand,
      guarded(logger,
        [weak, handler, packed = std::move(packed)]() mutable
        {
          auto s = weak.lock();
          if (!s)
            return;
          std::apply([&](auto&&... unpacked) { handler(*s, std::forward<decltype(unpacked)>(unpacked)...); },
            std::move(packed));
        }));
  };
}

/// @ref post_borrowing for a component that borrows the lifetime of a **sibling** it holds a
/// `std::weak_ptr` to (rather than its own `weak_from_this()`).
///
/// Same single-shot, weak-lifetime, exception-guarded contract as @ref post_borrowing, but the weak
/// reference is supplied explicitly instead of taken from `self`. Use it where the posting object is
/// not the object whose lifetime gates the work - e.g. a sample sink that posts onto its owning
/// subscription's strand and must no-op if that subscription is gone. @p Target need not derive from
/// `enable_shared_from_this` (the caller already holds the `weak_ptr`).
///
/// @tparam Target   The type whose lifetime is borrowed; the handler receives a live `Target&`.
/// @tparam Executor The strand/executor type to post onto.
/// @tparam Handler  Continuation invocable as `handler(Target&, Args...)`.
/// @param weak      Weak reference to the target; re-locked on the strand before @p handler runs.
/// @param strand    The strand to post onto; captured by value.
/// @param logger    Logger for @ref ua::async::guarded; captured by value.
/// @param handler   Continuation invoked on @p strand with a live `Target&` followed by the
///                  producer's arguments.
/// @return A move-only callback suitable as a producer's completion handler (or invoked with `()` to
///         post immediately).
/// @see post_borrowing
template<class Target, class Executor, class Handler>
auto post_borrowing(std::weak_ptr<Target> weak, Executor strand, Logger logger, Handler handler)
{
  return [weak = std::move(weak),
           strand = std::move(strand),
           logger = std::move(logger),
           handler = std::move(handler)](auto&&... args) mutable
  {
    auto packed = std::make_tuple(std::forward<decltype(args)>(args)...);
    boost::asio::post(strand,
      guarded(std::move(logger),
        [weak = std::move(weak), handler = std::move(handler), packed = std::move(packed)]() mutable
        {
          auto s = weak.lock();
          if (!s)
            return;
          std::apply([&](auto&&... unpacked) { handler(*s, std::forward<decltype(unpacked)>(unpacked)...); },
            std::move(packed));
        }));
  };
}

/// @ref post_borrowing for a weak-borrow whose dead-self path shares MUTABLE state with the alive path.
///
/// The completion-owning @ref post_borrowing overload delivers a PRECOMPUTED `goneResult` when @p self
/// is gone. That fails when the gone value and the alive work draw on the same mutable object (e.g. a
/// shared `ParsedIdentityToken` that whichever path runs finalises and moves out): building the
/// goneResult up front would consume that object before it is known which path runs. This overload
/// defers both sides - on the strand it runs `aliveHandler(Self&)` if @p self survived, else
/// `goneHandler()`; exactly one runs, and never eagerly. Both are wrapped in @ref ua::async::guarded.
///
/// Because both handlers own a slice of the shared state, capture it by a shared handle (e.g. a
/// `shared_ptr`) or by copy in each - the unused handler is simply destroyed. The returned callable is
/// `noexcept` and is invoked with `()` to post now (these are not producer completions).
///
/// @tparam Self         Owning component type; must derive from `std::enable_shared_from_this<Self>`.
/// @tparam Executor     The strand/executor type to post onto.
/// @tparam AliveHandler Invocable as `aliveHandler(Self&)` - runs on the strand with a live @p self.
/// @tparam GoneHandler  Invocable as `goneHandler()` - runs on the strand when @p self is gone.
/// @param self          Non-owning pointer; alive at this call. Only a weak reference is retained.
/// @param strand        The strand to post onto; captured by value.
/// @param logger        Logger for @ref ua::async::guarded; captured by value.
/// @param aliveHandler  Continuation for the live-self path.
/// @param goneHandler   Continuation for the dead-self path (delivers the owed completion).
/// @return A `noexcept` callable; invoke it with `()` to post.
/// @see post_borrowing
template<class Self, class Executor, class AliveHandler, class GoneHandler>
auto post_borrowing_or_else(
  Self* self, Executor strand, Logger logger, AliveHandler aliveHandler, GoneHandler goneHandler)
{
  detail::post_helper_static_checks<Self>();
  return [weak = self->weak_from_this(),
           strand = std::move(strand),
           logger = std::move(logger),
           aliveHandler = std::move(aliveHandler),
           goneHandler = std::move(goneHandler)]() mutable noexcept
  {
    // nosemgrep: catch-all-empty-body (noexcept strand-post boundary; same asio::post containment as above)
    try
    {
      boost::asio::post(strand,
        guarded(std::move(logger),
          [weak, aliveHandler = std::move(aliveHandler), goneHandler = std::move(goneHandler)]() mutable
          {
            auto s = weak.lock();
            if (!s)
            {
              goneHandler();
              return;
            }
            aliveHandler(*s);
          }));
    }
    catch (...)
    {
      // As with the completion-owning post_borrowing overload: a bad_alloc while enqueuing the handler
      // loses both handlers unfired, but the noexcept boundary is preserved (never propagates).
    }
  };
}

/// Posts a **self-owning** continuation onto a strand, exception-guarded.
///
/// The fourth sanctioned post form. `post_borrowing` / `post_owning` are for continuations whose
/// lifetime is a *component* (`Self : enable_shared_from_this<Self>`, captured weakly/strongly and
/// re-checked on the strand turn). This one is for continuations that carry their **own** lifetime -
/// a free-function flow state machine whose `shared_ptr<Flow>` is captured (moved) into the closure,
/// so there is no component `Self` and nothing to re-check: the work always runs and manages itself.
/// It is the named form of the "bare `guarded(...)` post" the `no-raw-asio-post` gate sanctions for a
/// genuinely self-less step, so such flows do not open-code (and duplicate) the post.
///
/// @param strand The strand to serialize on. A STRAND, and a required one: this used to take an
///               optional and run the continuation INLINE when it was disengaged, which meant a
///               flow's steps could run on whatever thread answered. That is survivable for a
///               callback state machine, whose state is only ever touched by whoever holds it, and
///               is not survivable for a coroutine, whose own suspension state would then be
///               written from two threads at once (@ref ua::async::await_callback). Every caller
///               has one - `SecureChannelContext::strand()` is engaged for the life of a bound
///               channel - so the fallback protected nothing but tests that skipped supplying it.
/// @param logger Logger for @ref guarded to record a swallowed exception; captured by value.
/// @param fn     The self-owning continuation (typically a lambda that has moved a `shared_ptr<Flow>`
///               into its captures). Invoked at most once.
template<class Fn>
void post_self_owning(
  const boost::asio::strand<boost::asio::any_io_executor>& strand, const Logger& logger, Fn&& fn)
{
  boost::asio::post(strand, ua::async::guarded(logger, std::forward<Fn>(fn)));
}

}  // namespace ua::async

#endif  // UA_ON_STRAND_H
