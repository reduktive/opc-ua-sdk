// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef STRAND_TEST_ACCESS_BASE_H
#define STRAND_TEST_ACCESS_BASE_H

#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <future>
#include <type_traits>

namespace ua::test
{

/// Forward declaration - each TestAccess class specializes this.
template<typename Derived>
class StrandGuard;

// ---------------------------------------------------------------------------
// Macros for declaring guard accessors (one line per member).
// These live in the StrandGuard<Derived> specialization body.
//
// The guard accesses target privates via pointer-to-member constants that are
// private inside the TestAccess class (which is already friended by the target).
// The guard is a friend of TestAccess, so it can read these private PMFs.
// This avoids needing the guard to be friended by the target itself.
//
// Each guard specialization must define:
//   using TA = <ConcreteTestAccess>;
// ---------------------------------------------------------------------------

/// Expose a data member as a mutable reference accessor on the guard.
/// `pmf_name` is a private static constexpr PMF constant on the TA class.
#define STRAND_GUARD_DATA(accessor_name, pmf_name) \
  auto& accessor_name()                            \
  {                                                \
    return mTarget.*TA::pmf_name;                  \
  }

/// Expose a method as a forwarding accessor on the guard.
/// `pmf_name` is a private static constexpr PMF constant on the TA class.
#define STRAND_GUARD_METHOD(accessor_name, pmf_name)                       \
  decltype(auto) accessor_name(auto&&... args)                             \
  {                                                                        \
    return (mTarget.*TA::pmf_name)(std::forward<decltype(args)>(args)...); \
  }

/// CRTP base for strand-safe TestAccess classes.
///
/// Provides `on_strand(target, fn)` which posts `fn` to the target's strand and blocks
/// the calling (test) thread until it completes. The lambda receives a `StrandGuard` -
/// the only way to access target internals - so tests cannot accidentally access target
/// state off-strand.
///
/// Also provides `strand_barrier(target)` for pure synchronization (drain the strand)
/// without accessing any state.
///
/// Derived classes must provide:
///   static boost::asio::strand<boost::asio::any_io_executor>& get_strand(TargetT& target, StrandKey);
///
template<typename Derived, typename TargetT>
struct StrandTestAccessBase
{
  /// Passkey type - only constructible by this base class.
  /// Derived::get_strand must require this as a parameter, preventing tests from
  /// calling get_strand directly.
  struct StrandKey
  {
  private:
    friend struct StrandTestAccessBase;
    explicit StrandKey() = default;
  };

  /// Run `fn(guard)` on the target's strand and return the result.
  /// Blocks the calling thread (main test thread only - never call from a strand).
  template<typename F>
  static auto on_strand(TargetT& target, F&& fn)
  {
    using Guard = StrandGuard<Derived>;
    using R = std::invoke_result_t<F, Guard&>;
    std::promise<R> p;
    boost::asio::post(Derived::get_strand(target, StrandKey{}),
      [&]()
      {
        Guard guard{target};
        if constexpr (std::is_void_v<R>)
        {
          fn(guard);
          p.set_value();
        }
        else
        {
          p.set_value(fn(guard));
        }
      });
    return p.get_future().get();
  }

  /// Convenience overload for shared_ptr<TargetT>.
  template<typename F>
  static auto on_strand(std::shared_ptr<TargetT>& target, F&& fn)
  {
    return on_strand(*target, std::forward<F>(fn));
  }

  /// Convenience overload for const shared_ptr<TargetT>.
  template<typename F>
  static auto on_strand(const std::shared_ptr<TargetT>& target, F&& fn)
  {
    return on_strand(*target, std::forward<F>(fn));
  }

  /// Post `fn(guard)` to the target's strand WITHOUT blocking the caller (fire-and-forget).
  ///
  /// Unlike `on_strand`, this does NOT wait for `fn` to run, so it is safe to call from a strand or a
  /// thread-pool worker without risking a strand/thread-pool deadlock (blocking on a same-strand post
  /// that only a free worker could service). Ordering relies solely on the target strand's FIFO
  /// guarantee: `fn` runs before any work posted to the same strand after this call. `fn` is moved
  /// into the posted task, so it (and whatever it captures) need only outlive the strand turn, not
  /// this call.
  ///
  /// The caller must keep @p target alive until the posted task runs. Prefer the `shared_ptr` overload
  /// when the target's lifetime is not otherwise pinned across the post.
  template<typename F>
  static void post_on_strand(TargetT& target, F fn)
  {
    using Guard = StrandGuard<Derived>;
    boost::asio::post(Derived::get_strand(target, StrandKey{}),
      [&target, fn = std::move(fn)]() mutable
      {
        Guard guard{target};
        fn(guard);
      });
  }

  /// Fire-and-forget overload that keeps the target alive until the posted task runs by capturing the
  /// owning `shared_ptr`. Use this whenever the target could otherwise be destroyed before the strand
  /// services the post.
  template<typename F>
  static void post_on_strand(std::shared_ptr<TargetT> target, F fn)
  {
    using Guard = StrandGuard<Derived>;
    auto& strand = Derived::get_strand(*target, StrandKey{});
    boost::asio::post(strand,
      [target = std::move(target), fn = std::move(fn)]() mutable
      {
        Guard guard{*target};
        fn(guard);
      });
  }

  /// Post an empty lambda to the target's strand and block until it runs.
  /// Use for pure synchronization (draining the strand) without accessing state.
  static void strand_barrier(TargetT& target)
  {
    std::promise<void> p;
    boost::asio::post(Derived::get_strand(target, StrandKey{}), [&]() { p.set_value(); });
    p.get_future().get();
  }

  /// Convenience overload for shared_ptr<TargetT>.
  static void strand_barrier(std::shared_ptr<TargetT>& target)
  {
    strand_barrier(*target);
  }

  /// Convenience overload for const shared_ptr<TargetT>.
  static void strand_barrier(const std::shared_ptr<TargetT>& target)
  {
    strand_barrier(*target);
  }
};

}  // namespace ua::test

#endif  // !STRAND_TEST_ACCESS_BASE_H
