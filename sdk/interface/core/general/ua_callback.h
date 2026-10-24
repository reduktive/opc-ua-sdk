// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Move-only single-shot callback, with or without guaranteed delivery.
/// @ingroup general

#ifndef UA_CALLBACK_H
#define UA_CALLBACK_H

#include "ua_callback.h"
#include "ua_callback_safety.h"
#include "ua_defines.h"
#include "ua_exceptions.h"
#include "ua_result.h"
#include "ua_status_code.h"

#include <concepts>
#include <cstddef>
#include <cstring>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace ua
{

/// The value delivered when a @ref Callback is destroyed without having been invoked.
///
/// The shutdown value is supplied by this trait rather than stored in the callback, for two
/// reasons: a per-instance value would make every one of the SDK's construction sites pass a
/// second argument, and storing a `T` would make `sizeof(Callback<T>)` depend on `sizeof(T)`.
///
/// The primary template covers the entire SDK callback surface, because every callback payload is
/// a @ref Result specialization and each of those is constructible from a non-Good @ref Status.
/// Specialize for a payload outside that family, or for a site that needs a different status.
///
/// @tparam T Callback payload type.
/// @ingroup general
template<typename T>
struct CallbackShutdownValue
{
  /// Returns the value to deliver to an un-invoked callback at destruction.
  ///
  /// Parenthesized, and through an explicit @ref StatusCode "StatusCode": brace-initialization would prefer
  /// an initializer-list constructor, so a `Result<std::vector<StatusCode>>` would be built as a one-element
  /// *value* rather than as an error.
  ///
  /// @return A `T` carrying @ref Status::BadShutdown.
  [[nodiscard]] static T value()
  {
    return T(StatusCode{Status::BadShutdown});
  }
};

/// Shutdown value for a batch payload.
///
/// @ref BatchResult is an aggregate whose first member is a @ref VoidResult, so it cannot be
/// brace-initialized from a @ref Status the way the @ref Result family can. The batch fails as a
/// whole with no per-item results.
///
/// @tparam T Per-item result type of the batch.
/// @ingroup general
template<typename T>
struct CallbackShutdownValue<BatchResult<T>>
{
  /// Returns a batch that failed as a whole with @ref Status::BadShutdown.
  ///
  /// @return A `BatchResult<T>` carrying a bad batch status and no items.
  [[nodiscard]] static BatchResult<T> value()
  {
    return BatchResult<T>{VoidResult{Status::BadShutdown}, {}};
  }
};

/// A move-only, single-shot completion callback, invoked at most once and by default exactly once.
///
/// `Callback<T>` replaces `std::function<void(T)>` at the SDK's asynchronous interfaces and upgrades the
/// completion contract from "invoked if the operation completes" to **invoked exactly once,
/// always**. Either the owner calls it, or the owner drops it and the destructor delivers
/// @ref CallbackShutdownValue "CallbackShutdownValue<T>::value()" instead. An operation that is
/// abandoned - because a session closed, a component was torn down, or a code path simply forgot -
/// can therefore no longer strand its caller waiting for a result that will never arrive.
///
/// @par The two contracts
/// @p Guaranteed selects which promise the type makes. Both are single-shot; they differ only in
/// what a dropped callback does.
///   - `true` (the default) is the completion contract above: dropping it delivers the shutdown
///     value. This is what a caller awaiting a result needs.
///   - `false` is at-most-once with no delivery on destruction, for the sites that have genuinely
///     decided nothing is owed - a callback handed to a side path that may legitimately end
///     without an answer, where a shutdown delivery would race ahead of the real result the other
///     path is about to produce. Saying that in the type is checkable; saying it by calling
///     @ref release at the drop site is not, and it has to be remembered at every one of them.
/// A `Callback<T, false>` never asks for @ref CallbackShutdownValue, so it also serves a payload
/// that has no meaningful shutdown value.
///
/// The type is move-only by design, and that is what makes the guarantee cheap. A copyable
/// callback with the same guarantee must arbitrate between copies, which costs a shared control
/// block and an atomic flag on top of the type-erased callable. One owner needs neither: a plain
/// `bool`-equivalent state and no allocation beyond the callable itself. Move-only also lets a
/// callback carry a move-only payload, which `std::function` cannot.
///
/// Small callables - user lambdas and forwarding wrappers - are stored inside the object with no
/// allocation; see @ref fits_inline_v. Larger ones fall back to the heap, exactly as
/// `std::function` does today, so the change costs no additional allocations anywhere.
///
/// @par Threading
/// A `Callback` has exactly one owner at a time. It may be *moved* between threads, but it is
/// never *shared*, so `operator()` and the destructor cannot race without an ownership defect that
/// this type is not obliged to defend against. Nothing here is synchronized.
///
/// @par Re-entrancy
/// The stored callable is moved out and destroyed *before* the user code runs, and the callback is
/// marked spent before that. It is therefore safe for the invoked code to destroy the object that
/// owns this callback, or to invoke this callback again; the second call is a no-op.
///
/// @tparam T          Payload type delivered to the callable. When @p Guaranteed, it must be
///                    constructible by @ref CallbackShutdownValue::value().
/// @tparam Guaranteed Whether dropping the callback delivers the shutdown value.
/// @tparam Bytes      Bytes of in-object storage for the callable before it reaches the heap.
/// @ingroup general
/// @see CallbackShutdownValue, detail::invoke_user_callback
template<typename T, bool Guaranteed = true, std::size_t Bytes = 32>
class Callback
{
public:
  /// Bytes of in-object storage available to the callable before it must be heap-allocated.
  ///
  /// The default is chosen from measured closure sizes at this SDK's async interfaces: a user-supplied
  /// lambda is typically 16 bytes and a forwarding completion 48, while an internal
  /// `post_borrowing` continuation is 160 - of which 136 is a captured strand and a captured
  /// logger, values that are the same for every operation of a request. A buffer big enough for
  /// the last makes every `Callback` 168+ bytes and correspondingly costly to pass by value, so it
  /// is a size to choose per interface rather than a number to maximise. The default keeps the common
  /// small callables allocation-free and leaves the large internal ones on the heap, where
  /// `std::function` already puts them.
  static constexpr std::size_t inlineCapacity = Bytes;

  /// True if a callable of type @p F is stored inside the callback, with no heap allocation.
  ///
  /// A callable qualifies when it fits the inline buffer, is no more aligned than
  /// `std::max_align_t`, and can be moved without throwing - the last because moving a `Callback`
  /// and invoking one are both `noexcept`.
  ///
  /// @tparam F Callable type; cv-qualifiers and references are stripped before the test.
  template<typename F>
  static constexpr bool fits_inline_v =
    sizeof(std::decay_t<F>) <= inlineCapacity && alignof(std::decay_t<F>) <= alignof(std::max_align_t) &&
    std::is_nothrow_move_constructible_v<std::decay_t<F>>;

  /// Constructs an empty callback that holds no obligation and fires nothing when destroyed.
  Callback() noexcept = default;

  /// Constructs an empty callback, so `nullptr` remains a valid "no callback" argument.
  Callback(std::nullptr_t) noexcept
  {}

  /// Constructs a callback that owns @p f.
  ///
  /// Implicit, so an existing call site passing a lambda is unchanged. A *nullable* callable that
  /// is empty - a null `std::function` or function pointer, the established way of saying "no
  /// callback was supplied" - yields an empty callback rather than an obligation to deliver a
  /// shutdown value to nothing.
  ///
  /// @tparam F Callable type invocable with a `T`.
  /// @param f Callable to own; copied or moved into the callback.
  /// @throws Anything the move or copy of @p f throws, and `std::bad_alloc` if @p f does not fit
  ///         the inline buffer. The callback is left empty in that case.
  template<typename F>
    requires(!std::same_as<std::decay_t<F>, Callback> && std::invocable<std::decay_t<F>&, T>)
  Callback(F&& f)
  {
    using Callable = std::decay_t<F>;
    if constexpr (detail::is_nullable_callback_v<Callable>)
    {
      if (!f)
      {
        return;
      }
    }
    if constexpr (fits_inline_v<Callable>)
    {
      ::new (static_cast<void*>(mStorage)) Callable(std::forward<F>(f));
      mVTable = &InlineOps<Callable>::vTable;
    }
    else
    {
      store_pointer(mStorage, new Callable(std::forward<F>(f)));
      mVTable = &HeapOps<Callable>::vTable;
    }
  }

  /// Move-constructs, transferring the obligation and leaving @p other empty.
  ///
  /// @param other Callback to take over; left empty and firing nothing when destroyed.
  Callback(Callback&& other) noexcept
  {
    adopt(other);
  }

  /// Move-assigns, transferring @p other's obligation into this callback.
  ///
  /// Any obligation this callback already held is not silently discarded: when @p Guaranteed it is
  /// fired with the shutdown value, because dropping it is exactly the case this type exists to
  /// prevent. That firing happens *after* the assignment has completed, so user code reached this
  /// way observes the callback in its final state.
  ///
  /// @param other Callback to take over; left empty. Self-assignment is a no-op.
  /// @return A reference to this callback.
  Callback& operator=(Callback&& other) noexcept
  {
    if (this != &other)
    {
      Callback outgoing(std::move(*this));
      adopt(other);
      // ~outgoing fires the displaced obligation here, with *this already fully assigned.
    }
    return *this;
  }

  /// Assigns a new callable, firing the shutdown value for any obligation this callback displaces.
  ///
  /// The new callable is constructed *before* the existing obligation is disturbed, so a throwing
  /// construction leaves this callback untouched.
  ///
  /// @tparam F Callable type invocable with a `T`.
  /// @param f Callable to own; copied or moved into the callback.
  /// @return A reference to this callback.
  /// @throws Anything the corresponding converting constructor throws.
  template<typename F>
    requires(!std::same_as<std::decay_t<F>, Callback> && std::invocable<std::decay_t<F>&, T>)
  Callback& operator=(F&& f)
  {
    return *this = Callback(std::forward<F>(f));
  }

  Callback(const Callback&) = delete;
  Callback& operator=(const Callback&) = delete;

  /// Destroys the callback, delivering @ref CallbackShutdownValue::value() if it was never
  /// invoked and @p Guaranteed.
  ///
  /// That is the guarantee: a pending completion that nobody fired is reported rather than lost.
  /// Without it the callable is simply destroyed. An empty, spent, moved-from or released callback
  /// fires nothing either way.
  ///
  /// @note Never throws. The delivery runs through @ref detail::invoke_user_callback, so a
  ///       throwing user callable cannot escape - which matters here because this destructor may
  ///       run during stack unwinding.
  ~Callback() noexcept
  {
    if (mVTable)
    {
      if constexpr (Guaranteed)
      {
        fire_shutdown();
      }
      else
      {
        release();
      }
    }
  }

  /// Returns true while this callback still holds an obligation to deliver.
  ///
  /// False for an empty, spent, moved-from or released callback, so the established
  /// `if (cb) { cb(result); }` guard keeps working and additionally skips an already-fired
  /// callback.
  ///
  /// @return `true` if invoking this callback would reach a callable.
  [[nodiscard]] explicit operator bool() const noexcept
  {
    return mVTable != nullptr;
  }

  /// Compares against `nullptr`, matching `std::function`.
  ///
  /// Equivalent to `!static_cast<bool>(*this)`: true for an empty, spent, moved-from or released
  /// callback. C++20 synthesizes the reversed and negated forms, so `cb != nullptr` also works.
  ///
  /// @param unused The `nullptr` literal being compared against.
  /// @return `true` if this callback holds no obligation.
  [[nodiscard]] bool operator==(std::nullptr_t unused) const noexcept
  {
    UA_UNUSED(unused);
    return mVTable == nullptr;
  }

  /// Delivers @p value to the callable, at most once.
  ///
  /// The callback is marked spent and the callable is moved out of it before the call, so the
  /// invoked code may safely destroy this callback's owner or call this callback again. Every
  /// later call, and any call on an empty callback, is a no-op.
  ///
  /// `const`-qualified, exactly as `std::function::operator()` is. Firing a completion is what
  /// consumes it, and the overwhelmingly common shape at a call site is a completion captured by
  /// value into a continuation that is not declared `mutable`; requiring `mutable` at every such
  /// site would be friction with no safety return, because a `const Callback` is still owned by
  /// exactly one owner. The spent state is therefore `mutable`.
  ///
  /// @param value Payload to deliver; moved into the callable.
  /// @note Never throws: an exception from the callable is caught by
  ///       @ref detail::invoke_user_callback.
  void operator()(T value) const noexcept
  {
    const VTable* vtable = mVTable;
    if (!vtable)
    {
      return;
    }
    mVTable = nullptr;
    vtable->invoke(mStorage, std::move(value));
  }

  /// Abandons the obligation without firing, leaving the callback empty.
  ///
  /// For the rare site that has deliberately decided no result is owed - never as a way to quieten
  /// a shutdown delivery that is inconvenient, which is the case this type exists to surface.
  void release() noexcept
  {
    if (const VTable* vtable = mVTable)
    {
      mVTable = nullptr;
      vtable->destroy(mStorage);
    }
  }

private:
  /// The type-erasure dispatch table. One static instance exists per stored callable type and
  /// storage strategy, so a `Callback` costs one pointer of type information.
  struct VTable
  {
    /// Consumes the stored callable, destroying it before delivering @p value to it.
    void (*invoke)(void* storage, T&& value) noexcept;
    /// Move-constructs the callable into @p to and destroys the one in @p from.
    void (*relocate)(void* from, void* to) noexcept;
    /// Destroys the stored callable without invoking it.
    void (*destroy)(void* storage) noexcept;
  };

  /// Operations for a callable held in the inline buffer.
  template<typename F>
  struct InlineOps
  {
    static void invoke(void* storage, T&& value) noexcept
    {
      F* target = static_cast<F*>(storage);
      // Move out and destroy before running user code: from here on nothing touches the Callback,
      // so the invoked code is free to destroy whatever owns it.
      F callable = std::move(*target);
      target->~F();
      detail::invoke_user_callback(callable, std::move(value));
    }

    static void relocate(void* from, void* to) noexcept
    {
      F* source = static_cast<F*>(from);
      ::new (to) F(std::move(*source));
      source->~F();
    }

    static void destroy(void* storage) noexcept
    {
      static_cast<F*>(storage)->~F();
    }

    static constexpr VTable vTable{&invoke, &relocate, &destroy};
  };

  /// Operations for a callable too large, too aligned or too throwing to hold inline; the buffer
  /// holds a pointer to it instead.
  template<typename F>
  struct HeapOps
  {
    static void invoke(void* storage, T&& value) noexcept
    {
      // Ownership moves to this frame before user code runs, so the invoked code may destroy the
      // Callback; the block is released when this returns.
      std::unique_ptr<F> owner(static_cast<F*>(load_pointer(storage)));
      detail::invoke_user_callback(*owner, std::move(value));
    }

    static void relocate(void* from, void* to) noexcept
    {
      store_pointer(to, load_pointer(from));
    }

    static void destroy(void* storage) noexcept
    {
      // The same ownership transfer invoke() performs, without running the callable: taking the
      // block into a unique_ptr releases it when this returns.
      const std::unique_ptr<F> owner(static_cast<F*>(load_pointer(storage)));
    }

    static constexpr VTable vTable{&invoke, &relocate, &destroy};
  };

  /// Reads the heap callable's address out of the inline buffer.
  [[nodiscard]] static void* load_pointer(const void* storage) noexcept
  {
    void* pointer = nullptr;
    std::memcpy(&pointer, storage, sizeof(pointer));
    return pointer;
  }

  /// Writes the heap callable's address into the inline buffer.
  static void store_pointer(void* storage, void* pointer) noexcept
  {
    std::memcpy(storage, &pointer, sizeof(pointer));
  }

  /// Takes over @p other's obligation. This callback must be empty.
  void adopt(Callback& other) noexcept
  {
    if (other.mVTable)
    {
      other.mVTable->relocate(other.mStorage, mStorage);
      mVTable = other.mVTable;
      other.mVTable = nullptr;
    }
  }

  /// Delivers the shutdown value for an obligation nobody fired.
  void fire_shutdown() noexcept
  {
    try
    {
      (*this)(CallbackShutdownValue<T>::value());
    }
    catch (...)
    {
      // Only constructing the shutdown value can throw - the delivery itself cannot. There is no
      // caller to report to from a destructor, and the obligation cannot be met, so drop it
      // rather than leak the callable.
      detail::ignore_expected_exception();
      release();
    }
  }

  // Deliberately left uninitialized: the buffer is only ever read when mVTable says a callable
  // lives there, and zeroing 32 bytes per construction is pure cost at every async interface.
  //
  // Both are `mutable` so that firing - which necessarily consumes the callable - is available
  // through a const Callback, as it is through a const std::function.
  alignas(std::max_align_t) mutable std::byte mStorage[inlineCapacity];
  mutable const VTable* mVTable = nullptr;
};

/// Throws unless @p value still holds an obligation to deliver.
///
/// The @ref Callback counterpart of `check(const std::function<R(Args...)>&)`, so a precondition
/// check at an entry point reads the same whichever completion type it takes. It lives here rather
/// than beside the other overloads because `ua_exceptions.h` is below this header.
///
/// @tparam T          Callback payload type.
/// @tparam Guaranteed Whether the callback delivers on destruction.
/// @tparam Bytes      The callback's inline capacity.
/// @param value       The callback to validate; not retained.
/// @param throwStatus The Status raised on failure. Defaults to `Status::BadInvalidArgument`.
/// @param location    The throw site; defaults to the caller's location.
/// @throws UaException if @p value is empty, spent, moved-from or released.
/// @ingroup general
template<typename T, bool Guaranteed, std::size_t Bytes>
void check(const Callback<T, Guaranteed, Bytes>& value, Status throwStatus = Status::BadInvalidArgument,
  source_location location = UA_CURRENT_LOCATION)
{
  if (!value)
  {
    throw_empty_function_check(throwStatus, location);
  }
}

}  // namespace ua

#endif  // !UA_CALLBACK_H
