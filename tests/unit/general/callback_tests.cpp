// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_callback.h"
#include "ua_result.h"

#include <array>
#include <cstddef>
#include <functional>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace ua;

namespace
{

using Payload = Result<int>;

/// Payload outside the Result family, used to prove the shutdown value comes from the trait.
struct CustomPayload
{
  int code = 0;
};

/// Records how often it is copied and moved, so the delivery path can be shown to move.
struct Tracker
{
  static inline int copies = 0;
  static inline int moves = 0;

  Tracker() = default;

  Tracker(const Tracker&)
  {
    ++copies;
  }

  Tracker(Tracker&&) noexcept
  {
    ++moves;
  }

  Tracker& operator=(const Tracker&)
  {
    ++copies;
    return *this;
  }

  Tracker& operator=(Tracker&&) noexcept
  {
    ++moves;
    return *this;
  }

  ~Tracker() = default;

  static void reset()
  {
    copies = 0;
    moves = 0;
  }
};

/// Callable with class-specific allocation operators, so the storage strategy is observable: the
/// heap path builds it with `new Callable(...)`, the inline path never allocates at all.
template<std::size_t Padding>
struct CountingCallable
{
  static inline int allocations = 0;
  static inline int deallocations = 0;

  static void* operator new(std::size_t size)
  {
    ++allocations;
    return ::operator new(size);
  }

  static void operator delete(void* block) noexcept
  {
    ++deallocations;
    ::operator delete(block);
  }

  static void reset()
  {
    allocations = 0;
    deallocations = 0;
  }

  int* fired;
  std::byte padding[Padding];

  void operator()(Payload) const
  {
    ++*fired;
  }
};

using SmallCallable = CountingCallable<1>;
using LargeCallable = CountingCallable<64>;

/// Owns a callback and is destroyed by the callback it owns, exercising re-entrant teardown.
struct Owner
{
  ua::Callback<Payload> completion;
};

}  // namespace

namespace ua
{

template<>
struct CallbackShutdownValue<CustomPayload>
{
  static CustomPayload value()
  {
    return CustomPayload{42};
  }
};

}  // namespace ua

namespace
{

// ---------------------------------------------------------------------------------------------
// Type properties
// ---------------------------------------------------------------------------------------------

static_assert(!std::is_copy_constructible_v<ua::Callback<Payload>>, "Callback must be move-only");
static_assert(!std::is_copy_assignable_v<ua::Callback<Payload>>, "Callback must be move-only");
static_assert(std::is_nothrow_move_constructible_v<ua::Callback<Payload>>);
static_assert(std::is_nothrow_move_assignable_v<ua::Callback<Payload>>);
static_assert(std::is_nothrow_destructible_v<ua::Callback<Payload>>);
static_assert(std::is_nothrow_default_constructible_v<ua::Callback<Payload>>);

// The whole point of the inline buffer is that Callback stays cheap to pass by value: the buffer,
// one vtable pointer, and whatever alignment padding that implies. Spell that out rather than
// writing `2 * sizeof(void*)`, which is the same number only on a 64-bit ABI: the buffer is
// over-aligned to max_align_t (16) on both, so a 32-bit build pays 4 bytes for the pointer and 12
// for padding where a 64-bit build pays 8 and 8. The bound is 48 either way - unchanged on 64-bit,
// where it remains exactly tight - and the budget now tracks the layout instead of coinciding with it.
constexpr std::size_t callbackSizeBudget =
  ((ua::Callback<Payload>::inlineCapacity + sizeof(void*) + alignof(std::max_align_t) - 1) /
    alignof(std::max_align_t)) *
  alignof(std::max_align_t);
static_assert(sizeof(ua::Callback<Payload>) <= callbackSizeBudget);

static_assert(ua::Callback<Payload>::fits_inline_v<SmallCallable>, "a small callable must not allocate");
static_assert(
  !ua::Callback<Payload>::fits_inline_v<LargeCallable>, "an oversized callable must go to the heap");
static_assert(ua::Callback<Payload>::fits_inline_v<std::function<void(Payload)>>);

// ---------------------------------------------------------------------------------------------
// Construction and emptiness
// ---------------------------------------------------------------------------------------------

TEST(CallbackTest, DefaultConstructedHoldsNoObligation)
{
  ua::Callback<Payload> callback;
  EXPECT_FALSE(static_cast<bool>(callback));
}

TEST(CallbackTest, NullptrConstructedHoldsNoObligation)
{
  ua::Callback<Payload> callback{nullptr};
  EXPECT_FALSE(static_cast<bool>(callback));
}

TEST(CallbackTest, ComparesAgainstNullptrLikeAStdFunction)
{
  ua::Callback<Payload> empty;
  EXPECT_TRUE(empty == nullptr);
  EXPECT_FALSE(empty != nullptr);

  ua::Callback<Payload> held = [](Payload) {
  };
  EXPECT_FALSE(held == nullptr);
  EXPECT_TRUE(held != nullptr);

  held(Payload{1});
  EXPECT_TRUE(held == nullptr);  // spent
}

TEST(CallbackTest, LambdaConstructedHoldsAnObligation)
{
  ua::Callback<Payload> callback = [](Payload) {
  };
  EXPECT_TRUE(static_cast<bool>(callback));
}

TEST(CallbackTest, EmptyStdFunctionHoldsNoObligation)
{
  const std::function<void(Payload)> unset;
  ua::Callback<Payload> callback = unset;
  EXPECT_FALSE(static_cast<bool>(callback));
}

TEST(CallbackTest, NonEmptyStdFunctionHoldsAnObligationAndIsInvoked)
{
  int fired = 0;
  const std::function<void(Payload)> function = [&fired](Payload)
  {
    ++fired;
  };
  ua::Callback<Payload> callback = function;
  ASSERT_TRUE(static_cast<bool>(callback));
  callback(Payload{7});
  EXPECT_EQ(fired, 1);
}

// ---------------------------------------------------------------------------------------------
// Invocation
// ---------------------------------------------------------------------------------------------

TEST(CallbackTest, DeliversTheSuppliedValue)
{
  int delivered = 0;
  ua::Callback<Payload> callback = [&delivered](Payload result)
  {
    delivered = result.value();
  };
  callback(Payload{7});
  EXPECT_EQ(delivered, 7);
}

TEST(CallbackTest, DeliversAtMostOnce)
{
  int fired = 0;
  ua::Callback<Payload> callback = [&fired](Payload)
  {
    ++fired;
  };
  callback(Payload{1});
  callback(Payload{2});
  callback(Payload{3});
  EXPECT_EQ(fired, 1);
}

TEST(CallbackTest, IsSpentAfterInvocation)
{
  ua::Callback<Payload> callback = [](Payload) {
  };
  callback(Payload{1});
  EXPECT_FALSE(static_cast<bool>(callback));
}

TEST(CallbackTest, InvokingAnEmptyCallbackIsANoOp)
{
  ua::Callback<Payload> callback;
  callback(Payload{1});
  EXPECT_FALSE(static_cast<bool>(callback));
}

TEST(CallbackTest, DestructionAfterInvocationDeliversNothingFurther)
{
  int fired = 0;
  {
    ua::Callback<Payload> callback = [&fired](Payload)
    {
      ++fired;
    };
    callback(Payload{1});
  }
  EXPECT_EQ(fired, 1);
}

TEST(CallbackTest, ReleasesTheCallableAsSoonAsItHasFired)
{
  const auto witness = std::make_shared<int>(0);
  std::weak_ptr<int> observer = witness;
  {
    ua::Callback<Payload> callback = [held = witness](Payload) {
    };
    EXPECT_EQ(observer.use_count(), 2);
    callback(Payload{1});
    // The callable, and everything it captured, is gone the moment the obligation is met - it is
    // not held until the Callback itself is destroyed.
    EXPECT_EQ(observer.use_count(), 1);
  }
}

// ---------------------------------------------------------------------------------------------
// Guaranteed delivery on destruction
// ---------------------------------------------------------------------------------------------

TEST(CallbackTest, DeliversTheShutdownValueWhenNeverInvoked)
{
  int fired = 0;
  StatusCode delivered{Status::Good};
  {
    ua::Callback<Payload> callback = [&](Payload result)
    {
      ++fired;
      delivered = result.status_code();
    };
  }
  EXPECT_EQ(fired, 1);
  EXPECT_EQ(delivered.value(), static_cast<StatusCodeValue>(Status::BadShutdown));
}

TEST(CallbackTest, DeliversTheShutdownValueForAVoidResult)
{
  StatusCode delivered{Status::Good};
  {
    ua::Callback<VoidResult> callback = [&delivered](VoidResult result)
    {
      delivered = result.status_code();
    };
  }
  EXPECT_EQ(delivered.value(), static_cast<StatusCodeValue>(Status::BadShutdown));
}

TEST(CallbackTest, DeliversTheShutdownValueForABatchResult)
{
  // BatchResult is an aggregate whose first member is a VoidResult, so it needs its own trait
  // specialization; a batch abandoned unfired fails as a whole with no per-item results.
  StatusCode delivered{Status::Good};
  std::size_t items = 1;
  {
    ua::Callback<BatchResult<Result<int>>> callback = [&](BatchResult<Result<int>> batch)
    {
      delivered = batch.batchStatus.status_code();
      items = batch.items.size();
    };
  }
  EXPECT_EQ(delivered.value(), static_cast<StatusCodeValue>(Status::BadShutdown));
  EXPECT_EQ(items, 0u);
}

TEST(CallbackTest, MayBeInvokedThroughAConstReference)
{
  // Parity with std::function: firing is const, so a completion captured by value into a
  // continuation that is not declared `mutable` can still deliver.
  int fired = 0;
  ua::Callback<Payload> callback = [&fired](Payload)
  {
    ++fired;
  };
  const ua::Callback<Payload>& constant = callback;
  constant(Payload{1});
  EXPECT_EQ(fired, 1);
  EXPECT_FALSE(static_cast<bool>(callback));
}

TEST(CallbackTest, ACapturedCompletionFiresFromANonMutableLambda)
{
  int fired = 0;
  ua::Callback<Payload> inner = [&fired](Payload)
  {
    ++fired;
  };
  const auto continuation = [held = std::move(inner)](Payload result)
  {
    held(std::move(result));
  };
  continuation(Payload{1});
  EXPECT_EQ(fired, 1);
}

TEST(CallbackTest, ShutdownValueIsAnErrorEvenWhenThePayloadIsAContainerOfStatusCodes)
{
  // Regression: a StatusCode is constructible from a Status, so brace-initializing
  // Result<std::vector<StatusCode>> would select the vector's initializer-list constructor and
  // produce a *good* one-element result instead of an error.
  bool good = true;
  {
    ua::Callback<Result<std::vector<StatusCode>>> callback = [&good](Result<std::vector<StatusCode>> result)
    {
      good = result.is_good();
    };
  }
  EXPECT_FALSE(good);
}

TEST(CallbackTest, ShutdownValueComesFromTheTrait)
{
  int delivered = 0;
  {
    ua::Callback<CustomPayload> callback = [&delivered](CustomPayload payload)
    {
      delivered = payload.code;
    };
  }
  EXPECT_EQ(delivered, 42);
}

// ---------------------------------------------------------------------------------------------
// release()
// ---------------------------------------------------------------------------------------------

TEST(CallbackTest, ReleaseSuppressesTheShutdownDelivery)
{
  int fired = 0;
  {
    ua::Callback<Payload> callback = [&fired](Payload)
    {
      ++fired;
    };
    callback.release();
    EXPECT_FALSE(static_cast<bool>(callback));
  }
  EXPECT_EQ(fired, 0);
}

TEST(CallbackTest, ReleaseDestroysTheCallable)
{
  const auto witness = std::make_shared<int>(0);
  std::weak_ptr<int> observer = witness;
  {
    ua::Callback<Payload> callback = [held = witness](Payload) {
    };
    callback.release();
    EXPECT_EQ(observer.use_count(), 1);
  }
}

TEST(CallbackTest, ReleaseAfterInvocationIsHarmless)
{
  int fired = 0;
  ua::Callback<Payload> callback = [&fired](Payload)
  {
    ++fired;
  };
  callback(Payload{1});
  callback.release();
  callback.release();
  EXPECT_EQ(fired, 1);
}

// ---------------------------------------------------------------------------------------------
// Move semantics
// ---------------------------------------------------------------------------------------------

TEST(CallbackTest, MoveConstructionTransfersTheObligation)
{
  int fired = 0;
  {
    ua::Callback<Payload> source = [&fired](Payload)
    {
      ++fired;
    };
    ua::Callback<Payload> target(std::move(source));
    EXPECT_FALSE(static_cast<bool>(source));
    EXPECT_TRUE(static_cast<bool>(target));
    EXPECT_EQ(fired, 0);
  }
  // Exactly one delivery, from the target: the emptied source owes nothing.
  EXPECT_EQ(fired, 1);
}

TEST(CallbackTest, AMovedFromCallbackDeliversNothing)
{
  int fired = 0;
  ua::Callback<Payload> source = [&fired](Payload)
  {
    ++fired;
  };
  {
    ua::Callback<Payload> target(std::move(source));
    target(Payload{1});
  }
  EXPECT_EQ(fired, 1);
  source(Payload{2});
  EXPECT_EQ(fired, 1);
}

TEST(CallbackTest, MoveAssignmentDeliversToTheDisplacedObligation)
{
  int displaced = 0;
  int incoming = 0;
  {
    ua::Callback<Payload> target = [&displaced](Payload result)
    {
      ++displaced;
      EXPECT_EQ(result.status_code().value(), static_cast<StatusCodeValue>(Status::BadShutdown));
    };
    ua::Callback<Payload> source = [&incoming](Payload)
    {
      ++incoming;
    };

    target = std::move(source);

    // The obligation the assignment overwrote is not lost; it is reported as a shutdown.
    EXPECT_EQ(displaced, 1);
    EXPECT_EQ(incoming, 0);
    EXPECT_TRUE(static_cast<bool>(target));
    EXPECT_FALSE(static_cast<bool>(source));
  }
  EXPECT_EQ(displaced, 1);
  EXPECT_EQ(incoming, 1);
}

TEST(CallbackTest, MoveAssignmentOverAnEmptyCallbackDeliversNothingExtra)
{
  int fired = 0;
  {
    ua::Callback<Payload> target;
    ua::Callback<Payload> source = [&fired](Payload)
    {
      ++fired;
    };
    target = std::move(source);
    EXPECT_EQ(fired, 0);
  }
  EXPECT_EQ(fired, 1);
}

TEST(CallbackTest, SelfMoveAssignmentKeepsTheObligation)
{
  int fired = 0;
  {
    ua::Callback<Payload> callback = [&fired](Payload)
    {
      ++fired;
    };
    ua::Callback<Payload>& alias = callback;
    callback = std::move(alias);
    EXPECT_TRUE(static_cast<bool>(callback));
    EXPECT_EQ(fired, 0);
  }
  EXPECT_EQ(fired, 1);
}

TEST(CallbackTest, ConvertingAssignmentDeliversToTheDisplacedObligation)
{
  int displaced = 0;
  int incoming = 0;
  {
    ua::Callback<Payload> callback = [&displaced](Payload)
    {
      ++displaced;
    };
    callback = [&incoming](Payload)
    {
      ++incoming;
    };
    EXPECT_EQ(displaced, 1);
    EXPECT_EQ(incoming, 0);
  }
  EXPECT_EQ(incoming, 1);
}

// ---------------------------------------------------------------------------------------------
// Storage strategy
// ---------------------------------------------------------------------------------------------

TEST(CallbackTest, ASmallCallableIsStoredInlineWithoutAllocating)
{
  SmallCallable::reset();
  int fired = 0;
  {
    ua::Callback<Payload> callback = SmallCallable{&fired, {}};
    callback(Payload{1});
  }
  EXPECT_EQ(fired, 1);
  EXPECT_EQ(SmallCallable::allocations, 0);
  EXPECT_EQ(SmallCallable::deallocations, 0);
}

TEST(CallbackTest, AnOversizedCallableIsHeapAllocatedAndFreedOnDelivery)
{
  LargeCallable::reset();
  int fired = 0;
  {
    ua::Callback<Payload> callback = LargeCallable{&fired, {}};
    EXPECT_EQ(LargeCallable::allocations, 1);
    callback(Payload{1});
    EXPECT_EQ(LargeCallable::deallocations, 1);
  }
  EXPECT_EQ(fired, 1);
}

TEST(CallbackTest, AnOversizedCallableIsFreedWhenReleased)
{
  LargeCallable::reset();
  int fired = 0;
  {
    ua::Callback<Payload> callback = LargeCallable{&fired, {}};
    callback.release();
    EXPECT_EQ(LargeCallable::deallocations, 1);
  }
  EXPECT_EQ(fired, 0);
}

TEST(CallbackTest, AnOversizedCallableSurvivesAMoveWithoutReallocating)
{
  LargeCallable::reset();
  int fired = 0;
  {
    ua::Callback<Payload> source = LargeCallable{&fired, {}};
    ua::Callback<Payload> target(std::move(source));
    EXPECT_EQ(LargeCallable::allocations, 1);
    EXPECT_EQ(LargeCallable::deallocations, 0);
  }
  EXPECT_EQ(fired, 1);
  EXPECT_EQ(LargeCallable::allocations, 1);
  EXPECT_EQ(LargeCallable::deallocations, 1);
}

TEST(CallbackTest, CarriesAMoveOnlyCapture)
{
  int delivered = 0;
  {
    auto owned = std::make_unique<int>(7);
    ua::Callback<Payload> callback = [held = std::move(owned), &delivered](Payload)
    {
      delivered = *held;
    };
  }
  EXPECT_EQ(delivered, 7);
}

TEST(CallbackTest, CarriesACaptureTooLargeForInlineStorage)
{
  int delivered = 0;
  {
    const std::array<int, 32> bulk{{1, 2, 3}};
    ua::Callback<Payload> callback = [bulk, &delivered](Payload)
    {
      delivered = bulk[1];
    };
  }
  EXPECT_EQ(delivered, 2);
}

// ---------------------------------------------------------------------------------------------
// Robustness: throwing callables, unwinding, re-entrancy
// ---------------------------------------------------------------------------------------------

TEST(CallbackTest, AThrowingCallableDoesNotEscapeInvocation)
{
  ua::Callback<Payload> callback = [](Payload)
  {
    throw std::runtime_error("handler");
  };
  EXPECT_NO_THROW(callback(Payload{1}));
  EXPECT_FALSE(static_cast<bool>(callback));
}

TEST(CallbackTest, AThrowingCallableDoesNotEscapeTheShutdownDelivery)
{
  EXPECT_NO_THROW({
    ua::Callback<Payload> callback = [](Payload)
    {
      throw std::runtime_error("handler");
    };
  });
}

TEST(CallbackTest, DeliversWhileAnExceptionIsUnwinding)
{
  int fired = 0;
  try
  {
    ua::Callback<Payload> callback = [&fired](Payload)
    {
      ++fired;
    };
    throw std::runtime_error("unwind");
  }
  catch (const std::runtime_error&)
  {}
  EXPECT_EQ(fired, 1);
}

TEST(CallbackTest, InvokedCodeMayDestroyTheObjectOwningTheCallback)
{
  int fired = 0;
  auto* owner = new Owner{};
  owner->completion = [owner, &fired](Payload)
  {
    ++fired;
    delete owner;
  };
  ua::Callback<Payload> taken = std::move(owner->completion);
  taken(Payload{1});
  EXPECT_EQ(fired, 1);
}

TEST(CallbackTest, InvokedCodeMayReinvokeTheSameCallback)
{
  int fired = 0;
  ua::Callback<Payload> callback;
  callback = [&callback, &fired](Payload)
  {
    ++fired;
    callback(Payload{Status::BadInternalError});
  };
  callback(Payload{1});
  EXPECT_EQ(fired, 1);
}

TEST(CallbackTest, ShutdownDeliveryMayDestroyAnotherCallback)
{
  int inner = 0;
  {
    ua::Callback<Payload> outer;
    auto nested = ua::Callback<Payload>{[&inner](Payload result)
      {
        ++inner;
        EXPECT_EQ(result.status_code().value(), static_cast<StatusCodeValue>(Status::BadShutdown));
      }};
    // A callback captured by another callback: move-only is viral, and the inner obligation is
    // met when the outer one is destroyed unfired.
    outer = [held = std::move(nested)](Payload) mutable {
    };
  }
  EXPECT_EQ(inner, 1);
}

// ---------------------------------------------------------------------------------------------
// Containers and payload handling
// ---------------------------------------------------------------------------------------------

TEST(CallbackTest, AContainerOfCallbacksDeliversToEachOnDestruction)
{
  int fired = 0;
  {
    std::vector<ua::Callback<Payload>> pending;
    for (int index = 0; index < 4; ++index)
    {
      pending.emplace_back([&fired](Payload) { ++fired; });
    }
    EXPECT_EQ(fired, 0);
  }
  EXPECT_EQ(fired, 4);
}

TEST(CallbackTest, ThePayloadIsMovedRatherThanCopied)
{
  Tracker::reset();
  {
    ua::Callback<Result<Tracker>> callback = [](Result<Tracker> result)
    {
      EXPECT_TRUE(result.is_good());
    };
    callback(Result<Tracker>{Tracker{}});
  }
  EXPECT_EQ(Tracker::copies, 0);
}

}  // namespace
