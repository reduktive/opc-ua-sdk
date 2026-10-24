// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// What a task guarantees when the world stops being tidy.
///
/// A collaborator handed a completion may fire it from any thread, at any time, twice, or never,
/// and may do so after the task that asked has been destroyed. These pin what happens in each case,
/// and each one is written so that breaking the property it names makes it fail - a test that
/// passes whether or not the mechanism works is not evidence of anything.
///
/// The properties, and where each is pinned:
///   value and nesting          - a task's value reaches its awaiter, through one level or several
///   inline completion          - a collaborator answering on the calling stack costs no suspension
///   destruction                - destroying a suspended task runs its locals' destructors
///   liveness                   - a completion arriving after the task died is dropped
///   identity                   - a completion from a finished suspension cannot resume its successor
///   arity                      - a completion fired twice resumes once; one never fired leaks nothing
///   serialisation              - a task resumes on its strand and nowhere else
///   containment                - a throw in a body, nested or not, does not escape into the machinery
///   races                      - teardown against off-thread completions, run hard

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>
#include <vector>

#include "ua_await_callback.h"
#include "ua_coro.h"

using namespace ua::async;

namespace
{

using Strand = boost::asio::strand<boost::asio::io_context::executor_type>;

/// Reports where it is, so a test can tell a copy in the frame from a reference to the caller's.
struct Tracked
{
  int id;
  static inline std::atomic<int> destroyed{0};

  explicit Tracked(int value) : id(value)
  {}

  Tracked(Tracked&& other) noexcept : id(other.id)
  {}

  Tracked(const Tracked&) = delete;
  Tracked& operator=(const Tracked&) = delete;

  ~Tracked()
  {
    destroyed.fetch_add(1);
  }
};

/// Counts the coroutine local's lifetime, so a destroyed frame is observable.
struct Tracer
{
  static inline std::atomic<int> alive{0};

  Tracer()
  {
    alive.fetch_add(1);
  }

  Tracer(const Tracer&) = delete;
  Tracer& operator=(const Tracer&) = delete;

  ~Tracer()
  {
    alive.fetch_sub(1);
  }
};

/// Stands in for a namespace interface: takes a completion exactly as the SDK's `*_async` members do, and
/// either answers on the calling stack or keeps it to fire later, from wherever the test likes.
class Collaborator
{
public:
  explicit Collaborator(bool answerInline = false, size_t inlineAnswers = 1)
    : mAnswerInline(answerInline), mInlineAnswers(inlineAnswers)
  {}

  void read_async(std::function<void(int)> done)
  {
    ++mCalls;
    if (mAnswerInline)
    {
      for (size_t answer = 0; answer < mInlineAnswers; ++answer)
      {
        done(++mNextValue);
      }
      return;
    }
    mPending = std::move(done);
  }

  void fire(int value)
  {
    if (mPending)
    {
      mPending(value);
    }
  }

  [[nodiscard]] std::function<void(int)> take()
  {
    return std::exchange(mPending, nullptr);
  }

  [[nodiscard]] bool has_pending() const
  {
    return static_cast<bool>(mPending);
  }

  [[nodiscard]] int calls() const
  {
    return mCalls;
  }

private:
  bool mAnswerInline;
  size_t mInlineAnswers;
  int mNextValue{0};
  int mCalls{0};
  std::function<void(int)> mPending;
};

/// A snapshot of why completions were dropped or delivered, so a test can assert that the protocol
/// MADE a decision rather than that nothing visibly happened. The difference is not academic: a
/// completion that emptied its own weak pointer on first use dropped its second firing before the
/// generation was ever consulted, and the test meant to prove the generation check worked passed
/// regardless.
struct Decisions
{
  std::uint64_t ownerGone{};
  std::uint64_t taskGone{};
  std::uint64_t staleGeneration{};
  std::uint64_t notSuspended{};
  std::uint64_t resumed{};

  static Decisions now()
  {
    const auto& counts = rejection_counts();
    return {counts.ownerGone.load(),
      counts.taskGone.load(),
      counts.staleGeneration.load(),
      counts.notSuspended.load(),
      counts.resumed.load()};
  }

  /// What happened since @p earlier.
  Decisions since(const Decisions& earlier) const
  {
    return {ownerGone - earlier.ownerGone,
      taskGone - earlier.taskGone,
      staleGeneration - earlier.staleGeneration,
      notSuspended - earlier.notSuspended,
      resumed - earlier.resumed};
  }
};

/// Starts a task ON its strand, which is how a component starts one and what the primitive's
/// contract requires. Starting off-strand still works, but every completion that answers on the
/// calling stack then has to be queued rather than run inline - so a test that starts off-strand
/// measures the wrong thing and would have us "fix" the primitive to suit it.
template<typename Make>
auto start_on_strand(boost::asio::io_context& io, auto& strand, Make make)
{
  std::optional<decltype(make())> task;
  boost::asio::dispatch(strand, [&] { task.emplace(make()); });
  io.restart();
  io.poll();
  return std::move(*task);
}

/// An io_context plus its strand, drained on demand.
struct Loop
{
  boost::asio::io_context io;
  Strand strand{boost::asio::make_strand(io.get_executor())};
  ua::Logger logger;

  /// Stands in for the component that owns the tasks: production passes `weak_from_this()`, and a
  /// resumption pins this for as long as it runs. A test can `owner.reset()` to model the owner
  /// dying, which is what takes the frames with it.
  std::shared_ptr<int> owner{std::make_shared<int>(0)};

  /// Stands in for the request's cancellation token. A test can `cancelled->store(true)` to model
  /// the initiator withdrawing, which makes the next resumption throw ua::async::Abandoned.
  std::shared_ptr<std::atomic_bool> cancelled{std::make_shared<std::atomic_bool>(false)};

  /// How every task below gets that token: nothing passes it. Each of these coroutines takes a
  /// `Loop&` first, exactly as a member coroutine takes `*this` first, and the promise adopts the
  /// token of its first argument at construction. Rename this accessor and every withdrawal test
  /// here goes red - which is the point, and what `tooling/ci/falsify_coro.py` asserts.
  /// @see ua::async::detail::PromiseBase
  std::shared_ptr<const std::atomic_bool> cancellation_token() const noexcept
  {
    return cancelled;
  }

  /// Runs everything queued. `poll()` leaves the context stopped once it drains, so restart first.
  std::size_t drain()
  {
    io.restart();
    return io.poll();
  }
};

Task<int> read_once(Loop& loop, Collaborator& collaborator)
{
  const Tracer tracer;
  const int value = co_await await_callback<int>(
    loop.strand, loop.logger, loop.owner, [&](auto done) { collaborator.read_async(std::move(done)); });
  co_return value;
}

Task<int> read_twice(Loop& loop, Collaborator& first, Collaborator& second)
{
  const int a = co_await await_callback<int>(
    loop.strand, loop.logger, loop.owner, [&](auto done) { first.read_async(std::move(done)); });
  const int b = co_await await_callback<int>(
    loop.strand, loop.logger, loop.owner, [&](auto done) { second.read_async(std::move(done)); });
  co_return a + b;
}

Task<int> doubles_the_inner(Loop& loop, Collaborator& collaborator)
{
  const int inner = co_await read_once(loop, collaborator);
  co_return inner * 2;
}

// Tasks are named functions taking references, never immediately-invoked lambdas. A lambda's closure
// is a temporary that dies at the end of the statement that called it, while the body goes on
// reaching its captures through that closure after every suspension - so `[&]{...}()` as a coroutine
// is a use-after-free that happens to work whenever the stack is not reused. It cost an afternoon
// here; it is not a style preference.

Task<> assign_read_once(Loop& loop, Collaborator& collaborator, int& out)
{
  out = co_await read_once(loop, collaborator);
  co_return;
}

Task<> assign_nested(Loop& loop, Collaborator& collaborator, int& out)
{
  out = co_await doubles_the_inner(loop, collaborator);
  co_return;
}

Task<> assign_read_twice(Loop& loop, Collaborator& first, Collaborator& second, int& out)
{
  out = co_await read_twice(loop, first, second);
  co_return;
}

Task<> assign_and_count(Loop& loop, Collaborator& collaborator, int& out, int& resumes)
{
  out = co_await read_once(loop, collaborator);
  ++resumes;
  co_return;
}

Task<> record_resuming_thread(Loop& loop, Collaborator& collaborator, std::atomic<bool>& onStrand)
{
  (void)co_await await_callback<int>(
    loop.strand, loop.logger, loop.owner, [&](auto done) { collaborator.read_async(std::move(done)); });
  onStrand.store(loop.strand.running_in_this_thread());
  co_return;
}

Task<> throws_after_resume(Loop& loop, Collaborator& collaborator)
{
  (void)co_await await_callback<int>(
    loop.strand, loop.logger, loop.owner, [&](auto done) { collaborator.read_async(std::move(done)); });
  throw std::runtime_error{"after resume"};
}

Task<int> always_throws()
{
  throw std::runtime_error{"inner"};
  co_return 0;
}

Task<> catches_the_inner(bool& caught)
{
  try
  {
    (void)co_await always_throws();
  }
  catch (const std::runtime_error&)
  {
    caught = true;
  }
  co_return;
}

// A weak_ptr parameter, because that is the shape in the SDK: a component holds its collaborators
// weakly and must lock to use one. Taking a shared_ptr BY VALUE would settle the question before it
// is asked - a by-value parameter lives in the frame for the whole coroutine, so it is held across
// every suspension whatever the body does with blocks.

Task<int> holds_across_suspension(Loop& loop, Collaborator& collaborator, std::weak_ptr<int> owner)
{
  auto strong = owner.lock();  // locked, and then deliberately kept across the await below
  const int value = co_await await_callback<int>(
    loop.strand, loop.logger, loop.owner, [&](auto done) { collaborator.read_async(std::move(done)); });
  co_return value + (strong ? *strong : 0);
}

Task<int> scopes_before_suspension(Loop& loop, Collaborator& collaborator, std::weak_ptr<int> owner)
{
  int base = 0;
  {
    // Locked, checked and used - all of which needs a local. The point is only how long it lives.
    auto strong = owner.lock();
    if (!strong)
    {
      co_return 0;
    }
    base = *strong;
  }  // released HERE, before anything suspends
  const int value = co_await await_callback<int>(
    loop.strand, loop.logger, loop.owner, [&](auto done) { collaborator.read_async(std::move(done)); });
  co_return value + base;
}

/// Reports where its parameter lives, so a test can see whether it was moved into the frame or
/// merely referred to.
Task<int> takes_by_value(Loop& loop, Collaborator& collaborator, Tracked value, const void** seenAt)
{
  *seenAt = &value;
  (void)co_await await_callback<int>(
    loop.strand, loop.logger, loop.owner, [&](auto done) { collaborator.read_async(std::move(done)); });
  co_return value.id;
}

Task<int> takes_by_rvalue_ref(Loop& loop, Collaborator& collaborator, Tracked&& value, const void** seenAt)
{
  *seenAt = &value;
  (void)co_await await_callback<int>(
    loop.strand, loop.logger, loop.owner, [&](auto done) { collaborator.read_async(std::move(done)); });
  // Deliberately does NOT touch `value` after resuming: the referent is the caller's temporary and
  // is already destroyed. Reading it here is what this test exists to make impossible to write by
  // accident.
  co_return 0;
}

/// Awaits a callback, then suspends again on a NESTED TASK rather than another callback.
///
/// That second suspension is the one that used to leave the first await's generation standing: a
/// nested Task does not begin a new CallbackAwaitable, so nothing bumped it. @see
/// ASecondFiringWhileANestedFlowIsSuspendedDoesNotReachTheRetiredAwaitable
Task<int> reads_then_awaits_a_nested_flow(Loop& loop, Collaborator& first, Collaborator& nested)
{
  const int a = co_await await_callback<int>(
    loop.strand, loop.logger, loop.owner, [&](auto done) { first.read_async(std::move(done)); });
  const int b = co_await read_once(loop, nested);
  co_return a + b;
}

/// Awaits twice, recording how far it got and what stopped it.
///
/// For the cancellation tests: `steps` says how many awaits resumed, and `abandoned` says whether
/// the body was unwound by ua::async::Abandoned rather than carrying on with an answer nobody wants.
Task<int> reads_twice_recording_progress(
  Loop& loop, Collaborator& first, Collaborator& second, int& steps, bool& abandoned)
{
  try
  {
    const int a = co_await await_callback<int>(
      loop.strand, loop.logger, loop.owner, [&](auto done) { first.read_async(std::move(done)); });
    ++steps;
    const int b = co_await await_callback<int>(
      loop.strand, loop.logger, loop.owner, [&](auto done) { second.read_async(std::move(done)); });
    ++steps;
    co_return a + b;
  }
  catch (const ua::async::Abandoned&)
  {
    abandoned = true;
    co_return -1;
  }
}

/// Records how many times the collaborator was actually ASKED.
///
/// Every other withdrawal test here observes a body that stopped. This one observes work that was
/// never started, which is the other half of what withdrawal means and the only half a check placed
/// on the RESUMPTION cannot deliver.
Task<> counts_what_it_started(Loop& loop, Collaborator& collaborator, int& initiations, bool& abandoned)
{
  try
  {
    (void)co_await await_callback<int>(loop.strand,
      loop.logger,
      loop.owner,
      [&](auto done)
      {
        ++initiations;
        collaborator.read_async(std::move(done));
      });
  }
  catch (const ua::async::Abandoned&)
  {
    abandoned = true;
  }
}

/// Awaits answers that are already here - the shape an interface with a synchronous form produces.
///
/// Nothing in the callback machinery is on this path: no completion, no generation, no mutex, no
/// strand hop, and no suspension. That is the point of it, and it is also why it is the shape that
/// would have slipped past a withdrawal check living inside `CallbackAwaitable`.
Task<> takes_answers_that_are_already_here(Loop& loop, int& steps, bool& abandoned)
{
  try
  {
    steps += co_await ua::async::ready(1);
    steps += co_await ua::async::ready(1);
  }
  catch (const ua::async::Abandoned&)
  {
    abandoned = true;
  }
}

/// Awaits a collaborator whose initiation throws, and contains it the way a service would.
Task<int> throws_from_its_initiation(Loop& loop, bool& reachedTheBody)
{
  try
  {
    co_return co_await await_callback<int>(
      loop.strand, loop.logger, loop.owner, [](auto) { throw std::runtime_error{"dependency gone"}; });
  }
  catch (const std::runtime_error&)
  {
    reachedTheBody = true;
    co_return -1;
  }
}

/// Deliberately does NOT take a Loop: its first argument offers no `cancellation_token()`, so its
/// promise adopts none and the task cannot be withdrawn. That is the right answer for work with no
/// initiator to withdraw it, and it is what a coroutine gets by default.
Task<int> race_read(
  Strand strand, ua::Logger logger, std::weak_ptr<const void> owner, Collaborator& collaborator)
{
  const int value = co_await await_callback<int>(
    strand, logger, std::move(owner), [&](auto done) { collaborator.read_async(std::move(done)); });
  co_return value;
}

/// Where the stack pointer is, so a test can assert that a loop of awaits does not walk it down.
/// Taken from the frame address rather than a helper's local, which the optimiser is free to place
/// anywhere.
inline long stack_depth_from(const char* anchor)
{
  const auto* here = static_cast<const char*>(__builtin_frame_address(0));
  const long delta = anchor - here;
  return delta < 0 ? -delta : delta;
}

Task<int> many_inline_steps(
  Loop& loop, Collaborator& collaborator, int steps, const char* anchor, long& deepest)
{
  int total = 0;
  for (int step = 0; step < steps; ++step)
  {
    total += co_await await_callback<int>(
      loop.strand, loop.logger, loop.owner, [&](auto done) { collaborator.read_async(std::move(done)); });
    const long depth = stack_depth_from(anchor);
    if (depth > deepest)
    {
      deepest = depth;
    }
  }
  co_return total;
}

}  // namespace

// --- value and nesting --------------------------------------------------------------------------

TEST(CoroTest, AFlowsValueReachesItsAwaiter)
{
  Loop loop;
  Collaborator collaborator;

  int seen = 0;
  auto task = assign_read_once(loop, collaborator, seen);

  collaborator.fire(7);
  loop.drain();

  EXPECT_EQ(seen, 7);
}

TEST(CoroTest, AValuePropagatesThroughANestedFlow)
{
  Loop loop;
  Collaborator collaborator;

  int seen = 0;
  auto task = assign_nested(loop, collaborator, seen);

  collaborator.fire(21);
  loop.drain();

  EXPECT_EQ(seen, 42) << "the inner task's value did not reach the outer one";
}

TEST(CoroTest, SuccessiveAwaitsInOneFlowEachResumeOnce)
{
  Loop loop;
  Collaborator first;
  Collaborator second;

  int seen = 0;
  auto task = assign_read_twice(loop, first, second, seen);

  first.fire(10);
  loop.drain();
  ASSERT_TRUE(second.has_pending()) << "the task did not reach its second await";
  second.fire(5);
  loop.drain();

  EXPECT_EQ(seen, 15);
}

// --- inline completion --------------------------------------------------------------------------

TEST(CoroTest, AnInlineCollaboratorNeitherSuspendsNorPosts)
{
  Loop loop;
  Collaborator inlineCollaborator{true};

  auto task = start_on_strand(loop.io, loop.strand, [&] { return read_once(loop, inlineCollaborator); });

  // Finished on the strand it was started on: dispatch ran the completion inline, so nothing was
  // queued and there is nothing left for the loop to run.
  EXPECT_TRUE(task.done()) << "an inline answer should have completed the task already";
  EXPECT_EQ(loop.drain(), 0u) << "an inline answer should not have posted anything";
}

// @relation(AC-COMP-CORE-ASYNC-CORO-03-A-COMPLETION-RESUMES-ONCE, scope=function)
TEST(CoroTest, TwoInlineAnswersKeepTheFirstWithoutPosting)
{
  Loop loop;
  Collaborator collaborator{true, 2};
  int seen = 0;
  int resumes = 0;
  auto task = start_on_strand(
    loop.io, loop.strand, [&] { return assign_and_count(loop, collaborator, seen, resumes); });

  EXPECT_TRUE(task.done());
  EXPECT_EQ(seen, 1);
  EXPECT_EQ(resumes, 1);
  EXPECT_EQ(loop.drain(), 0u);
}

TEST(CoroTest, ManyInlineStepsCostOneTurnAndNoStackGrowth)
{
  Loop loop;
  Collaborator inlineCollaborator{true};

  // A task whose collaborator always answers inline must not consume stack per step, or a Read of a
  // thousand operations would grow the stack a thousand deep.
  const char anchor = 0;

  long shallowDeepest = 0;
  auto shallow = start_on_strand(loop.io,
    loop.strand,
    [&] { return many_inline_steps(loop, inlineCollaborator, 10, &anchor, shallowDeepest); });
  EXPECT_TRUE(shallow.done());

  long deepDeepest = 0;
  auto deep = start_on_strand(loop.io,
    loop.strand,
    [&] { return many_inline_steps(loop, inlineCollaborator, 2000, &anchor, deepDeepest); });
  EXPECT_TRUE(deep.done());

  EXPECT_EQ(loop.drain(), 0u) << "inline steps should post nothing at all";
  EXPECT_EQ(inlineCollaborator.calls(), 2010);

  // The point: two hundred times the awaits must not cost two hundred times the stack. An await that
  // completes inline does not suspend and does not nest, so the depth is whatever one iteration
  // needs - a Read carrying a thousand operations costs the same stack as one carrying ten.
  EXPECT_EQ(deepDeepest, shallowDeepest) << "a loop of inline awaits walked the stack down: 10 steps used "
                                         << shallowDeepest << " bytes, 2000 used " << deepDeepest;
}

// --- destruction --------------------------------------------------------------------------------

TEST(CoroTest, DestroyingASuspendedFlowRunsItsLocalsDestructors)
{
  Loop loop;
  Collaborator collaborator;

  Tracer::alive.store(0);
  {
    auto task = read_once(loop, collaborator);
    ASSERT_EQ(Tracer::alive.load(), 1) << "the task should be suspended with its local alive";
  }
  EXPECT_EQ(Tracer::alive.load(), 0) << "destroying a suspended task must run its locals' destructors";
}

TEST(CoroTest, DestroyingAnOuterFlowDestroysTheInnerItIsAwaiting)
{
  Loop loop;
  Collaborator collaborator;

  Tracer::alive.store(0);
  {
    auto outer = doubles_the_inner(loop, collaborator);
    ASSERT_EQ(Tracer::alive.load(), 1) << "the inner task should be suspended with its local alive";
  }
  EXPECT_EQ(Tracer::alive.load(), 0) << "the inner frame outlived the outer task that owned it";
}

// --- liveness and identity ----------------------------------------------------------------------

TEST(CoroTest, ACompletionArrivingAfterTheFlowDiedIsDropped)
{
  Loop loop;
  Collaborator collaborator;

  std::function<void(int)> stranded;
  {
    auto task = read_once(loop, collaborator);
    stranded = collaborator.take();
    ASSERT_TRUE(stranded) << "the collaborator should be holding a completion";
  }

  // The task is gone. Firing must be a no-op rather than a use-after-free.
  const auto before = Decisions::now();
  stranded(99);
  const auto after = Decisions::now().since(before);

  EXPECT_EQ(loop.drain(), 0u) << "a completion for a dead task should not have posted a resume";
  EXPECT_EQ(after.taskGone, 1u)
    << "the completion was dropped, but not because the task had gone - the weak pointer is what "
       "makes this safe, so it must be what did it";
}

TEST(CoroTest, ATaskDestroyedBetweenACompletionAndItsResumptionIsReportedAsGone)
{
  Loop loop;
  Collaborator collaborator;

  auto task = start_on_strand(loop.io, loop.strand, [&] { return read_once(loop, collaborator); });
  ASSERT_TRUE(collaborator.has_pending());

  const auto before = Decisions::now();

  // Fired off the strand, so the resumption is QUEUED: the task is alive when the completion
  // consults it and destroyed by the time that turn comes. The cheap check before the hop cannot
  // see this one, which is why the strand side asks again.
  collaborator.fire(7);
  task = Task<int>{};
  loop.drain();

  const auto after = Decisions::now().since(before);
  EXPECT_EQ(after.taskGone, 1u)
    << "the task was destroyed, and that - not a stale suspension - is why this was dropped";
  EXPECT_EQ(after.resumed, 0u);
}

TEST(CoroTest, ACompletionFromAFinishedSuspensionCannotResumeItsSuccessor)
{
  Loop loop;
  Collaborator first;
  Collaborator second;

  int seen = 0;
  auto task = assign_read_twice(loop, first, second, seen);

  // Take the first suspension's completion, let the task move on to the second, then fire the
  // stale one. Its generation belongs to a suspension that is over.
  auto stale = first.take();
  ASSERT_TRUE(stale);
  stale(10);
  loop.drain();
  ASSERT_TRUE(second.has_pending()) << "the task should be waiting on its second collaborator";

  const auto before = Decisions::now();
  stale(1000);
  loop.drain();
  const auto after = Decisions::now().since(before);

  EXPECT_EQ(seen, 0) << "a stale completion resumed a suspension it did not belong to";
  EXPECT_EQ(after.staleGeneration, 1u)
    << "the stale completion was dropped, but NOT by the generation check - so that check is "
       "untested by this case";
  EXPECT_EQ(after.taskGone, 0u) << "the task was alive; dropping it as gone is the wrong reason";

  second.fire(5);
  loop.drain();
  EXPECT_EQ(seen, 15) << "the live completion should still resume the task normally";
}

// --- arity --------------------------------------------------------------------------------------

TEST(CoroTest, ACompletionFiredTwiceResumesOnce)
{
  Loop loop;
  Collaborator collaborator;

  int resumes = 0;
  int seen = 0;
  auto task = assign_and_count(loop, collaborator, seen, resumes);

  auto done = collaborator.take();
  ASSERT_TRUE(done);
  const auto before = Decisions::now();
  done(3);
  done(4);
  loop.drain();
  const auto after = Decisions::now().since(before);

  EXPECT_EQ(resumes, 1) << "a completion fired twice resumed the task twice";
  EXPECT_EQ(seen, 3) << "the second firing overwrote the first answer";
  EXPECT_EQ(after.resumed, 1u) << "the task resumed other than exactly once";

  // Dropped by one of the two liveness mechanisms, and it matters which are possible: the task here
  // is `read_once`, awaited as a temporary whose Task is destroyed the moment the await completes,
  // so its state is released and the second firing finds an expired weak pointer. A task that
  // outlives its suspension - one with a later await still to come - is caught by the generation
  // instead. Either is the protocol deciding; neither being incremented would mean the second
  // firing was ignored by accident.
  EXPECT_EQ(after.taskGone + after.staleGeneration, 1u)
    << "the second firing was not dropped by the protocol at all";
}

TEST(CoroTest, ASecondFiringOnALivingFlowIsRejectedByItsGeneration)
{
  // The sibling test above fires twice at a task that is a temporary, destroyed the moment its await
  // completes - so the second firing is dropped because the task has GONE, and a broken generation
  // check would look identical. Here the task has a second await still to come, so it is very much
  // alive when the stale firing arrives, and only the generation can reject it. Without this case a
  // completion that emptied its own weak pointer would pass the whole suite.
  Loop loop;
  Collaborator first;
  Collaborator second;

  int seen = 0;
  auto task = assign_read_twice(loop, first, second, seen);

  auto done = first.take();
  ASSERT_TRUE(done);
  done(10);
  loop.drain();
  ASSERT_TRUE(second.has_pending()) << "the task should now be waiting on its second collaborator";

  const auto before = Decisions::now();
  done(10);  // the same completion again, while its task is alive and suspended elsewhere
  loop.drain();
  const auto after = Decisions::now().since(before);

  EXPECT_EQ(after.staleGeneration, 1u)
    << "a living task's stale completion must be rejected by the generation, not by anything else";
  EXPECT_EQ(after.taskGone, 0u)
    << "the task was alive - reporting it as gone means the weak pointer was emptied, and the "
       "generation check is doing no work";
  EXPECT_EQ(after.resumed, 0u) << "the stale firing resumed the task";
}

TEST(CoroTest, ASecondFiringWhileANestedFlowIsSuspendedDoesNotReachTheRetiredAwaitable)
{
  Loop loop;
  Collaborator first;
  Collaborator nested;

  auto task = start_on_strand(
    loop.io, loop.strand, [&] { return reads_then_awaits_a_nested_flow(loop, first, nested); });

  auto fireFirstAgain = first.take();
  ASSERT_TRUE(fireFirstAgain);

  // Answer the first await. The task carries on and suspends on the NESTED flow - which begins no
  // CallbackAwaitable of its own at this level, so nothing here bumps the first await's generation.
  fireFirstAgain(1);
  loop.drain();
  ASSERT_TRUE(nested.has_pending()) << "the task should now be waiting inside the nested flow";

  const auto before = Decisions::now();

  // The first collaborator fires a second time. Its awaitable is long destroyed - the temporary died
  // with its co_await full-expression - but its generation stood until the awaitable retired it.
  fireFirstAgain(99);
  loop.drain();

  const auto after = Decisions::now().since(before);
  EXPECT_EQ(after.staleGeneration, 1u) << "a destroyed awaitable's generation must not still be current";
  EXPECT_EQ(after.notSuspended, 0u)
    << "reaching the notSuspended branch means the handler already wrote through a dangling `self`";
  EXPECT_EQ(after.resumed, 0u);
}

// Spawning starts the work. `initial_suspend` is `suspend_never`, so a task is in flight the moment
// it is created - which is what makes `for (auto& t : tasks) co_await t;` a JOIN over work already
// running rather than a sequence that starts each one when it reaches it.
//
// Nothing else in the suite can see this. Flip `initial_suspend` and every result is still correct,
// every test still passes, and every batched request silently costs N round trips instead of one.
TEST(CoroTest, SpawningATaskStartsItRatherThanWaitingForTheAwait)
{
  Loop loop;
  Collaborator first;
  Collaborator second;

  auto firstTask = read_once(loop, first);
  auto secondTask = read_once(loop, second);

  // Neither has been awaited. Both must already have reached their collaborator.
  EXPECT_TRUE(first.take()) << "the first task must have started when it was created";
  EXPECT_TRUE(second.take()) << "the second must be in flight too - it did not wait for the first to finish";
}

// A request that has been cancelled or has timed out has already answered its client. A body that
// resumes afterwards would compute a result nobody reads, into state that is being torn down. The
// token is asked on every resumption, so a body cannot carry on past a withdrawal by forgetting to
// look - which is what a hand-written check after each await depends on.
TEST(CoroTest, ACompletionArrivingAfterItsWorkWasCancelledUnwindsRatherThanResuming)
{
  Loop loop;
  Collaborator first;
  Collaborator second;
  int steps = 0;
  bool abandoned = false;

  auto task = reads_twice_recording_progress(loop, first, second, steps, abandoned);
  auto done = first.take();
  ASSERT_TRUE(done) << "the first await should be suspended on the collaborator";
  ASSERT_EQ(steps, 0);

  // The initiator withdraws while the task is suspended, then the collaborator answers anyway.
  loop.cancelled->store(true);
  done(7);
  loop.drain();

  EXPECT_TRUE(abandoned) << "the resumption must unwind the body, not continue it";
  EXPECT_EQ(steps, 0) << "the body must not have run past the await it was suspended on";
  EXPECT_FALSE(second.take()) << "the second collaborator must never have been asked";
}

// The token is asked at EVERY await, not only the first. A body that got past one suspension before
// the withdrawal must still stop at the next.
TEST(CoroTest, ALaterAwaitStillObservesAWithdrawalThatArrivedAfterAnEarlierOne)
{
  Loop loop;
  Collaborator first;
  Collaborator second;
  int steps = 0;
  bool abandoned = false;

  auto task = reads_twice_recording_progress(loop, first, second, steps, abandoned);
  auto firstDone = first.take();
  ASSERT_TRUE(firstDone);
  firstDone(1);
  loop.drain();
  ASSERT_EQ(steps, 1) << "the first await should have resumed normally";

  auto secondDone = second.take();
  ASSERT_TRUE(secondDone) << "the body should now be suspended on the second collaborator";

  loop.cancelled->store(true);
  secondDone(2);
  loop.drain();

  EXPECT_TRUE(abandoned);
  EXPECT_EQ(steps, 1) << "the body must not have run past the second await";
}

// The other half of withdrawal: a request nobody wants must not START work either. A check that
// only runs on the resumption cannot deliver this - by the time it runs, the collaborator has already
// been asked, and whatever that cost has already been spent.
TEST(CoroTest, AWithdrawnTaskNeverStartsTheWorkAtAll)
{
  Loop loop;
  Collaborator collaborator;
  int initiations = 0;
  bool abandoned = false;

  // Withdrawn before the body runs a single instruction, which is what a batch of operations spawned
  // after a cancel looks like.
  loop.cancelled->store(true);
  auto task = counts_what_it_started(loop, collaborator, initiations, abandoned);

  EXPECT_EQ(initiations, 0) << "the collaborator must never have been asked";
  EXPECT_TRUE(abandoned) << "and the body must have unwound rather than suspended forever";
  EXPECT_FALSE(collaborator.take());
}

// THE reason the withdrawal check does not live in `CallbackAwaitable`. This body never suspends and
// never touches the callback machinery, and it still stops. Move the check back into the awaitable
// and this is the test that goes red while every other one stays green.
TEST(CoroTest, AnAnswerThatWasAlreadyHereStillObservesAWithdrawal)
{
  Loop loop;
  int steps = 0;
  bool abandoned = false;

  loop.cancelled->store(true);
  auto task = takes_answers_that_are_already_here(loop, steps, abandoned);

  EXPECT_EQ(steps, 0) << "a co_await that answers immediately must still observe the withdrawal";
  EXPECT_TRUE(abandoned);
}

// ...and what it costs when nobody has withdrawn anything: nothing. No suspension, no strand turn,
// no allocation - the body runs to completion inside the call that started it. This is the whole
// reason an interface is given a synchronous form, so it is pinned rather than assumed.
TEST(CoroTest, AnAnswerThatWasAlreadyHereCostsNoSuspension)
{
  Loop loop;
  int steps = 0;
  bool abandoned = false;

  auto task = takes_answers_that_are_already_here(loop, steps, abandoned);

  EXPECT_EQ(steps, 2);
  EXPECT_FALSE(abandoned);
  EXPECT_TRUE(task.done()) << "nothing suspended, so the task finished where it was started";
  EXPECT_EQ(loop.drain(), 0u) << "and nothing was ever queued to the strand";
}

TEST(CoroTest, AThrowFromTheInitiationReachesTheBodyRatherThanHangingIt)
{
  Loop loop;

  // A collaborator whose accessor throws before it ever takes the completion - a dependency reached
  // after teardown, which the SDK's accessors do by design. Nothing will ever resume this task, so
  // logging and dropping the throw would suspend it forever and the request would never complete.
  bool reachedTheBody = false;
  auto task =
    start_on_strand(loop.io, loop.strand, [&] { return throws_from_its_initiation(loop, reachedTheBody); });
  loop.drain();

  EXPECT_TRUE(reachedTheBody)
    << "the throw must re-enter the body at the co_await, where the caller can contain it";
  EXPECT_TRUE(task.done()) << "and the task must finish rather than stay suspended";
}

TEST(CoroTest, ACompletionNeverFiredLeaksNothing)
{
  Loop loop;
  Collaborator collaborator;

  Tracer::alive.store(0);
  {
    auto task = read_once(loop, collaborator);
    (void)collaborator.take();  // the collaborator simply forgets it
  }
  EXPECT_EQ(Tracer::alive.load(), 0) << "a task whose collaborator never answered leaked its frame";
  EXPECT_EQ(loop.drain(), 0u);
}

// --- serialisation ------------------------------------------------------------------------------

TEST(CoroTest, AFlowResumesOnItsStrandAndNowhereElse)
{
  Loop loop;
  Collaborator collaborator;

  std::atomic<bool> onStrand{false};
  auto task = record_resuming_thread(loop, collaborator, onStrand);

  // Fire from a thread that is not running the strand.
  auto done = collaborator.take();
  ASSERT_TRUE(done);
  std::thread off([&] { done(1); });
  off.join();

  loop.drain();
  EXPECT_TRUE(onStrand.load()) << "the task resumed somewhere other than its strand";
}

// --- containment --------------------------------------------------------------------------------

TEST(CoroTest, AThrowOnTheStartingStackDoesNotEscape)
{
  Loop loop;

  EXPECT_NO_THROW({ auto task = always_throws(); }) << "a throw escaped the task into its starter";
}

TEST(CoroTest, AThrowAfterResumeDoesNotEscape)
{
  Loop loop;
  Collaborator collaborator;

  auto task = throws_after_resume(loop, collaborator);

  auto done = collaborator.take();
  ASSERT_TRUE(done);
  EXPECT_NO_THROW({
    done(1);
    loop.drain();
  }) << "a throw escaped a resumed task into the strand";
}

TEST(CoroTest, AThrowInsideANestedFlowReachesItsAwaiterAndIsContainedThere)
{
  Loop loop;

  bool caught = false;
  auto outer = catches_the_inner(caught);

  EXPECT_TRUE(caught) << "an inner task's exception did not reach the task awaiting it";
}

// --- what a suspended task keeps alive -----------------------------------------------------------

TEST(CoroTest, AStrongReferenceHeldAcrossASuspensionKeepsItsTargetAlive)
{
  Loop loop;
  Collaborator collaborator;
  auto owner = std::make_shared<int>(100);

  auto task = start_on_strand(loop.io,
    loop.strand,
    [&] { return holds_across_suspension(loop, collaborator, std::weak_ptr<int>{owner}); });

  // The task is suspended, and its frame is holding the reference. Whatever `owner` points at
  // cannot be destroyed until this task finishes or is destroyed - which is the cycle R7 is about
  // when the target transitively owns the frame.
  EXPECT_EQ(owner.use_count(), 2) << "a reference held across a suspension should be in the frame";
}

TEST(CoroTest, AStrongReferenceScopedBeforeTheSuspensionIsNotHeld)
{
  Loop loop;
  Collaborator collaborator;
  auto owner = std::make_shared<int>(100);

  auto task = start_on_strand(loop.io,
    loop.strand,
    [&] { return scopes_before_suspension(loop, collaborator, std::weak_ptr<int>{owner}); });

  // A frame holds only what is live ACROSS a suspension, so a local whose block ends first never
  // enters it. This is what makes the block-scoping remedy in R7 actually work rather than merely
  // look tidier.
  EXPECT_EQ(owner.use_count(), 1)
    << "a reference released before the suspension was kept in the frame anyway";
}

// --- how a parameter reaches the body ------------------------------------------------------------

TEST(CoroTest, AByValueParameterIsMovedIntoTheFrameAndSurvivesTheSuspension)
{
  Loop loop;
  Collaborator collaborator;

  const void* temporaryAt = nullptr;
  const void* seenInBody = nullptr;

  auto task = start_on_strand(loop.io,
    loop.strand,
    [&]
    {
      Tracked temporary{7};
      temporaryAt = &temporary;
      return takes_by_value(loop, collaborator, std::move(temporary), &seenInBody);
    });

  EXPECT_NE(seenInBody, temporaryAt)
    << "a by-value parameter should be MOVED into the frame, not left in the caller";

  collaborator.fire(1);
  loop.drain();
  // It was still readable after the suspension precisely because the frame owns it.
}

TEST(CoroTest, AnRvalueReferenceParameterIsNotMovedIntoTheFrame)
{
  Loop loop;
  Collaborator collaborator;

  const void* temporaryAt = nullptr;
  const void* seenInBody = nullptr;
  int destroyedBeforeResume = 0;

  auto task = start_on_strand(loop.io,
    loop.strand,
    [&]
    {
      Tracked temporary{9};
      temporaryAt = &temporary;
      return takes_by_rvalue_ref(loop, collaborator, std::move(temporary), &seenInBody);
    });

  // `T&&` stores the REFERENCE. Nothing was moved, so the body is looking at the caller's object -
  // which has now been destroyed, while the task is still suspended. `T&&` is the idiomatic sink
  // parameter everywhere else in C++, and here it is a dangling reference waiting to be read.
  EXPECT_EQ(seenInBody, temporaryAt)
    << "an rvalue-reference parameter should refer to the caller's object, not a frame copy";

  destroyedBeforeResume = Tracked::destroyed.load();
  collaborator.fire(1);
  loop.drain();
  EXPECT_GT(destroyedBeforeResume, 0)
    << "the referent should already be destroyed while the task is suspended";
}

// --- races --------------------------------------------------------------------------------------

TEST(CoroTest, TeardownRacingOffThreadCompletionsIsSafe)
{
  // The properties above are each checked once, in a fixed order. This runs the same handshake
  // repeatedly against a real thread pool so that the orderings which only appear under contention
  // are exercised too. Run under TSan, this is what says the weak/generation protocol is sound.
  //
  // It destroys the task ON its strand, so it says nothing about the case where the OWNER is
  // released from somewhere else - which is the one production presents. See
  // OwnerTeardownOffStrandRacingCompletionsIsSafe for that.
  constexpr int rounds = 400;

  for (int round = 0; round < rounds; ++round)
  {
    boost::asio::io_context io;
    auto strand = boost::asio::make_strand(io.get_executor());
    ua::Logger logger;

    Collaborator collaborator;
    auto owner = std::make_shared<int>(0);
    auto task = std::make_unique<Task<int>>();

    *task = race_read(strand, logger, owner, collaborator);

    auto done = collaborator.take();
    ASSERT_TRUE(done);

    boost::asio::thread_pool pool{2};
    std::atomic<bool> go{false};

    boost::asio::post(pool,
      [&]
      {
        while (!go.load(std::memory_order_acquire))
        {
        }
        done(round);
      });

    boost::asio::post(pool,
      [&]
      {
        while (!go.load(std::memory_order_acquire))
        {
        }
        // Destroy the task while the completion may be in flight. Both must be on the strand, which
        // is what the primitive's contract requires of a caller.
        boost::asio::dispatch(strand, [&] { task.reset(); });
        io.restart();
        io.poll();
      });

    go.store(true, std::memory_order_release);
    pool.join();

    io.restart();
    io.poll();
  }

  SUCCEED() << "no crash, no use-after-free, and nothing resumed a frame that had gone";
}

TEST(CoroTest, ACompletionArrivingAfterItsOwnerDiedIsDroppedBeforeTheTaskIsConsulted)
{
  Loop loop;
  Collaborator collaborator;

  auto task = start_on_strand(loop.io, loop.strand, [&] { return read_once(loop, collaborator); });
  ASSERT_TRUE(collaborator.has_pending());

  // The owner dies while the task is still suspended - a service erased by its session. The task
  // itself is untouched and its state still shared, so a protocol that asked only "does this task
  // exist" would answer yes and go on to write into a frame whose owner is releasing it.
  loop.owner.reset();

  const auto before = Decisions::now();
  collaborator.fire(7);
  const auto ranOnTheStrand = loop.drain();
  const auto after = Decisions::now().since(before);

  EXPECT_EQ(after.ownerGone, 1u) << "the drop is decided on the owner, and decided first";
  EXPECT_EQ(after.taskGone, 0u)
    << "the task was alive throughout - which is exactly why the owner check is not redundant";
  EXPECT_EQ(after.resumed, 0u);
  EXPECT_EQ(ranOnTheStrand, 0u)
    << "and decided before the hop: an owner already gone is not worth queueing a turn for";
}

TEST(CoroTest, AnOwnerDyingBetweenACompletionAndItsResumptionStopsTheResumption)
{
  Loop loop;
  Collaborator collaborator;

  auto task = start_on_strand(loop.io, loop.strand, [&] { return read_once(loop, collaborator); });
  ASSERT_TRUE(collaborator.has_pending());

  const auto before = Decisions::now();

  // Fired off the strand, so the resumption is QUEUED rather than run. The owner is alive when the
  // completion consults it and gone by the time that turn comes - which is the whole window the
  // strand-side pin exists for, and the one interleaving that can otherwise reach into a frame its
  // owner is releasing. The answer from before the hop is not good enough, so it is asked again.
  collaborator.fire(7);
  loop.owner.reset();
  loop.drain();

  const auto after = Decisions::now().since(before);
  EXPECT_EQ(after.ownerGone, 1u) << "asked again on the strand, not carried over from before it";
  EXPECT_EQ(after.resumed, 0u) << "the task was alive and its generation current; only the owner had gone";
}

TEST(CoroTest, OwnerTeardownOffStrandRacingCompletionsIsSafe)
{
  // The test above destroys the task ON its strand. Nothing in this SDK can promise that: a
  // service's last reference is dropped by the session that owns it, on the SESSION's strand, so
  // its frames are released from a thread the task knows nothing about. That is the shape run here,
  // and it is safe only because a resumption pins the owner across the generation check AND the
  // resume. Without the pin the check is stale the moment it is made, and the write into the frame
  // that follows is a use-after-free - which is what ASan is here to say.
  constexpr int rounds = 400;

  struct Owner
  {
    Task<int> task;
  };

  for (int round = 0; round < rounds; ++round)
  {
    boost::asio::io_context io;
    auto strand = boost::asio::make_strand(io.get_executor());
    ua::Logger logger;

    Collaborator collaborator;

    // The owner holds the task, exactly as a service holds its operations'.
    auto owner = std::make_shared<Owner>();
    owner->task = race_read(strand, logger, owner, collaborator);

    auto done = collaborator.take();
    ASSERT_TRUE(done);

    boost::asio::thread_pool pool{2};
    std::atomic<bool> go{false};

    boost::asio::post(pool,
      [&]
      {
        while (!go.load(std::memory_order_acquire))
        {
        }
        done(round);
        // Runs the resumption this queued - on THIS thread, which is the strand's for its duration.
        io.restart();
        io.poll();
      });

    boost::asio::post(pool,
      [&, held = owner]() mutable
      {
        while (!go.load(std::memory_order_acquire))
        {
        }
        // The owner's last reference, released off the strand and concurrently with the resumption.
        held.reset();
      });

    owner.reset();
    go.store(true, std::memory_order_release);
    pool.join();

    io.restart();
    io.poll();
  }

  SUCCEED() << "an owner released from another thread never leaves a resumption in a freed frame";
}
