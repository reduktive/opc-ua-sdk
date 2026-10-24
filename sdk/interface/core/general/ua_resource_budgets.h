// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Consolidated resource-protection budget tokens: node/edge work, recursion depth, and loop
///        iteration guards that bound recursive/iterative traversal and decode against denial-of-service
///        via maliciously crafted (deeply nested, densely linked, or non-terminating) input.
/// @ingroup general

#ifndef UA_RESOURCE_BUDGETS_H
#define UA_RESOURCE_BUDGETS_H

#include "ua_error_detail.h"
#include "ua_exceptions.h"

#include <memory>

namespace ua
{

/// A node/edge work budget that bounds the cost of a graph traversal or decode.
///
/// Counts units of work as they are performed and throws once either bound is crossed,
/// protecting against maliciously crafted inputs (e.g. deeply nested or densely linked
/// structures) that would otherwise exhaust resources. Budget state lives in the instance;
/// copies are independent.
///
/// Not thread-safe: a single budget must be confined to one thread for the duration of a
/// traversal.
/// @ingroup general
/// @see StackDepth, LoopLimit
class WorkBudget
{
public:
  /// Deleted: a budget has no meaningful default; bounds must be supplied.
  WorkBudget() = delete;

  /// Constructs a budget bounded to @p maxNodes node units and @p maxEdges edge units.
  ///
  /// @param maxNodes Maximum number of node units that may be consumed (inclusive).
  /// @param maxEdges Maximum number of edge units that may be consumed (inclusive).
  WorkBudget(size_t maxNodes, size_t maxEdges)
    : mNodesUsed(0), mEdgesUsed(0), mMaxNodes(maxNodes), mMaxEdges(maxEdges)
  {}

  /// Charges one node unit against the budget.
  ///
  /// @throws UaException with @ref Status::BadEncodingLimitsExceeded if charging this unit
  ///         would exceed the node bound.
  /// @post On return, one further node unit has been consumed.
  void consume_node()
  {
    if (++mNodesUsed > mMaxNodes)
    {
      throw UaException(Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("NodeBudgetExceeded", "Node work budget exceeded", "WorkBudget")
          .context(ua::ContextKeys::max, std::to_string(mMaxNodes))
          .context(ua::ContextKeys::actual, std::to_string(mNodesUsed)));
    }
  }

  /// Charges one edge unit against the budget.
  ///
  /// @throws UaException with @ref Status::BadEncodingLimitsExceeded if charging this unit
  ///         would exceed the edge bound.
  /// @post On return, one further edge unit has been consumed.
  void consume_edge()
  {
    if (++mEdgesUsed > mMaxEdges)
    {
      throw UaException(Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("EdgeBudgetExceeded", "Edge work budget exceeded", "WorkBudget")
          .context(ua::ContextKeys::max, std::to_string(mMaxEdges))
          .context(ua::ContextKeys::actual, std::to_string(mEdgesUsed)));
    }
  }

  /// Returns the number of node units consumed so far.
  ///
  /// @return The number of node units charged against this budget so far.
  [[nodiscard]] size_t nodes_used() const
  {
    return mNodesUsed;
  }

  /// Returns the number of edge units consumed so far.
  ///
  /// @return The number of edge units charged against this budget so far.
  [[nodiscard]] size_t edges_used() const
  {
    return mEdgesUsed;
  }

private:
  size_t mNodesUsed;
  size_t mEdgesUsed;
  size_t mMaxNodes;
  size_t mMaxEdges;
};

/// A shared work-budget passed through codecs and generated decode paths.
///
/// Carries TWO independent guards against decoding bombs, both throwing @ref
/// Status::BadEncodingLimitsExceeded when crossed:
///   * a cumulative nodes+edges WORK budget (fan-out / total-cost protection). The edge bound
///     defaults to the square of the node bound (saturating at @c SIZE_MAX) so a limit of N can
///     traverse the denser edge sets that explicit accounting exposes.
///   * a live recursion-DEPTH counter (call-stack protection). @ref enter_recursion increments it
///     and the returned RAII scope decrements it on unwind, so it tracks the CURRENT structural
///     nesting depth - bounding deep-narrow recursion (a native stack-overflow DoS) WITHOUT
///     penalising wide-shallow structures (the depth unwinds after each sibling). Capped at the
///     same configured limit, un-squared.
///
/// Budget state is reference-counted: all copies of a @ref StackDepth share one budget, so
/// charges made through any copy are seen by the others. Not thread-safe; confine a budget
/// (and its copies) to a single traversal on one thread.
/// @ingroup general
/// @see WorkBudget, LoopLimit
class StackDepth
{
  struct State;  // shared budget state, defined below; forward-declared so DepthScope can hold it.

public:
  /// RAII scope holding one unit of the shared recursion-depth counter; releases it on destruction.
  /// Move-only so the descent's frame owns exactly one depth unit for its lifetime.
  class DepthScope
  {
  public:
    /// Constructs an empty scope that holds no depth unit and releases nothing on destruction.
    DepthScope() = default;

    /// Constructs a scope that owns one already-charged depth unit of @p state, released on unwind.
    ///
    /// @param state Shared budget state whose live-depth counter has already been incremented for
    ///              this scope; the scope decrements it again when destroyed.
    explicit DepthScope(std::shared_ptr<struct State> state) : mState(std::move(state))
    {}

    /// Deleted: a depth unit is uniquely owned by one frame, so a scope is not copyable.
    DepthScope(const DepthScope&) = delete;
    /// Deleted: a depth unit is uniquely owned by one frame, so a scope is not copy-assignable.
    DepthScope& operator=(const DepthScope&) = delete;

    /// Transfers the owned depth unit from @p other, leaving @p other empty.
    ///
    /// @param other Scope to move from; left holding no depth unit afterwards.
    DepthScope(DepthScope&& other) noexcept : mState(std::move(other.mState))
    {
      other.mState = nullptr;
    }

    /// Releases any depth unit currently held, then takes ownership of @p other's, leaving it empty.
    ///
    /// @param other Scope to move from; left holding no depth unit afterwards.
    /// @return Reference to this scope.
    DepthScope& operator=(DepthScope&& other) noexcept;
    /// Releases the owned depth unit (decrements the shared live-depth counter), if any.
    ~DepthScope();

  private:
    std::shared_ptr<struct State> mState;
  };

  /// Deleted: a budget has no meaningful default; a bound must be supplied.
  StackDepth() = delete;

  /// Default recursion-depth cap (native-stack-overflow guard for hostile, deeply-nested wire input).
  ///
  /// One depth unit is NOT one native frame: the heaviest recursive decode path
  /// (Variant -> Array<Variant> -> Variant -> ...) charges this counter roughly every 3-4 native
  /// frames of ~1-2 KB each. The cap must hold the WHOLE descent within the SMALLEST stack any decode
  /// ever runs on - a 1 MB thread stack: that is Windows' default thread stack, and the deliberate
  /// `ulimit -s 1024` CI lane that exists to catch exactly this class of bug. 100 units bounds the
  /// descent to well under 1 MB with several-x margin, yet sits far above any legitimate OPC UA
  /// message nesting (a handful of levels) - it matches the reference stacks (open62541 caps near 100,
  /// UA-.NETStandard at 200), so it never trips on real data. A larger cap (the previous 1000) fits an
  /// 8 MB stack but OVERFLOWS a 1 MB one BEFORE the counter fires, turning this guard into a crash
  /// instead of a clean BadEncodingLimitsExceeded - the very pre-auth DoS this class exists to prevent
  /// (regression-covered by decode_recursion_dos_integration_tests + UaBinaryEncodingLimitsTests).
  ///
  /// The nodes+edges WORK budget is sized separately (much larger): it bounds total decode effort,
  /// which is orthogonal to the native-stack depth this guard protects.
  static constexpr size_t defaultMaxDepth = 100;

  /// Constructs a budget bounded to @p maxWork node units (edge bound derived as @c maxWork^2,
  /// saturating at @c SIZE_MAX) and @p maxDepth live recursion units.
  ///
  /// @param maxWork  Maximum cumulative node units (inclusive); the edge bound is @c maxWork^2.
  /// @param maxDepth Maximum LIVE structural recursion depth (inclusive) - bounds deep-narrow
  ///                 nesting against native stack overflow; decremented as the recursion unwinds.
  explicit StackDepth(size_t maxWork, size_t maxDepth = defaultMaxDepth)
    : mState(
        std::make_shared<State>(State{WorkBudget{maxWork, compute_default_max_edges(maxWork)}, 0, maxDepth}))
  {}

  /// Copies a reference to the shared budget; the copy charges against the same state.
  StackDepth(const StackDepth&) = default;

  /// Moves the reference to the shared budget.
  StackDepth(StackDepth&&) noexcept = default;

  /// Rebinds this handle to another shared budget; the copy charges against the same state.
  ///
  /// @return Reference to this budget handle.
  StackDepth& operator=(const StackDepth&) = default;

  /// Moves the reference to the shared budget.
  ///
  /// @return Reference to this budget handle.
  StackDepth& operator=(StackDepth&&) noexcept = default;

  /// Destroys this handle, releasing its reference to the shared budget.
  ~StackDepth() = default;

  /// Charges one node unit against the shared budget.
  ///
  /// @throws UaException with @ref Status::BadEncodingLimitsExceeded if charging this unit
  ///         would exceed the node bound.
  /// @post On return, one further node unit has been consumed from the shared budget.
  void consume_node()
  {
    mState->work.consume_node();
  }

  /// Charges one edge unit against the shared budget.
  ///
  /// @throws UaException with @ref Status::BadEncodingLimitsExceeded if charging this unit
  ///         would exceed the edge bound.
  /// @post On return, one further edge unit has been consumed from the shared budget.
  void consume_edge()
  {
    mState->work.consume_edge();
  }

  /// Enters one structural recursion level: charges the live depth counter and returns an RAII
  /// scope that releases it on destruction (so the counter tracks CURRENT nesting depth and
  /// unwinds as the recursion returns - bounding deep-narrow nesting without penalising width).
  ///
  /// Call this at the top of every recursive composite decode (Variant, ExtensionObject,
  /// DiagnosticInfo, DataValue, nested struct, ...); hold the returned scope for the decode's body.
  ///
  /// @return An RAII @ref DepthScope owning the charged depth unit; it releases the unit
  ///         (decrementing the live-depth counter) when destroyed as the recursion unwinds.
  /// @throws UaException with @ref Status::BadEncodingLimitsExceeded if this descent would exceed
  ///         the configured recursion-depth bound (native-stack-overflow DoS guard).
  [[nodiscard]] DepthScope enter_recursion()
  {
    if (++mState->depthUsed > mState->maxDepth)
    {
      throw UaException(Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("RecursionDepthExceeded", "Decode recursion depth exceeded", "StackDepth")
          .context(ua::ContextKeys::max, std::to_string(mState->maxDepth))
          .context(ua::ContextKeys::actual, std::to_string(mState->depthUsed)));
    }
    return DepthScope{mState};
  }

private:
  struct State
  {
    WorkBudget work;  ///< node/edge work budget (fan-out / total-cost guard), shared across copies
    size_t depthUsed;  ///< live structural recursion depth (inc on enter_recursion, dec on unwind)
    size_t maxDepth;  ///< recursion-depth cap (native-stack-overflow guard)
  };

  static size_t compute_default_max_edges(size_t maxNodes)
  {
    // Preserve existing call-site expectations where `StackDepth{N}` previously bounded recursion
    // depth only. With explicit nodes+edges accounting, a depth limit of N can legitimately
    // traverse far more than N edges. Default to N^2 edges (with overflow protection).
    if (maxNodes == 0)
    {
      return 0;
    }

    constexpr size_t max = std::numeric_limits<size_t>::max();
    if (maxNodes > max / maxNodes)
    {
      return max;
    }
    return maxNodes * maxNodes;
  }

  std::shared_ptr<State> mState;
};

inline StackDepth::DepthScope::~DepthScope()
{
  if (mState)
  {
    --mState->depthUsed;
  }
}

inline StackDepth::DepthScope& StackDepth::DepthScope::operator=(DepthScope&& other) noexcept
{
  if (this != &other)
  {
    if (mState)
    {
      --mState->depthUsed;
    }
    mState = std::move(other.mState);
    other.mState = nullptr;
  }
  return *this;
}

/// An iteration counter that bounds the number of passes through a loop.
///
/// Guards unbounded loops driven by untrusted input by capping total iterations. Choose the
/// throwing @ref consume_iteration or the non-throwing @ref try_increment depending on whether
/// the call site treats budget exhaustion as an error or as a normal stop condition.
///
/// Not thread-safe; confine an instance to a single loop on one thread.
/// @ingroup general
/// @see WorkBudget, StackDepth
class LoopLimit
{
public:
  /// Deleted: a limit has no meaningful default; a bound must be supplied.
  LoopLimit() = delete;

  /// Constructs a limit allowing at most @p maxDepth iterations.
  ///
  /// @param maxDepth Maximum number of iterations permitted (inclusive).
  explicit LoopLimit(size_t maxDepth) : mCurrentIteration(0), mMaxIterations(maxDepth)
  {}

  /// Charges one iteration against the limit.
  ///
  /// @throws UaException with @ref Status::BadEncodingLimitsExceeded if charging this iteration
  ///         would exceed the bound.
  /// @post On return, one further iteration has been consumed.
  /// @see try_increment
  void consume_iteration()
  {
    if (++mCurrentIteration > mMaxIterations)
    {
      throw UaException(Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("LoopBudgetExceeded", "Loop iteration budget exceeded", "LoopLimit")
          .context(ua::ContextKeys::max, std::to_string(mMaxIterations))
          .context(ua::ContextKeys::actual, std::to_string(mCurrentIteration)));
    }
  }

  /// Charges one iteration and reports whether the limit still holds, without throwing.
  ///
  /// @return @c true if the iteration was within the bound; @c false once the bound is
  ///         exceeded.
  /// @post On return, one further iteration has been consumed regardless of the result.
  /// @see consume_iteration
  bool try_increment()
  {
    return (++mCurrentIteration <= mMaxIterations);
  }

  /// Alias of @ref try_increment that charges one iteration and reports whether the limit holds.
  ///
  /// @return @c true if the iteration was within the bound; @c false once the bound is
  ///         exceeded.
  /// @post On return, one further iteration has been consumed regardless of the result.
  /// @see try_increment
  bool increment_and_test()
  {
    return try_increment();
  }

private:
  size_t mCurrentIteration;
  size_t mMaxIterations;
};

/// A per-call recursion-depth budget consumed monotonically as an async traversal descends.
///
/// Unlike @ref StackDepth::enter_recursion (a live RAII counter that unwinds with the native stack in
/// the synchronous codec), this token is a path-local progress counter for callback/continuation
/// flows where there is no native stack to unwind: it is passed by value down a call path and
/// decremented locally via consume(), so it bounds the CUMULATIVE logical descent of one branch.
/// Configured maxima live in @ref ExecutionLimits and seed the initial value at an entry point. Copies
/// are independent, so each branch of a traversal carries its own remaining count.
///
/// @ingroup general
/// @see StackDepth, LoopLimit, ExecutionLimits
struct DepthBudget
{
  size_t remaining{};  ///< Recursion levels still available before the budget is exhausted.

  /// Charges @p n levels against the remaining depth budget.
  ///
  /// Decrements @ref remaining by @p n on success.
  ///
  /// @param n Number of depth levels to consume; defaults to one.
  /// @throws UaException with @ref Status::BadEncodingLimitsExceeded (detail key
  ///         `DepthBudgetExceeded`) if @p n exceeds the remaining budget; @ref remaining is
  ///         left unchanged in that case.
  /// @post `remaining == old(remaining) - n` when no exception is thrown.
  void consume(size_t n = 1)
  {
    if (remaining < n)
    {
      throw UaException{Status::BadEncodingLimitsExceeded,
        ErrorDetail::build("DepthBudgetExceeded", "Depth budget exceeded", "DepthBudget")
          .context(ua::ContextKeys::actual, std::to_string(n))
          .context(ua::ContextKeys::limit, std::to_string(remaining))};
    }
    remaining -= n;
  }
};

}  // namespace ua

#endif  // UA_RESOURCE_BUDGETS_H
