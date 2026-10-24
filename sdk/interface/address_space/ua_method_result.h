// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The outcome of a Method call, and how a typed method handler reports it.
/// @ingroup address_space

#ifndef UA_METHOD_RESULT_H
#define UA_METHOD_RESULT_H

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_logger.h"
#include "ua_node.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_to_string.h"

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace ua
{

/// @cond METHOD_RESULT_DETAIL
namespace detail
{
struct MethodCallAccess;
}  // namespace detail

/// @endcond

/// What a typed method handler is told about the call it serves.
/// @ingroup address_space
class MethodCall
{
public:
  /// @param objectId The Object the Method was called on.
  /// @param methodId The Method.
  /// @param context  The calling session's context; null for a call with no session.
  MethodCall(NodeId objectId, NodeId methodId, shared_ptr<const MethodCallContext> context)
    : mObjectId(std::move(objectId)), mMethodId(std::move(methodId)), mContext(std::move(context))
  {}

  /// Returns the Object the Method was called on: for a Method declared on an ObjectType, the instance.
  /// @return The ObjectId of the call.
  const NodeId& object_id() const noexcept
  {
    return mObjectId;
  }

  /// Returns the Method.
  /// @return The MethodId of the call.
  const NodeId& method_id() const noexcept
  {
    return mMethodId;
  }

  /// Returns the calling session's context. A call with no session (one the server's own code makes,
  /// such as @ref MethodAccessor::try_call_sync) gets an empty context, whose `sessionId` is null; a
  /// handler that needs a session refuses such a call.
  /// @return The calling session's context.
  const MethodCallContext& context() const noexcept
  {
    static const MethodCallContext noSession{};
    if (mContext)
    {
      return *mContext;
    }
    return noSession;
  }

private:
  friend struct detail::MethodCallAccess;

  NodeId mObjectId;
  NodeId mMethodId;
  shared_ptr<const MethodCallContext> mContext;
};

/// @cond METHOD_RESULT_DETAIL
namespace detail
{

/// The calling session's context by shared ownership, null for a call with no session: for SDK code that
/// hands it to something that keeps it.
struct MethodCallAccess
{
  static const shared_ptr<const MethodCallContext>& shared_context(const MethodCall& call) noexcept
  {
    return call.mContext;
  }
};

}  // namespace detail

/// @endcond

/// The input arguments a method handler refuses, each with its status (OPC 10000-4 5.11.2.4, Table 68).
///
/// Made by @ref reject_argument; returned as a @ref MethodResult, which the client receives as
/// `Bad_InvalidArgument` with one status per input argument. Every rejected argument carries an
/// @ref ErrorDetail, either the handler's own, or one the SDK builds. The SDK adds the argument's index and
/// name and the Method and Object NodeIds to it, and never the argument's value, which can be a secret;
/// a handler adds the value itself when it is safe to show.
/// @ingroup address_space
class ArgumentRejection
{
public:
  /// One rejected argument.
  struct Rejected
  {
    /// The argument's index in the Method's input arguments.
    std::size_t index;
    /// Why it was rejected: a Bad status, such as `Bad_OutOfRange` or `Bad_TypeMismatch`, carrying the
    /// handler's @ref ErrorDetail if it gave one.
    StatusCode status;
  };

  /// Rejects another argument as well.
  /// @param index  The argument's index in the Method's input arguments.
  /// @param status Why: a Bad status.
  /// @return This rejection.
  ArgumentRejection& and_argument(std::size_t index, StatusCode status)
  {
    mRejected.push_back(Rejected{index, std::move(status)});
    return *this;
  }

  /// Rejects another argument as well, saying why in an @ref ErrorDetail.
  /// @param index  The argument's index in the Method's input arguments.
  /// @param status Why: a Bad status.
  /// @param detail The facts, built by the rules of error handling: a literal summary and context keys.
  /// @return This rejection.
  ArgumentRejection& and_argument(std::size_t index, StatusCode status, shared_ptr<const ErrorDetail> detail)
  {
    return and_argument(index, StatusCode{status.value(), std::move(detail)});
  }

  /// Returns the rejected arguments, in the order they were given.
  /// @return The rejected arguments.
  const std::vector<Rejected>& rejected() const noexcept
  {
    return mRejected;
  }

private:
  std::vector<Rejected> mRejected;
};

/// Rejects the input argument at @p index.
/// @param index  The argument's index in the Method's input arguments.
/// @param status Why: a Bad status, such as `Bad_OutOfRange`.
/// @return The rejection; add further arguments with @ref ArgumentRejection::and_argument.
/// @ingroup address_space
inline ArgumentRejection reject_argument(std::size_t index, StatusCode status)
{
  return ArgumentRejection{}.and_argument(index, std::move(status));
}

/// Rejects the input argument at @p index, saying why in an @ref ErrorDetail.
/// @param index  The argument's index in the Method's input arguments.
/// @param status Why: a Bad status, such as `Bad_OutOfRange`.
/// @param detail The facts: a literal summary and context keys, never free text.
/// @return The rejection; add further arguments with @ref ArgumentRejection::and_argument.
/// @ingroup address_space
inline ArgumentRejection reject_argument(
  std::size_t index, StatusCode status, shared_ptr<const ErrorDetail> detail)
{
  return ArgumentRejection{}.and_argument(index, std::move(status), std::move(detail));
}

/// @cond METHOD_RESULT_DETAIL
namespace detail
{

struct MethodResultAccess;
struct MethodResultCallbackFactory;

/// A Good status with a subcode, which OPC 10000-4 5.11.2.4 forbids as a Method's statusCode in the Call
/// service's response. For the Call service only: a @ref MethodResult and an in-process call keep such a
/// status as it was given.
inline bool is_good_with_subcode(const StatusCode& status) noexcept
{
  return status.is_good() && has_subcode(status);
}

/// The statusCode the Call service answers a client for a Method whose statusCode is the Good status with a
/// subcode @p given, which OPC 10000-4 5.11.2.4 forbids there: plain Good, carrying the ErrorDetail
/// `MethodStatusQualified` whose cause is @p given with its own detail. For the Call service only, which
/// also logs a warning naming the Method and the code.
inline StatusCode method_status_qualified(const StatusCode& given)
{
  return StatusCode{Status::Good,
    ErrorDetail::build("MethodStatusQualified",
      "A Method's statusCode cannot be Good with a subcode (OPC 10000-4 5.11.2.4); answered Good",
      "MethodService")
      .cause(given)};
}

/// The status a handler's own mistake is reported with: the client never sees a status the handler did
/// not mean, and the ErrorDetail says what the handler did.
inline StatusCode method_status_not_allowed(const StatusCode& given, std::string summary)
{
  return StatusCode{Status::BadInternalError,
    ErrorDetail::build("MethodStatusNotAllowed", std::move(summary), "MethodResult")
      .context(ContextKeys::actual, to_string(given))};
}

}  // namespace detail

/// @endcond

/// The outcome of a Method call (OPC 10000-4 5.11.2.2), as a typed method handler reports it.
///
/// | Made by | The result holds |
/// |---|---|
/// | the outputs (`return {a, b};`) | `Good`, the outputs |
/// | @ref with_status (an Uncertain status, outputs) | that status, the outputs |
/// | @ref with_status (a Good subcode, outputs) | that status, the outputs; a client receives `Good` |
/// | a `Result` holding the only output | its status, a Good subcode included, the output |
/// | a Bad `StatusCode`, or a failed `Result` / `VoidResult` | that status, its `ErrorDetail`, no outputs |
/// | a status that is not Bad, for a Method with no outputs | that status, a Good subcode included |
/// | @ref reject_argument | `Bad_InvalidArgument`, one status per input argument |
///
/// The result holds the status the handler gave, and an in-process call (@ref MethodAccessor::try_call_sync)
/// returns it as given. The Call service answers a client the result's status as the Method's statusCode,
/// with the outputs, and its `ErrorDetail` in the operation's diagnostics, with one exception: OPC 10000-4
/// 5.11.2.4 forbids a Good status with a subcode as a Method's statusCode, so the Call service answers one
/// plain `Good`, keeps the outputs, gives that status the `ErrorDetail` `MethodStatusQualified` whose cause
/// is the given code, and logs a warning naming the Method and the code. A handler's mistake is reported
/// as `Bad_InternalError` with an `ErrorDetail` saying what it did, never as a status it did not mean: a
/// Bad status given to @ref with_status, a successful `Result` or a status that is not Bad given where
/// outputs are due, or a rejection whose status is not Bad.
/// @tparam Out The output arguments' C++ types.
/// @ingroup address_space
template<typename... Out>
class MethodResult
{
  static constexpr bool sSingleStatusOutput =
    sizeof...(Out) == 1 && (std::is_same_v<std::remove_cvref_t<Out>, StatusCode> && ...);

public:
  /// Good, with every output. (For a Method whose only output is a `StatusCode`, use the
  /// `std::in_place` form: a lone `StatusCode` means a failure.)
  /// @param outputs The outputs.
  MethodResult(Out... outputs)  // NOLINT(google-explicit-constructor): a handler returns its outputs
    requires(!sSingleStatusOutput)
    : mStatus(Status::Good), mOutputs(std::in_place, std::move(outputs)...)
  {}

  /// Good, with every output.
  /// @param outputs The outputs.
  MethodResult(std::in_place_t, Out... outputs)
    : mStatus(Status::Good), mOutputs(std::in_place, std::move(outputs)...)
  {}

  /// A status with the outputs: an Uncertain status for a call that failed but whose outputs explain
  /// why, such as an application error code (OPC 10000-4 5.11.2.2). A plain `Good` is the same as
  /// returning the outputs. A Good status with a subcode is kept with the outputs; the Call service
  /// answers it to a client plain `Good` with the outputs and the `ErrorDetail` `MethodStatusQualified`,
  /// whose cause is the given code (OPC 10000-4 5.11.2.4). A Bad status is the handler's mistake: the
  /// result holds `Bad_InternalError`.
  /// @param status  The status.
  /// @param outputs The outputs.
  /// @return The result.
  static MethodResult with_status(StatusCode status, Out... outputs)
  {
    if (status.is_bad())
    {
      return MethodResult{detail::method_status_not_allowed(
        status, "with_status reports outputs; a Bad status is returned without outputs")};
    }
    MethodResult result{std::in_place, std::move(outputs)...};
    result.mStatus = std::move(status);
    return result;
  }

  /// A failure: the status, no outputs, and the `ErrorDetail` in the client's diagnostics.
  /// @param status A Bad status. For a Method with no outputs, a Good and an Uncertain status are also
  ///               accepted, since nothing is missing; a Good status with a subcode is kept, and the Call
  ///               service answers it to a client plain `Good` with the `ErrorDetail`
  ///               `MethodStatusQualified` (OPC 10000-4 5.11.2.4).
  /// @param detail The facts; when null, the status's own `ErrorDetail` is kept.
  MethodResult(
    StatusCode status, shared_ptr<const ErrorDetail> detail = {})  // NOLINT(google-explicit-constructor)
    : mStatus(std::move(status))
  {
    if (detail)
    {
      mStatus = StatusCode{mStatus.value(), std::move(detail)};
    }
    if (mStatus.is_bad())
    {
      return;
    }
    if constexpr (sizeof...(Out) == 0)
    {
      mOutputs.emplace();
    }
    else
    {
      mStatus = detail::method_status_not_allowed(
        mStatus, "A status that is not Bad needs the Method's outputs; return them, or use with_status");
    }
  }

  /// Passes a Result on. A result holding no value gives its status and `ErrorDetail`, without outputs. A
  /// `Result` of exactly the only output's type holding a value is that output with the result's status,
  /// as @ref with_status gives it: a Good subcode and an Uncertain status are kept, and the Call service
  /// answers a Good subcode to a client plain `Good` with the `ErrorDetail` `MethodStatusQualified` (OPC
  /// 10000-4 5.11.2.4). Any other `Result` holding a value carries none of the Method's outputs, so it is
  /// accepted only by a Method that has none, with its status as the
  /// @ref MethodResult(StatusCode, shared_ptr<const ErrorDetail>) constructor gives it.
  /// @tparam U The result's value type.
  /// @param result The result.
  template<typename U>
  MethodResult(const Result<U>& result)  // NOLINT(google-explicit-constructor): `return written;`
    : MethodResult(from_result(result))
  {}

  /// `Bad_InvalidArgument`, with one status per input argument.
  /// @param rejection The rejected arguments.
  MethodResult(
    ArgumentRejection rejection)  // NOLINT(google-explicit-constructor): `return reject_argument(...);`
    : mStatus(Status::BadInvalidArgument)
  {
    if (rejection.rejected().empty())
    {
      mStatus = StatusCode{Status::BadInternalError,
        ErrorDetail::build(
          "ArgumentRejectionEmpty", "An argument rejection names no input argument", "MethodResult")};
      return;
    }
    for (const auto& rejected : rejection.rejected())
    {
      if (!rejected.status.is_bad())
      {
        mStatus =
          detail::method_status_not_allowed(rejected.status, "A rejected input argument needs a Bad status");
        mArgumentResults.clear();
        return;
      }
      if (rejected.index < mArgumentResults.size() && mArgumentResults[rejected.index].is_bad())
      {
        mStatus = StatusCode{Status::BadInternalError,
          ErrorDetail::build("ArgumentRejectedTwice", "An input argument was rejected twice", "MethodResult")
            .context(ContextKeys::operationIndex, rejected.index)};
        mArgumentResults.clear();
        return;
      }
      if (rejected.index >= mArgumentResults.size())
      {
        mArgumentResults.resize(rejected.index + 1, StatusCode{Status::Good});
      }
      mArgumentResults[rejected.index] = rejected.status;
    }
  }

  /// Returns the result's status: for a handler's result, the status the handler gave, a Good subcode
  /// included, or the `Bad_InternalError` its mistake is reported with; for an in-process call's result
  /// (@ref MethodAccessor::try_call_sync), the status the call answered. The Call service answers a
  /// handler's status to a client as the Method's statusCode, a Good subcode as plain `Good` (see the
  /// class description).
  /// @return The status, carrying its `ErrorDetail` if it has one.
  const StatusCode& status_code() const noexcept
  {
    return mStatus;
  }

  /// Returns whether the result carries outputs: true for a successful call, and for an Uncertain one
  /// made with @ref with_status.
  /// @return Whether @ref outputs may be read.
  bool has_outputs() const noexcept
  {
    return mOutputs.has_value();
  }

  /// Returns the outputs.
  /// @return The outputs, in order.
  /// @throws UaException with the result's own status and `ErrorDetail` when there are none, as
  ///         `Result<T>::value()` does.
  const std::tuple<Out...>& outputs() const
  {
    if (!mOutputs)
    {
      if (auto detail = mStatus.shared_detail())
      {
        throw UaException{mStatus.as_status(), std::move(detail)};
      }
      throw UaException{mStatus.as_status(),
        ErrorDetail::build(
          "MethodResultWithoutOutputs", "The Method call returned no outputs", "MethodResult")
          .cause(mStatus)};
    }
    return *mOutputs;
  }

  /// Returns the only output.
  /// @return The output.
  /// @throws UaException as @ref outputs does.
  const auto& value() const
    requires(sizeof...(Out) == 1)
  {
    return std::get<0>(outputs());
  }

  /// Returns the status of each input argument: empty unless the call was rejected with
  /// `Bad_InvalidArgument`. Each status carries its argument's `ErrorDetail`. A rejection made by a
  /// handler runs to the highest rejected index; a result read from a call has one per input argument.
  /// @return The statuses, by argument index.
  const std::vector<StatusCode>& argument_results() const noexcept
  {
    return mArgumentResults;
  }

private:
  friend struct detail::MethodResultAccess;

  template<typename U>
  static MethodResult from_result(const Result<U>& result)
  {
    if constexpr (!std::is_void_v<U> && sizeof...(Out) == 1)
    {
      if constexpr ((std::is_same_v<std::remove_cvref_t<U>, Out> && ...))
      {
        if (result.has_value())
        {
          return with_status(result.status_code(), result.value());
        }
      }
    }
    return MethodResult{result.status_code(), result.shared_detail()};
  }

  struct FromParts
  {};

  explicit MethodResult(FromParts) : mStatus(Status::Good)
  {}

  StatusCode mStatus;
  std::optional<std::tuple<Out...>> mOutputs;
  std::vector<StatusCode> mArgumentResults;
};

/// The completion of an asynchronous method handler: call it once, from any thread, with the result.
///
/// Copies share one completion. The first call completes the Method; a second is ignored and logged as
/// an error. If every copy is destroyed uncalled, the SDK completes the call with `Bad_InternalError`
/// and an `ErrorDetail` naming the Method, so the client never waits for a time-out.
/// @tparam Out The output arguments' C++ types.
/// @ingroup address_space
template<typename... Out>
class MethodResultCallback
{
public:
  /// Completes the Method with @p result.
  /// @param result The result; the outputs convert to it, as do a failure and a rejection.
  void operator()(MethodResult<Out...> result) const
  {
    if (mState)
    {
      mState->complete(std::move(result));
    }
  }

private:
  friend struct detail::MethodResultCallbackFactory;

  struct State
  {
    std::function<void(MethodResult<Out...>)> deliver;
    Logger logger;
    NodeId methodId;
    std::atomic<bool> completed{false};

    State(std::function<void(MethodResult<Out...>)> deliverResult, Logger log, NodeId method)
      : deliver(std::move(deliverResult)), logger(std::move(log)), methodId(std::move(method))
    {}

    State(const State&) = delete;
    State& operator=(const State&) = delete;
    State(State&&) = delete;
    State& operator=(State&&) = delete;

    void complete(MethodResult<Out...> result)
    {
      if (completed.exchange(true, std::memory_order_acq_rel))
      {
        logger.error("A method handler completed Method {} a second time; the second result is ignored",
          to_string(methodId));
        return;
      }
      deliver(std::move(result));
    }

    ~State()
    {
      if (completed.load(std::memory_order_acquire))
      {
        return;
      }
      try
      {
        deliver(MethodResult<Out...>{StatusCode{Status::BadInternalError,
          ErrorDetail::build("MethodCompletionDropped",
            "The method handler released its completion without calling it",
            "MethodAdapter")
            .context(ContextKeys::methodId, to_string(methodId))}});
      }
      catch (...)
      {
        logger.error(
          "Method {} could not be completed after its handler released the completion", to_string(methodId));
      }
    }
  };

  explicit MethodResultCallback(std::shared_ptr<State> state) : mState(std::move(state))
  {}

  std::shared_ptr<State> mState;
};

/// @cond METHOD_RESULT_DETAIL
namespace detail
{

/// Makes the completion an asynchronous handler receives (the SDK's adapter is its only maker).
struct MethodResultCallbackFactory
{
  template<typename... Out>
  static MethodResultCallback<Out...> make(
    std::type_identity_t<std::function<void(MethodResult<Out...>)>> deliver, Logger logger, NodeId methodId)
  {
    using State = typename MethodResultCallback<Out...>::State;
    return MethodResultCallback<Out...>{
      std::make_shared<State>(std::move(deliver), std::move(logger), std::move(methodId))};
  }
};

/// Builds a MethodResult from a call's wire outcome (the typed local call).
struct MethodResultAccess
{
  template<typename... Out>
  static MethodResult<Out...> make(StatusCode status,
    std::type_identity_t<std::optional<std::tuple<Out...>>> outputs, std::vector<StatusCode> argumentResults)
  {
    MethodResult<Out...> result{typename MethodResult<Out...>::FromParts{}};
    result.mStatus = std::move(status);
    result.mOutputs = std::move(outputs);
    result.mArgumentResults = std::move(argumentResults);
    return result;
  }
};

/// A generated binding's handler reports its outputs as one struct; the adapter encodes them one by one.
/// Keeps the status, the ErrorDetail and the argument results.
template<typename... Out, typename Struct, typename ToTuple>
MethodResult<Out...> method_result_from_struct(MethodResult<Struct> result, const ToTuple& toTuple)
{
  std::optional<std::tuple<Out...>> outputArguments;
  if (result.has_outputs())
  {
    outputArguments.emplace(toTuple(std::get<0>(result.outputs())));
  }
  return MethodResultAccess::make<Out...>(
    result.status_code(), std::move(outputArguments), result.argument_results());
}

/// The completion a generated binding's asynchronous handler receives: its struct result reaches @p done
/// one output at a time, under the same once-only rule (a dropped or doubled completion is caught here).
template<typename Struct, typename... Out, typename ToTuple>
MethodResultCallback<Struct> struct_method_result_callback(
  MethodResultCallback<Out...> done, ToTuple toTuple, Logger logger, NodeId methodId)
{
  return MethodResultCallbackFactory::make<Struct>(
    [done = std::move(done), toTuple = std::move(toTuple)](MethodResult<Struct> result)
    { done(method_result_from_struct<Out...>(std::move(result), toTuple)); },
    std::move(logger),
    std::move(methodId));
}

template<typename Handler, typename InputTuple, typename OutputTuple>
struct MethodHandlerForm
{
  static constexpr bool isSync = false;
  static constexpr bool isAsync = false;
};

template<typename Handler, typename... In, typename... Out>
struct MethodHandlerForm<Handler, std::tuple<In...>, std::tuple<Out...>>
{
  static constexpr bool isSync =
    std::is_invocable_r_v<MethodResult<Out...>, Handler&, const MethodCall&, const In&...>;
  static constexpr bool isAsync =
    std::is_invocable_r_v<void, Handler&, const MethodCall&, const In&..., MethodResultCallback<Out...>>;
};

}  // namespace detail

/// @endcond

/// A synchronous method handler: `(const MethodCall&, const In&...) -> MethodResult<Out...>`, for work
/// that waits for nothing.
/// @tparam Handler     The handler's type.
/// @tparam InputTuple  `std::tuple<In...>`.
/// @tparam OutputTuple `std::tuple<Out...>`.
/// @ingroup address_space
template<typename Handler, typename InputTuple, typename OutputTuple>
concept SyncMethodHandler = detail::MethodHandlerForm<Handler, InputTuple, OutputTuple>::isSync;

/// An asynchronous method handler: `(const MethodCall&, const In&..., MethodResultCallback<Out...>)`,
/// which starts the work and hands the result over later through the callback.
/// @tparam Handler     The handler's type.
/// @tparam InputTuple  `std::tuple<In...>`.
/// @tparam OutputTuple `std::tuple<Out...>`.
/// @ingroup address_space
template<typename Handler, typename InputTuple, typename OutputTuple>
concept AsyncMethodHandler = detail::MethodHandlerForm<Handler, InputTuple, OutputTuple>::isAsync;

}  // namespace ua

#endif  // UA_METHOD_RESULT_H
