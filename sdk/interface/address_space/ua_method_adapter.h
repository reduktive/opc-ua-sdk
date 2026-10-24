// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_METHOD_ADAPTER_H
#define UA_METHOD_ADAPTER_H

/// @file
/// @brief Adapter that decodes Call-service arguments into a typed method handler.
/// @ingroup address_space

#include "ua_built_in_types_fwd_decl.h"
#include "ua_node.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_error_detail.h"
#include "ua_callback_safety.h"
#include "ua_to_result.h"
#include "ua_variant.h"
#include "ua_built_in_type_id.h"
#include "ua_to_string.h"
#include "ua_diagnostic_info.h"
#include "ua_data_type_of.h"
#include "ua_logger.h"
#include "ua_method_arguments.h"
#include "ua_method_result.h"
#include "ua_ref_structure.h"
#include "ua_utilities.h"

#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace ua
{

struct MethodCallContext;

namespace detail
{

/// True for `std::optional<U>`. A `std::optional<U>` tuple element marks an *optional*
/// trailing input argument (OPC 10000-4 5.11.2.2): the client may omit it, in which
/// case the handler receives std::nullopt.
template<typename T>
// Mirrors the std:: type-trait convention (snake_case + `_v`), so it reads like the standard
// traits it sits alongside; deliberately exempt from the CamelCase class rule.
// NOLINTNEXTLINE(readability-identifier-naming)
struct is_optional_method_arg : std::false_type
{};

template<typename U>
// NOLINTNEXTLINE(readability-identifier-naming) -- see the is_optional_method_arg primary template
struct is_optional_method_arg<std::optional<U>> : std::true_type
{};

/// Convenience value alias for the @ref is_optional_method_arg trait's `value` member.
template<typename T>
// NOLINTNEXTLINE(readability-identifier-naming) -- mirrors the std:: `_v` trait-alias convention
inline constexpr bool is_optional_method_arg_v = is_optional_method_arg<T>::value;

/// True for `Array<U>` tuple elements (an array-valued input argument). Used to render the
/// expected type name for a decode-failure diagnostic, since `Array<U>` classifies through its
/// element type rather than through @ref built_in_type directly.
template<typename T>
// NOLINTNEXTLINE(readability-identifier-naming) -- mirrors the std:: type-trait convention
struct is_array_method_arg : std::false_type
{};

template<typename U>
// NOLINTNEXTLINE(readability-identifier-naming) -- see the is_array_method_arg primary template
struct is_array_method_arg<Array<U>> : std::true_type
{};

/// Convenience value alias for the @ref is_array_method_arg trait's `value` member.
template<typename T>
// NOLINTNEXTLINE(readability-identifier-naming) -- mirrors the std:: `_v` trait-alias convention
inline constexpr bool is_array_method_arg_v = is_array_method_arg<T>::value;

/// Extracts the element type of an `Array<U>` tuple element. Only instantiated for array
/// elements (guarded by @ref is_array_method_arg_v), so the primary template carries no member.
template<typename T>
// NOLINTNEXTLINE(readability-identifier-naming) -- mirrors the std:: type-trait convention
struct method_arg_array_element
{};

/// Specialization for an `Array<U>` element: `type` names the array's element type.
template<typename U>
// NOLINTNEXTLINE(readability-identifier-naming) -- see the method_arg_array_element primary template
struct method_arg_array_element<Array<U>>
{
  using type = U;  ///< The array's element type.
};

/// Renders the OPC UA built-in type name expected for a method-argument slot of C++ type @p T,
/// for a decode-failure diagnostic. A `std::optional<U>` unwraps to its inner type; an `Array<U>`
/// renders as `"Array<U>"`; every other type maps through @ref built_in_type to its symbolic
/// @ref BuiltInTypeId name (e.g. `"Int32"`). This is the OPC UA built-in-type symbol, not the C++
/// type name -- structured/extension-object types therefore render as `"ExtensionObject"`.
///
/// @return The symbolic OPC UA built-in type name expected for an argument slot of type @p T.
template<typename T>
std::string method_arg_expected_type_name()
{
  if constexpr (is_optional_method_arg_v<T>)
  {
    return method_arg_expected_type_name<typename T::value_type>();
  }
  else if constexpr (is_array_method_arg_v<T>)
  {
    return "Array<" + method_arg_expected_type_name<typename method_arg_array_element<T>::type>() + ">";
  }
  else
  {
    return to_string(built_in_type<T>());
  }
}

/// Renders the OPC UA built-in type name actually presented in @p value, for a decode-failure
/// diagnostic. An empty Variant renders as `"Null"`; otherwise the contained built-in type's
/// symbolic name. Never throws: the empty case is handled explicitly rather than letting
/// @ref Variant::get_built_in_type throw on an empty Variant.
///
/// @param value Variant whose contained built-in type name is rendered.
/// @return The symbolic OPC UA built-in type name presented in @p value, or `"Null"` when empty.
inline std::string method_arg_actual_type_name(const Variant& value)
{
  if (value.empty())
  {
    return to_string(BuiltInTypeId::Null);
  }
  return to_string(value.get_built_in_type());
}

/// Trailing-only invariant (OPC 10000-3 5.7.3: optional input arguments shall always
/// follow any non-optional ones). True iff no required (non-optional) element follows an
/// optional one in the tuple. Empty tuples and all-required tuples are trivially valid.
///
/// Equivalent to: there is no pair of indices (i, j) with i < j where element i is optional
/// and element j is required.
///
/// @return `true` iff no required (non-optional) element follows an optional one in @p InputArgs.
template<typename InputArgs>
constexpr bool method_args_trailing_only()
{
  constexpr std::size_t size = std::tuple_size_v<InputArgs>;
  if constexpr (size == 0)
  {
    return true;
  }
  else
  {
    // Build a per-element "is optional" flag array, then verify that once an optional element
    // is seen no later element is required.
    constexpr std::array<bool, size> optionalFlags = []<std::size_t... I>(std::index_sequence<I...>)
    {
      return std::array<bool, size>{is_optional_method_arg_v<std::tuple_element_t<I, InputArgs>>...};
    }(std::make_index_sequence<size>{});

    bool seenOptional = false;
    for (const bool elementIsOptional : optionalFlags)
    {
      if (elementIsOptional)
      {
        seenOptional = true;
      }
      else if (seenOptional)
      {
        return false;  // a required element follows an optional one
      }
    }
    return true;
  }
}

/// Convenience value alias for @ref method_args_trailing_only<InputArgs>(); true iff no required
/// element follows an optional one.
template<typename InputArgs>
inline constexpr bool method_args_trailing_only_v = method_args_trailing_only<InputArgs>();

/// Number of *required* (leading non-optional) input arguments. Optional trailing
/// arguments (`std::optional<U>` elements) are excluded. The trailing-only invariant is
/// enforced here at compile time.
///
/// @return The number of required (leading non-optional) input arguments in @p InputArgs.
template<typename InputArgs>
constexpr std::size_t method_required_arg_count()
{
  static_assert(method_args_trailing_only_v<InputArgs>,
    "MethodAdapter input arguments violate the trailing-only invariant: an optional "
    "(std::optional<T>) input argument must not be followed by a required one "
    "(OPC 10000-3 5.7.3).");

  return []<std::size_t... I>(std::index_sequence<I...>)
  {
    return (std::size_t{0} + ... +
            (is_optional_method_arg_v<std::tuple_element_t<I, InputArgs>> ? std::size_t{0} : std::size_t{1}));
  }(std::make_index_sequence<std::tuple_size_v<InputArgs>>{});
}

}  // namespace detail

/// Decodes a Call service request into a strongly-typed method handler.
///
/// Wraps a handler that receives method input arguments as a typed @p InputArgs
/// tuple instead of a raw `Variant` list. When invoked as a node's method
/// callable, the adapter validates arity, decodes each `Variant` into the
/// corresponding tuple element, and forwards the result to the wrapped handler;
/// decode and arity failures are reported to the completion callback without
/// reaching the handler.
///
/// @p InputArgs is a `std::tuple` whose elements name the expected argument
/// types in order. A trailing `std::optional<U>` element marks an *optional*
/// trailing input argument (OPC 10000-4 5.11.2.2) that the client may omit, in
/// which case the handler receives `std::nullopt`. Optional arguments must
/// follow all required ones (OPC 10000-3 5.7.3); this trailing-only invariant
/// is checked at compile time.
///
/// @tparam InputArgs  `std::tuple` of expected input-argument types, in
///                    declaration order, with optional trailing elements modelled
///                    as `std::optional<U>`.
/// @tparam OutputArgs `void` for this form, whose handler encodes its own outputs; the
///                    `std::tuple<In...>, std::tuple<Out...>` specialisation below takes a handler of
///                    either typed form and encodes the outputs itself.
/// @ingroup address_space
template<typename InputArgs, typename OutputArgs = void>
class MethodAdapter
{
public:
  /// Typed method handler invoked once the input arguments are decoded.
  ///
  /// Receives the calling object's NodeId, the decoded @p InputArgs tuple, the
  /// (nullable) per-call @ref MethodCallContext, a pre-sized @ref CallMethodResult
  /// to populate, and the completion callback. The handler must signal completion
  /// exactly once by invoking the callback with the populated result; throwing
  /// instead converts the active exception to a status code and completes the
  /// call. The context is held by shared ownership so a handler that completes
  /// asynchronously may retain it past the synchronous portion of the call.
  using Handler = std::function<void(const NodeId& objectId, const InputArgs&,
    shared_ptr<const MethodCallContext>, CallMethodResult, CallMethodCompleteCallback)>;

  /// Constructs an adapter that forwards decoded calls to @p handler.
  ///
  /// @param handler Typed handler invoked on a successful argument decode. Moved
  ///                into the adapter and retained for the adapter's lifetime.
  explicit MethodAdapter(Handler handler);

  /// Decodes @p callMethodRequest and invokes the wrapped handler.
  ///
  /// Validates argument arity against @p InputArgs, decodes each input
  /// `Variant` into the matching tuple element, then forwards the call to the
  /// handler. The outcome is delivered to @p callback exactly once. Too few
  /// arguments complete with `BadArgumentsMissing`, too many with
  /// `BadTooManyArguments`, and a per-argument decode failure with
  /// `BadInvalidArgument` and the offending slot marked `BadTypeMismatch`; in
  /// each case an @ref ErrorDetail is attached and the handler is not called.
  /// This operator never throws - a handler that throws is caught and its
  /// exception converted to a status code on @p callback.
  ///
  /// @param callMethodRequest Request carrying the object NodeId and input
  ///                          argument `Variant` list.
  /// @param context           Per-call session context, or null when no session
  ///                          context is available. Held by shared ownership for
  ///                          the (possibly asynchronous) duration of the call.
  /// @param callback          Receives the @ref CallResult outcome exactly once.
  /// @pre @p callback is non-empty and a handler was supplied at construction;
  ///      otherwise the call fails with `BadInvalidArgument` / `BadInvalidState`.
  void operator()(const CallMethodRequest& callMethodRequest, shared_ptr<const MethodCallContext> context,
    CallMethodCompleteCallback callback) const;

private:
  Handler mHandler;
};

template<typename InputArgs, typename OutputArgs>
MethodAdapter<InputArgs, OutputArgs>::MethodAdapter(Handler handler) : mHandler(std::move(handler))
{}

template<typename InputArgs, typename OutputArgs>
void MethodAdapter<InputArgs, OutputArgs>::operator()(const CallMethodRequest& callMethodRequest,
  shared_ptr<const MethodCallContext> context, CallMethodCompleteCallback callback) const
{
  check_true(static_cast<bool>(callback), Status::BadInvalidArgument);
  check(mHandler, Status::BadInvalidState);

  // required_arg_count == tuple_size for all-required tuples, so the guards below behave
  // exactly as a strict exact-arity check unless the handler opts into optional trailing
  // arguments via std::optional<U> tuple elements.
  constexpr size_t requiredArgCount = detail::method_required_arg_count<InputArgs>();

  auto& inputArgs = callMethodRequest.input_arguments();
  if (inputArgs.size() < requiredArgCount)
  {
    callback(CallResult{StatusCode{Status::BadArgumentsMissing},
      ErrorDetail::build(
        "InvalidMethodArguments", "Too few arguments supplied to method call.", "MethodAdapter")
        .context(ua::ContextKeys::sizeMin, std::to_string(requiredArgCount))
        .context(ua::ContextKeys::sizeActual, std::to_string(inputArgs.size()))});
    return;
  }
  else if (inputArgs.size() > std::tuple_size_v<InputArgs>)
  {
    callback(CallResult{StatusCode{Status::BadTooManyArguments},
      ErrorDetail::build(
        "InvalidMethodArguments", "Too many arguments supplied to method call.", "MethodAdapter")
        .context(ua::ContextKeys::sizeMax, std::to_string(std::tuple_size_v<InputArgs>))
        .context(ua::ContextKeys::sizeActual, std::to_string(inputArgs.size()))});
    return;
  }

  CallMethodResult result;
  result.input_argument_results().resize(std::tuple_size_v<InputArgs>);

  // Decode every argument independently. A type mismatch on one argument must not hide the others:
  // Part 4 5.11.2 requires a per-argument result, so each failing argument records its own
  // Bad_TypeMismatch (not just the first one encountered). Optional trailing arguments
  // (std::optional<U> tuple elements) are left as std::nullopt when not supplied.
  InputArgs input;
  size_t index{0};
  bool anyArgumentInvalid{false};
  auto copier = [&inputArgs, &index, &result, &anyArgumentInvalid]<typename T>(T& arg)
  {
    try
    {
      if constexpr (detail::is_optional_method_arg_v<T>)
      {
        // Optional trailing argument: decode if supplied, otherwise leave std::nullopt.
        using Inner = typename T::value_type;
        if (index < inputArgs.size())
        {
          arg = inputArgs[index].template as<Inner>();
        }
      }
      else
      {
        arg = std::move(inputArgs[index].as<T>());
      }
    }
    catch (const UaException& decodeError)
    {
      result.input_argument_results().payload().at(index) = Status::BadTypeMismatch;

      // ErrorDetail propagation: record WHY the slot failed (expected vs actual type + the
      // failing slot index), not merely THAT it failed. DiagnosticInfo has no ErrorDetail field
      // of its own, so the detail rides on its inner_status_code() StatusCode (which carries it
      // losslessly via shared_detail()); the Variant's own decode cause is chained beneath it.
      // The per-argument diagnostics vector is resized lazily on the first failure to match the
      // input_argument_results() length, leaving successfully-decoded slots as null DiagnosticInfo.
      auto& diagnostics = result.input_argument_diagnostic_infos().payload();
      if (diagnostics.size() < std::tuple_size_v<InputArgs>)
      {
        diagnostics.resize(std::tuple_size_v<InputArgs>);
      }

      const std::string expectedTypeName = detail::method_arg_expected_type_name<T>();
      const std::string actualTypeName = (index < inputArgs.size())
                                           ? detail::method_arg_actual_type_name(inputArgs[index])
                                           : to_string(BuiltInTypeId::Null);

      DiagnosticInfo diagnostic;
      diagnostic.inner_status_code() = StatusCode{Status::BadTypeMismatch,
        ErrorDetail::build(
          "ArgumentTypeMismatch", "Method input argument does not match the expected type.", "MethodAdapter")
          .context(ua::ContextKeys::typeExpected, expectedTypeName)
          .context(ua::ContextKeys::typeActual, actualTypeName)
          .context(ua::ContextKeys::operationIndex, std::to_string(index))
          .cause(decodeError.take_detail())};
      diagnostics.at(index) = std::move(diagnostic);

      anyArgumentInvalid = true;
    }
    ++index;
  };

  std::apply([&copier](auto&... x) { (..., copier(x)); }, input);

  if (anyArgumentInvalid)
  {
    result.status_code() = Status::BadInvalidArgument;
    callback(CallResult{std::move(result)});
    return;
  }

  // Race-resolution: user handler may invoke the callback OR throw; if it
  // throws after invoking, the catch must not double-fire. make_fire_once
  // wraps the callback in a CAS guard shared by both paths.
  auto guarded = detail::make_fire_once<CallResult>(std::move(callback));
  try
  {
    mHandler(callMethodRequest.object_id(), input, std::move(context), std::move(result), guarded);
  }
  catch (...)
  {
    guarded(ua::exception_to_status_code(std::current_exception()));
  }
}

/// @cond METHOD_ADAPTER_DETAIL
namespace detail
{

/// The Bad_TypeMismatch a decode of a method argument throws.
[[noreturn]] inline void throw_method_value_mismatch()
{
  throw UaException{Status::BadTypeMismatch,
    ErrorDetail::build(
      "MethodValueTypeMismatch", "The value does not hold the argument's type.", "MethodAdapter")};
}

/// Decodes one scalar of C++ type @p T from @p value; throws Bad_TypeMismatch on a mismatch.
template<typename T>
T method_scalar_from(const Variant& value)
{
  if constexpr (std::is_same_v<T, Variant>)
  {
    return value;
  }
  else if constexpr (std::is_same_v<T, std::string>)
  {
    return std::string{value.as<String>()};
  }
  else if constexpr (std::is_enum_v<T>)
  {
    // OPC 10000-6 5.2.4: an enumeration travels as its Int32 value.
    return utils::from_underlying<T>(static_cast<std::underlying_type_t<T>>(value.as<int32_t>()));
  }
  else if constexpr (std::derived_from<T, Structure>)
  {
    if (const T* structure = value.try_as<T>())
    {
      return *structure;
    }
    throw_method_value_mismatch();
  }
  else
  {
    return value.as<T>();
  }
}

/// Decodes the elements of a one-dimensional array of C++ element type @p E from @p value.
template<typename E>
std::vector<E> method_elements_from(const Variant& value)
{
  if constexpr (std::is_same_v<E, std::string>)
  {
    std::vector<E> elements;
    for (const auto& element : value.as<Array<String>>().payload())
    {
      elements.emplace_back(element);
    }
    return elements;
  }
  else if constexpr (std::is_enum_v<E>)
  {
    std::vector<E> elements;
    for (const int32_t element : value.as<Array<int32_t>>().payload())
    {
      elements.push_back(utils::from_underlying<E>(static_cast<std::underlying_type_t<E>>(element)));
    }
    return elements;
  }
  else if constexpr (std::derived_from<E, Structure>)
  {
    std::vector<E> elements;
    for (const auto& element : value.as<Array<RefStructure<Structure>>>().payload())
    {
      const auto* structure = dynamic_cast<const E*>(element.get());
      if (structure == nullptr)
      {
        throw_method_value_mismatch();
      }
      elements.push_back(*structure);
    }
    return elements;
  }
  else
  {
    return value.as<Array<E>>().payload();
  }
}

/// Decodes a method argument of C++ type @p T (a mapped scalar, `ua::Array<E>` or `std::vector<E>`).
template<typename T>
T method_value_from(const Variant& value)
{
  if constexpr (DataTypeArray<T>::isArray)
  {
    auto elements = method_elements_from<typename DataTypeArray<T>::Element>(value);
    if constexpr (std::is_same_v<T, std::vector<typename DataTypeArray<T>::Element>>)
    {
      return elements;
    }
    else
    {
      T array;
      array = elements;
      return array;
    }
  }
  else
  {
    return method_scalar_from<T>(value);
  }
}

/// Encodes a one-dimensional array of C++ element type @p E.
template<typename E>
Variant method_elements_to(const std::vector<E>& elements)
{
  if constexpr (std::is_same_v<E, std::string>)
  {
    Array<String> array;
    for (const auto& element : elements)
    {
      array.payload().emplace_back(element);
    }
    return Variant{std::move(array)};
  }
  else if constexpr (std::is_enum_v<E>)
  {
    Array<int32_t> array;
    for (const E element : elements)
    {
      array.payload().push_back(utils::as_int32(element));
    }
    return Variant{std::move(array)};
  }
  else if constexpr (std::derived_from<E, Structure>)
  {
    Array<RefStructure<Structure>> array;
    for (const auto& element : elements)
    {
      const unique_ptr<Structure> copy = std::make_unique<E>(element);
      array.payload().emplace_back(copy);
    }
    return Variant{std::move(array)};
  }
  else
  {
    Array<E> array;
    array = elements;
    return Variant{std::move(array)};
  }
}

/// Encodes a method output of C++ type @p T.
template<typename T>
Variant method_value_to(const T& value)
{
  if constexpr (std::is_same_v<T, Variant>)
  {
    return value;
  }
  else if constexpr (DataTypeArray<T>::isArray)
  {
    if constexpr (std::is_same_v<T, std::vector<typename DataTypeArray<T>::Element>>)
    {
      return method_elements_to(value);
    }
    else
    {
      return method_elements_to(value.payload());
    }
  }
  else if constexpr (std::is_same_v<T, std::string>)
  {
    return Variant{String{value}};
  }
  else if constexpr (std::is_enum_v<T>)
  {
    const int32_t encoded = utils::as_int32(value);
    return Variant{encoded};
  }
  else
  {
    return Variant{value};
  }
}

/// The type name a decode diagnostic expects for an argument of C++ type @p T.
template<typename T>
std::string method_value_type_name()
{
  if constexpr (DataTypeOptional<T>::isOptional)
  {
    return method_value_type_name<typename DataTypeOptional<T>::Inner>();
  }
  else if constexpr (DataTypeArray<T>::isArray)
  {
    return "Array<" + method_value_type_name<typename DataTypeArray<T>::Element>() + ">";
  }
  else if constexpr (std::is_same_v<T, Variant>)
  {
    return "BaseDataType";
  }
  else if constexpr (GeneratedDataType<T>)
  {
    return std::string{T::typeName};
  }
  else
  {
    return to_string(built_in_type<T>());
  }
}

/// Adds @p key unless the detail already has it: a layer never discards a lower layer's context.
inline void add_context_if_absent(ErrorDetail& detail, const ContextKey& key, std::string value)
{
  for (const auto& entry : detail.context)
  {
    if (entry.key == key.value())
    {
      return;
    }
  }
  detail.context.push_back(NamedValue{std::string{key.value()}, std::move(value)});
}

/// The ErrorDetail of one rejected input argument: the handler's own, or a minimal one, with the facts
/// the SDK knows. Never the argument's value (it can be a secret).
inline shared_ptr<const ErrorDetail> rejected_argument_detail(const StatusCode& rejected, std::size_t index,
  const std::string& name, const NodeId& methodId, const NodeId& objectId)
{
  ErrorDetail detail;
  if (const auto& given = rejected.shared_detail())
  {
    detail = *given;
  }
  else
  {
    detail = *std::shared_ptr<const ErrorDetail>{ErrorDetail::build(
      "MethodArgumentRejected", "The method handler rejected an input argument.", "MethodAdapter")
                                                   .cause(StatusCode{rejected.value()})};
  }
  add_context_if_absent(detail, ContextKeys::operationIndex, std::to_string(index));
  if (!name.empty())
  {
    add_context_if_absent(detail, ContextKeys::argumentName, name);
  }
  add_context_if_absent(detail, ContextKeys::methodId, to_string(methodId));
  add_context_if_absent(detail, ContextKeys::objectId, to_string(objectId));
  return std::make_shared<const ErrorDetail>(std::move(detail));
}

}  // namespace detail

/// @endcond

/// Decodes a Call service request into a typed method handler of either form, and encodes its result.
///
/// The handler is synchronous, `(const MethodCall&, const In&...) -> MethodResult<Out...>`, for work
/// that waits for nothing, or asynchronous, `(const MethodCall&, const In&...,
/// MethodResultCallback<Out...>)`, for work that must ask the address space or another component; the form is
/// chosen at compile time from the handler's parameters, and a handler of both forms (a generic lambda) or
/// neither does not compile. The adapter checks the argument count, decodes every input (a mismatch is
/// `Bad_InvalidArgument` with `Bad_TypeMismatch` for that argument, and the handler is not called),
/// calls the handler, and turns its @ref MethodResult into the Call's result:
///
/// | The handler returns, or passes to `done` | The client receives |
/// |---|---|
/// | the outputs | `Good`, with the outputs |
/// | `MethodResult::with_status(Good_..., outputs)` | `Good` and the outputs; `MethodStatusQualified` |
/// | `MethodResult::with_status(Uncertain_..., outputs)` | that status, with the outputs |
/// | a Bad `StatusCode`, or a failed `Result` / `VoidResult` | that status, no outputs, the `ErrorDetail` |
/// | `reject_argument(...)` | `Bad_InvalidArgument`, a status per input, a DiagnosticInfo per rejection |
/// | (either form) throws | `Bad_InternalError` with an `ErrorDetail`; the exception never escapes |
/// | (asynchronous) every copy of `done` dropped | `Bad_InternalError`, the `ErrorDetail` naming the Method |
/// | (asynchronous) `done` called twice | the first result counts; the second is ignored and logged |
///
/// A Good status with a subcode is not allowed as a Method's statusCode (OPC 10000-4 5.11.2.4): the Call
/// service answers it plain `Good` with the outputs, the given code as the cause of the `ErrorDetail`
/// `MethodStatusQualified`, and logs a warning. A caller in the same process (@ref MethodAccessor) receives
/// the code as given.
///
/// The handler runs on the thread that delivers the Call to the Method node. It never calls a `*_sync`
/// function: on an executor thread that returns `Bad_WouldBlock`. Work that needs the address space
/// uses the asynchronous form.
/// @tparam In  The input arguments' C++ types; a trailing `std::optional<T>` is an optional argument.
/// @tparam Out The output arguments' C++ types.
/// @ingroup address_space
template<typename... In, typename... Out>
class MethodAdapter<std::tuple<In...>, std::tuple<Out...>>
{
public:
  /// Wraps @p handler.
  /// @tparam Handler A synchronous or asynchronous method handler (see the class description).
  /// @param handler The handler; copied with the adapter.
  /// @param inputs  The input arguments' descriptions, whose names go into a rejected argument's
  ///                ErrorDetail; default for none.
  /// @param logger  Where a handler that completes twice is reported; silent by default.
  template<typename Handler>
  explicit MethodAdapter(Handler handler, ua::Inputs<In...> inputs = {}, Logger logger = {})
    : mInputNames(std::apply(
        [](const Arg<In>&... args) { return std::vector<std::string>{args.name...}; }, inputs.args)),
      mLogger(std::move(logger))
  {
    constexpr bool isSync = SyncMethodHandler<Handler, std::tuple<In...>, std::tuple<Out...>>;
    constexpr bool isAsync = AsyncMethodHandler<Handler, std::tuple<In...>, std::tuple<Out...>>;
    static_assert(isSync != isAsync,
      "A method handler has exactly one of two forms: (const ua::MethodCall&, const In&...) -> "
      "ua::MethodResult<Out...>, or (const ua::MethodCall&, const In&..., ua::MethodResultCallback<Out...>) "
      "-> void");
    if constexpr (isSync)
    {
      mBody = [handler = std::move(handler)](const MethodCall& call,
                const std::tuple<In...>& inputValues,
                MethodResultCallback<Out...>
                  done) mutable
      {
        done(std::apply([&handler, &call](const In&... values) -> MethodResult<Out...>
          { return handler(call, values...); },
          inputValues));
      };
    }
    else
    {
      mBody = [handler = std::move(handler)](const MethodCall& call,
                const std::tuple<In...>& inputValues,
                MethodResultCallback<Out...>
                  done) mutable
      {
        std::apply([&handler, &call, &done](const In&... values)
          { handler(call, values..., std::move(done)); },
          inputValues);
      };
    }
  }

  /// Decodes @p callMethodRequest, calls the handler and delivers the Call's result to @p callback once.
  /// @param callMethodRequest The request: the Object, the Method and the input arguments.
  /// @param context           The calling session's context, or null.
  /// @param callback          Receives the result exactly once.
  void operator()(const CallMethodRequest& callMethodRequest, shared_ptr<const MethodCallContext> context,
    CallMethodCompleteCallback callback) const
  {
    check_true(static_cast<bool>(callback), Status::BadInvalidArgument);
    constexpr std::size_t declared = sizeof...(In);
    constexpr std::size_t required = detail::method_required_arg_count<std::tuple<In...>>();

    const auto& arguments = callMethodRequest.input_arguments();
    if (arguments.size() < required)
    {
      callback(CallResult{StatusCode{Status::BadArgumentsMissing},
        ErrorDetail::build(
          "InvalidMethodArguments", "Too few arguments supplied to method call.", "MethodAdapter")
          .context(ContextKeys::sizeMin, std::to_string(required))
          .context(ContextKeys::sizeActual, std::to_string(arguments.size()))});
      return;
    }
    if (arguments.size() > declared)
    {
      callback(CallResult{StatusCode{Status::BadTooManyArguments},
        ErrorDetail::build(
          "InvalidMethodArguments", "Too many arguments supplied to method call.", "MethodAdapter")
          .context(ContextKeys::sizeMax, std::to_string(declared))
          .context(ContextKeys::sizeActual, std::to_string(arguments.size()))});
      return;
    }

    std::tuple<In...> inputValues;
    CallMethodResult rejected;
    bool anyArgumentInvalid = false;
    [&]<std::size_t... I>(std::index_sequence<I...>)
    {
      (decode_argument<I>(arguments, std::get<I>(inputValues), rejected, anyArgumentInvalid), ...);
    }(std::make_index_sequence<declared>{});
    if (anyArgumentInvalid)
    {
      rejected.status_code() = Status::BadInvalidArgument;
      callback(CallResult{std::move(rejected)});
      return;
    }

    const MethodCall call{callMethodRequest.object_id(), callMethodRequest.method_id(), std::move(context)};
    auto guarded = detail::make_fire_once<CallResult>(std::move(callback));
    auto done = detail::MethodResultCallbackFactory::make<Out...>(
      [guarded, inputNames = mInputNames, objectId = call.object_id(), methodId = call.method_id()](
        MethodResult<Out...> result) { guarded(CallResult{encode(result, inputNames, methodId, objectId)}); },
      mLogger,
      call.method_id());
    try
    {
      mBody(call, inputValues, done);
    }
    catch (...)
    {
      const StatusCode thrown = ua::exception_to_status_code(std::current_exception());
      done(MethodResult<Out...>{StatusCode{Status::BadInternalError,
        ErrorDetail::build("MethodHandlerThrew", "The method handler threw an exception.", "MethodAdapter")
          .context(ContextKeys::methodId, to_string(call.method_id()))
          .cause(thrown)}});
    }
  }

private:
  template<std::size_t I>
  void decode_argument(const Array<Variant>& arguments, std::tuple_element_t<I, std::tuple<In...>>& target,
    CallMethodResult& rejected, bool& anyArgumentInvalid) const
  {
    using T = std::tuple_element_t<I, std::tuple<In...>>;
    try
    {
      if constexpr (detail::DataTypeOptional<T>::isOptional)
      {
        if (I < arguments.size())
        {
          target = detail::method_value_from<typename detail::DataTypeOptional<T>::Inner>(arguments[I]);
        }
      }
      else
      {
        target = detail::method_value_from<T>(arguments[I]);
      }
    }
    catch (const UaException& decodeError)
    {
      if (rejected.input_argument_results().size() < sizeof...(In))
      {
        rejected.input_argument_results().resize(sizeof...(In));
        rejected.input_argument_diagnostic_infos().resize(sizeof...(In));
      }
      rejected.input_argument_results().payload().at(I) = Status::BadTypeMismatch;
      auto mismatch = ErrorDetail::build(
        "ArgumentTypeMismatch", "Method input argument does not match the expected type.", "MethodAdapter")
                        .context(ContextKeys::typeExpected, detail::method_value_type_name<T>())
                        .context(ContextKeys::typeActual, detail::method_arg_actual_type_name(arguments[I]))
                        .context(ContextKeys::operationIndex, I);
      if (I < mInputNames.size() && !mInputNames[I].empty())
      {
        mismatch.context(ContextKeys::argumentName, mInputNames[I]);
      }
      DiagnosticInfo diagnostic;
      diagnostic.inner_status_code() =
        StatusCode{Status::BadTypeMismatch, std::move(mismatch).cause(decodeError.take_detail())};
      rejected.input_argument_diagnostic_infos().payload().at(I) = std::move(diagnostic);
      anyArgumentInvalid = true;
    }
  }

  static CallMethodResult encode(const MethodResult<Out...>& result,
    const std::vector<std::string>& inputNames, const NodeId& methodId, const NodeId& objectId)
  {
    CallMethodResult wire;
    const auto& argumentResults = result.argument_results();
    if (argumentResults.empty())
    {
      wire.status_code() = result.status_code();
      if (result.has_outputs())
      {
        wire.output_arguments().resize(sizeof...(Out));
        std::apply(
          [&wire](const Out&... outputs)
          {
            std::size_t index = 0;
            ((wire.output_arguments().payload().at(index++) = detail::method_value_to(outputs)), ...);
          },
          result.outputs());
      }
      return wire;
    }
    if (argumentResults.size() > sizeof...(In))
    {
      wire.status_code() = StatusCode{Status::BadInternalError,
        ErrorDetail::build("ArgumentRejectionIndexOutOfRange",
          "The method handler rejected an input argument the Method does not have.",
          "MethodAdapter")
          .context(ContextKeys::operationIndex, argumentResults.size() - 1)
          .context(ContextKeys::sizeMax, sizeof...(In))
          .context(ContextKeys::methodId, to_string(methodId))};
      return wire;
    }
    wire.status_code() = Status::BadInvalidArgument;
    wire.input_argument_results().resize(sizeof...(In));
    wire.input_argument_diagnostic_infos().resize(sizeof...(In));
    for (std::size_t index = 0; index < argumentResults.size(); ++index)
    {
      const StatusCode& status = argumentResults[index];
      if (!status.is_bad())
      {
        continue;
      }
      wire.input_argument_results().payload().at(index) = StatusCode{status.value()};
      std::string name;
      if (index < inputNames.size())
      {
        name = inputNames[index];
      }
      DiagnosticInfo diagnostic;
      diagnostic.inner_status_code() =
        StatusCode{status.value(), detail::rejected_argument_detail(status, index, name, methodId, objectId)};
      wire.input_argument_diagnostic_infos().payload().at(index) = std::move(diagnostic);
    }
    return wire;
  }

  std::function<void(const MethodCall&, const std::tuple<In...>&, MethodResultCallback<Out...>)> mBody;
  std::vector<std::string> mInputNames;
  Logger mLogger;
};

}  // namespace ua

#endif  // UA_METHOD_ADAPTER_H
