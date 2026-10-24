// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A Method's input and output arguments, described once for both its Properties and its decoding.
/// @ingroup address_space

#ifndef UA_METHOD_ARGUMENTS_H
#define UA_METHOD_ARGUMENTS_H

#include "ua_data_type_of.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_variant.h"

#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

namespace ua
{

/// One argument of a Method.
///
/// The C++ type @p T is the argument's type in the handler, and through @ref ua::data_type_of it is also
/// the DataType, ValueRank and ArrayDimensions published in the Method's `InputArguments` or
/// `OutputArguments` Property, so the published signature and the decoding cannot disagree. Made by
/// @ref ua::arg, or by @ref ua::argument for an argument whose DataType is known only at run time.
/// @tparam T The argument's C++ type; @ref ua::hasDataType must be true for it.
/// @ingroup address_space
template<typename T>
struct Arg
{
  /// The argument's name, published as `Argument.Name`.
  std::string name;
  /// The argument's description, published as `Argument.Description`; empty when there is none.
  LocalizedText description{};
  /// The DataType given to @ref ua::argument. Unset otherwise, and then @ref ua::data_type_of<T>() applies.
  std::optional<NodeId> dataType{};
  /// The ValueRank given to @ref ua::argument. Unset otherwise, and then @ref ua::value_rank_of<T>() applies.
  std::optional<int32_t> valueRank{};
};

/// A Method's input arguments, in order. A trailing `std::optional<T>` argument is optional
/// (OPC 10000-3 5.7.3): the client may omit it, and the handler then receives `std::nullopt`.
/// @tparam T The arguments' C++ types.
/// @ingroup address_space
template<typename... T>
struct Inputs
{
  /// The arguments.
  std::tuple<Arg<T>...> args;
};

/// A Method's output arguments, in order.
/// @tparam T The arguments' C++ types.
/// @ingroup address_space
template<typename... T>
struct Outputs
{
  /// The arguments.
  std::tuple<Arg<T>...> args;
};

/// Describes an argument of C++ type @p T.
///
/// @tparam T The argument's C++ type. A type without an OPC UA DataType does not compile here (see
///           @ref ua::hasDataType); describe such an argument with @ref ua::argument instead.
/// @param name        The argument's name.
/// @param description The argument's description; empty for none.
/// @return The argument.
/// @ingroup address_space
template<typename T>
Arg<T> arg(std::string name, std::string description = {})
{
  static_assert(hasDataType<T>,
    "No OPC UA DataType is known for this argument type: specialise ua::DataTypeOf for it, or describe the "
    "argument with ua::argument(name, dataType, valueRank)");
  Arg<T> methodArgument;
  methodArgument.name = std::move(name);
  if (!description.empty())
  {
    methodArgument.description = LocalizedText{"", std::move(description)};
  }
  return methodArgument;
}

/// Describes an argument whose DataType is known only at run time, such as a structure with no C++
/// type. The handler receives it as a `ua::Variant`.
///
/// @param name        The argument's name.
/// @param dataType    The DataType's NodeId, in the server's namespace indexes.
/// @param valueRank   The ValueRank (@ref ua::ValueRank::scalar, 1 for a one-dimensional array, ...).
/// @param description The argument's description; empty for none.
/// @return The argument.
/// @ingroup address_space
inline Arg<Variant> argument(
  std::string name, NodeId dataType, int32_t valueRank, std::string description = {})
{
  Arg<Variant> argument = arg<Variant>(std::move(name), std::move(description));
  argument.dataType = std::move(dataType);
  argument.valueRank = valueRank;
  return argument;
}

/// @cond METHOD_ARGUMENTS_DETAIL
namespace detail
{

/// True when no required argument follows an optional one (OPC 10000-3 5.7.3).
template<typename... T>
consteval bool optional_arguments_trail()
{
  // The leading false keeps the array non-empty; it cannot precede an optional argument.
  constexpr bool optionals[] = {false, DataTypeOptional<T>::isOptional...};
  bool seenOptional = false;
  for (const bool optional : optionals)
  {
    if (!optional && seenOptional)
    {
      return false;
    }
    seenOptional = seenOptional || optional;
  }
  return true;
}

}  // namespace detail

/// @endcond

/// A Method's input arguments, from their descriptions in order.
///
/// @tparam T The arguments' C++ types, deduced. Optional (`std::optional<T>`) arguments must follow
///           every required one (OPC 10000-3 5.7.3); otherwise this does not compile.
/// @param args The arguments.
/// @return The input arguments.
/// @ingroup address_space
template<typename... T>
Inputs<T...> inputs(Arg<T>... args)
{
  static_assert(detail::optional_arguments_trail<T...>(),
    "An optional (std::optional<T>) input argument must not be followed by a required one (OPC 10000-3 "
    "5.7.3)");
  return Inputs<T...>{std::tuple<Arg<T>...>{std::move(args)...}};
}

/// A Method's output arguments, from their descriptions in order.
///
/// @tparam T The arguments' C++ types, deduced; an output cannot be optional.
/// @param args The arguments.
/// @return The output arguments.
/// @ingroup address_space
template<typename... T>
Outputs<T...> outputs(Arg<T>... args)
{
  static_assert(!(detail::DataTypeOptional<T>::isOptional || ...),
    "An output argument cannot be optional: a Method returns every output or none (OPC 10000-4 5.11.2.2)");
  return Outputs<T...>{std::tuple<Arg<T>...>{std::move(args)...}};
}

}  // namespace ua

#endif  // UA_METHOD_ARGUMENTS_H
