// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief OPC UA ValueRank: the dimensionality of a Variable or VariableType value.
/// @ingroup core_types

#ifndef UA_VALUE_RANK_H
#define UA_VALUE_RANK_H

#include "ua_includes.h"

namespace ua
{

/// The OPC UA `ValueRank` of a Variable or VariableType value.
///
/// `ValueRank` is the `Int32` attribute defined by OPC 10000-3 5.6.2 that
/// states the dimensionality a value may take: a negative well-known constant
/// (see @ref scalarOrOneDimension, @ref any, @ref scalar, @ref oneOrMore)
/// or a positive count giving the exact number of array dimensions. A
/// default-constructed `ValueRank` is @ref any (the value may be a scalar or an
/// array of any rank). The wrapped value is never below @ref scalarOrOneDimension.
/// @ingroup core_types
class ValueRank
{
public:
  /// The value is a scalar or a one-dimensional array (well-known rank `-3`).
  ///
  /// The lowest valid `ValueRank`, below @ref any.
  static constexpr int32_t scalarOrOneDimension{-3};

  /// The value may be a scalar or an array of any dimensionality (well-known rank `-2`).
  static constexpr int32_t any{-2};

  /// The value is always a scalar (well-known rank `-1`).
  static constexpr int32_t scalar{-1};

  /// The value is an array with one or more dimensions (well-known rank `0`).
  static constexpr int32_t oneOrMore{0};

  /// Constructs a `ValueRank` equal to @ref any.
  ValueRank();

  /// Constructs a `ValueRank` from a raw OPC UA rank value.
  ///
  /// @param value The rank: a well-known negative constant
  ///              (@ref scalarOrOneDimension ... @ref scalar) or a positive
  ///              array-dimension count.
  /// @pre @p value is at least @ref scalarOrOneDimension (`-3`).
  /// @throws UaException with `Status::BadInvalidArgument` if @p value is below
  ///         @ref scalarOrOneDimension.
  ValueRank(int32_t value);

  /// Returns whether the rank is @ref any.
  ///
  /// @return `true` if the rank is @ref any.
  bool is_any() const;

  /// Returns whether the rank is @ref scalar (the value is always a scalar).
  ///
  /// @return `true` if the rank is @ref scalar.
  bool is_scalar() const;

  /// Returns whether the rank is @ref scalarOrOneDimension.
  ///
  /// @return `true` if the rank is @ref scalarOrOneDimension.
  bool is_scalar_or_one_dimension() const;

  /// Returns whether the rank denotes an array with a fixed dimension count.
  ///
  /// @return `true` for any positive rank (one or more fixed dimensions),
  ///         `false` for the negative well-known constants and @ref oneOrMore.
  bool is_array() const;

  /// Returns whether the rank is exactly one fixed dimension (rank `1`).
  ///
  /// @return `true` if the rank is exactly one fixed dimension.
  bool is_one_dimensional() const;

  /// Returns whether the rank is @ref oneOrMore (an array of unspecified rank).
  ///
  /// @return `true` if the rank is @ref oneOrMore.
  bool is_one_or_more_dimensional() const;

  /// Returns the fixed number of array dimensions, if the rank specifies one.
  ///
  /// @return The positive dimension count when @ref is_array() holds; an empty
  ///         optional for the negative well-known constants and @ref oneOrMore.
  optional<int32_t> no_of_dimensions() const;

  /// Returns the raw OPC UA rank value, including negative well-known constants.
  ///
  /// @return The wrapped `Int32` rank value.
  int32_t as_int32() const;

  /// Sets the rank to @ref any.
  void set_to_any();

  /// Sets the rank to @ref scalar.
  void set_to_scalar();

  /// Sets the rank to a single fixed dimension (rank `1`).
  void set_to_one_dimensional();

  /// Sets the rank to @ref oneOrMore (an array of unspecified dimensionality).
  void set_to_one_or_more_dimensional();

  /// Sets the rank to a fixed number of array dimensions.
  ///
  /// @param noOfDims The number of array dimensions; `0` is equivalent to
  ///                 @ref oneOrMore, any positive count fixes the rank.
  /// @pre @p noOfDims fits in an `int32_t`; otherwise the conversion terminates
  ///      the process.
  void set_no_of_dimensions(size_t noOfDims);

private:
  int32_t mValue;
};

}  // namespace ua

#endif  // !UA_VALUE_RANK_H
