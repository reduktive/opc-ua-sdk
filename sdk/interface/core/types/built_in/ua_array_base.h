// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Type-erased base of the multidimensional array value type.
/// @ingroup core_types

#ifndef UA_ARRAY_BASE_H
#define UA_ARRAY_BASE_H

#include "ua_includes.h"
#include "ua_built_in_type_id.h"

namespace ua
{

class Encoder;
class Decoder;
class StackDepth;

template<typename T>
class Array;

/// The size of each dimension of a multidimensional array, outermost first.
///
/// Each entry is the length of one dimension and must be strictly positive; the
/// number of entries is the array's `ArrayBase::value_rank` "value rank". An
/// empty (or absent) vector denotes a one-dimensional array. The product of all
/// entries equals the total element count.
using Dimensions = std::vector<int32_t>;

/// Element-type-erased base of the @ref Array "Array<T>" value type.
///
/// Holds the dimension metadata shared by every array element type and exposes
/// the type-agnostic operations (element count, value rank, built-in type) that
/// callers can use without knowing the static element type. The concrete
/// element storage lives in the derived @ref Array "Array<T>"; the pure-virtual
/// hooks below form its extension contract.
///
/// @ingroup core_types
class ArrayBase
{
public:
  virtual ~ArrayBase() = default;

  /// Compares two arrays for equality by their dimension metadata.
  ///
  /// @return `true` if both arrays have equal dimension metadata; otherwise `false`.
  /// @note This base comparison considers only the @ref Dimensions; the derived
  ///       @ref Array "Array<T>" extends it to also compare element values.
  bool operator==(const ArrayBase&) const = default;

  /// Returns the array dimensions, or an empty optional if none are set.
  ///
  /// @return The dimension sizes (outermost first), or `nullopt` for an array
  ///         that carries no explicit dimension metadata.
  const optional<ua::Dimensions>& dimensions() const;

  /// Returns a mutable reference to the array dimensions.
  ///
  /// @return A mutable reference to the optional array dimensions (outermost first).
  /// @warning Mutating the dimensions through this reference bypasses the
  ///          product-vs-size validation performed by
  ///          @ref add_and_validate_dimensions; the caller is responsible for
  ///          keeping the dimensions consistent with @ref size.
  /// @see add_and_validate_dimensions
  optional<ua::Dimensions>& dimensions();

  /// Returns the total number of elements stored in the array.
  ///
  /// @return The total number of elements stored in the array.
  virtual size_t size() const = 0;

  /// Returns the value rank, i.e. the number of array dimensions.
  ///
  /// @return The count of entries in @ref dimensions, or `1` when no dimension
  ///         metadata is set (an array is at least one-dimensional).
  int32_t value_rank() const;

  /// Returns the built-in type identifier of the array's element type.
  ///
  /// @return The built-in type identifier of the array's element type.
  virtual BuiltInTypeId built_in_type_id() const = 0;

  // virtual string_view type_name() const = 0;

  /// Sets the array dimensions after validating them against the element count.
  ///
  /// If @p dims is non-empty, every entry must be strictly positive and the
  /// product of the entries must equal @ref size; the dimensions are then moved
  /// into place. An empty @p dims clears any existing dimension metadata.
  ///
  /// @param[in] dims The dimension sizes to install (outermost first); consumed
  ///                 on success.
  /// @throws UaException with @ref Status::BadInvalidArgument if an entry is not
  ///         strictly positive or the product of the entries does not match
  ///         @ref size.
  /// @post On success, @ref dimensions holds @p dims (or is empty when @p dims
  ///       was empty).
  void add_and_validate_dimensions(Dimensions&& dims);

protected:
  /// Dimension sizes (outermost first); empty optional means no explicit rank.
  optional<ua::Dimensions> mDimensions;

  ArrayBase() = default;

  /// Constructs an array base with the given dimensions, copied into place.
  ///
  /// @param[in] dimensions The dimension sizes (outermost first).
  ArrayBase(const ua::Dimensions& dimensions);

  /// Constructs an array base with the given dimensions, moved into place.
  ///
  /// @param[in] dimensions The dimension sizes (outermost first); consumed.
  ArrayBase(ua::Dimensions&& dimensions);

  /// Copies the dimension metadata; for use by a derived @ref Array "Array<T>".
  /// @param obj The array base whose dimension metadata is copied.
  ArrayBase(const ArrayBase& obj) = default;
  /// Moves the dimension metadata, leaving @p obj's dimensions empty.
  /// @param obj The array base whose dimension metadata is moved from; left empty.
  ArrayBase(ArrayBase&& obj) noexcept = default;
  /// Copy-assigns the dimension metadata; for use by a derived @ref Array "Array<T>".
  /// @param obj The array base whose dimension metadata is copied.
  /// @return A reference to this array base.
  ArrayBase& operator=(const ArrayBase& obj) = default;
  /// Move-assigns the dimension metadata, leaving @p obj's dimensions empty.
  /// @param obj The array base whose dimension metadata is moved from; left empty.
  /// @return A reference to this array base.
  ArrayBase& operator=(ArrayBase&& obj) noexcept = default;

  /// Computes the product of all dimension sizes (the total element count).
  ///
  /// @param[in] dimensions The dimension sizes to multiply (outermost first).
  /// @return The product of every entry.
  /// @throws UaException with @ref Status::BadInvalidArgument if @p dimensions
  ///         is empty or any entry is not strictly positive.
  static size_t calculate_no_of_elements(const ua::Dimensions& dimensions);
};

}  // namespace ua

#endif  // !UA_ARRAY_BASE_H
