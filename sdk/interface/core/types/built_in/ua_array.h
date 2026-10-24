// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Owning, dimensioned container for OPC UA built-in element types.
/// @ingroup core_types

#ifndef UA_ARRAY_H
#define UA_ARRAY_H

#include <vector>
#include "fmt/format.h"
#include "ua_includes.h"
#include "ua_array_base.h"
#include "ua_error_detail.h"
#include "ua_resource_budgets.h"
#include "ua_ref_structure.h"

namespace ua
{

/// Tag wrapper requesting an @ref Array of a given length, default-initialized.
///
/// Disambiguates the size-constructing @ref Array overload from the
/// `std::initializer_list<T>` constructor under brace initialization: `Array<int>{Size{4}}`
/// builds four default elements, whereas `Array<int>{4}` builds a single element with value 4.
/// @ingroup core_types
struct Size
{
  size_t value;  ///< Number of elements to create.
};

/// An owning, optionally multi-dimensional sequence of OPC UA values of element type @p T.
///
/// Wraps a contiguous `std::vector<T>` payload and the @ref Dimensions inherited from
/// @ref ArrayBase. With no dimensions set the array is a flat one-dimensional sequence; when
/// dimensions are present the flattened payload length must equal their product (validated at
/// construction). Element access, iteration, and growth mirror `std::vector`. `Array<bool>` is
/// supported via `std::vector<bool>`'s proxy references.
///
/// @tparam T Element type - an OPC UA built-in type for which @ref built_in_type is defined.
/// @ingroup core_types
template<typename T>
class Array final : public ArrayBase
{
public:
  /// The element type, so generic code (and @ref Variant::to) can recover `T` from an `Array<T>`.
  using value_type = T;

  /// Constructs an empty array with no dimensions.
  Array();

  /// Move-constructs from @p other, transferring its payload and dimensions.
  ///
  /// @param other The array to move from; left empty and valid.
  /// @post @p other is left empty and valid.
  Array(Array&& other) noexcept;

  /// Move-assigns from @p other, transferring its payload and dimensions.
  ///
  /// @param other The array to move from; left empty and valid.
  /// @return A reference to this array.
  /// @post @p other is left empty and valid.
  Array& operator=(Array&& other) noexcept;

  /// Copy-constructs a deep copy of @p other, including its dimensions.
  /// @param other The array to deep-copy.
  Array(const Array& other);

  /// Constructs an array of @p size default-initialized elements with no dimensions.
  ///
  /// @param size Number of elements to create; see @ref Size for why this is wrapped.
  explicit Array(Size size);

  /// Constructs a dimensioned array from a flattened @p payload.
  ///
  /// @param dimensions Length along each dimension, outermost first; empty leaves the array
  ///                   one-dimensional.
  /// @param payload    Flattened elements in row-major order.
  /// @throws UaException with @ref Status::BadInvalidArgument if @p dimensions is non-empty and
  ///         its element-count product does not equal `payload.size()`.
  Array(const Dimensions& dimensions, const std::vector<T>& payload);

  /// Copy-assigns a deep copy of @p other, including its dimensions.
  ///
  /// @param other The array to deep-copy.
  /// @return A reference to this array.
  Array& operator=(const Array& other);

  /// Destroys the array, releasing its payload.
  ~Array() override = default;

  /// Constructs a one-dimensional array from a braced initializer list.
  ///
  /// @param init The elements to copy into the payload, in order.
  Array(std::initializer_list<T> init);

  /// Replaces the payload with @p elements, leaving the dimensions unchanged.
  ///
  /// @param elements The new flattened payload to copy in.
  /// @return A reference to this array.
  Array& operator=(const std::vector<T>& elements);

  /// Returns whether both arrays have equal payloads and equal dimensions.
  ///
  /// @return `true` if the payloads and dimensions both compare equal, `false` otherwise.
  bool operator==(const Array&) const;

  // Returns the vector's own reference type rather than `const T&` / `T&` so
  // `Array<bool>` works: `std::vector<bool>` stores bits and yields proxy
  // references, not `bool&`. For every other `T` these aliases are exactly
  // `const T&` / `T&`, so behaviour is unchanged.

  /// Returns the element at @p index without bounds checking.
  ///
  /// @param index Zero-based offset into the flattened payload; must be less than @ref size.
  /// @return A reference to the element; for `Array<bool>` a proxy reference.
  typename std::vector<T>::const_reference operator[](size_t index) const;

  /// Returns a mutable reference to the element at @p index without bounds checking.
  ///
  /// @param index Zero-based offset into the flattened payload; must be less than @ref size.
  /// @return A reference to the element; for `Array<bool>` a proxy reference.
  typename std::vector<T>::reference operator[](size_t index);

  /// Returns the number of elements in the flattened payload.
  ///
  /// @return The element count of the payload.
  size_t size() const override;

  /// Returns the underlying flattened payload.
  ///
  /// @return A const reference to the flattened payload vector.
  const std::vector<T>& payload() const;

  /// Returns a mutable reference to the underlying flattened payload.
  ///
  /// @return A mutable reference to the flattened payload vector.
  /// @warning Mutating the payload length directly does not update the dimensions; callers are
  ///          responsible for keeping them consistent.
  std::vector<T>& payload();

  /// Returns whether the payload contains no elements.
  ///
  /// @return `true` if the payload is empty, `false` otherwise.
  bool empty() const;

  /// Returns a read-only view over the flattened payload.
  ///
  /// @return A span valid until the array is resized, reassigned, or destroyed.
  span<const T> as_span() const;

  /// Returns a mutable view over the flattened payload.
  ///
  /// @return A span valid until the array is resized, reassigned, or destroyed.
  span<T> as_span();

  /// Returns a const iterator to the first element of the flattened payload.
  ///
  /// @return A const iterator to the first element, or @ref end if the payload is empty.
  auto begin() const;

  /// Returns an iterator to the first element of the flattened payload.
  ///
  /// @return An iterator to the first element, or @ref end if the payload is empty.
  auto begin();

  /// Returns a const iterator one past the last element of the flattened payload.
  ///
  /// @return A const iterator one past the last element.
  auto end() const;

  /// Returns an iterator one past the last element of the flattened payload.
  ///
  /// @return An iterator one past the last element.
  auto end();

  /// Returns the OPC UA built-in type identifier of the element type @p T.
  ///
  /// @return The @ref BuiltInTypeId corresponding to element type @p T.
  BuiltInTypeId built_in_type_id() const override;

  //  string_view type_name() const override;

  /// Returns an owning deep copy of this array as a base-class pointer.
  ///
  /// @return A `unique_ptr` owning a deep copy of this array.
  unique_ptr<Array> clone() const;

  /// Reserves capacity for at least @p capacity elements without changing @ref size.
  ///
  /// @param capacity Minimum number of elements the payload should be able to hold.
  void reserve(size_t capacity);

  /// Resizes the payload to @p size elements, default-initializing any new ones.
  ///
  /// @param size Number of elements the payload should contain after the call.
  /// @note Does not update the dimensions.
  void resize(size_t size);

  /// Appends a copy of @p value to the payload.
  ///
  /// @param value The element to copy onto the end of the payload.
  void push_back(const T& value);

  /// Appends @p value to the payload by move.
  ///
  /// @param value The element to move onto the end of the payload.
  void push_back(T&& value);

  /// Constructs an element in place at the end of the payload.
  ///
  /// @tparam Args Constructor argument types for @p T.
  /// @param args  Arguments forwarded to the element constructor.
  /// @return A reference to the newly constructed element.
  template<typename... Args>
  T& emplace_back(Args&&... args);

  /// Removes all elements and clears any dimensions.
  void clear();

private:
  std::vector<T> mElements;

  /// Deep-copies the payload of @p other into this freshly constructed array.
  ///
  /// @tparam U Element type of the source; its elements must assign to @p T.
  /// @param other The source array whose payload is copied in.
  template<typename U>
  void copy_ctor(const Array<U>& other);

  /// Deep-copies the payload of @p other over this array's payload.
  ///
  /// @tparam U Element type of the source; its elements must assign to @p T.
  /// @param other The source array whose payload is copied in.
  /// @return `*this`.
  template<typename U>
  Array& copy_assign(const Array<U>& other);
};

template<typename T>
Array<T>::Array() = default;

template<typename T>
Array<T>::Array(const Array& other) : ArrayBase(other)
{
  copy_ctor(other);
}

template<typename T>
Array<T>::Array(Size size)
{
  mElements.resize(size.value);
}

template<typename T>
Array<T>::Array(const Dimensions& dimensions, const std::vector<T>& payload) : ArrayBase(dimensions)
{
  if (!dimensions.empty())
  {
    const size_t expectedNoOfElements = calculate_no_of_elements(dimensions);
    if (expectedNoOfElements != payload.size())
    {
      throw UaException(Status::BadInvalidArgument,
        ErrorDetail::build("ArrayDimensionMismatch",
          "Flattened payload length does not match the product of the array dimensions.",
          "ua::Array")
          .context(ua::ContextKeys::sizeExpected, std::to_string(expectedNoOfElements))
          .context(ua::ContextKeys::sizeActual, std::to_string(payload.size())));
    }
  }

  mElements = payload;
}

template<typename T>
Array<T>::Array(std::initializer_list<T> init) : mElements(init)
{}

template<typename T>
Array<T>& Array<T>::operator=(const Array& other)
{
  return copy_assign(other);
}

template<typename T>
Array<T>& Array<T>::operator=(const std::vector<T>& elements)
{
  mElements = elements;
  return *this;
}

template<typename T>
bool Array<T>::operator==(const Array&) const = default;

template<typename T>
typename std::vector<T>::const_reference Array<T>::operator[](size_t index) const
{
  return mElements[index];
}

template<typename T>
typename std::vector<T>::reference Array<T>::operator[](size_t index)
{
  return mElements[index];
}

template<typename T>
size_t Array<T>::size() const
{
  return mElements.size();
}

template<typename T>
const std::vector<T>& Array<T>::payload() const
{
  return mElements;
}

template<typename T>
std::vector<T>& Array<T>::payload()
{
  return mElements;
}

template<typename T>
bool Array<T>::empty() const
{
  return mElements.empty();
}

template<typename T>
span<const T> Array<T>::as_span() const
{
  return mElements;
}

template<typename T>
span<T> Array<T>::as_span()
{
  return mElements;
}

template<typename T>
auto Array<T>::begin() const
{
  return mElements.begin();
}

template<typename T>
auto Array<T>::begin()
{
  return mElements.begin();
}

template<typename T>
auto Array<T>::end() const
{
  return mElements.end();
}

template<typename T>
auto Array<T>::end()
{
  return mElements.end();
}

template<typename T>
BuiltInTypeId Array<T>::built_in_type_id() const
{
  return built_in_type<T>();
}

// template<typename T>
// string_view Array<T>::type_name() const
// {
//   return get_typename<T>();
// }

template<typename T>
unique_ptr<Array<T>> Array<T>::clone() const
{
  return make_unique<Array>(*this);
}

template<typename T>
void Array<T>::reserve(size_t capacity)
{
  mElements.reserve(capacity);
}

template<typename T>
void Array<T>::resize(size_t size)
{
  mElements.resize(size);
}

template<typename T>
void Array<T>::push_back(const T& value)
{
  mElements.push_back(value);
}

template<typename T>
void Array<T>::push_back(T&& value)
{
  mElements.push_back(std::move(value));
}

template<typename T>
template<typename... Args>
T& Array<T>::emplace_back(Args&&... args)
{
  return mElements.emplace_back(std::forward<Args>(args)...);
}

template<typename T>
void Array<T>::clear()
{
  if (mDimensions)
  {
    mDimensions.reset();
  }
  mElements.clear();
}

template<typename T>
template<typename U>
void Array<T>::copy_ctor(const Array<U>& other)
{
  mElements = other.mElements;
}

/// @copydoc Array::copy_assign(const Array<U>&)
template<typename T>
template<typename U>
Array<T>& Array<T>::copy_assign(const Array<U>& other)
{
  ArrayBase::operator=(static_cast<const ArrayBase&>(other));
  mElements = other.mElements;
  return *this;
}

template<typename T>
Array<T>::Array(Array&& other) noexcept
  : ArrayBase(static_cast<ArrayBase&&>(other)), mElements(std::move(other.mElements))
{}

template<typename T>
Array<T>& Array<T>::operator=(Array&& other) noexcept
{
  ArrayBase::operator=(static_cast<ArrayBase&&>(other));
  mElements = std::move(other.mElements);
  return *this;
}

namespace array_utils
{

/// Builds an array of cloned structure references from @p source, preserving its dimensions.
///
/// @tparam T     Element type; each element must expose a `clone()` returning a structure handle.
/// @param source Array whose elements are individually cloned into reference handles.
/// @return A new @ref Array of @ref RefStructure copies carrying @p source's dimensions.
template<typename T>
Array<RefStructure<>> copy_to_array_of_references(const Array<T>& source)
{
  Array<RefStructure<Structure>> result;

  for (const auto& element : source.payload())
  {
    result.payload().push_back(element.clone());
  }

  result.dimensions() = source.dimensions();
  return result;
}

/// Builds an array of cloned structure references from a plain @p source vector.
///
/// @tparam T     Element type; each element must expose a `clone()` returning a structure handle.
/// @param source Vector whose elements are individually cloned into reference handles.
/// @return A new @ref Array of @ref RefStructure copies with no dimensions set.
template<typename T>
Array<RefStructure<>> copy_to_array_of_references(const std::vector<T>& source)
{
  Array<RefStructure<Structure>> result;
  for (const auto& element : source)
  {
    result.payload().push_back(element.clone());
  }
  return result;
}

}  // namespace array_utils

}  // namespace ua

#endif  // !UA_ARRAY_H
