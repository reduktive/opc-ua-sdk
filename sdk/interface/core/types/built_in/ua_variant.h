// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief A type-erased OPC UA Variant holding any built-in scalar or array value.
/// @ingroup core_types

#ifndef UA_VARIANT_H
#define UA_VARIANT_H

#include <memory>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>
#include "ua_includes.h"
#include "ua_locale_id.h"
#include "ua_built_in_type_id.h"
#include "ua_byte_string.h"
#include "ua_data_value.h"
#include "ua_date_time.h"
#include "ua_decimal.h"
#include "ua_diagnostic_info.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_guid.h"
#include "ua_localized_text.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_result.h"
#include "ua_status_code.h"
#include "ua_array.h"
#include "ua_xml_element.h"
#include "ua_ref_structure.h"
#include "ua_ref_wrapper.h"

namespace ua
{

class Structure;

/// Constraint satisfied by every built-in OPC UA scalar type a @c Variant can hold.
///
/// Holds for the primitive types (`bool`, the fixed-width integers, `float`, `double`) and the
/// built-in scalar value types (`DateTime`, `Guid`, `XmlElement`, `String`, `ByteString`,
/// `NodeId`, `ExpandedNodeId`, `StatusCode`, `QualifiedName`, `LocalizedText`,
/// `RefStructure<Structure>`, `DataValue`, `Decimal`).
///
/// @tparam T Candidate type to test.
/// @see IsBuiltInArrayType, IsBuiltInType
template<class T>
concept IsBuiltInScalarType = IsAnyOf<T, bool, int8_t, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t,
  uint64_t, float, double, DateTime, Guid, XmlElement, String, ByteString, NodeId, ExpandedNodeId, StatusCode,
  QualifiedName, LocalizedText, RefStructure<Structure>, DataValue, Decimal>;

/// Constraint satisfied by every built-in OPC UA array type a @c Variant can hold.
///
/// Holds for `Array<T>` of any built-in scalar type, plus `Array<Variant>` for nested variant
/// arrays.
///
/// @tparam T Candidate type to test.
/// @see IsBuiltInScalarType, IsBuiltInType
template<class T>
concept IsBuiltInArrayType = IsAnyOf<T, Array<Variant>, Array<String>, Array<DateTime>, Array<Guid>,
  Array<ByteString>, Array<XmlElement>, Array<NodeId>, Array<ExpandedNodeId>, Array<StatusCode>,
  Array<QualifiedName>, Array<LocalizedText>, Array<RefStructure<Structure>>, Array<DataValue>,
  Array<Decimal>, Array<int64_t>, Array<int32_t>, Array<int16_t>, Array<uint8_t>, Array<uint64_t>,
  Array<uint32_t>, Array<uint16_t>, Array<int8_t>, Array<double>, Array<float>, Array<bool>>;

/// Constraint satisfied by any built-in OPC UA type, scalar or array.
///
/// Equivalent to `IsBuiltInScalarType<T> || IsBuiltInArrayType<T>`.
///
/// @tparam T Candidate type to test.
/// @see IsBuiltInScalarType, IsBuiltInArrayType
template<class T>
concept IsBuiltInType = (IsBuiltInScalarType<T> || IsBuiltInArrayType<T>);

namespace detail
{
/// Copyable, deep-cloning box for the `DataValue` scalar alternative of @ref Variant.
///
/// `DataValue` stores its `Variant` inline, so `sizeof(DataValue)` depends on `sizeof(Variant)`.
/// Holding the `DataValue` here behind a pointer breaks that size recursion - `sizeof(Variant)` stays
/// independent of `sizeof(DataValue)`. Copy deep-clones, so the enclosing `ScalarGroup` variant
/// remains copy-constructible (which `Variant::copy_from` relies on). The generic scalar write paths
/// (the `Variant` scalar constructors, operator=, copy_from) construct this `BoxedDataValue`
/// alternative directly via `std::in_place_type` when the held type is a `DataValue`.
/// @ingroup core_types
class BoxedDataValue
{
public:
  /// Default-constructs a box holding a default-constructed @ref DataValue.
  BoxedDataValue() : mValue(make_unique<DataValue>())
  {}

  /// Boxes @p value, taking ownership of a heap copy.
  ///
  /// Explicit: the scalar write paths (the `Variant` scalar constructors and `operator=`,
  /// `copy_from`) construct the `BoxedDataValue` alternative directly via `std::in_place_type`
  /// rather than relying on an implicit `DataValue -> BoxedDataValue` conversion.
  /// @param value @ref DataValue to box; moved into the heap-allocated storage.
  explicit BoxedDataValue(DataValue value) : mValue(make_unique<DataValue>(std::move(value)))
  {}

  /// Copy-constructs an independent box, deep-copying the boxed @ref DataValue.
  /// @param other Box whose boxed @ref DataValue is deep-copied.
  BoxedDataValue(const BoxedDataValue& other) : mValue(make_unique<DataValue>(*other.mValue))
  {}

  /// Defaulted memberwise move construction.
  BoxedDataValue(BoxedDataValue&&) noexcept = default;

  /// Copy-assigns, deep-copying @p other's boxed @ref DataValue into an independent box.
  /// @param other Box whose boxed @ref DataValue is deep-copied into this box.
  /// @return Reference to this box.
  BoxedDataValue& operator=(const BoxedDataValue& other)
  {
    mValue = make_unique<DataValue>(*other.mValue);
    return *this;
  }

  /// Defaulted memberwise move assignment.
  /// @return Reference to this box.
  BoxedDataValue& operator=(BoxedDataValue&&) noexcept = default;

  /// Destroys the box, releasing the boxed @ref DataValue.
  ~BoxedDataValue() = default;

  /// Dereferences to the boxed @ref DataValue.
  /// @return Reference to the boxed @ref DataValue.
  DataValue& operator*() noexcept
  {
    return *mValue;
  }

  /// Dereferences to the boxed @ref DataValue (const overload).
  /// @return Const reference to the boxed @ref DataValue.
  const DataValue& operator*() const noexcept
  {
    return *mValue;
  }

  /// Returns a pointer to the boxed @ref DataValue (never null).
  /// @return Pointer to the boxed @ref DataValue; never null.
  DataValue* get() noexcept
  {
    return mValue.get();
  }

  /// Returns a pointer to the boxed @ref DataValue (const overload; never null).
  /// @return Const pointer to the boxed @ref DataValue; never null.
  const DataValue* get() const noexcept
  {
    return mValue.get();
  }

  /// Compares two boxes by their boxed @ref DataValue values.
  /// @param other Box to compare against.
  /// @return `true` if both boxed @ref DataValue values compare equal; `false` otherwise.
  bool operator==(const BoxedDataValue& other) const
  {
    return *mValue == *other.mValue;
  }

private:
  unique_ptr<DataValue> mValue;
};
}  // namespace detail

/// A type-erased container for any built-in OPC UA value, scalar or array.
///
/// A Variant either is empty or holds exactly one built-in scalar (see @c IsBuiltInScalarType)
/// or one built-in array (see @c IsBuiltInArrayType), including `Structure`-derived values and
/// nested `Array<Variant>`. The held value is owned by the Variant; copying copies the contained
/// value (deep copy), and moving transfers it. This is a plain value type with no internal
/// synchronisation: it is not thread-safe for concurrent mutation, but distinct instances may be
/// used from different threads.
///
/// Query the contained type with the `is_*` predicates or @ref get_built_in_type, then read it
/// with the throwing @ref as accessor or the non-throwing @ref try_as accessor.
///
/// @ingroup core_types
/// @see IsBuiltInType, DataValue, Array
class Variant
{
public:
  /// Constructs an empty Variant holding no value.
  ///
  /// @post empty() == true
  Variant();

  /// Copy-constructs from @p other, deep-copying the contained value.
  /// @param other Variant to copy from.
  Variant(const Variant& other);

  /// Move-constructs from @p other, transferring the contained value.
  ///
  /// @post @p other is left empty.
  /// @param other Variant to move from.
  Variant(Variant&& other) noexcept;

  /// Copy-assigns from @p other, deep-copying the contained value.
  /// @param other Variant to copy from.
  /// @return Reference to this Variant.
  Variant& operator=(const Variant& other);

  /// Move-assigns from @p other, transferring the contained value.
  ///
  /// @post @p other is left empty.
  /// @param other Variant to move from.
  /// @return Reference to this Variant.
  Variant& operator=(Variant&& other) noexcept;

  /// Destroys the Variant, releasing any contained value.
  ~Variant() = default;

  /// Constructs a Variant holding a copy of a built-in scalar value.
  ///
  /// @tparam T Built-in scalar type (see @c IsBuiltInScalarType).
  /// @param value Value to copy into the Variant.
  template<typename T>
    requires IsBuiltInScalarType<T>
  explicit Variant(const T& value);

  /// Constructs a Variant holding a copy of a built-in array value.
  ///
  /// @tparam T Built-in array type (see @c IsBuiltInArrayType).
  /// @param value Array to copy into the Variant.
  template<typename T>
    requires IsBuiltInArrayType<T>
  explicit Variant(const T& value);

  /// Constructs a Variant by moving a built-in scalar value into it.
  ///
  /// @tparam T Built-in scalar type (see @c IsBuiltInScalarType).
  /// @param value Value to move into the Variant.
  template<typename T>
    requires IsBuiltInScalarType<T>
  explicit Variant(T&& value) noexcept;

  /// Constructs a Variant by moving a built-in array value into it.
  ///
  /// @tparam T Built-in array type (see @c IsBuiltInArrayType).
  /// @param value Array to move into the Variant.
  template<typename T>
    requires IsBuiltInArrayType<T>
  explicit Variant(T&& value) noexcept;

  /// Constructs a Variant that takes ownership of a heap-allocated `Structure`-derived value.
  ///
  /// @tparam T Type derived from @ref Structure.
  /// @param value Owning pointer whose pointee is adopted by the Variant; must be non-null.
  template<typename T>
    requires std::derived_from<T, Structure>
  explicit Variant(unique_ptr<T>&& value) noexcept;

  /// Constructs a Variant from a `Structure`-derived value, heap-allocating a copy internally.
  ///
  /// Convenience overload that accepts a concrete `Structure` subtype by value; the Variant
  /// allocates and owns a copy.
  ///
  /// @tparam T Concrete type derived from @ref Structure (not @ref Structure itself).
  /// @param value Value moved into the internally allocated storage.
  template<typename T>
    requires(std::derived_from<T, Structure> && !std::same_as<T, Structure>)
  explicit Variant(T value);

  /// Replaces the contained value with a copy of a built-in scalar.
  ///
  /// @tparam T Built-in scalar type (see @c IsBuiltInScalarType).
  /// @param value Value to copy into the Variant.
  /// @return Reference to this Variant.
  template<typename T>
    requires IsBuiltInScalarType<T>
  Variant& operator=(const T& value);

  /// Replaces the contained value with a copy of a built-in array.
  ///
  /// @tparam T Built-in array type (see @c IsBuiltInArrayType).
  /// @param value Array to copy into the Variant.
  /// @return Reference to this Variant.
  template<typename T>
    requires IsBuiltInArrayType<T>
  Variant& operator=(const T& value);

  /// Replaces the contained value by moving in a built-in scalar.
  ///
  /// @tparam T Built-in scalar type (see @c IsBuiltInScalarType).
  /// @param value Value to move into the Variant.
  /// @return Reference to this Variant.
  template<typename T>
    requires IsBuiltInScalarType<T>
  Variant& operator=(T&& value) noexcept;

  /// Replaces the contained value, taking ownership of a heap-allocated `Structure`-derived value.
  ///
  /// @tparam T Type derived from @ref Structure.
  /// @param value Owning pointer whose pointee is adopted by the Variant; must be non-null.
  /// @return Reference to this Variant.
  template<typename T>
    requires std::derived_from<T, Structure>
  Variant& operator=(unique_ptr<T>&& value) noexcept;

  /// Replaces the contained value with a `Structure`-derived value, copying it to the heap.
  ///
  /// Convenience overload that accepts a concrete `Structure` subtype by value.
  ///
  /// @tparam T Concrete type derived from @ref Structure (not @ref Structure itself).
  /// @param value Value moved into the internally allocated storage.
  /// @return Reference to this Variant.
  template<typename T>
    requires(std::derived_from<T, Structure> && !std::same_as<T, Structure>)
  Variant& operator=(T value);

  /// Replaces the contained value by moving in a built-in array.
  ///
  /// @tparam T Built-in array type (see @c IsBuiltInArrayType).
  /// @param value Array to move into the Variant.
  /// @return Reference to this Variant.
  template<typename T>
    requires IsBuiltInArrayType<T>
  Variant& operator=(T&& value) noexcept;

  /// Compares two Variants for equality.
  ///
  /// Two Variants are equal when both are empty, or both hold the same built-in type and their
  /// contained values compare equal.
  /// @param other Variant to compare against.
  /// @return `true` if both Variants are empty, or hold the same built-in type with equal values; `false`
  /// otherwise.
  bool operator==(const Variant& other) const;

  /// Returns whether the Variant holds no value.
  /// @return `true` if the Variant holds no value; `false` otherwise.
  bool empty() const;

  /// Returns whether the Variant holds a built-in array value.
  /// @return `true` if the Variant holds a built-in array value; `false` otherwise.
  bool is_array() const;

  /// Returns whether the Variant holds a built-in scalar value.
  /// @return `true` if the Variant holds a built-in scalar value; `false` otherwise.
  bool is_scalar() const;

  /// Returns whether the Variant holds a `bool` scalar.
  /// @return `true` if the Variant holds a `bool` scalar; `false` otherwise.
  bool is_boolean() const;

  /// Returns whether the Variant holds an `int8_t` scalar.
  /// @return `true` if the Variant holds an `int8_t` scalar; `false` otherwise.
  bool is_int8() const;

  /// Returns whether the Variant holds a `uint8_t` scalar.
  /// @return `true` if the Variant holds a `uint8_t` scalar; `false` otherwise.
  bool is_uint8() const;

  /// Returns whether the Variant holds an `int16_t` scalar.
  /// @return `true` if the Variant holds an `int16_t` scalar; `false` otherwise.
  bool is_int16() const;

  /// Returns whether the Variant holds a `uint16_t` scalar.
  /// @return `true` if the Variant holds a `uint16_t` scalar; `false` otherwise.
  bool is_uint16() const;

  /// Returns whether the Variant holds an `int32_t` scalar.
  /// @return `true` if the Variant holds an `int32_t` scalar; `false` otherwise.
  bool is_int32() const;

  /// Returns whether the Variant holds a `uint32_t` scalar.
  /// @return `true` if the Variant holds a `uint32_t` scalar; `false` otherwise.
  bool is_uint32() const;

  /// Returns whether the Variant holds an `int64_t` scalar.
  /// @return `true` if the Variant holds an `int64_t` scalar; `false` otherwise.
  bool is_int64() const;

  /// Returns whether the Variant holds a `uint64_t` scalar.
  /// @return `true` if the Variant holds a `uint64_t` scalar; `false` otherwise.
  bool is_uint64() const;

  /// Returns whether the Variant holds a `float` scalar.
  /// @return `true` if the Variant holds a `float` scalar; `false` otherwise.
  bool is_float() const;

  /// Returns whether the Variant holds a `double` scalar.
  /// @return `true` if the Variant holds a `double` scalar; `false` otherwise.
  bool is_double() const;

  /// Returns whether the Variant holds a @ref DateTime scalar.
  /// @return `true` if the Variant holds a @ref DateTime scalar; `false` otherwise.
  bool is_date_time() const;

  /// Returns whether the Variant holds a @ref Guid scalar.
  /// @return `true` if the Variant holds a @ref Guid scalar; `false` otherwise.
  bool is_guid() const;

  /// Returns whether the Variant holds an @ref XmlElement scalar.
  /// @return `true` if the Variant holds an @ref XmlElement scalar; `false` otherwise.
  bool is_xml_element() const;

  /// Returns whether the Variant holds a @ref String scalar.
  /// @return `true` if the Variant holds a @ref String scalar; `false` otherwise.
  bool is_string() const;

  /// Returns whether the Variant holds a @ref ByteString scalar.
  /// @return `true` if the Variant holds a @ref ByteString scalar; `false` otherwise.
  bool is_byte_string() const;

  /// Returns whether the Variant holds a @ref NodeId scalar.
  /// @return `true` if the Variant holds a @ref NodeId scalar; `false` otherwise.
  bool is_node_id() const;

  /// Returns whether the Variant holds an @ref ExpandedNodeId scalar.
  /// @return `true` if the Variant holds an @ref ExpandedNodeId scalar; `false` otherwise.
  bool is_expanded_node_id() const;

  /// Returns whether the Variant holds a @ref StatusCode scalar.
  /// @return `true` if the Variant holds a @ref StatusCode scalar; `false` otherwise.
  bool is_status_code() const;

  /// Returns whether the Variant holds a @ref QualifiedName scalar.
  /// @return `true` if the Variant holds a @ref QualifiedName scalar; `false` otherwise.
  bool is_qualified_name() const;

  /// Returns whether the Variant holds a @ref LocalizedText scalar.
  /// @return `true` if the Variant holds a @ref LocalizedText scalar; `false` otherwise.
  bool is_localized_text() const;

  /// Returns whether the Variant holds a @ref Structure scalar.
  /// @return `true` if the Variant holds a @ref Structure scalar; `false` otherwise.
  bool is_structure() const;

  /// Returns whether the Variant holds a @ref DataValue scalar.
  /// @return `true` if the Variant holds a @ref DataValue scalar; `false` otherwise.
  bool is_data_value() const;

  /// Returns whether the Variant holds a @ref Decimal scalar.
  /// @return `true` if the Variant holds a @ref Decimal scalar; `false` otherwise.
  bool is_decimal() const;

  /// Returns whether the Variant holds an array of `bool`.
  /// @return `true` if the Variant holds an array of `bool`; `false` otherwise.
  bool is_array_of_boolean() const;

  /// Returns whether the Variant holds an array of `int8_t`.
  /// @return `true` if the Variant holds an array of `int8_t`; `false` otherwise.
  bool is_array_of_int8() const;

  /// Returns whether the Variant holds an array of `uint8_t`.
  /// @return `true` if the Variant holds an array of `uint8_t`; `false` otherwise.
  bool is_array_of_uint8() const;

  /// Returns whether the Variant holds an array of `int16_t`.
  /// @return `true` if the Variant holds an array of `int16_t`; `false` otherwise.
  bool is_array_of_int16() const;

  /// Returns whether the Variant holds an array of `uint16_t`.
  /// @return `true` if the Variant holds an array of `uint16_t`; `false` otherwise.
  bool is_array_of_uint16() const;

  /// Returns whether the Variant holds an array of `int32_t`.
  /// @return `true` if the Variant holds an array of `int32_t`; `false` otherwise.
  bool is_array_of_int32() const;

  /// Returns whether the Variant holds an array of `uint32_t`.
  /// @return `true` if the Variant holds an array of `uint32_t`; `false` otherwise.
  bool is_array_of_uint32() const;

  /// Returns whether the Variant holds an array of `int64_t`.
  /// @return `true` if the Variant holds an array of `int64_t`; `false` otherwise.
  bool is_array_of_int64() const;

  /// Returns whether the Variant holds an array of `uint64_t`.
  /// @return `true` if the Variant holds an array of `uint64_t`; `false` otherwise.
  bool is_array_of_uint64() const;

  /// Returns whether the Variant holds an array of `float`.
  /// @return `true` if the Variant holds an array of `float`; `false` otherwise.
  bool is_array_of_float() const;

  /// Returns whether the Variant holds an array of `double`.
  /// @return `true` if the Variant holds an array of `double`; `false` otherwise.
  bool is_array_of_double() const;

  /// Returns whether the Variant holds an array of @ref DateTime.
  /// @return `true` if the Variant holds an array of @ref DateTime; `false` otherwise.
  bool is_array_of_date_time() const;

  /// Returns whether the Variant holds an array of @ref Guid.
  /// @return `true` if the Variant holds an array of @ref Guid; `false` otherwise.
  bool is_array_of_guid() const;

  /// Returns whether the Variant holds an array of @ref XmlElement.
  /// @return `true` if the Variant holds an array of @ref XmlElement; `false` otherwise.
  bool is_array_of_xml_element() const;

  /// Returns whether the Variant holds an array of @ref String.
  /// @return `true` if the Variant holds an array of @ref String; `false` otherwise.
  bool is_array_of_string() const;

  /// Returns whether the Variant holds an array of @ref ByteString.
  /// @return `true` if the Variant holds an array of @ref ByteString; `false` otherwise.
  bool is_array_of_byte_string() const;

  /// Returns whether the Variant holds an array of @ref NodeId.
  /// @return `true` if the Variant holds an array of @ref NodeId; `false` otherwise.
  bool is_array_of_node_id() const;

  /// Returns whether the Variant holds an array of @ref ExpandedNodeId.
  /// @return `true` if the Variant holds an array of @ref ExpandedNodeId; `false` otherwise.
  bool is_array_of_expanded_node_id() const;

  /// Returns whether the Variant holds an array of @ref StatusCode.
  /// @return `true` if the Variant holds an array of @ref StatusCode; `false` otherwise.
  bool is_array_of_status_code() const;

  /// Returns whether the Variant holds an array of @ref QualifiedName.
  /// @return `true` if the Variant holds an array of @ref QualifiedName; `false` otherwise.
  bool is_array_of_qualified_name() const;

  /// Returns whether the Variant holds an array of @ref LocalizedText.
  /// @return `true` if the Variant holds an array of @ref LocalizedText; `false` otherwise.
  bool is_array_of_localized_text() const;

  /// Returns whether the Variant holds an array of @ref Structure.
  /// @return `true` if the Variant holds an array of @ref Structure; `false` otherwise.
  bool is_array_of_structure() const;

  /// Returns whether the Variant holds an array of @ref DataValue.
  /// @return `true` if the Variant holds an array of @ref DataValue; `false` otherwise.
  bool is_array_of_data_value() const;

  /// Returns whether the Variant holds an array of @ref Decimal.
  /// @return `true` if the Variant holds an array of @ref Decimal; `false` otherwise.
  bool is_array_of_decimal() const;

  /// Returns whether the Variant holds an array of @ref Variant.
  /// @return `true` if the Variant holds an array of @ref Variant; `false` otherwise.
  bool is_array_of_variant() const;

  /// Returns the contained array through its type-erased base.
  ///
  /// The reference is valid for the lifetime of this Variant and remains valid only while the
  /// Variant continues to hold the same value.
  ///
  /// @return Reference to the contained array as an @ref ArrayBase.
  /// @throws UaException if the Variant does not hold an array.
  const ArrayBase& get_array_base() const;

  /// Returns the contained array through its mutable type-erased base.
  ///
  /// The reference is valid for the lifetime of this Variant and remains valid only while the
  /// Variant continues to hold the same value.
  ///
  /// @return Reference to the contained array as an @ref ArrayBase.
  /// @throws UaException if the Variant does not hold an array.
  ArrayBase& get_array_base();

  /// Returns the OPC UA built-in type id of the contained value.
  ///
  /// For arrays this is the element type's id (the array rank is not encoded in the id).
  ///
  /// @return The @ref BuiltInTypeId of the contained value.
  /// @throws UaException if the Variant is empty.
  BuiltInTypeId get_built_in_type() const;

  /// Returns a const reference to the contained value as type @p T.
  ///
  /// @tparam T Built-in type the Variant is expected to hold.
  /// @return Reference to the contained value; valid only while the Variant holds it.
  /// @throws UaException if the Variant is empty or does not hold a @p T.
  /// @see try_as
  template<typename T>
  auto as() const -> const T&;

  /// Returns a mutable reference to the contained value as type @p T.
  ///
  /// @tparam T Built-in type the Variant is expected to hold.
  /// @return Reference to the contained value; valid only while the Variant holds it.
  /// @throws UaException if the Variant is empty or does not hold a @p T.
  /// @see try_as
  template<typename T>
  auto as() -> T&;

  /// Returns a pointer to the contained value if it is a built-in scalar of type @p T.
  ///
  /// Non-throwing counterpart to @ref as. The pointer is valid only while the Variant continues to
  /// hold the same value.
  ///
  /// @tparam T Built-in scalar type to test for (see @c IsBuiltInScalarType).
  /// @return Pointer to the contained value, or `nullptr` if the Variant does not hold a @p T.
  /// @see as
  template<typename T>
    requires IsBuiltInScalarType<T>
  const T* try_as() const
  {
    auto scalarGroup = std::get_if<ScalarGroup>(&mValue);
    if (!scalarGroup)
      return nullptr;
    if constexpr (std::is_same_v<T, DataValue>)
    {
      // DataValue is stored boxed; debox to the logical DataValue.
      auto boxed = std::get_if<detail::BoxedDataValue>(scalarGroup);
      return boxed ? boxed->get() : nullptr;
    }
    else
    {
      return std::get_if<T>(scalarGroup);
    }
  }

  /// Returns a pointer to the contained `Structure` if it is dynamically of type @p T.
  ///
  /// Non-throwing counterpart to @ref as for `Structure`-derived types; performs a `dynamic_cast`
  /// on the contained structure. The pointer is valid only while the Variant continues to hold the
  /// same value.
  ///
  /// @tparam T Concrete type derived from @ref Structure (not @ref Structure itself).
  /// @return Pointer to the contained value, or `nullptr` if the Variant does not hold a structure
  ///         or the structure is not a @p T.
  /// @see as
  template<typename T>
    requires(std::derived_from<T, Structure> && !std::same_as<T, Structure>)
  const T* try_as() const
  {
    if (!is_structure())
      return nullptr;
    auto scalarGroup = std::get_if<ScalarGroup>(&mValue);
    if (!scalarGroup)
      return nullptr;
    auto* refStruct = std::get_if<RefStructure<Structure>>(scalarGroup);
    if (!refStruct || !refStruct->get())
      return nullptr;
    return dynamic_cast<const T*>(refStruct->get());
  }

  /// Returns a pointer to the contained array if it is a built-in array of type @p T.
  ///
  /// The array counterpart of the scalar @ref try_as -- it borrows rather than copies, so a caller
  /// that only reads the elements pays nothing for the access. The pointer is valid only while the
  /// Variant continues to hold the same value. Use @ref to when the elements must outlive the
  /// Variant, since that overload copies.
  ///
  /// @tparam T Built-in array type to test for (see @c IsBuiltInArrayType), e.g. `Array<double>`.
  /// @return Pointer to the contained array, or `nullptr` if the Variant does not hold a @p T.
  /// @see as, to, to_vector
  template<typename T>
    requires IsBuiltInArrayType<T>
  const T* try_as() const
  {
    const auto* arrayGroup = std::get_if<ArrayGroup>(&mValue);
    if (!arrayGroup || !*arrayGroup)
      return nullptr;
    return std::get_if<T>(&**arrayGroup);
  }

  /// Coerces the contained value to a native C++ @p T, scalar or array, non-throwing.
  ///
  /// The `Result`-returning counterpart to `try_as:` on a match it returns a copy of the
  /// contained value; on a mismatch it returns a bad `Result<T>` carrying `Bad_TypeMismatch` and a
  /// source-tagged @ref ErrorDetail recording the expected-vs-actual @ref BuiltInTypeId. This is
  /// exact-type extraction  -  there is no lossy numeric conversion (a Variant holding `Int32` does
  /// not coerce to `Double`). @p T may be a built-in scalar or a built-in array (`Array<U>`), so one
  /// rule covers both; for any other `T` the call still compiles and returns a clean
  /// `Bad_NotSupported` (no value, no type-mismatch detail). Used by the tier-2
  /// typed-value sugar (`Connection::read_value<T>`, `TypedAccess::read_values<T>`).
  ///
  /// @tparam T Native C++ type to coerce the contained value to.
  /// @return `Result<T>` holding a copy of the value, or a bad Result (`Bad_TypeMismatch` on a
  ///         type mismatch, `Bad_NotSupported` for an unsupported @p T).
  /// @see try_as, to_vector
  template<class T>
  Result<T> to() const noexcept
  {
    if constexpr (IsBuiltInScalarType<T>)
    {
      if (const T* held = try_as<T>())
      {
        return Result<T>{*held};
      }
      // noexcept body: never call the throwing get_built_in_type() (it aborts for the moved-from-array
      // state). A live array coerced through this scalar path renders its array-ness (Int32[]).
      const BuiltInTypeId actual = actual_type_or_null();
      const bool actualIsArray = is_array() && actual != BuiltInTypeId::Null;
      return Result<T>{
        Status::BadTypeMismatch, make_coercion_error(built_in_type<T>(), actual, actualIsArray)};
    }
    else if constexpr (IsBuiltInArrayType<T>)
    {
      if (const T* held = try_as<T>())
      {
        return Result<T>{*held};
      }
      const BuiltInTypeId actual = actual_type_or_null();
      const bool actualIsArray = is_array() && actual != BuiltInTypeId::Null;
      return Result<T>{Status::BadTypeMismatch,
        make_coercion_error(built_in_type<typename T::value_type>(),
          actual,
          actualIsArray,
          /*expectedIsArray=*/true)};
    }
    else
    {
      return Result<T>{Status::BadNotSupported};
    }
  }

  /// Coerces the contained built-in array to a `std::vector<T>` of its element type, non-throwing.
  ///
  /// The array analogue of `to:` on a match it returns a copy of the array payload; on a
  /// mismatch it returns a bad `Result<std::vector<T>>` carrying `Bad_TypeMismatch` and a
  /// source-tagged @ref ErrorDetail with the expected-vs-actual element @ref BuiltInTypeId. Exact
  /// element-type extraction only (no per-element numeric conversion). For a @p T whose `Array<T>`
  /// is not a built-in array type the call compiles and returns a clean `Bad_NotSupported`.
  ///
  /// @tparam T Native C++ element type of the expected `Array<T>`.
  /// @return `Result<std::vector<T>>` holding a copy of the elements, or a bad Result.
  /// @see to, try_as
  template<class T>
  Result<std::vector<T>> to_vector() const noexcept
  {
    if constexpr (IsBuiltInArrayType<Array<T>>)
    {
      if (const auto* arrayGroup = std::get_if<ArrayGroup>(&mValue); arrayGroup && *arrayGroup)
      {
        if (const auto* array = std::get_if<Array<T>>(&**arrayGroup))
        {
          return Result<std::vector<T>>{array->payload()};
        }
      }
      // noexcept body: use the non-throwing type reporter. Both the expected and actual sides of this
      // array coercer are element types, so the actual is rendered without the array suffix.
      return Result<std::vector<T>>{Status::BadTypeMismatch,
        make_coercion_error(built_in_type<T>(), actual_type_or_null(), /*actualIsArray=*/false)};
    }
    else
    {
      return Result<std::vector<T>>{Status::BadNotSupported};
    }
  }

  /// Encodes the Variant to the wire using the supplied encoder.
  ///
  /// @tparam Encoder Encoder type providing the codec primitives.
  /// @param limit Remaining nesting budget; decremented as nested structures and arrays are
  ///              encoded to bound recursion.
  /// @param encoder Encoder to write the encoded value to.
  template<typename Encoder>
  void encode(StackDepth limit, Encoder& encoder) const;

  /// Resets the Variant to the empty state, releasing any contained value.
  ///
  /// @post empty() == true
  void clear();

  /// Returns the OPC UA built-in type id for the Variant type itself.
  ///
  /// Always @ref BuiltInTypeId::Variant; identifies the wire type of a Variant field, as opposed
  /// to @ref get_built_in_type which reports the type of the contained value.
  /// @return @ref BuiltInTypeId::Variant.
  static BuiltInTypeId built_in_type_id();

private:
  // NOTE: DataValue is stored boxed (detail::BoxedDataValue) - it holds its Variant inline, so storing
  // it here directly would make sizeof(Variant) recurse on itself. The logical type remains DataValue
  // throughout the public API (see as<DataValue>/try_as<DataValue> deboxing).
  using ScalarGroup = std::variant<bool, int8_t, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t,
    uint64_t, float, double, DateTime, Guid, XmlElement, String, ByteString, NodeId, ExpandedNodeId,
    StatusCode, QualifiedName, LocalizedText, RefStructure<Structure>, detail::BoxedDataValue, Decimal>;

  using ArrayGroupInstance = std::variant<Array<Variant>, Array<String>, Array<DateTime>, Array<Guid>,
    Array<ByteString>, Array<XmlElement>, Array<NodeId>, Array<ExpandedNodeId>, Array<StatusCode>,
    Array<QualifiedName>, Array<LocalizedText>, Array<RefStructure<Structure>>, Array<DataValue>,
    Array<Decimal>, Array<int64_t>, Array<int32_t>, Array<int16_t>, Array<uint8_t>, Array<uint64_t>,
    Array<uint32_t>, Array<uint16_t>, Array<int8_t>, Array<double>, Array<float>, Array<bool>>;

  using ArrayGroup = RefWrapper<ArrayGroupInstance>;

  std::variant<std::monostate, ScalarGroup, ArrayGroup> mValue;

  template<typename T>
  bool is_array_present() const;

  template<typename T>
  bool is_scalar_present() const;

  void copy_from(const Variant& other);

  /// Reports the built-in type of the contained value for diagnostics, without ever throwing.
  ///
  /// The noexcept-safe counterpart to `get_built_in_type:` it returns @ref BuiltInTypeId::Null for
  /// any state that is "not a live scalar or a live array"  -  an empty Variant AND the moved-from-array
  /// state (the `ArrayGroup` alternative is still present but its backing wrapper has been moved out).
  /// @ref get_built_in_type throws for those states, which would cross the `noexcept` boundary of the
  /// @ref to / @ref to_vector coercers and call `std::terminate`; this helper must be used there
  /// instead.
  ///
  /// @return The contained value's @ref BuiltInTypeId, or @ref BuiltInTypeId::Null when the Variant
  ///         holds no live scalar or array.
  BuiltInTypeId actual_type_or_null() const noexcept;

  /// Builds the source-tagged `Bad_TypeMismatch` @ref ErrorDetail for a failed @ref to / @ref
  /// to_vector coercion, recording the expected and actual @ref BuiltInTypeId as symbolic names.
  ///
  /// Out-of-line (in ua_variant.cpp) so the header-inline `to<T>()` / `to_vector<T>()` templates do
  /// not pull in the `to_string(BuiltInTypeId)` renderer (which itself includes this header).
  ///
  /// @param expected      The @ref BuiltInTypeId the coercion required.
  /// @param actual        The @ref BuiltInTypeId actually contained (`Null` when the Variant holds no
  ///                      live scalar or array).
  /// @param actualIsArray When `true`, the actual type is rendered with an `[]` array suffix so a
  ///                      live-array value coerced through the scalar @ref to reads legibly (e.g.
  ///                      `Int32[]` rather than a nonsensical bare `Int32`).
  /// @param expectedIsArray When `true`, the expected type is rendered with an `[]` suffix, so an
  ///                      array coercion (`to<Array<T>>`) reports `Double[]` rather than `Double`.
  /// @return A newly-owned @ref ErrorDetail describing the mismatch.
  static std::unique_ptr<ErrorDetail> make_coercion_error(
    BuiltInTypeId expected, BuiltInTypeId actual, bool actualIsArray, bool expectedIsArray = false);
};

template<typename T>
  requires std::derived_from<T, Structure>
Variant::Variant(unique_ptr<T>&& value) noexcept
{
  // Adopts the pointee (API-D2.2): an rvalue selects RefStructure's adopting constructor, not the cloning one.
  ScalarGroup group = RefStructure<Structure>{unique_ptr<Structure>{std::move(value)}};
  mValue = std::move(group);
}

template<typename T>
  requires(std::derived_from<T, Structure> && !std::same_as<T, Structure>)
Variant::Variant(T value)
{
  ScalarGroup group = RefStructure<Structure>{std::make_unique<T>(std::move(value))};
  mValue = std::move(group);
}

template<typename T>
  requires(std::derived_from<T, Structure> && !std::same_as<T, Structure>)
Variant& Variant::operator=(T value)
{
  ScalarGroup group = RefStructure<Structure>{std::make_unique<T>(std::move(value))};
  mValue = std::move(group);
  return *this;
}

template<typename T>
  requires IsBuiltInScalarType<T>
Variant::Variant(const T& value)
{
  if constexpr (std::is_same_v<T, DataValue>)
  {
    // DataValue is stored boxed; construct the BoxedDataValue alternative directly.
    mValue = ScalarGroup{std::in_place_type<detail::BoxedDataValue>, value};
  }
  else
  {
    ScalarGroup group = value;
    mValue = std::move(group);
  }
}

template<typename T>
  requires IsBuiltInArrayType<T>
Variant::Variant(const T& value)
{
  auto group = make_unique<ArrayGroupInstance>();
  *group = value;
  mValue = ArrayGroup{std::move(group)};
}

template<typename T>
  requires IsBuiltInScalarType<T>
Variant::Variant(T&& value) noexcept
{
  if constexpr (std::is_same_v<std::remove_reference_t<T>, DataValue>)
  {
    // DataValue is stored boxed; construct the BoxedDataValue alternative directly.
    mValue = ScalarGroup{std::in_place_type<detail::BoxedDataValue>, std::forward<T>(value)};
  }
  else
  {
    ScalarGroup group = std::forward<T>(value);
    mValue = std::move(group);
  }
}

template<typename T>
  requires IsBuiltInArrayType<T>
Variant::Variant(T&& value) noexcept
{
  auto group = make_unique<ArrayGroupInstance>();
  *group = std::forward<T>(value);
  mValue = ArrayGroup{std::move(group)};
}

template<typename T>
  requires std::derived_from<T, Structure>
Variant& Variant::operator=(unique_ptr<T>&& value) noexcept
{
  // Adopts the pointee (API-D2.2), as the constructor does.
  ScalarGroup group = RefStructure<Structure>{unique_ptr<Structure>{std::move(value)}};
  mValue = std::move(group);
  return *this;
}

/// Returns the textual type name `"Variant"` used in diagnostics and codec metadata.
/// @return The type name `"Variant"`.
template<>
inline string_view get_typename<Variant>()
{
  return "Variant";
}

/// Resolves any @ref LocalizedText held by a @ref Variant to the preferred session locale.
///
/// Walks @p value one level and dispatches by contained type, rewriting it in place:
///
///   - scalar @ref LocalizedText       -> collapse to a single session-locale scalar
///   - @c Array<LocalizedText>         -> collapse each element
///   - @c Structure -derived (scalar)  -> delegate to the virtual @c Structure::resolve
///   - @c Array<RefStructure<...>>     -> resolve each non-null element
///   - anything else                   -> no-op
///
/// @p locales is the ordered list of session locale preferences (most-preferred first); the
/// best matching translation is selected per OPC UA locale-matching rules, with an empty list
/// requesting the default locale. The function is synchronous, never throws, and mutates @p value
/// in place. It is invoked at service-response construction (Read, Browse, TranslateBrowsePath,
/// Call) and at sampling-engine fanout - not on the encode hot path.
///
/// @param[in,out] value   The value whose LocalizedText content is resolved in place.
/// @param locales         Ordered session locale preferences, most-preferred first. The span is
///                        borrowed for the duration of the call only and is not retained.
/// @ingroup core_types
void resolve_in_variant(Variant& value, span<const LocaleId> locales);

}  // namespace ua

#endif  // !UA_VARIANT_H
