// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Value-semantic, deep-copying wrapper around a polymorphic Structure pointer.
/// @ingroup core_types

#ifndef UA_REF_STRUCTURE_H
#define UA_REF_STRUCTURE_H

#include "ua_utilities.h"
#include "ua_built_in_type_id.h"
#include "ua_structure.h"

namespace ua
{

/// A value-semantic holder for a polymorphic @ref Structure, copied by cloning.
///
/// Wraps a `unique_ptr<T>` so that a heap-allocated, polymorphic OPC UA structure
/// can be stored and passed with value semantics. Copying a RefStructure performs a
/// deep copy via @ref Structure::clone (the held object is duplicated, not shared);
/// moving transfers ownership and leaves the source empty. This lets structured
/// DataTypes participate in @ref Variant and other value types without slicing.
///
/// @tparam T The held structure type; defaults to @ref Structure. Must derive from
///           @ref Structure (the clone result is `dynamic_cast` to `T*`).
/// @note Not thread-safe: a single instance must not be accessed concurrently from
///       multiple threads without external synchronisation.
/// @ingroup core_types
template<typename T = Structure>
class RefStructure
{
public:
  /// Constructs an empty holder owning no structure.
  ///
  /// @post `get() == nullptr` and `operator bool()` is `false`.
  RefStructure() = default;

  /// Move-constructs, transferring ownership and leaving @p other empty.
  ///
  /// @param other The holder to move from; left empty.
  RefStructure(RefStructure&& other) noexcept = default;

  /// Move-assigns, transferring ownership and leaving @p other empty.
  ///
  /// @param other The holder to move from; left empty.
  /// @return Reference to this holder.
  RefStructure& operator=(RefStructure&& other) noexcept = default;

  /// Destroys the holder, releasing any held structure.
  ~RefStructure() = default;

  /// Copy-constructs by deep-cloning the structure held by @p other.
  ///
  /// @param other The holder whose structure is deep-cloned.
  /// @post This holds an independent clone; @p other is unchanged.
  RefStructure(const RefStructure& other)
  {
    copy_from(other.inner_unique_ptr());
  }

  /// Constructs by deep-cloning the structure referenced by @p other.
  ///
  /// @param other Source pointer to clone; if null, the holder is left empty. The
  ///              pointee is not adopted - a clone is taken and @p other is unchanged.
  RefStructure(const unique_ptr<Structure>& other)
  {
    copy_from(other);
  }

  /// Constructs by adopting @p other, leaving it empty; nothing is cloned or allocated.
  ///
  /// @param other Source pointer to adopt; if null, the holder is left empty.
  RefStructure(unique_ptr<Structure>&& other) noexcept
    : mValue(std::move(other))
  {}

  /// Copy-assigns by deep-cloning the structure held by @p other.
  ///
  /// @param other The holder whose structure is deep-cloned.
  /// @return Reference to this holder.
  /// @post This holds an independent clone; @p other is unchanged.
  RefStructure& operator=(const RefStructure& other)
  {
    copy_from(other.inner_unique_ptr());
    return *this;
  }

  /// Assigns by deep-cloning the structure referenced by @p other.
  ///
  /// @param other Source pointer to clone; if null, the holder becomes empty. The
  ///              pointee is not adopted - a clone is taken and @p other is unchanged.
  /// @return Reference to this holder.
  RefStructure& operator=(const unique_ptr<Structure>& other)
  {
    copy_from(other);
    return *this;
  }

  /// Assigns by adopting ownership of @p other, leaving it empty.
  ///
  /// Unlike the copying overloads, this transfers the pointee without cloning.
  ///
  /// @param other Source pointer to adopt; ownership is transferred and @p other is left empty.
  /// @return Reference to this holder.
  RefStructure& operator=(unique_ptr<Structure>&& other)
  {
    mValue = std::move(other);
    return *this;
  }

  /// Returns whether both holders are empty or hold equal structures.
  ///
  /// Compares the held structures by value (an empty holder equals only another
  /// empty holder).
  ///
  /// @param obj The holder to compare against.
  /// @return `true` if both holders are empty or hold equal structures.
  bool operator==(const RefStructure& obj) const
  {
    return utils::compare(mValue, obj.mValue);
  }

  /// Returns the logical negation of operator==.
  ///
  /// @param obj The holder to compare against.
  /// @return `true` if the holders are not equal.
  bool operator!=(const RefStructure& obj) const
  {
    return !(operator==(obj));
  }

  /// Accesses the held structure through the underlying owning pointer.
  ///
  /// @return Reference to the held `unique_ptr<T>`; null if the holder is empty.
  unique_ptr<T>& operator->()
  {
    return mValue;
  }

  /// Accesses the held structure through the underlying owning pointer.
  ///
  /// @return Reference to the held `unique_ptr<T>`; null if the holder is empty.
  const unique_ptr<T>& operator->() const
  {
    return mValue;
  }

  /// Dereferences to the held structure.
  ///
  /// @return Reference to the held `T`.
  /// @pre The holder is non-empty (`operator bool()` is `true`); otherwise the
  ///      behaviour is undefined.
  T& operator*()
  {
    return *mValue;
  }

  /// Dereferences to the held structure.
  ///
  /// @return Reference to the held `T`.
  /// @pre The holder is non-empty (`operator bool()` is `true`); otherwise the
  ///      behaviour is undefined.
  const T& operator*() const
  {
    return *mValue;
  }

  /// Returns whether a structure is held.
  ///
  /// @return `true` if a structure is held, `false` if the holder is empty.
  operator bool() const
  {
    return (mValue != nullptr);
  }

  /// Returns a non-owning pointer to the held structure.
  ///
  /// @return Pointer to the held `T`, or `nullptr` if the holder is empty. Ownership
  ///         is retained by this holder; the pointer is valid only for its lifetime.
  T* get()
  {
    return mValue.get();
  }

  /// Returns a non-owning pointer to the held structure.
  ///
  /// @return Pointer to the held `T`, or `nullptr` if the holder is empty. Ownership
  ///         is retained by this holder; the pointer is valid only for its lifetime.
  const T* get() const
  {
    return mValue.get();
  }

  /// Returns the underlying owning pointer for direct manipulation.
  ///
  /// @return Reference to the held `unique_ptr<T>`. Mutating it (e.g. `reset`) bypasses
  ///         the cloning semantics of the copy/assign overloads.
  unique_ptr<T>& inner_unique_ptr()
  {
    return mValue;
  }

  /// Returns the underlying owning pointer for inspection.
  ///
  /// @return Reference to the held `unique_ptr<T>`; null if the holder is empty.
  const unique_ptr<T>& inner_unique_ptr() const
  {
    return mValue;
  }

  /// Returns the OPC UA built-in type id of the held structure type.
  ///
  /// @return The @ref BuiltInTypeId reported by `T`. Independent of whether a
  ///         structure is currently held.
  static BuiltInTypeId built_in_type_id()
  {
    return T::built_in_type_id();
  }

private:
  unique_ptr<T> mValue;

  void copy_from(const unique_ptr<T>& other)
  {
    if (!other)
    {
      mValue.reset();
    }
    else
    {
      unique_ptr<Structure> structure = other->clone();
      mValue.reset(dynamic_cast<T*>(structure.release()));
    }
  }
};

}  // namespace ua

#endif  // !UA_REF_STRUCTURE_H
