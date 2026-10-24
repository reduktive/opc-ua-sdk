// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Move-only owning wrapper around a `unique_ptr` with value-like access.
/// @ingroup core_types

#ifndef UA_REF_WRAPPER_H
#define UA_REF_WRAPPER_H

#include "ua_utilities.h"
#include "ua_built_in_type_id.h"

namespace ua
{

/// A move-only owning handle that gives value-like access to a heap-allocated `T`.
///
/// Wraps a `unique_ptr<T>` and forwards dereference, member access, and boolean
/// testing to it, so a `RefWrapper<T>` can be used like the pointed-to object
/// while retaining sole ownership of the allocation. Copying is deleted; the
/// wrapper is moved, never duplicated. A default-constructed or moved-from
/// wrapper is empty (holds no object); test with `operator bool` before
/// dereferencing.
///
/// @tparam T Type of the owned object.
/// @ingroup core_types
template<typename T>
class RefWrapper
{
public:
  /// Constructs an empty wrapper that owns no object.
  RefWrapper() = default;

  /// Move-constructs, transferring ownership and leaving @p other empty.
  ///
  /// @param other The wrapper to move from; left empty.
  RefWrapper(RefWrapper&& other) noexcept = default;

  /// Move-assigns, transferring ownership and leaving @p other empty.
  ///
  /// @param other The wrapper to move from; left empty.
  /// @return Reference to this wrapper.
  RefWrapper& operator=(RefWrapper&& other) noexcept = default;

  /// Deleted: a `RefWrapper` is move-only and cannot be copied.
  RefWrapper(const RefWrapper&) = delete;

  /// Deleted: a `RefWrapper` is move-only and cannot be copy-assigned.
  RefWrapper& operator=(const RefWrapper&) = delete;

  /// Destroys the wrapper, releasing any owned object.
  ~RefWrapper() = default;

  /// Constructs by adopting an existing owning pointer.
  ///
  /// @param[in] other Pointer to adopt; ownership is transferred and @p other
  ///                  is left empty. May be null, yielding an empty wrapper.
  explicit RefWrapper(unique_ptr<T>&& other) noexcept : mValue(std::move(other))
  {}

  /// Replaces the owned object by adopting an existing owning pointer.
  ///
  /// Any previously owned object is destroyed before the new one is adopted.
  ///
  /// @param[in] other Pointer to adopt; ownership is transferred and @p other
  ///                  is left empty. May be null, yielding an empty wrapper.
  /// @return Reference to this wrapper.
  RefWrapper& operator=(unique_ptr<T>&& other) noexcept
  {
    mValue = std::move(other);
    return *this;
  }

  /// Provides member access to the owned object.
  ///
  /// @return Reference to the underlying owning pointer; the chained `->`
  ///         resolves to the owned `T`.
  /// @pre The wrapper is non-empty.
  unique_ptr<T>& operator->()
  {
    return mValue;
  }

  /// Provides const member access to the owned object.
  ///
  /// @return Const reference to the underlying owning pointer; the chained `->`
  ///         resolves to the owned `T`.
  /// @pre The wrapper is non-empty.
  const unique_ptr<T>& operator->() const
  {
    return mValue;
  }

  /// Dereferences to the owned object.
  ///
  /// @return Reference to the owned `T`.
  /// @pre The wrapper is non-empty.
  T& operator*()
  {
    return *mValue;
  }

  /// Dereferences to the owned object (const).
  ///
  /// @return Const reference to the owned `T`.
  /// @pre The wrapper is non-empty.
  const T& operator*() const
  {
    return *mValue;
  }

  /// Tests whether the wrapper currently owns an object.
  ///
  /// @return `true` if an object is owned, `false` if empty.
  operator bool() const
  {
    return (mValue != nullptr);
  }

  /// Returns a non-owning pointer to the owned object.
  ///
  /// @return Pointer to the owned `T`, or `nullptr` if empty. Ownership is
  ///         retained by the wrapper; the caller must not delete the pointer
  ///         or use it beyond the wrapper's lifetime.
  T* get()
  {
    return mValue.get();
  }

  /// Returns a non-owning const pointer to the owned object.
  ///
  /// @return Const pointer to the owned `T`, or `nullptr` if empty. Ownership
  ///         is retained by the wrapper; the caller must not delete the pointer
  ///         or use it beyond the wrapper's lifetime.
  const T* get() const
  {
    return mValue.get();
  }

  /// Returns the underlying owning pointer for direct manipulation.
  ///
  /// @return Reference to the wrapped `unique_ptr<T>`. Ownership remains with
  ///         the wrapper unless the caller moves the pointer out.
  unique_ptr<T>& inner_unique_ptr()
  {
    return mValue;
  }

  /// Returns the underlying owning pointer for inspection (const).
  ///
  /// @return Const reference to the wrapped `unique_ptr<T>`.
  const unique_ptr<T>& inner_unique_ptr() const
  {
    return mValue;
  }

private:
  unique_ptr<T> mValue;
};

}  // namespace ua

#endif  // !UA_REF_WRAPPER_H
