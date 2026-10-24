// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Application-facing helpers for reading and formatting an @ref ua::ErrorDetail cause chain,
///        and for attaching one more application-level link (client design section 7.10.1, section 8.15.5).
/// @ingroup general

#ifndef UA_ERROR_CHAIN_H
#define UA_ERROR_CHAIN_H

#include "ua_error_detail.h"
#include "ua_result.h"
#include "ua_status_code.h"

#include <cstddef>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace ua
{

/// A read-only, outermost-to-innermost view over an @ref ua::ErrorDetail cause chain.
///
/// Construct from a @ref ua::StatusCode (the chain hanging off its attached detail) or a borrowed
/// @ref ua::ErrorDetail. The `StatusCode` overload keeps the chain alive for the view's lifetime, so it is
/// safe over a temporary (e.g. `ErrorChainView{result.status_code()}`); the `ErrorDetail` overload
/// borrows and must not outlive the referenced detail.
/// @ingroup general
class ErrorChainView
{
public:
  /// @param status The status.
  /// Views the chain attached to @p status (empty when the status carries no detail). Holds a shared
  /// reference to the chain, so it is safe over a temporary `StatusCode`.
  explicit ErrorChainView(const StatusCode& status)
    : mKeepAlive(status.shared_detail()), mHead(mKeepAlive.get())
  {}

  /// @param detail Diagnostic detail associated with the notification.
  /// Views the chain rooted at the borrowed @p detail; the caller owns @p detail's lifetime.
  explicit ErrorChainView(const ErrorDetail& detail) : mHead(&detail)
  {}

  /// Rejects binding to a temporary `ErrorDetail:` the view would dangle immediately. Use the
  /// @ref ua::StatusCode overload (which keeps the chain alive) for temporaries.
  explicit ErrorChainView(const ErrorDetail&&) = delete;

  /// Forward iterator yielding `const ErrorDetail&`, outermost link first.
  class iterator
  {
  public:
    /// Callback invoked for iterator category notifications.
    using iterator_category = std::forward_iterator_tag;
    /// Callback invoked for value type notifications.
    using value_type = ErrorDetail;
    /// Callback invoked for reference notifications.
    using reference = const ErrorDetail&;
    /// Callback invoked for pointer notifications.
    using pointer = const ErrorDetail*;
    /// Callback invoked for difference type notifications.
    using difference_type = std::ptrdiff_t;

    iterator() = default;

    /// @param node Target node identifier.
    /// Returns or updates the iterator.
    explicit iterator(const ErrorDetail* node) : mNode(node)
    {}

    /// @return The requested value.
    /// Supports value-handle comparison or assignment.
    reference operator*() const
    {
      return *mNode;
    }

    /// @return The requested value.
    /// Supports value-handle comparison or assignment.
    pointer operator->() const
    {
      return mNode;
    }

    /// @return A reference to this object.
    /// Supports value-handle comparison or assignment.
    iterator& operator++()
    {
      mNode = (mNode != nullptr) ? mNode->cause.get() : nullptr;
      return *this;
    }

    /// @return The requested value.
    /// Supports value-handle comparison or assignment.
    iterator operator++(int)
    {
      iterator prev = *this;
      ++*this;
      return prev;
    }

    /// Supports value-handle comparison or assignment.
    friend bool operator==(const iterator& lhs, const iterator& rhs)
    {
      return lhs.mNode == rhs.mNode;
    }

    /// Supports value-handle comparison or assignment.
    friend bool operator!=(const iterator& lhs, const iterator& rhs)
    {
      return lhs.mNode != rhs.mNode;
    }

  private:
    const ErrorDetail* mNode = nullptr;
  };

  /// @return The requested value.
  /// Returns or updates the begin.
  [[nodiscard]] iterator begin() const
  {
    return iterator{mHead};
  }

  /// @return The requested value.
  /// Returns or updates the end.
  [[nodiscard]] iterator end() const
  {
    return iterator{nullptr};
  }

  /// @return The requested value.
  /// The number of links in the chain (0 when there is no attached detail).
  [[nodiscard]] std::size_t depth() const
  {
    std::size_t links = 0;
    for (const ErrorDetail* node = mHead; node != nullptr; node = node->cause.get())
    {
      ++links;
    }
    return links;
  }

private:
  std::shared_ptr<const ErrorDetail> mKeepAlive;  // non-null only for the StatusCode overload
  const ErrorDetail* mHead = nullptr;
};

/// Formats a @ref ua::StatusCode and its full @ref ua::ErrorDetail chain as a human-readable, log-scrapable
/// string: outermost link first, each inner link indented one level deeper, with stable `key=value`
/// context rendering. When the status carries no detail, the bare status name/code is returned.
///
/// @param status Status to format.
/// @return The formatted, outermost-first chain text.
[[nodiscard]] std::string format(const StatusCode& status);

/// Attaches one more @ref ua::ErrorDetail link at the application boundary, becoming the outermost link with
/// the existing chain preserved beneath it. A good @p result is returned unchanged (no link added), so
/// annotating a success is a safe no-op. An Uncertain @p result is annotated and keeps its code and, when it
/// holds one, its value.
///
/// @tparam T       Result value type.
/// @param result   Result to annotate.
/// @param code     Machine-readable code for the new link (`server.symbolic.`-free; application code).
/// @param summary  One-line human-readable description of the application-level intent.
/// @param source   Producing component, dot-separated (e.g. `myapp.batch_executor`).
/// @param context  Structured facts for the new link.
/// @return @p result unchanged when good; otherwise a Result carrying the same numeric status with the
///         new outermost link wrapping the original chain, holding @p result's value when it holds one.
template<typename T>
[[nodiscard]] Result<T> annotate(Result<T> result, std::string_view code, std::string summary,
  std::string_view source, std::vector<NamedValue> context = {})
{
  if (result.is_good())
  {
    return result;
  }

  const StatusCode inner = result.status_code();
  auto link = std::make_shared<ErrorDetail>();
  link->code = std::string{code};
  link->summary = std::move(summary);
  link->source = std::string{source};
  link->context = std::move(context);
  link->innerStatus = inner.value();
  link->cause = inner.shared_detail();  // preserve the existing chain beneath

  StatusCode annotated{inner.value(), std::move(link)};
  if constexpr (!std::is_void_v<T>)
  {
    if (result.has_value())
    {
      return detail::held(std::move(result).value(), std::move(annotated));
    }
  }
  return Result<T>{std::move(annotated)};
}

}  // namespace ua

#endif  // !UA_ERROR_CHAIN_H
