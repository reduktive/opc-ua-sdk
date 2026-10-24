// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Core type aliases, lock guards, concepts, and shared definitions for the SDK.
/// @ingroup general

#ifndef UA_DEFINES_H
#define UA_DEFINES_H

#include <mutex>
#include <shared_mutex>
#include <span>
#include <memory>
#include <string_view>
#include <cstdint>
#include <optional>
#include "boost/numeric/conversion/cast.hpp"

/// Suppresses an unused-variable or unused-parameter warning for @p a.
///
/// Evaluates @p a and discards the result via a cast to `void`.
///
/// @param a Expression to mark as deliberately unused.
#define UA_UNUSED(a) (void)(a)

namespace ua
{

using std::byte;
using std::span;

using std::shared_ptr;
using std::unique_ptr;
using std::weak_ptr;

using std::make_shared;
using std::make_unique;

using std::optional;
using std::string_view;

using boost::numeric_cast;

/// Scoped exclusive guard over a `std::mutex`.
using Lock = std::lock_guard<std::mutex>;
/// Scoped shared (reader) guard over a `std::shared_mutex`.
using ReadLock = std::shared_lock<std::shared_mutex>;
/// Scoped exclusive (writer) guard over a `std::shared_mutex`.
using WriteLock = std::unique_lock<std::shared_mutex>;

/// Satisfied when @p T is the same type as at least one type in the pack @p U.
///
/// @tparam T Type being tested.
/// @tparam U Candidate types to match against.
template<typename T, typename... U>
concept IsAnyOf = (std::same_as<T, U> || ...);

/// Satisfied when @p T is an enumeration type.
///
/// @tparam T Type being tested.
template<typename T>
concept IsEnum = std::is_enum<T>::value;

class Structure;

/// Satisfied when @p T derives from @ref ua::Structure (an OPC UA structured type).
///
/// @tparam T Type being tested.
template<typename T>
concept IsStructure = (std::derived_from<T, Structure>);

/// Identifier of an OPC UA transport profile.
/// @ingroup general
enum class TransportProfileId
{
  UaTcpUaScUaBinary = 0  ///< UA-TCP transport with UA-SecureConversation and UA Binary encoding.
};

/// A decoded service response: its numeric type identifier paired with the message body.
///
/// The `uint32_t` is the response message's numeric NodeId; the @ref ua::Structure holds the
/// decoded body. Ownership of the body is shared.
using Response = std::pair<uint32_t, shared_ptr<Structure>>;
/// A decoded service request: its numeric type identifier paired with the message body.
///
/// Shares the layout of `Response` (type identifier plus shared-owned @ref ua::Structure body).
/// @see Response
using Request = Response;

}  // namespace ua

#endif  // !UA_DEFINES_H
