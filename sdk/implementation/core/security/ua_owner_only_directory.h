// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Internal helpers that create and verify directories other local users cannot enter (not
/// public API).
///
/// Two policies exist and are kept apart on purpose. The strict one (@ref ensure_owner_only_directory,
/// @ref private_user_directory, @ref create_owner_only_subdirectory) is for SDK-owned state: the
/// directory must be the current user's own and inaccessible to anyone else, or it is refused. The
/// lenient one (@ref create_directories_owner_only) is for an operator-configured location: a directory
/// the SDK creates is owner-only, but one that already exists is the operator's choice and is left as
/// it is (chmod-ing a shared directory such as /tmp would lock other users out).

#ifndef UA_OWNER_ONLY_DIRECTORY_H
#define UA_OWNER_ONLY_DIRECTORY_H

#include <filesystem>
#include <string_view>
#include <system_error>

namespace ua::security
{

/// Ensures @p directory is an owner-only directory of the current user: created 0700 when absent (so
/// there is no window in which another user can enter it; a concurrent creator that won the race is
/// verified like an existing directory), and refused when it exists as a symbolic link, is not a
/// directory, belongs to another user, or is accessible to group or others. On Windows the ownership
/// checks are not available; the directory and any missing parents are created.
/// @param directory The directory to create or verify.
/// @param source    The ErrorDetail source naming the caller.
/// @throws UaException `Bad_ConfigurationError` with code `PrivateDirectoryRejected` and the path as
///         `ContextKeys::filePath` when the directory cannot be created or is refused.
void ensure_owner_only_directory(const std::filesystem::path& directory, std::string_view source);

/// A per-user, owner-only directory `<temp>/<name>-<uid>` (`<temp>/<name>` on Windows) for state that
/// must not be shared with other local users, created or verified by @ref ensure_owner_only_directory.
/// @param name   The directory name before the user suffix.
/// @param source The ErrorDetail source naming the caller.
/// @return The directory's path.
/// @throws UaException as @ref ensure_owner_only_directory.
std::filesystem::path private_user_directory(std::string_view name, std::string_view source);

/// A new, empty directory inside @p parent that no other caller has been given: `mkdtemp` (created
/// 0700, fails rather than reuse) on POSIX, an exclusive create of a random name on Windows. The
/// directory is named @p prefix followed by a unique suffix.
/// @param parent The directory to create it in; normally one verified by @ref ensure_owner_only_directory.
/// @param prefix The leading part of the new directory's name.
/// @param source The ErrorDetail source naming the caller.
/// @return The new directory's path.
/// @throws UaException `Bad_ConfigurationError` with code `PrivateDirectoryRejected` and @p parent as
///         `ContextKeys::filePath` when no directory could be created.
std::filesystem::path create_owner_only_subdirectory(
  const std::filesystem::path& parent, std::string_view prefix, std::string_view source);

/// Creates @p directory and any missing parents, and makes the directory owner-only when this call
/// created it. A directory that already exists is left as it is: this is the lenient policy for an
/// operator-configured location.
/// @param directory The directory to create.
/// @param error     Receives the failure of the create or of the permission change; cleared otherwise.
/// @return Whether this call created @p directory. True with @p error set means it was created but
///         could not be made owner-only.
bool create_directories_owner_only(const std::filesystem::path& directory, std::error_code& error);

}  // namespace ua::security

#endif  // !UA_OWNER_ONLY_DIRECTORY_H
