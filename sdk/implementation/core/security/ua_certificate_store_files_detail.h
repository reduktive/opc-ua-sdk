// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Internal list-directory replacement used by @ref ua::CertificateStoreFiles (not public API).

#ifndef UA_CERTIFICATE_STORE_FILES_DETAIL_H
#define UA_CERTIFICATE_STORE_FILES_DETAIL_H

#include <filesystem>
#include <functional>
#include <vector>

namespace ua::certificate_store_files_detail
{

/// One list directory to replace: where it lives and how its new content is written.
struct ListReplacement
{
  std::filesystem::path directory;
  std::function<void(const std::filesystem::path& into)> writeNewContent;
  /// Test seam: runs after the current directory was renamed aside and before the fresh one is renamed
  /// in, so a test can make that rename (and the restore) fail. Empty in production.
  std::function<void(const std::filesystem::path& directory)> afterRenamedAsideForTests;
};

/// Replaces the content of the given list directories together: every new list is written into a
/// fresh sibling (`<dir>.new`) first, then each is swapped into place by renaming the current
/// directory aside (`<dir>.old`) and the fresh one in; a failure restores every directory already
/// swapped and removes the fresh ones. `<dir>.old` is removed last. A crash leaves each list under
/// exactly one of its three names, which @ref recover_list_directories puts back at the next start.
void replace_list_directories(const std::vector<ListReplacement>& replacements);

/// Restores the directories of one replacement (the lists that are replaced together) after a crash
/// left it unfinished. When any of them still has a `<dir>.new`, the swap had not finished, so every
/// one is rolled back: a `<dir>.old` becomes `<dir>` again (replacing a new `<dir>` already renamed in)
/// and the `<dir>.new` siblings are removed. When none has, the swap finished and the `<dir>.old`
/// siblings are removed. Either way the pair ends whole: all old or all new.
void recover_list_directories(const std::vector<std::filesystem::path>& directories);

}  // namespace ua::certificate_store_files_detail

#endif  // !UA_CERTIFICATE_STORE_FILES_DETAIL_H
