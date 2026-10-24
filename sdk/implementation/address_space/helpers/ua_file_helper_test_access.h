// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#pragma once

#include "ua_status_code.h"

#include <optional>

namespace ua::detail::file_helper_tests
{

/// Arms a ONE-SHOT fault for the next FileHelper create: after the FileType node exists, the first
/// handler install reports @p fault instead of its own result, which drives the rollback path
/// (the node is removed again and @p fault is what the caller receives). Test-only; the production
/// code cannot otherwise be made to fail between node creation and handler installation.
void set_handler_install_fault_for_tests(std::optional<StatusCode> fault);

/// Takes (and clears) the armed fault. Called by the create operation itself.
std::optional<StatusCode> take_handler_install_fault_for_tests();

/// Arms the fault for one scope and clears it on exit, so a create that never reaches the first
/// handler install (or a test that fails before its create) cannot leak the fault into a later
/// test: the slot is process-global, shared by every FileHelper in the process, and is armed only
/// through this guard.
struct ScopedHandlerInstallFault
{
  explicit ScopedHandlerInstallFault(StatusCode fault)
  {
    set_handler_install_fault_for_tests(std::move(fault));
  }

  ~ScopedHandlerInstallFault()
  {
    set_handler_install_fault_for_tests(std::nullopt);
  }

  ScopedHandlerInstallFault(const ScopedHandlerInstallFault&) = delete;
  ScopedHandlerInstallFault& operator=(const ScopedHandlerInstallFault&) = delete;
  ScopedHandlerInstallFault(ScopedHandlerInstallFault&&) = delete;
  ScopedHandlerInstallFault& operator=(ScopedHandlerInstallFault&&) = delete;
};

}  // namespace ua::detail::file_helper_tests
