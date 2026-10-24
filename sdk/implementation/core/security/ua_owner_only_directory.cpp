// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_owner_only_directory.h"

#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_status.h"

#include <cerrno>
#include <string>

#ifdef _WIN32
#include <random>
#else
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace ua::security
{

namespace
{

[[noreturn]] void refuse_private_directory(
  const std::filesystem::path& directory, std::string_view reason, std::string_view source)
{
  throw UaException{Status::BadConfigurationError,
    ErrorDetail::build("PrivateDirectoryRejected", std::string{reason}, std::string{source})
      .context(ua::ContextKeys::filePath, directory.string())};
}

}  // namespace

void ensure_owner_only_directory(const std::filesystem::path& directory, std::string_view source)
{
  std::error_code error;
#ifdef _WIN32
  std::filesystem::create_directories(directory, error);
  if (error)
  {
    refuse_private_directory(directory, "the private directory could not be created", source);
  }
#else
  const auto status = std::filesystem::symlink_status(directory, error);
  if (error || !std::filesystem::exists(status))
  {
    // Owner-only from the start (mkdir 0700), so there is no window in which another user can enter
    // it; a concurrent creator that won the race is verified like an existing directory below.
    if (::mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST)
    {
      refuse_private_directory(directory, "the private directory could not be created", source);
    }
  }
  const auto verified = std::filesystem::symlink_status(directory, error);
  if (error || std::filesystem::is_symlink(verified) || !std::filesystem::is_directory(verified))
  {
    refuse_private_directory(directory, "the private directory path is a link or not a directory", source);
  }

  struct stat info
  {};

  if (::lstat(directory.c_str(), &info) != 0)
  {
    refuse_private_directory(directory, "the private directory cannot be inspected", source);
  }
  if (info.st_uid != ::geteuid())
  {
    refuse_private_directory(directory, "the private directory is owned by another user", source);
  }
  if ((info.st_mode & 077) != 0)
  {
    refuse_private_directory(
      directory, "the private directory is accessible to other users (mode must be 0700)", source);
  }
#endif
}

std::filesystem::path private_user_directory(std::string_view name, std::string_view source)
{
  std::error_code error;
#ifdef _WIN32
  const auto directory = std::filesystem::temp_directory_path(error) / std::string{name};
#else
  const auto directory =
    std::filesystem::temp_directory_path(error) / (std::string{name} + "-" + std::to_string(::geteuid()));
#endif
  ensure_owner_only_directory(directory, source);
  return directory;
}

std::filesystem::path create_owner_only_subdirectory(
  const std::filesystem::path& parent, std::string_view prefix, std::string_view source)
{
#ifdef _WIN32
  std::random_device entropy;
  for (int attempt = 0; attempt < 16; ++attempt)
  {
    const auto candidate =
      parent / (std::string{prefix} + std::to_string(entropy()) + std::to_string(entropy()));
    std::error_code error;
    if (std::filesystem::create_directory(candidate, error))
    {
      return candidate;
    }
  }
  refuse_private_directory(parent, "no instance directory could be created", source);
#else
  std::string pattern = (parent / (std::string{prefix} + "XXXXXX")).string();
  if (::mkdtemp(pattern.data()) == nullptr)
  {
    refuse_private_directory(parent, "no instance directory could be created", source);
  }
  return std::filesystem::path{pattern};
#endif
}

bool create_directories_owner_only(const std::filesystem::path& directory, std::error_code& error)
{
  const bool created = std::filesystem::create_directories(directory, error) && !error;
  if (created)
  {
    std::filesystem::permissions(
      directory, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, error);
  }
  return created;
}

}  // namespace ua::security
