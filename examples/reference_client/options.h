// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef REDUKTIVE_REFERENCE_CLIENT_OPTIONS_H
#define REDUKTIVE_REFERENCE_CLIENT_OPTIONS_H

/// @file
/// @brief Command-line parsing for the reference client.
///
/// All of the Boost.Program_options dependency is confined to this file, so that main.cpp is
/// about the client's lifecycle and nothing else.

#include <filesystem>
#include <optional>
#include <string>

namespace reduktive::reference
{

/// Everything the operator can choose when starting the reference client.
struct Options
{
  std::filesystem::path pkiRoot{"reference-client-pki"};
  std::string endpointUrl{"opc.tcp://127.0.0.1:4840"};
  std::optional<std::filesystem::path> exportCertificate;
  std::optional<std::filesystem::path> trustCertificate;
  bool provisionOnly{false};
  bool showHelp{false};
};

/// Parses the command line, rejecting unknown, malformed, or repeated options.
///
/// This converts syntax and values only. Checks that depend on the selected mode belong with the
/// work that depends on them.
Options parse_options(int argc, char** argv);

/// Prints the accepted options and the environment variable that supplies the key credential.
void print_usage();

}  // namespace reduktive::reference

#endif  // REDUKTIVE_REFERENCE_CLIENT_OPTIONS_H
