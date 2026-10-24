// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#include "options.h"

#include <fmt/format.h>

#include <boost/program_options.hpp>

#include <sstream>
#include <string>
#include <string_view>

namespace reduktive::reference
{
namespace
{
namespace program_options = boost::program_options;

constexpr std::string_view keyCredentialEnvironment = "REDUKTIVE_REFERENCE_KEY_PASSWORD";

/// Declares every accepted option once. Boost.Program_options uses the same description for
/// parsing and for help, so the option list and its documentation cannot drift apart.
program_options::options_description command_line_options()
{
  program_options::options_description description{"Options"};
  auto addOption = description.add_options();
  addOption("help,h", "Show this help");
  addOption("pki",
    program_options::value<std::string>()->value_name("directory"),
    "Persistent PKI root (default: reference-server-pki)");
  addOption("listen",
    program_options::value<std::string>()->value_name("host:port"),
    "UA-TCP bind address (default: 127.0.0.1:4840)");
  addOption("model",
    program_options::value<std::string>()->value_name("NodeSet2.xml"),
    "External demo information model (required to run)");
  addOption("export-certificate",
    program_options::value<std::string>()->value_name("file"),
    "Export this server's public DER certificate");
  addOption("trust-certificate",
    program_options::value<std::string>()->value_name("file"),
    "Trust an operator-approved client DER certificate");
  addOption("provision-only", "Provision/import/export, then exit");
  return description;
}

}  // namespace

/// Renders the option list and reminds the operator that the key credential comes only from the
/// environment.
void print_usage()
{
  std::ostringstream renderedOptions;
  renderedOptions << command_line_options();
  fmt::print(
    "Usage: reference_server [options]\n{}\n"
    "Set {} through your shell or secret provider before running.\n",
    renderedOptions.str(),
    keyCredentialEnvironment);
}

/// Rejects unknown, missing, or repeated scalar options, and accepts both `--option value` and
/// `--option=value`.
Options parse_options(int argc, char** argv)
{
  program_options::variables_map parsed;
  program_options::store(program_options::parse_command_line(argc, argv, command_line_options()), parsed);
  program_options::notify(parsed);

  Options options;
  if (parsed.count("pki") != 0)
  {
    options.pkiRoot = parsed["pki"].as<std::string>();
  }
  if (parsed.count("listen") != 0)
  {
    options.listenAddress = parsed["listen"].as<std::string>();
  }
  if (parsed.count("model") != 0)
  {
    options.modelPath = parsed["model"].as<std::string>();
  }
  if (parsed.count("export-certificate") != 0)
  {
    options.exportCertificate = parsed["export-certificate"].as<std::string>();
  }
  if (parsed.count("trust-certificate") != 0)
  {
    options.trustCertificate = parsed["trust-certificate"].as<std::string>();
  }
  options.provisionOnly = parsed.count("provision-only") != 0;
  options.showHelp = parsed.count("help") != 0;
  return options;
}
}  // namespace reduktive::reference
