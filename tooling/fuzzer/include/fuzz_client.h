// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_CLIENT_H
#define FUZZ_CLIENT_H

#include "ua_application_configuration.h"
#include "ua_client_config_bundle.h"

namespace fuzz
{

/// The client configuration every harness needs.
///
/// Each harness drives a None/None channel against the misbehaving server and then creates a
/// Session on it. A client refuses a Session on an unsecured channel unless the application opts
/// in, so without this the session-bearing scenarios are rejected locally and never reach the
/// wire - and because a refusal is reported as an ordinary bad status, the campaign would still
/// run, still emit plausible per-case status codes, and fuzz nothing past channel open. The
/// silence is the danger, which is why this lives in one place rather than being repeated per
/// harness and forgotten in the next one.
inline ua::client::CreateConfig make_insecure_client_config()
{
  auto application = ua::ApplicationConfig::load_default();
  application.allowInsecureEndpoints = true;
  return ua::client::CreateConfig{
    .identity = ua::ApplicationIdentity::load_default(), .application = std::move(application)};
}

}  // namespace fuzz

#endif  // FUZZ_CLIENT_H
