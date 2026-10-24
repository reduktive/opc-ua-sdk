// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "test_utilities.h"
#include "ua_guid.h"

#include <optional>
#include <mutex>
#include <system_error>
#include <vector>

using namespace std::chrono_literals;

namespace ua::test_utils
{

namespace
{
// Trust-list roots allocated by create_default_config in this process, reclaimed by
// cleanup_process_trust_list_dirs at the end of the run. Guarded because fixtures
// may build configurations off the test's own worker threads.
std::mutex gTrustListPathsMutex;
std::vector<std::filesystem::path> gTrustListPaths;

void register_trust_list_path(const std::filesystem::path& path)
{
  const std::lock_guard lock{gTrustListPathsMutex};
  gTrustListPaths.push_back(path);
}
}  // namespace

namespace detail
{

void remove_trust_list_dirs(
  const std::vector<std::filesystem::path>& roots, const std::vector<std::filesystem::path>& parents)
{
  std::error_code ec;
  for (const auto& root : roots)
  {
    std::filesystem::remove_all(root, ec);
  }

  for (const auto& parent : parents)
  {
    std::filesystem::remove(parent, ec);
  }
}

}  // namespace detail

void cleanup_process_trust_list_dirs()
{
  std::vector<std::filesystem::path> roots;
  {
    const std::lock_guard lock{gTrustListPathsMutex};
    roots.swap(gTrustListPaths);
  }

  // Innermost first: each parent is only removable once its children are gone.
  detail::remove_trust_list_dirs(
    roots, {"./temp/test_pki/app", "./temp/test_pki/user", "./temp/test_pki", "./temp"});
}

void set_identity_fields(ua::ApplicationIdentity& identity)
{
  identity.productUri = "uri://reduktive.com/opcua/TestServer";
  identity.applicationName.text() = "reduktive Test Server";
  identity.applicationType = ApplicationType::Server;

  identity.buildInfo.build_date() = DateTime::now();
  identity.buildInfo.manufacturer_name() = "reduktive";
  identity.buildInfo.product_name() = "Test Server";
  identity.buildInfo.product_uri() = identity.productUri;
  identity.buildInfo.software_version() = "0.1";
}

ua::ApplicationConfig create_default_config()
{
  auto config = ua::ApplicationConfig::load_default();

  // Each test gets a unique trust list directory to avoid cross-test key/password collisions.
  // Both roots are registered for end-of-run deletion: the SDK materialises seven subdirectories
  // under each, so leaving them behind grows the build tree without bound across runs.
  auto uniqueId = Guid::create_and_generate().as_string();
  const auto appPath = std::filesystem::path{"./temp/test_pki/app/" + uniqueId};
  const auto userPath = std::filesystem::path{"./temp/test_pki/user/" + uniqueId};
  register_trust_list_path(appPath);
  register_trust_list_path(userPath);
  config.file_trust_list_configuration().defaultApplicationGroupTrustListPath = appPath;
  config.file_trust_list_configuration().defaultUserTokenGroupTrustListPath = userPath;
  // NOT armed. The SDK default is a 5s trust-list refresh timer, and a test that stands up a server
  // then drains its pool waits for that timer to fire before join() returns - about 5.2s per test,
  // uniformly, in every suite that creates a Server. Nothing here exercises refresh; the one test
  // that does (ConfigurationTrust.TrustListRefreshPeriod*) sets its own period. An unset period
  // skips arming entirely - see CertificateStoreFiles::initialise_file_system_monitoring.
  config.file_trust_list_configuration().trustListRefreshPeriod = std::nullopt;

  config.application_description_part().applicationUri =
    std::string{"uri://reduktive.com/TestServer/"} + uniqueId;

  // Most tests drive None endpoints deliberately, on both sides: a Server refuses to expose one and a
  // client refuses to create a Session over one unless the application opts in. Security-specific
  // suites override this back to false where the rejection itself is under test.
  config.allowInsecureEndpoints = true;

  return config;
}

ua::ApplicationConfig create_test_config()
{
  return create_default_config();
}

ua::client::CreateConfig create_test_client_config()
{
  return ua::client::CreateConfig{
    .identity = ua::ApplicationIdentity::load_default(), .application = create_test_config()};
}

}  // namespace ua::test_utils