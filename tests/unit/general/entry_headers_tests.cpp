// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Item 2 (public API review 2026-10): a role's entry header is enough on its own. Only the entry headers
// are included before the test framework, so this file compiles only if they are complete: the
// Connection a Client returns (API-2.1), the Session's service objects (API-2.2), runtime_shutdown for
// Runtime::attach (API-2.3) and fmt formatting of SDK types (API-2.4).

#include "ua_client.h"
#include "ua_client_session.h"
#include "ua_core_client.h"
#include "ua_server.h"

#include <gtest/gtest.h>

#include <exception>
#include <string>
#include <type_traits>
#include <utility>

namespace
{

template<class T>
concept Attachable = requires(ua::Runtime& runtime, T handle) { runtime.attach(std::move(handle)); };

struct WithoutShutdown
{};

// API-2.3: the constraint refuses a type with no runtime_shutdown at the caller's line (a compile-fail
// test, written as a constraint check so it runs in every build), and the SDK's role types satisfy it
// through their own headers.
static_assert(!Attachable<WithoutShutdown>, "a type without runtime_shutdown must not be attachable");
static_assert(Attachable<ua::server::Server>, "ua_server.h must declare runtime_shutdown(Server&, ...)");
static_assert(Attachable<ua::client::Client>, "ua_client.h must declare runtime_shutdown(Client&, ...)");
static_assert(
  Attachable<ua::client::CoreClient>, "ua_core_client.h must declare runtime_shutdown(CoreClient&, ...)");

// API-2.1 and API-2.2: complete types, not forward declarations.
static_assert(sizeof(ua::client::Connection) > 0, "ua_client.h must define Connection");
// API-9.6: the exception converter customers use in their own asynchronous handlers is public, in ua.
static_assert(
  std::is_same_v<decltype(&ua::exception_to_status_code), ua::StatusCode (*)(std::exception_ptr) noexcept>,
  "the entry headers must declare ua::exception_to_status_code");
static_assert(sizeof(ua::client::SessionViewServices) > 0, "ua_client_session.h must define the services");
static_assert(
  sizeof(ua::client::SessionAttributeServices) > 0, "ua_client_session.h must define the services");

TEST(EntryHeaders, SdkTypesFormatThroughTheRoleHeaders)
{
  // API-2.4: ua_fmt.h comes with ua_client.h and ua_server.h.
  EXPECT_EQ(fmt::format("{}", ua::NodeId{2, uint32_t{5}}), "ns=2;i=5");
}

}  // namespace
