// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_UNIT_CLIENT_SESSION_CAPTURE_HARNESS_H
#define UA_TESTS_UNIT_CLIENT_SESSION_CAPTURE_HARNESS_H

/// @file
/// @brief Compact capture harness for driving a client @ref ua::client::SessionImpl to Active over a
///        null-connection @ref ua::client::SecureChannelImpl, capturing every outgoing service request and
///        injecting synthetic responses.
///
/// This is a trimmed sibling of the `TestSessionSetup` inside client_session_impl_tests.cpp, shared by the
/// SessionModelAccess and RealSessionOps unit tests. It installs the SecureChannel outgoing-request observer
/// interface (so a test can assert what the client actually sent) and drives the CreateSession handshake to
/// completion with a synthetic response so the channel pending map is clean before the test's own traffic.

#include "ua_application_configuration.h"
#include "ua_certificate_store.h"
#include "ua_create_session_response.h"
#include "ua_crypto.h"
#include "ua_structure.h"
#include "ua_structure_factory.h"

#include "../sdk/implementation/client/secure_channel/ua_client_secure_channel_test_access.h"
#include "../sdk/implementation/client/session/ua_client_session_test_access.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

namespace ua::client::test_capture
{

using namespace std::chrono_literals;

/// Poll @p pred until it returns true or @p timeout elapses.
template<typename Pred>
inline bool wait_until(Pred pred, std::chrono::milliseconds timeout = 2000ms)
{
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (pred())
    {
      return true;
    }
    std::this_thread::sleep_for(5ms);
  }
  return false;
}

/// Minimal SessionDependencies for a None, unauthenticated session.
class FakeSessionDeps : public ua::client::SessionDependencies
{
public:
  explicit FakeSessionDeps(boost::asio::any_io_executor ex)
    : mExecutor(ex), mAppCfg(ua::ApplicationConfig::load_default())
  {}

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  std::shared_ptr<const ua::Crypto> crypto() override
  {
    return nullptr;
  }

  std::shared_ptr<ua::CertificateStore> certificate_store() override
  {
    return nullptr;
  }

  const ua::ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  ua::StructureFactory& structure_factory() override
  {
    return mFactory;
  }

  ua::Logger logger() override
  {
    return {};
  }

  uint32_t service_timeout_ms() override
  {
    return 10000;
  }

  uint32_t default_return_diagnostics() override
  {
    return defaultReturnDiagnostics;
  }

  bool wrap_tier0() override
  {
    return wrapTier0;
  }

  bool wrapTier0 = false;
  uint32_t defaultReturnDiagnostics = 0;

private:
  boost::asio::any_io_executor mExecutor;
  ua::ApplicationConfig mAppCfg;
  ua::StructureFactory mFactory;
};

/// Minimal SecureChannelDependencies for a None null-connection channel.
class FakeChannelDeps : public ua::client::SecureChannelDependencies
{
public:
  explicit FakeChannelDeps(boost::asio::any_io_executor ex)
    : mExecutor(ex), mAppCfg(ua::ApplicationConfig::load_default())
  {}

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  std::shared_ptr<const ua::Crypto> crypto() override
  {
    return nullptr;
  }

  std::shared_ptr<ua::CertificateStore> certificate_store() override
  {
    return nullptr;
  }

  const ua::ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  ua::StructureFactory& structure_factory() override
  {
    return mFactory;
  }

  ua::Logger logger() override
  {
    return {};
  }

  uint32_t service_timeout_ms() override
  {
    return 10000;
  }

  uint32_t default_return_diagnostics() override
  {
    return 0;
  }

private:
  boost::asio::any_io_executor mExecutor;
  ua::ApplicationConfig mAppCfg;
  ua::StructureFactory mFactory;
};

/// A null-connection SessionImpl driven to Active, with outgoing-request capture and response injection.
struct CaptureHarness
{
  std::shared_ptr<FakeChannelDeps> channelDeps;
  std::shared_ptr<FakeSessionDeps> sessionDeps;
  std::shared_ptr<ua::client::SecureChannelImpl> channel;
  std::shared_ptr<ua::client::SessionImpl> session;
  /// Clones of every outgoing service request the client sent through the channel.
  std::shared_ptr<std::vector<std::unique_ptr<ua::Structure>>> capturedRequests;

  using STA = ua::client::SessionTestAccess;
  using SCTA = ua::client::SecureChannelTestAccess;

  /// Build the channel + session and drive the session to Active with the CreateSession handshake consumed.
  static CaptureHarness create_active(boost::asio::any_io_executor ex,
    ua::client::SessionImpl::Config sessionConfig = {}, bool wrapTier0 = false)
  {
    CaptureHarness harness;
    harness.channelDeps = std::make_shared<FakeChannelDeps>(ex);

    harness.channel = ua::client::SecureChannelImpl::create(
      harness.channelDeps,
      nullptr,  // no real connection (test mode)
      ua::connection_protocol::NegotiatedLimits{},
      ua::client::SecureChannelImpl::Config{},
      [](ua::VoidResult) {},
      [](ua::VoidResult) {});

    // Force the channel Open so session requests pass through the send path (which stores the response
    // callback in the channel pending map rather than framing onto a wire).
    SCTA::on_strand(*harness.channel,
      [](auto& g) { g.channel_state() = ua::client::SecureChannelImpl::ChannelState::Open; });

    // Install the outgoing-request capture observer BEFORE the session sends anything.
    harness.capturedRequests = std::make_shared<std::vector<std::unique_ptr<ua::Structure>>>();
    auto captured = harness.capturedRequests;
    SCTA::on_strand(*harness.channel,
      [captured](auto& g)
      {
        g.outgoing_request_observer() = [captured](const ua::Structure& request)
        {
          captured->push_back(request.clone());
        };
      });

    harness.sessionDeps = std::make_shared<FakeSessionDeps>(ex);
    harness.sessionDeps->wrapTier0 = wrapTier0;
    harness.session = ua::client::SessionImpl::create(
      harness.sessionDeps,
      harness.channel,
      std::move(sessionConfig),
      ua::client::SessionImpl::SecurityInfo{},
      [](ua::VoidResult) {},
      [](ua::VoidResult) {});

    // The session starts the CreateSession handshake and parks awaiting a response. Consume it with a
    // synthetic good CreateSessionResponse so the channel pending map is empty before the test's traffic.
    harness.wait_for_pending_request();
    auto createResp = std::make_shared<ua::CreateSessionResponse>();
    createResp->response_header().service_result() = ua::Status::Good;
    createResp->session_id() = ua::NodeId{1, 42};
    createResp->authentication_token() = ua::NodeId{1, 99};
    createResp->revised_session_timeout() = 600000.0;
    harness.inject_channel_response(std::move(createResp));
    wait_until([&]() { return harness.session->is_created(); });

    harness.set_active();
    return harness;
  }

  /// Wrap the impl in a public Session handle (shares ownership; keeps the impl alive while borrowed).
  ua::client::Session session_handle() const
  {
    return STA::wrap(session);
  }

  /// Force the session Active on its strand (send_request requires Active + a bound channel).
  void set_active()
  {
    STA::on_strand(*session, [](auto& g) { g.set_session_active(ua::NodeId{1, 42}, ua::NodeId{1, 99}); });
  }

  /// A copy of the first captured outgoing request of type @p ReqT, or nullopt if none was sent.
  template<typename ReqT>
  std::optional<ReqT> first_captured()
  {
    return SCTA::on_strand(*channel,
      [this](auto&) -> std::optional<ReqT>
      {
        for (const auto& req : *capturedRequests)
        {
          if (const auto* typed = dynamic_cast<const ReqT*>(req.get()))
          {
            return *typed;
          }
        }
        return std::nullopt;
      });
  }

  /// Copies of every captured outgoing request of type @p ReqT, in send order.
  template<typename ReqT>
  std::vector<ReqT> all_captured()
  {
    return SCTA::on_strand(*channel,
      [this](auto&) -> std::vector<ReqT>
      {
        std::vector<ReqT> out;
        for (const auto& req : *capturedRequests)
        {
          if (const auto* typed = dynamic_cast<const ReqT*>(req.get()))
          {
            out.push_back(*typed);
          }
        }
        return out;
      });
  }

  /// Wait until at least one request is parked in the channel pending map.
  bool wait_for_pending_request(std::chrono::milliseconds timeout = 500ms)
  {
    return wait_until([this]()
      { return SCTA::on_strand(*channel, [](auto& g) { return !g.pending_requests().empty(); }); },
      timeout);
  }

  /// Wait until at least @p count requests of type @p ReqT have been captured.
  template<typename ReqT>
  bool wait_for_captured_count(size_t count, std::chrono::milliseconds timeout = 2000ms)
  {
    return wait_until([this, count]() { return all_captured<ReqT>().size() >= count; }, timeout);
  }

  /// Resolve the oldest parked channel request with @p response, resuming the session flow that awaits it.
  bool inject_channel_response(std::shared_ptr<ua::Structure> response)
  {
    return SCTA::on_strand(*channel,
      [resp = std::move(response)](auto& g) mutable
      {
        auto& pending = g.pending_requests();
        if (pending.empty())
        {
          return false;
        }
        auto it = pending.begin();
        auto callback = std::move(it->second);
        pending.erase(it);
        callback(ua::client::SecureChannelImpl::ServiceResponseResult{std::move(resp)});
        return true;
      });
  }

  bool inject_channel_failure(ua::StatusCode status)
  {
    return SCTA::on_strand(*channel,
      [status = std::move(status)](auto& g) mutable
      {
        auto& pending = g.pending_requests();
        if (pending.empty())
          return false;
        auto it = pending.begin();
        auto callback = std::move(it->second);
        pending.erase(it);
        callback(ua::client::SecureChannelImpl::ServiceResponseResult{std::move(status)});
        return true;
      });
  }

  /// Fail any parked channel/session requests and drive the session to Closed so no self-referencing flow
  /// keeps the object graph alive past the pool's teardown.
  void cleanup_sync()
  {
    if (!session)
    {
      return;
    }
    SCTA::on_strand(*channel,
      [](auto& g)
      {
        auto pending = std::move(g.pending_requests());
        g.pending_requests().clear();
        for (auto& [handle, callback] : pending)
        {
          callback(ua::client::SecureChannelImpl::ServiceResponseResult{ua::Status::BadConnectionClosed});
        }
      });

    auto state = STA::on_strand(*session, [](auto& g) { return g.session_state(); });
    using SS = STA::SessionState;
    if (state != SS::Closed && state != SS::Idle)
    {
      STA::on_strand(*session, [](auto& g) { g.inject_channel_error(ua::Status::BadConnectionClosed); });
      STA::on_strand(*session, [](auto& g) { g.inject_channel_error(ua::Status::BadConnectionClosed); });
    }
    STA::strand_barrier(*session);
  }

  /// Drop every executor-pinned shared_ptr so a subsequent pool drain completes.
  void release()
  {
    session.reset();
    channel.reset();
    sessionDeps.reset();
    channelDeps.reset();
    capturedRequests.reset();
  }
};

}  // namespace ua::client::test_capture

#endif  // UA_TESTS_UNIT_CLIENT_SESSION_CAPTURE_HARNESS_H
