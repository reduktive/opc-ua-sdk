// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef TEST_STUBS_H
#define TEST_STUBS_H

#include "ua_server.h"
#include "../sdk/implementation/server/session/ua_server_session.h"
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include "ua_event_bus.h"
#include "ua_sinks.h"
#include "ua_server_configuration.h"

#include "ua_session_security.h"
#include "ua_diagnostic_policy.h"
#include "access_control_test_support.h"

#include <memory>
#include <mutex>

using namespace ua;
using namespace ua::server;

class SessionInfoStub : public SessionInfo, public SessionSecurityContext
{
public:
  // A destructor does not block: the shutdown is started and the stub does not wait for it. It completes
  // on the Server's executor, or with BadServerHalted when the Server goes before it can run there.
  ~SessionInfoStub()
  {
    mServer.shutdown_async({}, [](VoidResult) {});
  }

  SessionInfoStub(ua::server::Server server, boost::asio::any_io_executor executor)
    : mServer(std::move(server)), mExecutor(executor), mAddressSpace(mServer.address_space()),
      mConfig(mServer.config().application), mServerConfig(mServer.config().server)
  {
    mEndpointSecurity = std::make_shared<const EndpointSecurityContext>();
    auto security = std::const_pointer_cast<EndpointSecurityContext>(mEndpointSecurity);
    security->endpointPolicyId = "Test/None";
    security->messageSecurityMode = ua::MessageSecurityMode::None;
    security->securityPolicyId = ua::SecurityPolicyId::None;

    mUserIdentity = std::make_shared<const UserIdentity>(
      UserIdentity{.userId = "test", .displayName = "Test", .kind = UserTokenKind::Anonymous});

    mAccessIdentity = ua::test_helpers::configure_test_access(mAddressSpace,
      mUserIdentity,
      mEndpointSecurity,
      ua::test_helpers::all_permissions(),
      {NodeId{ObjectId::WellKnownRole_SecurityAdmin}});
  }

  /// Constructs the fail-closed fixture used by retained tests that predate AccessIdentity.
  ///
  /// The null marker keeps those call sites source-compatible while making their real condition
  /// explicit: the session has no activated access identity.
  SessionInfoStub(
    ua::server::Server server, boost::asio::any_io_executor executor, std::nullptr_t, bool noAccessIdentity)
    : SessionInfoStub(std::move(server), std::move(executor))
  {
    if (noAccessIdentity)
    {
      mAccessIdentity.reset();
    }
  }

  boost::asio::any_io_executor executor() const
  {
    return mExecutor;
  }

  AddressSpace address_space() const override
  {
    return mAddressSpace;
  }

  const ::ua::ApplicationConfig& configuration() const override
  {
    return *mConfig;
  }

  const ::ua::server::ServerConfig& server_configuration() const override
  {
    return mServerConfig;
  }

  // SessionSecurityContext
  ua::NodeId session_id() const override
  {
    return ua::NodeId{1, ua::Guid::create_and_generate()};
  }

  std::shared_ptr<const ua::server::EndpointSecurityContext> endpoint_security() const override
  {
    return mEndpointSecurity;
  }

  /// Put this session in the only state in which a service's DiagnosticInformation is observable.
  ///
  /// The stub defaults to an unsecured channel and the shipped default diagnostic policy, which is
  /// the right default for a service test: it is the weakest configuration a service ever runs on.
  /// Both of those suppress every DiagnosticInfo outright (`ua_diagnostic_policy.h` - gate 1 on an
  /// unsecured channel, and `Level::None` for a caller carrying no diagnostics claim), and neither
  /// lifting alone is sufficient. A test whose subject is the diagnostic a service returns has
  /// nothing to observe until both are lifted, and would otherwise read the suppression as the
  /// service failing to produce the diagnostic at all.
  void enable_operation_diagnostics()
  {
    auto security = std::const_pointer_cast<ua::server::EndpointSecurityContext>(mEndpointSecurity);
    security->messageSecurityMode = ua::MessageSecurityMode::SignAndEncrypt;
    security->securityPolicyId = ua::SecurityPolicyId::Basic256Sha256;
    security->endpointPolicyId = "Test/SignAndEncrypt";
    mServerConfig.diagnosticPolicy.defaultLevel = ua::server::ServerConfig::DiagnosticPolicy::Level::Full;
  }

  std::shared_ptr<const ua::server::UserIdentity> user_identity() const override
  {
    return mUserIdentity;
  }

  std::shared_ptr<const ua::AccessIdentity> access_identity() const override
  {
    return mAccessIdentity;
  }

  void set_access_identity_for_test(std::shared_ptr<const ua::AccessIdentity> identity)
  {
    mAccessIdentity = std::move(identity);
  }

  ua::server::DiagnosticSecurityContext diagnostic_security_context() const override
  {
    return ua::server::detail::make_diagnostic_security_context(
      *mEndpointSecurity, *mUserIdentity, mServerConfig.diagnosticPolicy);
  }

  Logger logger() const override
  {
    return log;
  }

  /// A handle to the sink a test set in @ref eventSink, which the test owns.
  ///
  /// An event bus the test holds in a `shared_ptr` is shared as a server shares its own, so that a weak
  /// reference taken from it lasts exactly as long as the bus, whatever becomes of this Session. Any other
  /// sink is given out through a handle that does not own it, the same one while the pointer is unchanged,
  /// so that a weak reference taken from it stays lockable while the test's sink is set.
  std::shared_ptr<EventSink> event_sink() const override
  {
    if (auto* bus = dynamic_cast<ua::server::EventBus*>(eventSink))
    {
      if (auto owned = bus->weak_from_this().lock())
      {
        return owned;
      }
    }
    const std::lock_guard<std::mutex> lock(mEventSinkMutex);
    if (mEventSinkHandle.get() != eventSink)
    {
      mEventSinkHandle = eventSink ? std::shared_ptr<EventSink>(eventSink, [](EventSink*) {}) : nullptr;
    }
    return mEventSinkHandle;
  }

  EventSink* eventSink{nullptr};

  /// The logger the Session's services log through; disabled unless a test sets one before the service
  /// starts.
  Logger log{};

private:
  mutable std::mutex mEventSinkMutex;
  mutable std::shared_ptr<EventSink> mEventSinkHandle;
  ua::server::Server mServer;
  boost::asio::any_io_executor mExecutor;
  AddressSpace mAddressSpace;
  shared_ptr<const ::ua::ApplicationConfig> mConfig;
  ::ua::server::ServerConfig mServerConfig;

  std::shared_ptr<const ua::server::EndpointSecurityContext> mEndpointSecurity;
  std::shared_ptr<const ua::server::UserIdentity> mUserIdentity;
  std::shared_ptr<const ua::AccessIdentity> mAccessIdentity;
};

#endif  // TEST_STUBS_H
