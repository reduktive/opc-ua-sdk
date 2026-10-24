// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TESTS_HELPERS_FAKE_CONNECTION_PROTOCOL_DEPS_H
#define UA_TESTS_HELPERS_FAKE_CONNECTION_PROTOCOL_DEPS_H

#include "ua_connection_protocol.h"

namespace ua::test_helpers
{

class FakeConnectionProtocolDeps final : public ua::ConnectionProtocolDependencies
{
public:
  explicit FakeConnectionProtocolDeps(boost::asio::any_io_executor ex);

  boost::asio::any_io_executor executor() override;
  ua::EncodingLimits encoding_limits() const override;
  ua::connection_protocol::Limits connection_protocol_limits() const override;

  ua::Logger logger() override
  {
    return mLogger;
  }

  void set_server_limits(ua::connection_protocol::Limits l);
  void set_encoding_limits(ua::EncodingLimits l);

  /// Installs a real logger so tests can assert on what the ConnectionProtocol logs (e.g. a swallowed
  /// "guarded async continuation" exception). Unset by default -> a null logger, matching production
  /// deps that provide no sink.
  void set_logger(ua::Logger logger);

private:
  boost::asio::any_io_executor mExecutor;
  ua::connection_protocol::Limits mServerLimits;
  ua::EncodingLimits mEncodingLimits;
  ua::Logger mLogger;
};

}  // namespace ua::test_helpers

#endif  // UA_TESTS_HELPERS_FAKE_CONNECTION_PROTOCOL_DEPS_H
