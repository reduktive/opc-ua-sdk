// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "fake_connection_protocol_deps.h"

namespace ua::test_helpers
{

FakeConnectionProtocolDeps::FakeConnectionProtocolDeps(boost::asio::any_io_executor ex) : mExecutor(ex)
{
  // Keep limits permissive for decoding in tests.
  mEncodingLimits =
    ua::EncodingLimits{.execution = ua::ExecutionLimits{.decodeWorkLimit = 64, .loopLimit = 100000}};
}

boost::asio::any_io_executor FakeConnectionProtocolDeps::executor()
{
  return mExecutor;
}

ua::EncodingLimits FakeConnectionProtocolDeps::encoding_limits() const
{
  return mEncodingLimits;
}

ua::connection_protocol::Limits FakeConnectionProtocolDeps::connection_protocol_limits() const
{
  return mServerLimits;
}

void FakeConnectionProtocolDeps::set_server_limits(ua::connection_protocol::Limits l)
{
  mServerLimits = l;
}

void FakeConnectionProtocolDeps::set_encoding_limits(ua::EncodingLimits l)
{
  mEncodingLimits = l;
}

void FakeConnectionProtocolDeps::set_logger(ua::Logger logger)
{
  mLogger = std::move(logger);
}

}  // namespace ua::test_helpers
