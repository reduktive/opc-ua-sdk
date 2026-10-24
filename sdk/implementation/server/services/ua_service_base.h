// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SERVICE_BASE_H
#define UA_SERVICE_BASE_H

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/system/error_code.hpp>
#include "ua_logger.h"
#include "ua_on_strand.h"
#include "ua_timer.h"
#include "ua_service.h"

namespace ua::server
{

class SessionInfo;

/// Returns the @ref ua::Logger of the session @p session refers to, or a null
/// (no-op) Logger if the session is already gone.
///
/// Out-of-line so `ua_service_base.h` need not pull in the full `SessionInfo`
/// definition (and the heavy `ua_server.h` behind it). A @ref ua::Logger is a
/// value handle, so the returned copy keeps logging working even after the
/// session - and the server behind it - has been destroyed, which is exactly
/// the situation a drain continuation guarded by @ref ua::async::guarded faces.
///
/// Lives directly in `ua::server` (not a `detail` sub-namespace) deliberately: a
/// `ua::server::detail` would shadow `ua::detail` for the many unqualified
/// `detail::` references inside `ua::server`.
///
/// @param session Weak reference to the owning session; not retained.
/// @return The session's logger, or a default no-op logger if it has expired.
Logger logger_of(const weak_ptr<SessionInfo>& session);

/// CRTP base for server service classes. Provides the common members and
/// boilerplate that every service shares (strand, timeout timer, session
/// info, deleted copy/move, and the `start()` / `set_timeout()` patterns).
///
/// Derived classes must:
///   - Declare `friend class ServiceBase<Derived>;`
///   - Provide a `void begin_processing()` member function that kicks off
///     the per-service callback chain (returns immediately; subsequent
///     work runs through continuations on the per-service flow struct).
template<typename Derived>
class ServiceBase : public Service, public std::enable_shared_from_this<Derived>
{
public:
  ServiceBase() = delete;
  ServiceBase(const ServiceBase&) = delete;
  ServiceBase(ServiceBase&&) noexcept = delete;
  ServiceBase& operator=(const ServiceBase&) = delete;
  ServiceBase& operator=(ServiceBase&&) noexcept = delete;
  ~ServiceBase() override = default;

protected:
  weak_ptr<SessionInfo> mSessionInfo;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  Timer mTimeoutTimer;
  bool mFinished{false};
  /// Logger for this service's async work, sourced from the owning session at construction and held
  /// by value (a @ref ua::Logger is a cheap value handle), so it survives the session's - and the
  /// server's - destruction. That is the property the post helpers rely on: a continuation posted to
  /// @ref mStrand may run during shutdown drain, after the session is gone, and @ref ua::async::guarded
  /// still needs a usable logger to record (rather than silently discard) a dead-dependency exception.
  /// Passed in at each post call site (never exposed via a public getter). Session-less services (the
  /// second constructor) leave it a default no-op logger unless they set it themselves.
  Logger mLogger;

  ServiceBase(
    IntegerId requestHandle, weak_ptr<SessionInfo> sessionInfo, boost::asio::any_io_executor executor)
    : Service(requestHandle), mSessionInfo(std::move(sessionInfo)),
      mStrand(boost::asio::make_strand(executor)), mLogger(logger_of(mSessionInfo))
  {}

  /// Constructor for session-less services (e.g. DiscoveryServiceSet).
  ServiceBase(IntegerId requestHandle, boost::asio::any_io_executor executor)
    : Service(requestHandle), mStrand(boost::asio::make_strand(executor))
  {}

  /// Atomically marks the service as finished and cancels the timeout timer.
  /// Returns true if this call transitioned the service to finished state,
  /// false if it was already finished (i.e. the callback was already invoked).
  bool try_finish()
  {
    if (mFinished)
      return false;
    mFinished = true;
    if (mTimeoutTimer)
      mTimeoutTimer.cancel();
    return true;
  }

  /// Posts the derived class's `begin_processing()` hook onto the strand.
  /// Called from the static `create()` factory after construction. Strong
  /// `self` capture keeps the freshly-created service alive across the
  /// post-to-strand window - at the call site the only existing strong
  /// owner is the local in `create()` returning to the caller, so a weak
  /// capture would race the caller storing the returned shared_ptr.
  void start()
  {
    ::ua::async::post_owning(
      static_cast<Derived*>(this), mStrand, mLogger, [](Derived& self) { self.begin_processing(); })();
  }

  /// Common timeout implementation. Derived passes the timeout hint from its
  /// request header. The timeout callback calls `static_cast<Derived*>(this)->timeout()`.
  void set_timeout(uint32_t timeoutHint)
  {
    if (timeoutHint == 0)
    {
      return;
    }

    auto me = this->weak_from_this();

    mTimeoutTimer = Timer::schedule_after(mStrand,
      std::chrono::milliseconds(timeoutHint),
      [me](boost::system::error_code ec)
      {
        if (ec)
        {
          return;
        }

        if (auto service = me.lock())
        {
          service->timeout();
        }
      });
  }
};

}  // namespace ua::server

#endif  // !UA_SERVICE_BASE_H
