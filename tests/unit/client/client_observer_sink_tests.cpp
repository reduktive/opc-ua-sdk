// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the Client-scoped observer sink wired into ua::client::CoreClientImpl (W6-prereq / J58,
// client design section 7.8 / wiring section 1). CoreClientImpl now owns a detail::ClientObserverSink
// (constructed eagerly in create() with an empty - Client-scoped - weak ConnectionImpl, so every fire
// delivers a null const Connection*). The W6 PullCertificateManager host shim fires its Client-level
// SecurityObserver hooks through client_observer_sink(). set_security_observer re-installs the security slot
// so a runtime-registered observer is delivered to.
//
// Reached via CoreClientTestAccess::impl (client_observer_sink() is on the impl surface, not the move-only
// Client facade). A single-thread pool runs the async work (the same substrate as the W5 registry-revalidate
// tests): Client::create binds a periodic trust-list-refresh timer to the executor, so a hand-pumped
// io_context would never drain - a background pool is the correct driver. The sink delivers each hook on its
// OWN delivery strand (a pool worker thread), so the fake observer is thread-safe and the test observes
// delivery via a bounded poll on the atomic counter (a hard FAIL on timeout, never an unbounded wait).
//
// Falsifiability: every test asserts the CAPTURED hook + its argument (the delivered certificate's DER bytes
// / the null-ness of the Client-scoped Connection*), not merely that nothing crashed. The re-resolve test
// fires BEFORE registering and AGAIN after, so a missing re-resolve in set_security_observer fails a concrete
// assertion. The replacement test drains the pool and asserts the replaced observer never fired.

#include "stub_x509_certificate.h"  // ua::testing::make_stub_certificate (tests/helpers, on the include path)

#include "ua_client.h"
#include "ua_core_client_impl.h"
#include "ua_client_observers.h"
#include "ua_client_test_hooks.h"
#include "ua_error_detail.h"
#include "ua_observer_sink.h"
#include "ua_x509_certificate.h"

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <gtest/gtest.h>

#include "dev_factories.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace
{

using namespace std::chrono_literals;

using ua::client::Client;
using ua::client::CoreClientImpl;
using ua::client::CoreClientTestAccess;
using ua::client::PullCertLifecycleEvent;
using ua::client::SecurityObserver;

// A thread-safe fake Client-level SecurityObserver: it captures each Client-scoped hook and its argument. The
// counters are atomic and the delivered DER is mutex-guarded because the sink delivers on its own delivery
// strand (a pool worker thread), off the test thread.
class FakeSecurityObserver : public SecurityObserver
{
public:
  std::atomic<int> certRotated{0};
  std::atomic<int> pullCert{0};
  std::atomic<bool> pullCertConnWasNull{false};
  PullCertLifecycleEvent pullCertEvent{};

  void on_certificate_rotated(const ua::X509Certificate& newCert) override
  {
    {
      const std::lock_guard<std::mutex> lock(mMutex);
      mLastRotatedDer = newCert.der_encoding();
    }
    certRotated.fetch_add(1, std::memory_order_release);
  }

  void on_pull_cert_management_lifecycle(const ua::client::Connection* connection,
    PullCertLifecycleEvent event, std::shared_ptr<const ua::ErrorDetail>) override
  {
    pullCertConnWasNull.store(connection == nullptr, std::memory_order_relaxed);
    pullCertEvent = event;
    pullCert.fetch_add(1, std::memory_order_release);
  }

  ua::ByteString last_rotated_der()
  {
    const std::lock_guard<std::mutex> lock(mMutex);
    return mLastRotatedDer;
  }

private:
  std::mutex mMutex;
  ua::ByteString mLastRotatedDer;
};

class ClientObserverSinkOnImpl : public ::testing::Test
{
protected:
  // One worker thread: the delivery-strand fan-out is serialised, so a fence posted after a fire is a true
  // barrier and the bounded polls below observe delivery deterministically.
  boost::asio::thread_pool mPool{1};
  Client mClient = ua::test_helpers::make_dev_client(mPool.get_executor());
  std::shared_ptr<CoreClientImpl> mClientImpl = CoreClientTestAccess::impl(mClient.core());

  // A bounded poll on an atomic delivery counter: a fire that is never delivered must FAIL promptly rather
  // than hang CI, so a timeout is a hard failure (never an unbounded wait).
  static void wait_for_count(std::atomic<int>& counter, int expected)
  {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (counter.load(std::memory_order_acquire) < expected && std::chrono::steady_clock::now() < deadline)
    {
      std::this_thread::sleep_for(1ms);
    }
    ASSERT_GE(counter.load(std::memory_order_acquire), expected);
  }

  // A round-trip fence on the (single-thread) pool executor: after it returns, every task queued on the pool
  // before it has run - so an erroneous stray fire would already be observable.
  void drain_pool()
  {
    std::promise<void> fenced;
    auto future = fenced.get_future();
    boost::asio::post(mPool.get_executor(), [&fenced] { fenced.set_value(); });
    future.get();
  }
};

// The sink exists (eagerly constructed in create()) and is the SAME object every call - the accessor is a
// lock-free read of a set-once member.
TEST_F(ClientObserverSinkOnImpl, ClientObserverSinkIsConstructedEagerlyAndStable)
{
  const auto sink = mClientImpl->client_observer_sink();
  ASSERT_NE(sink, nullptr) << "ClientImpl must own a Client-scoped observer sink from construction";
  EXPECT_EQ(sink.get(), mClientImpl->client_observer_sink().get())
    << "the sink is set once and never swapped";
}

// A Client-level SecurityObserver registered via set_security_observer receives a Client-scoped
// on_certificate_rotated fired through client_observer_sink(), carrying the exact certificate.
TEST_F(ClientObserverSinkOnImpl, ClientSecurityObserverReceivesCertificateRotated)
{
  auto observer = std::make_shared<FakeSecurityObserver>();
  mClient.set_security_observer(observer);

  const auto cert = ua::testing::make_stub_certificate();
  mClientImpl->client_observer_sink()->fire_certificate_rotated(cert);

  wait_for_count(observer->certRotated, 1);
  EXPECT_EQ(observer->last_rotated_der(), cert->der_encoding())
    << "the rotated certificate must be delivered intact to the Client-level SecurityObserver";
}

// The re-resolve proof: an observer registered AFTER construction (a runtime set_security_observer) still
// receives fires. Firing BEFORE registration delivers nothing (the eager sink's security slot is null); after
// registration it does - which only holds if set_security_observer re-installs the slot into the sink.
TEST_F(ClientObserverSinkOnImpl, RuntimeRegisteredSecurityObserverReceivesFires)
{
  // No observer registered yet: the sink's security slot is null, so this fire is a no-op.
  mClientImpl->client_observer_sink()->fire_certificate_rotated(ua::testing::make_stub_certificate());
  drain_pool();

  auto observer = std::make_shared<FakeSecurityObserver>();
  mClient.set_security_observer(observer);  // runtime registration -> must re-resolve into the sink

  mClientImpl->client_observer_sink()->fire_pull_cert_management_lifecycle(
    PullCertLifecycleEvent::CertificateCommitted, nullptr);

  wait_for_count(observer->pullCert, 1);
  EXPECT_EQ(observer->pullCertEvent, PullCertLifecycleEvent::CertificateCommitted);
  EXPECT_TRUE(observer->pullCertConnWasNull.load())
    << "the Client-scoped sink carries no associated Connection, so it delivers a null const Connection*";
  EXPECT_EQ(observer->certRotated.load(), 0)
    << "the pre-registration cert-rotated fire must never reach the later observer";
}

// Replacing the Client-level SecurityObserver at runtime re-resolves the sink: only the current observer
// receives subsequent fires (falsifies a stale-slot regression where the first observer keeps firing).
TEST_F(ClientObserverSinkOnImpl, ReplacingSecurityObserverReresolvesToTheNewOne)
{
  auto first = std::make_shared<FakeSecurityObserver>();
  auto second = std::make_shared<FakeSecurityObserver>();
  mClient.set_security_observer(first);
  mClient.set_security_observer(second);  // wholesale replacement -> re-resolve

  mClientImpl->client_observer_sink()->fire_certificate_rotated(ua::testing::make_stub_certificate());

  wait_for_count(second->certRotated, 1);
  drain_pool();  // any (erroneous) fire to the replaced observer would have run by now
  EXPECT_EQ(first->certRotated.load(), 0) << "the replaced observer must not fire";
  EXPECT_EQ(second->certRotated.load(), 1) << "only the current Client-level observer fires";
}

}  // namespace
