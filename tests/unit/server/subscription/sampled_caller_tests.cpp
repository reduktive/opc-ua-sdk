// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The caller a sampling read is made for (NR-49, NR-70 A3): a sink answers its Subscription's current caller,
// the Session's security context keeps one CallerInfo and replaces it with its identity, and each sampling
// tick reads every due item with its sink's caller of that tick. Also the MonitoringRoute arm that observes
// the caller passed to `create_monitoring_async`, which needs a security context overriding `caller()`.

#include "monitoring_release_fixture.h"

#include "../sdk/implementation/server/session/ua_server_session.h"
#include "../sdk/implementation/server/session/ua_server_session_test_access.h"
#include "ua_sample_sink_impl.h"

#include "ua_default_namespace.h"
#include "ua_event_bus.h"
#include "ua_instance_utils.h"
#include "ua_namespace_monitoring.h"
#include "ua_orphaned_subscription_store.h"
#include "ua_request_info.h"
#include "ua_server_components.h"
#include "ua_sinks.h"
#include "ua_subscription_id_allocator.h"
#include "ua_subscription_router.h"
#include "ua_value_source.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace ua::test::monitoring_release;

namespace
{

/// A Session security context whose `caller()` answers the CallerInfo the test gives. Its other members are
/// @p inner's where one is given (so a Subscription can authorize with it), else the caller's.
class CallerSecurityContext final : public server::SessionSecurityContext
{
public:
  CallerSecurityContext(
    std::shared_ptr<const server::SessionSecurityContext> inner, std::shared_ptr<const CallerInfo> caller)
    : mInner(std::move(inner)), mCaller(std::move(caller))
  {}

  NodeId session_id() const override
  {
    return mInner ? mInner->session_id() : mCaller->sessionId;
  }

  std::shared_ptr<const EndpointSecurityContext> endpoint_security() const override
  {
    return mInner ? mInner->endpoint_security() : nullptr;
  }

  std::shared_ptr<const UserIdentity> user_identity() const override
  {
    return mInner ? mInner->user_identity() : nullptr;
  }

  std::shared_ptr<const AccessIdentity> access_identity() const override
  {
    return mInner ? mInner->access_identity() : mCaller->identity;
  }

  std::shared_ptr<const CallerInfo> caller() const override
  {
    return mCaller;
  }

private:
  std::shared_ptr<const server::SessionSecurityContext> mInner;
  std::shared_ptr<const CallerInfo> mCaller;
};

/// A sink that records what it is pushed. It does not override `caller()`.
class RecordingSink : public SampleSink
{
public:
  void push(std::vector<std::pair<IntegerId, DataValue>> samples) override
  {
    const std::lock_guard lock{mMutex};
    for (auto& sample : samples)
    {
      mSamples.push_back(std::move(sample));
    }
  }

  void invalidate(IntegerId monitoredItemId, StatusCode reason) override
  {
    (void)monitoredItemId;
    (void)reason;
  }

  void detach() override
  {}

  std::vector<std::pair<IntegerId, DataValue>> samples() const
  {
    const std::lock_guard lock{mMutex};
    return mSamples;
  }

private:
  mutable std::mutex mMutex;
  std::vector<std::pair<IntegerId, DataValue>> mSamples;
};

/// A sink whose `caller()` answers the CallerInfo the test sets.
class CallerSink final : public RecordingSink
{
public:
  explicit CallerSink(std::shared_ptr<const CallerInfo> caller) : mCaller(std::move(caller))
  {}

  void set_caller(std::shared_ptr<const CallerInfo> caller)
  {
    const std::lock_guard lock{mCallerMutex};
    mCaller = std::move(caller);
  }

  std::shared_ptr<const CallerInfo> caller() const override
  {
    const std::lock_guard lock{mCallerMutex};
    return mCaller;
  }

private:
  mutable std::mutex mCallerMutex;
  std::shared_ptr<const CallerInfo> mCaller;
};

/// A sink whose `caller()` throws.
class ThrowingCallerSink final : public RecordingSink
{
public:
  std::shared_ptr<const CallerInfo> caller() const override
  {
    throw std::runtime_error{"the test sink's caller() throws"};
  }
};

/// The identity each read of a Variable's Value was made for, in order. Holds the address only: the identity
/// is valid only until the handler returns, and the test keeps the identities it compares with alive.
class ReadLog
{
public:
  void record(const AccessIdentity* identity)
  {
    const std::lock_guard lock{mMutex};
    mReads.push_back(identity);
  }

  std::vector<const AccessIdentity*> reads() const
  {
    const std::lock_guard lock{mMutex};
    return mReads;
  }

private:
  mutable std::mutex mMutex;
  std::vector<const AccessIdentity*> mReads;
};

std::shared_ptr<const UserIdentity> make_user(const std::string& userId)
{
  auto user = std::make_shared<UserIdentity>();
  user->userId = userId;
  user->displayName = userId;
  user->kind = UserTokenKind::UserName;
  return user;
}

std::shared_ptr<const EndpointSecurityContext> make_endpoint()
{
  auto endpoint = std::make_shared<EndpointSecurityContext>();
  endpoint->endpointPolicyId = "Test/SignAndEncrypt";
  endpoint->messageSecurityMode = MessageSecurityMode::SignAndEncrypt;
  endpoint->securityPolicyId = SecurityPolicyId::Basic256Sha256;
  return endpoint;
}

std::shared_ptr<const AccessIdentity> make_identity(uint64_t key, const std::string& userId)
{
  return std::make_shared<const AccessIdentity>(AccessIdentityKey{key},
    std::vector<NodeId>{},
    make_user(userId),
    make_endpoint(),
    String{"urn:test:sampled-caller:client"});
}

std::shared_ptr<const CallerInfo> make_caller(
  std::shared_ptr<const AccessIdentity> identity, NodeId sessionId)
{
  auto caller = std::make_shared<CallerInfo>();
  caller->identity = std::move(identity);
  caller->sessionId = std::move(sessionId);
  caller->clientUserId = String{"test"};
  caller->channelSecurityMode = MessageSecurityMode::SignAndEncrypt;
  return caller;
}

/// The SessionDependencies a Session's security context reaches for its Role refresh; it has no Role
/// configuration, so the context answers the identity committed to it.
class FakeSessionDeps final : public server::SessionDependencies
{
public:
  explicit FakeSessionDeps(boost::asio::any_io_executor executor)
    : mExecutor(executor), mAppCfg(ApplicationConfig::load_default())
  {}

  weak_ptr<DiscoveryDependencies> discovery_dependencies() override
  {
    return {};
  }

  boost::asio::any_io_executor executor() override
  {
    return mExecutor;
  }

  shared_ptr<const Crypto> crypto() override
  {
    return nullptr;
  }

  WeakAddressSpace address_space() override
  {
    return {};
  }

  const ApplicationConfig& configuration() override
  {
    return mAppCfg;
  }

  const ServerConfig& server_configuration() override
  {
    return mServerCfg;
  }

  shared_ptr<CertificateStore> default_application_group_certificate_store() override
  {
    return nullptr;
  }

  StructureFactory& structure_factory() override
  {
    throw UaException{
      Status::BadInternalError, make_error_detail("TestError", "Not used in this test", "Test")};
  }

  std::vector<ServerEndpointConfig> endpoints() override
  {
    return {};
  }

  void remove_session(const shared_ptr<server::Session>&) override
  {}

  const ServerComponents& components() const override
  {
    return mHooks;
  }

  std::shared_ptr<ServerObserver> observer() override
  {
    return nullptr;
  }

  Logger logger() override
  {
    return {};
  }

  std::shared_ptr<RequestLatencyTracker> latency_tracker() override
  {
    return nullptr;
  }

  std::shared_ptr<ServerSummaryCounters> summary_counters() override
  {
    return nullptr;
  }

  std::shared_ptr<std::atomic<bool>> diagnostics_enabled() override
  {
    return nullptr;
  }

  SubscriptionIdAllocator& subscription_id_allocator() override
  {
    return mSubscriptionIdAllocator;
  }

  SubscriptionRouter& subscription_router() override
  {
    return mSubscriptionRouter;
  }

  OrphanedSubscriptionStore& orphaned_subscription_store() override
  {
    return mOrphanedSubscriptionStore;
  }

  EventBus& event_bus() override
  {
    return mEventBus;
  }

  std::shared_ptr<EventBus> event_bus_shared() override
  {
    return {};
  }

  std::shared_ptr<NodeManagementDelegate> node_management_delegate() override
  {
    return nullptr;
  }

  optional<StatusCode> begin_identity_attempt(const server::ClientId&, std::string_view) override
  {
    return std::nullopt;
  }

  void finish_identity_attempt(
    const server::ClientId&, std::string_view, server::IdentityAttemptOutcome) override
  {}

  std::shared_ptr<std::atomic<uint32_t>> in_flight_discovery_requests() override
  {
    return nullptr;
  }

private:
  SubscriptionIdAllocator mSubscriptionIdAllocator;
  SubscriptionRouter mSubscriptionRouter;
  OrphanedSubscriptionStore mOrphanedSubscriptionStore;
  boost::asio::any_io_executor mExecutor;
  EventBus mEventBus{AddressSpace::create("", mExecutor)};
  ApplicationConfig mAppCfg;
  ServerConfig mServerCfg;
  ServerComponents mHooks;
};

}  // namespace

class SampledCaller : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mAddressSpace.emplace(AddressSpace::create("urn:test", mExecutor));
    mNamespace = default_ns::Namespace::create("urn:test:sampled-caller", mExecutor);
    auto index = mAddressSpace->try_add_namespace_sync(mNamespace);
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    mIndex = index.value();
    create_variable(NodeId{mIndex, 1u}, 1.0);
    create_variable(NodeId{mIndex, 2u}, 2.0);
  }

  void TearDown() override
  {
    if (mNamespace)
    {
      if (!mHandles.empty())
      {
        auto released = std::make_shared<std::promise<void>>();
        auto done = released->get_future();
        mNamespace->delete_monitoring_async(
          RequestInfo{}, mHandles, [released](BatchResult<VoidResult>) { released->set_value(); });
        (void)done.wait_for(5s);
      }
      mNamespace->shutdown_async([](VoidResult) {});
    }
    mNamespace.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  void create_variable(const NodeId& nodeId, double value)
  {
    auto node = mAddressSpace->create_node_sync(nodeId, NodeClass::Variable);
    auto accessor = node.as<VariableAccessor>();
    ASSERT_TRUE(accessor.has_value());
    accessor->set_browse_name(QualifiedName{nodeId.namespace_index(), "Value"});
    accessor->set_data_type(NodeId{DataTypeId::Double});
    accessor->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
    accessor->write_value_sync(Variant{value});
  }

  /// Gives @p nodeId a value read handler that records the identity of each read in @p log and answers 1.0.
  void install_read_log(const NodeId& nodeId, std::shared_ptr<ReadLog> log)
  {
    auto installed = std::make_shared<std::promise<VoidResult>>();
    auto future = installed->get_future();
    ua::instance_utils::resolve_and_set_value_source_async(*mAddressSpace,
      nodeId,
      ua::make_value_source(
        [log](const ValueSource::ReadContext& context,
          const Node&,
          const ReadValueId&,
          std::function<void(DataValueResult)>
            done)
        {
          log->record(context.caller != nullptr ? context.caller->identity.get() : nullptr);
          done(DataValue{Variant{1.0}});
        }),
      [installed](VoidResult result) { installed->set_value(std::move(result)); });
    ASSERT_EQ(future.wait_for(5s), std::future_status::ready) << "the read handler was not installed";
    const auto result = future.get();
    ASSERT_TRUE(result.is_good()) << to_string(result.status_code());
  }

  /// Registers a polled monitoring of @p nodeId's Value through the namespace, delivering to @p sink.
  void register_polled(const NodeId& nodeId, IntegerId monitoredItemId, std::shared_ptr<SampleSink> sink)
  {
    MonitoringCreateItem item;
    item.nodeId = nodeId;
    item.attributeId = AttributeId::Value;
    item.monitoredItemId = monitoredItemId;
    item.samplingInterval = 50;
    item.queueSize = 1;
    item.sink = std::move(sink);
    auto answered = std::make_shared<std::promise<BatchResult<MonitoringCreateItemResult>>>();
    auto future = answered->get_future();
    mNamespace->create_monitoring_async(RequestInfo{},
      nullptr,
      std::span<const MonitoringCreateItem>{&item, 1},
      [answered](BatchResult<MonitoringCreateItemResult> result) { answered->set_value(std::move(result)); });
    ASSERT_EQ(future.wait_for(5s), std::future_status::ready) << "create_monitoring did not answer";
    auto result = future.get();
    ASSERT_TRUE(result.batchStatus.is_good()) << to_string(result.batchStatus.status_code());
    ASSERT_EQ(result.items.size(), 1u);
    ASSERT_TRUE(result.items[0].is_good()) << to_string(result.items[0].status_code());
    mHandles.push_back(result.items[0].value().handle);
  }

  std::shared_ptr<Subscription> make_subscription()
  {
    return Subscription::create(
      1, 1'000'000.0, 100, 3, 0, true, 0, mExecutor, [](IntegerId) {}, [](IntegerId) {});
  }

  /// The Subscription's sample sink, read on its strand, so after every configuration posted before.
  static std::shared_ptr<SampleSink> sample_sink(Subscription& subscription)
  {
    return STA::on_strand(
      subscription, [](auto& guard) -> std::shared_ptr<SampleSink> { return guard.sample_sink(); });
  }

  static void close_and_destroy(std::shared_ptr<Subscription>& subscription)
  {
    std::promise<void> closed;
    auto done = closed.get_future();
    subscription->close_async([&closed] { closed.set_value(); });
    ASSERT_EQ(done.wait_for(5s), std::future_status::ready) << "close_async did not complete";
    std::weak_ptr<Subscription> weak = subscription;
    subscription.reset();
    ASSERT_TRUE(wait_until([&weak] { return weak.expired(); })) << "the Subscription was not destroyed";
  }

  boost::asio::thread_pool mThreadPool{4};
  boost::asio::any_io_executor mExecutor;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<default_ns::Namespace> mNamespace;
  uint16_t mIndex{0};
  std::vector<MonitoringHandle> mHandles;
};

// N overrides only the batched members. The Subscription's Session security context answers C; the create
// passes C's address, the modify and the deletion reach N's batched members with the handle N issued.
// @relation(AC-COMP-ADDRSP-NAMESPACE-MONITORING-ENTRY-01-THE-BATCHED-MEMBERS-ARE-CALLED, scope=function)
TEST_F(MonitoringRoute, TheSubscriptionCallsTheBatchedMembers)
{
  const auto caller = make_caller(mSecurityContext->access_identity(), NodeId{1, uint32_t{1}});
  auto context = std::make_shared<CallerSecurityContext>(mSecurityContext, caller);
  auto subscription = make_subscription();
  subscription->configure_access_recheck(
    std::chrono::hours{1}, context, WeakAddressSpace{*mAddressSpace}, {});
  mRouteA->issue_next({7});

  auto answers = std::make_shared<std::atomic<int>>(0);
  const auto results = create_counted(*subscription, {value_item(NodeId{2, 1u}, 1)}, context, answers);
  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::Good) << to_string(results[0].status_code());
  const auto creates = mRouteA->create_calls();
  ASSERT_EQ(creates.size(), 1u) << "N's create_monitoring_async was not called once";
  EXPECT_EQ(creates[0].items, 1u);
  EXPECT_EQ(creates[0].caller, caller.get()) << "the create was not given the Subscription's current caller";

  const auto modified = modify_counted(
    *subscription, {results[0].monitored_item_id()}, 500, std::make_shared<std::atomic<int>>(0));
  ASSERT_EQ(modified.size(), 1u);
  EXPECT_EQ(modified[0].status_code().as_status(), Status::Good) << to_string(modified[0].status_code());
  EXPECT_EQ(mRouteA->modify_calls(), (std::vector<std::vector<MonitoringHandle>>{{7}}));

  delete_subscription(subscription);
  EXPECT_TRUE(
    wait_until([this] { return mRouteA->delete_calls() == std::vector<std::vector<MonitoringHandle>>{{7}}; }))
    << "after the deletion N's delete_monitoring_async calls released " << text(mRouteA->released_handles())
    << ", not one call with {7}";
}

// The sink does not override caller(), so every sample is read as the server's own read.
// @relation(AC-COMP-ADDRSP-SAMPLED-CALLER-01-A-SINK-WITHOUT-A-CALLER-IS-SAMPLED-AS-THE-SERVERS-OWN-READ, scope=function)
TEST_F(SampledCaller, ASinkWithoutACallerIsSampledAsTheServersOwnRead)
{
  const NodeId variable{mIndex, 1u};
  auto log = std::make_shared<ReadLog>();
  install_read_log(variable, log);
  register_polled(variable, 1, std::make_shared<RecordingSink>());

  ASSERT_TRUE(wait_until([&log] { return log->reads().size() >= 2u; })) << "two samples were not read";
  const auto reads = log->reads();
  for (std::size_t i = 0; i < reads.size(); ++i)
  {
    EXPECT_EQ(reads[i], nullptr) << "sampling read " << i << " was made with an identity";
  }
}

// The security context is the server Session's own kind, committed as ActivateSession commits an identity.
// @relation(AC-COMP-ADDRSP-SAMPLED-CALLER-01-THE-SESSION-KEEPS-ONE-CALLER-REPLACED-WITH-ITS-IDENTITY, scope=function)
TEST_F(SampledCaller, TheSessionKeepsOneCallerReplacedWithItsIdentity)
{
  auto dependencies = std::make_shared<FakeSessionDeps>(mExecutor);
  auto context = SessionTestAccess::new_security_context(dependencies);
  const NodeId sessionId{1, uint32_t{4711}};
  const auto i1 = make_identity(1, "alice");
  const auto i2 = make_identity(2, "bob");

  SessionTestAccess::set_security_context(*context, sessionId, make_endpoint(), make_user("alice"), i1);
  const auto first = context->caller();
  const auto second = context->caller();
  ASSERT_NE(first, nullptr) << "the Session's security context answers no caller";
  EXPECT_EQ(first.get(), second.get()) << "two calls answered two objects";
  EXPECT_EQ(first->identity.get(), i1.get());
  EXPECT_EQ(first->sessionId, sessionId);

  SessionTestAccess::set_security_context(*context, sessionId, make_endpoint(), make_user("bob"), i2);
  const auto third = context->caller();
  const auto fourth = context->caller();
  ASSERT_NE(third, nullptr);
  EXPECT_EQ(third.get(), fourth.get()) << "two calls after the new identity answered two objects";
  EXPECT_NE(third.get(), first.get()) << "the caller was not replaced with the identity";
  EXPECT_EQ(third->identity.get(), i2.get());
}

// Configuring the access re-check again is what TransferSubscriptions does with the new Session's context.
// @relation(AC-COMP-ADDRSP-SAMPLED-CALLER-01-AFTER-A-TRANSFER-THE-SINK-ANSWERS-THE-NEW-SESSIONS-CALLER, scope=function)
TEST_F(SampledCaller, AfterATransferTheSinkAnswersTheNewSessionsCaller)
{
  const auto c1 = make_caller(make_identity(1, "alice"), NodeId{1, uint32_t{1}});
  const auto c2 = make_caller(make_identity(2, "alice"), NodeId{1, uint32_t{2}});
  auto s1 = std::make_shared<CallerSecurityContext>(nullptr, c1);
  auto s2 = std::make_shared<CallerSecurityContext>(nullptr, c2);
  auto subscription = make_subscription();

  subscription->configure_access_recheck(std::chrono::hours{1}, s1, WeakAddressSpace{*mAddressSpace}, {});
  const auto sink = sample_sink(*subscription);
  ASSERT_NE(sink, nullptr);
  EXPECT_EQ(sink->caller().get(), c1.get()) << "the sink does not answer S1's caller";

  subscription->configure_access_recheck(std::chrono::hours{1}, s2, WeakAddressSpace{*mAddressSpace}, {});
  (void)sample_sink(*subscription);
  EXPECT_EQ(sink->caller().get(), c2.get())
    << "after the second configuration the sink does not answer S2's caller";

  close_and_destroy(subscription);
}

// The reads before the change are I1's; once a read is made for I2, none after it is made for I1.
// @relation(AC-COMP-ADDRSP-SAMPLED-CALLER-02-EACH-TICK-READS-FOR-THE-SINKS-CURRENT-CALLER, scope=function)
TEST_F(SampledCaller, EachTickReadsForTheSinksCurrentCaller)
{
  const NodeId variable{mIndex, 1u};
  auto log = std::make_shared<ReadLog>();
  install_read_log(variable, log);
  const auto i1 = make_identity(1, "alice");
  const auto i2 = make_identity(2, "bob");
  auto sink = std::make_shared<CallerSink>(make_caller(i1, NodeId{1, uint32_t{1}}));
  register_polled(variable, 1, sink);

  const auto has = [&log](const AccessIdentity* identity, std::size_t from)
  {
    const auto reads = log->reads();
    return from < reads.size() &&
           std::find(reads.begin() + static_cast<std::ptrdiff_t>(from), reads.end(), identity) != reads.end();
  };
  ASSERT_TRUE(wait_until([&] { return has(i1.get(), 0); })) << "no sampling read was made for I1";
  const auto changedAt = log->reads().size();
  sink->set_caller(make_caller(i2, NodeId{1, uint32_t{1}}));

  // A read for I2, and one more read after it.
  ASSERT_TRUE(wait_until(
    [&]
    {
      const auto reads = log->reads();
      const auto firstI2 =
        std::find(reads.begin() + static_cast<std::ptrdiff_t>(changedAt), reads.end(), i2.get());
      return firstI2 != reads.end() && reads.end() - firstI2 >= 2;
    }))
    << "after the change no sampling read was made for I2 and followed by another";
  const auto reads = log->reads();
  for (std::size_t i = 0; i < changedAt; ++i)
  {
    EXPECT_EQ(reads[i], i1.get()) << "sampling read " << i << ", before the change, was not made for I1";
  }
  const auto firstI2 = static_cast<std::size_t>(
    std::find(reads.begin() + static_cast<std::ptrdiff_t>(changedAt), reads.end(), i2.get()) - reads.begin());
  for (std::size_t i = firstI2 + 1; i < reads.size(); ++i)
  {
    EXPECT_NE(reads[i], i1.get()) << "sampling read " << i
                                  << ", after the first read for I2, was made for I1";
  }
}

// X's caller() throws; Y does not override it. Both are due at the same interval. X's item is answered
// Bad_InternalError for the tick, and Y's is read.
// @relation(AC-COMP-ADDRSP-SAMPLED-CALLER-02-A-SINK-WHOSE-CALLER-THROWS-HAS-ITS-ITEMS-ANSWERED-BAD, scope=function)
TEST_F(SampledCaller, ASinkWhoseCallerThrowsHasItsItemsAnsweredBadInternalError)
{
  auto x = std::make_shared<ThrowingCallerSink>();
  auto y = std::make_shared<RecordingSink>();
  register_polled(NodeId{mIndex, 1u}, 1, x);
  register_polled(NodeId{mIndex, 2u}, 2, y);

  ASSERT_TRUE(wait_until([&] { return !x->samples().empty() && !y->samples().empty(); }))
    << "a sink received no sample: X " << x->samples().size() << ", Y " << y->samples().size();
  const auto xSample = x->samples().front().second;
  const auto xStatus = xSample.status().value_or(StatusCode{Status::Good});
  EXPECT_EQ(xStatus.as_status(), Status::BadInternalError) << to_string(xStatus);
  const auto& detail = xStatus.shared_detail();
  EXPECT_EQ(detail ? detail->code : std::string{"absent"}, "SampleSinkCallerThrew");

  const auto ySample = y->samples().front().second;
  const auto yStatus = ySample.status().value_or(StatusCode{Status::Good});
  EXPECT_EQ(yStatus.as_status(), Status::Good) << to_string(yStatus);
  EXPECT_EQ(ySample.value().as<double>(), 2.0);
}
