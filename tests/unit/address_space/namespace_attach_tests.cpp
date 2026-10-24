// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The namespace context: created only by registration, accepted once, closed when registration
/// fails, and passed on by a namespace that forwards (COMP-ADDRSP-NAMESPACE-CONTEXT).

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

#include "namespace_registration_coordinator_test_access.h"
#include "ua_address_space.h"
#include "ua_address_space_change_events.h"
#include "ua_error_detail.h"
#include "ua_exceptions.h"
#include "ua_history_namespace.h"
#include "ua_namespace.h"
#include "ua_namespace_context.h"
#include "ua_namespace_items.h"
#include "ua_node_accessor.h"
#include "ua_objecttype_id.h"
#include <boost/asio/thread_pool.hpp>

using namespace ua;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

namespace
{

/// Records every on_attached call and the index its context answers; answers each call with the result
/// the test gives it.
class AttachRecordingNamespace final : public Namespace
{
public:
  explicit AttachRecordingNamespace(String uri, VoidResult answer = VoidResult{})
    : mUri(std::move(uri)), mAnswer(std::move(answer))
  {}

  String uri() const override
  {
    return mUri;
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    callback(VoidResult{});
  }

  void find_nodes_async(const RequestInfo&, std::span<const NodeId> nodeIds, std::optional<Duration>,
    std::function<void(BatchResult<NodeResult>)> callback) override
  {
    resolve_each(nodeIds,
      std::move(callback),
      [](const NodeId&, std::function<void(NodeResult)> done)
      { done(NodeResult{StatusCode{Status::BadNodeIdUnknown}}); });
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery>,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    complete(BatchResult<NodeReferencesResult>{VoidResult{StatusCode{Status::BadNotSupported}}, {}});
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem>, Duration,
    bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    complete(BatchResult<DataValueResult>{VoidResult{StatusCode{Status::BadNotSupported}}, {}});
  }

  /// Code that holds a genuine context may call attach (NR-39): the namespace offers the context it holds.
  VoidResult attach_again()
  {
    return attach(context());
  }

  uint16_t index_from_context() const
  {
    return context().index();
  }

  /// Reports through the context, as a namespace reports changes it made itself.
  void report_model_changed(std::span<const ModelChangeReport> changes) const
  {
    context().model_changed(changes);
  }

  void report_semantics_changed(std::span<const SemanticChangeReport> changes) const
  {
    context().semantics_changed(changes);
  }

  VoidResult report_constant_values_changed(std::function<void(VoidResult)> completion) const
  {
    return context().constant_values_changed(std::move(completion));
  }

  std::vector<uint16_t> attached_indexes() const
  {
    const std::lock_guard lock(mMutex);
    return mAttached;
  }

private:
  VoidResult on_attached(const NamespaceContext& attached) override
  {
    {
      const std::lock_guard lock(mMutex);
      mAttached.push_back(attached.index());
    }
    return mAnswer;
  }

  String mUri;
  VoidResult mAnswer;
  mutable std::mutex mMutex;
  std::vector<uint16_t> mAttached;
};

/// Holds another namespace and, for the test, attaches it with the context this namespace answers before it
/// is attached itself.
class HoldingNamespace final : public Namespace
{
public:
  explicit HoldingNamespace(std::shared_ptr<AttachRecordingNamespace> inner) : mInner(std::move(inner))
  {}

  String uri() const override
  {
    return mInner->uri();
  }

  void shutdown_async(std::function<void(VoidResult)> callback) noexcept override
  {
    callback(VoidResult{});
  }

  void find_nodes_async(const RequestInfo& request, std::span<const NodeId> nodeIds,
    std::optional<Duration> maxAge, std::function<void(BatchResult<NodeResult>)> callback) override
  {
    mInner->find_nodes_async(request, nodeIds, maxAge, std::move(callback));
  }

  void read_references_async(const RequestInfo&, std::span<const ReferenceQuery>,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    complete(BatchResult<NodeReferencesResult>{VoidResult{StatusCode{Status::BadNotSupported}}, {}});
  }

  void read_values_async(const RequestInfo&, const CallerInfo*, std::span<const ValueReadItem>, Duration,
    bool, std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    complete(BatchResult<DataValueResult>{VoidResult{StatusCode{Status::BadNotSupported}}, {}});
  }

  VoidResult attach_inner_with_own_context()
  {
    return mInner->attach(context());
  }

private:
  std::shared_ptr<AttachRecordingNamespace> mInner;
};

class AcceptedPreparation final : public ::ua::detail::NamespaceRegistrationPreparation
{
public:
  void commit() noexcept override
  {}
};

/// A lifecycle participant that refuses the next registration's preparation, then accepts every one.
class RefuseNextParticipant final : public ::ua::detail::NamespaceRegistrationParticipant
{
public:
  void prepare_async(::ua::detail::NamespaceRegistrationCandidate,
    ::ua::detail::NamespaceRegistrationPreparationCallback callback) noexcept override
  {
    if (refuseNext.exchange(false))
    {
      callback(::ua::detail::NamespaceRegistrationPreparationResult{StatusCode{Status::BadConfigurationError,
        ErrorDetail::build("InjectedParticipantRefusal",
          "The participant refused the preparation",
          "RefuseNextParticipant")}});
      return;
    }
    callback(::ua::detail::NamespaceRegistrationPreparationResult{std::make_shared<AcceptedPreparation>()});
  }

  std::atomic<bool> refuseNext{true};
};

Result<uint16_t> register_and_wait(AddressSpace& addressSpace, std::shared_ptr<Namespace> space)
{
  auto promise = std::make_shared<std::promise<Result<uint16_t>>>();
  auto future = promise->get_future();
  addressSpace.add_namespace_async(
    std::move(space), [promise](Result<uint16_t> result) { promise->set_value(std::move(result)); });
  if (future.wait_for(5s) != std::future_status::ready)
  {
    ADD_FAILURE() << "the registration did not answer within 5 s";
    return Result<uint16_t>{StatusCode{Status::BadTimeout}};
  }
  return future.get();
}

bool chain_has_code(const StatusCode& status, std::string_view code)
{
  for (auto detail = status.shared_detail(); detail != nullptr; detail = detail->cause)
  {
    if (detail->code == code)
    {
      return true;
    }
  }
  return false;
}

}  // namespace

// @relation(AC-COMP-ADDRSP-NAMESPACE-CONTEXT-01-REGISTRATION-GIVES-THE-NAMESPACE-ITS-INDEX, scope=function)
TEST(NamespaceAttach, RegistrationGivesTheNamespaceItsIndex)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:attach-index", pool.get_executor());
    auto space = std::make_shared<AttachRecordingNamespace>("urn:test:attach-index-ns");

    const auto registered = register_and_wait(addressSpace, space);
    ASSERT_TRUE(registered.is_good());
    const uint16_t index = registered.value();
    EXPECT_EQ(space->attached_indexes(), (std::vector<uint16_t>{index}));
    EXPECT_EQ(space->index_from_context(), index);
  }
  pool.join();
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-CONTEXT-01-A-SECOND-ATTACH-IS-REFUSED, scope=function)
TEST(NamespaceAttach, ASecondAttachIsRefusedWithBadInvalidState)
{
  boost::asio::thread_pool pool{2};
  {
    auto first = AddressSpace::create("urn:test:attach-twice-1", pool.get_executor());
    auto second = AddressSpace::create("urn:test:attach-twice-2", pool.get_executor());
    // The second address space would offer another index than the first did.
    ASSERT_TRUE(
      register_and_wait(second, std::make_shared<AttachRecordingNamespace>("urn:test:attach-twice-filler"))
        .is_good());
    auto space = std::make_shared<AttachRecordingNamespace>("urn:test:attach-twice-ns");

    const auto registered = register_and_wait(first, space);
    ASSERT_TRUE(registered.is_good());
    const uint16_t index = registered.value();

    const auto again = register_and_wait(second, space);
    EXPECT_EQ(again.status_code().as_status(), Status::BadInvalidState);
    const auto reattached = space->attach_again();
    EXPECT_EQ(reattached.status_code().as_status(), Status::BadInvalidState);
    EXPECT_EQ(space->attached_indexes(), (std::vector<uint16_t>{index}));
    EXPECT_EQ(space->index_from_context(), index);
  }
  pool.join();
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-CONTEXT-01-A-REFUSAL-FROM-ON-ATTACHED-FAILS-THE-REGISTRATION, scope=function)
TEST(NamespaceAttach, ARefusalFromOnAttachedFailsTheRegistration)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:attach-refused", pool.get_executor());
    auto space = std::make_shared<AttachRecordingNamespace>("urn:test:attach-refused-ns",
      VoidResult{StatusCode{Status::BadConfigurationError,
        ErrorDetail::build(
          "RefusedOnAttach", "The namespace refused its context", "AttachRecordingNamespace")}});

    const auto registered = register_and_wait(addressSpace, space);
    EXPECT_EQ(registered.status_code().as_status(), Status::BadConfigurationError);
    EXPECT_TRUE(chain_has_code(registered.status_code(), "RefusedOnAttach"));
    EXPECT_THROW(
      (void)addressSpace.namespace_array().get_namespace_index("urn:test:attach-refused-ns"), UaException);
  }
  pool.join();
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-CONTEXT-01-ONLY-THE-REGISTRATION-CREATES-A-CONTEXT, scope=function)
TEST(NamespaceAttach, OnlyTheRegistrationCreatesAContext)
{
  EXPECT_FALSE(std::is_default_constructible_v<NamespaceContext>);
  EXPECT_FALSE((std::is_constructible_v<NamespaceContext, uint16_t>));
  EXPECT_TRUE(std::is_copy_constructible_v<NamespaceContext>);
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-CONTEXT-02-A-FAILED-REGISTRATION-CLOSES-THE-CONTEXT, scope=function)
TEST(NamespaceAttach, AFailedRegistrationClosesTheContext)
{
  boost::asio::thread_pool pool{2};
  {
    auto addressSpace = AddressSpace::create("urn:test:attach-closed", pool.get_executor());
    auto participant = std::make_shared<RefuseNextParticipant>();
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);
    auto x = std::make_shared<AttachRecordingNamespace>("urn:test:attach-closed-x");

    const auto refused = register_and_wait(addressSpace, x);
    EXPECT_EQ(refused.status_code().as_status(), Status::BadConfigurationError);
    EXPECT_TRUE(chain_has_code(refused.status_code(), "InjectedParticipantRefusal"));
    const auto offered = x->attached_indexes();
    ASSERT_EQ(offered.size(), 1u);
    ASSERT_FALSE(participant->refuseNext.load());

    const auto again = register_and_wait(addressSpace, x);
    EXPECT_EQ(again.status_code().as_status(), Status::BadInvalidState);
    EXPECT_EQ(x->attached_indexes().size(), 1u) << "on_attached was called again for the closed context";

    auto y = std::make_shared<AttachRecordingNamespace>("urn:test:attach-closed-y");
    const auto next = register_and_wait(addressSpace, y);
    ASSERT_TRUE(next.is_good());
    EXPECT_EQ(next.value(), offered.front());
  }
  pool.join();
}

// NR-39 rule 4: the context a failed registration leaves on its object reports nothing, while the address
// space lives on and gives the same index to the next registration. X's three reports are refused or ignored:
// constant_values_changed answers Bad_Shutdown and never calls its completion, model_changed leaves the model
// generation where it was, and semantics_changed raises no event. The control is Y, registered next at the
// index X was offered: the same reports through Y's context advance the generation and raise Y's event. The
// executor has one thread, so the steps posted from this thread run in the order they were posted, and Y's
// event arriving means that an event of X, had one been posted before it, has already arrived.
// @relation(AC-COMP-ADDRSP-NAMESPACE-CONTEXT-02-A-FAILED-REGISTRATIONS-CONTEXT-REPORTS-NOTHING, scope=function)
TEST(NamespaceAttach, AFailedRegistrationsContextReportsNothing)
{
  boost::asio::thread_pool pool{1};
  {
    auto addressSpace = AddressSpace::create("urn:test:attach-closed-reports", pool.get_executor());

    // Shared with the handler, which a step posted before the address space is destroyed may still run.
    struct SemanticEvents
    {
      std::mutex mutex;
      std::condition_variable arrived;
      std::vector<NodeId> owners;
    };

    auto events = std::make_shared<SemanticEvents>();
    detail::AddressSpaceChangeEvents::set_handler(addressSpace,
      [events](const detail::AddressSpaceChange& change)
      {
        if (change.kind != detail::AddressSpaceChangeKind::Semantic)
        {
          return;
        }
        {
          const std::lock_guard lock{events->mutex};
          for (const auto& entry : change.changes)
          {
            events->owners.push_back(entry.affected);
          }
        }
        events->arrived.notify_all();
      });
    auto participant = std::make_shared<RefuseNextParticipant>();
    NamespaceRegistrationCoordinatorTestAccess::install_participant(addressSpace, participant);
    auto x = std::make_shared<AttachRecordingNamespace>("urn:test:attach-closed-reports-x");
    const auto refused = register_and_wait(addressSpace, x);
    ASSERT_EQ(refused.status_code().as_status(), Status::BadConfigurationError);
    ASSERT_EQ(x->attached_indexes().size(), 1u);
    auto y = std::make_shared<AttachRecordingNamespace>("urn:test:attach-closed-reports-y");
    const auto registered = register_and_wait(addressSpace, y);
    ASSERT_TRUE(registered.is_good());
    ASSERT_EQ(registered.value(), x->attached_indexes().front());
    const uint16_t index = registered.value();
    const NodeId ownerOfX{index, "OwnerReportedByX"};
    const NodeId ownerOfY{index, "OwnerReportedByY"};

    auto completed = std::make_shared<std::atomic<bool>>(false);
    const auto advance =
      x->report_constant_values_changed([completed](VoidResult) { completed->store(true); });
    EXPECT_EQ(advance.status_code().as_status(), Status::BadShutdown)
      << "the context of a failed registration queued a ConfigurationVersion advance";

    const auto before = addressSpace.model_generation();
    x->report_model_changed({});
    EXPECT_EQ(addressSpace.model_generation(), before)
      << "the context of a failed registration advanced the model generation";
    y->report_model_changed({});
    EXPECT_GT(addressSpace.model_generation(), before) << "the control: Y's report did not advance it";

    const SemanticChangeReport fromX[] = {
      SemanticChangeReport{ownerOfX, NodeId{ObjectTypeId::BaseObjectType}}};
    x->report_semantics_changed(fromX);
    const SemanticChangeReport fromY[] = {
      SemanticChangeReport{ownerOfY, NodeId{ObjectTypeId::BaseObjectType}}};
    y->report_semantics_changed(fromY);
    {
      std::unique_lock lock{events->mutex};
      ASSERT_TRUE(events->arrived.wait_for(lock,
        5s,
        [&] {
          return std::find(events->owners.begin(), events->owners.end(), ownerOfY) != events->owners.end();
        }))
        << "the control: Y's report raised no SemanticChangeEvent";
      EXPECT_EQ(std::find(events->owners.begin(), events->owners.end(), ownerOfX), events->owners.end())
        << "the context of a failed registration raised a SemanticChangeEvent";
    }
    EXPECT_FALSE(completed->load()) << "the refused advance called its completion";
  }
  pool.join();
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-CONTEXT-03-A-FORWARDING-NAMESPACE-PASSES-THE-CONTEXT-ON, scope=function)
TEST(NamespaceAttach, AForwardingNamespacePassesTheContextOn)
{
  boost::asio::thread_pool pool{2};
  {
    auto first = AddressSpace::create("urn:test:attach-forwarded-1", pool.get_executor());
    auto second = AddressSpace::create("urn:test:attach-forwarded-2", pool.get_executor());
    // The second address space would offer another index than the first did.
    ASSERT_TRUE(register_and_wait(
      second, std::make_shared<AttachRecordingNamespace>("urn:test:attach-forwarded-filler"))
                  .is_good());
    auto inner = std::make_shared<AttachRecordingNamespace>("urn:test:attach-forwarded-ns");
    auto forwarding = std::make_shared<::ua::history::HistoryNamespace>(inner, nullptr);

    const auto registered = register_and_wait(first, forwarding);
    ASSERT_TRUE(registered.is_good());
    const uint16_t index = registered.value();
    EXPECT_EQ(inner->attached_indexes(), (std::vector<uint16_t>{index}));
    EXPECT_EQ(inner->index_from_context(), index);

    const auto own = register_and_wait(second, inner);
    EXPECT_EQ(own.status_code().as_status(), Status::BadInvalidState);
  }
  pool.join();
}

// @relation(AC-COMP-ADDRSP-NAMESPACE-CONTEXT-01-THE-CONTEXT-BEFORE-ATTACH-IS-REFUSED, scope=function)
TEST(NamespaceAttach, TheContextBeforeAttachIsRefused)
{
  boost::asio::thread_pool pool{2};
  {
    auto inner = std::make_shared<AttachRecordingNamespace>("urn:test:attach-early-ns");
    auto holder = std::make_shared<HoldingNamespace>(inner);

    const auto early = holder->attach_inner_with_own_context();
    EXPECT_EQ(early.status_code().as_status(), Status::BadInvalidArgument);
    ASSERT_NE(early.status_code().shared_detail(), nullptr);
    EXPECT_EQ(early.status_code().shared_detail()->code, "NamespaceContextNotFromRegistration");
    EXPECT_TRUE(inner->attached_indexes().empty())
      << "on_attached was called with a context not from a registration";

    auto addressSpace = AddressSpace::create("urn:test:attach-early", pool.get_executor());
    const auto registered = register_and_wait(addressSpace, inner);
    ASSERT_TRUE(registered.is_good());
    const uint16_t index = registered.value();
    EXPECT_EQ(inner->index_from_context(), index);
  }
  pool.join();
}
