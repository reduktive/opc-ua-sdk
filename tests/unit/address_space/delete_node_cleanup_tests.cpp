// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// When the address space deletes a Node, every Node in another namespace that the deleted Node referenced is
// asked to remove its half of the link. The delete waits for those removals, logs every one that leaves a
// Reference behind, and answers Uncertain_ReferenceNotDeleted when one did (NR-42 A-6; delivery decision
// DL-17; Part 4 5.7.4.4 Table 30).
//
// The referrers live in a namespace whose answers the test scripts (ScriptedReferrerNamespace): a lookup can
// fail, a removal can be refused or held back, and its own deletes can be refused or held back. Every answer
// it gives to a removal is posted to the executor, as a namespace answering on its own worker does. The
// executor has one thread, and a delete whose order matters is issued on it: a removal answer then cannot run
// until the work that issued the removal has returned.

#include <gtest/gtest.h>

#include "scripted_referrer_namespace.h"
#include "test_utilities.h"

#include "instantiation/ua_node_subtree.h"
#include "ua_address_space.h"
#include "ua_application_configuration.h"
#include "ua_data_type_registration.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "ua_file_stream.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_namespace_array.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"
#include "ua_referencetype_id.h"
#include "ua_status_to_string.h"
#include "ua_structure_factory.h"
#include "ua_to_string.h"

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

const std::string removalFailedWarning =
  "Could not remove a cross-namespace reference to a deleted node; the referrer keeps a reference to a node "
  "that no longer exists";
const std::string referrerNotFoundWarning =
  "Could not find a node in another namespace that referenced a deleted node; if it still exists, it keeps a "
  "reference to a node that no longer exists";
const std::string ownedNodeRemainsWarning =
  "Owned subtree node could not be removed; it remains in the address space";

/// Records what the address space logs, its structured fields rendered as text.
class RecordingLogSink final : public LogSink
{
public:
  struct Entry
  {
    LogLevel level;
    std::string category;
    std::string message;
    std::vector<std::string> fieldValues;

    /// Whether some field contains @p text.
    bool names(const std::string& text) const
    {
      for (const auto& value : fieldValues)
      {
        if (value.find(text) != std::string::npos)
        {
          return true;
        }
      }
      return false;
    }
  };

  void log(const LogEntry& entry) override
  {
    Entry copy{entry.level, std::string{entry.category}, entry.message, {}};
    for (const auto& field : entry.fields)
    {
      std::visit(
        [&copy](const auto& value)
        {
          std::ostringstream text;
          text << value;
          copy.fieldValues.push_back(text.str());
        },
        field.value);
    }
    const std::lock_guard lock{mMutex};
    mEntries.push_back(std::move(copy));
  }

  std::vector<Entry> entries() const
  {
    const std::lock_guard lock{mMutex};
    return mEntries;
  }

private:
  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};

/// The warnings in the category "address_space" among @p entries whose message is @p message.
std::vector<RecordingLogSink::Entry> address_space_warnings(
  const std::vector<RecordingLogSink::Entry>& entries, const std::string& message)
{
  std::vector<RecordingLogSink::Entry> found;
  for (const auto& entry : entries)
  {
    if (entry.level == LogLevel::Warning && entry.category == "address_space" && entry.message == message)
    {
      found.push_back(entry);
    }
  }
  return found;
}

/// Whether some entry among @p entries names @p text in a field.
bool any_names(const std::vector<RecordingLogSink::Entry>& entries, const std::string& text)
{
  for (const auto& entry : entries)
  {
    if (entry.names(text))
    {
      return true;
    }
  }
  return false;
}

/// A delete issued on the executor: how often its callback ran, what it answered, and the log as it stood
/// when the callback ran.
struct PendingDelete
{
  std::mutex mutex;
  std::condition_variable answered;
  int calls = 0;
  std::optional<VoidResult> result;
  std::vector<RecordingLogSink::Entry> logAtAnswer;
};

class DeleteNodeCleanup : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mExecutor = mThreadPool.get_executor();
    mAddressSpace.emplace(AddressSpace::create("urn:test", mExecutor));
    mAddressSpace->set_logger(Logger{mLog, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"});
    mA = test::ScriptedReferrerNamespace::create("urn:test:delete-cleanup:a", mExecutor);
    mB = test::ScriptedReferrerNamespace::create("urn:test:delete-cleanup:b", mExecutor);
    mD = test::ScriptedReferrerNamespace::create("urn:test:delete-cleanup:d", mExecutor);
    for (auto [ns, index] : {std::pair{mA, &mIndexA}, std::pair{mB, &mIndexB}, std::pair{mD, &mIndexD}})
    {
      auto added = mAddressSpace->try_add_namespace_sync(ns);
      ASSERT_TRUE(added.is_good()) << to_string(added.status_code());
      *index = added.value();
    }
  }

  void TearDown() override
  {
    for (const auto& ns : {mA, mB, mD})
    {
      if (ns)
      {
        ns->release_everything();
      }
    }
    drain_executor();
    mA.reset();
    mB.reset();
    mD.reset();
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  NodeId in_a(const std::string& name) const
  {
    return NodeId{mIndexA, name};
  }

  NodeId in_b(const std::string& name) const
  {
    return NodeId{mIndexB, name};
  }

  NodeId in_d(const std::string& name) const
  {
    return NodeId{mIndexD, name};
  }

  /// Loads the OPC UA namespace's Nodes, so that the ReferenceType hierarchy a subtree delete walks exists:
  /// without it no ReferenceType is known to be hierarchical.
  void load_namespace_zero()
  {
    const auto limits = make_encoding_limits(ApplicationConfig::load_default());
    auto lookup = namespace_array_utils::get_index_lookup_function(*mAddressSpace);
    const CodecNamespaceContext context{std::move(lookup), {}, {}, {}};
    register_ua_data_types_with_factory(context, &mStructureFactory, &mStructureFactory);
    FileStream input{"NodeSet2.xml"};
    input.open_for_read();
    auto nodeSets = xml::nodeset::Parser::parse(limits,
      input,
      mStructureFactory,
      mAddressSpace->namespace_array(),
      mAddressSpace->server_array(),
      xml::nodeset::Parser::GetDependentModelCallback{});
    auto importer = xml::nodeset::ImportEngine::create(limits, *mAddressSpace, nodeSets, {});
    importer->import_all_sync({}, {});
  }

  void create_object(const NodeId& nodeId)
  {
    auto created = mAddressSpace->try_create_node_sync(nodeId, NodeClass::Object, {});
    ASSERT_TRUE(created.is_good()) << to_string(nodeId) << ": " << to_string(created.status_code());
  }

  /// Gives @p source a forward Reference of @p type to @p target and @p target its inverse half, each held
  /// by the Node the address space finds.
  void link(const NodeId& source, ReferenceTypeId type, const NodeId& target)
  {
    auto sourceNode = mAddressSpace->try_find_node_sync(source);
    ASSERT_TRUE(sourceNode.is_good()) << to_string(source);
    auto targetNode = mAddressSpace->try_find_node_sync(target);
    ASSERT_TRUE(targetNode.is_good()) << to_string(target);
    auto forward = sourceNode.value().try_add_reference_sync(NodeId{type}, ExpandedNodeId{target}, true);
    ASSERT_TRUE(forward.is_good()) << to_string(forward.status_code());
    auto inverse = targetNode.value().try_add_reference_sync(NodeId{type}, ExpandedNodeId{source}, false);
    ASSERT_TRUE(inverse.is_good()) << to_string(inverse.status_code());
  }

  /// Issues `delete_node_async` on the executor, so that it runs as a service's work does.
  std::shared_ptr<PendingDelete> start_delete(const NodeId& nodeId, bool subtree)
  {
    auto pending = std::make_shared<PendingDelete>();
    boost::asio::post(mExecutor,
      [addressSpace = *mAddressSpace, log = mLog, pending, nodeId, subtree]() mutable
      {
        addressSpace.delete_node_async(nodeId,
          subtree,
          ReferenceHalves::Both,
          [log, pending](VoidResult result)
          {
            auto snapshot = log->entries();
            const std::lock_guard lock{pending->mutex};
            ++pending->calls;
            pending->result = std::move(result);
            pending->logAtAnswer = std::move(snapshot);
            pending->answered.notify_all();
          });
      });
    return pending;
  }

  static bool wait_answered(PendingDelete& pending, std::chrono::milliseconds timeout = 5s)
  {
    std::unique_lock lock{pending.mutex};
    return pending.answered.wait_for(lock, timeout, [&pending] { return pending.calls > 0; });
  }

  static int calls(PendingDelete& pending)
  {
    const std::lock_guard lock{pending.mutex};
    return pending.calls;
  }

  /// Returns once every handler posted to the executor before this call has run.
  void drain_executor()
  {
    std::promise<void> ran;
    auto done = ran.get_future();
    boost::asio::post(mExecutor, [&ran] { ran.set_value(); });
    ASSERT_EQ(done.wait_for(5s), std::future_status::ready) << "the executor did not drain";
  }

  static bool wait_until(const std::function<bool()>& condition, std::chrono::milliseconds timeout = 5s)
  {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!condition())
    {
      if (std::chrono::steady_clock::now() > deadline)
      {
        return false;
      }
      std::this_thread::sleep_for(2ms);
    }
    return true;
  }

  Status lookup(const NodeId& nodeId)
  {
    return mAddressSpace->try_find_node_sync(nodeId).status_code().as_status();
  }

  static std::string detail_code(const VoidResult& result)
  {
    const auto detail = result.shared_detail();
    return detail ? detail->code : std::string{};
  }

  /// The context value @p detail carries under the key node.id, or "".
  static std::string context_node(const ErrorDetail& detail)
  {
    for (const auto& entry : detail.context)
    {
      if (entry.key == std::string{ContextKeys::nodeId.value()})
      {
        return entry.value;
      }
    }
    return {};
  }

  /// Checks the cause chain of a delete that left a Reference behind: the delete's ErrorDetail
  /// CrossNamespaceReferenceNotRemoved names @p deleted, carries @p failure as its inner status and has as
  /// its cause the ErrorDetail ReferrerKeepsReference, which names @p referrer, carries @p failure as its
  /// inner status and has as its cause the ErrorDetail coded @p failureCode that the referrer's namespace
  /// answered.
  static void expect_left_behind_chain(const VoidResult& result, const NodeId& deleted,
    const NodeId& referrer, Status failure, const std::string& failureCode)
  {
    const auto outer = result.shared_detail();
    ASSERT_NE(outer, nullptr) << "the delete carries no ErrorDetail";
    EXPECT_EQ(outer->code, "CrossNamespaceReferenceNotRemoved");
    EXPECT_NE(context_node(*outer).find(to_string(deleted)), std::string::npos)
      << "the ErrorDetail does not name the deleted Node " << to_string(deleted) << ": '"
      << context_node(*outer) << "'";
    EXPECT_EQ(StatusCode{outer->innerStatus}.as_status(), failure)
      << "the ErrorDetail's inner status is " << to_string(StatusCode{outer->innerStatus});
    const auto keeps = outer->cause;
    ASSERT_NE(keeps, nullptr) << "the ErrorDetail has no cause";
    EXPECT_EQ(keeps->code, "ReferrerKeepsReference");
    EXPECT_NE(context_node(*keeps).find(to_string(referrer)), std::string::npos)
      << "the cause does not name the referrer " << to_string(referrer) << ": '" << context_node(*keeps)
      << "'";
    EXPECT_EQ(StatusCode{keeps->innerStatus}.as_status(), failure)
      << "the cause's inner status is " << to_string(StatusCode{keeps->innerStatus});
    ASSERT_NE(keeps->cause, nullptr) << "the cause does not carry the referrer namespace's answer";
    EXPECT_EQ(keeps->cause->code, failureCode);
  }

  boost::asio::thread_pool mThreadPool{1};
  boost::asio::any_io_executor mExecutor;
  std::optional<AddressSpace> mAddressSpace;
  std::shared_ptr<RecordingLogSink> mLog = std::make_shared<RecordingLogSink>();
  StructureFactory mStructureFactory;
  std::shared_ptr<test::ScriptedReferrerNamespace> mA;
  std::shared_ptr<test::ScriptedReferrerNamespace> mB;
  std::shared_ptr<test::ScriptedReferrerNamespace> mD;
  uint16_t mIndexA = 0;
  uint16_t mIndexB = 0;
  uint16_t mIndexD = 0;
};

}  // namespace

// @relation(AC-COMP-ADDRSP-DELETE-CROSS-NAMESPACE-CLEANUP-01-COMPLETES-AFTER-REMOVALS, scope=function)
TEST_F(DeleteNodeCleanup, CompletesOnlyAfterOtherNamespacesAnswered)
{
  const NodeId n = in_a("N");
  const NodeId r = in_b("R");
  create_object(n);
  create_object(r);
  link(n, ReferenceTypeId::Organizes, r);
  mB->hold_removals(r);

  auto pending = start_delete(n, false);
  ASSERT_TRUE(wait_until([this] { return mB->held_removals() == 1u; }))
    << "the removal of R's Reference to N never reached B";
  // Everything the delete did on the executor has returned.
  drain_executor();
  EXPECT_EQ(calls(*pending), 0) << "the delete answered while B's answer to the removal was held back";

  mB->release_removals();
  ASSERT_TRUE(wait_answered(*pending)) << "the delete never answered after B's answer was released";
  drain_executor();
  EXPECT_EQ(calls(*pending), 1);
}

// @relation(AC-COMP-ADDRSP-DELETE-CROSS-NAMESPACE-CLEANUP-01-LEFT-BEHIND-REFERENCES-LOGGED, scope=function)
TEST_F(DeleteNodeCleanup, AnUnresolvableReferrerIsLogged)
{
  const NodeId n = in_a("N");
  const NodeId r1 = in_b("R1");
  // In a namespace index the address space does not hold.
  const NodeId r2{static_cast<uint16_t>(mIndexD + 50U), "R2"};
  const NodeId r3 = in_b("R3");
  const NodeId r4 = in_b("R4");
  create_object(n);
  for (const auto& r : {r1, r3, r4})
  {
    create_object(r);
    link(n, ReferenceTypeId::Organizes, r);
  }
  {
    auto nNode = mAddressSpace->try_find_node_sync(n);
    ASSERT_TRUE(nNode.is_good());
    auto toR2 =
      nNode.value().try_add_reference_sync(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{r2}, true);
    ASSERT_TRUE(toR2.is_good()) << to_string(toR2.status_code());
  }
  mB->answer_removals(r1, StatusCode{Status::BadInternalError});
  mB->answer_removals(r3, StatusCode{Status::UncertainReferenceNotDeleted});
  mB->fail_lookups(r4, StatusCode{Status::BadNodeIdUnknown});

  auto pending = start_delete(n, false);
  ASSERT_TRUE(wait_answered(*pending));
  const auto notFound = address_space_warnings(pending->logAtAnswer, referrerNotFoundWarning);
  ASSERT_EQ(notFound.size(), 1u)
    << "when the delete answered, the log did not hold exactly one warning in the "
       "category address_space that a referrer could not be found";
  EXPECT_TRUE(notFound.front().names(to_string(n))) << "the warning does not name the deleted Node";
  EXPECT_TRUE(notFound.front().names(to_string(r2))) << "the warning does not name R2";
  EXPECT_TRUE(notFound.front().names(to_string(Status::BadNodeIdUnknown)))
    << "the warning does not name the status";
  EXPECT_FALSE(any_names(pending->logAtAnswer, to_string(Status::UncertainReferenceNotDeleted)))
    << "R3, which held nothing, was logged";
  EXPECT_FALSE(any_names(pending->logAtAnswer, to_string(r4))) << "R4, which does not exist, was logged";
}

// @relation(AC-COMP-ADDRSP-DELETE-CROSS-NAMESPACE-CLEANUP-01-LEFT-BEHIND-REFERENCES-LOGGED, scope=function)
TEST_F(DeleteNodeCleanup, AFailedRemovalAtAFoundReferrerIsLogged)
{
  const NodeId n = in_a("N");
  const NodeId r1 = in_b("R1");
  const NodeId r2 = in_b("R2");
  const NodeId r3 = in_b("R3");
  create_object(n);
  for (const auto& r : {r1, r2, r3})
  {
    create_object(r);
    link(n, ReferenceTypeId::Organizes, r);
  }
  mB->answer_removals(r1, StatusCode{Status::BadInternalError});
  mB->fail_lookups(r2, StatusCode{Status::BadNodeIdUnknown});
  mB->answer_removals(r3, StatusCode{Status::UncertainReferenceNotDeleted});

  auto pending = start_delete(n, false);
  ASSERT_TRUE(wait_answered(*pending));
  const auto failed = address_space_warnings(pending->logAtAnswer, removalFailedWarning);
  ASSERT_EQ(failed.size(), 1u) << "when the delete answered, the log held no warning in the category "
                                  "address_space that a found referrer's removal failed";
  EXPECT_TRUE(failed.front().names(to_string(n))) << "the warning does not name the deleted Node";
  EXPECT_TRUE(failed.front().names(to_string(Status::BadInternalError)))
    << "the warning does not name the removal's status";

  // R3 answered Uncertain_ReferenceNotDeleted, which leaves nothing behind: nothing is logged for it, even
  // once every removal has answered.
  ASSERT_TRUE(wait_until([this, r3] { return mB->answered_removals(r3) == 1u; }));
  drain_executor();
  EXPECT_FALSE(any_names(mLog->entries(), to_string(Status::UncertainReferenceNotDeleted)))
    << "R3, which held nothing, was logged";
}

// @relation(AC-COMP-ADDRSP-DELETE-CROSS-NAMESPACE-CLEANUP-02-REFUSED-REMOVAL-IS-UNCERTAIN, scope=function)
// @relation(AC-SVR-NM-DN-024-SDK-DELETE-REPORTS-REFERENCE-LEFT-BEHIND, scope=function)
TEST_F(DeleteNodeCleanup, ARemovalTheReferrerRefusesAnswersUncertainReferenceNotDeleted)
{
  const NodeId n1 = in_a("N1");
  const NodeId n2 = in_a("N2");
  const NodeId r1 = in_b("R1");
  const NodeId r3 = in_b("R3");
  for (const auto& id : {n1, n2, r1, r3})
  {
    create_object(id);
  }
  link(n1, ReferenceTypeId::Organizes, r1);
  link(n2, ReferenceTypeId::Organizes, r3);
  mB->answer_removals(r1,
    StatusCode{Status::BadInternalError,
      ErrorDetail::build("RemovalRefused", "The referrer refused to remove its half", "ScriptedReferrer")});
  mB->answer_removals(r3, StatusCode{Status::UncertainReferenceNotDeleted});

  auto first = start_delete(n1, false);
  ASSERT_TRUE(wait_answered(*first));
  EXPECT_EQ(first->result->status_code().as_status(), Status::UncertainReferenceNotDeleted)
    << to_string(first->result->status_code());
  expect_left_behind_chain(*first->result, n1, r1, Status::BadInternalError, "RemovalRefused");
  EXPECT_EQ(lookup(n1), Status::BadNodeIdUnknown) << "the Uncertain delete did not delete N1";

  auto second = start_delete(n2, false);
  ASSERT_TRUE(wait_answered(*second));
  EXPECT_EQ(second->result->status_code().as_status(), Status::Good)
    << "a referrer that held no such Reference made the delete " << to_string(second->result->status_code());
  EXPECT_EQ(lookup(n2), Status::BadNodeIdUnknown);
}

// @relation(AC-COMP-ADDRSP-DELETE-CROSS-NAMESPACE-CLEANUP-02-FAILED-LOOKUP-IS-UNCERTAIN-UNLESS-UNKNOWN, scope=function)
TEST_F(DeleteNodeCleanup, AFailedReferrerLookupAnswersUncertainUnlessTheReferrerIsUnknown)
{
  const NodeId n3 = in_a("N3");
  const NodeId n4 = in_a("N4");
  const NodeId r2 = in_b("R2");
  const NodeId r4 = in_b("R4");
  for (const auto& id : {n3, n4, r2, r4})
  {
    create_object(id);
  }
  link(n3, ReferenceTypeId::Organizes, r2);
  link(n4, ReferenceTypeId::Organizes, r4);
  mB->fail_lookups(r2,
    StatusCode{Status::BadInternalError,
      ErrorDetail::build("LookupFailed", "The referrer could not be looked up", "ScriptedReferrer")});
  mB->fail_lookups(r4, StatusCode{Status::BadNodeIdUnknown});

  auto first = start_delete(n3, false);
  ASSERT_TRUE(wait_answered(*first));
  EXPECT_EQ(first->result->status_code().as_status(), Status::UncertainReferenceNotDeleted)
    << to_string(first->result->status_code());
  expect_left_behind_chain(*first->result, n3, r2, Status::BadInternalError, "LookupFailed");

  auto second = start_delete(n4, false);
  ASSERT_TRUE(wait_answered(*second));
  EXPECT_EQ(second->result->status_code().as_status(), Status::Good)
    << "a referrer that does not exist made the delete " << to_string(second->result->status_code());
}

// @relation(AC-COMP-ADDRSP-DELETE-CROSS-NAMESPACE-CLEANUP-02-REFERRER-GONE-BEFORE-REMOVAL-LEAVES-GOOD, scope=function)
TEST_F(DeleteNodeCleanup, AReferrerDeletedAfterItsLookupLeavesTheDeleteGood)
{
  const NodeId n9 = in_a("N9");
  const NodeId r7 = in_b("R7");
  create_object(n9);
  create_object(r7);
  link(n9, ReferenceTypeId::Organizes, r7);
  // R7 is found, then answers its removal as a Node deleted after its lookup does.
  mB->answer_removals(r7, StatusCode{Status::BadNodeIdUnknown});

  auto pending = start_delete(n9, false);
  ASSERT_TRUE(wait_answered(*pending));
  ASSERT_TRUE(wait_until([this, r7] { return mB->answered_removals(r7) == 1u; }));
  drain_executor();
  EXPECT_EQ(pending->result->status_code().as_status(), Status::Good)
    << to_string(pending->result->status_code());
  EXPECT_EQ(lookup(n9), Status::BadNodeIdUnknown);
  EXPECT_FALSE(any_names(mLog->entries(), to_string(n9)))
    << "a referrer that holds nothing was logged as keeping a reference to N9";
}

// @relation(AC-COMP-ADDRSP-DELETE-CROSS-NAMESPACE-CLEANUP-02-SUBTREE-RANKS-BAD-ABOVE-UNCERTAIN, scope=function)
TEST_F(DeleteNodeCleanup, ASubtreeDeleteRanksBadAboveUncertainAboveGood)
{
  load_namespace_zero();
  // (a) A child's Uncertain outranks the other child's and the Node's own Good.
  const NodeId p1 = in_a("P1");
  const NodeId c1 = in_a("C1");
  const NodeId c2 = in_a("C2");
  const NodeId r1 = in_b("R1");
  // (b) The Node's own Uncertain outranks its child's Good.
  const NodeId p2 = in_a("P2");
  const NodeId c3 = in_a("C3");
  const NodeId r5 = in_b("R5");
  // (c) A Bad that arrives after an Uncertain outranks it.
  const NodeId p3 = in_a("P3");
  const NodeId c4 = in_a("C4");
  const NodeId c5 = in_d("C5");
  const NodeId r6 = in_b("R6");
  for (const auto& id : {p1, c1, c2, r1, p2, c3, r5, p3, c4, c5, r6})
  {
    create_object(id);
  }
  link(p1, ReferenceTypeId::HasComponent, c1);
  link(p1, ReferenceTypeId::HasComponent, c2);
  link(r1, ReferenceTypeId::Organizes, c1);
  link(p2, ReferenceTypeId::HasComponent, c3);
  link(r5, ReferenceTypeId::Organizes, p2);
  link(p3, ReferenceTypeId::HasComponent, c4);
  link(p3, ReferenceTypeId::HasComponent, c5);
  link(r6, ReferenceTypeId::Organizes, c4);
  for (const auto& r : {r1, r5, r6})
  {
    mB->answer_removals(r, StatusCode{Status::BadInternalError});
  }
  mD->refuse_deletes(c5, StatusCode{Status::BadInternalError});
  mD->hold_deletes(c5);

  auto a = start_delete(p1, true);
  ASSERT_TRUE(wait_answered(*a));
  EXPECT_EQ(a->result->status_code().as_status(), Status::UncertainReferenceNotDeleted)
    << "(a) " << to_string(a->result->status_code());

  auto b = start_delete(p2, true);
  ASSERT_TRUE(wait_answered(*b));
  EXPECT_EQ(b->result->status_code().as_status(), Status::UncertainReferenceNotDeleted)
    << "(b) " << to_string(b->result->status_code());

  {
    auto p3Node = mAddressSpace->try_find_node_sync(p3);
    ASSERT_TRUE(p3Node.is_good());
    auto references = p3Node.value().try_get_references_sync();
    ASSERT_TRUE(references.is_good());
    std::string held;
    for (const auto& reference : references.value())
    {
      held += to_string(reference.type_id()) + (reference.is_forward() ? " -> " : " <- ") +
              to_string(reference.target_id()) + "; ";
    }
    ASSERT_NE(held.find(to_string(c5)), std::string::npos)
      << "precondition: P3 references C5; P3 holds " << held;
    auto c5Node = mAddressSpace->try_find_node_sync(c5);
    ASSERT_TRUE(c5Node.is_good()) << "precondition: C5 exists: " << to_string(c5Node.status_code());
  }
  auto c = start_delete(p3, true);
  ASSERT_TRUE(wait_until([this] { return mD->held_deletes() == 1u; }))
    << "(c) C5's delete never reached D; the delete of P3 "
    << (calls(*c) == 0 ? std::string{"has not answered"}
                       : "answered " + to_string(c->result->status_code()) + " " + detail_code(*c->result))
    << "; C5 lookup " << to_string(lookup(c5)) << "; C4 lookup " << to_string(lookup(c4)) << "; P3 lookup "
    << to_string(lookup(p3));
  // C4's delete has answered once B's answer to the removal at R6 has been delivered.
  ASSERT_TRUE(wait_until([this, r6] { return mB->answered_removals(r6) == 1u; }));
  drain_executor();
  mD->release_deletes();
  ASSERT_TRUE(wait_answered(*c));
  EXPECT_EQ(c->result->status_code().as_status(), Status::BadInternalError)
    << "(c) " << to_string(c->result->status_code());
}

// @relation(AC-COMP-ADDRSP-NODE-CHANGE-ROUTE-03-A-RELEASED-ADDRESS-SPACE-ENDS-THE-CASCADE-WITH-ADDRESS-SPACE-GONE, scope=function)
TEST_F(DeleteNodeCleanup, ASubtreeDeleteWhoseAddressSpaceIsReleasedAnswersAddressSpaceGone)
{
  load_namespace_zero();
  const NodeId p = in_a("P");
  const NodeId c = in_d("C");
  create_object(p);
  create_object(c);
  link(p, ReferenceTypeId::HasComponent, c);
  mD->hold_deletes(c);

  auto pending = start_delete(p, true);
  ASSERT_TRUE(wait_until([this] { return mD->held_deletes() == 1u; })) << "C's delete never reached D";
  drain_executor();
  mAddressSpace.reset();
  mD->release_deletes();

  ASSERT_TRUE(wait_answered(*pending)) << "the delete never answered after its address space was released";
  EXPECT_EQ(pending->result->status_code().as_status(), Status::BadShutdown)
    << to_string(pending->result->status_code());
  EXPECT_EQ(detail_code(*pending->result), "AddressSpaceGone");
}

// @relation(AC-COMP-ADDRSP-DELETE-CROSS-NAMESPACE-CLEANUP-02-SYNC-DELETE-REPORTS-UNCERTAIN, scope=function)
TEST_F(DeleteNodeCleanup, TheBlockingDeletesReportUncertainReferenceNotDeleted)
{
  const NodeId n5 = in_a("N5");
  const NodeId n6 = in_a("N6");
  const NodeId r5 = in_b("R5");
  const NodeId r6 = in_b("R6");
  for (const auto& id : {n5, n6, r5, r6})
  {
    create_object(id);
  }
  link(n5, ReferenceTypeId::Organizes, r5);
  link(n6, ReferenceTypeId::Organizes, r6);
  mB->answer_removals(r5, StatusCode{Status::BadInternalError});
  mB->answer_removals(r6, StatusCode{Status::BadInternalError});

  // This thread is not the address space's executor.
  const auto answered = mAddressSpace->try_delete_node_sync(n5, false);
  EXPECT_EQ(answered.status_code().as_status(), Status::UncertainReferenceNotDeleted)
    << "try_delete_node_sync answered " << to_string(answered.status_code());

  std::optional<StatusCode> thrown;
  try
  {
    mAddressSpace->delete_node_sync(n6, false);
  }
  catch (const UaException& exception)
  {
    thrown = exception.status_code();
  }
  ASSERT_TRUE(thrown.has_value()) << "delete_node_sync did not throw";
  EXPECT_EQ(thrown->as_status(), Status::UncertainReferenceNotDeleted) << to_string(*thrown);

  EXPECT_EQ(lookup(n5), Status::BadNodeIdUnknown);
  EXPECT_EQ(lookup(n6), Status::BadNodeIdUnknown);
}

namespace
{

class NodeSubtreeCleanup : public DeleteNodeCleanup
{};

}  // namespace

// @relation(AC-COMP-ADDRSP-DELETE-CROSS-NAMESPACE-CLEANUP-02-OWNED-SUBTREE-CLEANUP-IGNORES-UNCERTAIN, scope=function)
TEST_F(NodeSubtreeCleanup, ANodeDeletedWithAReferenceLeftBehindIsNotReportedAsRemaining)
{
  const NodeId n7 = in_a("N7");
  const NodeId n8 = in_a("N8");
  const NodeId r = in_b("R");
  for (const auto& id : {n7, n8, r})
  {
    create_object(id);
  }
  link(n7, ReferenceTypeId::Organizes, r);
  mB->answer_removals(r, StatusCode{Status::BadInternalError});
  mA->refuse_deletes(n8, StatusCode{Status::BadInternalError});

  {
    // Dropping the handle deletes every Node it recorded as created.
    NodeSubtree subtree{*mAddressSpace, n7, {n7, n8}};
  }
  ASSERT_TRUE(wait_until([this, r] { return mB->answered_removals(r) == 1u; }))
    << "the removal of R's Reference to N7 never answered";
  drain_executor();

  EXPECT_EQ(lookup(n7), Status::BadNodeIdUnknown);
  const auto entries = mLog->entries();
  const auto remaining = address_space_warnings(entries, ownedNodeRemainsWarning);
  ASSERT_EQ(remaining.size(), 1u) << "expected one 'remains' warning, for N8";
  EXPECT_TRUE(remaining.front().names(to_string(n8)));
  EXPECT_FALSE(remaining.front().names(to_string(n7)));
  const auto leftBehind = address_space_warnings(entries, removalFailedWarning);
  ASSERT_EQ(leftBehind.size(), 1u);
  EXPECT_TRUE(leftBehind.front().names(to_string(n7)));
}
