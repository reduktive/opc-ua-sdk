// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief ClientBrowse cluster of the client integration-test matrix (the 18 `ClientBrowse.*` rows).
///
/// These are END-TO-END integration tests of the TIER-2 managed `BrowseCursor` (client design section 7.5)
/// reached via `Connection::typed().browse(start, options)`, plus the wire-shaped multi-node Browse of
/// `Connection::service_requests()` (section 7.2). The tier-2 `Connection` is built by wrapping a real
/// `ConnectionImpl` over an activated tier-0 Session (the same construction the committed ClientRead
/// (046acc46) / ClientWrite (751d0f88) slices use). The Connection is single-shot with NO keep-alive poll:
/// no background traffic races the MisbehavingServer response mutators / request observer, and the bootstrap
/// runs against an un-mutated server (mutators/observers are armed only AFTER `start`).
///
/// The cursor paginates via BrowseNext continuation points. Two server-side interfaces drive the rows:
///   - `set_response_mutator` (BrowseResponse / BrowseNextResponse) injects continuation-point
///     manipulations (long CP, empty page + CP continues, short page + CP, null/empty CP = done,
///     Good_MoreData without CP, per-node bad status, service-level serviceResult, empty Results[]).
///   - `set_request_observer` (added to the MisbehavingServer for this slice) observes the DECODED outgoing
///     request so a row can assert what the client put on the wire: the BrowseNext continuation-point bytes,
///     the `releaseContinuationPoints` flag, or the ABSENCE of a BrowseNext.
///   - ComplianceWithNodes rows browse real server nodes (deterministic pagination, resultMask filtering,
///     HasDictionaryEntry typed targets).
///
/// Falsifiability: every test encodes the matrix row's `[neg: ...]` falsifier. CL-VIEW-017 (BUILT): the
/// cursor preserves a remote reference's serverIndex on the Entry's ExpandedNodeId targetNodeId and emits
/// on_advisory_diagnostic for a remote reference that omits its mandatory displayName. Rows whose tier-2
/// behaviour is not yet built (the ViewDescription mutual-exclusion builder, reconnect-driven cursor
/// invalidation) pin the built, spec-consistent guarantee that IS observable and record the unbuilt part.

#include "compliance_helpers.h"
#include "offloading_node_management_delegate.h"
#include "matchers.h"
#include "requests.h"

#include "misbehaving_server.h"

#include "ua_connection.h"
#include "ua_connection_handle_factory.h"
#include "ua_connection_impl.h"
#include "ua_connection_impl_test_access.h"
#include "ua_service_set.h"
#include "ua_typed_access.h"

#include "ua_browse_cursor.h"
#include "ua_browse_description.h"
#include "ua_browse_next_request.h"
#include "ua_browse_next_response.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result.h"
#include "ua_browse_result_mask.h"

#include "ua_application_configuration.h"
#include "ua_array.h"
#include "ua_byte_string.h"
#include "ua_client.h"
#include "ua_client_secure_channel.h"
#include "ua_client_session.h"
#include "ua_continuation_point.h"
#include "ua_expanded_node_id.h"
#include "ua_localized_text.h"
#include "ua_logger.h"
#include "ua_namespace_table.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_reference_description.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_structure.h"
#include "ua_to_string.h"
#include "ua_utc_time.h"
#include "ua_variable_id.h"
#include "ua_variabletype_id.h"

// Node-management + TranslateBrowsePaths addenda (the DeleteReferences per-item rows and the
// RelativePath targetName row at the end of this file).

#include "ua_session_node_management_services.h"
#include "ua_session_view_services.h"

#include "ua_add_nodes_result.h"
#include "ua_browse_path.h"
#include "ua_browse_path_result.h"
#include "ua_browse_path_target.h"
#include "ua_delete_references_item.h"
#include "ua_delete_references_request.h"
#include "ua_delete_references_response.h"
#include "ua_namespace_delegates.h"
#include "ua_hierarchical_path.h"
#include "ua_relative_path_element.h"
#include "ua_server.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"

#include <boost/asio/thread_pool.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "test_components.h"
using namespace ua;
using namespace ua::client;
using namespace ua::server;
using namespace ua::test_helpers;
using namespace std::chrono_literals;

using ua::test_helpers::MisbehavingServer;

namespace
{

// ---------------------------------------------------------------------------------------------
// StartedConnection: wraps a `ConnectionImpl` (built over an activated Session, no reconnect wiring ->
// single-shot, no keep-alive) into the public tier-2 `Connection` handle, runs the bootstrap, and closes
// gracefully on destruction. Copied verbatim from the ClientRead / ClientWrite slices - the same tier-2
// interface.
// ---------------------------------------------------------------------------------------------
class StartedConnection
{
public:
  StartedConnection(
    boost::asio::any_io_executor executor, Session session, ua::client::detail::ConnectionConfig config = {})
  {
    auto impl = ua::client::detail::ConnectionImpl::create(
      std::move(executor), std::move(session), std::move(config), Logger{});

    std::promise<VoidResult> promise;
    auto future = promise.get_future();
    impl->start_async([&promise](VoidResult result) { promise.set_value(std::move(result)); });
    mStartStatus = future.get();

    mImpl = impl;
    mConnection.emplace(ua::client::detail::ConnectionHandleFactory::make_connection(std::move(impl)));
  }

  ~StartedConnection()
  {
    if (mConnection)
      (void)mConnection->try_close_sync();
  }

  StartedConnection(const StartedConnection&) = delete;
  StartedConnection& operator=(const StartedConnection&) = delete;

  const VoidResult& start_status() const
  {
    return mStartStatus;
  }

  Connection& operator*()
  {
    return *mConnection;
  }

  Connection* operator->()
  {
    return &*mConnection;
  }

  /// Stimulates the only part of a fresh-Session reconnect that is not publicly drivable in this
  /// single-shot fixture: publication of a new Session identity generation. Cursor construction and the
  /// operation under test remain on the public tier-2 API; this is a test-only stimulus hook.
  void simulate_fresh_session_install()
  {
    using TestAccess = ua::client::detail::ConnectionImplTestAccess;
    TestAccess::set_browse_session_generation(*mImpl, TestAccess::browse_session_generation(*mImpl) + 1);
  }

private:
  std::shared_ptr<ua::client::detail::ConnectionImpl> mImpl;
  VoidResult mStartStatus{};  // default-constructs to Good
  std::optional<Connection> mConnection;
};

// ---------------------------------------------------------------------------------------------
// A read-only capture of the BrowseNext requests the client put on the wire (release flag + continuation
// points), populated on a server strand by the MisbehavingServer request observer and read by the test
// thread. Guarded because the two run concurrently.
// ---------------------------------------------------------------------------------------------
struct CapturedBrowseNext
{
  bool release = false;
  std::vector<ua::ContinuationPoint> continuationPoints;
};

struct RequestCapture
{
  mutable std::mutex mutex;
  std::size_t browses = 0;
  std::vector<CapturedBrowseNext> browseNexts;

  // The observer forwarded by MisbehavingServer::set_request_observer records Browse and BrowseNext requests.
  void observe(const ua::Structure& request)
  {
    if (dynamic_cast<const ua::BrowseRequest*>(&request))
    {
      std::lock_guard lock(mutex);
      ++browses;
      return;
    }
    if (const auto* browseNext = dynamic_cast<const ua::BrowseNextRequest*>(&request))
    {
      CapturedBrowseNext captured;
      captured.release = browseNext->release_continuation_points();
      for (const auto& continuationPoint : browseNext->continuation_points())
        captured.continuationPoints.push_back(continuationPoint);
      std::lock_guard lock(mutex);
      browseNexts.push_back(std::move(captured));
    }
  }

  std::size_t browse_count() const
  {
    std::lock_guard lock(mutex);
    return browses;
  }

  std::size_t browse_next_count() const
  {
    std::lock_guard lock(mutex);
    return browseNexts.size();
  }

  std::vector<CapturedBrowseNext> snapshot() const
  {
    std::lock_guard lock(mutex);
    return browseNexts;
  }
};

// Busy-wait until @p predicate holds or @p timeout elapses (for the async fire-and-forget release BrowseNext
// that the cursor destructor posts). Returns the final predicate value.
bool wait_until(const std::function<bool()>& predicate, std::chrono::milliseconds timeout = 3000ms)
{
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (predicate())
      return true;
    std::this_thread::sleep_for(5ms);
  }
  return predicate();
}

// ---------------------------------------------------------------------------------------------
// MisbehavingBrowseFixture: a real client bound to a MisbehavingServer's crypto + trusted certificate store,
// on its own thread pool, with an activated Session wrapped into a started tier-2 Connection. Mirror of the
// ClientRead slice's MisbehavingReadFixture. The bootstrap completes against the un-mutated server; the test
// arms the response mutators / request observer AFTER construction.
// ---------------------------------------------------------------------------------------------
class MisbehavingBrowseFixture
{
public:
  explicit MisbehavingBrowseFixture(
    MisbehavingServer& server, ua::client::detail::ConnectionConfig config = {})
  {
    auto appConfig = ua::test_utils::create_test_config();
    const auto clientStore = server.client_certificate_store();
    const auto ownCertificates = clientStore->try_get_application_certificates_sync();
    if (ownCertificates.is_good() && !ownCertificates.value().empty() &&
        ownCertificates.value().front().certificate)
    {
      const auto sanUris = ownCertificates.value().front().certificate->san_uris();
      if (!sanUris.empty())
        appConfig.application_description_part().applicationUri = sanUris.front();
    }
    ua::client::CreateConfig clientConfig{
      .identity = ApplicationIdentity::load_default(), .application = std::move(appConfig)};
    mClient.emplace(Client::create(mThreadPool.executor(),
      std::move(clientConfig),
      ua::client::ClientComponents{.crypto = server.crypto(),
        .applicationGroupCertificateStore = clientStore,
        .logLevel = LogLevel::Warning}));

    CoreClient::OpenChannelConfig openConfig;
    openConfig.endpointUrl = server.endpoint_url_none();
    openConfig.timeout = 5000ms;
    auto channel = mClient->core().open_channel_sync(openConfig);
    auto session = channel.create_session_sync({.sessionName = "ClientBrowseMatrix"});
    session.activate_sync();
    mConnection.emplace(mThreadPool.executor(), std::move(session), std::move(config));
  }

  ~MisbehavingBrowseFixture()
  {
    mConnection.reset();
    mClient.reset();
    ua::test_utils::drain_with_timeout(mThreadPool);
  }

  MisbehavingBrowseFixture(const MisbehavingBrowseFixture&) = delete;
  MisbehavingBrowseFixture& operator=(const MisbehavingBrowseFixture&) = delete;

  Connection& conn()
  {
    return **mConnection;
  }

  StartedConnection& started()
  {
    return *mConnection;
  }

  const VoidResult& start_status() const
  {
    return mConnection->start_status();
  }

private:
  boost::asio::thread_pool mThreadPool;
  std::optional<Client> mClient;
  std::optional<StartedConnection> mConnection;
};

// A node present on every server (the Root folder organizes Objects/Types/Views: >1 forward reference, so a
// page size of 1 forces the real server to hand back a genuine continuation point).
NodeId root_folder()
{
  return NodeId{ObjectId::RootFolder};
}

// Builds an injected forward reference to @p target for the response-mutator rows.
ua::ReferenceDescription make_reference(const ua::NodeId& target, std::string_view name = "Injected")
{
  ua::ReferenceDescription reference;
  reference.node_id().node_id() = target;
  reference.is_forward() = true;
  reference.reference_type_id() = ua::NodeId{ua::ReferenceTypeId::Organizes};
  reference.browse_name() = ua::QualifiedName{0, std::string{name}};
  reference.display_name() = ua::LocalizedText{"", std::string{name}};
  reference.node_class() = ua::NodeClass::Object;
  return reference;
}

// Counts the ConnectionObserver diagnostic hooks (on_advisory_diagnostic) for the CL-VIEW-017 advisory row.
class AdvisoryCountingObserver : public ua::client::ConnectionObserver
{
public:
  void on_advisory_diagnostic(
    const ua::client::Connection&, std::shared_ptr<const ua::ErrorDetail> detail) override
  {
    mAdvisoryFires.fetch_add(1, std::memory_order_acq_rel);
    if (detail)
    {
      std::lock_guard<std::mutex> guard(mLastCodeMutex);
      mLastCode = detail->code;
    }
  }

  int advisory_fires() const
  {
    return mAdvisoryFires.load(std::memory_order_acquire);
  }

  std::string last_code() const
  {
    std::lock_guard<std::mutex> guard(mLastCodeMutex);
    return mLastCode;
  }

private:
  std::atomic<int> mAdvisoryFires{0};
  mutable std::mutex mLastCodeMutex;
  std::string mLastCode;
};

// Overwrites a BrowseResult page (status Good) with @p references and @p continuationPoint.
void set_page(ua::BrowseResult& result, std::vector<ua::ReferenceDescription> references,
  ua::ContinuationPoint continuationPoint)
{
  result.status_code() = ua::StatusCode{ua::Status::Good};
  ua::Array<ua::ReferenceDescription> array;
  for (auto& reference : references)
    array.push_back(std::move(reference));
  result.references() = std::move(array);
  result.continuation_point() = std::move(continuationPoint);
}

}  // namespace

// =============================================================================================
// Fixture: one gtest suite `ClientBrowse`. Derives from ComplianceWithNodes so the real-server rows have a
// populated address space; adds a pagination parent (7 typed children) and a HasDictionaryEntry hierarchy
// before the server starts.
// =============================================================================================
class ClientBrowse : public ComplianceWithNodes
{
protected:
  void configure_server() override
  {
    ComplianceWithNodes::configure_server();

    auto addressSpace = mServer.server().address_space();

    // Pagination parent: an Object with exactly 7 forward HasComponent references to typed Variables. With a
    // page size of 2 the server pages 2,2,2,1 (three full pages + a short final page), so the cursor must
    // drive BrowseNext off the continuation point, not the array size.
    mPaginationParentId = NodeId{mTestNamespaceIndex, uint32_t{9000}};
    auto parentNode = addressSpace.create_node_sync(mPaginationParentId, NodeClass::Object);
    auto parent = parentNode.as<ObjectAccessor>();
    parent->set_browse_name(QualifiedName{mTestNamespaceIndex, "PaginationParent"});
    parent->set_display_name(LocalizedText{"", "PaginationParent"});
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mPaginationParentId);

    for (uint32_t i = 0; i < sPaginationChildCount; ++i)
    {
      NodeId childId{mTestNamespaceIndex, uint32_t{9010 + i}};
      mPaginationChildIds.push_back(childId);
      auto childNode = addressSpace.create_node_sync(childId, NodeClass::Variable);
      auto child = childNode.as<VariableAccessor>();
      const auto name = "PagChild" + std::to_string(i);
      child->set_browse_name(QualifiedName{mTestNamespaceIndex, name});
      child->set_display_name(LocalizedText{"", name});
      child->set_data_type(NodeId{DataTypeId::Int32});
      child->write_value_sync(int32_t{static_cast<int32_t>(i)});
      child->set_access_level(AccessLevelType{AccessLevelType::Bit::CurrentRead});
      // A HasTypeDefinition so the TypeDefinition result-mask field is populated (verifying it is OMITTED
      // when masked out, ResultMask rows).
      childNode.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{VariableTypeId::BaseDataVariableType});
      parentNode.add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, childId);
    }

    // HasDictionaryEntry hierarchy: a source Object with three forward HasDictionaryEntry references - two to
    // DictionaryEntryType-family targets (Irdi / Uri) and one to a non-DictionaryEntryType target.
    mDictSourceId = NodeId{mTestNamespaceIndex, uint32_t{9100}};
    auto dictSourceNode = addressSpace.create_node_sync(mDictSourceId, NodeClass::Object);
    auto dictSource = dictSourceNode.as<ObjectAccessor>();
    dictSource->set_browse_name(QualifiedName{mTestNamespaceIndex, "DictSource"});
    dictSource->set_display_name(LocalizedText{"", "DictSource"});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mDictSourceId);

    auto makeDictTarget = [&](uint32_t id, std::string_view name, ObjectTypeId typeDefinition) -> NodeId
    {
      NodeId targetId{mTestNamespaceIndex, id};
      auto targetNode = addressSpace.create_node_sync(targetId, NodeClass::Object);
      auto target = targetNode.as<ObjectAccessor>();
      target->set_browse_name(QualifiedName{mTestNamespaceIndex, std::string{name}});
      target->set_display_name(LocalizedText{"", std::string{name}});
      targetNode.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{typeDefinition});
      dictSourceNode.add_reference_sync(NodeId{ReferenceTypeId::HasDictionaryEntry}, targetId);
      return targetId;
    };
    mDictIrdiTargetId = makeDictTarget(9101, "IrdiTarget", ObjectTypeId::IrdiDictionaryEntryType);
    mDictUriTargetId = makeDictTarget(9102, "UriTarget", ObjectTypeId::UriDictionaryEntryType);
    mDictWrongTargetId = makeDictTarget(9103, "WrongTarget", ObjectTypeId::BaseObjectType);
  }

  Session open_activated_session(std::string name)
  {
    auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
    auto session = channel.create_session_sync({.sessionName = std::move(name)});
    session.activate_sync();
    return session;
  }

  static constexpr uint32_t sPaginationChildCount = 7;
  NodeId mPaginationParentId;
  std::vector<NodeId> mPaginationChildIds;
  NodeId mDictSourceId;
  NodeId mDictIrdiTargetId;
  NodeId mDictUriTargetId;
  NodeId mDictWrongTargetId;
};

// =============================================================================================
// Row 1 - CursorDropReleasesContinuationPoint  (MisbehavingServer)
// Dropping a cursor that still holds a non-empty continuation point must post a release-only BrowseNext
// (releaseContinuationPoints=TRUE) carrying that continuation point, so the server-side CP is not leaked.
// [neg: abandoned CP must be explicitly released]
// =============================================================================================
// @verifies AC-CL-VIEW-002-RELEASE-CP
// @relation(AC-CL-VIEW-002-RELEASE-CP, scope=function)
TEST_F(ClientBrowse, CursorDropReleasesContinuationPoint)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });

  // A real continuation point: page size 1 over RootFolder (3 forward references) makes the real server hand
  // back a genuine CP after the first reference.
  BrowseOptions options;
  options.requestedMaxReferencesPerNode = 1;

  {
    auto cursor = fixture.conn().typed().browse(root_folder(), options);
    auto first = cursor.try_next_sync();
    ASSERT_TRUE(first.is_good()) << "the first reference must be delivered: "
                                 << to_string(first.status_code());
    ASSERT_TRUE(cursor.has_more()) << "a continuation point is held after the first (of three) reference";
    ASSERT_EQ(capture->browse_next_count(), 0u)
      << "no BrowseNext yet (the page was consumed from the buffer)";
  }  // ~BrowseCursor posts a release-only BrowseNext (fire-and-forget)

  ASSERT_TRUE(wait_until([&] { return capture->browse_next_count() >= 1; }))
    << "dropping a cursor holding a continuation point must issue a release BrowseNext";
  auto browseNexts = capture->snapshot();
  ASSERT_EQ(browseNexts.size(), 1u) << "exactly one BrowseNext - the RAII release";
  EXPECT_TRUE(browseNexts[0].release) << "the abandoned CP must be released (releaseContinuationPoints=TRUE)";
  ASSERT_EQ(browseNexts[0].continuationPoints.size(), 1u);
  EXPECT_FALSE(browseNexts[0].continuationPoints[0].empty())
    << "the release must carry the held (non-empty) continuation point";
}

// =============================================================================================
// Row 2 - CursorInvalidatedOnSessionChangeNoDoomedBrowseNext  (MisbehavingServer, reconnect)
// A cursor must not replay a doomed BrowseNext once its underlying session is no longer usable.
// [neg: stale cursor must not replay across sessions]
//
// This fixture intentionally owns no reconnect FSM, so it uses a private test hook solely to publish the
// fresh-Session generation change that reconnect_commit publishes in production. Construction, cursor
// creation, and the operation/assertions under test all remain at the public tier-2 API.
// =============================================================================================
// @verifies CL-VIEW-001
// @relation(CL-VIEW-001, scope=function)
TEST_F(ClientBrowse, CursorInvalidatedOnSessionChangeNoDoomedBrowseNext)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });

  BrowseOptions options;
  options.requestedMaxReferencesPerNode = 1;
  auto cursor = fixture.conn().typed().browse(root_folder(), options);

  auto first = cursor.try_next_sync();
  ASSERT_TRUE(first.is_good()) << "the first reference must be delivered before the session is dropped";
  ASSERT_TRUE(cursor.has_more()) << "a continuation point is held (a BrowseNext would otherwise follow)";
  ASSERT_EQ(capture->browse_next_count(), 0u) << "no BrowseNext has been issued yet";

  fixture.started().simulate_fresh_session_install();

  auto afterSessionChange = cursor.try_next_sync();
  ASSERT_TRUE(afterSessionChange.is_bad());
  EXPECT_EQ(afterSessionChange.status_code(), ua::StatusCode{ua::Status::BadSessionIdInvalid});
  ASSERT_NE(afterSessionChange.shared_detail(), nullptr);
  EXPECT_EQ(afterSessionChange.shared_detail()->code, "BrowseCursorSessionChanged");
  EXPECT_EQ(capture->browse_next_count(), 0u)
    << "no doomed BrowseNext (the stale continuation point) may reach the replacement Session";
}

// =============================================================================================
// Row 3 - CursorPaginatesViaContinuationPointNotArraySize  (ComplianceWithNodes)
// For a node with N*max+1 references, the cursor must yield exactly N*max+1 entries by keying pagination on
// continuation-point presence, not on 'page size == requestedMax'.
// [neg: pagination keyed on CP, not size]
// =============================================================================================
// @verifies CL-VIEW-003
// @relation(CL-VIEW-003, scope=function)
TEST_F(ClientBrowse, CursorPaginatesViaContinuationPointNotArraySize)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("B3")};
  ASSERT_TRUE(connection.start_status().is_good());

  // 7 children, page size 2 -> the server pages 2,2,2,1 (three full pages carrying a CP + a short final page
  // with an empty CP). A loop keyed on 'size==max means more' would either stop after the first short page or
  // issue a doomed extra BrowseNext.
  BrowseOptions options;
  options.direction = BrowseDirection::Forward;
  options.referenceTypeId = NodeId{ReferenceTypeId::HasComponent};
  options.includeSubtypes = false;
  options.requestedMaxReferencesPerNode = 2;

  auto cursor = connection->typed().browse(mPaginationParentId, options);

  std::vector<NodeId> seen;
  for (;;)
  {
    auto next = cursor.try_next_sync();
    if (next.is_bad())
    {
      EXPECT_EQ(next.status_code(), StatusCode{Status::BadNoData})
        << "the walk terminates by exhaustion, not a service error: " << to_string(next.status_code());
      break;
    }
    seen.push_back(next.value().targetNodeId);
    ASSERT_LE(seen.size(), sPaginationChildCount + 1) << "the cursor must not over-yield (doomed BrowseNext)";
  }

  EXPECT_EQ(seen.size(), sPaginationChildCount)
    << "the cursor must yield every reference across the paged BrowseNext walk";
  for (const auto& childId : mPaginationChildIds)
    EXPECT_NE(std::find(seen.begin(), seen.end(), childId), seen.end())
      << "child " << to_string(childId) << " must appear exactly once in the paged walk";
}

// =============================================================================================
// Row 4 - EmptyPageWithContinuationContinues  (MisbehavingServer)
// A Good page with empty References but a non-null continuation point (Err-019) is valid mid-stream: the
// cursor must issue a BrowseNext and yield the later references, not treat the empty page as end-of-results.
// [neg: empty page + CP is valid mid-stream]
// =============================================================================================
// @verifies AC-CL-VIEW-005-CP-IS-THE-SIGNAL
// @relation(AC-CL-VIEW-005-CP-IS-THE-SIGNAL, scope=function)
TEST_F(ClientBrowse, EmptyPageWithContinuationContinues)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const NodeId laterTarget{VariableId::Server_ServerStatus_State};
  server.set_response_mutator(
    [laterTarget](Response& response)
    {
      if (auto* browse = dynamic_cast<BrowseResponse*>(response.second.get()))
      {
        // Initial Browse: an EMPTY page carrying a non-null continuation point.
        if (!browse->results().empty())
          set_page(browse->results()[0], {}, ua::ContinuationPoint{0xAB, 0xCD});
      }
      else if (auto* browseNext = dynamic_cast<BrowseNextResponse*>(response.second.get()))
      {
        // BrowseNext: the real page with the later reference and no further CP.
        if (!browseNext->results().empty())
          set_page(browseNext->results()[0], {make_reference(laterTarget, "Later")}, ua::ContinuationPoint{});
      }
    });

  auto cursor = fixture.conn().typed().browse(root_folder());
  auto entry = cursor.try_next_sync();
  ASSERT_TRUE(entry.is_good())
    << "the empty page + CP must drive a BrowseNext that yields the later reference: "
    << to_string(entry.status_code());
  EXPECT_EQ(entry.value().targetNodeId, laterTarget)
    << "the reference that arrived only after the empty-page BrowseNext must be delivered, not dropped";
}

// =============================================================================================
// Row 5 - FollowsHasDictionaryEntryToTypedTargets  (ComplianceWithNodes)
// The typed dictionary helper must return all conformant targets in browse order with their TypeDefinitions,
// skip the wrong-typed target, and emit an advisory rather than failing the whole browse.
// =============================================================================================
// @verifies CL-ADDRSP-015
// @relation(CL-ADDRSP-015, scope=function)
TEST_F(ClientBrowse, FollowsHasDictionaryEntryToTypedTargets)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("B5")};
  ASSERT_TRUE(connection.start_status().is_good());
  auto observer = std::make_shared<AdvisoryCountingObserver>();
  connection->set_connection_observer(observer);

  auto entriesResult = connection->typed().try_dictionary_entries_for_sync(mDictSourceId);
  ASSERT_TRUE(entriesResult.is_good());
  const auto& entries = entriesResult.value();

  auto findEntry = [&](const NodeId& target) -> const BrowseCursor::Entry*
  {
    for (const auto& entry : entries)
      if (entry.targetNodeId == target)
        return &entry;
    return nullptr;
  };

  const BrowseCursor::Entry* irdi = findEntry(mDictIrdiTargetId);
  const BrowseCursor::Entry* uri = findEntry(mDictUriTargetId);
  ASSERT_NE(irdi, nullptr) << "the IRDI DictionaryEntry target must be returned";
  ASSERT_NE(uri, nullptr) << "the URI DictionaryEntry target must be returned";
  EXPECT_EQ(irdi->typeDefinition, NodeId{ObjectTypeId::IrdiDictionaryEntryType})
    << "the IRDI target must carry its TypeDefinition";
  EXPECT_EQ(uri->typeDefinition, NodeId{ObjectTypeId::UriDictionaryEntryType})
    << "the URI target must carry its TypeDefinition";
  EXPECT_EQ(findEntry(mDictWrongTargetId), nullptr) << "a non-DictionaryEntryType target must be skipped";
  for (int attempt = 0; attempt < 200 && observer->advisory_fires() < 1; ++attempt)
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
  EXPECT_EQ(observer->advisory_fires(), 1);
  EXPECT_EQ(observer->last_code(), "NonConformantDictionaryEntryTarget");
}

// =============================================================================================
// Row 6 - GoodMoreDataWithoutContinuationPointEmitsAdvisory  (MisbehavingServer)
// A Good_MoreData status with an EMPTY continuation point and empty References (Err-024) is a server
// non-conformance: the cursor must TERMINATE (trusting CP-empty over the Good_MoreData sub-code), not loop
// forever waiting for data that never comes. [neg: Good_MoreData without CP is a server bug]
//
// Built end-to-end (CL-VIEW-005): the cursor's advisory interface surfaces the non-conformance via
// on_advisory_diagnostic ("BrowseGoodMoreDataWithoutContinuationPoint") while still TERMINATING safely - it
// does NOT hang or issue a doomed BrowseNext. This asserts both halves: the safety-critical termination AND
// the advisory now fires with the right code.
// =============================================================================================
// @verifies AC-CL-VIEW-005-CP-IS-THE-SIGNAL
// @relation(AC-CL-VIEW-005-CP-IS-THE-SIGNAL, scope=function)
TEST_F(ClientBrowse, GoodMoreDataWithoutContinuationPointEmitsAdvisory)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto observer = std::make_shared<AdvisoryCountingObserver>();
  fixture.conn().set_connection_observer(observer);

  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* browse = dynamic_cast<BrowseResponse*>(response.second.get()))
      {
        if (!browse->results().empty())
        {
          set_page(browse->results()[0], {}, ua::ContinuationPoint{});  // empty refs, empty CP
          browse->results()[0].status_code() = StatusCode{Status::GoodMoreData};  // but claims "more"
        }
      }
    });

  auto cursor = fixture.conn().typed().browse(root_folder());
  auto entry = cursor.try_next_sync();
  EXPECT_TRUE(entry.is_bad()) << "Good_MoreData with an empty CP must terminate the walk, not loop forever";
  EXPECT_EQ(entry.status_code(), StatusCode{Status::BadNoData})
    << "the terminated walk reports exhaustion (no references, no CP)";
  EXPECT_FALSE(cursor.has_more()) << "the cursor must not claim more data on a CP-empty Good_MoreData page";
  EXPECT_EQ(capture->browse_next_count(), 0u)
    << "trusting Good_MoreData over the empty CP would issue a doomed BrowseNext; none must be sent";
  // The observer is called from a posted task, so the advisory can arrive after try_next_sync returns.
  ASSERT_TRUE(wait_until([&] { return observer->advisory_fires() >= 1; }))
    << "a Good_MoreData page with an empty continuation point is non-conformant and must surface an advisory";
  EXPECT_EQ(observer->last_code(), "BrowseGoodMoreDataWithoutContinuationPoint")
    << "the advisory must carry the specific non-conformance code";
}

// =============================================================================================
// Row 7 - LongContinuationPointRoundTrippedUnmodified  (MisbehavingServer)
// A 1000-byte continuation point handed to the client must be replayed byte-identical in the follow-up
// BrowseNext (the opaque CP is preserved verbatim, never truncated or rewritten).
// [neg: opaque CP must be preserved verbatim]
// =============================================================================================
// @verifies CL-VIEW-005
// @relation(CL-VIEW-005, scope=function)
TEST_F(ClientBrowse, LongContinuationPointRoundTrippedUnmodified)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  // A recognisable 1000-byte opaque continuation point (byte[i] = i % 251, a non-trivial pattern).
  std::vector<uint8_t> longBytes(1000);
  for (std::size_t i = 0; i < longBytes.size(); ++i)
    longBytes[i] = static_cast<uint8_t>(i % 251);
  const ua::ContinuationPoint longContinuationPoint{longBytes};

  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });
  server.set_response_mutator(
    [longContinuationPoint](Response& response)
    {
      if (auto* browse = dynamic_cast<BrowseResponse*>(response.second.get()))
      {
        // Initial Browse: one reference + the 1000-byte continuation point.
        if (!browse->results().empty())
          set_page(browse->results()[0],
            {make_reference(NodeId{VariableId::Server_ServerStatus_State}, "First")},
            longContinuationPoint);
      }
    });

  auto cursor = fixture.conn().typed().browse(root_folder());
  auto first = cursor.try_next_sync();
  ASSERT_TRUE(first.is_good()) << "the first (pre-continuation) reference must be delivered";

  // The second advance replays the 1000-byte CP in a BrowseNext. The real server rejects the unknown CP, so
  // this advance completes bad - the assertion is on the OUTGOING request the observer captured.
  (void)cursor.try_next_sync();

  ASSERT_TRUE(wait_until([&] { return capture->browse_next_count() >= 1; }))
    << "the cursor must issue a BrowseNext for the held continuation point";
  auto browseNexts = capture->snapshot();
  ASSERT_GE(browseNexts.size(), 1u);
  ASSERT_FALSE(browseNexts[0].release) << "a data BrowseNext, not a release";
  ASSERT_EQ(browseNexts[0].continuationPoints.size(), 1u);
  const ua::ContinuationPoint& sent = browseNexts[0].continuationPoints[0];
  ASSERT_EQ(sent.size(), longBytes.size()) << "the 1000-byte continuation point must not be truncated";
  EXPECT_TRUE(std::equal(sent.begin(), sent.end(), longBytes.begin()))
    << "the opaque continuation point must be replayed byte-for-byte, not rewritten";
}

// =============================================================================================
// Row 8 - MixedPerNodeFailuresPreserveOrder  (MisbehavingServer)
// Three different per-node bad codes in one Browse response must each appear at their correct index; results
// must not be re-ordered or de-duplicated. [neg: positional integrity of mixed failures]
// =============================================================================================
// @verifies AC-CL-VIEW-004-PERNODE-STATUS
// @relation(AC-CL-VIEW-004-PERNODE-STATUS, scope=function)
TEST_F(ClientBrowse, MixedPerNodeFailuresPreserveOrder)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  server.set_response_mutator(
    [](Response& response)
    {
      auto* browse = dynamic_cast<BrowseResponse*>(response.second.get());
      if (!browse || browse->results().size() != 3)
        return;
      browse->results()[0].status_code() = StatusCode{Status::BadNodeIdInvalid};
      browse->results()[1].status_code() = StatusCode{Status::BadNodeIdUnknown};
      browse->results()[2].status_code() = StatusCode{Status::BadReferenceTypeIdInvalid};
    });

  auto request = BrowseRequestBuilder()
                   .browse(NodeId{ObjectId::RootFolder})
                   .browse(NodeId{ObjectId::ObjectsFolder})
                   .browse(NodeId{ObjectId::Server})
                   .build();
  auto result = fixture.conn().service_requests().try_browse_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "the Browse service itself succeeds; the failures are per-node";
  ASSERT_EQ(result.value().results().size(), 3u);
  EXPECT_EQ(result.value().results()[0].status_code(), StatusCode{Status::BadNodeIdInvalid})
    << "index 0's code must stay at index 0";
  EXPECT_EQ(result.value().results()[1].status_code(), StatusCode{Status::BadNodeIdUnknown})
    << "index 1's code must stay at index 1";
  EXPECT_EQ(result.value().results()[2].status_code(), StatusCode{Status::BadReferenceTypeIdInvalid})
    << "index 2's code must stay at index 2";
}

// =============================================================================================
// Row 9 - NullAndEmptyContinuationPointMeanDone  (MisbehavingServer)
// A null continuation point (case A) and a zero-length continuation point (case B) after a full page must
// BOTH terminate the cursor; no subsequent BrowseNext may be issued. [neg: null == empty == done]
// =============================================================================================
// @verifies AC-CL-VIEW-005-CP-IS-THE-SIGNAL
// @relation(AC-CL-VIEW-005-CP-IS-THE-SIGNAL, scope=function)
TEST_F(ClientBrowse, NullAndEmptyContinuationPointMeanDone)
{
  for (int mode = 0; mode < 2; ++mode)  // 0 = null CP, 1 = zero-length CP
  {
    MisbehavingServer server;
    MisbehavingBrowseFixture fixture{server};
    ASSERT_TRUE(fixture.start_status().is_good());

    auto capture = std::make_shared<RequestCapture>();
    server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });

    const ua::ContinuationPoint terminalCp =
      (mode == 0) ? ua::ContinuationPoint{} : ua::ContinuationPoint{std::vector<uint8_t>{}};
    server.set_response_mutator(
      [terminalCp](Response& response)
      {
        if (auto* browse = dynamic_cast<BrowseResponse*>(response.second.get()))
        {
          if (!browse->results().empty())
            set_page(browse->results()[0],
              {make_reference(NodeId{VariableId::Server_ServerStatus_State}, "Only")},
              terminalCp);
        }
      });

    auto cursor = fixture.conn().typed().browse(root_folder());
    auto first = cursor.try_next_sync();
    ASSERT_TRUE(first.is_good()) << "mode " << mode << ": the single page reference must be delivered";
    EXPECT_FALSE(cursor.has_more()) << "mode " << mode << ": a null/empty CP means the walk is done";

    auto second = cursor.try_next_sync();
    EXPECT_TRUE(second.is_bad()) << "mode " << mode << ": the walk is exhausted after the terminal CP";
    EXPECT_EQ(capture->browse_next_count(), 0u)
      << "mode " << mode << ": a null/empty continuation point must issue NO BrowseNext (== done)";
  }
}

// =============================================================================================
// Row 10 - PerNodeBadStatusSurfacedIndependently  (MisbehavingServer)
// Across a multi-node Browse, each per-node bad/uncertain status must surface at its exact index while a
// Good peer returns normally; Uncertain must NOT be reclassified as Bad.
// [neg: Bad_NoContinuationPoints per-node + Uncertain preserved]
// =============================================================================================
// @verifies AC-CL-VIEW-004-PERNODE-STATUS
// @relation(AC-CL-VIEW-004-PERNODE-STATUS, scope=function)
TEST_F(ClientBrowse, PerNodeBadStatusSurfacedIndependently)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto injected = std::make_shared<std::atomic<uint32_t>>(0);
  server.set_response_mutator(
    [injected](Response& response)
    {
      auto* browse = dynamic_cast<BrowseResponse*>(response.second.get());
      if (!browse || browse->results().size() != 2)
        return;
      const uint32_t code = injected->load();
      if (code != 0)
        browse->results()[0].status_code() = StatusCode{code};  // slot 1 (index 0) parameterised
      // index 1 keeps the server's real Good BrowseResult (the untouched peer)
    });

  for (Status status : {Status::BadNodeIdInvalid,
         Status::BadNodeIdUnknown,
         Status::BadReferenceTypeIdInvalid,
         Status::BadBrowseDirectionInvalid,
         Status::BadNodeNotInView,
         Status::BadNoContinuationPoints,
         Status::UncertainNotAllNodesAvailable})
  {
    injected->store(StatusCode{status}.as_uint32());
    auto request = BrowseRequestBuilder()
                     .browse(NodeId{ObjectId::RootFolder})
                     .browse(NodeId{ObjectId::ObjectsFolder})
                     .build();
    auto result = fixture.conn().service_requests().try_browse_sync(std::move(request));
    ASSERT_TRUE(result.is_good()) << "the Browse service itself succeeds; the failure is per-node";
    ASSERT_EQ(result.value().results().size(), 2u);

    EXPECT_EQ(result.value().results()[0].status_code(), StatusCode{status})
      << "the injected per-node code 0x" << std::hex << StatusCode{status}.as_uint32()
      << " must surface at index 0";
    if (status == Status::UncertainNotAllNodesAvailable)
      EXPECT_TRUE(result.value().results()[0].status_code().is_uncertain())
        << "Uncertain must NOT be reclassified as Bad";
    EXPECT_TRUE(result.value().results()[1].status_code().is_good())
      << "the untouched Good peer at index 1 must return normally (one bad node must not poison the batch)";
  }
}

// =============================================================================================
// Row 11 - RemoteReferenceOptionalFieldsTolerated  (MisbehavingServer)
// Case A: a remote reference with null browseName, null typeDefinition, NodeClass=Unspecified must surface
// with empty fields and NO error. Case B: a remote reference with an empty displayName must surface AND emit
// an advisory (displayName mandatory for remotes). [neg: missing mandatory displayName on remote ref]
//
// BUILT (CL-VIEW-017): both cases pin the built guarantee - the cursor TOLERATES null/empty optional fields
// on a remote reference and surfaces the entry rather than rejecting it. Case B additionally pins the
// advisory: a remote reference (serverIndex != 0) with an empty displayName emits on_advisory_diagnostic (the
// cursor now holds an observer interface via the Connection's ObserverSink), while a conformant remote
// reference (Case A, present displayName) does NOT.
// =============================================================================================
// @verifies AC-CL-VIEW-017-REMOTE-TARGETS
// @relation(AC-CL-VIEW-017-REMOTE-TARGETS, scope=function)
TEST_F(ClientBrowse, RemoteReferenceOptionalFieldsTolerated)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto observer = std::make_shared<AdvisoryCountingObserver>();
  fixture.conn().set_connection_observer(observer);

  auto mode = std::make_shared<std::atomic<int>>(0);  // 1 = case A (null fields), 2 = case B (empty display)
  server.set_response_mutator(
    [mode](Response& response)
    {
      auto* browse = dynamic_cast<BrowseResponse*>(response.second.get());
      if (!browse || browse->results().empty())
        return;
      ua::ReferenceDescription reference;
      reference.node_id().node_id() = NodeId{VariableId::Server_ServerStatus_State};
      reference.node_id().server_index() = 7;  // a REMOTE reference (displayName is mandatory for remotes)
      reference.is_forward() = true;
      reference.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
      if (mode->load() == 1)
      {
        // Case A: null browseName, null typeDefinition, NodeClass=Unspecified, PRESENT displayName
        // (conformant).
        reference.display_name() = LocalizedText{"", "PresentDisplay"};
        reference.node_class() = ua::NodeClass::Unspecified;
      }
      else
      {
        // Case B: present browseName, EMPTY displayName (non-conformant remote).
        reference.browse_name() = QualifiedName{0, "RemoteName"};
        reference.node_class() = ua::NodeClass::Object;
        reference.display_name() = LocalizedText{};
      }
      set_page(browse->results()[0], {std::move(reference)}, ua::ContinuationPoint{});
    });

  // Case A: null optional fields tolerated, entry surfaced, no error, and (conformant displayName) NO
  // advisory.
  mode->store(1);
  {
    auto cursor = fixture.conn().typed().browse(root_folder());
    auto entry = cursor.try_next_sync();
    ASSERT_TRUE(entry.is_good()) << "case A: null optional fields must be tolerated, not rejected";
    EXPECT_EQ(entry.value().targetNodeId.node_id(), NodeId{VariableId::Server_ServerStatus_State});
    EXPECT_EQ(entry.value().targetNodeId.server_index(), 7u) << "the remote serverIndex is preserved";
    EXPECT_TRUE(entry.value().browseName.name().empty()) << "case A: the null browseName surfaces empty";
    EXPECT_EQ(entry.value().typeDefinition, NodeId{}) << "case A: the null typeDefinition surfaces empty";
    EXPECT_EQ(entry.value().nodeClass, ua::NodeClass::Unspecified);
  }
  std::this_thread::sleep_for(std::chrono::milliseconds{50});  // let any erroneous advisory reach the strand
  EXPECT_EQ(observer->advisory_fires(), 0)
    << "a conformant remote reference (present displayName) fires no advisory";

  // Case B: empty displayName still surfaces the entry AND emits on_advisory_diagnostic (non-conformant
  // remote).
  mode->store(2);
  {
    auto cursor = fixture.conn().typed().browse(root_folder());
    auto entry = cursor.try_next_sync();
    ASSERT_TRUE(entry.is_good()) << "case B: an empty displayName must still surface the entry, not error";
    EXPECT_EQ(entry.value().targetNodeId.node_id(), NodeId{VariableId::Server_ServerStatus_State});
    EXPECT_TRUE(entry.value().displayName.text().empty()) << "case B: the empty displayName is carried as-is";
  }
  for (int attempt = 0; attempt < 200 && observer->advisory_fires() < 1; ++attempt)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
  }
  EXPECT_EQ(observer->advisory_fires(), 1) << "case B: a remote reference missing its mandatory displayName "
                                              "must emit on_advisory_diagnostic (CL-VIEW-017)";
}

// =============================================================================================
// Row 12 - RemoteReferenceServerIndexPreserved  (MisbehavingServer)
// A reference whose targetNodeId carries serverIndex=10 must retain that serverIndex (ExpandedNodeId
// preserved), so the reference is not mistaken for a local one. [neg: remote serverIndex must survive]
//
// BUILT (CL-VIEW-017): `BrowseCursor::Entry::targetNodeId` is now an `ExpandedNodeId`, and `to_entry` keeps
// the full wire ExpandedNodeId, so a remote reference's serverIndex survives. The user detects a cross-server
// target via `targetNodeId.server_index() != 0`; the SDK does not auto-connect to follow it.
// =============================================================================================
// @verifies AC-CL-VIEW-017-REMOTE-TARGETS
// @relation(AC-CL-VIEW-017-REMOTE-TARGETS, scope=function)
TEST_F(ClientBrowse, RemoteReferenceServerIndexPreserved)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const NodeId remoteInner{VariableId::Server_ServerStatus_State};
  server.set_response_mutator(
    [remoteInner](Response& response)
    {
      auto* browse = dynamic_cast<BrowseResponse*>(response.second.get());
      if (!browse || browse->results().empty())
        return;
      ua::ReferenceDescription reference;
      reference.node_id().node_id() = remoteInner;
      reference.node_id().server_index() = 10;  // a remote (cross-server) reference
      reference.is_forward() = true;
      reference.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
      reference.browse_name() = QualifiedName{0, "Remote"};
      reference.display_name() = LocalizedText{"", "Remote"};
      reference.node_class() = ua::NodeClass::Object;
      set_page(browse->results()[0], {std::move(reference)}, ua::ContinuationPoint{});
    });

  auto cursor = fixture.conn().typed().browse(root_folder());
  auto entry = cursor.try_next_sync();
  ASSERT_TRUE(entry.is_good()) << "the remote reference must be surfaced (not dropped)";
  // BUILT (CL-VIEW-017): the serverIndex is preserved on the ExpandedNodeId targetNodeId.
  EXPECT_EQ(entry.value().targetNodeId.server_index(), 10u)
    << "the remote reference's serverIndex must be preserved (not narrowed to a local NodeId)";
  EXPECT_EQ(entry.value().targetNodeId.node_id(), remoteInner)
    << "the target's inner NodeId is surfaced alongside the serverIndex";
}

// =============================================================================================
// NamespaceUriTargetResolvedToLocalIndexOnBrowse - CL-VIEW-018 (end-to-end over MisbehavingServer)
// A LOCAL reference target whose ExpandedNodeId carries a NamespaceUri (wire index 0 per the codec invariant,
// Part 6 section 5.2.2.10) is resolved to its LOCAL NamespaceIndex during flattening - the URI overrides the
// encoded index. An UNMAPPED URI is preserved verbatim (no stale index substituted). This drives the WIRED
// tier-2 browse path (to_entry -> NamespaceTable::resolve_local against the Connection's bootstrapped
// snapshot), not the resolver in isolation. [neg: unmapped URI preserved, not indexed]
// =============================================================================================
// @verifies AC-CL-VIEW-018-NAMESPACEURI-WINS
// @relation(AC-CL-VIEW-018-NAMESPACEURI-WINS, scope=function)
TEST_F(ClientBrowse, NamespaceUriTargetResolvedToLocalIndexOnBrowse)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto table = fixture.conn().namespace_table();
  ASSERT_NE(table, nullptr) << "the bootstrap must publish a NamespaceTable snapshot to resolve against";
  // Resolve against the highest bootstrapped namespace (index >= 1 when the server publishes an application
  // namespace; NS0 index 0 otherwise - the wired resolution path is exercised either way: the URI is consumed
  // and dropped, the local index becomes authoritative).
  const auto localIndex = static_cast<ua::client::NamespaceIndex>(table->size() - 1);
  const std::string mappedUri{*table->lookup_uri(localIndex)};
  const std::string unmappedUri = "urn:vendor:namespace-absent-from-this-server";

  const NodeId innerNode{uint16_t{0}, uint32_t{4242}};  // wire namespace index 0 (a URI is present)
  server.set_response_mutator(
    [innerNode, mappedUri, unmappedUri](Response& response)
    {
      auto* browse = dynamic_cast<BrowseResponse*>(response.second.get());
      if (!browse || browse->results().empty())
        return;
      auto makeUriRef = [&](const std::string& uri, std::string_view name)
      {
        ua::ReferenceDescription reference;
        reference.node_id() = ua::ExpandedNodeId{innerNode, uri};  // URI-bearing target (wire index 0)
        reference.is_forward() = true;
        reference.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
        reference.browse_name() = QualifiedName{0, std::string{name}};
        reference.display_name() = LocalizedText{"", std::string{name}};
        reference.node_class() = ua::NodeClass::Object;
        return reference;
      };
      set_page(browse->results()[0],
        {makeUriRef(mappedUri, "Mapped"), makeUriRef(unmappedUri, "Unmapped")},
        ua::ContinuationPoint{});
    });

  auto cursor = fixture.conn().typed().browse(root_folder());

  // Entry 1: the mapped URI resolves to its local index and the URI is dropped.
  auto mapped = cursor.try_next_sync();
  ASSERT_TRUE(mapped.is_good()) << "the URI-bearing local reference must be surfaced";
  EXPECT_EQ(mapped.value().targetNodeId.node_id().namespace_index(), localIndex)
    << "the NamespaceUri must resolve to its local index (overriding the wire index 0)";
  EXPECT_EQ(mapped.value().targetNodeId.node_id().identifier().get_numeric(), 4242u)
    << "the identifier is preserved through resolution";
  EXPECT_TRUE(static_cast<std::string_view>(mapped.value().targetNodeId.namespace_uri()).empty())
    << "a resolved URI is dropped - the local index is now authoritative";

  // Entry 2: the unmapped URI is preserved verbatim (no stale index substituted).
  auto unmapped = cursor.try_next_sync();
  ASSERT_TRUE(unmapped.is_good()) << "an unmapped-URI reference is still surfaced (preserved, not dropped)";
  EXPECT_EQ(static_cast<std::string_view>(unmapped.value().targetNodeId.namespace_uri()), unmappedUri)
    << "an unmapped URI is preserved verbatim for user inspection, not substituted with a stale index";
}

// =============================================================================================
// Row 13 - ResultMaskSubsetReturnsPartialDescription  (ComplianceWithNodes)
// With resultMask=BrowseName|DisplayName, cursor entries expose those two fields and default-empty for the
// others, with no error raised for the (correctly) empty fields.
// [neg: unselected fields empty, not an error]
// =============================================================================================
// @verifies CL-VIEW-007
// @relation(CL-VIEW-007, scope=function)
TEST_F(ClientBrowse, ResultMaskSubsetReturnsPartialDescription)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("B13")};
  ASSERT_TRUE(connection.start_status().is_good());

  BrowseOptions options;
  options.referenceTypeId = NodeId{ReferenceTypeId::HasComponent};
  options.includeSubtypes = false;
  options.resultMask = static_cast<uint32_t>(BrowseResultMask::BrowseName) |
                       static_cast<uint32_t>(BrowseResultMask::DisplayName);

  auto cursor = connection->typed().browse(mPaginationParentId, options);
  auto entry = cursor.try_next_sync();
  ASSERT_TRUE(entry.is_good()) << "a partial result mask must not raise an error: "
                               << to_string(entry.status_code());

  EXPECT_NE(entry.value().targetNodeId, NodeId{}) << "the always-present nodeId must be populated";
  EXPECT_FALSE(entry.value().browseName.name().empty()) << "the selected BrowseName field must be populated";
  EXPECT_FALSE(entry.value().displayName.text().empty())
    << "the selected DisplayName field must be populated";
  EXPECT_EQ(entry.value().typeDefinition, NodeId{})
    << "the unselected TypeDefinition field must be empty, not an error";
  EXPECT_EQ(entry.value().referenceTypeId, NodeId{})
    << "the unselected ReferenceType field must be empty, not an error";
}

// =============================================================================================
// Row 14 - ResultMaskZeroReturnsOnlyNodeId  (ComplianceWithNodes)
// With resultMask=0, cursor entries carry only the always-present nodeId and every other field is
// default-empty. [neg: resultMask=0 edge]
// =============================================================================================
// @verifies CL-VIEW-007
// @relation(CL-VIEW-007, scope=function)
TEST_F(ClientBrowse, ResultMaskZeroReturnsOnlyNodeId)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("B14")};
  ASSERT_TRUE(connection.start_status().is_good());

  BrowseOptions options;
  options.referenceTypeId = NodeId{ReferenceTypeId::HasComponent};
  options.includeSubtypes = false;
  options.resultMask = 0;

  auto cursor = connection->typed().browse(mPaginationParentId, options);
  auto entry = cursor.try_next_sync();
  ASSERT_TRUE(entry.is_good()) << "resultMask=0 must not raise an error: " << to_string(entry.status_code());

  EXPECT_NE(entry.value().targetNodeId, NodeId{}) << "the nodeId is always present, even at resultMask=0";
  EXPECT_TRUE(entry.value().browseName.name().empty()) << "BrowseName must be default-empty at resultMask=0";
  EXPECT_TRUE(entry.value().displayName.text().empty())
    << "DisplayName must be default-empty at resultMask=0";
  EXPECT_EQ(entry.value().typeDefinition, NodeId{}) << "TypeDefinition must be default-empty at resultMask=0";
  EXPECT_EQ(entry.value().referenceTypeId, NodeId{}) << "ReferenceType must be default-empty at resultMask=0";
}

// =============================================================================================
// Row 15 - ServiceGoodButResultsEmptyRejected  (MisbehavingServer)
// A ServiceResult=Good response with a cleared Results[] array (Err-002) is a server contract violation: the
// cursor must surface Bad_UnexpectedError, not a silent empty success.
// [neg: Good service + missing results is a contract violation]
// =============================================================================================
// @verifies AC-CL-VIEW-006-SERVICE-ABORT
// @relation(AC-CL-VIEW-006-SERVICE-ABORT, scope=function)
TEST_F(ClientBrowse, ServiceGoodButResultsEmptyRejected)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* browse = dynamic_cast<BrowseResponse*>(response.second.get()))
        browse->results() = ua::Array<ua::BrowseResult>{};  // Good service result, but no per-node result
    });

  auto cursor = fixture.conn().typed().browse(root_folder());
  auto entry = cursor.try_next_sync();
  EXPECT_TRUE(entry.is_bad())
    << "a Good service result with empty Results[] must be rejected, not empty-Good";
  EXPECT_EQ(entry.status_code(), StatusCode{Status::BadUnexpectedError})
    << "the contract violation surfaces as Bad_UnexpectedError";
}

// =============================================================================================
// Row 16 - ServiceResultBadAbortsBatch  (MisbehavingServer)
// A service-level bad (parameterised) with an empty Results[] array must surface the SERVICE status to the
// awaiting cursor advance; the client must not index the empty Results[] or fabricate Good.
// [neg: service-level bad, results array empty]
//
// Cursor-facade flatten ADDED (this slice): the tier-0 wire-op funnel returns the BrowseResponse verbatim
// (its ResponseHeader.serviceResult is NOT lifted into the outer Result), so the cursor now flattens a bad
// serviceResult BEFORE the empty-results shape check - mirroring ua_discovery.cpp:47 + the read/write value
// facades. Covered by the fake-session unit test
// BrowseCursor.ServiceLevelBadWithEmptyResultsSurfacesServiceCode.
// =============================================================================================
// @verifies AC-CL-VIEW-006-SERVICE-ABORT
// @relation(AC-CL-VIEW-006-SERVICE-ABORT, scope=function)
TEST_F(ClientBrowse, ServiceResultBadAbortsBatch)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto serviceResult = std::make_shared<std::atomic<uint32_t>>(0);
  server.set_response_mutator(
    [serviceResult](Response& response)
    {
      auto* browse = dynamic_cast<BrowseResponse*>(response.second.get());
      if (!browse)
        return;
      const uint32_t code = serviceResult->load();
      if (code == 0)
        return;
      browse->response_header().service_result() = StatusCode{code};
      browse->results() = ua::Array<ua::BrowseResult>{};  // service-level bad AND empty Results[]
    });

  for (Status status : {Status::BadViewIdUnknown,
         Status::BadViewTimestampInvalid,
         Status::BadViewParameterMismatch,
         Status::BadViewVersionInvalid,
         Status::BadNothingToDo,
         Status::BadTooManyOperations})
  {
    serviceResult->store(StatusCode{status}.as_uint32());
    auto cursor = fixture.conn().typed().browse(root_folder());
    auto entry = cursor.try_next_sync();
    EXPECT_TRUE(entry.is_bad()) << "service error 0x" << std::hex << StatusCode{status}.as_uint32()
                                << " must abort the walk, not be swallowed";
    EXPECT_EQ(entry.status_code(), StatusCode{status})
      << "the exact service-level code must surface (not the empty-results BadUnexpectedError)";
  }
}

// =============================================================================================
// Row 17 - ShortPageWithContinuationStillContinues  (MisbehavingServer)
// A page with References.size() < requestedMax but a NON-empty continuation point must still drive a
// follow-up BrowseNext; a short page must not be read as end-of-results.
// [neg: short page must not be read as end-of-results]
// =============================================================================================
// @verifies CL-VIEW-003
// @verifies AC-CL-VIEW-005-CP-IS-THE-SIGNAL
// @relation(CL-VIEW-003, CL-VIEW-005, scope=function)
TEST_F(ClientBrowse, ShortPageWithContinuationStillContinues)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  const NodeId firstTarget{VariableId::Server_ServerStatus_State};
  const NodeId secondTarget{VariableId::Server_ServerStatus_CurrentTime};
  server.set_response_mutator(
    [firstTarget, secondTarget](Response& response)
    {
      if (auto* browse = dynamic_cast<BrowseResponse*>(response.second.get()))
      {
        // Initial Browse: a SHORT page (1 reference, far below the requested max) + a non-empty CP.
        if (!browse->results().empty())
          set_page(
            browse->results()[0], {make_reference(firstTarget, "First")}, ua::ContinuationPoint{0x11, 0x22});
      }
      else if (auto* browseNext = dynamic_cast<BrowseNextResponse*>(response.second.get()))
      {
        // BrowseNext: the final reference, no further CP.
        if (!browseNext->results().empty())
          set_page(
            browseNext->results()[0], {make_reference(secondTarget, "Second")}, ua::ContinuationPoint{});
      }
    });

  BrowseOptions options;
  options.requestedMaxReferencesPerNode = 100;  // the page (1 ref) is far short of this
  auto cursor = fixture.conn().typed().browse(root_folder(), options);

  auto first = cursor.try_next_sync();
  ASSERT_TRUE(first.is_good()) << "the short page's reference must be delivered";
  EXPECT_EQ(first.value().targetNodeId, firstTarget);
  EXPECT_TRUE(cursor.has_more()) << "a non-empty CP after a short page means more references remain";

  auto second = cursor.try_next_sync();
  ASSERT_TRUE(second.is_good()) << "the short page + CP must drive a follow-up BrowseNext, not terminate";
  EXPECT_EQ(second.value().targetNodeId, secondTarget)
    << "the reference behind the short-page continuation point must be delivered, not dropped";
}

// =============================================================================================
// Row 18 - ViewDescriptionBothTimestampAndVersionRejectedNoWire  (MisbehavingServer)
// Part 4 section 7.45: timestamp and viewVersion are mutually exclusive. The tier-2 builder rejects both
// before issuing Browse, preserving Bad_InvalidArgument and its ErrorDetail through the synchronous facade.
// =============================================================================================
// @verifies CL-VIEW-008
// @relation(CL-VIEW-008, scope=function)
TEST_F(ClientBrowse, ViewDescriptionBothTimestampAndVersionRejectedNoWire)
{
  MisbehavingServer server;
  MisbehavingBrowseFixture fixture{server};
  ASSERT_TRUE(fixture.start_status().is_good());

  auto capture = std::make_shared<RequestCapture>();
  server.set_request_observer([capture](const ua::Structure& request) { capture->observe(request); });

  BrowseOptions options;
  options.viewTimestamp = ua::UtcTime{2024, 1, 1, 0, 0, 0};
  options.viewVersion = 7;
  auto cursor = fixture.conn().typed().browse(root_folder(), options);

  auto result = cursor.try_next_sync();

  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadInvalidArgument});
  ASSERT_NE(result.shared_detail(), nullptr);
  EXPECT_EQ(result.shared_detail()->code, "BrowseViewParametersMutuallyExclusive");
  EXPECT_EQ(capture->browse_count(), 0u) << "invalid view parameters must fail before Browse wire I/O";
  EXPECT_EQ(capture->browse_next_count(), 0u) << "invalid view parameters must not issue BrowseNext";
}

// =============================================================================================
// Row (Slice 2a) - ReadSurfaceCacheServesRepeatedBrowseFromCache  (MisbehavingServer)
//
// Read-surface Browse cache (client design section 8.7): with the per-Connection address-space cache ENABLED,
// a SECOND identical Browse(X) is served from the cache - so only ONE BrowseRequest reaches the server for
// two client browses of the same node. A response mutator pins the first browse to a clean single page (no
// continuation point) so it is installable (single-page-only, v1); the second browse must not reach the wire.
//
// Intentionally UNTAGGED: the browse-RESULT cache (mBrowseCache, section 8.7 "BrowseCursor repeated-walk
// acceleration") has no dedicated CL-* integration requirement of its own. The CL-EVT-003 rows cover its
// per-node INVALIDATION and are blocked on Slice 2b's "Changes" SelectClause (a live GeneralModelChange
// currently arrives with a null Changes field -> conservative full-flush -> the per-node differential is not
// yet observable end-to-end). This row exercises the read-surface WIRING, not a matrix requirement - so it
// does NOT fabricate a coverage citation.
// =============================================================================================
TEST_F(ClientBrowse, ReadSurfaceCacheServesRepeatedBrowseFromCache)
{
  MisbehavingServer server;
  ua::client::detail::ConnectionConfig config;
  config.addressSpaceCache.enabled = true;  // opt in to the read-surface cache
  MisbehavingBrowseFixture fixture{server, std::move(config)};
  ASSERT_TRUE(fixture.start_status().is_good());

  // Arm AFTER bootstrap (so the bootstrap's traffic - incl. the enabled cache's event-backbone subscribes -
  // is not counted): count only Browse (not BrowseNext) requests, and pin every Browse response to a clean
  // single page so the first browse is installable.
  // Count only Browses OF THE NODE UNDER TEST. The claim is "a repeated identical browse issues no
  // second wire Browse for that node", not "no Browse of any kind crosses the wire": the Connection
  // legitimately browses other nodes for its own reasons - the event subscriber resolves an OfType
  // subtype closure by walking HasSubtype, for one - and counting those couples this row to unrelated
  // internals, where it will keep breaking on changes that have nothing to do with the cache.
  auto browseRequestCount = std::make_shared<std::atomic<int>>(0);
  server.set_request_observer(
    [browseRequestCount](const ua::Structure& request)
    {
      const auto* browse = dynamic_cast<const ua::BrowseRequest*>(&request);
      if (browse == nullptr)
      {
        return;
      }
      for (const auto& description : browse->nodes_to_browse())
      {
        if (description.node_id() == NodeId{ObjectId::RootFolder})
        {
          browseRequestCount->fetch_add(1);
          return;
        }
      }
    });
  server.set_response_mutator(
    [](Response& response)
    {
      if (auto* browse = dynamic_cast<BrowseResponse*>(response.second.get());
          browse != nullptr && !browse->results().empty())
      {
        set_page(browse->results()[0],
          {make_reference(NodeId{ObjectId::ObjectsFolder}, "CachedChild")},
          ua::ContinuationPoint{});  // no continuation point -> a whole single page -> installable
      }
    });

  // Browse #1: MISS - a wire Browse is issued (and its single page installed into the cache).
  {
    auto cursor = fixture.conn().typed().browse(root_folder());
    auto first = cursor.try_next_sync();
    ASSERT_TRUE(first.is_good()) << "the first browse must deliver its entry: "
                                 << to_string(first.status_code());
  }
  ASSERT_TRUE(wait_until([&] { return browseRequestCount->load() == 1; }))
    << "exactly one BrowseRequest reaches the server for the first browse";

  // Browse #2: identical Browse(root_folder) - served from the read-surface cache, NO extra wire Browse.
  {
    auto cursor = fixture.conn().typed().browse(root_folder());
    auto first = cursor.try_next_sync();
    ASSERT_TRUE(first.is_good()) << "the cached browse serves its first entry: "
                                 << to_string(first.status_code());
    EXPECT_EQ(first.value().targetNodeId, NodeId{ObjectId::ObjectsFolder})
      << "the cached (mutator-injected) reference is served, proving a cache hit";
  }

  // Give any (erroneous) second wire Browse a chance to land, then assert none did.
  std::this_thread::sleep_for(100ms);
  EXPECT_EQ(browseRequestCount->load(), 1)
    << "a second identical browse must be served from the read-surface cache (exactly one wire Browse total)";
}

// =============================================================================================
// RelativePathElementBeforeTheLastMustCarryATargetName  (ComplianceWithNodes)
//
// Part 4 section 7.31 requires `targetName` on every RelativePathElement except the final element. This
// test isolates that generic non-final requirement on TranslateBrowsePathsToNodeIds, whose stricter
// Part 4 section 5.8.4.2 contract also requires the final targetName (covered by TBP-003). The positive
// control therefore names every element instead of using the generic final-element permission that
// this Service expressly disallows.
// @verifies AC-SVR-VIEW-REL-002-TARGETNAME-EXCEPT-FINAL
TEST_F(ClientBrowse, RelativePathElementBeforeTheLastMustCarryATargetName)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("RelPath")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto request = TranslateBrowsePathsBuilder()
                   // Path 0: three elements, the SECOND omits its targetName -> must be refused.
                   .path(NodeId{ObjectId::ObjectsFolder})
                   .step(QualifiedName{mTestNamespaceIndex, "TestFolder"})
                   .step(QualifiedName{})
                   .step(QualifiedName{mTestNamespaceIndex, "TestMethod"})
                   // Path 1: control - the same shape with every targetName present must resolve, so
                   // the refusal above is attributable to the omission and not to the path shape.
                   .path(NodeId{ObjectId::ObjectsFolder})
                   .step(QualifiedName{mTestNamespaceIndex, "TestFolder"})
                   .step(QualifiedName{mTestNamespaceIndex, "TestMethod"})
                   .build();

  auto result = connection->service_requests().try_translate_browse_paths_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "the service itself succeeds; the refusal is per-path: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 2u);

  EXPECT_EQ(result.value().results()[0].status_code(), StatusCode{Status::BadBrowseNameInvalid})
    << "an element before the last with no targetName must be refused";

  EXPECT_EQ(result.value().results()[1].status_code(), StatusCode{Status::Good})
    << "the control path (every targetName present) must resolve: "
    << to_string(result.value().results()[1].status_code());
  ASSERT_FALSE(result.value().results()[1].targets().empty())
    << "the control path must produce the target it names";
  EXPECT_EQ(result.value().results()[1].targets()[0].target_id().node_id(), mTestMethodId);
}

// =============================================================================================
// DeleteReferences per-item rows (Part 4 section 5.7.5), observed over the same tier-2 Connection this file
// browses with, and confirmed against the address space by a Browse of the source node.
//
// The server refuses the whole NodeManagement service set when no `NodeManagementDelegate` is
// installed, so these rows install one. It is deliberately a PASS-THROUGH: every DeleteReferences
// item is handed straight to the SDK's own `NodeAccessor::try_remove_reference_sync` and that
// `VoidResult` is reported verbatim. The delegate classifies nothing, so a per-item status other
// than the address space's own can only have come out of the server's DeleteReferences flow.
// =============================================================================================

class PassThroughNodeManagementDelegate final : public NodeManagementDelegate
{
public:
  void add_nodes_async(std::shared_ptr<const Context> /*context*/, ua::AddressSpace /*addressSpace*/,
    std::vector<NodeManagementDelegate::AuthorizedAddNode> items, AddNodesCompleteCallback callback) override
  {
    ua::BatchResult<AddNodesItemResult> batch;
    batch.items.reserve(items.size());
    for (const auto& item : items)
    {
      (void)item;
      ua::AddNodesResult result;
      result.status_code() = ua::Status::BadNotSupported;
      batch.items.emplace_back(std::move(result));
    }
    callback(std::move(batch));
  }

  void add_references_async(std::shared_ptr<const Context> /*context*/, ua::AddressSpace /*addressSpace*/,
    std::vector<ua::AddReferencesItem> items, NodeMgmtCompleteCallback callback) override
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.reserve(items.size());
    for (const auto& item : items)
    {
      (void)item;
      batch.items.emplace_back(ua::VoidResult{ua::StatusCode{ua::Status::BadNotSupported}});
    }
    callback(std::move(batch));
  }

  void delete_nodes_async(std::shared_ptr<const Context> /*context*/, ua::AddressSpace /*addressSpace*/,
    std::vector<ua::DeleteNodesItem> items, NodeMgmtCompleteCallback callback) override
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.reserve(items.size());
    for (const auto& item : items)
    {
      (void)item;
      batch.items.emplace_back(ua::VoidResult{ua::StatusCode{ua::Status::BadNotSupported}});
    }
    callback(std::move(batch));
  }

  void delete_references_async(std::shared_ptr<const Context> /*context*/, ua::AddressSpace addressSpace,
    std::vector<ua::DeleteReferencesItem> items, NodeMgmtCompleteCallback callback) override
  {
    ua::BatchResult<ua::VoidResult> batch;
    batch.items.reserve(items.size());
    for (const auto& item : items)
    {
      NodeId protectedSource;
      {
        std::lock_guard<std::mutex> guard(mMutex);
        mSeenSources.push_back(item.source_node_id());
        protectedSource = mProtectedSource;
      }
      // Server policy on the Node itself: its References may not be removed by anyone. Part 4
      // Table 33 keeps this distinct from Bad_UserAccessDenied, and SVR-NM-DR-025's DESIGN_COVERAGE
      // places the application-domain check here, in the delegate, not in Namespace Role policy.
      if (!protectedSource.is_null() && item.source_node_id() == protectedSource)
      {
        batch.items.emplace_back(ua::VoidResult{ua::StatusCode{ua::Status::BadNoDeleteRights}});
        continue;
      }
      auto sourceResult = addressSpace.try_find_node_sync(item.source_node_id());
      if (sourceResult.is_bad())
      {
        batch.items.emplace_back(ua::VoidResult{sourceResult.status_code()});
        continue;
      }
      auto source = sourceResult.value();
      // Both halves for deleteBidirectional TRUE, the named half alone for FALSE.
      batch.items.emplace_back(source.try_remove_reference_sync(item.reference_type_id(),
        item.target_node_id(),
        item.is_forward(),
        item.delete_bidirectional() ? ua::ReferenceHalves::Both : ua::ReferenceHalves::ThisHalfOnly));
    }
    callback(std::move(batch));
  }

  /// The source NodeId of every item the SDK actually handed down, in delivery order.
  std::vector<NodeId> seen_sources() const
  {
    std::lock_guard<std::mutex> guard(mMutex);
    return mSeenSources;
  }

  /// Mark @p nodeId as a Node whose References the server will not remove for anyone: items naming
  /// it as source are answered Bad_NoDeleteRights and nothing is removed. Everything else still
  /// goes to the address space verbatim.
  void protect_source(NodeId nodeId)
  {
    std::lock_guard<std::mutex> guard(mMutex);
    mProtectedSource = std::move(nodeId);
  }

private:
  mutable std::mutex mMutex;
  std::vector<NodeId> mSeenSources;
  NodeId mProtectedSource;
};

// =============================================================================================
// Fixture: ClientBrowse plus a pass-through NodeManagement delegate and one source Object holding a
// single forward Organizes reference to one target Object.
// =============================================================================================
class ClientBrowseDeleteReferences : public ClientBrowse
{
protected:
  void configure_server() override
  {
    ClientBrowse::configure_server();

    auto addressSpace = mServer.server().address_space();
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});

    mDeleteRefSourceId = NodeId{mTestNamespaceIndex, uint32_t{9200}};
    auto sourceNode = addressSpace.create_node_sync(mDeleteRefSourceId, NodeClass::Object);
    auto source = sourceNode.as<ObjectAccessor>();
    source->set_browse_name(QualifiedName{mTestNamespaceIndex, "DeleteRefSource"});
    source->set_display_name(LocalizedText{"", "DeleteRefSource"});
    sourceNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mDeleteRefSourceId);

    mDeleteRefTargetId = NodeId{mTestNamespaceIndex, uint32_t{9201}};
    auto targetNode = addressSpace.create_node_sync(mDeleteRefTargetId, NodeClass::Object);
    auto target = targetNode.as<ObjectAccessor>();
    target->set_browse_name(QualifiedName{mTestNamespaceIndex, "DeleteRefTarget"});
    target->set_display_name(LocalizedText{"", "DeleteRefTarget"});
    targetNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});

    // The reference under test: source --Organizes--> target.
    sourceNode.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mDeleteRefTargetId);

    mDelegate = std::make_shared<PassThroughNodeManagementDelegate>();
    mServer.server().set_node_management_delegate(ua::test::offloaded(mDelegate));
  }

  /// Forward Organizes targets of the DeleteReferences source node, read back over the wire.
  std::vector<NodeId> organizes_targets_of_source(Connection& connection)
  {
    BrowseOptions options;
    options.direction = BrowseDirection::Forward;
    options.referenceTypeId = NodeId{ReferenceTypeId::Organizes};
    options.includeSubtypes = false;

    auto cursor = connection.typed().browse(mDeleteRefSourceId, options);
    std::vector<NodeId> targets;
    for (;;)
    {
      auto next = cursor.try_next_sync();
      if (next.is_bad())
      {
        EXPECT_EQ(next.status_code(), StatusCode{Status::BadNoData})
          << "the Browse walk may end only by exhausting the cursor; an earlier wire failure must not "
             "be mistaken for absence of the reference under test";
        break;
      }
      targets.push_back(next.value().targetNodeId.node_id());
      if (targets.size() > 16)
        break;  // the fixture holds one such reference; do not spin on a misbehaving walk
    }
    return targets;
  }

  NodeId mDeleteRefSourceId;
  NodeId mDeleteRefTargetId;
  std::shared_ptr<PassThroughNodeManagementDelegate> mDelegate;
};

// =============================================================================================
// DeleteReferenceNamingANonReferenceTypeIsRefused  (ClientBrowseDeleteReferences)
//
// Part 4 section 5.7.5: an item whose `referenceTypeId` is not a ReferenceType Node must have
// Bad_ReferenceTypeIdInvalid in ITS slot. The sharp case is an id that RESOLVES but names the wrong
// NodeClass - a plausible implementation only checks that the id is known to the address space (or
// leaves the check out entirely and lets the removal quietly find no match), and then reports
// success or a generic no-match for a request that named something that could never be a reference.
//
// The service resolves the id and verifies NodeClass before target/source authorization, so the
// refused item never reaches the mutation delegate.
// @relation(AC-SVR-NM-DR-021-REFERENCETYPEIDINVALID, scope=function)
TEST_F(ClientBrowseDeleteReferences, DeleteReferenceNamingANonReferenceTypeIsRefused)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("DR21")};
  ASSERT_TRUE(connection.start_status().is_good());

  // The target Object is a perfectly good node - and is not a ReferenceType.
  auto request = DeleteReferencesBuilder()
                   .delete_reference(mDeleteRefSourceId, mDeleteRefTargetId, mDeleteRefTargetId)
                   .delete_bidirectional(false)
                   .build();

  auto result = connection->service_requests().try_delete_references_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "the service itself succeeds; the failure is per-item: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 1u);
  EXPECT_EQ(result.value().results()[0], StatusCode{Status::BadReferenceTypeIdInvalid})
    << "a referenceTypeId that names a node of the wrong NodeClass must be refused as an invalid "
       "reference type, not accepted or reported as a generic no-match";

  // Falsifiability: the real reference must be untouched by the refused request.
  auto targets = organizes_targets_of_source(*connection);
  ASSERT_FALSE(targets.empty()) << "the source must still expose its forward Organizes reference";
  EXPECT_NE(std::find(targets.begin(), targets.end(), mDeleteRefTargetId), targets.end())
    << "a refused DeleteReferences item must not remove anything";
}

// =============================================================================================
// DeleteReferenceWithAServerIndexOutsideTheServerArrayIsRefused  (ClientBrowseDeleteReferences)
//
// Part 4 section 5.7.5.4: the target's `serverIndex` is resolved against the ServerArray, and an index that
// is not in it must put Bad_ServerIndexInvalid in that item's slot. A plausible implementation reads
// only the inner NodeId of the ExpandedNodeId - the serverIndex then silently disappears and a
// request naming a reference on a DIFFERENT server is answered as though it named a local one.
// @verifies AC-SVR-NM-DR-022-SERVERINDEXINVALID
TEST_F(ClientBrowseDeleteReferences, DeleteReferenceWithAServerIndexOutsideTheServerArrayIsRefused)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("DR22")};
  ASSERT_TRUE(connection.start_status().is_good());

  ua::DeleteReferencesRequest request;
  ua::DeleteReferencesItem item;
  item.source_node_id() = mDeleteRefSourceId;
  item.reference_type_id() = NodeId{ReferenceTypeId::Organizes};
  item.is_forward() = true;
  ExpandedNodeId remoteTarget{mDeleteRefTargetId};
  remoteTarget.server_index() = 7;  // this server's ServerArray holds index 0 only
  item.target_node_id() = std::move(remoteTarget);
  item.delete_bidirectional() = false;
  request.references_to_delete().push_back(std::move(item));

  auto result = connection->service_requests().try_delete_references_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "the service itself succeeds; the failure is per-item: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 1u);
  EXPECT_EQ(result.value().results()[0], StatusCode{Status::BadServerIndexInvalid})
    << "a target serverIndex outside the ServerArray must be refused as an invalid server index";

  // Falsifiability: the same-named LOCAL reference must survive - the request named a reference on
  // another server, so mistaking it for the local one would delete the wrong thing.
  auto targets = organizes_targets_of_source(*connection);
  ASSERT_FALSE(targets.empty()) << "the source must still expose its forward Organizes reference";
  EXPECT_NE(std::find(targets.begin(), targets.end(), mDeleteRefTargetId), targets.end())
    << "an item naming a foreign serverIndex must not remove the local reference to the same node";
}

// =============================================================================================
// DeleteReferenceWithAnUnresolvableTargetIsRefused  (ClientBrowseDeleteReferences)
//
// Part 4 section 5.7.5.4: a `targetNodeId` that is null, or that does not identify a valid TargetNode, must
// put Bad_TargetNodeIdInvalid in that item's slot. A plausible implementation validates the source
// (which it must resolve anyway to authorize the item) and never looks the target up at all, so a
// request naming a node that does not exist comes back indistinguishable from one that matched
// nothing. Both shapes the requirement names are driven here, and both slots are asserted.
// @verifies AC-SVR-NM-DR-023-TARGETNODEIDINVALID
TEST_F(ClientBrowseDeleteReferences, DeleteReferenceWithAnUnresolvableTargetIsRefused)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("DR23")};
  ASSERT_TRUE(connection.start_status().is_good());

  const NodeId absentTarget{mTestNamespaceIndex, uint32_t{9299}};  // never created
  auto request = DeleteReferencesBuilder()
                   .delete_reference(mDeleteRefSourceId, NodeId{ReferenceTypeId::Organizes}, absentTarget)
                   .delete_bidirectional(false)
                   .delete_reference(mDeleteRefSourceId, NodeId{ReferenceTypeId::Organizes}, NodeId{})
                   .delete_bidirectional(false)
                   .build();

  auto result = connection->service_requests().try_delete_references_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "the service itself succeeds; the failures are per-item: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 2u);
  EXPECT_EQ(result.value().results()[0], StatusCode{Status::BadTargetNodeIdInvalid})
    << "a target that does not identify a valid node must be refused as an invalid target";
  EXPECT_EQ(result.value().results()[1], StatusCode{Status::BadTargetNodeIdInvalid})
    << "a null target must be refused as an invalid target";

  // Falsifiability: the source's genuine reference must be untouched by the refused items.
  auto targets = organizes_targets_of_source(*connection);
  ASSERT_FALSE(targets.empty()) << "the source must still expose its forward Organizes reference";
  EXPECT_NE(std::find(targets.begin(), targets.end(), mDeleteRefTargetId), targets.end())
    << "a refused DeleteReferences item must not remove anything";
}

// =============================================================================================
// Fixture: ClientBrowseDeleteReferencesAuthz - a server whose RolePermissions deny RemoveReference on
// ONE source node and permit it on its sibling, plus the same pass-through NodeManagement delegate.
//
// Two sibling Objects each hold one forward Organizes reference to a shared target: the session may
// delete the reference held by one of them and not the reference held by the other.
// =============================================================================================
class ClientBrowseDeleteReferencesAuthz : public ComplianceSecured
{
protected:
  void configure_components(server::ServerComponents& components) override
  {
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous}});
  }

  void SetUp() override
  {
    ComplianceSecured::SetUp();

    CoreClient::OpenChannelConfig channelConfig;
    channelConfig.endpointUrl = mEndpointUrl;
    channelConfig.securityMode = MessageSecurityMode::None;
    channelConfig.securityPolicyId = SecurityPolicyId::None;
    mChannel.emplace(mClient->core().open_channel_sync(std::move(channelConfig)));
    mSession.emplace(mChannel->create_session_sync({.sessionName = "ClientBrowseDeleteRefAuthz"}));
    mSession->activate_sync();

    auto addressSpace = mServer->address_space();
    mAuthzNamespace =
      default_ns::Namespace::create("urn:test:clientbrowse:deleterefs", mServerThreadPool.executor());
    mAuthzNamespaceIndex = addressSpace.add_namespace_sync(mAuthzNamespace);

    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});
    auto makeObject = [&](uint32_t identifier, std::string_view name) -> NodeId
    {
      NodeId nodeId{mAuthzNamespaceIndex, identifier};
      auto node = addressSpace.create_node_sync(nodeId, NodeClass::Object);
      auto object = node.as<ObjectAccessor>();
      object->set_browse_name(QualifiedName{mAuthzNamespaceIndex, std::string{name}});
      object->set_display_name(LocalizedText{"", std::string{name}});
      set_source_permissions(node, true);
      node.add_reference_sync(
        NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
      objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, nodeId);
      return nodeId;
    };

    mAllowedSourceId = makeObject(uint32_t{5100}, "AllowedSource");
    const NodeId deniedSourceId = makeObject(uint32_t{5101}, "DeniedSource");
    mSharedTargetId = makeObject(uint32_t{5102}, "SharedTarget");
    *mDeniedSourceId = deniedSourceId;
    set_source_permissions(addressSpace.find_node_sync(deniedSourceId), false);

    addressSpace.find_node_sync(mAllowedSourceId)
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mSharedTargetId);
    addressSpace.find_node_sync(deniedSourceId)
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mSharedTargetId);

    mDelegate = std::make_shared<PassThroughNodeManagementDelegate>();
    mServer->set_node_management_delegate(ua::test::offloaded(mDelegate));
  }

  static void set_source_permissions(NodeAccessor node, bool mayRemoveReference)
  {
    PermissionType permissions{
      {PermissionType::Bit::Browse, PermissionType::Bit::Read, PermissionType::Bit::AddReference}};
    if (mayRemoveReference)
    {
      permissions.set(PermissionType::Bit::RemoveReference);
    }
    RolePermissionType anonymousPermissions;
    anonymousPermissions.role_id() = NodeId{ObjectId::WellKnownRole_Anonymous};
    anonymousPermissions.permissions() = permissions;
    node.set_role_permissions(std::vector<RolePermissionType>{anonymousPermissions});
  }

  void TearDown() override
  {
    if (mSession)
      (void)mSession->try_close_sync();
    if (mChannel)
      (void)mChannel->try_close_sync();
    ComplianceSecured::TearDown();
  }

  /// Forward Organizes targets of @p sourceId, read back over the wire.
  std::vector<NodeId> organizes_targets_of(const NodeId& sourceId)
  {
    std::vector<NodeId> targets;
    auto browseResult = mSession->view().try_browse_sync(BrowseRequestBuilder()
                                                           .browse(sourceId)
                                                           .direction(BrowseDirection::Forward)
                                                           .reference_type(NodeId{ReferenceTypeId::Organizes})
                                                           .include_subtypes(false)
                                                           .build());
    EXPECT_TRUE(browseResult.is_good())
      << "the verification Browse must succeed: " << to_string(browseResult.status_code());
    if (browseResult.is_bad())
      return targets;
    EXPECT_EQ(browseResult.value().results().size(), 1u)
      << "the one-node verification Browse must return exactly one result";
    if (browseResult.value().results().empty())
      return targets;
    EXPECT_TRUE(browseResult.value().results()[0].status_code().is_good())
      << "the verification Browse result must be Good: "
      << to_string(browseResult.value().results()[0].status_code());
    for (const auto& reference : browseResult.value().results()[0].references())
      targets.push_back(reference.node_id().node_id());
    return targets;
  }

  std::shared_ptr<NodeId> mDeniedSourceId{std::make_shared<NodeId>()};
  std::shared_ptr<default_ns::Namespace> mAuthzNamespace;
  uint16_t mAuthzNamespaceIndex{0};
  NodeId mAllowedSourceId;
  NodeId mSharedTargetId;
  std::shared_ptr<PassThroughNodeManagementDelegate> mDelegate;
  std::optional<SecureChannel> mChannel;
  std::optional<Session> mSession;
};

// =============================================================================================
// DeleteReferencesRefusesOnlyTheUnauthorizedReference  (ClientBrowseDeleteReferencesAuthz)
//
// Part 4 section 5.7.5: authorization is per item, scoped to the item's sourceNodeId, and a denied item is
// marked Bad_UserAccessDenied without ever reaching the delegate. A plausible implementation
// authorizes the REQUEST rather than the item - one denial then fails the whole batch (the permitted
// reference survives when it should have gone), or, worse, the batch is dispatched wholesale and the
// delegate removes the reference the session was refused.
// @verifies AC-SVR-NM-DR-024-DELETEREFERENCES-DENIED
TEST_F(ClientBrowseDeleteReferencesAuthz, DeleteReferencesRefusesOnlyTheUnauthorizedReference)
{
  const NodeId deniedSourceId = *mDeniedSourceId;

  // Both references exist before the request, so the assertions below are about what the request
  // did, not about what the fixture built.
  {
    auto before = organizes_targets_of(mAllowedSourceId);
    ASSERT_NE(std::find(before.begin(), before.end(), mSharedTargetId), before.end())
      << "the permitted source must hold the reference before the delete";
    auto beforeDenied = organizes_targets_of(deniedSourceId);
    ASSERT_NE(std::find(beforeDenied.begin(), beforeDenied.end(), mSharedTargetId), beforeDenied.end())
      << "the denied source must hold the reference before the delete";
  }

  auto request = DeleteReferencesBuilder()
                   .delete_reference(mAllowedSourceId, NodeId{ReferenceTypeId::Organizes}, mSharedTargetId)
                   .delete_bidirectional(false)
                   .delete_reference(deniedSourceId, NodeId{ReferenceTypeId::Organizes}, mSharedTargetId)
                   .delete_bidirectional(false)
                   .build();

  auto result = mSession->node_management().try_delete_references_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "one denied item must not fail the service: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 2u);
  EXPECT_EQ(result.value().results()[0], StatusCode{Status::Good})
    << "the permitted item must succeed alongside the denied one";
  EXPECT_EQ(result.value().results()[1], StatusCode{Status::BadUserAccessDenied})
    << "the item whose sourceNodeId the session may not modify must be denied in its own slot";

  // The permitted reference is gone.
  auto allowedAfter = organizes_targets_of(mAllowedSourceId);
  EXPECT_EQ(std::find(allowedAfter.begin(), allowedAfter.end(), mSharedTargetId), allowedAfter.end())
    << "the permitted reference must actually have been removed";

  // The denied reference remains.
  auto deniedAfter = organizes_targets_of(deniedSourceId);
  ASSERT_FALSE(deniedAfter.empty()) << "the denied source must still be browsable";
  EXPECT_NE(std::find(deniedAfter.begin(), deniedAfter.end(), mSharedTargetId), deniedAfter.end())
    << "a denied item must leave its reference in place";

  // And the denied item never reached the delegate at all.
  auto seen = mDelegate->seen_sources();
  ASSERT_FALSE(seen.empty()) << "the permitted item must have been dispatched to the delegate";
  EXPECT_NE(std::find(seen.begin(), seen.end(), mAllowedSourceId), seen.end())
    << "the permitted item must reach the delegate";
  EXPECT_EQ(std::find(seen.begin(), seen.end(), deniedSourceId), seen.end())
    << "a denied item must be marked without ever being handed to the delegate";
}

// =============================================================================================
// DeleteReferencesRefusesAReferenceTypeIdThatIsNotAReferenceType  (ClientBrowseDeleteReferences)
//
// Part 4 section 5.7.5: an item whose `referenceTypeId` does not identify a ReferenceType Node must carry
// Bad_ReferenceTypeIdInvalid in its own slot. The sharp case is an id that RESOLVES but names the
// wrong NodeClass: a plausible implementation performs no reference-type check at all and simply
// lets the removal find no matching reference, so a request naming something that could never be a
// reference is answered with the same generic no-match as a well-formed request for a reference that
// is merely absent. Item 1 below IS that well-formed absence (a genuine ReferenceType the source
// holds no reference of), so an implementation that answers the two alike - in either direction -
// fails one of the two assertions. That discriminating second item is what this row adds over the
// single-item sibling above, which drives the same obligation with the bad item alone.
//
// The absent-valid ReferenceType sibling distinguishes invalid classification from an ordinary
// no-match result and keeps the negative arm non-vacuous.
// @relation(AC-SVR-NM-DR-021-REFERENCETYPEIDINVALID, scope=function)
TEST_F(ClientBrowseDeleteReferences, DeleteReferencesRefusesAReferenceTypeIdThatIsNotAReferenceType)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("DR21Live")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto request =
    DeleteReferencesBuilder()
      // Item 0: the referenceTypeId names a real, resolvable node that is an Object.
      .delete_reference(mDeleteRefSourceId, mDeleteRefTargetId, mDeleteRefTargetId)
      .delete_bidirectional(false)
      // Item 1: a genuine ReferenceType, of which the source holds no reference.
      .delete_reference(mDeleteRefSourceId, NodeId{ReferenceTypeId::HasNotifier}, mDeleteRefTargetId)
      .delete_bidirectional(false)
      .build();

  auto result = connection->service_requests().try_delete_references_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "the service itself succeeds; the failure is per-item: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 2u);
  EXPECT_EQ(result.value().results()[0], StatusCode{Status::BadReferenceTypeIdInvalid})
    << "a referenceTypeId naming a node of the wrong NodeClass must be refused as an invalid "
       "reference type, not accepted and not reported as a generic no-match";
  EXPECT_NE(result.value().results()[1], StatusCode{Status::BadReferenceTypeIdInvalid})
    << "a genuine ReferenceType must not be refused as invalid merely because no such reference "
       "exists - refusing it too makes the rejection above blind to what a ReferenceType is";

  // Falsifiability: the source's real reference must be untouched by the refused item.
  auto targets = organizes_targets_of_source(*connection);
  ASSERT_FALSE(targets.empty()) << "the source must still expose its forward Organizes reference";
  EXPECT_NE(std::find(targets.begin(), targets.end(), mDeleteRefTargetId), targets.end())
    << "a refused DeleteReferences item must not remove anything";
}

// =============================================================================================
// DeleteReferencesRefusesAnInvalidReferenceTypeInItsOwnSlot  (ClientBrowseDeleteReferences)
//
// Part 4 section 5.7.5: Bad_ReferenceTypeIdInvalid is an OPERATION-level result - it belongs in the slot of
// the item that named the bad referenceTypeId and nowhere else. The plausible implementation this
// row is aimed at is the one that does perform the check but at the wrong granularity: it validates
// the request, finds one item naming a node that is not a ReferenceType, and abandons the whole
// batch, so a well-formed item that shares the batch is answered with the same failure and its
// reference is still there afterwards. The two refusal siblings above drive the refusal itself;
// what this row adds is the other half of "that item's slot" - the batch around it still executes,
// and the legitimate deletion really happens. The removal is what makes the refusal in slot 0
// falsifiable: a whole-batch abort satisfies neither the Good in slot 1 nor the missing reference.
//
// The valid sibling is executed after the invalid slot is classified, proving per-item isolation.
// @relation(AC-SVR-NM-DR-021-REFERENCETYPEIDINVALID, scope=function)
// The macro must stay on one line: the traceability tooling matches a single-line
// TEST_F and reads a wrapped one as a test that does not exist.
// clang-format off
TEST_F(ClientBrowseDeleteReferences, DeleteReferencesRefusesAnInvalidReferenceTypeInItsOwnSlot)
// clang-format on
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("DR21Batch")};
  ASSERT_TRUE(connection.start_status().is_good());

  // The reference the batch legitimately deletes must exist first, so its absence afterwards is
  // attributable to this request.
  {
    auto before = organizes_targets_of_source(*connection);
    ASSERT_NE(std::find(before.begin(), before.end(), mDeleteRefTargetId), before.end())
      << "the source must hold its forward Organizes reference before the delete";
  }

  auto request =
    DeleteReferencesBuilder()
      // Item 0: the referenceTypeId names a real, resolvable node that is an Object.
      .delete_reference(mDeleteRefSourceId, mDeleteRefTargetId, mDeleteRefTargetId)
      .delete_bidirectional(false)
      // Item 1: a well-formed item on the same source, naming a reference that exists.
      .delete_reference(mDeleteRefSourceId, NodeId{ReferenceTypeId::Organizes}, mDeleteRefTargetId)
      .delete_bidirectional(false)
      .build();

  auto result = connection->service_requests().try_delete_references_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "one invalid item must not fail the service: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 2u);
  EXPECT_EQ(result.value().results()[0], StatusCode{Status::BadReferenceTypeIdInvalid})
    << "a referenceTypeId naming a node of the wrong NodeClass must be refused as an invalid "
       "reference type in its own slot";
  EXPECT_EQ(result.value().results()[1], StatusCode{Status::Good})
    << "the well-formed item sharing the batch must succeed - the refusal above is per item, not "
       "per request";

  // The legitimate deletion really happened: the refusal in slot 0 cannot have come from an
  // implementation that abandoned the batch.
  auto after = organizes_targets_of_source(*connection);
  EXPECT_EQ(std::find(after.begin(), after.end(), mDeleteRefTargetId), after.end())
    << "the well-formed item must actually have removed its reference";
}

// =============================================================================================
// DeleteReferenceNamingATypeNodeOtherThanAReferenceTypeIsRefused  (ClientBrowseDeleteReferences)
//
// Part 4 section 5.7.5: an item whose `referenceTypeId` does not identify a ReferenceType Node must carry
// Bad_ReferenceTypeIdInvalid in its own slot. The siblings above drive the check with an Object, and
// an implementation can pass those while still getting the NodeClass wrong: the plausible near-miss
// is a check written as "the id must name a TYPE node" (`is_type_node()`, or a NodeClass mask over
// the four type classes), which rejects an Object and cheerfully accepts an ObjectType - a node that
// resolves, is a type, and could never be a reference. Item 0 is exactly that node. Item 1 is the
// other side of the same mistake: an ABSTRACT ReferenceType is a valid ReferenceType Node, so an
// implementation that narrows the check to concrete reference types over-rejects it. Its target is
// chosen from a branch of the hierarchy the fixture's Organizes reference is not under, so no
// matching rule - exact or subtype - can let item 1 remove the reference the falsifier reads back.
// @relation(AC-SVR-NM-DR-021-REFERENCETYPEIDINVALID, scope=function)
TEST_F(ClientBrowseDeleteReferences, DeleteReferenceNamingATypeNodeOtherThanAReferenceTypeIsRefused)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("DR21Type")};
  ASSERT_TRUE(connection.start_status().is_good());

  // The reference the falsifier reads back must exist before the request, so its survival below is a
  // statement about what this request did.
  {
    auto before = organizes_targets_of_source(*connection);
    ASSERT_NE(std::find(before.begin(), before.end(), mDeleteRefTargetId), before.end())
      << "the source must hold its forward Organizes reference before the delete";
  }

  auto request =
    DeleteReferencesBuilder()
      // Item 0: an ObjectType - it resolves, it is a Type Node, and it is not a ReferenceType.
      .delete_reference(mDeleteRefSourceId, NodeId{ObjectTypeId::BaseObjectType}, mDeleteRefTargetId)
      .delete_bidirectional(false)
      // Item 1: an abstract but genuine ReferenceType, in a branch of the hierarchy that cannot
      // match the source's Organizes reference.
      .delete_reference(
        mDeleteRefSourceId, NodeId{ReferenceTypeId::NonHierarchicalReferences}, mDeleteRefTargetId)
      .delete_bidirectional(false)
      .build();

  auto result = connection->service_requests().try_delete_references_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "the service itself succeeds; the failure is per-item: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 2u);
  EXPECT_EQ(result.value().results()[0], StatusCode{Status::BadReferenceTypeIdInvalid})
    << "a referenceTypeId naming an ObjectType must be refused as an invalid reference type - being "
       "a type Node is not being a ReferenceType Node";
  EXPECT_NE(result.value().results()[1], StatusCode{Status::BadReferenceTypeIdInvalid})
    << "an abstract ReferenceType IS a valid ReferenceType Node and must not be refused as invalid; "
       "refusing it too makes the rejection above blind to what a ReferenceType is";

  // Falsifiability: neither item may remove anything - item 0 was refused, and item 1 names a
  // reference type the source holds no reference of.
  auto targets = organizes_targets_of_source(*connection);
  ASSERT_FALSE(targets.empty()) << "the source must still expose its forward Organizes reference";
  EXPECT_NE(std::find(targets.begin(), targets.end(), mDeleteRefTargetId), targets.end())
    << "a refused DeleteReferences item must not remove anything";
}

// =============================================================================================
// Fixture: the ClientBrowseDeleteReferencesAuthz address space, with the session granted RemoveReference
// on every source and the protection expressed where the
// obligation puts it - on the Node, in the NodeManagement delegate. SVR-NM-DR-025 distinguishes
// "the Node forbids removing its References" (Bad_NoDeleteRights) from "this session may not touch
// this Node" (Bad_UserAccessDenied), and its DESIGN_COVERAGE names
// `NodeManagementDelegate::delete_references_async` - "delegate-enforced delete rights on the source
// Node" - as the site. RolePermissions are the OTHER mechanism: AC-SVR-NM-DR-024 requires a
// permission denial to surface as Bad_UserAccessDenied, which is exactly what the service does for
// every node-management flow (ua_node_management_service.cpp:560, :1334, :1739), so a node-level
// server policy cannot be expressed through it.
// =============================================================================================
class ClientBrowseDeleteReferencesProtectedNode : public ClientBrowseDeleteReferencesAuthz
{
protected:
  void configure_components(server::ServerComponents& components) override
  {
    components.roleConfiguration = RoleConfiguration::from_well_known_grants(
      {{WellKnownRole::Anonymous, IdentityCriteriaType::Anonymous}});
  }

  void SetUp() override
  {
    ClientBrowseDeleteReferencesAuthz::SetUp();
    set_source_permissions(mServer->address_space().find_node_sync(*mDeniedSourceId), true);
    mDelegate->protect_source(*mDeniedSourceId);
  }
};

// =============================================================================================
// DeleteReferenceOnAProtectedNodeIsRefusedAsNoDeleteRights  (ClientBrowseDeleteReferencesProtectedNode)
//
// Part 4 section 5.7.5.3 (Table 33): Bad_NoDeleteRights - "the Server will not allow the node to be
// deleted" - is an operation-level code of its own, listed alongside and distinct from
// Bad_UserAccessDenied. When the source Node itself is protected from Reference deletion, that
// item's slot must carry it and the reference must survive.
//
// The batch is deliberately three items and the middle one is refused BEFORE dispatch (null target
// -> Bad_TargetNodeIdInvalid), so the two items the delegate answers are non-adjacent in the
// response. The service must therefore land the delegate's per-item statuses back in slots 0 and 2
// through `authorizedIndices`, and a plausible implementation that appends them in delegate order,
// or that smears one bad item across the batch, puts Bad_NoDeleteRights in the wrong slot or turns
// the permitted item bad. The permitted item's reference really disappearing and the protected
// item's really surviving is what stops the status assertions from standing alone.
// @verifies AC-SVR-NM-DR-025-NODELETERIGHTS
TEST_F(ClientBrowseDeleteReferencesProtectedNode, DeleteReferenceOnAProtectedNodeIsRefusedAsNoDeleteRights)
{
  const NodeId protectedSourceId = *mDeniedSourceId;

  // Both references exist before the request, so the assertions below are about what the request
  // did, not about what the fixture built.
  {
    auto before = organizes_targets_of(mAllowedSourceId);
    ASSERT_NE(std::find(before.begin(), before.end(), mSharedTargetId), before.end())
      << "the permitted source must hold the reference before the delete";
    auto beforeProtected = organizes_targets_of(protectedSourceId);
    ASSERT_NE(
      std::find(beforeProtected.begin(), beforeProtected.end(), mSharedTargetId), beforeProtected.end())
      << "the protected source must hold the reference before the delete";
  }

  auto request = DeleteReferencesBuilder()
                   // Item 0: permitted, and the delegate removes it.
                   .delete_reference(mAllowedSourceId, NodeId{ReferenceTypeId::Organizes}, mSharedTargetId)
                   .delete_bidirectional(false)
                   // Item 1: refused by the service before dispatch, so the delegate answers items
                   // 0 and 2 only and their statuses must be scattered back into non-adjacent slots.
                   .delete_reference(mAllowedSourceId, NodeId{ReferenceTypeId::Organizes}, NodeId{})
                   .delete_bidirectional(false)
                   // Item 2: the protected source.
                   .delete_reference(protectedSourceId, NodeId{ReferenceTypeId::Organizes}, mSharedTargetId)
                   .delete_bidirectional(false)
                   .build();

  auto result = mSession->node_management().try_delete_references_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "one refused item must not fail the service: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 3u);
  EXPECT_EQ(result.value().results()[0], StatusCode{Status::Good})
    << "the item on the unprotected source must succeed alongside the refused one";
  EXPECT_EQ(result.value().results()[1], StatusCode{Status::BadTargetNodeIdInvalid})
    << "the null-target item must keep its own slot, so the delegate's answers cannot simply be "
       "appended in delegate order";
  EXPECT_EQ(result.value().results()[2], StatusCode{Status::BadNoDeleteRights})
    << "an item whose source Node forbids removal of its References must be refused as "
       "Bad_NoDeleteRights, not collapsed into the access-denied code and not into the batch status";

  // The permitted reference is gone - the batch really executed.
  auto allowedAfter = organizes_targets_of(mAllowedSourceId);
  EXPECT_EQ(std::find(allowedAfter.begin(), allowedAfter.end(), mSharedTargetId), allowedAfter.end())
    << "the item on the unprotected source must actually have removed its reference";

  // The refused reference remains, and the Node is still readable by this session.
  auto protectedAfter = organizes_targets_of(protectedSourceId);
  ASSERT_FALSE(protectedAfter.empty())
    << "the protected source must still be browsable - the session may read it, it may only not "
       "remove its references";
  EXPECT_NE(std::find(protectedAfter.begin(), protectedAfter.end(), mSharedTargetId), protectedAfter.end())
    << "a refused DeleteReferences item must leave its reference in place";

  // The refusal happened at the Node, so the item was dispatched and came back refused; the item
  // the service itself refused never went down at all.
  auto seen = mDelegate->seen_sources();
  EXPECT_NE(std::find(seen.begin(), seen.end(), mAllowedSourceId), seen.end())
    << "the permitted item must reach the delegate";
  EXPECT_NE(std::find(seen.begin(), seen.end(), protectedSourceId), seen.end())
    << "the protected item must reach the delegate - that is where the Node's delete rights are "
       "enforced";
  EXPECT_EQ(seen.size(), 2u)
    << "the null-target item must be refused by the service without ever being dispatched";
}

// =============================================================================================
// EveryItemOnAProtectedNodeIsRefusedAsNoDeleteRights  (ClientBrowseDeleteReferencesProtectedNode)
//
// Part 4 section 5.7.5.3 (Table 33): Bad_NoDeleteRights is an OPERATION-level result. Part 4 section 5.7
// keeps operation-level results out of the service result - the service succeeds and each item carries its
// own code - and there is no exception for the case where NO item succeeded. That case is the one a
// plausible implementation gets wrong: having produced a response in which every slot is bad, it
// concludes there was nothing to do (or promotes the first item's code) and answers with a service
// fault, at which point the client cannot tell WHICH node refused, or why, and cannot distinguish a
// protected Node from a malformed request. The sibling row above always had one successful item, so
// an implementation that only escalates when the whole batch failed passes it. Both slots and the
// service result are asserted here, and the reference the Node protects is read back afterwards so
// the refusal is not merely a status with nothing behind it.
// @verifies AC-SVR-NM-DR-025-NODELETERIGHTS
TEST_F(ClientBrowseDeleteReferencesProtectedNode, EveryItemOnAProtectedNodeIsRefusedAsNoDeleteRights)
{
  const NodeId protectedSourceId = *mDeniedSourceId;

  // The reference exists before the request, so its survival below is about what the request did.
  {
    auto before = organizes_targets_of(protectedSourceId);
    ASSERT_NE(std::find(before.begin(), before.end(), mSharedTargetId), before.end())
      << "the protected source must hold the reference before the delete";
  }

  auto request = DeleteReferencesBuilder()
                   // Item 0: the reference the protected source really holds.
                   .delete_reference(protectedSourceId, NodeId{ReferenceTypeId::Organizes}, mSharedTargetId)
                   .delete_bidirectional(false)
                   // Item 1: a second item on the same protected source, naming an existing node as
                   // its target so it passes every service-side check and is refused for the same
                   // reason as item 0 - leaving the batch with no successful item at all.
                   .delete_reference(protectedSourceId, NodeId{ReferenceTypeId::Organizes}, mAllowedSourceId)
                   .delete_bidirectional(false)
                   .build();

  auto result = mSession->node_management().try_delete_references_sync(std::move(request));
  ASSERT_TRUE(result.is_good())
    << "a batch in which every item is refused at the Node is still a successfully executed service "
       "call - the refusals are operation-level results: "
    << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 2u)
    << "every requested operation must have a slot, including when none of them succeeded";
  EXPECT_EQ(result.value().results()[0], StatusCode{Status::BadNoDeleteRights})
    << "an item whose source Node forbids removal of its References must be refused as "
       "Bad_NoDeleteRights";
  EXPECT_EQ(result.value().results()[1], StatusCode{Status::BadNoDeleteRights})
    << "the second item on the same protected Node must carry the same operation-level code, not be "
       "collapsed into a service fault because no item in the batch succeeded";

  // The reference remains - and the Node is still readable, so the refusal was about deleting the
  // reference and not about the session's access to the Node.
  auto after = organizes_targets_of(protectedSourceId);
  ASSERT_FALSE(after.empty()) << "the protected source must still be browsable";
  EXPECT_NE(std::find(after.begin(), after.end(), mSharedTargetId), after.end())
    << "a refused DeleteReferences item must leave its reference in place";

  // Both items passed the service's own validation and were dispatched: the refusal came from the
  // Node's delete rights, which is where SVR-NM-DR-025 places it, and not from an earlier check
  // that happens to reject these items for some other reason.
  auto seen = mDelegate->seen_sources();
  ASSERT_EQ(seen.size(), 2u) << "both items must reach the site that enforces the Node's delete rights";
  EXPECT_EQ(seen[0], protectedSourceId);
  EXPECT_EQ(seen[1], protectedSourceId);
}

// =============================================================================================
// Fixture: ClientBrowse plus one source Object whose single forward Organizes reference targets a
// Node on ANOTHER server (the target's ExpandedNodeId carries a non-zero serverIndex). No remote
// reference exists in the default address space, so the stimulus has to be built here.
// =============================================================================================
class ClientBrowseRemoteReference : public ClientBrowse
{
protected:
  void configure_server() override
  {
    ClientBrowse::configure_server();

    auto addressSpace = mServer.server().address_space();
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});

    mRemoteSourceId = NodeId{mTestNamespaceIndex, uint32_t{9300}};
    auto sourceNode = addressSpace.create_node_sync(mRemoteSourceId, NodeClass::Object);
    auto source = sourceNode.as<ObjectAccessor>();
    source->set_browse_name(QualifiedName{mTestNamespaceIndex, "RemoteRefSource"});
    source->set_display_name(LocalizedText{"", "RemoteRefSource"});
    sourceNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mRemoteSourceId);

    // The only forward Organizes reference the source holds: its target lives on another server.
    ExpandedNodeId remoteTarget{NodeId{uint16_t{0}, sRemoteTargetIdentifier}};
    remoteTarget.server_index() = 1;
    sourceNode.add_reference_sync(Reference{
      NodeId{ReferenceTypeId::Organizes}, remoteTarget, true, LocalizedText{"", sRemoteTargetDisplayName}});
  }

  static constexpr uint32_t sRemoteTargetIdentifier = 4242;
  static constexpr std::string_view sRemoteTargetDisplayName = "RemoteRefTarget";
  NodeId mRemoteSourceId;
};

// =============================================================================================
// ReferenceDescriptionForARemoteTargetCarriesADisplayName  (ClientBrowseRemoteReference)
//
// Part 4 section 7.30: "The displayName shall be provided for remote Nodes." It is the one exception to the
// rule that a ReferenceDescription for a target on another server carries no metadata, and that is
// what makes it easy to lose: an implementation that fills the optional fields from the RESOLVED
// local target node, and skips resolution altogether when the target is remote, nulls displayName
// along with browseName, nodeClass and typeDefinition - implementing the nulling rule correctly and
// this clause not at all. The source below holds exactly one forward Organizes reference and that
// reference is the remote one, so the single ReferenceDescription returned is the one under test.
//
// @verifies AC-SVR-VIEW-RFD-004-DISPLAYNAME
TEST_F(ClientBrowseRemoteReference, ReferenceDescriptionForARemoteTargetCarriesADisplayName)
{
  auto browseResult = mSession->view().try_browse_sync(BrowseRequestBuilder()
                                                         .browse(mRemoteSourceId)
                                                         .direction(BrowseDirection::Forward)
                                                         .reference_type(NodeId{ReferenceTypeId::Organizes})
                                                         .include_subtypes(false)
                                                         .build());
  ASSERT_TRUE(browseResult.is_good()) << "the Browse must succeed: " << to_string(browseResult.status_code());
  ASSERT_EQ(browseResult.value().results().size(), 1u)
    << "the one-node Browse must return exactly one result";
  auto& result = browseResult.value().results()[0];
  ASSERT_TRUE(result.status_code().is_good())
    << "the Browse result must be Good: " << to_string(result.status_code());
  ASSERT_EQ(result.references().size(), 1u)
    << "the source holds exactly one forward Organizes reference - the remote one - and a "
       "ReferenceDescription must be emitted for it";

  auto& reference = result.references()[0];
  EXPECT_EQ(reference.node_id().node_id().identifier().get_numeric(), sRemoteTargetIdentifier)
    << "the reference under test is the one whose target lives on another server";
  EXPECT_EQ(std::string_view{reference.display_name().text()}, sRemoteTargetDisplayName)
    << "the authority-supplied displayName shall be preserved for a remote Node, even where the "
       "other optional metadata fields are null";
}

// =============================================================================================
// RemoteReferenceKeepsItsDisplayNameWhileItsOtherMetadataIsNulled  (ClientBrowseRemoteReference)
//
// Part 4 section 7.30 states the displayName obligation for remote Nodes as an EXCEPTION to the nulling
// rule its sibling requirement (SVR-VIEW-RFD-003) states, and a criterion that observes displayName
// alone cannot tell the exception from its opposite: a server that never took the remote path at all
// - because it resolved the target as though it were local, or because the reference lost its
// serverIndex on the way out - returns a fully populated ReferenceDescription and satisfies a
// displayName-only assertion while implementing nothing. The nulled siblings and the surviving
// serverIndex are therefore asserted here alongside the displayName: together they say the
// description IS the remote-nulled one AND it still carries the one field the clause excepts. A
// server that stops nulling in order to keep displayName fails this row just as a server that nulls
// displayName with the rest does.
//
// @verifies AC-SVR-VIEW-RFD-004-DISPLAYNAME
TEST_F(ClientBrowseRemoteReference, RemoteReferenceKeepsItsDisplayNameWhileItsOtherMetadataIsNulled)
{
  auto browseResult = mSession->view().try_browse_sync(BrowseRequestBuilder()
                                                         .browse(mRemoteSourceId)
                                                         .direction(BrowseDirection::Forward)
                                                         .reference_type(NodeId{ReferenceTypeId::Organizes})
                                                         .include_subtypes(false)
                                                         .build());
  ASSERT_TRUE(browseResult.is_good()) << "the Browse must succeed: " << to_string(browseResult.status_code());
  ASSERT_EQ(browseResult.value().results().size(), 1u)
    << "the one-node Browse must return exactly one result";
  auto& result = browseResult.value().results()[0];
  ASSERT_TRUE(result.status_code().is_good())
    << "the Browse result must be Good: " << to_string(result.status_code());
  ASSERT_EQ(result.references().size(), 1u)
    << "the source holds exactly one forward Organizes reference - the remote one - and a "
       "ReferenceDescription must be emitted for it";

  auto& reference = result.references()[0];

  // The description really is the one for the target on another server: the request asked for every
  // result-mask field (the builder's default), so what follows is about what the server chose to
  // fill in, not about what was asked for.
  ASSERT_EQ(reference.node_id().server_index(), 1u)
    << "the emitted reference must still name the other server - a serverIndex flattened to 0 would "
       "make everything below a statement about a local node";
  EXPECT_EQ(reference.node_id().node_id().identifier().get_numeric(), sRemoteTargetIdentifier)
    << "the target's inner NodeId is carried alongside the serverIndex";

  // The metadata the server may not invent for a Node it does not hold (SVR-VIEW-RFD-003).
  EXPECT_TRUE(reference.browse_name().name().empty())
    << "the browseName of a remote Node is not the server's to report";
  EXPECT_EQ(reference.node_class(), ua::NodeClass::Unspecified)
    << "the nodeClass of a remote Node is not the server's to report";
  EXPECT_TRUE(reference.type_definition().node_id().is_null())
    << "the typeDefinition of a remote Node is not the server's to report";

  // The one field Part 4 section 7.30 excepts from that rule, and the reason the exception exists: the
  // displayName is the only metadata a client has to identify the remote node with.
  EXPECT_EQ(std::string_view{reference.display_name().text()}, sRemoteTargetDisplayName)
    << "the authority-supplied displayName shall be preserved for a remote Node - nulling it along "
       "with the rest of the metadata implements the nulling rule and this clause not at all";
}

// =============================================================================================
// Fixture: ClientBrowse plus one source Object whose forward Organizes references are a MIXED pair -
// one to an ordinary local Object carrying a DisplayName of its own, and one to a Node on ANOTHER
// server. A single Browse of that source returns both descriptions, produced by the same service
// call under the same result mask.
// =============================================================================================
class ClientBrowseRemoteAndLocalReference : public ClientBrowse
{
protected:
  void configure_server() override
  {
    ClientBrowse::configure_server();

    auto addressSpace = mServer.server().address_space();
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});

    mMixedSourceId = NodeId{mTestNamespaceIndex, uint32_t{9310}};
    auto sourceNode = addressSpace.create_node_sync(mMixedSourceId, NodeClass::Object);
    auto source = sourceNode.as<ObjectAccessor>();
    source->set_browse_name(QualifiedName{mTestNamespaceIndex, "MixedRefSource"});
    source->set_display_name(LocalizedText{"", "MixedRefSource"});
    sourceNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mMixedSourceId);

    // The local half of the pair: a node this server holds, with a DisplayName it can read.
    mMixedLocalTargetId = NodeId{mTestNamespaceIndex, uint32_t{9311}};
    auto localNode = addressSpace.create_node_sync(mMixedLocalTargetId, NodeClass::Object);
    auto local = localNode.as<ObjectAccessor>();
    local->set_browse_name(QualifiedName{mTestNamespaceIndex, "MixedRefLocalTarget"});
    local->set_display_name(LocalizedText{"", "MixedRefLocalTarget"});
    localNode.add_reference_sync(
      NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::BaseObjectType});
    sourceNode.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, mMixedLocalTargetId);

    // The remote half: same source, same reference type, target on another server.
    ExpandedNodeId remoteTarget{NodeId{uint16_t{0}, sMixedRemoteTargetIdentifier}};
    remoteTarget.server_index() = 1;
    sourceNode.add_reference_sync(Reference{NodeId{ReferenceTypeId::Organizes},
      remoteTarget,
      true,
      LocalizedText{"", sMixedRemoteTargetDisplayName}});
  }

  static constexpr uint32_t sMixedRemoteTargetIdentifier = 4243;
  static constexpr std::string_view sMixedRemoteTargetDisplayName = "MixedRefRemoteTarget";
  NodeId mMixedSourceId;
  NodeId mMixedLocalTargetId;
};

// =============================================================================================
// RemoteReferenceCarriesADisplayNameAlongsideItsLocalSibling  (ClientBrowseRemoteAndLocalReference)
//
// Part 4 section 7.30: "The displayName shall be provided for remote Nodes." An assertion on a remote
// description alone leaves an innocent explanation open - that this Browse never carried displayName
// for anything, because the field was masked out, or because the service does not populate it at
// all - and a criterion answered by such a test would put a tick against section 7.30 while proving nothing
// about remote Nodes specifically. Here the local sibling is emitted by the SAME service call, from
// the same source, over the same reference type and under the same result mask, and it carries the
// DisplayName the fixture gave it: the displayName machinery is therefore demonstrably working in
// this very response, and an empty displayName on the description beside it is attributable to the
// remote path and to nothing else - which is exactly where an implementation that fills the optional
// fields only from a RESOLVED local target loses the field section 7.30 excepts from the nulling rule.
//
// The two descriptions are told apart by the target identifier the fixture assigned to each, not by
// serverIndex: section 7.30 makes the encoding of a remote nodeId conditional on serverIndex but places no
// duty on the server to echo it, so a discriminator built on serverIndex would decide this test on a
// field the obligation under verification says nothing about.
// @verifies AC-SVR-VIEW-RFD-004-DISPLAYNAME
TEST_F(ClientBrowseRemoteAndLocalReference, RemoteReferenceCarriesADisplayNameAlongsideItsLocalSibling)
{
  auto browseResult = mSession->view().try_browse_sync(BrowseRequestBuilder()
                                                         .browse(mMixedSourceId)
                                                         .direction(BrowseDirection::Forward)
                                                         .reference_type(NodeId{ReferenceTypeId::Organizes})
                                                         .include_subtypes(false)
                                                         .build());
  ASSERT_TRUE(browseResult.is_good()) << "the Browse must succeed: " << to_string(browseResult.status_code());
  ASSERT_EQ(browseResult.value().results().size(), 1u)
    << "the one-node Browse must return exactly one result";
  auto& result = browseResult.value().results()[0];
  ASSERT_TRUE(result.status_code().is_good())
    << "the Browse result must be Good: " << to_string(result.status_code());
  ASSERT_EQ(result.references().size(), 2u)
    << "the source holds exactly two forward Organizes references - one local, one remote - and a "
       "ReferenceDescription must be emitted for each";

  const ua::ReferenceDescription* remote = nullptr;
  const ua::ReferenceDescription* local = nullptr;
  for (const auto& reference : result.references())
  {
    const auto& identifier = reference.node_id().node_id().identifier();
    if (!identifier.is_numeric())
      continue;
    if (identifier.get_numeric() == sMixedRemoteTargetIdentifier)
      remote = &reference;
    else if (identifier.get_numeric() == mMixedLocalTargetId.identifier().get_numeric())
      local = &reference;
  }
  ASSERT_NE(remote, nullptr)
    << "a description must be emitted for the reference whose target lives on the other server, "
       "named by the identifier the fixture gave that target";
  ASSERT_NE(local, nullptr) << "the local sibling must be emitted too";

  // The control: displayName was asked for and this server does populate it, in this very response.
  EXPECT_EQ(local->display_name().text(), "MixedRefLocalTarget")
    << "the local sibling's displayName must be present, so an empty one on the remote description "
       "cannot be blamed on the result mask or on a server that never fills the field";

  // The obligation.
  EXPECT_EQ(std::string_view{remote->display_name().text()}, sMixedRemoteTargetDisplayName)
    << "the authority-supplied displayName shall be preserved for a remote Node - the sibling "
       "emitted beside it in the same result proves the field was requested and is reachable";
}

// =============================================================================================
// TranslateBrowsePaths client-surface rows (CL-VIEW-013 / 014 / 015 / 016), driven over the same
// tier-2 Connection this file browses with. The tier-2 convenience
// `TypedAccess::try_translate_browse_path_sync` returns one path's targets as `TranslatedNodeId`s; the
// wire-shaped `service_requests().try_translate_browse_paths_sync` carries the whole per-path
// result array. Which of the two a row uses is decided by the obligation: a row about what the
// client does with ONE path's outcome uses the tier-2 surface, a row about the independence of
// several paths uses the array. A shared RelativePath of forward, subtype-inclusive hierarchical steps
// comes from `ua::hierarchical_path`; an empty `QualifiedName` gives an element with no targetName,
// the stimulus CL-VIEW-013 needs.
// =============================================================================================

// =============================================================================================
// EmptyFinalTargetNameIsRefusedNotTreatedAsAWildcard  (ClientBrowse)
//
// Part 4 section 7.32 with section 5.8.4.2: a RelativePath element before the last must carry a targetName,
// and TranslateBrowsePaths narrows the general "empty name matches anything" reading so that the FINAL
// element must carry one too. Reading the absent name as "any" is the plausible mistake - the
// permission genuinely exists one clause over - and it is silent: the malformed path stops being
// malformed and becomes a path that matches every child of the penultimate node, so the caller is
// handed a Good answer naming a node it never asked for. The path below is exactly that trap: its
// penultimate element resolves to TestFolder, which holds five children, so a wildcard reading has
// something to return and the refusal cannot be mistaken for "nothing matched". The control that
// follows differs from it in the final targetName alone and resolves to the one node it names, so
// the refusal is attributable to the omission and not to the shape of the path.
// @verifies AC-CL-VIEW-013-TARGETNAME-REQUIRED
TEST_F(ClientBrowse, EmptyFinalTargetNameIsRefusedNotTreatedAsAWildcard)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("V13")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto refused = connection->typed().try_translate_browse_path_sync(NodeId{ObjectId::ObjectsFolder},
    ua::hierarchical_path({QualifiedName{mTestNamespaceIndex, "TestFolder"}, QualifiedName{}}));

  // A wildcard reading would surface one of TestFolder's five children as a resolved target; a
  // refusal carries none, which is the only way the caller can tell the path was malformed.
  ASSERT_TRUE(refused.is_bad())
    << "a final RelativePath element with no targetName must be refused, not read as a wildcard "
       "matching every child of the penultimate node: "
    << to_string(refused.status_code());
  EXPECT_TRUE(refused.status_code() == StatusCode{Status::BadInvalidArgument} ||
              refused.status_code() == StatusCode{Status::BadBrowseNameInvalid})
    << "the refusal must name the malformed browse name - rejected locally before wire I/O "
       "(Bad_InvalidArgument) or by the server (Bad_BrowseNameInvalid) - rather than surface as an "
       "unrelated failure: "
    << to_string(refused.status_code());

  // The control: the same path shape, differing only in the final targetName, resolves.
  auto resolved = connection->typed().try_resolve_path_sync(NodeId{ObjectId::ObjectsFolder},
    ua::hierarchical_path(
      {QualifiedName{mTestNamespaceIndex, "TestFolder"}, QualifiedName{mTestNamespaceIndex, "TestMethod"}}));
  ASSERT_TRUE(resolved.is_good()) << "the well-formed path must resolve, so the refusal above is "
                                     "attributable to the missing targetName: "
                                  << to_string(resolved.status_code());
  EXPECT_EQ(resolved.value(), mTestMethodId)
    << "the control resolves to the ONE node its final targetName names - the node a wildcard "
       "reading of the refused path would have picked one of at random";
}

// =============================================================================================
// EveryTargetMatchingTheFinalBrowseNameIsReturned  (ClientBrowse)
//
// Part 4 section 5.8.4.1: a BrowsePathResult carries a LIST of targets, because one relative path can
// legitimately match more than one node - a BrowseName is unique only within a type definition, so
// two components of an instance may share one. Multiple matches are how the service reports an
// ambiguity the caller has to resolve, and the plausible implementation loses it: the wire-shaped
// surface flattens to the first target because that is what the common case wants, and the caller
// is then handed one node of two with nothing to say the other existed. The fixture's
// BrowseChildObj0 holds exactly two Variables named "DuplicateTarget", so a first-only client
// returns a well-formed, plausible, and silently wrong answer.
// @verifies AC-CL-VIEW-014-MULTIPLE-TARGETS
TEST_F(ClientBrowse, EveryTargetMatchingTheFinalBrowseNameIsReturned)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("V14")};
  ASSERT_TRUE(connection.start_status().is_good());
  ASSERT_EQ(mDuplicateNameTargetIds.size(), 2u)
    << "the fixture must hold two nodes sharing one BrowseName for this row to mean anything";

  auto request = TranslateBrowsePathsBuilder()
                   .path(mDuplicateNameParentId)
                   .step(QualifiedName{mTestNamespaceIndex, "DuplicateTarget"})
                   .build();

  auto result = connection->service_requests().try_translate_browse_paths_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "the service itself succeeds: " << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 1u) << "one browse path, one result";
  const auto& pathResult = result.value().results()[0];
  EXPECT_EQ(pathResult.status_code(), StatusCode{Status::Good})
    << "an ambiguous path is not a failure - the ambiguity is reported as several targets: "
    << to_string(pathResult.status_code());

  ASSERT_FALSE(pathResult.targets().empty()) << "the path names two existing nodes and must match them";
  EXPECT_EQ(pathResult.targets().size(), 2u)
    << "both matches must be surfaced - taking the first and discarding the rest hides the ambiguity "
       "the caller has to resolve";

  std::vector<NodeId> surfaced;
  for (const auto& target : pathResult.targets())
    surfaced.push_back(target.target_id().node_id());
  for (const auto& expected : mDuplicateNameTargetIds)
    EXPECT_NE(std::find(surfaced.begin(), surfaced.end(), expected), surfaced.end())
      << "the target " << to_string(expected) << " shares the requested BrowseName and must appear "
      << "in the surfaced target list";

  // Item 8c section 10: the tier-2 translate returns both as well, and resolve_path, which names ONE
  // node, refuses the ambiguity with the count rather than picking one.
  const RelativePath duplicate =
    ua::hierarchical_path({QualifiedName{mTestNamespaceIndex, "DuplicateTarget"}});
  auto translated = connection->typed().try_translate_browse_path_sync(mDuplicateNameParentId, duplicate);
  ASSERT_TRUE(translated.is_good()) << to_string(translated.status_code());
  EXPECT_EQ(translated.value().size(), 2u) << "the tier-2 surface keeps every target too";
  auto ambiguous = connection->typed().try_resolve_path_sync(mDuplicateNameParentId, duplicate);
  ASSERT_TRUE(ambiguous.is_bad()) << "resolve_path must not choose one of two matches";
  EXPECT_EQ(ambiguous.status_code(), StatusCode{Status::BadTooManyMatches});
  ASSERT_NE(ambiguous.shared_detail(), nullptr);
  EXPECT_EQ(ambiguous.shared_detail()->code, "ResolvePathTooManyMatches");
}

// =============================================================================================
// RemainingPathIndexSentinelIsTheIndexMaximumNotThePathLength  (ClientBrowseRemoteReference)
//
// Part 4 section 5.8.4.2: "This value shall be equal to the maximum value of the Index data type if all
// elements were processed." The sentinel is the MAXIMUM, not the number of elements, and that is
// the trap on the reading side: a client that decides "fully resolved" by comparing
// remainingPathIndex against the path length reads every complete answer as incomplete, because the
// maximum exceeds any real length - and then tries forever to continue a translation that already
// finished. Both readings are driven here against the same connection: a path this server resolves
// end to end, and a path it abandons at a genuine reference to a node on another server (the
// fixture's only forward hierarchical reference from the source). The second is the reason the
// distinction matters - its target is not a resolved Node but a pointer to continue against the
// other server, and a client that treats it as final addresses the wrong thing.
// @verifies AC-CL-VIEW-015-REMAININGPATHINDEX
TEST_F(ClientBrowseRemoteReference, RemainingPathIndexSentinelIsTheIndexMaximumNotThePathLength)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("V15")};
  ASSERT_TRUE(connection.start_status().is_good());

  // A path of two elements that this server processes completely.
  auto resolved = connection->typed().try_translate_browse_path_sync(NodeId{ObjectId::ObjectsFolder},
    ua::hierarchical_path(
      {QualifiedName{mTestNamespaceIndex, "TestFolder"}, QualifiedName{mTestNamespaceIndex, "TestMethod"}}));
  ASSERT_TRUE(resolved.is_good()) << "the fully-resolvable path must translate: "
                                  << to_string(resolved.status_code());
  ASSERT_EQ(resolved.value().size(), 1u) << "the path names one node";
  EXPECT_EQ(resolved.value()[0].remainingPathIndex, uint32_t{0xFFFFFFFFu})
    << "a fully processed path reports the maximum value of the Index type (UInt32 max)";
  EXPECT_NE(resolved.value()[0].remainingPathIndex, uint32_t{2})
    << "the sentinel is the type maximum, NOT the number of path elements";
  EXPECT_TRUE(resolved.value()[0].is_fully_resolved())
    << "the client must read the sentinel as 'complete' - comparing it against the path length "
       "reports every complete translation as unfinished";
  EXPECT_TRUE(resolved.value()[0].is_local()) << "a fully resolved local path yields a local target";
  EXPECT_EQ(resolved.value()[0].local_node_id(), mTestMethodId)
    << "the target of a complete translation is the node the path names, and it is final";

  // A path abandoned at a reference to a node on another server: the first element leaves this
  // server, so one element of the two remains to be processed elsewhere.
  auto partial = connection->typed().try_translate_browse_path_sync(mRemoteSourceId,
    ua::hierarchical_path(
      {QualifiedName{mTestNamespaceIndex, "AnyChild"}, QualifiedName{mTestNamespaceIndex, "DeeperChild"}}));
  ASSERT_TRUE(partial.has_value())
    << "a translation abandoned at an external reference is DATA, not a failure - the residual is "
       "the caller's to continue: "
    << to_string(partial.status_code());
  EXPECT_EQ(partial.status_code().as_status(), Status::UncertainReferenceOutOfServer)
    << "the Result holding the targets carries the path's status as the server answered it";
  ASSERT_EQ(partial.value().size(), 1u) << "the path leaves this server at one reference";
  EXPECT_FALSE(partial.value()[0].is_fully_resolved())
    << "an index below the sentinel means the path was NOT fully processed";
  EXPECT_EQ(partial.value()[0].remainingPathIndex, uint32_t{1})
    << "the residual path begins at the first element this server could not process";
  EXPECT_LT(partial.value()[0].remainingPathIndex, uint32_t{2})
    << "the abandoned path's index is smaller than the path length, where the complete path's is "
       "larger - the two cases are only distinguishable if the sentinel is read as the maximum";
  EXPECT_FALSE(partial.value()[0].is_local())
    << "the target of an abandoned translation is a pointer to another server, not a node on this "
       "one - reading it as a resolved local NodeId addresses a node that does not exist here";
  EXPECT_EQ(partial.value()[0].targetId.server_index(), 1u)
    << "the cross-server pointer keeps the serverIndex the caller needs to continue against";
  EXPECT_EQ(partial.value()[0].targetId.node_id().identifier().get_numeric(), sRemoteTargetIdentifier)
    << "the pointer names the node on the other server the reference led to";

  // Item 8c section 10: resolve_path names one LOCAL node, so the same abandoned path is Bad_NoMatch,
  // naming the other server and the first element left to resolve.
  auto notLocal = connection->typed().try_resolve_path_sync(mRemoteSourceId,
    ua::hierarchical_path(
      {QualifiedName{mTestNamespaceIndex, "AnyChild"}, QualifiedName{mTestNamespaceIndex, "DeeperChild"}}));
  ASSERT_TRUE(notLocal.is_bad()) << "a pointer to another server is not a node on this one";
  EXPECT_EQ(notLocal.status_code(), StatusCode{Status::BadNoMatch});
  ASSERT_NE(notLocal.shared_detail(), nullptr);
  EXPECT_EQ(notLocal.shared_detail()->code, "ResolvePathNotLocal");
  std::vector<std::string> facts;
  for (const auto& fact : notLocal.shared_detail()->context)
    facts.push_back(fact.key + "=" + fact.value);
  EXPECT_NE(std::find(facts.begin(), facts.end(), "server.index=1"), facts.end());
  EXPECT_NE(std::find(facts.begin(), facts.end(), "index=1"), facts.end());
}

// =============================================================================================
// OnePathsTranslationFailureDoesNotInvalidateTheOthers  (ClientBrowseRemoteReference)
//
// Part 4 section 5.8.4.4: TranslateBrowsePaths carries one StatusCode per browse path, and a per-path
// failure is an operation-level result - it does not touch the service result and it does not touch
// its neighbours. The implementation this row is aimed at is the one that folds the array into a
// single verdict: seeing any non-Good entry it fails the call, and the paths that DID resolve are
// lost with it. Uncertain_ReferenceOutOfServer is what makes the folding actively harmful rather
// than merely lossy - it is not a failure at all but an instruction to continue the translation on
// another server, and a client that classifies Uncertain with Bad silently drops every cross-server
// path. All three outcomes below are produced by the server for real: path 0 names a child that
// does not exist, path 1 leaves this server at the fixture's genuine external reference, and path 2
// is an ordinary two-element path that resolves.
// @verifies AC-CL-VIEW-016-PERPATH-STATUS
TEST_F(ClientBrowseRemoteReference, OnePathsTranslationFailureDoesNotInvalidateTheOthers)
{
  StartedConnection connection{mClientThreadPool.executor(), open_activated_session("V16")};
  ASSERT_TRUE(connection.start_status().is_good());

  auto request = TranslateBrowsePathsBuilder()
                   // Path 0: nothing of that BrowseName is under ObjectsFolder -> Bad_NoMatch.
                   .path(NodeId{ObjectId::ObjectsFolder})
                   .step(QualifiedName{mTestNamespaceIndex, "NoSuchChildAnywhere"})
                   // Path 1: the source's only forward hierarchical reference leaves this server.
                   .path(mRemoteSourceId)
                   .step(QualifiedName{mTestNamespaceIndex, "AnyChild"})
                   .step(QualifiedName{mTestNamespaceIndex, "DeeperChild"})
                   // Path 2: an ordinary path that resolves, sharing the request with both failures.
                   .path(NodeId{ObjectId::ObjectsFolder})
                   .step(QualifiedName{mTestNamespaceIndex, "TestFolder"})
                   .step(QualifiedName{mTestNamespaceIndex, "TestMethod"})
                   .build();

  auto result = connection->service_requests().try_translate_browse_paths_sync(std::move(request));
  ASSERT_TRUE(result.is_good()) << "two failing paths must not fail the service call - the failures "
                                   "are operation-level results: "
                                << to_string(result.status_code());
  ASSERT_EQ(result.value().results().size(), 3u)
    << "every requested path must have a slot of its own, including the ones that failed";

  EXPECT_EQ(result.value().results()[0].status_code(), StatusCode{Status::BadNoMatch})
    << "the path that matched nothing carries its own failure in its own slot: "
    << to_string(result.value().results()[0].status_code());
  EXPECT_TRUE(result.value().results()[0].targets().empty())
    << "a path that matched nothing returns no target";

  EXPECT_EQ(result.value().results()[1].status_code(), StatusCode{Status::UncertainReferenceOutOfServer})
    << "the path that left this server carries the code that says so: "
    << to_string(result.value().results()[1].status_code());
  EXPECT_TRUE(result.value().results()[1].status_code().is_uncertain())
    << "Uncertain_ReferenceOutOfServer is uncertain, not bad";
  EXPECT_FALSE(result.value().results()[1].status_code().is_bad())
    << "an uncertain path must be distinguished from the bad one beside it, not collapsed into a "
       "failure - it is an instruction to continue the translation elsewhere";
  ASSERT_FALSE(result.value().results()[1].targets().empty())
    << "the uncertain path carries the cross-server pointer the caller continues from";
  EXPECT_EQ(result.value().results()[1].targets()[0].target_id().server_index(), 1u)
    << "that pointer names the other server";

  EXPECT_EQ(result.value().results()[2].status_code(), StatusCode{Status::Good})
    << "the path that resolved must be delivered alongside the two that did not: "
    << to_string(result.value().results()[2].status_code());
  ASSERT_FALSE(result.value().results()[2].targets().empty())
    << "the surviving path's targets must be delivered, not discarded with its neighbours' failures";
  EXPECT_EQ(result.value().results()[2].targets()[0].target_id().node_id(), mTestMethodId)
    << "and they must be the targets that path names";
}
