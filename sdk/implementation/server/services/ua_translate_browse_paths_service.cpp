// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_translate_browse_paths_service.h"
#include "ua_access_control.h"
#include "ua_on_strand.h"
#include "ua_address_space.h"
#include "ua_callback_safety.h"
#include "ua_diagnostic_collector.h"
#include "ua_error_detail.h"
#include "ua_log_exception.h"
#include "ua_node_accessor_route.h"
#include "ua_node_utilities.h"
#include "ua_reference.h"
#include "ua_referencetype_id.h"
#include "ua_server.h"
#include "ua_server_encoding_limits.h"
#include "ua_server_session_info.h"
#include "ua_session_security.h"
#include "ua_service_fault.h"
#include "ua_service_request_info.h"
#include "ua_stack_utilities.h"
#include "ua_status_routing.h"
#include "ua_subtype_facts.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <map>
#include <numeric>
#include <optional>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace ua::server
{

namespace
{

Index remaining_path_index(size_t currentIndex, size_t noOfElements)
{
  check_true(noOfElements > 0, Status::BadInvalidArgument);
  if (currentIndex < noOfElements - 1)
  {
    return numeric_cast<Index>(currentIndex + 1);
  }
  return std::numeric_limits<Index>::max();
}

/// Marks "no target of this element" for the two positions a path remembers while walking one.
constexpr size_t noTarget = std::numeric_limits<size_t>::max();

/// The answer at @p position of a lookup; null when the lookup failed as a whole or answered fewer items.
const NodeAccessorResult* lookup_answer(const BatchResult<NodeAccessorResult>& batch, size_t position)
{
  if (batch.batchStatus.is_bad() || (position >= batch.items.size()))
  {
    return nullptr;
  }
  return &batch.items[position];
}

/// A target's BrowseName: from its description, or from the getter when the description does not hold it.
QualifiedName browse_name_of(const NodeAccessor& target)
{
  auto nodeDescription = ua::detail::NodeAccessorRoute::attributes(target);
  if (nodeDescription.is_good() && !nodeDescription.value().browse_name().is_null())
  {
    return nodeDescription.value().browse_name();
  }
  return target.get_browse_name();
}

/// One Node whose References an element reads, for every path that reached it: the direction and
/// ReferenceTypes they ask for, and the resume token its namespace answered, held for the next round. A
/// token still held when the query goes - its paths answered, or the request withdrawn or failed - is
/// released through the namespace that issued it.
struct ElementQuery
{
  NodeAccessor node;
  BrowseDirection direction{BrowseDirection::Both};
  std::vector<NodeId> hint;
  /// A path reading the Node asks for any ReferenceType, so the hint stays empty.
  bool anyType{false};
  ua::detail::ResumeToken token;
  /// The answers in a row that held a token and no References (`ua::detail::maxEmptyReferencePages`).
  size_t emptyPages{0};
};

}  // namespace

// =============================================================================================
// What one path's walk carries (private to this translation unit)
// =============================================================================================
//
// One path's own data, and how far along it is. Nothing here records where in the walk the code has
// got to: a coroutine's position in its own body is that. The per-element and per-reference cursors
// are ordinary locals of the request's frame, which is where a local belongs.

struct TranslateBrowsePathsService::TranslateWalk
{
  size_t opIndex{0};
  BrowsePath browsePath;
  size_t totalElements{0};

  /// Where this element starts from: the previous element's answers.
  std::vector<NodeAccessor> currentTargets;
  /// Where this element's answers accumulate, rotated into @ref currentTargets at the end of the hop.
  std::vector<NodeAccessor> nextTargets;

  /// What this path will return: one entry per target reached, plus one per remote reference it
  /// could not follow.
  std::vector<BrowsePathTarget> browsePathTargets;
  /// The worst thing that happened along the way, and the path's status if it walks to the end.
  StatusCode walkStatus{Status::Good};
  /// The codes the namespaces gave the pages of References the path walked: a Good subcode or an Uncertain
  /// code on a page holding References, combined by @ref ua::detail::combined_status. The path answers it
  /// with @ref walkStatus, so a namespace's code reaches the client with the targets.
  StatusCode pageStatus{Status::Good};

  /// Where in THIS element each of the two things that can claim @ref walkStatus last happened: a
  /// target whose references could not be fetched, and a reference that leaves the server. The later
  /// of the two in target order is the one that stands, and they are decided in different passes of
  /// the element - so the position each was reached at is remembered rather than the order the code
  /// happens to write them in. Both are reset as the element is entered.
  /// @see TranslateBrowsePathsService::apply_element_status
  size_t failedFetchAt{noTarget};
  StatusCode failedFetchStatus{Status::Good};
  size_t remoteReferenceAt{noTarget};

  /// Part 4 5.8.4: references examined by THIS path, against the server's per-path cap. The walk
  /// fetches every reference of every reachable target at every element, so an unbounded walk is an
  /// authenticated CPU-amplification denial of service against the service strand.
  uint64_t referencesExamined{0};
  /// Set when the cap is passed. The path is answered after the hop's earlier references have been
  /// accounted for, not the instant the cap trips, so it returns exactly what it had reached.
  bool budgetExceeded{false};

  /// Set once this path has answered: it takes no further part in the walk.
  bool answered{false};
};

// =============================================================================================
// Construction / destruction
// =============================================================================================

shared_ptr<TranslateBrowsePathsService> TranslateBrowsePathsService::create(weak_ptr<SessionInfo> sessionInfo,
  std::vector<LocaleId> sessionLocales, uint32_t requestId, TranslateBrowsePathsToNodeIdsRequest&& request,
  boost::asio::any_io_executor executor, ServiceCallComplete callback)
{
  struct Wrapper : public TranslateBrowsePathsService
  {
  public:
    Wrapper(weak_ptr<SessionInfo> sessionInfo, std::vector<LocaleId> sessionLocales, uint32_t requestId,
      TranslateBrowsePathsToNodeIdsRequest&& request, boost::asio::any_io_executor executor,
      ServiceCallComplete callback)
      : TranslateBrowsePathsService(
          sessionInfo, std::move(sessionLocales), requestId, std::move(request), executor, callback)
    {}
  };

  auto service = make_shared<Wrapper>(
    sessionInfo, std::move(sessionLocales), requestId, std::move(request), executor, callback);
  service->start();
  return service;
}

TranslateBrowsePathsService::TranslateBrowsePathsService(weak_ptr<SessionInfo> sessionInfo,
  std::vector<LocaleId> sessionLocales, uint32_t requestId, TranslateBrowsePathsToNodeIdsRequest&& request,
  boost::asio::any_io_executor executor, ServiceCallComplete callback)
  : ServiceBase(request.request_header().request_handle(), sessionInfo, executor),
    mSessionLocales(std::move(sessionLocales)), mRequestId(requestId), mRequest(std::move(request)),
    mServiceCallCompleteCallback(callback), mCancelled(std::make_shared<std::atomic_bool>(false))
{}

TranslateBrowsePathsService::~TranslateBrowsePathsService()
{
  // A destructor is implicitly noexcept: an escaping exception calls std::terminate. try_finish(),
  // service-fault construction, and especially the user completion callback can all throw, so the
  // whole mid-flight teardown is guarded here.
  try
  {
    // An engaged response is what "this request is still in flight" means: it is built before the
    // first suspension and released by whichever of completion, failure, cancellation or timeout got
    // there first. try_finish() is the idempotent gate behind it.
    if (!mTranslateResponse)
    {
      return;
    }
    if (!try_finish())
    {
      return;
    }
    auto callback = std::move(mServiceCallCompleteCallback);
    mTranslateResponse.reset();
    if (callback)
    {
      auto serviceFault = stack_utils::create_service_fault(&mRequest.request_header(), Status::BadShutdown);
      callback(std::make_pair(mRequestId, std::static_pointer_cast<ua::Structure>(serviceFault)));
    }
  }
  catch (...)
  {
    ua::detail::ignore_expected_exception();
  }
}

void TranslateBrowsePathsService::begin_processing()
{
  mTranslateRequestTask = run_translate_request();
}

// =============================================================================================
// The request
// =============================================================================================

ua::async::Task<> TranslateBrowsePathsService::run_translate_request()
{
  // This task is a root - nobody awaits it - so an exception that escapes is stored in the promise
  // and read by nobody, and the request never answers.
  try
  {
    co_await dispatch_translate_request();
    // Completed HERE, not inside the body: the body has early exits - every path rejected by a
    // synchronous check, no access identity to authorize with - and every one of them still owes the
    // client a response.
    complete_translate();
  }
  catch (const ua::async::Abandoned&)
  {
    // The request was withdrawn while this was suspended: cancelled or timed out. Whoever withdrew
    // it answered the client.
    ua::detail::ignore_expected_exception();
  }
  catch (...)
  {
    ua::async::guarded(mLogger,
      [this]
      {
        auto er = ua::exception_to_status_code(std::current_exception());
        if (auto sessionInfo = mSessionInfo.lock())
        {
          log_exception(sessionInfo->logger().with_category("service"),
            LogLevel::Error,
            "TranslateBrowsePathsService",
            er);
        }
        fail_translate(VoidResult{er, er.shared_detail()});
      })();
  }
}

std::vector<TranslateBrowsePathsService::TranslateWalk> TranslateBrowsePathsService::prepare_translate_walks()
{
  const size_t noOfOperations = mRequest.browse_paths().size();
  std::vector<TranslateWalk> walks;
  walks.reserve(noOfOperations);

  for (size_t opIndex = 0; opIndex < noOfOperations; ++opIndex)
  {
    TranslateWalk walk;
    walk.opIndex = opIndex;
    walk.browsePath = mRequest.browse_paths()[opIndex];
    walk.totalElements = walk.browsePath.relative_path().elements().size();
    walks.push_back(std::move(walk));
  }

  // Synchronous, so a path this rejects never costs its namespace a round trip.
  for (auto& walk : walks)
  {
    if (walk.browsePath.starting_node().is_null())
    {
      finish_walk(walk,
        VoidResult{Status::BadNodeIdInvalid,
          ErrorDetail::build("InvalidStartingNodeId",
            "TranslateBrowsePaths starting node is structurally invalid",
            "TranslateBrowsePathsService")
            .context(ua::ContextKeys::index, std::to_string(walk.opIndex))
            .context(ua::ContextKeys::nodeId, ua::to_string(walk.browsePath.starting_node()))});
    }
  }

  return walks;
}

/// @par Matches the reference implementation
/// `run_translate_request` / `dispatch_translate_request` are the same two shapes as Read's in
/// `ua_attribute_service_set.cpp`: a root that contains and completes, and a body that resolves once,
/// authorizes once, and drives the work. What is different, and deliberately so, is that there is no
/// per-path coroutine below them.
///
/// @par Why the request drives the walk
/// The batching that matters is ACROSS paths within one relative-path element: every path still
/// walking has a set of live targets, and every reference target that survives the synchronous
/// filters can be resolved in one call, whatever path it belongs to. A per-path coroutine cannot see
/// the other paths, so it cannot do that, and making it do so would need a rendezvous per element -
/// which is the barrier this pattern has no place for.
///
/// The elements are genuinely serial: an element's input is the previous element's answers. So
/// nothing is lost by walking every path in step, one element at a time: the request costs one
/// resolution for the starting nodes plus one per element, whatever its width and however many
/// references each element examines.
ua::async::Task<> TranslateBrowsePathsService::dispatch_translate_request()
{
  // `walks` is built once and never grown again, so the pointers the passes below take into it stay
  // valid for the whole request. It lives in this frame, which owns every path's state for as long as
  // the request has one.
  std::vector<TranslateWalk> walks;

  // The session is locked, used and released BEFORE anything suspends. A shared_ptr to it held across
  // a co_await would live in this frame for the request's whole life - and the session transitively
  // owns this service, which owns the task, which owns the frame - the ownership cycle a
  // request-scoped task must not close.
  {
    auto sessionInfo = mSessionInfo.lock();

    DiagnosticSecurityContext securityContext;
    if (sessionInfo)
    {
      securityContext = sessionInfo->diagnostic_security_context();
    }
    // Built BEFORE the checks below, because a throw from any of them is answered with this collector.
    mTranslateCollector =
      DiagnosticCollector{mRequest.request_header().return_diagnostics(), securityContext};

    if (!sessionInfo)
    {
      throw_null_pointer_check(Status::BadInvalidArgument);
    }

    set_timeout();
    mRequestInfo = service_request_info(std::chrono::steady_clock::now(),
      mRequest.request_header().timeout_hint(),
      std::nullopt,
      mCancelled,
      mSessionLocales);

    const size_t noOfOperations{mRequest.browse_paths().size()};
    if (noOfOperations == 0)
    {
      throw UaException{Status::BadNothingToDo,
        make_error_detail("EmptyTranslateRequest",
          "TranslateBrowsePaths request contains no browse paths",
          "TranslateBrowsePathsService")};
    }

    auto& maxNodesPerTranslate = sessionInfo->server_configuration()
                                   .server_capabilities()
                                   .operationLimits.maxNodesPerTranslateBrowsePathsToNodeIds;
    if (maxNodesPerTranslate && (noOfOperations > maxNodesPerTranslate.value()))
    {
      throw UaException{Status::BadTooManyOperations,
        ErrorDetail::build("TooManyBrowsePaths",
          "Requested browse paths exceed the configured "
          "MaxNodesPerTranslateBrowsePathsToNodeIds limit",
          "TranslateBrowsePathsService")
          .context(ua::ContextKeys::actual, std::to_string(noOfOperations))
          .context(ua::ContextKeys::limit, std::to_string(maxNodesPerTranslate.value()))};
    }

    mTranslateAddressSpace = sessionInfo->address_space();
    mTranslateAccessControl = SessionAccessControl::create(*sessionInfo);
    mTranslateLimits = ua::server::make_server_encoding_limits(
      sessionInfo->configuration(), sessionInfo->server_configuration());
    mMaxWalkReferences = sessionInfo->server_configuration().maxBrowsePathWalkReferences.value_or(0);

    mTranslateResponse = make_shared<TranslateBrowsePathsToNodeIdsResponse>();
    mTranslateResponse->results().resize(noOfOperations);

    walks = prepare_translate_walks();
  }

  // Nothing can be authorized without a committed access identity, so nothing is browsed and nothing
  // is even resolved: every path answers here, before its namespace is touched.
  if (!mTranslateAccessControl)
  {
    const shared_ptr<const ErrorDetail> detail = make_error_detail("AuthorizationUnavailable",
      "No committed access identity for session - failed closed",
      "TranslateBrowsePathsService");
    for (auto& walk : walks)
    {
      finish_walk(walk, VoidResult{Status::BadUserAccessDenied, detail});
    }
    co_return;
  }

  auto addressSpace = *mTranslateAddressSpace;
  const WeakAddressSpace weakAddressSpace = addressSpace.weak();

  // --- ONE lookup per namespace for every path's starting node ----------------------------------
  //
  // Each distinct starting node is asked about once, and its answer goes to every path that starts there.
  std::vector<TranslateWalk*> starting;
  std::vector<size_t> startingLookupOf;
  std::vector<ua::detail::LookupItem> startingLookups;
  {
    std::unordered_map<NodeId, size_t> lookupOf;
    for (auto& walk : walks)
    {
      if (walk.answered)
      {
        continue;
      }
      const NodeId& startingNode = walk.browsePath.starting_node();
      const auto [entry, added] = lookupOf.try_emplace(startingNode, startingLookups.size());
      if (added)
      {
        startingLookups.push_back(ua::detail::LookupItem{startingNode, std::nullopt});
      }
      starting.push_back(&walk);
      startingLookupOf.push_back(entry->second);
    }
  }

  if (starting.empty())
  {
    // Every path was rejected by a synchronous check and has already written its own result.
    co_return;
  }

  auto startingBatch = co_await await_step<BatchResult<NodeAccessorResult>>(
    [this, &weakAddressSpace, &startingLookups](auto completion)
    {
      ua::detail::NodeAccessorRoute::find_nodes(
        weakAddressSpace, mRequestInfo, startingLookups, std::move(completion));
    });

  // --- ONE authorization per namespace for every starting node that resolved ---------------------
  std::vector<AccessControl::Item> subjects;
  std::vector<std::optional<size_t>> subjectOfLookup(startingLookups.size());
  for (size_t l = 0; l < startingLookups.size(); ++l)
  {
    const NodeAccessorResult* resolved = lookup_answer(startingBatch, l);
    if ((resolved != nullptr) && resolved->is_good())
    {
      subjectOfLookup[l] = subjects.size();
      subjects.push_back(AccessControl::Item{resolved->value(), AccessOperation::TranslateBrowsePaths});
    }
  }

  std::vector<AccessControl::Verdict> verdicts;
  if (!subjects.empty())
  {
    verdicts = co_await await_step<std::vector<AccessControl::Verdict>>([this, &subjects](auto completion)
      { mTranslateAccessControl->authorize_async(mRequestInfo, subjects, std::move(completion)); });
  }

  for (size_t k = 0; k < starting.size(); ++k)
  {
    const size_t l = startingLookupOf[k];
    if (!subjectOfLookup[l])
    {
      // A short batch is a namespace answering fewer items than it was asked about, which is a contract
      // breach rather than an outcome for the path, so it reads as an internal error; a batch status
      // answers every item.
      const NodeAccessorResult* resolved = lookup_answer(startingBatch, l);
      VoidResult failure{StatusCode{Status::BadInternalError}};
      if (resolved != nullptr)
      {
        failure = VoidResult{resolved->status_code(), resolved->shared_detail()};
      }
      else if (startingBatch.batchStatus.is_bad())
      {
        failure = startingBatch.batchStatus;
      }
      // Forward both status_code and shared_detail() per the Result invariant.
      finish_walk(*starting[k], failure);
      continue;
    }

    // A missing verdict is a contract breach rather than an outcome, so it denies: this path fails
    // closed, and says so as an internal error rather than as a user decision.
    const size_t s = *subjectOfLookup[l];
    AccessControl::Verdict verdict{.cause = StatusCode{Status::BadInternalError}};
    if (s < verdicts.size())
    {
      verdict = verdicts[s];
    }
    if (!verdict.permitted)
    {
      finish_walk(*starting[k], VoidResult{verdict.cause});
      continue;
    }

    // Asked only of a path whose starting node resolved AND was authorized: an unknown or
    // forbidden starting node is the answer, and an empty path behind it is never reached.
    if (starting[k]->totalElements == 0)
    {
      finish_walk(*starting[k],
        VoidResult{Status::BadNothingToDo,
          make_error_detail(
            "EmptyRelativePath", "Browse path has no elements", "TranslateBrowsePathsService")});
      continue;
    }

    // The starting node is the first element's only live target.
    starting[k]->currentTargets.push_back(subjects[s].node);
  }

  // Whether a ReferenceType W is a requested type D or a subtype of it, for every (W, D) this request has
  // asked: a type met again in a later element or round is not walked again.
  std::map<std::pair<NodeId, NodeId>, bool> subtypeAnswers;
  // Whether a ReferenceType is symmetric, for every type this request has looked up. Both halves of a
  // symmetric Reference are forward (OPC 10000-3 5.3.2), so its half stored as inverse is followed by a
  // forward element and not by an inverse one, as Browse reports it (OPC 10000-4 5.8.2.2).
  std::unordered_map<NodeId, bool> symmetry;

  // --- the walk: one relative-path element at a time, every path together -----------------------
  //
  // Every local below lives in this frame, so it survives each suspension without being re-found by
  // index, and the loop's own position is the whole of where the walk has got to.
  for (size_t elementIndex = 0;; ++elementIndex)
  {
    // --- 1. retire what has walked out, and screen this element ---------------------------------
    //
    // A path with no live targets left is NOT dropped here: it still has to screen its remaining
    // elements, because an element that names no target invalidates the path whether or not anything
    // reached it.
    std::vector<TranslateWalk*> live;
    live.reserve(walks.size());
    for (auto& walk : walks)
    {
      if (walk.answered)
      {
        continue;
      }
      if (elementIndex >= walk.totalElements)
      {
        finish_walked_out(walk);
        continue;
      }

      const auto& element = walk.browsePath.relative_path().elements().payload()[elementIndex];
      if (element.target_name().is_null())
      {
        finish_walk(walk,
          VoidResult{Status::BadBrowseNameInvalid,
            ErrorDetail::build("MissingBrowsePathTargetName",
              "TranslateBrowsePaths relative path element has no target name",
              "TranslateBrowsePathsService")
              .context(ua::ContextKeys::index, std::to_string(elementIndex))});
        continue;
      }

      walk.nextTargets.clear();
      walk.failedFetchAt = noTarget;
      walk.remoteReferenceAt = noTarget;
      live.push_back(&walk);
    }

    if (live.empty())
    {
      break;
    }

    // --- 2. the element's reached Nodes, each one query -------------------------------------------
    //
    // Every live target of every live path, in path order then target order - which is the order the
    // element's work is charged, filtered and applied in, so a path's answer does not depend on how
    // many other paths are in the request. A Node that several paths reach is read once, with the
    // direction and ReferenceTypes all of them want, and its answer goes to each.
    struct ElementTarget
    {
      TranslateWalk* walk{nullptr};
      size_t query{0};
    };

    std::vector<ElementTarget> elementTargets;
    std::vector<ElementQuery> queries;
    {
      std::unordered_map<NodeId, size_t> queryOf;
      for (auto* walk : live)
      {
        const auto& pathElement = walk->browsePath.relative_path().elements().payload()[elementIndex];
        const BrowseDirection direction =
          pathElement.is_inverse() ? BrowseDirection::Inverse : BrowseDirection::Forward;
        for (const auto& target : walk->currentTargets)
        {
          const NodeId targetId = target.get_node_id();
          const auto [entry, added] = queryOf.try_emplace(targetId, queries.size());
          if (added)
          {
            queries.push_back(ElementQuery{.node = target,
              .direction = direction,
              .hint = {},
              .anyType = false,
              .token = {},
              .emptyPages = 0});
          }
          ElementQuery& query = queries[entry->second];
          if (query.direction != direction)
          {
            query.direction = BrowseDirection::Both;
          }
          // The hint names every ReferenceType the paths reading the Node ask for, and is empty when one of
          // them asks for any type (NR-61: a hint never narrows what a path follows).
          const NodeId& referenceType = pathElement.reference_type_id();
          if (referenceType.is_null())
          {
            query.anyType = true;
            query.hint.clear();
          }
          else if (!query.anyType && (std::ranges::find(query.hint, referenceType) == query.hint.end()))
          {
            query.hint.push_back(referenceType);
          }
          elementTargets.push_back(ElementTarget{.walk = walk, .query = entry->second});
        }
      }
    }

    // --- 3. rounds: every query, then again those a namespace answered with a resume token ---------
    //
    // A namespace that answers a token with no References is followed for at most maxEmptyReferencePages
    // such answers in a row; an answer that holds a Reference starts the count again.
    std::vector<size_t> pending(queries.size());
    std::iota(pending.begin(), pending.end(), size_t{0});
    while (!pending.empty())
    {
      // One read per namespace for the round's queries. A token sent is consumed by the call whatever it
      // answers, so it is no longer this request's to release.
      std::vector<ua::detail::ReferenceRead> reads;
      reads.reserve(pending.size());
      for (const size_t q : pending)
      {
        ElementQuery& query = queries[q];
        reads.push_back(
          ua::detail::ReferenceRead{query.node, query.direction, query.hint, 0, std::move(query.token)});
      }

      std::vector<ua::detail::ReferencePage> pages;
      std::optional<StatusCode> readFailure;
      try
      {
        pages = co_await await_step<std::vector<ua::detail::ReferencePage>>(
          [this, &reads](auto completion) {
            ua::detail::NodeAccessorRoute::read_references(
              mRequestInfo, std::move(reads), std::move(completion));
          });
      }
      catch (const ua::async::Abandoned&)
      {
        throw;  // the whole request is over; stop
      }
      catch (...)
      {
        readFailure = ua::exception_to_status_code(std::current_exception());
      }
      if (!readFailure && (pages.size() != pending.size()))
      {
        // The pages could not be allocated.
        readFailure = StatusCode{Status::BadOutOfMemory};
      }

      // Each query's answer: its References, or why it has none. A token answered is held for the next
      // round, with the namespace that issued it.
      struct QueryAnswer
      {
        References references;
        /// The code of a page holding References: plain Good, a Good subcode or an Uncertain code.
        StatusCode code{Status::Good};
        std::optional<StatusCode> failed;
        shared_ptr<const ErrorDetail> detail;
      };

      std::vector<std::optional<size_t>> answerOf(queries.size());
      std::vector<QueryAnswer> answers(pending.size());
      for (size_t k = 0; k < pending.size(); ++k)
      {
        const size_t q = pending[k];
        answerOf[q] = k;
        if (readFailure)
        {
          answers[k].failed = *readFailure;
          continue;
        }
        auto& answer = pages[k].answer;
        if (!answer.has_value())
        {
          // Bad, or Uncertain without References.
          answers[k].failed = answer.status_code();
          answers[k].detail = answer.shared_detail();
          continue;
        }
        answers[k].code = answer.status_code();
        queries[q].token = std::move(pages[k].resumeToken);
        queries[q].emptyPages = answer.value().references.empty() ? queries[q].emptyPages + 1 : 0;
        if (!queries[q].token.empty() && (queries[q].emptyPages >= ua::detail::maxEmptyReferencePages))
        {
          // The namespace kept answering a token with no References: the Node's read fails, and its last
          // token is released.
          queries[q].token.release();
          auto failed = StatusCode{Status::BadInternalError,
            ErrorDetail::build("NamespacePagingDidNotEnd",
              "The namespace kept answering resume tokens for the References of a Node",
              "TranslateBrowsePathsService")
              .context(ua::ContextKeys::nodeId, ua::to_string(queries[q].node.get_node_id()))
              .context(ua::ContextKeys::limit, std::to_string(ua::detail::maxEmptyReferencePages))};
          answers[k].detail = failed.shared_detail();
          answers[k].failed = std::move(failed);
          continue;
        }
        answers[k].references = std::move(answer.value().references);
      }
      pages.clear();
      reads.clear();

      // --- 4. the synchronous filters, and what each survivor still has to be asked --------------
      struct Candidate
      {
        TranslateWalk* walk{nullptr};
        ExpandedNodeId targetId;
        size_t targetIndex{0};
        NodeId referenceType;
      };

      std::vector<Candidate> candidates;
      // References stored as inverse: whether the element follows one depends on whether its type is
      // symmetric.
      std::vector<Candidate> storedInverse;
      for (size_t t = 0; t < elementTargets.size(); ++t)
      {
        auto* walk = elementTargets[t].walk;
        const auto& at = answerOf[elementTargets[t].query];
        if (!at || walk->answered)
        {
          continue;
        }
        const QueryAnswer& answer = answers[*at];
        if (answer.failed)
        {
          // A failed read is a best-effort skip of that target: the path walks on with the targets that
          // did answer, its earlier pages' included, so a partial result can still surface. A later round
          // can meet an earlier target, so the position only moves forward and the status stays with the
          // target that stands.
          if ((walk->failedFetchAt == noTarget) || (t >= walk->failedFetchAt))
          {
            walk->failedFetchAt = t;
            walk->failedFetchStatus = *answer.failed;
          }
          if (answer.detail)
          {
            mTranslateCollector.add_item_detail(walk->opIndex, answer.detail);
          }
          continue;
        }
        if (walk->budgetExceeded)
        {
          // The cap tripped on an earlier target of this same path, so this one is never examined.
          continue;
        }
        if (answer.code != walk->pageStatus)
        {
          // The codes of the pages the path walked share its one status; a code with a SubCode that is not
          // answered is logged.
          walk->pageStatus = server::detail::combined_item_status(walk->pageStatus,
            answer.code,
            mLogger,
            "TranslateBrowsePathsService: the code of a page of References was not answered",
            walk->browsePath.starting_node());
        }
        const auto& pathElement = walk->browsePath.relative_path().elements().payload()[elementIndex];

        for (const auto& reference : answer.references)
        {
          ++walk->referencesExamined;
          if ((mMaxWalkReferences > 0) && (walk->referencesExamined > mMaxWalkReferences))
          {
            // Answered after this round's earlier references have been accounted for, so the path
            // still returns the remote targets it had reached before the cap tripped.
            walk->budgetExceeded = true;
            break;
          }

          if (!reference.is_forward())
          {
            storedInverse.push_back(Candidate{.walk = walk,
              .targetId = reference.target_id(),
              .targetIndex = t,
              .referenceType = reference.type_id()});
            continue;
          }
          if (pathElement.is_inverse())
          {
            continue;
          }

          candidates.push_back(Candidate{.walk = walk,
            .targetId = reference.target_id(),
            .targetIndex = t,
            .referenceType = reference.type_id()});
        }
      }
      answers.clear();

      // --- 4b. the Symmetric attribute of the types of References stored as inverse, in one lookup -----
      if (!storedInverse.empty())
      {
        std::vector<ua::detail::LookupItem> typeLookups;
        for (const auto& candidate : storedInverse)
        {
          if (!symmetry.contains(candidate.referenceType) &&
              (std::ranges::find_if(typeLookups,
                 [&candidate](const ua::detail::LookupItem& item)
                 { return item.nodeId == candidate.referenceType; }) == typeLookups.end()))
          {
            typeLookups.push_back(ua::detail::LookupItem{candidate.referenceType, std::nullopt});
          }
        }
        if (!typeLookups.empty())
        {
          auto typeBatch = co_await await_step<BatchResult<NodeAccessorResult>>(
            [this, &weakAddressSpace, &typeLookups](auto completion)
            {
              ua::detail::NodeAccessorRoute::find_nodes(
                weakAddressSpace, mRequestInfo, typeLookups, std::move(completion));
            });
          for (size_t l = 0; l < typeLookups.size(); ++l)
          {
            // A type that cannot be read is taken as not symmetric: the stored direction stands, as in
            // Browse.
            const NodeAccessorResult* found = lookup_answer(typeBatch, l);
            std::optional<ReferenceTypeAccessor> referenceType;
            if ((found != nullptr) && found->is_good())
            {
              referenceType = found->value().as<ReferenceTypeAccessor>();
            }
            symmetry.insert_or_assign(typeLookups[l].nodeId, referenceType && referenceType->get_symmetric());
          }
        }
        for (auto& candidate : storedInverse)
        {
          const auto known = symmetry.find(candidate.referenceType);
          const bool symmetric = (known != symmetry.end()) && known->second;
          if (candidate.walk->browsePath.relative_path().elements().payload()[elementIndex].is_inverse() !=
              symmetric)
          {
            candidates.push_back(std::move(candidate));
          }
        }
      }

      // --- 5. the ReferenceType facts this round still lacks, in one resolution --------------------
      //
      // Part 4 7.27: an unspecified (null) referenceTypeId follows all References and ignores
      // includeSubtypes - no type filter, so such a reference matches.
      std::vector<std::pair<NodeId, NodeId>> questions;
      for (const auto& candidate : candidates)
      {
        const auto& pathElement =
          candidate.walk->browsePath.relative_path().elements().payload()[elementIndex];
        const NodeId& requested = pathElement.reference_type_id();
        if (requested.is_null() || !pathElement.include_subtypes() || (candidate.referenceType == requested))
        {
          continue;
        }
        auto question = std::make_pair(candidate.referenceType, requested);
        if (!subtypeAnswers.contains(question) && (std::ranges::find(questions, question) == questions.end()))
        {
          questions.push_back(std::move(question));
        }
      }
      if (!questions.empty())
      {
        std::vector<bool> subtypes;
        try
        {
          subtypes = co_await await_step<std::vector<bool>>(
            [this, &addressSpace, &questions](auto completion)
            {
              SubtypeFacts::resolve_async(addressSpace,
                mRequestInfo,
                questions,
                SubtypeFacts::Bounds{mTranslateLimits.execution.loopLimit,
                  [](const NodeId& type)
                  {
                    return type == NodeId{ReferenceTypeId::References};
                  }},
                std::move(completion));
            });
        }
        catch (const ua::async::Abandoned&)
        {
          throw;
        }
        catch (...)
        {
          // What cannot be decided is not a match, which filters out every reference that needed it.
          subtypes.clear();
        }
        for (size_t c = 0; c < questions.size(); ++c)
        {
          subtypeAnswers.insert_or_assign(questions[c], c < subtypes.size() && subtypes[c]);
        }
      }

      // --- 6. apply the type answers, and emit what cannot be followed -----------------------------
      struct LocalTarget
      {
        TranslateWalk* walk{nullptr};
        NodeId targetId;
      };

      std::vector<LocalTarget> locals;
      locals.reserve(candidates.size());

      for (auto& candidate : candidates)
      {
        const auto& pathElement =
          candidate.walk->browsePath.relative_path().elements().payload()[elementIndex];
        const NodeId& requested = pathElement.reference_type_id();
        if (!requested.is_null() && (candidate.referenceType != requested))
        {
          if (!pathElement.include_subtypes())
          {
            continue;
          }
          const auto known = subtypeAnswers.find(std::make_pair(candidate.referenceType, requested));
          if ((known == subtypeAnswers.end()) || !known->second)
          {
            continue;
          }
        }

        if (candidate.targetId.is_remote())
        {
          // Emitted with the index of the element the client would resume at, so it can re-issue the
          // rest of the path against the server that owns the node.
          if ((candidate.walk->remoteReferenceAt == noTarget) ||
              (candidate.targetIndex >= candidate.walk->remoteReferenceAt))
          {
            candidate.walk->remoteReferenceAt = candidate.targetIndex;
          }
          BrowsePathTarget target;
          target.target_id() = candidate.targetId;
          target.remaining_path_index() = remaining_path_index(elementIndex, candidate.walk->totalElements);
          candidate.walk->browsePathTargets.push_back(std::move(target));
          continue;
        }

        if (candidate.targetId.is_not_index_based())
        {
          // A local target named by its namespace URI is looked up by that namespace's index, as Browse
          // resolves it; a URI the server does not hold names no Node here, and is skipped as a target
          // that does not resolve is.
          try
          {
            const uint16_t namespaceIndex =
              addressSpace.namespace_array().get_namespace_index(candidate.targetId.namespace_uri());
            candidate.targetId.namespace_uri().clear();
            candidate.targetId.node_id().namespace_index() = namespaceIndex;
          }
          catch (const UaException&)
          {
            ua::detail::ignore_expected_exception();
            continue;
          }
        }

        locals.push_back(LocalTarget{.walk = candidate.walk, .targetId = candidate.targetId.node_id()});
      }
      candidates.clear();

      for (auto* walk : live)
      {
        if (walk->budgetExceeded && !walk->answered)
        {
          apply_element_status(*walk);
          finish_walk(*walk,
            VoidResult{Status::BadQueryTooComplex,
              ErrorDetail::build("BrowsePathWalkTooComplex",
                "TranslateBrowsePaths walk exceeded the per-operation references-examined budget",
                "TranslateBrowsePathsService")
                .context(ua::ContextKeys::sizeMax, std::to_string(mMaxWalkReferences))});
        }
      }
      std::erase_if(locals, [](const LocalTarget& local) { return local.walk->answered; });

      // The queries the next round reads: those answered with a token that a path still walking reads. A
      // token no such path wants is released now, through the namespace that issued it.
      pending.clear();
      {
        std::vector<bool> wanted(queries.size(), false);
        for (const auto& elementTarget : elementTargets)
        {
          if (!elementTarget.walk->answered)
          {
            wanted[elementTarget.query] = true;
          }
        }
        for (size_t q = 0; q < queries.size(); ++q)
        {
          if (queries[q].token.empty())
          {
            continue;
          }
          if (wanted[q])
          {
            pending.push_back(q);
          }
          else
          {
            queries[q].token.release();
          }
        }
      }

      // --- 7. ONE lookup per namespace of the round's distinct local targets -----------------------
      // --- 8. and only those whose BrowseName is the one the element asked for are authorized -----
      std::vector<AccessControl::Item> roundSubjects;
      std::vector<std::pair<TranslateWalk*, size_t>> subjectOf;
      if (!locals.empty())
      {
        std::vector<ua::detail::LookupItem> targetLookups;
        std::vector<size_t> lookupOf;
        lookupOf.reserve(locals.size());
        {
          std::unordered_map<NodeId, size_t> distinct;
          for (const auto& local : locals)
          {
            const auto [entry, added] = distinct.try_emplace(local.targetId, targetLookups.size());
            if (added)
            {
              targetLookups.push_back(ua::detail::LookupItem{local.targetId, std::nullopt});
            }
            lookupOf.push_back(entry->second);
          }
        }

        auto targetBatch = co_await await_step<BatchResult<NodeAccessorResult>>(
          [this, &weakAddressSpace, &targetLookups](auto completion)
          {
            ua::detail::NodeAccessorRoute::find_nodes(
              weakAddressSpace, mRequestInfo, targetLookups, std::move(completion));
          });

        // Each found target's BrowseName, read once: from its description, or from the getter when the
        // description does not hold it.
        std::vector<std::optional<QualifiedName>> browseNames(targetLookups.size());
        std::vector<std::optional<size_t>> subjectOfTarget(targetLookups.size());
        for (size_t k = 0; k < locals.size(); ++k)
        {
          // A target that does not resolve is skipped and the path walks on with the rest - the
          // best-effort behaviour the reference corpus relies on. A short batch is skipped the same way, and
          // so is an Uncertain answer, with or without its Node: the SDK does not walk a path through a Node
          // the namespace is uncertain of (COMP-SVR-NAMESPACE-CALLS-24).
          const size_t l = lookupOf[k];
          const NodeAccessorResult* found = lookup_answer(targetBatch, l);
          if ((found == nullptr) || !found->is_good())
          {
            continue;
          }
          const NodeAccessor& target = found->value();
          if (!browseNames[l])
          {
            browseNames[l] = browse_name_of(target);
          }
          const auto& pathElement =
            locals[k].walk->browsePath.relative_path().elements().payload()[elementIndex];
          if (*browseNames[l] != pathElement.target_name())
          {
            continue;
          }
          if (!subjectOfTarget[l])
          {
            subjectOfTarget[l] = roundSubjects.size();
            roundSubjects.push_back(AccessControl::Item{target, AccessOperation::TranslateBrowsePaths});
          }
          subjectOf.emplace_back(locals[k].walk, *subjectOfTarget[l]);
        }
      }

      // --- 9. ONE authorization per namespace for the round ------------------------------------------
      // --- 10. and the survivors of THAT are what the next element starts from -----------------------
      if (!roundSubjects.empty())
      {
        auto roundVerdicts = co_await await_step<std::vector<AccessControl::Verdict>>(
          [this, &roundSubjects](auto completion)
          { mTranslateAccessControl->authorize_async(mRequestInfo, roundSubjects, std::move(completion)); });

        for (const auto& [walk, s] : subjectOf)
        {
          // A short verdict list is a contract breach rather than an outcome, so it denies: this
          // path fails closed.
          if ((s >= roundVerdicts.size()) || !roundVerdicts[s].permitted)
          {
            continue;
          }

          // Dedup by target NodeId: the same node can be reached through more than one matching
          // reference (an inverse element where two references resolve to the same parent). A node
          // is a single target, so emitting it twice is wrong - UACTT TranslateBrowsePath 004
          // follows one inverse element and expects exactly one target, not two.
          const auto targetId = roundSubjects[s].node.get_node_id();
          const bool alreadyPresent = std::any_of(walk->nextTargets.begin(),
            walk->nextTargets.end(),
            [&targetId](const NodeAccessor& existing) { return existing.get_node_id() == targetId; });
          if (!alreadyPresent)
          {
            walk->nextTargets.push_back(roundSubjects[s].node);
          }
        }
      }

      // Give the strand back before the next round.
      //
      // Every collaborator on this path can answer on the calling stack - the in-memory address
      // space always does - and a completion that arrives on the strand it is already running on
      // resumes inline rather than queueing. A walk would otherwise run from its first element to
      // its last inside the one strand turn the request started in, and this service's own timeout
      // timer, armed on that strand, could not run until it had finished: a client's timeoutHint
      // would go unhonoured and one pool thread would stay on this request for its whole length.
      co_await yield_strand();
    }

    if (elementTargets.empty())
    {
      // An element with no live target left still screens the remaining elements of every path that
      // reached it, and runs no round - so this is where its turn ends. @see yield_strand
      co_await yield_strand();
    }

    for (auto* walk : live)
    {
      if (!walk->answered)
      {
        apply_element_status(*walk);
      }
      walk->currentTargets = std::move(walk->nextTargets);
      walk->nextTargets.clear();
    }
  }
}

// =============================================================================================
// Answering one path
// =============================================================================================

void TranslateBrowsePathsService::finish_walk(TranslateWalk& walk, VoidResult terminalStatus)
{
  walk.answered = true;

  if (!mTranslateResponse || (walk.opIndex >= mTranslateResponse->results().size()))
  {
    return;
  }

  auto& result = mTranslateResponse->results()[walk.opIndex];
  result.status_code() = terminalStatus.status_code();
  if (terminalStatus.shared_detail())
  {
    mTranslateCollector.add_item_detail(walk.opIndex, terminalStatus.shared_detail());
  }
  result.targets() = walk.browsePathTargets;
}

void TranslateBrowsePathsService::apply_element_status(TranslateWalk& walk)
{
  // Part 4 5.8.4: a path that reached at least one target answers Good, one that could not follow a
  // reference out of the server answers Uncertain_ReferenceOutOfServer, and one whose references
  // could not be read answers what the read failed with. An element can meet both of the last two,
  // and only the one reached LATER along the element stands - which is the order a walk that
  // examined one target at a time produced, and the order a client reading the targets sees. Both
  // positions only move forward across an element's rounds, so a later round's earlier target does
  // not displace them.
  if ((walk.failedFetchAt != noTarget) &&
      ((walk.remoteReferenceAt == noTarget) || (walk.failedFetchAt > walk.remoteReferenceAt)))
  {
    walk.walkStatus = walk.failedFetchStatus;
    return;
  }
  if (walk.remoteReferenceAt != noTarget)
  {
    walk.walkStatus = Status::UncertainReferenceOutOfServer;
  }
}

void TranslateBrowsePathsService::finish_walked_out(TranslateWalk& walk)
{
  // Every target still live at the end of the path is a target of the path, with nothing of it left
  // to resolve.
  for (const auto& target : walk.currentTargets)
  {
    BrowsePathTarget browsePathTarget;
    browsePathTarget.target_id() = ExpandedNodeId{target.get_node_id()};
    browsePathTarget.remaining_path_index() = std::numeric_limits<Index>::max();
    walk.browsePathTargets.push_back(std::move(browsePathTarget));
  }

  if (walk.browsePathTargets.empty() && walk.walkStatus.is_good())
  {
    finish_walk(walk,
      VoidResult{Status::BadNoMatch,
        ErrorDetail::build("NoMatchingTarget",
          "Relative path produced no targets and no remote uncertainties",
          "TranslateBrowsePathsService")
          .context(ua::ContextKeys::nodeId, ua::to_string(walk.browsePath.starting_node()))});
    return;
  }

  // The path answers the code the walk reached and the codes its pages were answered with, combined, so a
  // Good subcode or an Uncertain code a namespace gave a page reaches the client with the targets. A code
  // with a SubCode that is not answered is logged.
  const StatusCode status =
    walk.pageStatus == walk.walkStatus
      ? walk.walkStatus
      : server::detail::combined_item_status(walk.pageStatus,
          walk.walkStatus,
          mLogger,
          "TranslateBrowsePathsService: the code of the pages a path walked was not answered",
          walk.browsePath.starting_node());
  finish_walk(walk, VoidResult{status});
}

// =============================================================================================
// Giving the strand back
// =============================================================================================

ua::async::Task<> TranslateBrowsePathsService::yield_strand()
{
  // A post, not a dispatch: `ua::async::post_borrowing` queues unconditionally, so the strand turn
  // this is called from ends here and whatever else that strand owes - this request's timeout timer
  // above all - gets its turn before the body resumes.
  co_await await_step<std::monostate>(
    [this](auto completion)
    {
      ua::async::post_borrowing(this,
        mStrand,
        mLogger,
        [completion = std::move(completion)](TranslateBrowsePathsService&) mutable
        { completion(std::monostate{}); })();
    });
}

// =============================================================================================
// Answering the request
// =============================================================================================

void TranslateBrowsePathsService::complete_translate()
{
  if (!try_finish())
  {
    return;
  }
  if (!mTranslateResponse)
  {
    return;
  }

  const size_t noOfOperations = mTranslateResponse->results().size();
  mTranslateCollector.apply_to(
    mTranslateResponse->response_header(), mTranslateResponse->diagnostic_infos(), noOfOperations);
  stack_utils::prepare_response_header(mRequest.request_header(), mTranslateResponse->response_header());

  auto serviceResponse = std::move(mTranslateResponse);
  if (mServiceCallCompleteCallback)
  {
    mServiceCallCompleteCallback(
      std::make_pair(mRequestId, std::static_pointer_cast<ua::Structure>(serviceResponse)));
  }
}

void TranslateBrowsePathsService::fail_translate(VoidResult error)
{
  // WITHDRAWN first, and then answered. Every path still suspended unwinds at its next await rather
  // than computing results into a response that is about to be released.
  // Withdrawal is asked at every await, so a body that is no longer wanted stops at its next
  // suspension rather than at a check someone remembered to write.
  if (mCancelled)
  {
    mCancelled->store(true);
  }

  mTranslateCollector.set_service_detail(error.status_code());
  send_service_fault(mRequest.request_header(), error.status_code(), mTranslateCollector);
  mTranslateResponse.reset();
}

void TranslateBrowsePathsService::abort(StatusCode reason)
{
  mCancelled->store(true);
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [reason = std::move(reason)](TranslateBrowsePathsService& self)
    {
      DiagnosticCollector collector{0};
      self.send_service_fault(self.mRequest.request_header(), reason, collector);
      // The walk stops on the token: it throws ua::async::Abandoned at its next resumption and
      // unwinds. Nothing here needs to reach into its state - there is none left outside the request's
      // own frame - and try_finish has already taken the right to answer, so a body that got a turn
      // before this one changes nothing.
      self.mTranslateResponse.reset();
    })();
}

void TranslateBrowsePathsService::timeout()
{
  mCancelled->store(true);

  DiagnosticCollector collector{0};
  send_service_fault(mRequest.request_header(), Status::BadTimeout, collector);
  mTranslateResponse.reset();
}

void TranslateBrowsePathsService::set_timeout()
{
  ServiceBase::set_timeout(mRequest.request_header().timeout_hint());
}

void TranslateBrowsePathsService::send_service_fault(
  const RequestHeader& requestHeader, StatusCode status, const DiagnosticCollector& collector)
{
  if (!try_finish())
    return;

  auto serviceFault = stack_utils::create_service_fault(&requestHeader, status);
  Array<DiagnosticInfo> unused;
  collector.apply_to(serviceFault->response_header(), unused, 0);
  if (mServiceCallCompleteCallback)
  {
    mServiceCallCompleteCallback(std::make_pair(mRequestId, serviceFault));
  }
}

}  // namespace ua::server
