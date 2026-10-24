// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_namespace_registration_coordinator.h"

#include "ua_self_owning_operation.h"

#include "ua_address_space_impl.h"
#include "ua_callback_safety.h"
#include "ua_default_namespace.h"
#include "ua_error_detail.h"
#include "ua_namespace_array.h"
#include "ua_namespace_context_state.h"
#include "ua_namespace_monitoring_support_access.h"
#include "ua_on_strand.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

#include <algorithm>
#include <cassert>
#include <deque>
#include <limits>
#include <optional>
#include <utility>
#include <unordered_map>
#include <vector>

namespace ua::detail
{

namespace
{

Result<uint16_t> coordinator_gone_add_result()
{
  return Result<uint16_t>{Status::BadShutdown,
    ErrorDetail::build("NamespaceRegistrationOwnerGone",
      "The address space was destroyed before namespace registration could run",
      "NamespaceRegistrationCoordinator")};
}

VoidResult coordinator_gone_void_result()
{
  return VoidResult{Status::BadShutdown,
    ErrorDetail::build("NamespaceRegistrationOwnerGone",
      "The address space was destroyed before namespace lifecycle work could run",
      "NamespaceRegistrationCoordinator")};
}

VoidResult shutdown_state_failure()
{
  return VoidResult{Status::BadShutdown,
    ErrorDetail::build("NamespaceRegistrationShuttingDown",
      "The address space no longer accepts namespace lifecycle work",
      "NamespaceRegistrationCoordinator")};
}

Result<uint16_t> shutdown_add_failure()
{
  const auto failure = shutdown_state_failure();
  return Result<uint16_t>{failure.status_code(), failure.shared_detail()};
}

/// Rolls back every prepared namespace registration, newest first.
///
/// Runs on the coordinator's OWN strand, passed in: this operation has a Logger but no executor of
/// its own, and both callers have a live strand in hand where they start it.
/// @see ua::async::SelfOwningOperation
class NamespacePreparationRollbackOperation final
  : public ua::async::SelfOwningOperation<NamespacePreparationRollbackOperation>
{
public:
  NamespacePreparationRollbackOperation(boost::asio::strand<boost::asio::any_io_executor> strand,
    Logger logger, std::vector<shared_ptr<NamespaceRegistrationPreparation>> preparations,
    std::function<void()> completion)
    : ua::async::SelfOwningOperation<NamespacePreparationRollbackOperation>(
        std::move(strand), std::move(logger)),
      mPreparations(std::move(preparations)), mCompletion(std::move(completion))
  {}

  static void start(boost::asio::strand<boost::asio::any_io_executor> strand, Logger logger,
    std::vector<shared_ptr<NamespaceRegistrationPreparation>> preparations, std::function<void()> completion)
  {
    launch(std::make_shared<NamespacePreparationRollbackOperation>(
      std::move(strand), std::move(logger), std::move(preparations), std::move(completion)));
  }

private:
  friend class ua::async::SelfOwningOperation<NamespacePreparationRollbackOperation>;

  ua::async::Task<> run()
  {
    try
    {
      // NEWEST FIRST, and each preparation is released as soon as it has answered - which is what
      // the index-walking-backwards chain did, one `preparation.reset()` at a time.
      while (!mPreparations.empty())
      {
        auto preparation = std::move(mPreparations.back());
        mPreparations.pop_back();

        auto result = co_await await_step<VoidResult>(
          [&preparation](auto completion) { preparation->rollback_async(std::move(completion)); });

        preparation.reset();

        // A rollback that fails is logged and the rest still run: leaving the remaining
        // preparations un-rolled-back because an earlier one failed would strand more state, not
        // less.
        if (result.is_bad())
        {
          mLogger.error({{"status", to_string(result.status_code())}},
            "Failed to roll back namespace registration preparation");
        }
      }
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      ua::async::guarded(mLogger, [] {})();
    }

    complete();
  }

  /// Answers when the body's frame could not be allocated. The completion MUST fire on every path:
  /// it is the coordinator's resume, and a coordinator that is never resumed never answers its
  /// caller and refuses every later registration.
  void fail_to_start(StatusCode)
  {
    complete();
  }

  void complete()
  {
    mPreparations.clear();
    if (auto completion = std::move(mCompletion))
    {
      completion();
    }
  }

  std::vector<shared_ptr<NamespaceRegistrationPreparation>> mPreparations;
  std::function<void()> mCompletion;
};

}  // namespace

class NamespaceRegistrationCoordinator::State final
{
public:
  using PreparedAppend = UriArray<shared_ptr<Namespace>, uint16_t>::PreparedAppend;

  enum class Lifecycle
  {
    Accepting,
    ShuttingDown,
    Stopped,
  };

  enum class RequestKind
  {
    Add,
    PrepareImportedMetadata,
    PrepareExisting,
    Shutdown,
  };

  struct ParticipantEntry
  {
    shared_ptr<NamespaceRegistrationParticipant> participant;
    std::vector<bool> preparedNamespaces;
  };

  struct PreparationTask
  {
    std::size_t participantIndex{0};
    uint16_t namespaceIndex{0};
  };

  struct Request
  {
    RequestKind kind{RequestKind::Add};
    uint64_t operationId{0};
    shared_ptr<Namespace> namespaceObject;
    AddNamespaceCallback addCallback;
    std::function<void(VoidResult)> voidCallback;
    std::optional<PreparedAppend> preparedAppend;
    std::optional<std::vector<std::optional<NodeId>>> preparedMetadataObjects;
    shared_ptr<const NamespaceRegistrationRoute> route;
    NamespaceRegistrationInitializer initializer;
    String namespaceUri;
    uint16_t namespaceIndex{0};
    std::optional<NodeId> metadataObject;
    NamespaceMetadataOptions metadataOptions;
    std::vector<PreparationTask> tasks;
    std::size_t taskOffset{0};
    std::vector<shared_ptr<NamespaceRegistrationPreparation>> preparations;
    std::size_t shutdownOutstanding{0};
    std::vector<bool> shutdownAnswered;
    // Shutdown: the namespace array when shutdown began, by index.
    Array<String> shutdownUris;
    // Shutdown: the namespaces it shuts down, by index, copied from the array when it began. The shutdown
    // asks these, never the array, which the address space's destructor may be destroying by then.
    std::vector<shared_ptr<Namespace>> shutdownNamespaces;
    // Registration: the context state given to the namespace, retained once the registration commits.
    shared_ptr<const NamespaceContextState> contextState;
    // Shutdown: per namespace index, the helpers of its registration not yet stopped; the namespace is
    // shut down when its count reaches 0.
    std::vector<std::size_t> helpersOutstanding;
    VoidResult firstShutdownFailure;
    bool rollbackInProgress{false};
  };

  Lifecycle lifecycle{Lifecycle::Accepting};
  uint64_t nextOperationId{1};
  std::size_t maximumNamespaces{static_cast<std::size_t>(std::numeric_limits<uint16_t>::max()) + 1U};
  std::vector<ParticipantEntry> participants;
  std::vector<std::optional<NodeId>> metadataObjects;
  // Publication intent of namespaces already committed, for participants installed afterwards. Only
  // written once an index is permanent, so a rolled-back registration leaves nothing behind.
  std::unordered_map<uint16_t, NamespaceMetadataOptions> metadataOptionsByIndex;
  std::deque<Request> queue;
  std::unique_ptr<Request> current;
  // The context state of every committed registration, NS0 and NS1 included, so that shutdown reaches each
  // registration's monitoring helper. The helper lives here and in the namespace's context, nowhere else.
  std::vector<shared_ptr<const NamespaceContextState>> contextStates;
};

shared_ptr<NamespaceRegistrationCoordinator> NamespaceRegistrationCoordinator::create(
  weak_ptr<AddressSpaceImpl> addressSpace, boost::asio::any_io_executor executor)
{
  return shared_ptr<NamespaceRegistrationCoordinator>{
    new NamespaceRegistrationCoordinator{std::move(addressSpace), std::move(executor)}};
}

NamespaceRegistrationCoordinator::NamespaceRegistrationCoordinator(
  weak_ptr<AddressSpaceImpl> addressSpace, boost::asio::any_io_executor executor)
  : mAddressSpace(std::move(addressSpace)), mExecutor(executor),
    mStrand(boost::asio::make_strand(std::move(executor))), mState(std::make_unique<State>())
{}

AddressSpace NamespaceRegistrationCoordinator::handle(shared_ptr<AddressSpaceImpl> addressSpace)
{
  return AddressSpace{std::move(addressSpace)};
}

shared_ptr<const NamespaceContextState> NamespaceRegistrationCoordinator::create_context_state(
  uint16_t namespaceIndex, const shared_ptr<Namespace>& nameSpace) const
{
  // The address space's MaxNodesPerRead as it stands at each tick: namespaces 0 and 1 are registered
  // before the server sets its operation limits (DL-69 (D6)).
  auto maxNodesPerRead = [addressSpace = mAddressSpace]() -> std::optional<uint32_t>
  {
    const auto space = addressSpace.lock();
    if (!space || !space->mOperationLimits)
    {
      return std::nullopt;
    }
    return space->mOperationLimits->maxNodesPerRead;
  };
  return std::make_shared<const NamespaceContextState>(namespaceIndex,
    MonitoringSupportAccess::create(mExecutor,
      mLogger.with_category("monitoring"),
      weak_ptr<Namespace>{nameSpace},
      std::move(maxNodesPerRead)),
    mAddressSpace);
}

void NamespaceRegistrationCoordinator::shut_uncommitted_helper(
  const shared_ptr<const NamespaceContextState>& state) noexcept
{
  if (state)
  {
    // A failed registration's context reports into nothing (NR-39 rule 4).
    state->closed.store(true, std::memory_order_release);
  }
  if (state && state->monitoring)
  {
    // Its index is given to the next registration, so nothing of this one may keep sampling.
    MonitoringSupportAccess::shutdown_async(*state->monitoring, {});
  }
}

NamespaceRegistrationCoordinator::~NamespaceRegistrationCoordinator()
{
  mState->lifecycle = State::Lifecycle::Stopped;
  const auto complete = [this](State::Request request)
  {
    auto addCallback = std::move(request.addCallback);
    auto voidCallback = std::move(request.voidCallback);
    request.preparations.clear();
    request.preparedAppend.reset();
    request.route.reset();
    request.namespaceObject.reset();
    if (addCallback)
    {
      ua::detail::invoke_user_callback(mLogger, addCallback, coordinator_gone_add_result());
      return;
    }
    if (voidCallback)
    {
      ua::detail::invoke_user_callback(mLogger, voidCallback, coordinator_gone_void_result());
    }
  };

  if (mState->current)
  {
    auto request = std::move(*mState->current);
    mState->current.reset();
    complete(std::move(request));
  }
  while (!mState->queue.empty())
  {
    auto request = std::move(mState->queue.front());
    mState->queue.pop_front();
    complete(std::move(request));
  }
}

void NamespaceRegistrationCoordinator::set_maximum_namespaces_for_tests(std::size_t maximumNamespaces)
{
  mState->maximumNamespaces = maximumNamespaces;
}

void NamespaceRegistrationCoordinator::set_logger(Logger logger)
{
  mLogger = std::move(logger);
}

uint16_t NamespaceRegistrationCoordinator::bootstrap_namespace(shared_ptr<Namespace> nameSpace)
{
  if (!nameSpace)
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("NamespaceMissing",
        "A namespace registration requires a non-null Namespace",
        "NamespaceRegistrationCoordinator")};
  }

  auto owner = mAddressSpace.lock();
  if (!owner)
  {
    throw UaException{Status::BadShutdown,
      ErrorDetail::build("NamespaceRegistrationOwnerGone",
        "The address space was destroyed during construction-only namespace registration",
        "NamespaceRegistrationCoordinator")};
  }
  auto prepared = owner->mNamespaceArray.mUriArray.prepare_append(nameSpace);
  const auto namespaceIndex = prepared.index();
  // Attached before it is configured, so that an object attached already is refused before anything of it
  // changes.
  auto contextState = create_context_state(namespaceIndex, nameSpace);
  if (auto attached = nameSpace->attach(NamespaceContext{contextState}); attached.is_bad())
  {
    shut_uncommitted_helper(contextState);
    throw UaException{attached.status_code()};
  }
  if (!owner->mNamespaceArray.mUriArray.commit_prepared_append(std::move(prepared)))
  {
    throw UaException{Status::BadInternalError,
      ErrorDetail::build("NamespaceBootstrapCommitConflict",
        "The construction-only namespace append lost its registry version",
        "NamespaceRegistrationCoordinator")};
  }
  mState->metadataObjects.push_back(nameSpace->metadata_object());
  mState->contextStates.push_back(std::move(contextState));
  return namespaceIndex;
}

void NamespaceRegistrationCoordinator::install_participant(
  shared_ptr<NamespaceRegistrationParticipant> participant)
{
  if (!participant)
  {
    throw UaException{Status::BadInvalidArgument,
      ErrorDetail::build("NamespaceParticipantMissing",
        "Cannot install a null namespace lifecycle participant",
        "NamespaceRegistrationCoordinator")};
  }
  if (mState->current || !mState->queue.empty() || mState->lifecycle != State::Lifecycle::Accepting)
  {
    throw UaException{Status::BadInvalidState,
      ErrorDetail::build("NamespaceParticipantInstallTooLate",
        "Namespace lifecycle participants must be installed before live work begins",
        "NamespaceRegistrationCoordinator")};
  }
  mState->participants.push_back(State::ParticipantEntry{std::move(participant), {}});
}

void NamespaceRegistrationCoordinator::add_namespace_async(
  shared_ptr<Namespace> nameSpace, NamespaceMetadataOptions metadata, AddNamespaceCallback callback) noexcept
{
  // A caller that passes no callback still has the work done; a failure is logged instead.
  callback = ua::detail::completion_or_log(std::move(callback), mLogger, "add_namespace_async");
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    coordinator_gone_add_result(),
    [nameSpace = std::move(nameSpace), metadata = std::move(metadata)](
      NamespaceRegistrationCoordinator& self, AddNamespaceCallback completion) mutable
    { self.enqueue_add(std::move(nameSpace), std::move(metadata), {}, std::move(completion)); })();
}

void NamespaceRegistrationCoordinator::add_imported_namespace_async(shared_ptr<Namespace> nameSpace,
  NamespaceRegistrationInitializer initializer, AddNamespaceCallback callback) noexcept
{
  // A caller that passes no callback still has the work done; a failure is logged instead.
  callback = ua::detail::completion_or_log(std::move(callback), mLogger, "add_imported_namespace_async");
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    coordinator_gone_add_result(),
    [nameSpace = std::move(nameSpace), initializer = std::move(initializer)](
      NamespaceRegistrationCoordinator& self, AddNamespaceCallback completion) mutable
    {
      self.enqueue_add(
        std::move(nameSpace), NamespaceMetadataOptions{}, std::move(initializer), std::move(completion));
    })();
}

void NamespaceRegistrationCoordinator::prepare_imported_metadata_async(uint16_t namespaceIndex,
  NodeId metadataObject, NamespaceRegistrationInitializer initializer,
  std::function<void(VoidResult)> callback) noexcept
{
  // A caller that passes no callback still has the work done; a failure is logged instead.
  callback = ua::detail::completion_or_log(std::move(callback), mLogger, "prepare_imported_metadata_async");
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    coordinator_gone_void_result(),
    [namespaceIndex, metadataObject = std::move(metadataObject), initializer = std::move(initializer)](
      NamespaceRegistrationCoordinator& self, std::function<void(VoidResult)> completion) mutable
    {
      self.enqueue_imported_metadata(
        namespaceIndex, std::move(metadataObject), std::move(initializer), std::move(completion));
    })();
}

void NamespaceRegistrationCoordinator::prepare_installed_namespaces_async(
  std::function<void(VoidResult)> callback) noexcept
{
  // A caller that passes no callback still has the work done; a failure is logged instead.
  callback =
    ua::detail::completion_or_log(std::move(callback), mLogger, "prepare_installed_namespaces_async");
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    coordinator_gone_void_result(),
    [](NamespaceRegistrationCoordinator& self, std::function<void(VoidResult)> completion)
    { self.enqueue_prepare_existing(std::move(completion)); })();
}

void NamespaceRegistrationCoordinator::shutdown_async(std::function<void(VoidResult)> callback) noexcept
{
  if (!callback)
  {
    // A caller that supplies no callback has no use for the result by construction - there is nowhere
    // to deliver it - so this substitute discards nothing a caller asked for. It keeps the post
    // machinery below total rather than swallowing a failure: every caller that DOES supply a callback
    // receives the real VoidResult, detail chain included.
    callback = [](VoidResult) {
    };
  }
  ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    std::move(callback),
    VoidResult{},
    [](NamespaceRegistrationCoordinator& self, std::function<void(VoidResult)> completion)
    { self.enqueue_shutdown(std::move(completion)); })();
}

void NamespaceRegistrationCoordinator::enqueue_add(shared_ptr<Namespace> nameSpace,
  NamespaceMetadataOptions metadata, NamespaceRegistrationInitializer initializer,
  AddNamespaceCallback callback)
{
  State::Request request;
  request.kind = State::RequestKind::Add;
  request.operationId = mState->nextOperationId++;
  request.namespaceObject = std::move(nameSpace);
  request.metadataOptions = std::move(metadata);
  request.initializer = std::move(initializer);
  request.addCallback = std::move(callback);
  mState->queue.push_back(std::move(request));
  start_next();
}

void NamespaceRegistrationCoordinator::enqueue_imported_metadata(uint16_t namespaceIndex,
  NodeId metadataObject, NamespaceRegistrationInitializer initializer,
  std::function<void(VoidResult)> callback)
{
  State::Request request;
  request.kind = State::RequestKind::PrepareImportedMetadata;
  request.operationId = mState->nextOperationId++;
  request.namespaceIndex = namespaceIndex;
  request.metadataObject = std::move(metadataObject);
  request.initializer = std::move(initializer);
  request.voidCallback = std::move(callback);
  mState->queue.push_back(std::move(request));
  start_next();
}

void NamespaceRegistrationCoordinator::enqueue_prepare_existing(std::function<void(VoidResult)> callback)
{
  State::Request request;
  request.kind = State::RequestKind::PrepareExisting;
  request.operationId = mState->nextOperationId++;
  request.voidCallback = std::move(callback);
  mState->queue.push_back(std::move(request));
  start_next();
}

void NamespaceRegistrationCoordinator::enqueue_shutdown(std::function<void(VoidResult)> callback)
{
  State::Request request;
  request.kind = State::RequestKind::Shutdown;
  request.operationId = mState->nextOperationId++;
  request.voidCallback = std::move(callback);
  mState->queue.push_back(std::move(request));
  start_next();
}

void NamespaceRegistrationCoordinator::start_next()
{
  if (mState->current || mState->queue.empty())
  {
    return;
  }
  mState->current = std::make_unique<State::Request>(std::move(mState->queue.front()));
  mState->queue.pop_front();

  switch (mState->current->kind)
  {
  case State::RequestKind::Add:
    start_add();
    break;
  case State::RequestKind::PrepareImportedMetadata:
    start_imported_metadata();
    break;
  case State::RequestKind::PrepareExisting:
    start_prepare_existing();
    break;
  case State::RequestKind::Shutdown:
    start_shutdown();
    break;
  }
}

void NamespaceRegistrationCoordinator::start_add()
{
  // An operation that starts with its owner gone answers as the destructor does.
  auto owner = mAddressSpace.lock();
  if (!owner)
  {
    finish_add(coordinator_gone_add_result());
    return;
  }
  if (mState->lifecycle != State::Lifecycle::Accepting)
  {
    finish_add(shutdown_add_failure());
    return;
  }

  try
  {
    auto& request = *mState->current;
    if (!request.namespaceObject)
    {
      finish_add(Result<uint16_t>{Status::BadInvalidArgument,
        ErrorDetail::build("NamespaceMissing",
          "A namespace registration requires a non-null Namespace",
          "NamespaceRegistrationCoordinator")});
      return;
    }

    request.namespaceUri = request.namespaceObject->uri();
    if (static_cast<string_view>(request.namespaceUri).empty())
    {
      finish_add(Result<uint16_t>{Status::BadInvalidArgument,
        ErrorDetail::build("NamespaceUriEmpty",
          "A namespace registration requires a non-empty URI",
          "NamespaceRegistrationCoordinator")});
      return;
    }

    const auto committedCount = owner->mNamespaceArray.get_namespace_array().size();
    if (committedCount >= mState->maximumNamespaces)
    {
      finish_add(Result<uint16_t>{Status::BadInvalidState,
        ErrorDetail::build("NamespaceTableFull",
          "The namespace table has no remaining index",
          "NamespaceRegistrationCoordinator")
          .context(ContextKeys::sizeMax, std::to_string(mState->maximumNamespaces))});
      return;
    }

    request.preparedAppend.emplace(owner->mNamespaceArray.mUriArray.prepare_append(request.namespaceObject));
    request.namespaceIndex = request.preparedAppend->index();
    // Attached before it is configured, so that an object attached already is refused before anything of it
    // changes. The object keeps its context if the registration then fails, and cannot be registered again.
    auto contextState = create_context_state(request.namespaceIndex, request.namespaceObject);
    if (auto attached = request.namespaceObject->attach(NamespaceContext{contextState}); attached.is_bad())
    {
      shut_uncommitted_helper(contextState);
      finish_add(Result<uint16_t>{attached.status_code()});
      return;
    }
    request.contextState = std::move(contextState);
    request.metadataObject = request.namespaceObject->metadata_object();
    request.route = std::make_shared<const NamespaceRegistrationRoute>(
      NamespaceRegistrationRoute{request.namespaceIndex, request.namespaceObject});
    request.tasks.reserve(mState->participants.size());
    for (std::size_t participantIndex = 0; participantIndex < mState->participants.size(); ++participantIndex)
    {
      auto& prepared = mState->participants[participantIndex].preparedNamespaces;
      if (prepared.size() <= request.namespaceIndex)
      {
        prepared.resize(static_cast<std::size_t>(request.namespaceIndex) + 1U, false);
      }
      request.tasks.push_back({participantIndex, request.namespaceIndex});
    }
    request.preparations.reserve(request.tasks.size());
    if (request.initializer)
    {
      start_initializer();
      return;
    }
    prepare_metadata_state_and_participants();
  }
  catch (...)
  {
    finish_add(Result<uint16_t>{ua::exception_to_status_code(std::current_exception())});
  }
}

void NamespaceRegistrationCoordinator::start_imported_metadata()
{
  auto owner = mAddressSpace.lock();
  if (!owner)
  {
    finish_void(coordinator_gone_void_result());
    return;
  }
  if (mState->lifecycle != State::Lifecycle::Accepting)
  {
    finish_void(shutdown_state_failure());
    return;
  }

  try
  {
    auto& request = *mState->current;
    if (!request.initializer || !request.metadataObject)
    {
      finish_void(VoidResult{Status::BadInvalidArgument,
        ErrorDetail::build("NamespaceMetadataInitializerMissing",
          "Imported namespace metadata preparation requires a declaration and initializer",
          "NamespaceRegistrationCoordinator")
          .context(ContextKeys::namespaceIndex, request.namespaceIndex)});
      return;
    }
    if (request.namespaceIndex >= mState->metadataObjects.size())
    {
      finish_void(VoidResult{Status::BadOutOfRange,
        ErrorDetail::build("NamespaceMetadataNamespaceMissing",
          "Imported metadata names an unregistered namespace index",
          "NamespaceRegistrationCoordinator")
          .context(ContextKeys::namespaceIndex, request.namespaceIndex)});
      return;
    }

    const auto& existingDeclaration = mState->metadataObjects[request.namespaceIndex];
    if (existingDeclaration && *existingDeclaration != *request.metadataObject)
    {
      finish_void(VoidResult{Status::BadConfigurationError,
        ErrorDetail::build("NamespaceMetadataDeclarationConflict",
          "A NodeSet declares different metadata for a namespace that already names an Object",
          "NamespaceRegistrationCoordinator")
          .context(ContextKeys::namespaceIndex, request.namespaceIndex)
          .context(ContextKeys::expected, to_string(*existingDeclaration))
          .context(ContextKeys::actual, to_string(*request.metadataObject))});
      return;
    }

    const bool alreadyPrepared = std::any_of(mState->participants.begin(),
      mState->participants.end(),
      [namespaceIndex = request.namespaceIndex](const State::ParticipantEntry& participant)
      {
        return namespaceIndex < participant.preparedNamespaces.size() &&
               participant.preparedNamespaces[namespaceIndex];
      });
    if (alreadyPrepared)
    {
      if (existingDeclaration == request.metadataObject)
      {
        finish_void(VoidResult{});
        return;
      }
      finish_void(VoidResult{Status::BadInvalidState,
        ErrorDetail::build("NamespaceMetadataAlreadyPublished",
          "A live namespace's published metadata Object cannot be replaced by a NodeSet import",
          "NamespaceRegistrationCoordinator")
          .context(ContextKeys::namespaceIndex, request.namespaceIndex)
          .context(ContextKeys::nodeId, to_string(*request.metadataObject))});
      return;
    }

    request.namespaceObject = owner->mNamespaceArray.get_namespace(request.namespaceIndex);
    if (!request.namespaceObject)
    {
      finish_void(VoidResult{Status::BadInvalidState,
        ErrorDetail::build("RegisteredNamespaceMissing",
          "A committed namespace has no Namespace implementation",
          "NamespaceRegistrationCoordinator")
          .context(ContextKeys::namespaceIndex, request.namespaceIndex)});
      return;
    }
    request.namespaceUri = request.namespaceObject->uri();
    start_initializer();
  }
  catch (...)
  {
    finish_void(VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void NamespaceRegistrationCoordinator::start_initializer()
{
  auto& request = *mState->current;
  auto owner = mAddressSpace.lock();
  if (!owner)
  {
    if (request.kind == State::RequestKind::Add)
    {
      finish_add(coordinator_gone_add_result());
    }
    else
    {
      finish_void(coordinator_gone_void_result());
    }
    return;
  }

  AddressSpace stagedAddressSpace{std::move(owner), request.route};
  NamespaceRegistrationCandidate candidate{request.namespaceIndex,
    request.namespaceUri,
    request.namespaceObject,
    request.metadataObject,
    std::move(stagedAddressSpace),
    request.metadataOptions};
  const auto operationId = request.operationId;
  auto completion = ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [operationId](
      NamespaceRegistrationCoordinator& self, NamespaceRegistrationInitializationResult result) mutable
    { self.on_initialized(operationId, std::move(result)); });
  request.initializer(std::move(candidate), std::move(completion));
}

void NamespaceRegistrationCoordinator::on_initialized(
  uint64_t operationId, NamespaceRegistrationInitializationResult result)
{
  if (!mState->current || mState->current->operationId != operationId || mState->current->rollbackInProgress)
  {
    return;
  }

  auto& request = *mState->current;
  if (!result.is_good())
  {
    if (request.kind == State::RequestKind::Add)
    {
      finish_add(Result<uint16_t>{result.status_code(), result.shared_detail()});
    }
    else
    {
      finish_void(VoidResult{result.status_code(), result.shared_detail()});
    }
    return;
  }

  auto initialized = std::move(result).value();
  if (initialized.preparation)
  {
    request.preparations.push_back(std::move(initialized.preparation));
  }
  if (request.kind == State::RequestKind::PrepareImportedMetadata)
  {
    if (!initialized.metadataObject || initialized.metadataObject != request.metadataObject)
    {
      finish_void(VoidResult{Status::BadConfigurationError,
        ErrorDetail::build("NamespaceMetadataInitializerMismatch",
          "The NodeSet metadata initializer did not stage the declared Object",
          "NamespaceRegistrationCoordinator")
          .context(ContextKeys::namespaceIndex, request.namespaceIndex)
          .context(ContextKeys::expected, to_string(*request.metadataObject))});
      return;
    }
    try
    {
      auto preparedMetadata = mState->metadataObjects;
      preparedMetadata[request.namespaceIndex] = request.metadataObject;
      request.preparedMetadataObjects.emplace(std::move(preparedMetadata));
    }
    catch (...)
    {
      finish_void(VoidResult{ua::exception_to_status_code(std::current_exception())});
      return;
    }
    for (auto& preparation : request.preparations)
    {
      preparation->commit();
    }
    mState->metadataObjects.swap(*request.preparedMetadataObjects);
    finish_void(VoidResult{});
    return;
  }

  if (initialized.metadataObject)
  {
    if (request.metadataObject && request.metadataObject != initialized.metadataObject)
    {
      finish_add(Result<uint16_t>{Status::BadConfigurationError,
        ErrorDetail::build("NamespaceMetadataDeclarationConflict",
          "The Namespace and imported NodeSet name different metadata Objects",
          "NamespaceRegistrationCoordinator")
          .context(ContextKeys::namespaceIndex, request.namespaceIndex)
          .context(ContextKeys::expected, to_string(*request.metadataObject))
          .context(ContextKeys::actual, to_string(*initialized.metadataObject))});
      return;
    }
    request.metadataObject = std::move(initialized.metadataObject);
  }
  prepare_metadata_state_and_participants();
}

void NamespaceRegistrationCoordinator::prepare_metadata_state_and_participants()
{
  try
  {
    auto& request = *mState->current;
    auto preparedMetadata = mState->metadataObjects;
    preparedMetadata.push_back(request.metadataObject);
    request.preparedMetadataObjects.emplace(std::move(preparedMetadata));
    prepare_next_participant();
  }
  catch (...)
  {
    finish_add(Result<uint16_t>{ua::exception_to_status_code(std::current_exception())});
  }
}

void NamespaceRegistrationCoordinator::start_prepare_existing()
{
  auto owner = mAddressSpace.lock();
  if (!owner)
  {
    finish_void(coordinator_gone_void_result());
    return;
  }
  if (mState->lifecycle != State::Lifecycle::Accepting)
  {
    finish_void(shutdown_state_failure());
    return;
  }

  try
  {
    auto& request = *mState->current;
    const auto namespaceUris = owner->mNamespaceArray.get_namespace_array();
    for (auto& participant : mState->participants)
    {
      if (participant.preparedNamespaces.size() < namespaceUris.size())
      {
        participant.preparedNamespaces.resize(namespaceUris.size(), false);
      }
    }
    for (std::size_t namespaceOffset = 0; namespaceOffset < namespaceUris.size(); ++namespaceOffset)
    {
      const auto namespaceIndex = numeric_cast<uint16_t>(namespaceOffset);
      for (std::size_t participantIndex = 0; participantIndex < mState->participants.size();
           ++participantIndex)
      {
        if (!mState->participants[participantIndex].preparedNamespaces[namespaceIndex])
        {
          request.tasks.push_back({participantIndex, namespaceIndex});
        }
      }
    }
    request.preparations.reserve(request.tasks.size());
    prepare_next_participant();
  }
  catch (...)
  {
    finish_void(VoidResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void NamespaceRegistrationCoordinator::prepare_next_participant()
{
  auto& request = *mState->current;
  if (request.taskOffset == request.tasks.size())
  {
    if (request.kind == State::RequestKind::Add)
    {
      bool committed = false;
      {
        // Locked before anything commits, so that an owner gone by now rolls the preparations back, and
        // released before the caller is answered.
        const auto owner = mAddressSpace.lock();
        if (!owner)
        {
          finish_add(coordinator_gone_add_result());
          return;
        }
        for (auto& preparation : request.preparations)
        {
          preparation->commit();
        }
        committed =
          owner->mNamespaceArray.mUriArray.commit_prepared_append(std::move(*request.preparedAppend));
      }
      assert(committed && "serialized namespace registry changed between prepare and commit");
      if (!committed)
      {
        finish_add(Result<uint16_t>{Status::BadInternalError,
          ErrorDetail::build("NamespaceCommitConflict",
            "The serialized namespace registry changed between preparation and commit",
            "NamespaceRegistrationCoordinator")});
        return;
      }
      mState->metadataObjects.swap(*request.preparedMetadataObjects);
      mState->metadataOptionsByIndex[request.namespaceIndex] = request.metadataOptions;
      mState->contextStates.push_back(std::move(request.contextState));
      for (const auto& task : request.tasks)
      {
        mState->participants[task.participantIndex].preparedNamespaces[task.namespaceIndex] = true;
      }
      finish_add(Result<uint16_t>{request.namespaceIndex});
      return;
    }

    for (auto& preparation : request.preparations)
    {
      preparation->commit();
    }
    for (const auto& task : request.tasks)
    {
      mState->participants[task.participantIndex].preparedNamespaces[task.namespaceIndex] = true;
    }
    finish_void(VoidResult{});
    return;
  }

  const auto task = request.tasks[request.taskOffset];
  auto owner = mAddressSpace.lock();
  if (!owner)
  {
    if (request.kind == State::RequestKind::Add)
    {
      finish_add(coordinator_gone_add_result());
    }
    else
    {
      finish_void(coordinator_gone_void_result());
    }
    return;
  }

  auto nameSpace = request.kind == State::RequestKind::Add
                     ? request.namespaceObject
                     : owner->mNamespaceArray.get_namespace(task.namespaceIndex);
  if (!nameSpace)
  {
    const auto failure = VoidResult{Status::BadInvalidState,
      ErrorDetail::build("RegisteredNamespaceMissing",
        "A committed namespace has no Namespace implementation",
        "NamespaceRegistrationCoordinator")
        .context(ContextKeys::namespaceIndex, task.namespaceIndex)};
    if (request.kind == State::RequestKind::Add)
    {
      finish_add(Result<uint16_t>{failure.status_code(), failure.shared_detail()});
    }
    else
    {
      finish_void(failure);
    }
    return;
  }

  AddressSpace stagedAddressSpace{
    std::move(owner), request.kind == State::RequestKind::Add ? request.route : nullptr};
  const auto metadataObject = request.kind == State::RequestKind::Add
                                ? request.metadataObject
                                : mState->metadataObjects[task.namespaceIndex];
  const auto metadataOptions = [&]() -> NamespaceMetadataOptions
  {
    if (request.kind == State::RequestKind::Add)
    {
      return request.metadataOptions;
    }
    const auto stored = mState->metadataOptionsByIndex.find(task.namespaceIndex);
    return stored == mState->metadataOptionsByIndex.end() ? NamespaceMetadataOptions{} : stored->second;
  }();
  NamespaceRegistrationCandidate candidate{task.namespaceIndex,
    nameSpace->uri(),
    std::move(nameSpace),
    metadataObject,
    std::move(stagedAddressSpace),
    metadataOptions};
  const auto operationId = request.operationId;
  auto completion = ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [operationId, task](
      NamespaceRegistrationCoordinator& self, NamespaceRegistrationPreparationResult result) mutable
    {
      self.on_participant_prepared(
        operationId, task.participantIndex, task.namespaceIndex, std::move(result));
    });
  mState->participants[task.participantIndex].participant->prepare_async(
    std::move(candidate), std::move(completion));
}

void NamespaceRegistrationCoordinator::on_participant_prepared(uint64_t operationId,
  std::size_t participantIndex, uint16_t namespaceIndex, NamespaceRegistrationPreparationResult result)
{
  if (!mState->current || mState->current->operationId != operationId ||
      mState->current->rollbackInProgress || mState->current->taskOffset >= mState->current->tasks.size())
  {
    return;
  }
  const auto expected = mState->current->tasks[mState->current->taskOffset];
  if (expected.participantIndex != participantIndex || expected.namespaceIndex != namespaceIndex)
  {
    return;
  }

  if (!result.is_good())
  {
    if (mState->current->kind == State::RequestKind::Add)
    {
      finish_add(Result<uint16_t>{result.status_code(), result.shared_detail()});
    }
    else
    {
      finish_void(VoidResult{result.status_code(), result.shared_detail()});
    }
    return;
  }
  if (!result.value())
  {
    const auto failure = VoidResult{Status::BadInternalError,
      ErrorDetail::build("NamespacePreparationMissing",
        "A namespace lifecycle participant returned success without prepared state",
        "NamespaceRegistrationCoordinator")
        .context(ContextKeys::namespaceIndex, namespaceIndex)};
    if (mState->current->kind == State::RequestKind::Add)
    {
      finish_add(Result<uint16_t>{failure.status_code(), failure.shared_detail()});
    }
    else
    {
      finish_void(failure);
    }
    return;
  }

  mState->current->preparations.push_back(std::move(result).value());
  ++mState->current->taskOffset;
  prepare_next_participant();
}

void NamespaceRegistrationCoordinator::start_shutdown()
{
  auto& request = *mState->current;
  {
    // The shutdown copies what it reads of the array, the namespaces included, here and under the owner; no
    // later turn of it reads the array, which the owner's destructor may be destroying by then. A coordinator
    // destroyed before the shutdown completes answers it from its destructor and releases the copies.
    auto owner = mAddressSpace.lock();
    if (!owner)
    {
      finish_void(coordinator_gone_void_result());
      return;
    }
    if (mState->lifecycle == State::Lifecycle::Stopped)
    {
      finish_void(VoidResult{});
      return;
    }
    mState->lifecycle = State::Lifecycle::ShuttingDown;
    request.shutdownUris = owner->mNamespaceArray.get_namespace_array();
    request.shutdownNamespaces.reserve(request.shutdownUris.size());
    for (std::size_t namespaceOffset = 0; namespaceOffset < request.shutdownUris.size(); ++namespaceOffset)
    {
      request.shutdownNamespaces.push_back(
        owner->mNamespaceArray.get_namespace(numeric_cast<uint16_t>(namespaceOffset)));
    }
  }
  const auto namespaceCount = request.shutdownUris.size();
  request.shutdownOutstanding = namespaceCount;
  request.shutdownAnswered.assign(namespaceCount, false);
  request.helpersOutstanding.assign(namespaceCount, 0);
  if (namespaceCount == 0)
  {
    mState->lifecycle = State::Lifecycle::Stopped;
    finish_void(VoidResult{});
    return;
  }

  // Every context is closed first, so that a later report is refused at once; the model changes already
  // posted then run before any helper or namespace is stopped (NR-67 steps 1 and 2).
  for (const auto& state : mState->contextStates)
  {
    state->closed.store(true, std::memory_order_release);
  }
  const auto operationId = request.operationId;
  if (auto owner = mAddressSpace.lock())
  {
    owner->when_posted_steps_done(ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [operationId](NamespaceRegistrationCoordinator& self) { self.stop_helpers(operationId); }));
    return;
  }
  stop_helpers(operationId);
}

void NamespaceRegistrationCoordinator::stop_helpers(uint64_t operationId)
{
  if (!mState->current || mState->current->operationId != operationId ||
      mState->current->kind != State::RequestKind::Shutdown)
  {
    return;
  }
  auto& request = *mState->current;
  const auto namespaceCount = request.shutdownUris.size();

  // Each namespace is shut down once its own registration's helper has stopped (NR-47 rule 7): the helper
  // stops its timers and answers once its ticks in flight are done, so no tick reads a Node of a namespace
  // that has been shut down, and a helper waiting on a slow read holds back only its own namespace. A
  // helper answers on its own thread, never this strand, and this strand never waits on one. Every helper
  // is counted before any is asked, and each answer is posted, so no namespace is stopped early.
  const auto helpers = mState->contextStates;
  for (const auto& state : helpers)
  {
    if (state->index < namespaceCount)
    {
      ++request.helpersOutstanding[state->index];
    }
  }
  std::vector<std::size_t> withoutHelper;
  for (std::size_t namespaceOffset = 0; namespaceOffset < namespaceCount; ++namespaceOffset)
  {
    if (request.helpersOutstanding[namespaceOffset] == 0)
    {
      withoutHelper.push_back(namespaceOffset);
    }
  }

  for (const auto& state : helpers)
  {
    MonitoringSupportAccess::shutdown_async(*state->monitoring,
      ua::async::post_borrowing(this,
        mStrand,
        mLogger,
        [operationId, namespaceOffset = std::size_t{state->index}](NamespaceRegistrationCoordinator& self)
        { self.on_helper_stopped(operationId, namespaceOffset); }));
  }
  for (const auto namespaceOffset : withoutHelper)
  {
    stop_namespace(operationId, namespaceOffset);
  }
}

void NamespaceRegistrationCoordinator::on_helper_stopped(uint64_t operationId, std::size_t namespaceOffset)
{
  if (!mState->current || mState->current->operationId != operationId ||
      mState->current->kind != State::RequestKind::Shutdown ||
      namespaceOffset >= mState->current->helpersOutstanding.size() ||
      mState->current->helpersOutstanding[namespaceOffset] == 0)
  {
    return;
  }
  if (--mState->current->helpersOutstanding[namespaceOffset] != 0)
  {
    return;
  }
  stop_namespace(operationId, namespaceOffset);
}

void NamespaceRegistrationCoordinator::stop_namespace(uint64_t operationId, std::size_t namespaceOffset)
{
  if (!mState->current || mState->current->operationId != operationId ||
      namespaceOffset >= mState->current->shutdownUris.size())
  {
    return;
  }
  auto namespaceUri = mState->current->shutdownUris[namespaceOffset];
  auto nameSpace = mState->current->shutdownNamespaces[namespaceOffset];
  if (!nameSpace)
  {
    on_namespace_stopped(operationId,
      namespaceOffset,
      std::move(namespaceUri),
      VoidResult{Status::BadInvalidState,
        ErrorDetail::build("RegisteredNamespaceMissing",
          "A committed namespace has no Namespace implementation during shutdown",
          "NamespaceRegistrationCoordinator")
          .context(ContextKeys::namespaceIndex, namespaceOffset)});
    return;
  }
  nameSpace->shutdown_async(ua::async::post_borrowing(this,
    mStrand,
    mLogger,
    [operationId, namespaceOffset, namespaceUri = std::move(namespaceUri)](
      NamespaceRegistrationCoordinator& self, VoidResult result) mutable {
      self.on_namespace_stopped(operationId, namespaceOffset, std::move(namespaceUri), std::move(result));
    }));
}

void NamespaceRegistrationCoordinator::on_namespace_stopped(
  uint64_t operationId, std::size_t namespaceOffset, String namespaceUri, VoidResult result)
{
  if (!mState->current || mState->current->operationId != operationId ||
      mState->current->kind != State::RequestKind::Shutdown ||
      namespaceOffset >= mState->current->shutdownAnswered.size() ||
      mState->current->shutdownAnswered[namespaceOffset])
  {
    return;
  }

  auto& request = *mState->current;
  request.shutdownAnswered[namespaceOffset] = true;
  if (result.is_bad() && request.firstShutdownFailure.is_good())
  {
    request.firstShutdownFailure = VoidResult{result.status_code(),
      ErrorDetail::build("NamespaceShutdownFailed",
        "A committed namespace failed to stop its background work",
        "NamespaceRegistrationCoordinator")
        .context(ContextKeys::namespaceUri, std::string{namespaceUri})
        .cause(result.status_code())};
  }
  if (--request.shutdownOutstanding != 0)
  {
    return;
  }

  mState->lifecycle = State::Lifecycle::Stopped;
  finish_void(request.firstShutdownFailure);
}

void NamespaceRegistrationCoordinator::finish_add(Result<uint16_t> result)
{
  if (!mState->current || mState->current->rollbackInProgress)
  {
    return;
  }
  if (result.is_bad() && !mState->current->preparations.empty())
  {
    mState->current->rollbackInProgress = true;
    const auto operationId = mState->current->operationId;
    auto preparations = std::move(mState->current->preparations);
    auto resume = ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [operationId, result = std::move(result)](NamespaceRegistrationCoordinator& self) mutable
      {
        if (self.mState->current && self.mState->current->operationId == operationId &&
            self.mState->current->rollbackInProgress)
        {
          self.complete_add(std::move(result));
        }
      });
    NamespacePreparationRollbackOperation::start(
      mStrand, mLogger, std::move(preparations), std::move(resume));
    return;
  }
  complete_add(std::move(result));
}

void NamespaceRegistrationCoordinator::complete_add(Result<uint16_t> result)
{
  auto request = std::move(mState->current);
  if (result.is_bad())
  {
    // The namespace object keeps its context; its helper stops here, where its registration failed (DL-68
    // (7)).
    shut_uncommitted_helper(request->contextState);
  }
  auto callback = std::move(request->addCallback);
  ua::async::guarded(mLogger,
    [callback = std::move(callback), result = std::move(result)]() mutable
    { callback(std::move(result)); })();
  start_next();
}

void NamespaceRegistrationCoordinator::finish_void(VoidResult result)
{
  if (!mState->current || mState->current->rollbackInProgress)
  {
    return;
  }
  if (result.is_bad() && !mState->current->preparations.empty())
  {
    mState->current->rollbackInProgress = true;
    const auto operationId = mState->current->operationId;
    auto preparations = std::move(mState->current->preparations);
    auto resume = ua::async::post_borrowing(this,
      mStrand,
      mLogger,
      [operationId, result = std::move(result)](NamespaceRegistrationCoordinator& self) mutable
      {
        if (self.mState->current && self.mState->current->operationId == operationId &&
            self.mState->current->rollbackInProgress)
        {
          self.complete_void(std::move(result));
        }
      });
    NamespacePreparationRollbackOperation::start(
      mStrand, mLogger, std::move(preparations), std::move(resume));
    return;
  }
  complete_void(std::move(result));
}

void NamespaceRegistrationCoordinator::complete_void(VoidResult result)
{
  auto request = std::move(mState->current);
  auto callback = std::move(request->voidCallback);
  ua::async::guarded(mLogger,
    [callback = std::move(callback), result = std::move(result)]() mutable
    { callback(std::move(result)); })();
  start_next();
}

void AddressSpaceNamespaceLifecycle::install_participant(
  AddressSpace& addressSpace, shared_ptr<NamespaceRegistrationParticipant> participant)
{
  addressSpace.mImpl->namespace_registration_coordinator().install_participant(std::move(participant));
}

void AddressSpaceNamespaceLifecycle::set_server_namespace_defaults(
  AddressSpace& addressSpace, const std::vector<RolePermissionType>& rolePermissions)
{
  addressSpace.mImpl->set_server_namespace_defaults(rolePermissions);
}

void AddressSpaceNamespaceLifecycle::prepare_installed_namespaces_async(
  AddressSpace& addressSpace, std::function<void(VoidResult)> callback) noexcept
{
  addressSpace.mImpl->namespace_registration_coordinator().prepare_installed_namespaces_async(
    std::move(callback));
}

void AddressSpaceNamespaceLifecycle::add_imported_namespace_async(AddressSpace& addressSpace,
  shared_ptr<Namespace> nameSpace, NamespaceRegistrationInitializer initializer,
  NamespaceRegistrationCoordinator::AddNamespaceCallback callback) noexcept
{
  addressSpace.mImpl->namespace_registration_coordinator().add_imported_namespace_async(
    std::move(nameSpace), std::move(initializer), std::move(callback));
}

void AddressSpaceNamespaceLifecycle::prepare_imported_metadata_async(AddressSpace& addressSpace,
  uint16_t namespaceIndex, NodeId metadataObject, NamespaceRegistrationInitializer initializer,
  std::function<void(VoidResult)> callback) noexcept
{
  addressSpace.mImpl->namespace_registration_coordinator().prepare_imported_metadata_async(
    namespaceIndex, std::move(metadataObject), std::move(initializer), std::move(callback));
}

}  // namespace ua::detail
