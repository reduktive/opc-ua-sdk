// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief AddressSpace-owned, append-only namespace lifecycle coordination.

#ifndef UA_NAMESPACE_REGISTRATION_COORDINATOR_H
#define UA_NAMESPACE_REGISTRATION_COORDINATOR_H

#include "ua_address_space.h"
#include "ua_logger.h"
#include "ua_namespace.h"
#include "ua_result.h"
#include "ua_role_permission_type.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace ua
{

class AddressSpaceImpl;

namespace test_helpers
{
class NamespaceRegistrationCoordinatorTestAccess;
}

namespace detail
{

struct NamespaceContextState;

/// Private route made available only while a namespace candidate is being prepared.
/// Observes the original candidate without extending its lifetime or allowing an index-only replacement.
struct NamespaceRegistrationRoute final
{
  uint16_t namespaceIndex{0};
  weak_ptr<Namespace> namespaceObject;
};

/// Inputs supplied to one lifecycle participant before a namespace becomes visible.
struct NamespaceRegistrationCandidate final
{
  uint16_t namespaceIndex{0};
  String namespaceUri;
  shared_ptr<Namespace> namespaceObject;
  std::optional<NodeId> metadataObject;
  AddressSpace stagedAddressSpace;
  /// What the registering caller asked to be published for this namespace.
  NamespaceMetadataOptions metadataOptions;
};

/// Owned, already-prepared participant state whose final publication cannot fail.
class NamespaceRegistrationPreparation
{
public:
  NamespaceRegistrationPreparation() = default;
  virtual ~NamespaceRegistrationPreparation() = default;

  NamespaceRegistrationPreparation(const NamespaceRegistrationPreparation&) = delete;
  NamespaceRegistrationPreparation& operator=(const NamespaceRegistrationPreparation&) = delete;
  NamespaceRegistrationPreparation(NamespaceRegistrationPreparation&&) = delete;
  NamespaceRegistrationPreparation& operator=(NamespaceRegistrationPreparation&&) = delete;

  /// Publishes the prepared state. Called exactly once, on the registration strand.
  virtual void commit() noexcept = 0;

  /// Removes staged resources before a failed registration completes.
  ///
  /// Preparations without asynchronous cleanup may keep the default. The callback is mandatory and
  /// is invoked exactly once; a bad cleanup result is logged while the original registration failure
  /// remains the caller-visible primary error.
  virtual void rollback_async(std::function<void(VoidResult)> callback) noexcept
  {
    callback(VoidResult{});
  }
};

using NamespaceRegistrationPreparationResult = Result<shared_ptr<NamespaceRegistrationPreparation>>;
using NamespaceRegistrationPreparationCallback = std::function<void(NamespaceRegistrationPreparationResult)>;

/// Fallible model content staged before lifecycle participants inspect a namespace candidate.
struct NamespaceRegistrationInitialization final
{
  std::optional<NodeId> metadataObject;
  shared_ptr<NamespaceRegistrationPreparation> preparation;
};

using NamespaceRegistrationInitializationResult = Result<NamespaceRegistrationInitialization>;
using NamespaceRegistrationInitializationCallback =
  std::function<void(NamespaceRegistrationInitializationResult)>;
using NamespaceRegistrationInitializer = std::function<void(
  NamespaceRegistrationCandidate candidate, NamespaceRegistrationInitializationCallback callback)>;

/// Optional address-space lifecycle work contributed by an owning layer.
class NamespaceRegistrationParticipant
{
public:
  NamespaceRegistrationParticipant() = default;
  virtual ~NamespaceRegistrationParticipant() = default;

  NamespaceRegistrationParticipant(const NamespaceRegistrationParticipant&) = delete;
  NamespaceRegistrationParticipant& operator=(const NamespaceRegistrationParticipant&) = delete;
  NamespaceRegistrationParticipant(NamespaceRegistrationParticipant&&) = delete;
  NamespaceRegistrationParticipant& operator=(NamespaceRegistrationParticipant&&) = delete;

  /// Performs every fallible step and returns an owned no-throw commit object.
  virtual void prepare_async(
    NamespaceRegistrationCandidate candidate, NamespaceRegistrationPreparationCallback callback) noexcept = 0;
};

/// Serializes namespace preparation, dense append, initial participant catch-up and shutdown.
class NamespaceRegistrationCoordinator final
  : public std::enable_shared_from_this<NamespaceRegistrationCoordinator>
{
public:
  using AddNamespaceCallback = std::function<void(Result<uint16_t>)>;

  static shared_ptr<NamespaceRegistrationCoordinator> create(
    weak_ptr<AddressSpaceImpl> addressSpace, boost::asio::any_io_executor executor);

  /// A handle on @p addressSpace for the calls the SDK makes on a context's behalf (NR-40).
  static AddressSpace handle(shared_ptr<AddressSpaceImpl> addressSpace);

  NamespaceRegistrationCoordinator(const NamespaceRegistrationCoordinator&) = delete;
  NamespaceRegistrationCoordinator& operator=(const NamespaceRegistrationCoordinator&) = delete;
  NamespaceRegistrationCoordinator(NamespaceRegistrationCoordinator&&) = delete;
  NamespaceRegistrationCoordinator& operator=(NamespaceRegistrationCoordinator&&) = delete;
  ~NamespaceRegistrationCoordinator();

  /// Construction-only logger installation, before the AddressSpace is exposed.
  void set_logger(Logger logger);

  /// Construction-only append used for NS0 and NS1 before participants can be installed.
  uint16_t bootstrap_namespace(shared_ptr<Namespace> nameSpace);

  /// Construction-only participant installation, before the Server is exposed.
  void install_participant(shared_ptr<NamespaceRegistrationParticipant> participant);

  /// Canonical live registration operation. Safe from any caller thread.
  void add_namespace_async(shared_ptr<Namespace> nameSpace, NamespaceMetadataOptions metadata,
    AddNamespaceCallback callback) noexcept;

  /// Internal NodeSet path: stages accepted metadata before participants and the permanent append.
  void add_imported_namespace_async(shared_ptr<Namespace> nameSpace,
    NamespaceRegistrationInitializer initializer, AddNamespaceCallback callback) noexcept;

  /// Internal NodeSet path for a bootstrap namespace not yet prepared by any participant.
  void prepare_imported_metadata_async(uint16_t namespaceIndex, NodeId metadataObject,
    NamespaceRegistrationInitializer initializer, std::function<void(VoidResult)> callback) noexcept;

  /// Prepares installed participants for namespaces committed before they were installed.
  void prepare_installed_namespaces_async(std::function<void(VoidResult)> callback) noexcept;

  /// Orders shutdown after every earlier registration operation: shuts down the monitoring helper of every
  /// committed registration and waits for each, then fans out to the namespaces' `shutdown_async`. The
  /// namespaces are copied from the array when the shutdown starts and asked through that copy, so no later
  /// turn of it reads the array.
  void shutdown_async(std::function<void(VoidResult)> callback) noexcept;

private:
  friend class ::ua::test_helpers::NamespaceRegistrationCoordinatorTestAccess;

  class State;

  NamespaceRegistrationCoordinator(
    weak_ptr<AddressSpaceImpl> addressSpace, boost::asio::any_io_executor executor);

  void set_maximum_namespaces_for_tests(std::size_t maximumNamespaces);

  void enqueue_add(shared_ptr<Namespace> nameSpace, NamespaceMetadataOptions metadata,
    NamespaceRegistrationInitializer initializer, AddNamespaceCallback callback);
  void enqueue_imported_metadata(uint16_t namespaceIndex, NodeId metadataObject,
    NamespaceRegistrationInitializer initializer, std::function<void(VoidResult)> callback);
  void enqueue_prepare_existing(std::function<void(VoidResult)> callback);
  void enqueue_shutdown(std::function<void(VoidResult)> callback);
  void start_next();
  void start_add();
  void start_imported_metadata();
  void start_prepare_existing();
  void start_shutdown();
  /// The shutdown's step after the posted model changes have run: stops the helpers, then the namespaces.
  void stop_helpers(uint64_t operationId);
  /// One helper of the namespace at @p namespaceOffset has stopped; the namespace is shut down when it
  /// was the last.
  void on_helper_stopped(uint64_t operationId, std::size_t namespaceOffset);
  /// Calls the shutdown_async of the namespace the shutdown holds at @p namespaceOffset; its answer goes to
  /// on_namespace_stopped.
  void stop_namespace(uint64_t operationId, std::size_t namespaceOffset);
  /// The state of a new registration's context: its index and a monitoring helper running on the address
  /// space's executor (not this coordinator's strand), holding @p nameSpace weakly.
  shared_ptr<const NamespaceContextState> create_context_state(
    uint16_t namespaceIndex, const shared_ptr<Namespace>& nameSpace) const;
  /// Shuts down the helper of a registration that did not commit; nothing waits for it.
  void shut_uncommitted_helper(const shared_ptr<const NamespaceContextState>& state) noexcept;
  void start_initializer();
  void on_initialized(uint64_t operationId, NamespaceRegistrationInitializationResult result);
  void prepare_metadata_state_and_participants();
  void prepare_next_participant();
  void on_participant_prepared(uint64_t operationId, std::size_t participantIndex, uint16_t namespaceIndex,
    NamespaceRegistrationPreparationResult result);
  void on_namespace_stopped(
    uint64_t operationId, std::size_t namespaceOffset, String namespaceUri, VoidResult result);
  void finish_add(Result<uint16_t> result);
  void complete_add(Result<uint16_t> result);
  void finish_void(VoidResult result);
  void complete_void(VoidResult result);

  /// The owner, and the only way to its namespace array: every read of the array locks it first, so no read
  /// reaches an array the owner's destructor is destroying.
  weak_ptr<AddressSpaceImpl> mAddressSpace;
  boost::asio::any_io_executor mExecutor;
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  Logger mLogger;
  std::unique_ptr<State> mState;
};

/// Internal bridges into the private coordinator owned by AddressSpaceImpl.
class AddressSpaceNamespaceLifecycle final
{
public:
  static void install_participant(
    AddressSpace& addressSpace, shared_ptr<NamespaceRegistrationParticipant> participant);

  static void prepare_installed_namespaces_async(
    AddressSpace& addressSpace, std::function<void(VoidResult)> callback) noexcept;

  static void add_imported_namespace_async(AddressSpace& addressSpace, shared_ptr<Namespace> nameSpace,
    NamespaceRegistrationInitializer initializer,
    NamespaceRegistrationCoordinator::AddNamespaceCallback callback) noexcept;

  static void prepare_imported_metadata_async(AddressSpace& addressSpace, uint16_t namespaceIndex,
    NodeId metadataObject, NamespaceRegistrationInitializer initializer,
    std::function<void(VoidResult)> callback) noexcept;

  /// Sets the Role permission defaults of namespaces 0 and 1 through the address space's own handles.
  static void set_server_namespace_defaults(
    AddressSpace& addressSpace, const std::vector<RolePermissionType>& rolePermissions);
};

}  // namespace detail
}  // namespace ua

#endif  // UA_NAMESPACE_REGISTRATION_COORDINATOR_H
