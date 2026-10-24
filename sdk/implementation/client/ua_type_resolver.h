// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TYPE_RESOLVER_H
#define UA_TYPE_RESOLVER_H

/// @file
/// @brief The per-Connection type-resolution component (@ref ua::client::detail::TypeResolver, client
///        design section 8.6): built-in  union  user-registered  union  Client-wide overlay  union
///        server-discovered structure types, resolved Lazily / Eagerly per @ref
///        ua::client::TypeResolutionPolicy, published as an immutable @ref TypeRegistry the codec consumes
///        lock-free.
/// @ingroup client

#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_result.h"
#include "ua_type_defer_gate.h"
#include "ua_type_registry.h"
#include "ua_type_resolution_policy.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace ua
{
class Structure;
class StructureDefinition;
class BrowseResponse;
class ReadResponse;
}  // namespace ua

namespace ua::client
{
class NamespaceTable;
}  // namespace ua::client

namespace ua::client::detail
{

class WireOps;
class SupportOps;
struct TypeResolverTestAccess;

/// An application-supplied structure registration (client design section 8.6.1). Keyed on `namespaceUri` (not
/// a NamespaceIndex) so it survives a namespace remap (CL-ADDRSP-012 / CL-VIEW-018).
struct UserTypeRegistration
{
  std::string namespaceUri;  ///< the type's namespace URI (not an index)
  ua::NodeId dataTypeIdentifier;  ///< the DataType identifier (index is resolved from URI)
  ua::NodeId binaryEncodingIdentifier;  ///< the DefaultBinary encoding identifier
  std::shared_ptr<const ua::Structure> decoder;  ///< decode prototype
  std::shared_ptr<const ua::Structure> encoder;  ///< encode prototype (same instance for symmetric types)
};

/// The per-registration outcome returned by @ref TypeResolver::register_types_async.
struct RegistrationOutcome
{
  std::string namespaceUri;
  ua::NodeId dataTypeIdentifier;
  ua::StatusCode status;  ///< Good; Bad_AlreadyExists (user-vs-user); Bad_NotFound (URI parked)
  bool retainedForLaterAttach = false;  ///< true when parked for a future namespace snapshot (URI absent)
};

/// The per-`Connection` type-resolution component (client design section 8.6 / section 9.8.3).
///
/// Strand model (section 8.6): the resolver has **no private strand**  -  it is part of `ConnectionImpl`'s
/// domain and the injected strand is `ConnectionImpl`'s. Every mutation (bootstrap, eager scan,
/// decode-and-defer resolve, user registration) runs on it; the immutable registry is published via an atomic
/// `shared_ptr<const TypeRegistry>` the codec loads lock-free from any thread (Rule 4 info-snapshot).
///
/// Lifetime (section 9.8.3): held by `shared_ptr`, derives from `enable_shared_from_this`; every internal
/// async completion is armed with `post_borrowing`  -  it weak-captures the resolver and no-ops if it is
/// gone, and locks the weak @ref WireOps interface and bails if the Connection behind it is gone, rather than
/// dereferencing a raw owner across an async boundary.
class TypeResolver : public std::enable_shared_from_this<TypeResolver>
{
public:
  /// Creates the resolver over the upward interface (section 8.2A.13).
  ///
  /// @param strand          `ConnectionImpl`'s strand (injected  -  the resolver never fabricates its own).
  /// @param wireOps         The wire interface for Browse / Read type discovery (held WEAK; locked per op).
  /// @param supportOps      The support interface for `namespace_table()` (held WEAK; locked per op).
  /// @param policy          The resolution mode + eager interest + decode-and-defer budget.
  /// @param clientWideOverlay The optional application-supplied `StructureFactory` overlay (may be null;
  ///                        merged at `ClientOverlay` precedence  -  above server-discovered, below user).
  /// @param logger          Logger for the guarded async boundaries and advisories.
  /// Announces a type the resolver has just installed: the encoding NodeId and the type's name. The
  /// Connection routes this to `TypeObserver::on_type_registered`. A callback rather than a sink
  /// reference so the resolver keeps no dependency on the observer layer; empty means "nobody is
  /// listening", which is the default.
  using TypeRegisteredNotifier = std::function<void(ua::NodeId, std::string)>;

  [[nodiscard]] static std::shared_ptr<TypeResolver> create(
    boost::asio::strand<boost::asio::any_io_executor> strand, std::weak_ptr<WireOps> wireOps,
    std::weak_ptr<SupportOps> supportOps, ua::client::TypeResolutionPolicy policy,
    std::shared_ptr<const StructureFactory> clientWideOverlay, ua::Logger logger,
    TypeRegisteredNotifier typeRegistered = {});

  TypeResolver(const TypeResolver&) = delete;
  TypeResolver& operator=(const TypeResolver&) = delete;
  TypeResolver(TypeResolver&&) = delete;
  TypeResolver& operator=(TypeResolver&&) = delete;
  ~TypeResolver() = default;

  /// The current immutable registry snapshot (atomic-load; safe from any thread). A codec consumer holds
  /// the returned shared_ptr for the duration of one encode/decode operation.
  [[nodiscard]] std::shared_ptr<const TypeRegistry> registry() const noexcept
  {
    return mRegistry.load();
  }

  /// The policy this resolver was constructed with (immutable after construction, so readable from any
  /// thread). Lets a caller read back the resolution mode / eager interest set / timeouts actually in force,
  /// rather than the ones it believes it configured.
  [[nodiscard]] const ua::client::TypeResolutionPolicy& policy() const noexcept
  {
    return mPolicy;
  }

  /// The decode-and-defer decision for one message: what the codec does with @p distinctUnresolvedCount
  /// distinct unknown encodings given the message's eligibility @p messageClass (section 9.2 / section 9.8
  /// override 2). Pure and thread-safe (does not touch the strand-private advisory dedup set).
  [[nodiscard]] DeferDecision classify_message(
    MessageClass messageClass, std::size_t distinctUnresolvedCount) const noexcept
  {
    return mDeferGate.classify(messageClass, distinctUnresolvedCount);
  }

  /// Whether a re-decode pass at zero-based @p passIndex is within `TypeDeferPolicy::maxReDecodePasses`.
  /// A budget of zero permits no pass at all, so resolved placeholders are delivered opaque rather than
  /// upgraded. Pure and thread-safe (does not touch the strand-private advisory dedup set).
  [[nodiscard]] bool may_redecode(std::size_t passIndex) const noexcept
  {
    return mDeferGate.may_redecode(passIndex);
  }

  /// Applies a batch of user registrations (section 8.6.3 attach-or-defer). Posts to the strand; the callback
  /// fires on the executor with a per-registration outcome vector. Registrations whose `namespaceUri` is
  /// not yet in the current NamespaceTable snapshot are parked and attach on a later
  /// @ref on_namespace_table_replaced_async.
  void register_types_async(std::vector<UserTypeRegistration> registrations,
    std::function<void(ua::Result<std::vector<RegistrationOutcome>>)> callback);

  /// Lazy decode-and-defer entry (section 8.6.4): resolves the structure behind @p encodingId (Browse
  /// HasEncoding  to  Read DataTypeDefinition  to  optional dictionary fallback) and installs it into the
  /// registry. Coalesces concurrent waiters per encoding NodeId. @p callback fires Good once resolved (or
  /// on the already-resolved fast path), or Bad on failure / a gone Connection.
  void resolve_async(ua::NodeId encodingId, std::shared_ptr<const ua::client::NamespaceTable> namespaces,
    std::function<void(ua::VoidResult)> callback);

  /// Records that an application-data value remained opaque after the one allowed re-decode pass. The
  /// bounded advisory gate is strand-owned: @p firstSeen fires on the executor only for the first sighting
  /// (or after LRU eviction), so a repeating unknown encoding cannot flood observers or grow memory without
  /// bound. Advisory-only; if the resolver is gone, the callback is simply not fired.
  void note_unresolved_async(ua::NodeId encodingId, std::function<void()> firstSeen);

  /// DataType-hierarchy discovery (CL-ADDRSP-009): resolves @p dataTypeId's IMMEDIATE supertype (Browse
  /// `HasSubtype` inverse) and records the edge in the registry via @ref StructureFactory::add_subtype_edge,
  /// publishing a bumped generation. One level per call  -  the caller loops (query
  /// @ref TypeRegistry::is_subtype_of; on `nullopt`, resolve the node whose edge is missing, then re-check
  /// the new generation) until the relation is decidable. Coalesces concurrent waiters per DataType. @p
  /// callback fires Good once the immediate supertype is recorded (or on the already-known /
  /// BaseDataType-root fast path, or when the server exposes no supertype  -  the edge stays unknown, so the
  /// caller stops), Bad on a Browse failure / a gone Connection.
  void resolve_subtype_async(ua::NodeId dataTypeId,
    std::shared_ptr<const ua::client::NamespaceTable> namespaces,
    std::function<void(ua::VoidResult)> callback);

  /// Bootstrap / reconnect namespace hook (section 8.6.3): attaches parked user registrations against @p
  /// snapshot and, under `Eager` / `EagerThenLazy`, runs the connect-time eager scan (bounded by
  /// `eagerScanBudget`).
  /// @p callback fires on the executor when the (synchronous) attach completes; the eager scan proceeds in
  /// the background.
  void on_namespace_table_replaced_async(
    std::shared_ptr<const ua::client::NamespaceTable> snapshot, std::function<void()> callback);

private:
  TypeResolver(boost::asio::strand<boost::asio::any_io_executor> strand, std::weak_ptr<WireOps> wireOps,
    std::weak_ptr<SupportOps> supportOps, ua::client::TypeResolutionPolicy policy,
    std::shared_ptr<const StructureFactory> clientWideOverlay, ua::Logger logger,
    TypeRegisteredNotifier typeRegistered);

  friend struct TypeResolverTestAccess;

  using ResolutionWaiter = std::function<void(ua::VoidResult)>;

  // --- on-strand helpers ---
  void rebuild_registry();  // freeze mWorkingFactory into a fresh atomic TypeRegistry generation
  void start_resolution(
    const ua::NodeId& encodingId, std::shared_ptr<const ua::client::NamespaceTable> namespaces);
  void on_browse_done(ua::NodeId encodingId, ua::Result<ua::BrowseResponse> response);
  // --- DataType subtype discovery (CL-ADDRSP-009) ---
  void start_subtype_resolution(const ua::NodeId& dataTypeId);
  void on_subtype_browse_done(ua::NodeId dataTypeId, ua::Result<ua::BrowseResponse> response);
  void settle_subtype_resolution(const ua::NodeId& dataTypeId, ua::VoidResult result);
  void on_definition_read(
    ua::NodeId encodingId, ua::NodeId dataTypeId, ua::Result<ua::ReadResponse> response);
  void on_dictionary_read(
    ua::NodeId encodingId, ua::NodeId dataTypeId, ua::Result<ua::ReadResponse> response);
  void finish_resolution(const ua::NodeId& encodingId, ua::NodeId dataTypeId, TypeSource source,
    std::shared_ptr<const ua::Structure> decoder = nullptr);
  // Arms the `resolutionTimeout` deadline for one in-flight resolution. On expiry the encoding's waiters
  // are settled Bad_Timeout via fail_resolution, so a server that never answers the Browse/Read cannot park
  // a caller indefinitely. A non-positive timeout arms nothing.
  void arm_resolution_deadline(const ua::NodeId& encodingId);
  void fail_resolution(const ua::NodeId& encodingId, ua::VoidResult result);
  void run_eager_scan();

  // Builds a clone-able decode prototype from an attacker-controlled server `StructureDefinition`
  // (Slice T1(b) / CL-ADDRSP-013). Bounded + fail-closed: returns nullptr (type stays opaque, non-fatal)
  // on an over-budget field count, an unresolved nested-field dependency (the chase is deferred this
  // slice), or any build exception, logging a source-tagged advisory. Never throws; never recurses on the
  // attacker's definition shape (section 3.1 DoS surface).
  [[nodiscard]] std::shared_ptr<const ua::Structure> build_server_structure_decoder(
    const ua::NodeId& encodingId, const ua::NodeId& dataTypeId, const ua::StructureDefinition& definition);

  // Adapts a user completion so it fires on the executor (off the strand).
  [[nodiscard]] std::function<void(ua::VoidResult)> on_executor(std::function<void(ua::VoidResult)> cb) const;
  [[nodiscard]] std::function<void()> on_executor_void(std::function<void()> cb) const;

  // mStrand first so mExecutor initialises from its inner executor (section 8.6: injected, never fabricated).
  boost::asio::strand<boost::asio::any_io_executor> mStrand;
  boost::asio::any_io_executor mExecutor;
  std::weak_ptr<WireOps> mWireOps;
  std::weak_ptr<SupportOps> mSupportOps;
  ua::client::TypeResolutionPolicy mPolicy;
  std::shared_ptr<const StructureFactory> mClientWideFactory;  // borrowed const overlay (may be null)
  ua::Logger mLogger;

  std::atomic<std::shared_ptr<const TypeRegistry>> mRegistry;  // the published immutable snapshot
  StructureFactory mWorkingFactory;  // strand-only accumulated set
  std::uint64_t mGeneration = 0;  // strand-only monotone generation
  std::shared_ptr<const ua::client::NamespaceTable> mNamespaces;  // strand-only last snapshot
  std::vector<UserTypeRegistration> mPendingUserRegistrations;  // strand-only attach-or-defer parking
  std::unordered_map<ua::NodeId, std::vector<ResolutionWaiter>> mResolutionInFlight;  // strand-only
  // One deadline per in-flight resolution (`TypeResolutionPolicy::resolutionTimeout`), armed when the
  // resolution starts and cancelled when it settles. Held by shared_ptr so the pending wait handler keeps
  // its own timer alive across the settle that erases this entry. Strand-only.
  std::unordered_map<ua::NodeId, std::shared_ptr<boost::asio::steady_timer>> mResolutionTimers;
  std::unordered_map<ua::NodeId, std::vector<ResolutionWaiter>>
    mSubtypeInFlight;  // strand-only (CL-ADDRSP-009)
  TypeRegisteredNotifier mTypeRegistered;  // fired on the strand when a type is installed
  TypeDeferGate mDeferGate;  // strand-only advisory dedup; classify() is pure
};

}  // namespace ua::client::detail

#endif  // UA_TYPE_RESOLVER_H
