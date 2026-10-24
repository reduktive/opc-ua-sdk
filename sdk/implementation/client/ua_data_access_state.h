// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_ACCESS_STATE_H
#define UA_DATA_ACCESS_STATE_H

/// @file
/// @brief The strand-free per-handle state the DA typed handles own (client design section 8.18.2), shared
/// between
///        the handle implementation and the `DataAccessAccessor` factory that constructs it.
/// @ingroup client

#include "ua_data_access.h"
#include "ua_data_value.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_semantic_change_cache.h"  // TypedPropertiesState base + SemanticChangeCache::Ticket member

#include <boost/asio/any_io_executor.hpp>

#include <atomic>
#include <map>
#include <memory>
#include <string>

namespace ua::client::detail
{

class WireOps;
class SupportOps;

/// The resolved DA Property snapshot every typed handle combines with the freshly-read Variable Value: the
/// ns0 `BrowseName`  to  Property `DataValue` map, resolved at construction and re-resolved by the manual
/// `refresh_properties_async` (CL-DA-010 manual path) and by the auto re-resolve a typed read performs when
/// @ref TypedPropertiesState::invalidated is set (the SemanticChange auto path). Held as an IMMUTABLE
/// snapshot behind an `std::atomic<std::shared_ptr<const ...>>` (see @ref DataAccessHandleBase): a re-resolve
/// BUILDS a fresh snapshot and publishes it by an atomic swap  -  it NEVER mutates the resolved data in
/// place. A concurrent reader on another executor thread (a copy of the handle mid-decode) therefore always
/// sees one whole, self-consistent snapshot, never a torn half-update (client design section 8.18.2; the
/// 10d-2 race class).
using ResolvedProperties = std::map<std::string, ua::DataValue>;

/// The interface refs + target NodeId every DA typed handle carries (client design section 8.18.2). Held by a
/// `std::shared_ptr` so every wire-op completion can weak-capture it and bail cleanly if the handle was
/// dropped mid-flight (section 9.8.3). The ONLY back-references are @ref wireOps / @ref supportOps,
/// `weak_ptr`s to the two narrow upward-interface roles  -  never a `weak_ptr<ConnectionImpl>`
/// (section 8.2A.13)
/// -  so no self-owning cycle can form. The resolved Properties live in @ref resolvedProperties as an
/// immutable, atomically-swapped snapshot (never mutated in place); because every copy of a handle shares one
/// state object, a refresh / auto re-resolve is visible to all copies the instant the swap is published.
///
/// Derives from @ref TypedPropertiesState so it carries the `invalidated` flag the per-Connection
/// @ref SemanticChangeCache flips (CL-DA-010/011). @ref cacheTicket is the RAII registration handle: it lives
/// on this shared state, so the registration is dropped exactly when the last handle copy destroys the state,
/// and the cache's weak entry then prunes lazily. The Ticket holds no strong back-reference to this state, so
/// no state and Ticket cycle forms.
struct DataAccessHandleBase : TypedPropertiesState
{
  std::weak_ptr<WireOps> wireOps;  ///< upward wire interface (section 8.2A.13); locked per op, bail if gone
  std::weak_ptr<SupportOps> supportOps;  ///< upward support interface (section 8.2A.13); locked per op
  boost::asio::any_io_executor executor;  ///< where results / boundary failures are delivered
  ua::Logger logger;  ///< logs advisory wire-boundary outcomes (CL-DIAG-002/-015)
  ua::NodeId nodeId;  ///< the Variable Object the handle targets (Read/Write node id)

  // The SemanticChangeCache registration ticket (CL-DA-010). Empty when the Connection had no cache at build
  // time (a gone/absent cache is a clean no-op  -  the manual refresh path still works). Kept alive by this
  // shared state; the cache's weak entry prunes lazily when the last handle copy drops the state.
  SemanticChangeCache::Ticket cacheTicket;

  // The resolved DA Property snapshot (see @ref ResolvedProperties). The immutable, atomically-swapped home
  // of EVERY resolved Property (the common `Definition` / `ValuePrecision` plus the per-type
  // Mandatory/Optional Properties). A build / refresh / auto re-resolve BUILDS a fresh map and `store`s it
  // (release); a decode / deadband / dictionary read `load`s it (acquire) and reads the immutable pointee  -
  // never in place (H2 / section 8.18.2). Default-initialised to an empty snapshot so a read is well-defined
  // even before the first resolve (which never happens for a successfully-built handle). The typed extraction
  // from this map lives in the decode helpers (`ua_data_access.cpp`).
  std::atomic<std::shared_ptr<const ResolvedProperties>> resolvedProperties{
    std::make_shared<const ResolvedProperties>()};
};

/// `AnalogItemType` per-handle state (client design section 8.18.2). Its resolved Properties (Mandatory
/// `EURange`, Optional `InstrumentRange` / `EngineeringUnits`) live in @ref
/// DataAccessHandleBase::resolvedProperties.
struct AnalogItemState : DataAccessHandleBase
{};

/// `TwoStateDiscreteType` per-handle state (client design section 8.18.2). Its Mandatory `TrueState` /
/// `FalseState` Properties live in @ref DataAccessHandleBase::resolvedProperties.
struct TwoStateDiscreteState : DataAccessHandleBase
{};

/// `MultiStateDiscreteType` per-handle state (client design section 8.18.2). Its Mandatory `EnumStrings`
/// Property lives in @ref DataAccessHandleBase::resolvedProperties.
struct MultiStateDiscreteState : DataAccessHandleBase
{};

/// `MultiStateValueDiscreteType` per-handle state (client design section 8.18.2). Its Mandatory `EnumValues`
/// Property lives in @ref DataAccessHandleBase::resolvedProperties.
struct MultiStateValueDiscreteState : DataAccessHandleBase
{};

}  // namespace ua::client::detail

#endif  // UA_DATA_ACCESS_STATE_H
