// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Handle to a Variable node typed as the base `BaseVariableType` (i=62).
/// @ingroup address_space

#ifndef UA_BASE_VARIABLE_H
#define UA_BASE_VARIABLE_H

#include "ua_includes.h"
#include "ua_address_space.h"
#include "ua_instantiation_options.h"
#include "ua_node_subtree.h"
#include "ua_result.h"
#include "ua_node.h"
#include "ua_value_source.h"

#include <functional>

namespace ua
{

/// Handle to a Variable node whose type definition is the base
/// `BaseVariableType` (i=62).
///
/// Wraps an existing or freshly instantiated Variable node together with the
/// @ref AddressSpace it lives in, and exposes the variable's live value: reading
/// and writing the value, and installing the read/write handlers that
/// produce and consume it. A Variable's value is dynamic and possibly
/// externally sourced - it is never a stored attribute, so it is always
/// accessed through this handle's value API rather than via attribute
/// read/write.
///
/// When the handle owns the node subtree it created, destroying the handle
/// without first calling @ref release removes that subtree from the address
/// space; a handle that references a pre-existing node owns nothing and only
/// references it.
///
/// Move-only: copying would duplicate ownership of the underlying subtree. This
/// type serves both as a usable handle and as the base class for generated,
/// strongly typed Variable handles, which call @ref create_variable_impl_async
/// to instantiate.
/// @ingroup address_space
class BaseVariable
{
public:
  /// Constructs an empty handle that references no node.
  BaseVariable() = default;

  virtual ~BaseVariable() = default;

  BaseVariable(const BaseVariable&) = delete;
  BaseVariable& operator=(const BaseVariable&) = delete;

  /// Transfers ownership of the referenced node and any owned subtree from the
  /// moved-from handle, leaving it empty.
  BaseVariable(BaseVariable&&) noexcept = default;

  /// Transfers ownership of the referenced node and any owned subtree from the
  /// moved-from handle, leaving it empty.
  ///
  /// @return Reference to this handle after the move.
  BaseVariable& operator=(BaseVariable&&) noexcept = default;

  /// Returns the NodeId of the referenced Variable node.
  ///
  /// The reference is valid for the lifetime of this handle.
  ///
  /// @return The NodeId of the referenced node; a null NodeId when the handle is empty.
  const NodeId& node_id() const;

  /// Releases ownership of the node subtree this handle created.
  ///
  /// After this call the underlying node remains in the address space but is no
  /// longer owned by the handle, so destroying the handle will not remove it. A
  /// no-op on a handle that owns no subtree.
  void release();

  // Value consumer API - reads/writes through the handler installed on the variable node.

  /// Callback receiving the @ref DataValueResult of @ref read_value_async.
  using ReadValueCompleteCallback = std::function<void(DataValueResult)>;

  /// Callback receiving the @ref VoidResult of @ref write_value_async.
  using WriteValueCompleteCallback = std::function<void(VoidResult)>;

  /// Reads the variable's live value asynchronously.
  ///
  /// Routes the read through the read handler installed on the variable node and
  /// completes on an unspecified worker thread - do not block the callback. The
  /// returned @ref DataValue carries value, status, and timestamps.
  ///
  /// TWO LAYERS, and they answer different questions. The Result reports whether the
  /// READ worked. The quality of what was read rides on `DataValue::status()`. A faulted
  /// transmitter therefore yields a GOOD Result carrying a DataValue whose status is Bad -
  /// you get the last value AND the fact that it is suspect, and deciding what that means
  /// is yours. Do not read the outer Result as "the value is fine".
  ///
  /// @param complete Receives the outcome: on success the Result holds the
  ///                 @ref DataValue; on failure it carries an @ref ErrorDetail.
  ///                 A null callback is ignored and the read is not performed.
  ///                 This overload never throws.
  /// @see try_read_value_sync, read_value_sync
  void read_value_async(ReadValueCompleteCallback complete) const noexcept;

  /// Reads the variable's live value, blocking until complete.
  ///
  /// @return The @ref DataValue, or an @ref ErrorDetail on failure. Never throws.
  /// @see read_value_async, read_value_sync
  DataValueResult try_read_value_sync() const noexcept;

  /// Reads the variable's live value, blocking until complete.
  ///
  /// The DataValue's status is the one `detail::combined_status` gives for the answer's code and the
  /// Value's own status, so a Good subcode on the answer reaches the caller.
  ///
  /// @return The @ref DataValue.
  /// @throws UaException unless the answer is Good, an Uncertain answer included; try_read_value_sync()
  ///         returns an Uncertain answer's value.
  /// @see read_value_async, try_read_value_sync
  DataValue read_value_sync() const;

  /// Writes the variable's live value asynchronously.
  ///
  /// Routes the write through the write handler installed on the variable node
  /// and completes on an unspecified worker thread - do not block the callback.
  ///
  /// @param value    The @ref DataValue to write (value, status, timestamps).
  /// @param complete Receives the outcome: on success an empty Result; on
  ///                 failure it carries an @ref ErrorDetail. With a null callback
  ///                 the write is still performed and a failure is logged. This
  ///                 overload never throws.
  /// @see try_write_value_sync, write_value_sync
  void write_value_async(DataValue value, WriteValueCompleteCallback complete) const noexcept;

  /// Writes the variable's live value, blocking until complete.
  ///
  /// @param value The @ref DataValue to write.
  /// @return An empty Result on success, or an @ref ErrorDetail on failure.
  ///         Never throws.
  /// @see write_value_async, write_value_sync
  VoidResult try_write_value_sync(DataValue value) const noexcept;

  /// Writes the variable's live value, blocking until complete.
  ///
  /// @param value The @ref DataValue to write.
  /// @throws UaException if the write fails.
  /// @see write_value_async, try_write_value_sync
  void write_value_sync(DataValue value) const;

  // Value handler registration - installs the handler that produces/consumes the value.

  /// Makes @p source the owner of this Variable's Value, replacing any attached one; null detaches it (see
  /// @ref ExternalValueSource::set_value_source).
  ///
  /// @param source The source; one source may serve many Variables (see @ref ValueSource).
  /// @param done   Receives the outcome: on success an empty Result; on failure it carries an
  ///               @ref ErrorDetail (e.g. the node does not accept a source). Runs on an unspecified
  ///               worker thread - do not block it. With a null callback the source is still attached
  ///               and a failure is logged.
  ///               This overload never throws.
  /// @see try_set_value_source_sync, set_value_source_sync
  void set_value_source_async(
    std::shared_ptr<ValueSource> source, std::function<void(VoidResult)> done) const noexcept;

  /// Makes @p source the owner of this Variable's Value, blocking until complete.
  ///
  /// @param source The source, or null to detach it.
  /// @return An empty Result on success, or an @ref ErrorDetail on failure. Never throws.
  /// @see set_value_source_async, set_value_source_sync
  VoidResult try_set_value_source_sync(std::shared_ptr<ValueSource> source) const noexcept;

  /// Makes @p source the owner of this Variable's Value, blocking until complete.
  ///
  /// @param source The source, or null to detach it.
  /// @throws UaException if the source cannot be attached.
  /// @see set_value_source_async, try_set_value_source_sync
  void set_value_source_sync(std::shared_ptr<ValueSource> source) const;

  /// Outcome payload for a successful Variable instantiation.
  struct CreateResultData
  {
    AddressSpace addressSpace;  ///< Address space the new node was created in.
    NodeId nodeId;  ///< NodeId of the newly created Variable node.
    NodeSubtree subtree;  ///< Owned subtree rooted at the new node.
  };

  /// Result carrying the outcome of a Variable instantiation.
  using CreateResult = Result<CreateResultData>;

  /// Callback receiving the @ref CreateResult of @ref create_variable_impl_async.
  using CreateImplCompleteCallback = std::function<void(CreateResult)>;

protected:
  /// Instantiates a new Variable node under @p parent and reports the result.
  ///
  /// The extension point through which generated, strongly typed Variable
  /// handles create their backing node; not called directly by SDK consumers.
  ///
  /// @param addressSpace   Address space to create the node in.
  /// @param parent         NodeId of the parent the new Variable is created under.
  /// @param browseName     BrowseName of the new node.
  /// @param typeDefinition NodeId of the Variable type to instantiate.
  /// @param options        Controls instantiation behaviour (e.g. modelling-rule handling).
  /// @param attributes     Initial attribute values for the new Variable.
  /// @param complete       Receives the outcome: on success the Result holds the
  ///                       @ref CreateResultData (including the owned subtree); on
  ///                       failure it carries an @ref ErrorDetail. Never throws.
  static void create_variable_impl_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    NodeId typeDefinition, InstantiationOptions options, VariableInstantiationAttributes attributes,
    CreateImplCompleteCallback complete) noexcept;

  /// Constructs a handle that references @p nodeId, optionally owning @p owned.
  ///
  /// Used by derived handles and the create path. When @p owned holds a subtree,
  /// the handle is responsible for it until @ref release is called.
  ///
  /// @param addressSpace Address space the referenced node lives in.
  /// @param nodeId       NodeId of the Variable node this handle references.
  /// @param owned        Subtree to take ownership of, or `std::nullopt` to reference without owning.
  BaseVariable(AddressSpace addressSpace, NodeId nodeId, optional<NodeSubtree> owned);

  optional<AddressSpace> mAddressSpace;  ///< Address space the handle is bound to; empty when the
                                         ///< handle references no node (default-constructed or moved-from).
  NodeId mNodeId;  ///< NodeId of the referenced Variable node; null when the handle is empty.
  optional<NodeSubtree> mOwned;  ///< Subtree this handle owns and removes on destruction unless
                                 ///< @ref release is called first; empty for attached handles.
};

}  // namespace ua

#endif  // UA_BASE_VARIABLE_H
