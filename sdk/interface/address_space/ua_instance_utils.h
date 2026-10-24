// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Asynchronous helpers for resolving and wiring instance nodes in the address space.
/// @ingroup address_space

#ifndef UA_INSTANCE_UTILS_H
#define UA_INSTANCE_UTILS_H

#include "ua_includes.h"
#include "ua_address_space.h"
#include "ua_node.h"
#include "ua_value_source.h"
#include "ua_node_accessor.h"
#include "ua_result.h"

namespace ua
{
/// Free-function helpers for inspecting and wiring instance nodes in the address space.
///
/// These utilities resolve type definitions, locate children by browse name, read and write
/// variable values, and install method-call and external value handlers. Every operation is
/// callback-canonical (`*_async`); there are no sync wrappers. All work is posted to the address
/// space's strand and each completion callback runs on an unspecified worker thread - do not block
/// it. The `AddressSpace`, `NodeAccessor`, and handler arguments are value handles taken by value;
/// the helpers retain only what they need for the duration of the operation.
///
/// @ingroup address_space
namespace instance_utils
{

/// Result carrying an optional @ref NodeId, empty when no matching node exists.
using OptionalNodeIdResult = Result<optional<NodeId>>;

// =====================================================================
// Public API - *_async (callback-canonical)
// =====================================================================

/// Resolves the local-only type definition @ref NodeId for a node.
///
/// Follows the node's `HasTypeDefinition` reference and returns the target NodeId, ignoring any
/// type definition that lives outside the local server.
///
/// @param node       Accessor for the instance node whose type definition is resolved.
/// @param onComplete Receives the outcome: the type definition NodeId, or `nullopt` when the node has no
///                   local type definition, with the code the namespace answered the node's References
///                   with (a Good subcode, or an Uncertain code with the References it held, is kept); an
///                   answer without References is passed on with its @ref ErrorDetail. Runs on an
///                   unspecified worker thread. Never throws.
void get_local_type_definition_id_async(
  NodeAccessor node, std::function<void(OptionalNodeIdResult)> onComplete) noexcept;

/// Verifies that an existing node's type definition exactly matches an expected type.
///
/// Succeeds only when the node's `HasTypeDefinition` target equals @p expectedTypeDef; subtypes do
/// not satisfy this check.
///
/// @param addressSpace   Address space that owns @p existingNode.
/// @param existingNode   Node whose type definition is checked.
/// @param expectedTypeDef Type definition NodeId the node must match exactly.
/// @param onComplete     Receives the outcome: success on an exact match, otherwise a bad Result
///                       carrying an @ref ErrorDetail. The check does not act on an answer the namespace
///                       is uncertain of: an Uncertain lookup or References read is answered
///                       `Bad_InternalError` (`LookupAnswerUncertain` or `ReferencesAnswerUncertain`) with
///                       the Uncertain code as its cause. Runs on an unspecified worker thread.
///                       Never throws.
/// @see attach_subtype_async
void attach_exact_async(AddressSpace addressSpace, NodeId existingNode, NodeId expectedTypeDef,
  std::function<void(VoidResult)> onComplete) noexcept;

/// Verifies that an existing node's type definition equals or is a subtype of a base type.
///
/// Succeeds when the node's `HasTypeDefinition` target is @p baseTypeDef itself or any node reached
/// by following `HasSubtype` references from it.
///
/// @param addressSpace Address space that owns @p existingNode.
/// @param existingNode Node whose type definition is checked.
/// @param baseTypeDef  Base type definition the node's type must equal or derive from.
/// @param onComplete   Receives the outcome: success when the type is compatible, otherwise a bad
///                     Result carrying an @ref ErrorDetail. An Uncertain answer to the node's lookup or
///                     References read, or to the lookup or References read of a type on the walk up
///                     `HasSubtype`, is refused as @ref attach_exact_async refuses it; a type on the walk
///                     that cannot be found or read ends it with `Bad_TypeMismatch`. Runs on an
///                     unspecified worker thread. Never throws.
/// @see attach_exact_async
void attach_subtype_async(AddressSpace addressSpace, NodeId existingNode, NodeId baseTypeDef,
  std::function<void(VoidResult)> onComplete) noexcept;

/// @ingroup address_space
/// Which layer reports a bad VALUE quality: the Result, or the DataValue inside it.
enum class ValueQualityPolicy
{
  /// Two-layer, and the model the rest of the SDK and the documentation use: the read
  /// SUCCEEDS and the bad quality rides on `DataValue::status()`. The caller decides what a
  /// suspect reading means.
  PreserveQuality,
  /// Single-layer: a Bad-severity `DataValue::status()` is surfaced AS a bad Result carrying
  /// a `BadVariableStatus` @ref ErrorDetail, and no DataValue is handed back.
  FlattenBadQuality,
};

/// Reads a variable node's value through its @ref VariableAccessor, FLATTENING bad quality.
///
/// @warning This is not the two-layer read. A Bad-severity `DataValue::status()` - a
/// faulted transmitter, a stale reading - is reported as a BAD Result carrying a
/// `BadVariableStatus` @ref ErrorDetail, and the DataValue is NOT handed back. That is
/// deliberate, and it exists for callers that must not treat a suspect reading as a usable
/// number, such as alarm evaluation. It is NOT what a caller
/// reading a value expects, and it is not what @ref ua::BaseVariable::read_value_async does.
/// If you want the value with its quality intact, call @ref read_variable_data_value_async.
///
/// Uncertain qualities are NOT flattened - only Bad severity - so a DA substatus still
/// arrives as a Result carrying the DataValue.
///
/// @param addressSpace Address space that owns @p target.
/// @param target       Variable node whose value is read.
/// @param onComplete   Receives the outcome: the @ref DataValue, with the code the namespace answered
///                     the lookup and the read with, combined by `detail::combined_status` (a Good
///                     subcode, or an Uncertain code with the value it held, is kept); on failure, or on
///                     a Bad value quality, it carries an @ref ErrorDetail. A caller that acts on the
///                     value tests `is_good()`. Runs on an unspecified worker thread. Never throws.
/// @see read_variable_data_value_async, write_variable_value_async
void read_variable_value_async(
  AddressSpace addressSpace, NodeId target, std::function<void(DataValueResult)> onComplete) noexcept;

/// Reads a variable node's value through its @ref VariableAccessor, PRESERVING quality.
///
/// The two-layer read (OPC 10000-4): the Result reports whether the read itself worked, and
/// the quality of what was read rides on `DataValue::status()`. A faulted transmitter yields
/// a GOOD Result carrying a DataValue whose status is Bad - which is the whole point, because
/// a caller usually needs the last value AND the fact that it is suspect.
///
/// @param addressSpace Address space that owns @p target.
/// @param target       Variable node whose value is read.
/// @param onComplete   Receives the outcome: the @ref DataValue, whatever its quality, with the code the
///                     namespace answered the lookup and the read with, combined by
///                     `detail::combined_status` (a Good subcode, or an Uncertain code with the value it
///                     held, is kept); on failure of the READ it carries an @ref ErrorDetail. Runs on an
///                     unspecified worker thread. Never throws.
/// @see read_variable_value_async, write_variable_value_async
void read_variable_data_value_async(
  AddressSpace addressSpace, NodeId target, std::function<void(DataValueResult)> onComplete) noexcept;

/// Writes a variable node's value through its @ref VariableAccessor.
///
/// @param addressSpace Address space that owns @p target.
/// @param target       Variable node whose value is written.
/// @param value        New value to store.
/// @param onComplete   Receives the write's own answer, its code whatever it is. A lookup of @p target
///                     answered Uncertain is not written to: it is answered `Bad_InternalError`
///                     (`LookupAnswerUncertain`) with the Uncertain code as its cause. Runs on an
///                     unspecified worker thread. Never throws.
/// @see read_variable_value_async
void write_variable_value_async(AddressSpace addressSpace, NodeId target, DataValue value,
  std::function<void(VoidResult)> onComplete) noexcept;

/// Finds a child node by browse name and returns its @ref NodeId.
///
/// Follows references of type @p refType from @p parent and matches the first hierarchical child
/// whose browse name equals @p browseName.
///
/// @param addressSpace Address space that owns @p parent.
/// @param parent       Node from which the child reference is followed.
/// @param refType      Reference type to traverse (e.g. `HasComponent`, `HasProperty`).
/// @param browseName   Browse name the child must match.
/// @param onComplete   Receives the outcome: on success the Result holds the child NodeId; on
///                     failure (including no match) it carries an @ref ErrorDetail. The search does not act
///                     on an answer the namespace is uncertain of: an Uncertain answer to the lookup of
///                     @p parent, of a target, or to the References read is `Bad_InternalError`
///                     (`LookupAnswerUncertain` or `ReferencesAnswerUncertain`) with the Uncertain code as
///                     its cause. Runs on an unspecified worker thread. Never throws.
/// @see find_child_by_browse_name_async
void find_child_id_by_browse_name_async(AddressSpace addressSpace, NodeId parent, NodeId refType,
  QualifiedName browseName, std::function<void(NodeIdResult)> onComplete) noexcept;

/// Finds a child node by browse name and returns its @ref NodeAccessor.
///
/// Follows references of type @p refType from @p parent and matches the first hierarchical child
/// whose browse name equals @p browseName.
///
/// @param addressSpace Address space that owns @p parent.
/// @param parent       Node from which the child reference is followed.
/// @param refType      Reference type to traverse (e.g. `HasComponent`, `HasProperty`).
/// @param browseName   Browse name the child must match.
/// @param onComplete   Receives the outcome: on success the Result holds an accessor for the child, with
///                     the code the namespace answered its lookup with (a Good subcode, or an Uncertain code
///                     with the accessor, is kept); on failure (including no match) it carries an
///                     @ref ErrorDetail. Runs on an unspecified worker thread. Never throws.
/// @see find_child_id_by_browse_name_async
void find_child_by_browse_name_async(AddressSpace addressSpace, NodeId parent, NodeId refType,
  QualifiedName browseName, std::function<void(NodeAccessorResult)> onComplete) noexcept;

/// Finds a child method node by browse name and returns its @ref MethodAccessor.
///
/// Follows references of type @p refType from @p parent and matches the first method child whose
/// browse name equals @p browseName.
///
/// @param addressSpace Address space that owns @p parent.
/// @param parent       Node from which the child reference is followed.
/// @param refType      Reference type to traverse (typically `HasComponent`).
/// @param browseName   Browse name the method child must match.
/// @param onComplete   Receives the outcome: on success the Result holds an accessor for the method, with
///                     the code of the child's lookup as @ref find_child_by_browse_name_async gives it; on
///                     failure (including no match or a non-method child) it carries an
///                     @ref ErrorDetail. Runs on an unspecified worker thread. Never throws.
void find_child_method_accessor_by_browse_name_async(AddressSpace addressSpace, NodeId parent, NodeId refType,
  QualifiedName browseName, std::function<void(MethodAccessorResult)> onComplete) noexcept;

/// Finds a child variable node by browse name and returns its @ref VariableAccessor.
///
/// Follows references of type @p refType from @p parent and matches the first variable child whose
/// browse name equals @p browseName.
///
/// @param addressSpace Address space that owns @p parent.
/// @param parent       Node from which the child reference is followed.
/// @param refType      Reference type to traverse (e.g. `HasComponent`, `HasProperty`).
/// @param browseName   Browse name the variable child must match.
/// @param onComplete   Receives the outcome: on success the Result holds an accessor for the
///                     variable, with the code of the child's lookup as @ref find_child_by_browse_name_async
///                     gives it; on failure (including no match or a non-variable child) it carries
///                     an @ref ErrorDetail. Runs on an unspecified worker thread. Never throws.
void find_child_variable_accessor_by_browse_name_async(AddressSpace addressSpace, NodeId parent,
  NodeId refType, QualifiedName browseName, std::function<void(VariableAccessorResult)> onComplete) noexcept;

/// Resolves a child method node and installs a call handler on it.
///
/// Locates the method child of @p parent reached by a `HasComponent` reference whose browse name is
/// @p browseName, then registers @p handler as the source invoked when the method is called.
///
/// @param addressSpace Address space that owns @p parent.
/// @param parent       Node owning the method as a `HasComponent` child.
/// @param browseName   Browse name of the method child.
/// @param handler      Call handler invoked on each method call; takes ownership by value.
/// @param onComplete   Receives the outcome: the code the Method's MethodCallSource answered the install
///                     with, whatever it is (a Good subcode, an Uncertain or a Bad code with its
///                     @ref ErrorDetail), or the failure to find the Method. A lookup answered Uncertain is
///                     not acted on: it is answered `Bad_InternalError` (`LookupAnswerUncertain`) with the
///                     Uncertain code as its cause. Runs on an unspecified worker thread. Never throws.
void resolve_and_set_method_handler_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  MethodCallSource::CallHandler handler, std::function<void(VoidResult)> onComplete) noexcept;

/// Resolves a variable node and makes @p source the owner of its Value via @ref ExternalValueSource.
///
/// Every read and write of @p variableNode's Value then goes to @p source; a null @p source detaches it, and
/// the next write gives the Variable a new default source.
///
/// @param addressSpace Address space that owns @p variableNode.
/// @param variableNode Variable node whose Value @p source owns.
/// @param source       The source, or null.
/// @param onComplete   Receives the outcome: success when the source is attached, otherwise a bad Result
///                     carrying an @ref ErrorDetail (Bad_NotSupported when the node accepts no source). Runs
///                     on an unspecified worker thread. Never throws.
void resolve_and_set_value_source_async(AddressSpace addressSpace, NodeId variableNode,
  std::shared_ptr<ValueSource> source, std::function<void(VoidResult)> onComplete) noexcept;

/// Projects a MultiStateValueDiscrete Variable's current Value through its EnumValues Property, the
/// value OPC 10000-8 section 5.3.3.5 gives its ValueAsText Property.
///
/// The answer is the DisplayName of the EnumValues entry whose Value equals the Variable's current
/// numeric Value, carrying the Variable's own timestamps so a sampled ValueAsText changes when, and
/// only when, the Value it describes does. The Value is empty - with a Good status - when there is no
/// text to give: the Variable holds no value, a value with a Bad status, or a non-numeric one, or has
/// no EnumValues entry for it.
///
/// @param addressSpace Address space that owns @p dataItem.
/// @param dataItem     The MultiStateValueDiscrete Variable (not its ValueAsText Property).
/// @param onComplete   Receives the projected DataValue with the code the namespace answered the Variable's
///                     Value read and its EnumValues read with, combined by `detail::combined_status` (a
///                     Good subcode, or an Uncertain code with the value it held, is kept); or the failure of
///                     a read that answered no value. Runs on an unspecified worker thread; do not block it.
///                     Never throws.
void project_value_as_text_async(
  AddressSpace addressSpace, NodeId dataItem, std::function<void(DataValueResult)> onComplete) noexcept;

/// Makes a MultiStateValueDiscrete Variable's ValueAsText Property answer from the Variable's Value.
///
/// Installs a read handler on the Property's @ref ExternalValueSource that answers
/// @ref project_value_as_text_async for @p dataItem, so every reader of the Property - a Read, and a
/// MonitoredItem sampling it - sees the text for the Value as it is now rather than whatever was last
/// written to the Property, and an empty LocalizedText when there is none. The Property's
/// MinimumSamplingInterval becomes -1 (indeterminate), since its value now changes without being
/// written. The handler holds the address space weakly, so it keeps nothing alive.
/// Best-effort: a Variable without the Property, or a namespace whose nodes do not offer an
/// ExternalValueSource, is left as it is.
///
/// @param addressSpace Address space that owns @p dataItem.
/// @param dataItem     The MultiStateValueDiscrete Variable whose ValueAsText Property to wire.
/// @param onComplete   Receives the outcome: Good when the handler is installed or there was nothing to
///                     wire, otherwise the failure. Runs on an unspecified worker thread; do not block
///                     it. Never throws.
void wire_value_as_text_async(
  AddressSpace addressSpace, NodeId dataItem, std::function<void(VoidResult)> onComplete) noexcept;

// =====================================================================
// Generated-code support
// =====================================================================

/// The bodies of the accessors the type generator emits for instance handles.
///
/// Each generated accessor is a call to one of these, so a body is compiled once, in the SDK, instead of once
/// per accessor in every generated class. Not for application code: the signatures follow the generator.
namespace detail
{

/// The names a generated typed Property read reports in its ErrorDetails.
struct PropertyReadNames
{
  const char* owner;      ///< The handle class: the source of an `AddressSpaceGone` detail.
  const char* property;   ///< The Property's name as the accessor spells it, quoted in a type mismatch.
  const char* operation;  ///< The accessor: the source of a type-mismatch detail.
};

/// Reads the value of the Property @p browseName of @p parent as a @p T.
///
/// @tparam T The Property's C++ value type; one of the scalar built-in types the generator maps a DataType
///           to, each instantiated once in the SDK.
/// @param addressSpace      Address space that owns @p parent.
/// @param parent            The instance whose Property is read.
/// @param browseName        The Property's BrowseName.
/// @param holdsExpectedType The @ref Variant test for a @p T, such as `&Variant::is_boolean`.
/// @param names             The names the ErrorDetails carry.
/// @param onComplete        Receives the value with the code of the lookup and the read combined by
///                          @ref ua::detail::combined_status; that code alone when it is Bad, or when it is
///                          not Good and there is no value; `Bad_TypeMismatch` when the value is not a @p T;
///                          or the failure of the lookup or the read. Never throws.
template<typename T>
void read_property_value_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  bool (Variant::*holdsExpectedType)() const, PropertyReadNames names,
  std::function<void(Result<T>)> onComplete) noexcept;

extern template void read_property_value_async<bool>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<bool>)>) noexcept;
extern template void read_property_value_async<uint8_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<uint8_t>)>) noexcept;
extern template void read_property_value_async<int8_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<int8_t>)>) noexcept;
extern template void read_property_value_async<uint16_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<uint16_t>)>) noexcept;
extern template void read_property_value_async<uint32_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<uint32_t>)>) noexcept;
extern template void read_property_value_async<uint64_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<uint64_t>)>) noexcept;
extern template void read_property_value_async<int16_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<int16_t>)>) noexcept;
extern template void read_property_value_async<int32_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<int32_t>)>) noexcept;
extern template void read_property_value_async<int64_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<int64_t>)>) noexcept;
extern template void read_property_value_async<double>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<double>)>) noexcept;
extern template void read_property_value_async<float>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<float>)>) noexcept;
extern template void read_property_value_async<String>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<String>)>) noexcept;
extern template void read_property_value_async<DateTime>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<DateTime>)>) noexcept;
extern template void read_property_value_async<ByteString>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<ByteString>)>) noexcept;
extern template void read_property_value_async<Guid>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<Guid>)>) noexcept;
extern template void read_property_value_async<NodeId>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<NodeId>)>) noexcept;
extern template void read_property_value_async<StatusCode>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<StatusCode>)>) noexcept;
extern template void read_property_value_async<QualifiedName>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<QualifiedName>)>) noexcept;
extern template void read_property_value_async<LocalizedText>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<LocalizedText>)>) noexcept;

/// Writes @p value to the Property @p browseName of @p parent.
///
/// @param addressSpace Address space that owns @p parent.
/// @param parent       The instance whose Property is written.
/// @param browseName   The Property's BrowseName.
/// @param owner        The handle class: the source of an `AddressSpaceGone` detail.
/// @param value        The value to write.
/// @param onComplete   Receives the write's answer, as @ref write_variable_value_async gives it, or the
///                     failure of the lookup. Never throws.
void write_property_value_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  const char* owner, Variant value, std::function<void(VoidResult)> onComplete) noexcept;

/// A child that a generated child accessor found: the address space, locked, and the child's NodeId.
struct FoundChild
{
  AddressSpace addressSpace;  ///< The address space that owns the child.
  NodeId nodeId;              ///< The child.
};

/// Finds the child @p browseName of @p parent for a generated child accessor.
///
/// @param addressSpace Address space that owns @p parent.
/// @param parent       The instance whose child is found.
/// @param refType      The reference type from @p parent to the child.
/// @param browseName   The child's BrowseName.
/// @param owner        The handle class: the source of an `AddressSpaceGone` detail.
/// @param onComplete   Receives the child, or the failure of the lookup, an answer that is not Good
///                     included, or `Bad_Shutdown` when the address space is gone. Never throws.
void find_child_for_accessor_async(AddressSpace addressSpace, NodeId parent, NodeId refType,
  QualifiedName browseName, const char* owner, std::function<void(Result<FoundChild>)> onComplete) noexcept;

/// Finds the child @p browseName of @p parent and attaches a @p Handle to it.
///
/// @tparam Handle The child's generated handle class, or @ref Property.
/// @param onComplete Receives what `Handle::attach_async` answers, or the failure of
///                   @ref find_child_for_accessor_async. Never throws.
template<typename Handle>
void attach_child_async(AddressSpace addressSpace, NodeId parent, NodeId refType, QualifiedName browseName,
  const char* owner, std::function<void(Result<Handle>)> onComplete) noexcept
{
  find_child_for_accessor_async(std::move(addressSpace),
    std::move(parent),
    std::move(refType),
    std::move(browseName),
    owner,
    [onComplete = std::move(onComplete)](Result<FoundChild> found) mutable
    {
      if (!found.has_value())
      {
        onComplete(Result<Handle>{found.status_code(), found.shared_detail()});
        return;
      }
      auto& child = found.value();
      Handle::attach_async(std::move(child.addressSpace), std::move(child.nodeId), std::move(onComplete));
    });
}

/// Checks a generated method-handler registration before it is made.
///
/// An unbound handle answers @p done, when there is one, with `Bad_InvalidState`. Otherwise a null @p done
/// is replaced by one that logs the outcome (@ref ua::detail::completion_or_log), and an empty handler is
/// answered `Bad_InvalidArgument` (`MethodHandlerEmpty`).
///
/// @param addressSpace The handle's address space; empty for an unbound handle.
/// @param hasHandler   Whether the handler to register is set.
/// @param owner        The handle class: the source of a `MethodHandlerEmpty` detail.
/// @param operation    The setter, named in the log when there is no @p done.
/// @param done         The setter's completion; replaced when null.
/// @return Whether the registration goes ahead; when it does not, @p done has been answered.
[[nodiscard]] bool begin_handler_registration(const optional<AddressSpace>& addressSpace, bool hasHandler,
  const char* owner, const char* operation, std::function<void(VoidResult)>& done) noexcept;

}  // namespace detail

}  // namespace instance_utils
}  // namespace ua

#endif  // UA_INSTANCE_UTILS_H
