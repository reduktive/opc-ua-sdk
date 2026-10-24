// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Tier-2 public `TypedAccess` handle: the typed-value convenience sugar of a managed
///        @ref ua::client::Connection (client design section 7.2A), reached via `Connection::typed()`.
/// @ingroup client

#ifndef UA_TYPED_ACCESS_H
#define UA_TYPED_ACCESS_H

#include "ua_attribute_id.h"
#include "ua_access_level_ex_type.h"
#include "ua_argument.h"
#include "ua_browse_cursor.h"
#include "ua_browse_path_result.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_call_method_result.h"
#include "ua_data_value.h"
#include "ua_expanded_node_id.h"
#include "ua_node_id.h"
#include "ua_numeric_range_builder.h"
#include "ua_qualified_name.h"
#include "ua_relative_path.h"
#include "ua_result.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_translated_node_id.h"
#include "ua_variant.h"

#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

namespace ua::client
{

namespace detail
{
class ConnectionImpl;
struct ConnectionHandleFactory;

/// Boxes one method-call input into a @ref ua::Variant for @ref args.
///
/// String-like inputs (`const char*`, `std::string`, `string_view`) route through @ref ua::String -
/// a @ref ua::Variant has no `const char*` / `std::string` constructor. A value that is already a
/// @ref ua::Variant passes through unchanged. Everything else forwards to the matching @ref
/// ua::Variant value constructor (a `int32_t`, `double`, `bool`, `NodeId`, ...).
///
/// @tparam T Deduced input type.
/// @param value The native input to box.
/// @return A @ref ua::Variant holding @p value.
template<class T>
ua::Variant to_call_arg(T&& value)
{
  using U = std::remove_cvref_t<T>;
  if constexpr (std::is_same_v<U, ua::Variant>)
  {
    return ua::Variant{std::forward<T>(value)};
  }
  else if constexpr (!ua::IsBuiltInScalarType<U> && std::is_constructible_v<ua::String, T>)
  {
    return ua::Variant{ua::String{std::forward<T>(value)}};
  }
  else
  {
    static_assert(std::is_constructible_v<ua::Variant, T>,
      "to_call_arg: unsupported method-argument type - no ua::Variant constructor accepts it. Pass a "
      "built-in OPC UA scalar (int32_t, double, bool, NodeId, ua::String, ...), a string "
      "(const char*/std::string/std::string_view, boxed through ua::String), or an explicit "
      "ua::Variant. Note: char, long long and unsigned long long are NOT built-in OPC UA scalar types "
      "- use int8_t/uint8_t or int64_t/uint64_t.");
    return ua::Variant{std::forward<T>(value)};
  }
}

/// The typed answer of a Value read: @p dataValue's value decoded to `T`, with the one code the read
/// answered.
///
/// The code is `ua::detail::combined_status` of @p outer (the status of the result that holds the
/// DataValue) and the DataValue's own status (Good when it has none), so neither a Good subcode nor an
/// Uncertain code is lost. A Bad code is answered without decoding the value. An Uncertain code with a
/// null value is answered without a value. Otherwise the value is decoded; a value that does not decode
/// to `T` is answered Bad_TypeMismatch (or Bad_NotSupported for a `T` that is not a built-in type), and a
/// decoded value is answered with the code: a Good subcode or an Uncertain code is kept with it.
///
/// @tparam T Native C++ type the value Variant is decoded to (via @ref ua::Variant::to).
/// @param outer     The status of the result holding @p dataValue.
/// @param dataValue The DataValue read.
/// @return The decoded value with the code, or the code without a value.
template<class T>
ua::Result<T> typed_value(const ua::StatusCode& outer, const ua::DataValue& dataValue)
{
  const ua::StatusCode code =
    ua::detail::combined_status(outer, dataValue.status().value_or(ua::StatusCode{ua::Status::Good}));
  if (code.is_bad())
  {
    return ua::Result<T>{code};
  }
  if (dataValue.value().empty() && !code.is_good())
  {
    return ua::Result<T>{code};
  }
  ua::Result<T> decoded = dataValue.value().template to<T>();
  if (!decoded.has_value())
  {
    return decoded;
  }
  return ua::detail::held<T>(std::move(decoded).value(), code);
}

/// The typed answer of a Value read whose Result may hold no DataValue: @p result's code when it holds
/// none, otherwise @ref typed_value of its DataValue with its code as the outer status.
///
/// @tparam T Native C++ type the value Variant is decoded to.
/// @param result The result of the DataValue read.
/// @return The decoded value with the code, or the code without a value.
template<class T>
ua::Result<T> typed_value(const ua::Result<ua::DataValue>& result)
{
  if (!result.has_value())
  {
    return ua::Result<T>{result.status_code(), result.shared_detail()};
  }
  return typed_value<T>(result.status_code(), result.value());
}
}  // namespace detail

class Connection;

/// Optional Variable metadata whose absence has normative meaning.
///
/// `accessLevelEx == std::nullopt` means the Server did not provide the optional
/// AccessLevelEx Attribute; callers must not infer that access is atomic.
/// @ingroup client
struct VariableMetadata
{
  /// The access level ex.
  std::optional<ua::AccessLevelExType> accessLevelEx;

  /// @return True when the requested condition is satisfied.
  /// Returns or updates the nonatomic read.
  [[nodiscard]] bool nonatomic_read() const noexcept
  {
    return accessLevelEx && accessLevelEx->test(ua::AccessLevelExType::Bit::NonatomicRead);
  }

  /// @return True when the requested condition is satisfied.
  /// Returns or updates the nonatomic write.
  [[nodiscard]] bool nonatomic_write() const noexcept
  {
    return accessLevelEx && accessLevelEx->test(ua::AccessLevelExType::Bit::NonatomicWrite);
  }
};

/// Introspected Method input metadata (OPC 10000-3 section section 5.7.1-5.7.3).
/// @ingroup client
struct MethodInputMetadata
{
  /// The input arguments.
  std::vector<ua::Argument> inputArguments;
  /// The trailing optional count.
  std::size_t trailingOptionalCount = 0;
};

/// The typed-value convenience surface of a managed @ref Connection (section 7.2A) - pure sugar over the
/// wire-shaped service set.
///
/// A lightweight move-only value handle over the same `ConnectionImpl` as its parent @ref Connection
/// (reached via `Connection::typed()`, parallel to `Connection::service_requests()`). It owns no
/// state of its own and is not directly constructible; every method builds a wire request from typed
/// inputs and forwards it through `ConnectionImpl`'s already-built, gated, ErrorDetail-wrapping
/// wire-op funnel (section 7.2 `invoke_wire_op`), then decodes the response into typed outputs. The single
/// tier-1 gate + NamespaceTable remap + `ErrorDetail` wrap (section 7.10) are applied ONCE inside the
/// funnel, so this handle never double-wraps.
///
/// Each operation follows the async / sync / try_sync triple (section 7.0):
///  - `*_async`    -  never throws; the callback receives the typed `Result` on the executor.
///  - `*_sync`     -  blocks; returns the bare value; throws `UaException` when the `Result` is not Good
///                    (an Uncertain answer included). A Good subcode on the answer is not returned; the
///                    `try_*_sync` form returns it. A `DataValue` form puts a Good subcode of the `Result` on
///                    the DataValue's status when that is plain Good.
///  - `try_*_sync` -  blocks; returns the typed `Result`; never throws.
///
/// A Good subcode or an Uncertain code the server answers is never replaced with plain Good. Where the
/// answer has two layers (a `Result<DataValue>`, a vector of per-item results) the ServiceResult is the
/// status of the outer `Result`; where it has one place, that place carries the combined code
/// (`ua::detail::combined_status`).
///
/// @warning The `*_sync` / `try_*_sync` variants block the calling thread on the async completion.
///          They MUST NOT be called from the Connection's executor thread.
///
/// @note Public methods may be called from any thread; the underlying `ConnectionImpl` posts to its
///       private strand internally.
/// @ingroup client
class TypedAccess
{
public:
  TypedAccess(const TypedAccess&) = delete;
  TypedAccess& operator=(const TypedAccess&) = delete;
  /// Returns or updates the typed access.
  TypedAccess(TypedAccess&&) noexcept = default;
  /// @return A reference to this object.
  /// Supports value-handle comparison or assignment.
  TypedAccess& operator=(TypedAccess&&) noexcept = default;
  ~TypedAccess() = default;

  // ============ Arbitrary attribute ============

  /// Reads a single arbitrary attribute of a Node, decoded to a @ref ua::DataValue.
  ///
  /// @param node Target node identifier.
  /// @param attribute Attribute to access.
  /// @param callback Completion callback that receives the operation result.
  /// Composes a single-node Read of @p attribute and returns `results[0]`. The outer Result is bad
  /// only on a service-level failure and carries a Good subcode or an Uncertain ServiceResult; the value
  /// quality lives on `DataValue::status()` (two-layer).
  void read_attribute_async(ua::NodeId node, ua::AttributeId attribute,
    std::function<void(ua::Result<ua::DataValue>)> callback) noexcept;
  /// Reads a single arbitrary attribute using @p indexRange.
  ///
  /// @param node Target node identifier.
  /// @param attribute Attribute to access.
  /// @param indexRange The index range.
  /// @param callback Completion callback that receives the operation result.
  /// The raw-string convenience is validated through @ref NumericRangeBuilder before any wire Read. Callers
  /// constructing ranges programmatically should use that builder and pass its successful wire value here.
  ///
  /// The returned @ref ua::DataValue is not resized to the requested range: Part 4 section 7.27 permits an
  /// upper-bound overflow to return a shorter, Good partial result. A lower-bound overflow remains a
  /// per-item `Bad_IndexRangeNoData` on `DataValue::status()`.
  void read_attribute_async(ua::NodeId node, ua::AttributeId attribute, ua::String indexRange,
    std::function<void(ua::Result<ua::DataValue>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param attribute Attribute to access.
  /// @return The requested value.
  /// Synchronously read attribute.
  ua::DataValue read_attribute_sync(ua::NodeId node, ua::AttributeId attribute);
  /// @param node Target node identifier.
  /// @param attribute Attribute to access.
  /// @param indexRange The index range.
  /// @return The requested value.
  /// Synchronously read attribute.
  ua::DataValue read_attribute_sync(ua::NodeId node, ua::AttributeId attribute, ua::String indexRange);
  /// @param node Target node identifier.
  /// @param attribute Attribute to access.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read attribute sync without throwing.
  ua::Result<ua::DataValue> try_read_attribute_sync(ua::NodeId node, ua::AttributeId attribute) noexcept;
  /// @param node Target node identifier.
  /// @param attribute Attribute to access.
  /// @param indexRange The index range.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read attribute sync without throwing.
  ua::Result<ua::DataValue> try_read_attribute_sync(
    ua::NodeId node, ua::AttributeId attribute, ua::String indexRange) noexcept;

  /// Reads a Variable Value using an explicitly requested OPC UA DataEncoding.
  ///
  /// @param node Target node identifier.
  /// @param dataEncoding The data encoding.
  /// @param callback Completion callback that receives the operation result.
  /// The returned ExtensionObject body encoding is checked against @p dataEncoding.
  /// A server that returns a different encoding is rejected with BadDecodingError.
  /// This dedicated Value-only API prevents accidentally setting DataEncoding on a
  /// non-Value attribute, which Part 4 defines as an error.
  void read_value_with_encoding_async(ua::NodeId node, ua::QualifiedName dataEncoding,
    std::function<void(ua::Result<ua::DataValue>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param dataEncoding The data encoding.
  /// @return The requested value.
  /// Synchronously read value with encoding.
  ua::DataValue read_value_with_encoding_sync(ua::NodeId node, ua::QualifiedName dataEncoding);
  /// @param node Target node identifier.
  /// @param dataEncoding The data encoding.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read value with encoding sync without throwing.
  ua::Result<ua::DataValue> try_read_value_with_encoding_sync(
    ua::NodeId node, ua::QualifiedName dataEncoding) noexcept;

  /// Reads the optional metadata governing a Variable's access semantics.
  ///
  /// @param node Target node identifier.
  /// @param callback Completion callback that receives the operation result.
  /// A per-item `BadAttributeIdInvalid` for AccessLevelEx is decoded as
  /// `VariableMetadata::accessLevelEx == nullopt`; other failures remain bad. A Good subcode or an Uncertain
  /// code of the read (the ServiceResult and the attribute's status combined) is the status of the result
  /// holding the metadata; an Uncertain attribute with no value is answered with its code and no metadata.
  void read_variable_metadata_async(
    ua::NodeId node, std::function<void(ua::Result<VariableMetadata>)> callback) noexcept;
  /// @param node Target node identifier.
  /// @return The requested value.
  /// Synchronously read variable metadata.
  /// A Good subcode on the answer is not returned; try_read_variable_metadata_sync() returns it.
  VariableMetadata read_variable_metadata_sync(ua::NodeId node);
  /// @param node Target node identifier.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read variable metadata sync without throwing.
  ua::Result<VariableMetadata> try_read_variable_metadata_sync(ua::NodeId node) noexcept;

  /// Writes a single arbitrary attribute of a Node from a @ref ua::DataValue.
  ///
  /// @param node Target node identifier.
  /// @param attribute Attribute to access.
  /// @param value Value to write or evaluate.
  /// @param callback Completion callback that receives the operation result.
  /// Composes a single Write and flattens the per-item write status into the returned `VoidResult`, combined
  /// with the ServiceResult: a Good subcode (such as Good_CompletesAsynchronously) or an Uncertain code of
  /// either is kept. A Value write first reads the Variable's ValueRank and ArrayDimensions; an Uncertain
  /// answer to that read is refused with Bad_InternalError (`ReadAnswerUncertain`).
  void write_attribute_async(ua::NodeId node, ua::AttributeId attribute, ua::DataValue value,
    std::function<void(ua::VoidResult)> callback) noexcept;
  /// Writes a single arbitrary attribute using @p indexRange.
  ///
  /// @param node Target node identifier.
  /// @param attribute Attribute to access.
  /// @param indexRange The index range.
  /// @param value Value to write or evaluate.
  /// @param callback Completion callback that receives the operation result.
  /// The range is syntax-validated locally. For a Value write, an enabled address-space cache that has
  /// observed AccessLevelEx.WriteFullArrayOnly rejects the operation before Write I/O; without cached
  /// knowledge the request falls through to the server.
  void write_attribute_async(ua::NodeId node, ua::AttributeId attribute, ua::String indexRange,
    ua::DataValue value, std::function<void(ua::VoidResult)> callback) noexcept;
  /// @param node Target node identifier.
  /// @param attribute Attribute to access.
  /// @param value Value to write or evaluate.
  /// Synchronously write attribute.
  void write_attribute_sync(ua::NodeId node, ua::AttributeId attribute, ua::DataValue value);
  /// @param node Target node identifier.
  /// @param attribute Attribute to access.
  /// @param indexRange The index range.
  /// @param value Value to write or evaluate.
  /// Synchronously write attribute.
  void write_attribute_sync(
    ua::NodeId node, ua::AttributeId attribute, ua::String indexRange, ua::DataValue value);
  /// @param node Target node identifier.
  /// @param attribute Attribute to access.
  /// @param value Value to write or evaluate.
  /// @return The requested value.
  /// Attempts to write attribute sync without throwing.
  ua::VoidResult try_write_attribute_sync(
    ua::NodeId node, ua::AttributeId attribute, ua::DataValue value) noexcept;
  /// @param node Target node identifier.
  /// @param attribute Attribute to access.
  /// @param indexRange The index range.
  /// @param value Value to write or evaluate.
  /// @return The requested value.
  /// Attempts to write attribute sync without throwing.
  ua::VoidResult try_write_attribute_sync(
    ua::NodeId node, ua::AttributeId attribute, ua::String indexRange, ua::DataValue value) noexcept;

  // ============ Bulk value reads / writes (single round-trip) ============

  /// Reads the Value attribute of many Nodes in a single Read round-trip.
  ///
  /// @param nodes The nodes.
  /// @param callback Completion callback that receives the operation result.
  /// The result vector is positional (`results[i]` is `nodes[i]`'s DataValue); the outer Result is
  /// bad only on a service-level failure and carries a Good subcode or an Uncertain ServiceResult. Per-node
  /// value quality is on each `DataValue::status()`.
  void read_values_async(std::vector<ua::NodeId> nodes,
    std::function<void(ua::Result<std::vector<ua::DataValue>>)> callback) noexcept;
  /// @param nodes The nodes.
  /// @return The requested value.
  /// Synchronously read values.
  /// A Good subcode on the answer is not returned; try_read_values_sync() returns it.
  std::vector<ua::DataValue> read_values_sync(std::vector<ua::NodeId> nodes);
  /// @param nodes The nodes.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read values sync without throwing.
  ua::Result<std::vector<ua::DataValue>> try_read_values_sync(std::vector<ua::NodeId> nodes) noexcept;

  /// Reads Values in one batch after inspecting every participant's AccessLevelEx.
  ///
  /// @param nodes The nodes.
  /// @param callback Completion callback that receives the operation result.
  /// When any present AccessLevelEx sets NonatomicRead, the values are still returned
  /// unchanged and `ConnectionObserver::on_advisory_diagnostic` is emitted to state
  /// that internal batch consistency is not guaranteed. Missing AccessLevelEx remains
  /// unknown and does not fabricate an atomicity guarantee. An Uncertain answer to the AccessLevelEx read
  /// is refused with Bad_InternalError (`ReadAnswerUncertain`), as a Bad one fails the read.
  void read_values_atomicity_checked_async(std::vector<ua::NodeId> nodes,
    std::function<void(ua::Result<std::vector<ua::DataValue>>)> callback) noexcept;
  /// @param nodes The nodes.
  /// @return The requested value.
  /// Synchronously read values atomicity checked.
  /// A Good subcode on the answer is not returned; try_read_values_atomicity_checked_sync() returns it.
  std::vector<ua::DataValue> read_values_atomicity_checked_sync(std::vector<ua::NodeId> nodes);
  /// @param nodes The nodes.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to read values atomicity checked sync without throwing.
  ua::Result<std::vector<ua::DataValue>> try_read_values_atomicity_checked_sync(
    std::vector<ua::NodeId> nodes) noexcept;

  /// Follows forward HasDictionaryEntry references and returns only conformant Object targets.
  ///
  /// @param source The source.
  /// @param callback Completion callback that receives the operation result.
  /// Every target's TypeDefinition is verified as DictionaryEntryType or a subtype. Non-conformant
  /// targets are skipped and reported through `ConnectionObserver::on_advisory_diagnostic`; multiple
  /// valid targets retain browse order. A Good subcode or an Uncertain code of the HasDictionaryEntry pages
  /// is the status of the result; an Uncertain answer while checking a target's supertypes is refused with
  /// Bad_InternalError (`ReferencesAnswerUncertain`).
  void dictionary_entries_for_async(
    ua::NodeId source, std::function<void(ua::Result<std::vector<BrowseCursor::Entry>>)> callback) noexcept;
  /// @param source The source.
  /// @return The requested value.
  /// Synchronously dictionary entries for.
  /// A Good subcode on the answer is not returned; try_dictionary_entries_for_sync() returns it.
  std::vector<BrowseCursor::Entry> dictionary_entries_for_sync(ua::NodeId source);
  /// @param source The source.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to dictionary entries for sync without throwing.
  ua::Result<std::vector<BrowseCursor::Entry>> try_dictionary_entries_for_sync(ua::NodeId source) noexcept;

  /// Writes the Value attribute of many (Node, value) pairs in a single Write round-trip.
  ///
  /// @param pairs The pairs.
  /// @param callback Completion callback that receives the operation result.
  /// The result vector is positional (`results[i]` is the write status of `pairs[i]`, a Good subcode
  /// kept); the outer Result is bad only on a service-level failure and carries a Good subcode or an
  /// Uncertain ServiceResult.
  void write_values_async(std::vector<std::pair<ua::NodeId, ua::Variant>> pairs,
    std::function<void(ua::Result<std::vector<ua::VoidResult>>)> callback) noexcept;
  /// @param pairs The pairs.
  /// @return The requested value.
  /// Synchronously write values.
  /// A Good subcode on the answer is not returned; try_write_values_sync() returns it.
  std::vector<ua::VoidResult> write_values_sync(std::vector<std::pair<ua::NodeId, ua::Variant>> pairs);
  /// @param pairs The pairs.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to write values sync without throwing.
  ua::Result<std::vector<ua::VoidResult>> try_write_values_sync(
    std::vector<std::pair<ua::NodeId, ua::Variant>> pairs) noexcept;

  // ============ Typed bulk read (T) ============

  /// Reads the Value attribute of many Nodes and decodes each to a native `T` via @ref
  /// ua::Variant::to.
  ///
  /// Per-element `Result<T>` preserves the two-layer model: an element is bad if its DataValue was Bad
  /// (surfaced AS the element Result carrying that per-op status code, WITHOUT decoding the Variant -
  /// CL-ATTR-005/006) OR the value did not decode to a `T`; the outer `Result` is bad only on a
  /// service-level failure. An element whose DataValue status is a Good subcode or an Uncertain code holds
  /// the decoded value with that code; an Uncertain DataValue with a null value is an element with the
  /// code and no value (@ref detail::typed_value). The outer `Result` carries the Read's ServiceResult when
  /// it is a Good subcode or an Uncertain code. Callers needing the per-element value quality distinct
  /// from the decode use the `Result<std::vector<DataValue>>` form. Header-inline: composes the
  /// non-templated @ref read_values_async then decodes.
  ///
  /// @tparam T Native C++ type each Node's Value is decoded to.
  /// @param nodes Nodes whose Value attributes are read.
  /// @param callback Completion callback receiving per-node decode results.
  template<class T>
  void read_values_async(std::vector<ua::NodeId> nodes,
    std::function<void(ua::Result<std::vector<ua::Result<T>>>)> callback) noexcept
  {
    read_values_async(std::move(nodes),
      [callback = std::move(callback)](ua::Result<std::vector<ua::DataValue>> result) mutable
      {
        if (!result.has_value())
        {
          // Single-wrap: propagate the funnel's service-level ErrorDetail unchanged.
          callback(ua::Result<std::vector<ua::Result<T>>>{result.status_code(), result.shared_detail()});
          return;
        }
        std::vector<ua::Result<T>> decoded;
        decoded.reserve(result.value().size());
        for (const auto& dataValue : result.value())
        {
          // Bad-quality short-circuit (CL-ATTR-005/006): a Bad per-op DataValue.status_code is
          // surfaced AS the element Result carrying that code, WITHOUT decoding the Variant; a Good
          // subcode or an Uncertain code stays with the decoded value.
          decoded.push_back(detail::typed_value<T>(ua::StatusCode{ua::Status::Good}, dataValue));
        }
        callback(ua::detail::held(std::move(decoded), result.status_code()));
      });
  }

  template<class T>
  /// @param nodes The nodes.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Synchronously read values. A Good subcode on the answer is not returned; try_read_values_sync()
  /// returns it.
  /// @throws ua::UaException when the Read's ServiceResult is not Good.
  std::vector<ua::Result<T>> read_values_sync(std::vector<ua::NodeId> nodes)
  {
    return ua::detail::good_value(try_read_values_sync<T>(std::move(nodes)));
  }

  /// @param nodes The nodes.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Blocking `try_*` bridge over @ref read_values_async<T>; never throws. Refused with `Bad_WouldBlock`
  /// on a thread of the Connection's executor, which is where the answer is produced. The template
  /// keeps the answer; the wait itself is `wait_sync`, out of line.
  template<class T>
  ua::Result<std::vector<ua::Result<T>>> try_read_values_sync(std::vector<ua::NodeId> nodes) noexcept
  {
    using ResultT = ua::Result<std::vector<ua::Result<T>>>;
    try
    {
      auto answer = std::make_shared<std::optional<ResultT>>();
      auto waited = wait_sync(
        [this, &nodes, answer](std::function<void()> done)
        {
          read_values_async<T>(std::move(nodes),
            [answer, done = std::move(done)](ResultT result) mutable
            {
              *answer = std::move(result);
              done();
            });
        });
      if (waited.is_bad())
      {
        return ResultT{waited.status_code()};
      }
      return std::move(**answer);
    }
    catch (...)
    {
      return ResultT{ua::Status::BadInvalidState};
    }
  }

  // ============ Translate browse path ============

  /// Resolves a relative path under a start node in one TranslateBrowsePathsToNodeIds round-trip and
  /// returns every target the server found, in the server's order. When several match, OPC 10000-4
  /// 5.8.4.1 puts first the one based on the start node's type definition, if there is one; the
  /// response does not say whether there is.
  ///
  /// A service-Good response with no target is a bad `Result{Bad_NoMatch}`, and a bad per-path status
  /// is the bad Result. A Good subcode or an Uncertain code of the path's status or of the ServiceResult
  /// (combined) is the status of the Result holding the targets. A PARTIAL or cross-server target is DATA,
  /// not an error: its
  /// @ref TranslatedNodeId::is_fully_resolved or @ref TranslatedNodeId::is_local is false, and the SDK
  /// never connects to another server to resolve the rest. For one local node, use @ref resolve_path_async.
  /// @param start        The start node.
  /// @param relativePath The relative path; its last element must name a target.
  /// @param callback     Receives every target, in the server's order, or the failure. Never throws.
  void translate_browse_path_async(ua::NodeId start, ua::RelativePath relativePath,
    std::function<void(ua::Result<std::vector<TranslatedNodeId>>)> callback) noexcept;
  /// Resolves a relative path to every target, blocking until complete. As @ref translate_browse_path_async.
  /// @param start        The start node.
  /// @param relativePath The relative path.
  /// @return Every target.
  /// @throws ua::UaException with the failure, including `Bad_NoMatch` for no target.
  /// A Good subcode on the answer is not returned; try_translate_browse_path_sync() returns it.
  std::vector<TranslatedNodeId> translate_browse_path_sync(ua::NodeId start, ua::RelativePath relativePath);
  /// Resolves a relative path to every target, blocking until complete. As @ref translate_browse_path_async.
  /// @param start        The start node.
  /// @param relativePath The relative path.
  /// @return Every target, or the failure. Never throws.
  ua::Result<std::vector<TranslatedNodeId>> try_translate_browse_path_sync(
    ua::NodeId start, ua::RelativePath relativePath) noexcept;

  /// Resolves a local @ref ua::ExpandedNodeId start against the current Session NamespaceTable, then
  /// translates as the bare-NodeId overload does (CL-VIEW-020). A non-zero ServerIndex names another
  /// Server and fails locally with `Bad_InvalidArgument`; connect to that Server first.
  /// @param start        The start node.
  /// @param relativePath The relative path.
  /// @param callback     Receives every target, or the failure. Never throws.
  void translate_browse_path_async(ua::ExpandedNodeId start, ua::RelativePath relativePath,
    std::function<void(ua::Result<std::vector<TranslatedNodeId>>)> callback) noexcept;
  /// As the asynchronous ExpandedNodeId overload, blocking until complete.
  /// @param start        The start node.
  /// @param relativePath The relative path.
  /// @return Every target.
  /// @throws ua::UaException with the failure.
  /// A Good subcode on the answer is not returned; try_translate_browse_path_sync() returns it.
  std::vector<TranslatedNodeId> translate_browse_path_sync(
    ua::ExpandedNodeId start, ua::RelativePath relativePath);
  /// As the asynchronous ExpandedNodeId overload, blocking until complete.
  /// @param start        The start node.
  /// @param relativePath The relative path.
  /// @return Every target, or the failure. Never throws.
  ua::Result<std::vector<TranslatedNodeId>> try_translate_browse_path_sync(
    ua::ExpandedNodeId start, ua::RelativePath relativePath) noexcept;

  /// Resolves a relative path to the one local node it names: the common case of finding a node by its
  /// BrowseNames (see @ref ua::hierarchical_path).
  ///
  /// Succeeds only for exactly one target that is fully resolved and local; it never chooses among
  /// several. A client programming against a type, whose instance may add a node with the same
  /// BrowseName, takes the first target of @ref translate_browse_path_async (OPC 10000-4 5.8.4.1).
  /// Otherwise it fails, and the @ref ua::ErrorDetail names the case. `Bad_NoMatch` for no target;
  /// `Bad_TooManyMatches` with the count (`count.actual`) for several; `Bad_NoMatch` for a partial or
  /// cross-server target, naming its server index (`server.index`) and the first unresolved element
  /// (`index`, `node.browse_name`). A Good subcode or an Uncertain code of the translation is the status of
  /// the Result holding the node.
  /// @param start        The start node.
  /// @param relativePath The relative path; its last element must name a target.
  /// @param callback     Receives the node, or the failure. Never throws.
  void resolve_path_async(
    ua::NodeId start, ua::RelativePath relativePath, std::function<void(ua::NodeIdResult)> callback) noexcept;
  /// Resolves a relative path to the one local node it names, blocking until complete. As
  /// @ref resolve_path_async.
  /// @param start        The start node.
  /// @param relativePath The relative path.
  /// @return The node.
  /// @throws ua::UaException with the failure.
  /// A Good subcode on the answer is not returned; try_resolve_path_sync() returns it.
  ua::NodeId resolve_path_sync(ua::NodeId start, ua::RelativePath relativePath);
  /// Resolves a relative path to the one local node it names, blocking until complete. As
  /// @ref resolve_path_async.
  /// @param start        The start node.
  /// @param relativePath The relative path.
  /// @return The node, or the failure. Never throws.
  ua::NodeIdResult try_resolve_path_sync(ua::NodeId start, ua::RelativePath relativePath) noexcept;

  // ============ Method call ============

  /// Invokes a Method on an Object, passing @p arguments as the positional input arguments.
  ///
  /// Composes a single-method `CallRequest` (`object`, `method`, `inputArguments = arguments`) and
  /// returns the per-method @ref ua::CallResult (= `Result<CallMethodResult>`). The outer Result is
  /// bad only on a service-level failure and carries a Good subcode or an Uncertain ServiceResult; the
  /// per-method status and output arguments are on the inner @ref ua::CallResult, whose status is the
  /// per-method statusCode as the server sent it (a Good subcode or an Uncertain code included, holding the
  /// CallMethodResult). Build @p arguments from native values with the free helper @ref args.
  ///
  /// Structured arguments are preflighted against the Method's InputArguments metadata and the
  /// per-Connection TypeResolver. Their concrete DataType must equal or subtype the declared DataType, and
  /// opaque structures require a registered encoding-to-DataType mapping; an Uncertain answer for that
  /// metadata is refused with Bad_InternalError (`ReadAnswerUncertain`). Non-structured arguments remain
  /// verbatim.
  /// @param object Object that owns the Method.
  /// @param method Method node to invoke.
  /// @param arguments Positional input arguments.
  /// @param callback Completion callback receiving the per-method result.
  void call_method_async(ua::NodeId object, ua::NodeId method, std::vector<ua::Variant> arguments,
    std::function<void(ua::Result<ua::CallResult>)> callback) noexcept;
  /// @param object The object.
  /// @param method The method.
  /// @param arguments The arguments.
  /// @return The requested value.
  /// Synchronously call method.
  /// A Good subcode on the answer is not returned; try_call_method_sync() returns it.
  ua::CallResult call_method_sync(ua::NodeId object, ua::NodeId method, std::vector<ua::Variant> arguments);
  /// @param object The object.
  /// @param method The method.
  /// @param arguments The arguments.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to call method sync without throwing.
  ua::Result<ua::CallResult> try_call_method_sync(
    ua::NodeId object, ua::NodeId method, std::vector<ua::Variant> arguments) noexcept;

  /// Reads a Method's InputArguments Property and correlates
  /// @param method The method.
  /// @param callback Completion callback that receives the operation result.
  /// HasOptionalInputArgumentDescription targets by BrowseName. Optional arguments must form a trailing
  /// suffix; malformed metadata fails with Bad_DecodingError. A Good subcode or an Uncertain code of the
  /// References or of the InputArguments read is the status of the Result holding the metadata; an
  /// Uncertain InputArguments read with no value is answered with its code and no metadata.
  void inspect_method_inputs_async(
    ua::NodeId method, std::function<void(ua::Result<MethodInputMetadata>)> callback) noexcept;
  /// @param method The method.
  /// @return The requested value.
  /// Synchronously inspect method inputs.
  /// A Good subcode on the answer is not returned; try_inspect_method_inputs_sync() returns it.
  MethodInputMetadata inspect_method_inputs_sync(ua::NodeId method);
  /// @param method The method.
  /// @return The operation result, including status and diagnostic detail on failure.
  /// Attempts to inspect method inputs sync without throwing.
  ua::Result<MethodInputMetadata> try_inspect_method_inputs_sync(ua::NodeId method) noexcept;

  // ============ Browse ============

  /// Opens a forward-iterator @ref BrowseCursor over the references from @p start (section 7.5).
  ///
  /// Returns synchronously: the cursor is constructed unstarted (holding a weak wire interface + the walk
  /// parameters), and the first @ref BrowseCursor::next_async issues the initial Browse; page exhaustion
  /// with a held continuation point drives BrowseNext transparently. Dropping the cursor (or
  /// `close_async`) releases the server continuation point. A cursor from a moved-from handle yields a
  /// bad Result on first advance.
  ///
  /// @param start   The node to browse the references of.
  /// @param options The walk parameters (direction / reference type / node-class mask / result mask).
  /// @return A move-only @ref BrowseCursor.
  [[nodiscard]] BrowseCursor browse(ua::NodeId start, BrowseOptions options = {});

  // ============ DEFERRED surface (declared in section 7.2A; built in later slices) ============
  //   - EventNotification::field_as<T> typed event-field access (Slice 10a  -  EventSubscriber)

private:
  friend class Connection;
  friend struct ua::client::detail::ConnectionHandleFactory;

  explicit TypedAccess(std::shared_ptr<detail::ConnectionImpl> impl);

  /// Calls @p start with a `done` callback and blocks until `done` runs, or refuses with
  /// `Bad_WouldBlock` before calling @p start on a thread of the Connection's executor. The wait of the
  /// header-inline templates, kept out of line so this public header needs no private one.
  ua::VoidResult wait_sync(const std::function<void(std::function<void()>)>& start) const noexcept;

  std::shared_ptr<detail::ConnectionImpl> mImpl;
};

/// Packs native C++ method-call inputs into a `std::vector<Variant>` for
/// `TypedAccess::call_method_async`.
///
/// Each argument is boxed into a @ref ua::Variant (via `detail::to_call_arg`): built-in scalar /
/// array values forward to the matching Variant constructor, string literals / `std::string` route
/// through @ref ua::String, and an existing @ref ua::Variant passes through. The result drops
/// straight into `call_method_async`'s `arguments` parameter, e.g.
/// `typed.call_method_async(obj, m, ua::client::args(int32_t{3}, "on", 4.2), cb)`.
///
/// @tparam Ts Deduced input types.
/// @param inputs The native method inputs, in call order.
/// @return A `std::vector<Variant>` of boxed inputs, preserving argument order.
template<class... Ts>
std::vector<ua::Variant> args(Ts&&... inputs)
{
  std::vector<ua::Variant> boxed;
  boxed.reserve(sizeof...(inputs));
  (boxed.push_back(detail::to_call_arg(std::forward<Ts>(inputs))), ...);
  return boxed;
}

}  // namespace ua::client

#endif  // UA_TYPED_ACCESS_H
