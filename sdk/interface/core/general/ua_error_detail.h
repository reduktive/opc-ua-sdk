// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ERROR_DETAIL_H
#define UA_ERROR_DETAIL_H

#include <concepts>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include "ua_error_detail_keys.h"
#include "ua_status_code.h"

/// @file
/// @brief Structured error context carried by Result<T> at failure sites.
/// @ingroup general

namespace ua
{

/// A single structured fact attached to one ErrorDetail layer: a controlled key
/// (drawn from the closed vocabulary in ua_error_detail_keys.h) paired with its
/// canonically-rendered string value. Facts live here, never interpolated into
/// the prose fields (summary/mDetail).
/// @ingroup general
struct NamedValue
{
  std::string key;  ///< Controlled context key from the closed vocabulary (ua_error_detail_keys.h).
  std::string value;  ///< Canonically-rendered string value for that key.
};

class ErrorDetailBuilder;  // fluent, context-bearing construction (defined below)

/// Structured error context attached to Result<T> at failure sites.
///
/// Designed for developer ergonomics, not wire serialization. The mapping to
/// OPC UA DiagnosticInfo happens at the service response boundary inside
/// DiagnosticCollector (service-internal, never exposed to namespace
/// implementations or user code).
///
/// An instance is created once at the failure site, optionally wrapped with
/// cause context by intermediate layers, and consumed at the service boundary.
/// It is shared immutably as `shared_ptr<const ErrorDetail>` on Result<T>;
/// because it is never mutated after construction it may be read from any
/// thread without synchronization.
/// @ingroup general
struct ErrorDetail
{
  /// Machine-readable identifier for the error condition.
  ///
  /// Examples: "DbConnectionRefused", "CertExpired", "TypeMismatch". Maps to
  /// DiagnosticInfo::symbolicId at the service boundary.
  std::string code;

  /// Short, one-line human-readable description suitable for log messages.
  ///
  /// Examples: "Database connection refused", "Node not found in address
  /// space". Maps to DiagnosticInfo::localizedText at the service boundary.
  std::string summary;

  /// Extended, multi-line diagnostic information.
  ///
  /// Empty when the summary says enough. Example: "Connection to
  /// 10.0.0.5:5432 timed out after 30s (retry 3/3)". Maps to
  /// DiagnosticInfo::additionalInfo at the service boundary.
  std::string detail;

  /// The component or layer that produced this error.
  ///
  /// Examples: "DatabaseNamespace", "OpenSslCrypto", "ReadService". Maps to
  /// DiagnosticInfo::namespaceUri (via a configured vendor namespace prefix)
  /// at the service boundary.
  std::string source;

  /// The underlying status value from the inner/causing operation.
  ///
  /// Stored as the bare wire-format value (no attached detail) - the rich
  /// cause chain lives in @ref cause. Defaults to Status::Good. Maps to
  /// DiagnosticInfo::innerStatusCode at the service boundary.
  StatusCodeValue innerStatus{utils::to_underlying(Status::Good)};

  /// Recursive cause chain; null when this is the root cause.
  ///
  /// Maps to DiagnosticInfo::innerDiagnosticInfo at the service boundary.
  shared_ptr<const ErrorDetail> cause;

  /// Structured facts for THIS layer (the node id that failed, the operation,
  /// the index, the limit, ...) as controlled key -> rendered-value pairs.
  ///
  /// Empty for layers with no structured fact. Keys are drawn from the closed
  /// vocabulary (ua_error_detail_keys.h); values are canonical rendered strings.
  /// Maps to DiagnosticInfo::additionalInfo (as a JSON object) at the wire
  /// boundary. A layer never discards a lower layer's context.
  std::vector<NamedValue> context;

  /// Opens a fluent, context-bearing builder. The canonical path for failure
  /// sites that carry structured facts; contextless layers may keep using the
  /// make_error_detail() free functions below.
  ///
  /// @param code    Machine-readable identifier; stored in @ref ErrorDetail::code.
  /// @param summary One-line human-readable description; stored in @ref ErrorDetail::summary.
  /// @param source  Producing component/layer; stored in @ref ErrorDetail::source.
  /// @return A builder seeded with the three prose fields, ready for fluent context/cause calls.
  static ErrorDetailBuilder build(std::string code, std::string summary, std::string source);
};

/// Renders an integral fact value to its canonical decimal string, so call sites
/// can pass a raw integer to context() instead of wrapping it in std::to_string.
/// Found (with ADL) alongside the per-type error_detail_render overloads declared
/// with each renderable type (e.g. the ua::to_string-backed ones in ua_to_string.h).
///
/// @param value Integral fact value to render.
/// @return The canonical decimal string form of @p value.
template<std::integral T>
[[nodiscard]] inline std::string error_detail_render(T value)
{
  return std::to_string(value);
}

/// Fluent builder for an ErrorDetail that carries structured context.
///
/// Facts go to context() under a controlled ContextKey; prose stays in the
/// summary/detail string literals. The wrap is lossless: cause() threads the
/// inner status and chain. Converts to unique_ptr<ErrorDetail> (for make_error_detail
/// sites) and to shared_ptr<const ErrorDetail> (so it drops directly into
/// StatusCode{...}, UaException{...} and Result{...} with no  terminal).
///
/// @code
///   throw UaException{Status::BadNodeIdUnknown,
///     ErrorDetail::build("NodeIdUnknown", "node not found", "server.services.read")
///       .context(ContextKeys::nodeId, nodeId)            // NodeId rendered canonically
///       .context(ContextKeys::operationIndex, i)};       // integer rendered; no
/// @endcode
/// @ingroup general
class ErrorDetailBuilder
{
public:
  /// Starts a builder for an ErrorDetail with the three required prose fields set.
  ///
  /// Equivalent to @ref ErrorDetail::build. The detail text, structured context, and cause
  /// chain are added fluently afterwards; pass string literals for prose (the prose-purity
  /// rule) and runtime facts through context().
  ///
  /// @param code    Machine-readable identifier; stored in @ref ErrorDetail::code.
  /// @param summary One-line human-readable description; stored in @ref ErrorDetail::summary.
  /// @param source  Producing component/layer; stored in @ref ErrorDetail::source.
  ErrorDetailBuilder(std::string code, std::string summary, std::string source)
    : mDetail(std::make_unique<ErrorDetail>())
  {
    mDetail->code = std::move(code);
    mDetail->summary = std::move(summary);
    mDetail->source = std::move(source);
  }

  /// Sets the extended prose (mDetail). Must be a string literal at call sites
  /// (the prose-purity rule); runtime facts belong in context().
  ///
  /// @param extended Extended diagnostic prose; stored in @ref ErrorDetail::detail.
  /// @return @c *this, for fluent chaining.
  ErrorDetailBuilder& detail(std::string extended) &
  {
    mDetail->detail = std::move(extended);
    return *this;
  }

  /// Appends one structured fact. @p key must be a vocabulary constant.
  ///
  /// @param key   Vocabulary constant naming the fact; stored as the wire key.
  /// @param value Canonically-rendered string value for @p key.
  /// @return @c *this, for fluent chaining.
  ErrorDetailBuilder& context(const ContextKey& key, std::string value) &
  {
    mDetail->context.push_back(NamedValue{std::string(key.value()), std::move(value)});
    return *this;
  }

  /// Appends a structured fact, rendering @p value to its canonical string via the
  /// ADL-found error_detail_render(@p value) -- so a NodeId, integer, etc. can be
  /// passed directly without a hand-written ua::to_string / std::to_string (which
  /// also removes the "wrong renderer" class of mistake). Only enabled for types
  /// that have an error_detail_render overload; strings use the overload above.
  ///
  /// @param key   Vocabulary constant naming the fact; stored as the wire key.
  /// @param value Renderable fact value, converted to its canonical string via error_detail_render.
  /// @return @c *this, for fluent chaining.
  template<class T>
    requires requires(const T& renderable) {
      { error_detail_render(renderable) } -> std::convertible_to<std::string>;
    }
  ErrorDetailBuilder& context(const ContextKey& key, const T& value) &
  {
    return context(key, error_detail_render(value));
  }

  /// Threads a rich StatusCode cause: lifts its numeric inner status and links
  /// its detail chain (mirrors the make_error_detail(.., StatusCode) overload).
  ///
  /// @param cause StatusCode supplying the numeric inner status and the cause chain.
  /// @return @c *this, for fluent chaining.
  ErrorDetailBuilder& cause(StatusCode cause) &
  {
    mDetail->innerStatus = cause.value();
    mDetail->cause = cause.shared_detail();
    return *this;
  }

  /// Links an explicit cause chain.
  ///
  /// @param cause Inner cause to link; stored in @ref ErrorDetail::cause. May be null.
  /// @return @c *this, for fluent chaining.
  ErrorDetailBuilder& cause(shared_ptr<const ErrorDetail> cause) &
  {
    mDetail->cause = std::move(cause);
    return *this;
  }

  /// Rvalue twins of the chaining methods above.
  ///
  /// A chain on a TEMPORARY yields an xvalue rather than an lvalue reference, so a helper can
  /// build a detail and return it by value:
  ///
  /// @code
  ///   ErrorDetailBuilder describe(const NodeId& node)
  ///   {
  ///     return ErrorDetail::build("NodeIdUnknown", "node not found", "server.services.read")
  ///       .context(ContextKeys::nodeId, node);
  ///   }
  /// @endcode
  ///
  /// Without them that return needs a copy, which the owning `unique_ptr` member deletes, so the
  /// builder had to be consumed exactly where it was built.
  /// @{

  /// @param extended Extended prose.
  /// @return This builder as an xvalue, so the chain can be returned or moved on.
  ErrorDetailBuilder&& detail(std::string extended) &&
  {
    static_cast<ErrorDetailBuilder&>(*this).detail(std::move(extended));
    return std::move(*this);
  }

  /// @param key   Controlled context key.
  /// @param value Value rendered canonically.
  /// @return This builder as an xvalue.
  ErrorDetailBuilder&& context(const ContextKey& key, std::string value) &&
  {
    static_cast<ErrorDetailBuilder&>(*this).context(key, std::move(value));
    return std::move(*this);
  }

  /// @tparam T    Type with a canonical rendering.
  /// @param key   Controlled context key.
  /// @param value Value rendered canonically.
  /// @return This builder as an xvalue.
  template<typename T>
  ErrorDetailBuilder&& context(const ContextKey& key, const T& value) &&
  {
    static_cast<ErrorDetailBuilder&>(*this).context(key, value);
    return std::move(*this);
  }

  /// @param cause The inner failure's status.
  /// @return This builder as an xvalue.
  ErrorDetailBuilder&& cause(StatusCode cause) &&
  {
    static_cast<ErrorDetailBuilder&>(*this).cause(cause);
    return std::move(*this);
  }

  /// @param cause The inner failure's detail.
  /// @return This builder as an xvalue.
  ErrorDetailBuilder&& cause(shared_ptr<const ErrorDetail> cause) &&
  {
    static_cast<ErrorDetailBuilder&>(*this).cause(std::move(cause));
    return std::move(*this);
  }

  /// @}

  /// Terminal: hands over the built ErrorDetail as an owning `unique_ptr`.
  ///
  /// The conversion that lets a builder be returned directly from the make_error_detail() free
  /// functions. Moves out the held detail; the builder is spent afterwards and must not be
  /// reused.
  ///
  /// @return The built ErrorDetail as an owning `std::unique_ptr`.
  operator std::unique_ptr<ErrorDetail>()
  {
    return std::move(mDetail);
  }

  /// Terminal: hands over the built ErrorDetail as a `shared_ptr<const ErrorDetail>`.
  ///
  /// The conversion that lets a builder drop straight into the braced-init error sinks
  /// (StatusCode{...}, UaException{...}, Result{...}) with no trailing ``. Moves out the
  /// held detail; the builder is spent afterwards and must not be reused.
  ///
  /// @return The built ErrorDetail as a `std::shared_ptr<const ErrorDetail>`.
  operator std::shared_ptr<const ErrorDetail>()
  {
    return std::move(mDetail);
  }

private:
  std::unique_ptr<ErrorDetail> mDetail;
};

inline ErrorDetailBuilder ErrorDetail::build(std::string code, std::string summary, std::string source)
{
  return ErrorDetailBuilder{std::move(code), std::move(summary), std::move(source)};
}

/// Creates an ErrorDetail from code, summary, and source.
///
/// @param code    Machine-readable identifier; stored in `ErrorDetail::code`.
/// @param summary One-line description; stored in `ErrorDetail::summary`.
/// @param source  Producing component; stored in `ErrorDetail::source`.
/// @return A newly owned ErrorDetail with no detail text, inner status, or
///         cause chain.
inline std::unique_ptr<ErrorDetail> make_error_detail(
  std::string code, std::string summary, std::string source)
{
  auto d = std::make_unique<ErrorDetail>();
  d->code = std::move(code);
  d->summary = std::move(summary);
  d->source = std::move(source);
  return d;
}

/// Creates an ErrorDetail with all string fields.
///
/// @param code    Machine-readable identifier; stored in `ErrorDetail::code`.
/// @param summary One-line description; stored in `ErrorDetail::summary`.
/// @param detail  Extended diagnostic text; stored in `ErrorDetail::detail`.
/// @param source  Producing component; stored in `ErrorDetail::source`.
/// @return A newly owned ErrorDetail with no inner status or cause chain.
inline std::unique_ptr<ErrorDetail> make_error_detail(
  std::string code, std::string summary, std::string detail, std::string source)
{
  auto d = std::make_unique<ErrorDetail>();
  d->code = std::move(code);
  d->summary = std::move(summary);
  d->detail = std::move(detail);
  d->source = std::move(source);
  return d;
}

/// Creates an ErrorDetail from code, summary, source, and an explicit cause chain.
///
/// @param code    Machine-readable identifier; stored in `ErrorDetail::code`.
/// @param summary One-line description; stored in `ErrorDetail::summary`.
/// @param source  Producing component; stored in `ErrorDetail::source`.
/// @param cause   Inner cause to chain; stored in `ErrorDetail::cause`.
///                May be null for a root cause.
/// @return A newly owned ErrorDetail linked to @p cause.
inline std::unique_ptr<ErrorDetail> make_error_detail(
  std::string code, std::string summary, std::string source, shared_ptr<const ErrorDetail> cause)
{
  auto d = std::make_unique<ErrorDetail>();
  d->code = std::move(code);
  d->summary = std::move(summary);
  d->source = std::move(source);
  d->cause = std::move(cause);
  return d;
}

/// Creates an ErrorDetail with all string fields and an explicit cause chain.
///
/// @param code    Machine-readable identifier; stored in `ErrorDetail::code`.
/// @param summary One-line description; stored in `ErrorDetail::summary`.
/// @param detail  Extended diagnostic text; stored in `ErrorDetail::detail`.
/// @param source  Producing component; stored in `ErrorDetail::source`.
/// @param cause   Inner cause to chain; stored in `ErrorDetail::cause`.
///                May be null for a root cause.
/// @return A newly owned ErrorDetail linked to @p cause.
inline std::unique_ptr<ErrorDetail> make_error_detail(std::string code, std::string summary,
  std::string detail, std::string source, shared_ptr<const ErrorDetail> cause)
{
  auto d = std::make_unique<ErrorDetail>();
  d->code = std::move(code);
  d->summary = std::move(summary);
  d->detail = std::move(detail);
  d->source = std::move(source);
  d->cause = std::move(cause);
  return d;
}

/// Creates an ErrorDetail from code, summary, and source, threading inner status
/// and cause chain off a single StatusCode.
///
/// @param code    Machine-readable identifier; stored in `ErrorDetail::code`.
/// @param summary One-line description; stored in `ErrorDetail::summary`.
/// @param source  Producing component; stored in `ErrorDetail::source`.
/// @param cause   Source of both the numeric inner status (via @c value(),
///                stored in `ErrorDetail::innerStatus`) and the rich cause
///                chain (via @c shared_detail(), stored in `ErrorDetail::cause`).
/// @return A newly owned ErrorDetail carrying @p cause's status and detail.
inline std::unique_ptr<ErrorDetail> make_error_detail(
  std::string code, std::string summary, std::string source, StatusCode cause)
{
  auto d = std::make_unique<ErrorDetail>();
  d->code = std::move(code);
  d->summary = std::move(summary);
  d->source = std::move(source);
  d->innerStatus = cause.value();
  d->cause = cause.shared_detail();
  return d;
}

/// Creates an ErrorDetail with all string fields, threading inner status and
/// cause chain off a single StatusCode.
///
/// @param code    Machine-readable identifier; stored in `ErrorDetail::code`.
/// @param summary One-line description; stored in `ErrorDetail::summary`.
/// @param detail  Extended diagnostic text; stored in `ErrorDetail::detail`.
/// @param source  Producing component; stored in `ErrorDetail::source`.
/// @param cause   Source of both the numeric inner status (via @c value(),
///                stored in `ErrorDetail::innerStatus`) and the rich cause
///                chain (via @c shared_detail(), stored in `ErrorDetail::cause`).
/// @return A newly owned ErrorDetail carrying @p cause's status and detail.
inline std::unique_ptr<ErrorDetail> make_error_detail(
  std::string code, std::string summary, std::string detail, std::string source, StatusCode cause)
{
  auto d = std::make_unique<ErrorDetail>();
  d->code = std::move(code);
  d->summary = std::move(summary);
  d->detail = std::move(detail);
  d->source = std::move(source);
  d->innerStatus = cause.value();
  d->cause = cause.shared_detail();
  return d;
}

/// Formats an ErrorDetail, including its full cause chain, as a human-readable
/// string.
///
/// Each successive cause level is indented by two additional spaces. Intended
/// for logs and diagnostics, not wire serialization.
///
/// Example output:
///   [OpenSslCrypto] CertExpired: Certificate expired (BadCertificateTimeInvalid 0x80140000)
///     detail: CN=server, expired 2025-01-01
///     caused by: [CertificateStore] ChainValidationFailed: Chain validation failed (BadCertificateUntrusted
///     0x801A0000)
///
/// @param detail Error to format.
/// @param indent Starting indentation depth, in two-space levels; callers pass 0
///               for top-level output.
/// @return The formatted multi-line string.
/// @ingroup general
std::string to_string(const ErrorDetail& detail, int indent = 0);

/// Renders a `StatusCode` for a human: its attached `ErrorDetail` when it
/// has one, its plain code when it does not.
///
/// `to_string(const StatusCode&)` renders only the numeric status - e.g.
/// `"BadTypeMismatch (0x80740000)"` - and discards any attached detail. That is
/// the right form when the code itself is the whole message, but it silently
/// drops the structured context the SDK recorded at the failure site. Use
/// `describe` wherever a failure is reported to a person (a log line, a
/// diagnostic, an error message) so that context survives.
///
/// @param status Status to render. May be Good, and may carry no detail; both
///               fall back to the plain-code form.
/// @return With no detail attached, the single-line `to_string(status)` form.
///         With a detail attached, the detail's own multi-line rendering -
///         summary, status, extended prose, structured context and cause chain,
///         as described on `to_string(const ErrorDetail&, int)`. That
///         rendering opens with the detail's inner status, so when the inner
///         status differs from @p status (or the detail carries none) the code
///         the caller holds is named in front, as `"<status>: <detail>"`.
/// @see to_string(const ErrorDetail&, int)
/// @ingroup general
[[nodiscard]] std::string describe(const StatusCode& status);

/// Wire (de)serialization of ErrorDetail structured context through the single
/// DiagnosticInfo.AdditionalInfo string.
///
/// A layer that carries structured context (ErrorDetail::context) is encoded as
/// a marker-tagged JSON object:
/// @code
///   {"$uactx":1,"detail":"<extended prose>","ctx":{"node.id":"ns=2;i=5",...}}
/// @endcode
/// `"detail"` is omitted when empty. When a layer has NO structured context the
/// AdditionalInfo is the plain extended prose (back-compatible and human-readable
/// for third-party clients). The marker lets the decoder tell our structured
/// payload from arbitrary vendor text and fall back gracefully.
///
/// Boost.JSON is confined to the implementation; this header stays dependency-light.
namespace detail
{

/// Builds the DiagnosticInfo.AdditionalInfo string for @p detail.
///
/// Returns the marker-tagged JSON object when `detail.context` is non-empty
/// (embedding `detail.mDetail` under `"detail"`); otherwise returns
/// `detail.mDetail` verbatim (plain prose, no structured facts to preserve).
///
/// @param detail Error whose extended prose and structured context are serialized.
/// @return The AdditionalInfo string: marker-tagged JSON when context is present, else plain prose.
[[nodiscard]] std::string make_additional_info(const ErrorDetail& detail);

/// Populates @p out.context and @p out.mDetail from an AdditionalInfo string.
///
/// If @p additionalInfo is our marker-tagged JSON object, this call fully defines
/// the output: both `out.mDetail` and `out.context` are overwritten (cleared
/// first, so absent `"detail"`/`"ctx"` fields leave no stale data). Otherwise the
/// whole string is treated as opaque extended prose - `out.mDetail` is replaced
/// with @p additionalInfo and `out.context` is left untouched - the graceful
/// fallback for non-SDK servers. Bounded against malformed or hostile input:
/// oversized blobs are not parsed, context is capped at a fixed entry count, and
/// over-long keys/values are silently truncated rather than rejected.
///
/// @param additionalInfo AdditionalInfo string to parse (marker-tagged JSON or opaque prose).
/// @param out            Error populated with the parsed detail prose and structured context.
void parse_additional_info(std::string_view additionalInfo, ErrorDetail& out);

}  // namespace detail

}  // namespace ua

#endif  // !UA_ERROR_DETAIL_H
