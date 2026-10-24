// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_ERROR_DETAIL_KEYS_H
#define UA_ERROR_DETAIL_KEYS_H

#include <string_view>

/// @file
/// @brief Controlled vocabulary of structured-context keys for ua::ErrorDetail.
/// @ingroup general
///
/// ContextKey is a CLOSED newtype: its constructor is private and only the
/// `ContextKeys` vocabulary may construct one, so a key not declared there --
/// including a raw string literal -- does NOT compile. Adding a key is a reviewed
/// one-line edit to ContextKeys (the single source of truth for the vocabulary).
///
/// Value-format contracts (one deterministic renderer per underlying type -- never
/// "std::to_string(...) or verbatim") are documented per key below. C++20: keys are
/// std::string_view, never const char*.
///
/// PRECEDENCE rules that recur across keys:
/// - Byte/element counts ALWAYS use the `size.*` subtree (size_actual / size_expected /
///   size_min / size_max / size_block); the bare `actual` / `expected` / `min` / `max` /
///   `length` keys are reserved for NON-size scalars.
/// - When `node.id` is present it embeds the namespace (and, for an ExpandedNodeId, the
///   server index and namespace URI), so the standalone `namespace.index`,
///   `namespace.uri`, and `server.index` keys are SUPPRESSED to avoid duplication.

namespace ua
{

/// A single key drawn from the closed ErrorDetail structured-context vocabulary.
///
/// Wraps the wire string used as the key in @ref ErrorDetail::context. The constructor
/// is private, so the only ContextKey values that exist are the named constants in
/// @ref ContextKeys (its sole friend); an off-vocabulary key -- including a raw string
/// literal -- is a compile error. Obtain one by naming a constant, e.g.
/// `ua::ContextKeys::nodeId`, and pass it to `ErrorDetailBuilder::context`.
/// @ingroup general
class ContextKey
{
public:
  /// Returns the underlying wire key string (the literal stored under it in mContext).
  ///
  /// The returned view aliases the constant's static storage and outlives any caller;
  /// it is the exact `subtree.leaf` token shown in each constant's documentation below.
  ///
  /// @return The wire key string; a view over static storage that outlives any caller.
  [[nodiscard]] constexpr std::string_view value() const noexcept
  {
    return mValue;
  }

  /// Compares two keys for identity (same vocabulary entry, i.e. same wire string).
  ///
  /// @return @c true when both keys wrap the same wire string; @c false otherwise.
  friend constexpr bool operator==(const ContextKey&, const ContextKey&) = default;

private:
  explicit constexpr ContextKey(std::string_view key) noexcept : mValue(key)
  {}

  std::string_view mValue;
  friend struct ContextKeys;
};

/// The controlled vocabulary: the complete, closed set of context keys.
///
/// A pure namespace-like scope for the ContextKey constants; deleting the default
/// constructor makes it non-instantiable. Reference a key as
/// `ua::ContextKeys::nodeId` (the names below carry the per-key value-format contract).
/// @ingroup general
struct ContextKeys
{
  ContextKeys() = delete;

  // ---- node.* -- target node identity & attributes ----

  /// Attribute of the node being acted on, as the symbolic AttributeId enum name.
  static constexpr ContextKey nodeAttribute{"node.attribute"};

  /// BrowseName of the targeted node, rendered `ns:Name` (the namespace-0 branch elides
  /// the prefix and renders the bare `Name`).
  static constexpr ContextKey nodeBrowseName{"node.browse_name"};

  /// NodeId of the targeted node, rendered via ua::to_string (the canonical
  /// `ns=<idx>;i=<id>` form; an ExpandedNodeId additionally embeds `svr=`/`nsu=`). When
  /// present, suppresses namespace_index (plain NodeId) or namespace_index +
  /// namespace_uri + server_index (ExpandedNodeId), since node.id already carries them.
  static constexpr ContextKey nodeId{"node.id"};

  // ---- namespace.* ----

  /// Namespace index that is a fact about the target, decimal. SUPPRESS when node.id is
  /// present (node.id already embeds the index).
  static constexpr ContextKey namespaceIndex{"namespace.index"};

  /// Namespace URI that is a fact about the target, verbatim. SUPPRESS when node.id is an
  /// ExpandedNodeId (it already carries the URI).
  static constexpr ContextKey namespaceUri{"namespace.uri"};

  /// Generation of the NamespaceTable snapshot a translation reads a NodeId's index FROM, decimal.
  static constexpr ContextKey namespaceSourceGeneration{"namespace.source_generation"};

  /// Generation of the NamespaceTable snapshot a translation resolves a URI INTO, decimal.
  static constexpr ContextKey namespaceTargetGeneration{"namespace.target_generation"};

  // ---- type.* -- DATA TYPES & algorithms only (never a DataEncoding -- see encoding) --

  /// Type actually presented, as its symbolic name. Used ONLY on a genuine mismatch
  /// (>=2 types involved); for a single type use type_id + type_name instead.
  static constexpr ContextKey typeActual{"type.actual"};

  /// Type the operation required, as its symbolic name. Used ONLY on a genuine mismatch
  /// (>=2 types involved); for a single type use type_id + type_name instead.
  static constexpr ContextKey typeExpected{"type.expected"};

  /// Numeric identifier of the single type/algorithm involved (NOT a DataEncoding -- see
  /// encoding). Pairs with type_name; not used on a mismatch.
  static constexpr ContextKey typeId{"type.id"};

  /// Symbolic name of the single type/algorithm involved (NOT a DataEncoding -- see
  /// encoding). Pairs with type_id; not used on a mismatch.
  static constexpr ContextKey typeName{"type.name"};

  // ---- encoding.* ----

  /// DataEncoding name in play, and ONLY that (e.g. "Default Binary" / "Default XML").
  /// Distinct from the type.* keys, which never name a DataEncoding.
  static constexpr ContextKey encoding{"encoding"};

  // ---- size.* -- BYTE/ELEMENT COUNTS (any bounded/compared count uses size_*) ----

  /// Observed BYTE/ELEMENT count at the failure site, decimal. PRECEDENCE: any
  /// byte/element count uses the size.* subtree, never bare actual/length.
  static constexpr ContextKey sizeActual{"size.actual"};

  /// Cipher/encoding block size in BYTES, decimal.
  static constexpr ContextKey sizeBlock{"size.block"};

  /// BYTE/ELEMENT count the operation required, decimal. PRECEDENCE: any byte/element
  /// count uses size.*, never bare expected.
  static constexpr ContextKey sizeExpected{"size.expected"};

  /// Maximum permitted BYTE/ELEMENT count, decimal. PRECEDENCE: a bounded byte/element
  /// count uses size.*, never bare max/limit.
  static constexpr ContextKey sizeMax{"size.max"};

  /// Minimum permitted BYTE/ELEMENT count, decimal. PRECEDENCE: a bounded byte/element
  /// count uses size.*, never bare min.
  static constexpr ContextKey sizeMin{"size.min"};

  // ---- length.* ----

  /// A count that is NEITHER bounded NOR compared, decimal. If the count is a byte/element
  /// count use the size.* subtree; if it is bounded use size_min/size_max instead.
  static constexpr ContextKey length{"length"};

  // ---- expected.* ----

  /// Generic expected value for a NON-size equality/match constraint. For byte/element
  /// counts use size_expected instead.
  static constexpr ContextKey expected{"expected"};

  // ---- actual.* ----

  /// Generic received-side value of a NON-size compare (the sole received-side key; there
  /// is no `got`/`received`). For byte/element counts use size_actual instead.
  static constexpr ContextKey actual{"actual"};

  // ---- limit.* ----

  /// Configured ceiling that was exceeded (timeout, quota), NON-size, decimal. For
  /// byte/element ceilings use size_max instead.
  static constexpr ContextKey limit{"limit"};

  // ---- min.* ----

  /// Minimum bound of a permitted NON-size scalar range. For byte/element counts use
  /// size_min instead.
  static constexpr ContextKey min{"min"};

  // ---- max.* ----

  /// Maximum bound of a permitted NON-size scalar range. For byte/element counts use
  /// size_max instead.
  static constexpr ContextKey max{"max"};

  // ---- count.* ----

  /// Observed count when reporting a count comparison, decimal.
  static constexpr ContextKey countActual{"count.actual"};

  /// Expected count when reporting a count comparison, decimal.
  static constexpr ContextKey countExpected{"count.expected"};

  /// Total count of a population relevant to the error -- an unbounded, uncompared count
  /// (e.g. how many items were in a batch), decimal.
  static constexpr ContextKey countTotal{"count.total"};

  // ---- index.* ----

  /// Generic zero/one-based positional index at the failure site (a position, not a
  /// size), decimal.
  static constexpr ContextKey index{"index"};

  // ---- operation.* ----

  /// Index of the failing element within a batch/array request (a position, not a size),
  /// decimal.
  static constexpr ContextKey operationIndex{"operation.index"};

  // ---- offset.* ----

  /// Byte offset within a buffer/stream (a position, not a size), decimal.
  static constexpr ContextKey offset{"offset"};

  // ---- value.* ----

  /// A data value or input fragment involved at the failure site (NOT a compare side --
  /// for those use actual/expected). Rendered for its underlying type.
  static constexpr ContextKey value{"value"};

  // ---- field.* ----

  /// Name of the field/member/component/named item involved (struct field, date
  /// component, etc.), verbatim.
  static constexpr ContextKey fieldName{"field.name"};

  // ---- uri.* ----

  /// Generic URI fact (security policy URI, etc.) not covered by a more specific key,
  /// verbatim.
  static constexpr ContextKey uri{"uri"};

  // ---- application.* ----

  /// ApplicationUri asserted by a peer or certificate, verbatim.
  static constexpr ContextKey applicationUri{"application.uri"};

  // ---- endpoint.* ----

  /// Resolved host/address of an endpoint, verbatim.
  static constexpr ContextKey endpointAddress{"endpoint.address"};

  /// Configured endpoint name referenced, verbatim.
  static constexpr ContextKey endpointName{"endpoint.name"};

  /// The endpoint's selected user-token policy id, verbatim.
  static constexpr ContextKey endpointPolicyId{"endpoint.policy_id"};

  /// TCP port of an endpoint, decimal.
  static constexpr ContextKey endpointPort{"endpoint.port"};

  /// Full endpoint URL, verbatim (also used for a connection target URL).
  static constexpr ContextKey endpointUrl{"endpoint.url"};

  // ---- remote.* ----

  /// Peer's remote network address on a connection, verbatim.
  static constexpr ContextKey remoteAddress{"remote.address"};

  // ---- security.* ----

  /// MessageSecurityMode in effect or required, rendered SYMBOLICALLY via
  /// ua::to_string(MessageSecurityMode) (e.g. "SignAndEncrypt").
  static constexpr ContextKey securityMode{"security.mode"};

  /// OPTIONAL numeric companion to security.mode, used only where the raw integer is
  /// itself the fact (e.g. an out-of-range mode value), decimal.
  static constexpr ContextKey securityModeValue{"security.mode.value"};

  /// Security policy in effect or required, as its URI (there is no public symbolic
  /// SecurityPolicy name to render).
  static constexpr ContextKey securityPolicy{"security.policy"};

  /// Currently-active SecurityToken id during a token mismatch, decimal.
  static constexpr ContextKey securityTokenActiveId{"security.token.active.id"};

  /// SecurityToken id referenced by the message, decimal.
  static constexpr ContextKey securityTokenId{"security.token.id"};

  /// Pending/renewing SecurityToken id during a token mismatch, decimal.
  static constexpr ContextKey securityTokenPendingId{"security.token.pending.id"};

  // ---- token.* ----

  /// User identity token kind presented, as the symbolic UserTokenType enum name.
  static constexpr ContextKey tokenKind{"token.kind"};

  /// UserTokenPolicy id referenced, verbatim.
  static constexpr ContextKey tokenPolicyId{"token.policy_id"};

  // ---- certificate.* -- thumbprint via ua::utils::bytes_to_hex_string ----

  /// Certificate/key family actually presented by the token, symbolic. Used on a genuine
  /// family mismatch (pairs with certificate_family_expected).
  static constexpr ContextKey certificateFamilyActual{"certificate.family.actual"};

  /// Certificate/key family the channel or policy required, symbolic. Used on a genuine
  /// family mismatch (pairs with certificate_family_actual).
  static constexpr ContextKey certificateFamilyExpected{"certificate.family.expected"};

  /// NotAfter validity bound of the certificate.
  static constexpr ContextKey certificateNotAfter{"certificate.not_after"};

  /// NotBefore validity bound of the certificate.
  static constexpr ContextKey certificateNotBefore{"certificate.not_before"};

  /// Serial number of the certificate involved.
  static constexpr ContextKey certificateSerialNumber{"certificate.serial_number"};

  /// Subject (e.g. CN) of the certificate involved, verbatim.
  static constexpr ContextKey certificateSubject{"certificate.subject"};

  /// Thumbprint of the certificate involved, as lowercase space-separated hex octets.
  static constexpr ContextKey certificateThumbprint{"certificate.thumbprint"};

  /// Issuer Name of the certificate involved, as OpenSSL's one-line rendering, verbatim. Names the
  /// issuer that could not be found when a certificate chain is incomplete.
  static constexpr ContextKey certificateIssuer{"certificate.issuer"};

  /// Where the certificate involved stands in the chain being validated: EndEntity, IssuingCa or
  /// HigherCa (`CertificateChainPosition`), symbolic.
  static constexpr ContextKey certificateChainPosition{"certificate.chain_position"};

  // ---- crl.* ----

  /// Issuer Name of the CRL involved, as OpenSSL's one-line rendering, verbatim.
  static constexpr ContextKey crlIssuer{"crl.issuer"};

  // ---- chain.* ----

  /// Depth in the certificate chain where validation failed (a position, not a size),
  /// decimal.
  static constexpr ContextKey chainDepth{"chain.depth"};

  /// Number of inner DiagnosticInfo / ErrorDetail chain levels omitted by the client-side
  /// depth cap (a count, decimal). Attached to the `client.diagnostic.truncated` sentinel.
  static constexpr ContextKey omittedDepth{"omitted_depth"};

  // ---- crypto.* -- crypto/OpenSSL facts; buffer sizes in BYTES ----

  /// Ciphertext buffer size in BYTES, decimal.
  static constexpr ContextKey cryptoCiphertextSize{"crypto.ciphertext.size"};

  /// Elliptic-curve group name involved (the queryable EC fact).
  static constexpr ContextKey cryptoCurve{"crypto.curve"};

  /// Bit degree of the elliptic curve. DIAGNOSTIC-ONLY -- not an oracle key (no test
  /// matches on it), decimal.
  static constexpr ContextKey cryptoCurveDegree{"crypto.curve.degree"};

  /// Generic crypto input data size in BYTES, decimal.
  static constexpr ContextKey cryptoDataSize{"crypto.data.size"};

  /// OpenSSL error-queue string (a library diagnostic, not an SDK StatusCode).
  static constexpr ContextKey cryptoError{"crypto.error"};

  /// HKDF info/context size in BYTES, decimal.
  static constexpr ContextKey cryptoInfoSize{"crypto.info.size"};

  /// IV length in BYTES the cipher required, decimal (pairs with crypto_iv_size).
  static constexpr ContextKey cryptoIvExpected{"crypto.iv.expected"};

  /// Initialization-vector size in BYTES, decimal.
  static constexpr ContextKey cryptoIvSize{"crypto.iv.size"};

  /// Key length in BYTES (unit always bytes), decimal.
  static constexpr ContextKey cryptoKeySize{"crypto.key.size"};

  /// Key length in BYTES the cipher/operation required (unit always bytes), decimal
  /// (pairs with crypto_key_size).
  static constexpr ContextKey cryptoKeySizeExpected{"crypto.key.size.expected"};

  /// OpenSSL numeric object identifier (NID) involved. DIAGNOSTIC-ONLY -- not an oracle
  /// key (no test matches on it), decimal.
  static constexpr ContextKey cryptoNid{"crypto.nid"};

  /// Plaintext buffer size in BYTES, decimal.
  static constexpr ContextKey cryptoPlaintextSize{"crypto.plaintext.size"};

  /// Whether a private key was available for the operation (boolean rendered "true"/
  /// "false").
  static constexpr ContextKey cryptoPrivatekeyPresent{"crypto.privatekey.present"};

  /// Private-key blob size in BYTES, decimal.
  static constexpr ContextKey cryptoPrivatekeySize{"crypto.privatekey.size"};

  /// Public-key blob size in BYTES, decimal.
  static constexpr ContextKey cryptoPublickeySize{"crypto.publickey.size"};

  /// RAND_status() result from the crypto RNG (the raw OpenSSL return), decimal.
  static constexpr ContextKey cryptoRandStatus{"crypto.rand_status"};

  /// KDF salt size in BYTES, decimal.
  static constexpr ContextKey cryptoSaltSize{"crypto.salt.size"};

  /// Shared-secret size in BYTES, decimal.
  static constexpr ContextKey cryptoSecretSize{"crypto.secret.size"};

  /// KDF seed size in BYTES, decimal.
  static constexpr ContextKey cryptoSeedSize{"crypto.seed.size"};

  /// Signature size in BYTES, decimal.
  static constexpr ContextKey cryptoSignatureSize{"crypto.signature.size"};

  // ---- sequence.* ----

  /// Last received sequence number when a sequencing error occurred, decimal. Distinct
  /// from request_id and request_handle (a per-chunk sequence counter, not a request id).
  static constexpr ContextKey sequenceLastSeen{"sequence.last_seen"};

  // ---- request.* ----

  /// RequestHeader.requestHandle -- the client-supplied handle echoed in the Response,
  /// decimal. NOT interchangeable with request_id (transport id).
  static constexpr ContextKey requestHandle{"request.handle"};

  /// Transport/secure-channel request id (channel-assigned, per-chunk), decimal. Do NOT
  /// use for the client-supplied requestHandle -- that is request_handle.
  static constexpr ContextKey requestId{"request.id"};

  // ---- channel.* ----

  /// SecureChannel id correlating the failure, decimal.
  static constexpr ContextKey channelId{"channel.id"};

  // ---- secure_channel.* ----

  /// Whether the SecureChannel had expired at the failure site (boolean rendered "true"/
  /// "false").
  static constexpr ContextKey secureChannelExpired{"secure_channel.expired"};

  // ---- state.* ----

  /// Channel state-machine value at the failure site. DIAGNOSTIC numeric (decimal); a
  /// symbolic state name is not rendered.
  static constexpr ContextKey stateChannel{"state.channel"};

  // ---- server.* ----

  /// ServerIndex referenced in an ExpandedNodeId/server table, decimal. SUPPRESS when
  /// node.id is present (an ExpandedNodeId already carries the server index).
  static constexpr ContextKey serverIndex{"server.index"};

  /// Server timestamp fact relevant to the failure.
  static constexpr ContextKey serverTimestamp{"server.timestamp"};

  // ---- session.* ----

  /// Session id (a NodeId) correlating the failure, rendered via ua::to_string(NodeId).
  static constexpr ContextKey sessionId{"session.id"};

  // ---- subscription.* ----

  /// Subscription id correlating the failure, decimal.
  static constexpr ContextKey subscriptionId{"subscription.id"};

  // ---- monitored_item.* ----

  /// MonitoredItem id/handle correlating the failure, decimal.
  static constexpr ContextKey monitoredItemId{"monitored_item.id"};

  // ---- event.* ----

  /// EventId the operation names, base64 via ua::to_string(ByteString). An EventId is opaque
  /// and single-use: a Condition allocates a fresh one on every state change, so the id a caller
  /// presents is the fact that identifies WHICH occurrence it acted on.
  static constexpr ContextKey eventId{"event.id"};

  // ---- listener.* ----

  /// Server listener handle referenced, decimal.
  static constexpr ContextKey listenerHandle{"listener.handle"};

  /// Configured listener name referenced, verbatim.
  static constexpr ContextKey listenerName{"listener.name"};

  // ---- reverse_connect.* ----

  /// Reverse-connect handle referenced, decimal.
  static constexpr ContextKey reverseConnectHandle{"reverse_connect.handle"};

  // ---- file.* ----

  /// OS/library file error code (NOT an SDK StatusCode), decimal.
  static constexpr ContextKey fileErrorCode{"file.error_code"};

  /// Filesystem path involved, verbatim.
  static constexpr ContextKey filePath{"file.path"};

  // ---- directory.* ----

  /// Directory path involved, verbatim.
  static constexpr ContextKey directory{"directory"};

  // ---- locale.* ----

  /// Locale id relevant to the failure, verbatim.
  static constexpr ContextKey locale{"locale"};

  // ---- method.* ----

  /// Method/operation name at the failure site, verbatim.
  static constexpr ContextKey method{"method"};
  /// NodeId of the Method a Call names, rendered via ua::to_string.
  static constexpr ContextKey methodId{"method.id"};
  /// NodeId of the Object a Call names, rendered via ua::to_string.
  static constexpr ContextKey objectId{"object.id"};

  // ---- argument.* ----

  /// Name of a Method's input or output argument, verbatim (Argument.Name). Never the value: an
  /// argument can be a secret, so its value is added under `value` only by code that knows it is safe.
  static constexpr ContextKey argumentName{"argument.name"};

  // ---- service.* ----

  /// OPC UA service name at the failure site, verbatim.
  static constexpr ContextKey service{"service"};

  // ---- bit.* -- option-set bit facts; hex via fmt "{:#06x}" -> lowercase ----

  /// Client-supplied OptionSet bit value during a merge mismatch, as fixed-width
  /// lowercase hex (e.g. "0x000f").
  static constexpr ContextKey bitClientValue{"bit.client_value"};

  /// Bit position involved in an OptionSet/encoding error (a position), decimal.
  static constexpr ContextKey bitIndex{"bit.index"};

  /// Symbolic name of the bit involved, verbatim.
  static constexpr ContextKey bitName{"bit.name"};

  /// Server-side valid OptionSet bit mask during a merge mismatch, as fixed-width
  /// lowercase hex (e.g. "0x00ff").
  static constexpr ContextKey bitServerMask{"bit.server_mask"};

  // ---- source.* ----

  /// `file:line` location within an INPUT DOCUMENT (NodeSet/XML), verbatim -- NOT the SDK
  /// component source location (that is carried separately on ErrorDetail).
  static constexpr ContextKey sourceLocation{"source.location"};

  // ---- pull_cert.* -- Pull-Model certificate-manager cycle facts (client section 8.1A.5) ----

  /// Symbolic FSM state the pull-cert cycle failed in (e.g. "RequestingCert"), verbatim.
  static constexpr ContextKey pullFailedState{"pull_cert.failed_state"};

  /// Consecutive-failure count at the failing pull-cert cycle (INCLUDING this failure), decimal.
  static constexpr ContextKey pullFailureCount{"pull_cert.failure_count"};

  /// Certificate-group NodeId being serviced when the pull-cert cycle failed, via ua::to_string(NodeId).
  static constexpr ContextKey pullGroupId{"pull_cert.group_id"};

  /// GDS-issued certificate-request id in flight when the pull-cert cycle failed, as hex octets. Distinct
  /// from request.id (the transport/secure-channel id).
  static constexpr ContextKey pullGdsRequestId{"pull_cert.gds_request_id"};

  // ---- error.* -- free-form diagnostic text from a lower layer (NOT a structured fact) -

  /// Free-form diagnostic message from a lower layer or a caught exception
  /// (`e.what()` / transport errorDescription / a pre-formatted reason), verbatim.
  static constexpr ContextKey errorMessage{"error.message"};
};

}  // namespace ua

#endif  // UA_ERROR_DETAIL_KEYS_H
