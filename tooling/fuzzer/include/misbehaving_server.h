// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef MISBEHAVING_SERVER_H
#define MISBEHAVING_SERVER_H

/// @file
/// @brief Deterministic "misbehaving server" test fixture: a real in-tree server that mutates its
///        own responses so a real client is driven through the adversarial secure-channel paths the
///        client requirements demand (bad nonces, wrong service results, sequence gaps, ...).
///
/// This is Phase 1 of the MisbehavingServer design (see
/// the design specification): the SEMANTIC (`ua::Response&`) layer only. It is
/// a reusable facade over the already-existing, strand-safe server test interfaces:
///   - `ServerImplTestAccess::set_on_secure_channel_available` (per-channel scoping hook), and
///   - `SecureChannelTestAccess::set_response_interceptor` (mutate the typed response BEFORE signing).
/// The wire-byte layer and the coverage-guided campaign role are later phases and are NOT implemented
/// here.
///
/// Threading contract: the response interceptor is installed on each new channel's private strand via
/// a NON-BLOCKING post (fire-and-forget), so the fixture works on a server executor of any size  -
/// including a single-threaded one. The install never blocks a worker; correctness relies on the
/// channel strand's FIFO ordering: the install is posted before the channel's first message-pump turn
/// is enqueued, so the interceptor is in place before the first response is produced. The default
/// executor is hardware-sized; tests may force a specific thread count (see the ctor's
/// `serverThreadCount` parameter).

#include "ua_server.h"

#include "ua_crypto_types.h"

#include "ua_byte_string.h"
#include "ua_defines.h"
#include "ua_integer_id.h"
#include "ua_status_code.h"

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ua
{
class Crypto;
class CertificateStore;
class X509Certificate;
class AsymmetricKeyPair;
class Structure;
}  // namespace ua

namespace ua::test_helpers
{

namespace detail
{
/// Mutex-guarded state co-owned by the fixture and every installed interceptor. Defined in the .cpp;
/// lives in `detail` (not nested-private) so the strand-side helper functions can name it.
struct MisbehavingServerState;
}  // namespace detail

/// Context handed to a `mutate_server_nonce` transform for each `OpenSecureChannelResponse` seen on a
/// channel. It lets a scenario distinguish the initial (Issue) OPN response from later renewals and
/// replay a previously issued nonce  -  the stimulus CL-SC-016 (nonce reuse on renewal) needs.
struct OpnNonceContext
{
  /// The `serverNonce` currently on the response body (the real server-generated value, unless an
  /// earlier transform on this same response already changed it).
  ua::ByteString current;
  /// Per-channel OPN-response ordinal: 1 = the Issue response, 2+ = renewals.
  uint32_t opnResponseIndex{0};
  /// The nonce actually delivered to the client on this channel's Issue response. Empty until the
  /// Issue response has been processed (i.e. only meaningful when `opnResponseIndex >= 2`).
  ua::ByteString firstIssueNonce;
};

/// A real `ua::server::Server` that misbehaves at the semantic (`ua::Response&`) layer.
///
/// The fixture owns the server (and its multi-threaded executor, PKI, and endpoints) and installs the
/// response-mutating interfaces. Scenario configuration is written by the test thread; the mutators run on
/// each channel's strand. All shared state lives in a mutex-guarded `ScenarioState` co-owned by the
/// fixture and the interceptors, so a strand turn that runs after the fixture starts tearing down
/// still touches live, synchronized state (never a dead `this`). The destructor closes and drains the
/// server BEFORE releasing that state.
///
/// Not copyable or movable: it owns strand-bound callbacks that capture the co-owned state, plus an
/// executor that must outlive them in a fixed order.
class MisbehavingServer
{
public:
  /// Fixture-only certificate scenario: the server presents a certificate (and chain) of the test's choosing
  /// on a secured endpoint of the test's choosing, and starts WITHOUT the startup check of its own
  /// certificate against the endpoint policies (approved decision F) - the point of a misbehaving server is
  /// to present what no conforming SDK server would (C13: client-side Security Policy Check).
  struct CertificateScenario
  {
    std::shared_ptr<const ua::X509Certificate> certificate;  ///< The server's own certificate.
    std::shared_ptr<const ua::AsymmetricKeyPair> keys;  ///< Its key pair.
    std::vector<std::shared_ptr<const ua::X509Certificate>>
      issuerCertificates;  ///< Sent after it (decision 24).
    ua::CertificateType certificateType{ua::CertificateType::RsaSha256Application};
    ua::SecurityPolicyId securedPolicy{ua::SecurityPolicyId::Basic256Sha256};  ///< The secured endpoint.
    ua::MessageSecurityMode securedMode{ua::MessageSecurityMode::SignAndEncrypt};
    /// Certificates the server trusts besides its generated client certificate (the scenario's own client).
    std::vector<std::shared_ptr<const ua::X509Certificate>> trustedCertificates;
    std::string applicationUri;  ///< The server's ApplicationUri; empty keeps the test default.
  };

  /// Construction-time knobs for the owned server.
  struct Config
  {
    /// Smallest secure-channel lifetime the server will grant. Kept deliberately small so
    /// renewal-driven scenarios (CL-SC-016) fire within a bounded test rather than after the
    /// production 5-minute default. Must be > 0.
    std::chrono::milliseconds secureChannelMinimumLifetime{std::chrono::milliseconds{2000}};
    /// Fixture-only: replaces the generated server certificate and secured endpoint (see
    /// CertificateScenario).
    std::optional<CertificateScenario> certificateScenario;
  };

  /// Builds, configures, and starts the owned server on its thread pool, then installs the per-channel
  /// response-interceptor scoping hook (the Phase-1 default scope; see @ref per_channel).
  ///
  /// The interceptor is installed with a non-blocking post to each channel's strand, so the executor
  /// size is unconstrained  -  a single-threaded executor works and never deadlocks. Ordering is
  /// guaranteed by the channel strand's FIFO discipline (see the class-level threading contract).
  /// Builds the fixture with default configuration.
  MisbehavingServer();

  /// Builds the fixture with the supplied configuration. @p serverThreadCount is a test-only knob:
  /// `std::nullopt` (the default) sizes the server thread pool to the hardware; an explicit value
  /// forces exactly that many worker threads (e.g. 1 to prove the interceptor install never blocks a
  /// worker).
  explicit MisbehavingServer(Config config, std::optional<std::size_t> serverThreadCount = std::nullopt);

  /// Closes and drains the owned server, then releases the shared scenario state  -  in that order, so
  /// no in-flight strand turn can observe a destroyed fixture.
  ~MisbehavingServer();

  MisbehavingServer(const MisbehavingServer&) = delete;
  MisbehavingServer& operator=(const MisbehavingServer&) = delete;
  MisbehavingServer(MisbehavingServer&&) = delete;
  MisbehavingServer& operator=(MisbehavingServer&&) = delete;

  // --- Scoping (design section 5) --------------------------------------------------------------------

  /// Selects the per-channel scope: the response interceptor is installed on every new channel. This
  /// is the Phase-1 default and is already active after construction; the method exists for fluent,
  /// self-documenting call sites and returns `*this`.
  ///
  /// `per_session` and `per_endpoint` are intentionally NOT provided in Phase 1:
  ///   - per_session would filter inside the interceptor by authentication token, but `ua::Response`
  ///     carries no token, so there is no in-band key to filter on at this layer; and
  ///   - per_endpoint needs an SDK accessor to map a channel to its listener that does not yet exist.
  /// Both are deferred to a later phase.
  MisbehavingServer& per_channel();

  // --- Mutators -------------------------------------------------------------------------------

  /// Raw explicit override: installs a mutator invoked (on the channel strand) for every response on every
  /// channel, before signing/encryption. The mutator may edit the typed body in place. Any exception
  /// it throws is caught at the fixture boundary and recorded (see @ref last_mutator_error)  -  it is
  /// never allowed to propagate out of the asio handler.
  void set_response_mutator(std::function<void(ua::Response&)> mutator);

  /// Rewrites the `serverNonce` on each `OpenSecureChannelResponse`. The transform receives an @ref
  /// OpnNonceContext (current nonce + per-channel OPN ordinal + the recorded Issue nonce) and returns
  /// the replacement nonce. Used by CL-SC-015 (wrong length) and CL-SC-016 (reuse on renewal).
  void mutate_server_nonce(std::function<ua::ByteString(const OpnNonceContext&)> transform);

  /// Under a policy with SecureChannelEnhancements, signs each channel's Issue `OpenSecureChannelResponse`
  /// over the response alone, as a renewal's is signed, instead of over the response followed by the
  /// request's Signature (OPC 10000-6 6.7.5, the ChannelThumbprint). The CL-SCE-006 stimulus: a conforming
  /// client refuses the response. On other policies the responses are unchanged.
  void sign_issue_response_without_request_signature();

  /// Installs a read-only observer of every DECODED service request seen on every channel, invoked (on the
  /// channel strand) at the top of request handling  -  the request-side counterpart to
  /// @ref set_response_mutator. It lets a scenario assert what the client actually put on the wire (e.g. the
  /// continuation point + `releaseContinuationPoints` flag of a BrowseNext, or the ABSENCE of a BrowseNext).
  /// The observer must not throw; any exception is caught at the fixture boundary and recorded (see
  /// @ref last_mutator_error). Observers COMPOSE (each call appends). The observer captures its own
  /// synchronization: it runs on a server worker/strand while the test thread reads what it records.
  void set_request_observer(std::function<void(const ua::Structure& request)> observer);

  /// Stamps `ResponseHeader.serviceResult` with @p status on service responses.
  ///
  /// The secure-channel handshake responses (`OpenSecureChannelResponse` /
  /// `CloseSecureChannelResponse`) are deliberately left untouched so the channel still opens; only
  /// service responses are stamped. Because the type system has no common response-header base, the
  /// wrapper recognises a curated set of response types (extensible); unrecognised responses pass
  /// through unchanged.
  void set_service_result(ua::StatusCode status);

  // --- Thin wrappers for API completeness (no Phase-1 demo: there is no subscription client yet) ---

  /// Adds @p skip to the notification sequence number of `PublishResponse`s for @p subscriptionId,
  /// creating an apparent gap. Wired but unexercised in Phase 1.
  void inject_sequence_gap(ua::IntegerId subscriptionId, uint32_t skip);

  /// Stamps `RepublishResponse` with `Bad_SubscriptionIdInvalid`. Wired but unexercised in Phase 1.
  void bad_subscription_id_on_republish();

  /// Clears `availableSequenceNumbers` on every `PublishResponse`. Wired but unexercised in Phase 1.
  void drop_available_sequence_numbers();

  // --- Observation (written on the strand, read by the test thread) ---------------------------

  /// Number of times any interceptor has fired across all channels. `> 0` proves the install interface ran.
  uint64_t interceptor_fire_count() const;

  /// The nonce delivered to the client on the most recent channel's Issue OPN response (post-mutation).
  std::optional<ua::ByteString> observed_issue_server_nonce() const;

  /// Prose describing the most recent mutator exception caught at the fixture boundary, if any.
  std::optional<std::string> last_mutator_error() const;

  // --- Client-facing artifacts (so a test can build a matching client) ------------------------

  /// Endpoint URL of the unauthenticated (SecurityPolicy None) endpoint.
  std::string endpoint_url_none() const;

  /// Endpoint URL of the Basic256Sha256 SignAndEncrypt endpoint.
  std::string endpoint_url_sign_encrypt() const;

  /// The crypto provider the server was built with (share it with the client for parity).
  std::shared_ptr<const ua::Crypto> crypto() const;

  /// A certificate store suitable for a client: it holds a client application certificate the server
  /// trusts, and trusts the server certificate.
  std::shared_ptr<ua::CertificateStore> client_certificate_store() const;

  /// The server's application instance certificate (pass to the client's OpenChannelConfig).
  std::shared_ptr<const ua::X509Certificate> server_certificate() const;

  /// Access to the owned server (e.g. to install additional test interfaces).
  ua::server::Server& server();

private:
  struct Impl;

  // Declared before mImpl so it is destroyed AFTER it: the server (in mImpl) is closed and drained
  // first, guaranteeing no strand turn can still reference mState when it is released.
  std::shared_ptr<detail::MisbehavingServerState> mState;
  std::unique_ptr<Impl> mImpl;
};

}  // namespace ua::test_helpers

#endif  // !MISBEHAVING_SERVER_H
