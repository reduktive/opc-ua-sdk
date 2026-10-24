// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Secure-channel security token: derived symmetric keys and lifetime tracking.
/// @ingroup security

#ifndef UA_SECURITY_TOKEN_H
#define UA_SECURITY_TOKEN_H

#include "ua_byte_string.h"
#include "ua_timer.h"
#include "ua_date_time.h"
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/any_io_executor.hpp>

namespace ua
{
enum class SecurityTokenRequestType;
enum class ChannelRole;

struct SecureChannelContext;
class SecurityPolicy;

/// A UASC secure-channel security token holding the symmetric keys and lifetime negotiated for one
/// keyset generation.
///
/// A token bundles the directional key material derived from the local and remote nonces during an
/// OpenSecureChannel (Issue) or renewal (Renew), together with its server-assigned id and revised
/// lifetime. A countdown timer started from @ref created_at fires the supplied timeout callback when
/// the token expires, signalling that the channel must roll over to a renewed token. Instances are
/// created through @ref create_async and are owned by the @ref SecureChannelContext they are
/// installed on; they are not constructed directly.
/// @ingroup security
class SecurityToken
{
public:
  /// Invoked, with no arguments, when the token's revised lifetime elapses.
  ///
  /// Runs on the strand the token was created with. Signals that the keyset has expired and the
  /// channel must renew; the callback must not assume the token still exists afterwards.
  using TokenTimeoutCallback = std::function<void()>;

  /// One direction's symmetric key material derived for a security token.
  ///
  /// Empty for the SecurityPolicy#None case, where no keys are derived. The same layout is used for
  /// both the local (sending) and remote (receiving) directions.
  ///
  /// The key material is zeroed before its memory is released: when the keys are destroyed (a token
  /// replaced, retired or closed with its channel) and when they are overwritten by assignment.
  struct Keys
  {
    Keys() = default;
    Keys(const Keys&) = default;
    Keys(Keys&&) noexcept = default;
    Keys& operator=(const Keys& other);
    Keys& operator=(Keys&& other) noexcept;
    ~Keys();

    ByteString signingKey;  ///< Key for the symmetric message signature (HMAC).
    ByteString encryptingKey;  ///< Key for symmetric message body encryption.
    ByteString initializationVector;  ///< Initialization vector seeding the block cipher.

  private:
    void scrub() noexcept;
  };

  /// Returns the server-assigned token identifier carried in every secured message header.
  ///
  /// @return The server-assigned token identifier.
  uint32_t id() const;

  /// Returns the key material used to secure messages this side sends.
  ///
  /// @return The local (sending) key material.
  const Keys& local_keys() const;

  /// Returns the key material used to verify and decrypt messages received from the peer.
  ///
  /// @return The remote (receiving) key material.
  const Keys& remote_keys() const;

  /// Returns the timestamp at which the token was created and its lifetime countdown began.
  ///
  /// @return The token creation timestamp.
  DateTime created_at() const;

  /// Returns the negotiated token lifetime, in milliseconds, after which the token expires.
  ///
  /// @return The negotiated token lifetime, in milliseconds.
  std::chrono::milliseconds revised_lifetime() const;

  /// Whether the revised lifetime has elapsed since the token was created, on the steady clock its expiry
  /// timer runs on (a wall-clock step neither lengthens nor shortens it). One clock read.
  ///
  /// @return `true` once the token has expired.
  bool has_expired() const;

  /// Outcome of @ref create_async - the newly installed token (owned by the context) or an error.
  using CreateResult = Result<SecurityToken*>;

  /// Derives the symmetric keys and constructs a token installed on the secure-channel context.
  ///
  /// Derives both key directions from @p localNonce and @p remoteNonce via the policy carried by
  /// @p context, then constructs a token and installs it on the context: as the active token for an
  /// @c Issue request, or as the pending (renewed) token for a @c Renew request. The token's
  /// expiry timer is armed from @p revisedLifetime.
  ///
  /// @param requestType          Whether this is an initial @c Issue or a @c Renew of an existing
  ///                             channel; selects the install slot on @p context.
  /// @param context              Secure-channel context that supplies the security policy and takes
  ///                             ownership of the created token. Must outlive the operation.
  /// @param id                   Server-assigned token identifier to embed in secured messages.
  /// @param revisedLifetime      Negotiated token lifetime, in milliseconds, used to arm the expiry
  ///                             timer.
  /// @param localNonce           This side's nonce contributed to key derivation.
  /// @param remoteNonce          The peer's nonce contributed to key derivation.
  /// @param role                 Whether this participant acts as server or client, fixing the
  ///                             nonce ordering used during key derivation.
  /// @param tokenTimeoutCallback Invoked when the token's lifetime elapses; see
  ///                             @ref TokenTimeoutCallback.
  /// @param callback             Receives the outcome: on success the @ref CreateResult holds a raw
  ///                             pointer to the installed token (owned by @p context); on failure it
  ///                             carries the originating status and @ref ErrorDetail from key
  ///                             derivation. This function never throws.
  static void create_async(SecurityTokenRequestType requestType, shared_ptr<SecureChannelContext> context,
    uint32_t id, std::chrono::milliseconds revisedLifetime, ByteString localNonce, ByteString remoteNonce,
    ChannelRole role, TokenTimeoutCallback tokenTimeoutCallback, std::function<void(CreateResult)> callback);

protected:
  /// Constructs a token from already-derived key material and arms its expiry timer.
  ///
  /// Not called directly; @ref create_async derives the keys and constructs the token. Exposed for
  /// derivation by the key-deriving security policies.
  ///
  /// @param strand               Strand on which the expiry timer runs and the timeout callback is
  ///                             invoked.
  /// @param localKeys            Derived key material for the local (sending) direction.
  /// @param remoteKeys           Derived key material for the remote (receiving) direction.
  /// @param id                   Server-assigned token identifier.
  /// @param revisedLifetime      Negotiated token lifetime, in milliseconds, used to arm the timer.
  /// @param tokenTimeoutCallback Invoked when the lifetime elapses; see @ref TokenTimeoutCallback.
  SecurityToken(boost::asio::strand<boost::asio::any_io_executor> strand, Keys localKeys, Keys remoteKeys,
    uint32_t id, std::chrono::milliseconds revisedLifetime, TokenTimeoutCallback tokenTimeoutCallback);

private:
  uint32_t mId;
  Keys mLocalKeys;
  Keys mRemoteKeys;
  Timer mTimeoutTimer;
  DateTime mCreatedAt;
  std::chrono::milliseconds mRevisedLifetime;
  std::chrono::steady_clock::time_point mExpiresAt;
};

}  // namespace ua

#endif  //! UA_SECURITY_TOKEN_H
