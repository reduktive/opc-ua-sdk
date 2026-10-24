// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Strips the credential from a UserIdentityToken before it is re-published.
///
/// Shared by the audit event emitter (Part 5 6.4.11: the audit event carries the token "with the
/// password removed") and the server observer (SESS-4): both hand the token to code the SDK does not
/// control, so both hand over the same redacted copy.

#ifndef UA_CREDENTIAL_REDACTION_H
#define UA_CREDENTIAL_REDACTION_H

#include "ua_issued_identity_token.h"
#include "ua_structure.h"
#include "ua_user_name_identity_token.h"

#include <memory>

namespace ua::server
{

/// Copy a presented UserIdentityToken for auditing with its secret removed.
///
/// Part 5 section 6.4.10 on `AuditActivateSessionEventType`: "UserIdentityToken reflects the
/// userIdentityToken parameter of the ActivateSession Service call. **For Username/Password tokens
/// the password shall not be included.**" The token still has to identify the user - the UserName,
/// the PolicyId and the EncryptionAlgorithm are what make the record worth keeping, and the last of
/// those records whether the credential was protected in transit - so this redacts the secret rather
/// than dropping the token.
///
/// An AuditEvent is the most widely readable thing a Server produces: it reaches every event
/// MonitoredItem on the Server Object, the local listener, and whatever historian or export the
/// deployment attaches. A secret copied into one is a credential written into every archive the
/// audit trail reaches, and it cannot be recalled from them.
///
/// The IssuedIdentityToken's `tokenData` is redacted on the same grounds although Part 5 names only
/// the password. It is a bearer credential - whoever holds it can impersonate the user until it
/// expires - so the harm is identical and the clause's silence is not a licence to publish it. The
/// X509 token's certificate is deliberately kept: it is public by construction and is the only field
/// that identifies the user on that path.
inline std::unique_ptr<Structure> redact_credentials(const Structure& token)
{
  auto copy = token.clone();

  if (auto* userName = dynamic_cast<UserNameIdentityToken*>(copy.get()))
  {
    userName->password() = ByteString{};
    return copy;
  }
  if (auto* issued = dynamic_cast<IssuedIdentityToken*>(copy.get()))
  {
    issued->token_data() = ByteString{};
    return copy;
  }
  return copy;
}

}  // namespace ua::server

#endif  //! UA_CREDENTIAL_REDACTION_H
