// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_IDENTITY_ATTEMPT_OUTCOME_H
#define UA_IDENTITY_ATTEMPT_OUTCOME_H

namespace ua::server
{

/// How an authentication attempt that was reserved against the identity lockout budget ended
/// (Part 4 5.6.3, 7.41.2.1; SESS-2). Shared by the session (which holds the reservation) and the
/// server (which keeps the budget).
enum class IdentityAttemptOutcome
{
  Success,  ///< The token validated: that user's failures are cleared; an active lockout is NOT lifted.
  Failure,  ///< The token was refused: one more failure for (client application, user).
  Abandoned  ///< No answer reached the client: the reservation is released and nothing is counted.
};

}  // namespace ua::server

#endif  // UA_IDENTITY_ATTEMPT_OUTCOME_H
