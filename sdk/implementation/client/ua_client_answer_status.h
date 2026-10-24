// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief How the client treats a server's answer that is not plain Good when the SDK itself acts on it.

#ifndef UA_CLIENT_ANSWER_STATUS_H
#define UA_CLIENT_ANSWER_STATUS_H

#include "ua_error_detail.h"
#include "ua_status.h"
#include "ua_status_code.h"

#include <memory>
#include <string>
#include <string_view>

namespace ua::client::detail
{

/// The status a step of the SDK refuses with when the server answered Uncertain and the SDK would act on
/// the answer itself (a preflight, a type or References walk, a lookup the next request depends on).
///
/// An application receives a server's Uncertain answer as it was sent; the SDK does not base its own
/// decisions on one, with or without a value. The refusal is Bad_InternalError with an ErrorDetail whose
/// code names what was answered (`ReadAnswerUncertain`, `ReferencesAnswerUncertain`, ...) and whose cause
/// is the Uncertain code with its own detail.
///
/// @param answer The Uncertain code the server answered.
/// @param code   The ErrorDetail code, such as `ReadAnswerUncertain`.
/// @param source The component that refuses.
/// @return Bad_InternalError carrying the refusal detail.
inline ua::StatusCode uncertain_answer_refused(
  const ua::StatusCode& answer, std::string_view code, std::string_view source)
{
  return ua::StatusCode{ua::Status::BadInternalError,
    ua::ErrorDetail::build(
      std::string{code}, "The SDK does not act on an answer the server is uncertain of", std::string{source})
      .cause(answer)};
}

/// The status a step of the SDK refuses with when the answer it acts on is not Good: an Uncertain
/// answer becomes @ref uncertain_answer_refused, a Bad answer is passed on as it is.
///
/// @param answer The answer's status; not Good.
/// @param code   The ErrorDetail code used for an Uncertain answer.
/// @param source The component that refuses.
/// @return The status to complete with.
inline ua::StatusCode answer_refused(
  const ua::StatusCode& answer, std::string_view code, std::string_view source)
{
  if (answer.is_uncertain())
  {
    return uncertain_answer_refused(answer, code, source);
  }
  return answer;
}

/// The status a step of the client refuses with when the application's CertificateStore answered Uncertain
/// and the step would use the answer itself (the own certificate a channel presents, the issuers a
/// signature is checked against).
///
/// The refusal is Bad_InternalError with an ErrorDetail coded `CertificateStoreAnswerUncertain` whose cause
/// is the Uncertain code with its own detail.
///
/// @param answer The Uncertain code the store answered.
/// @param source The component that refuses.
/// @return Bad_InternalError carrying the refusal detail.
inline ua::StatusCode certificate_store_answer_refused(const ua::StatusCode& answer, std::string_view source)
{
  return ua::StatusCode{ua::Status::BadInternalError,
    ua::ErrorDetail::build("CertificateStoreAnswerUncertain",
      "The SDK does not act on an answer the certificate store is uncertain of",
      std::string{source})
      .cause(answer)};
}

}  // namespace ua::client::detail

#endif  // UA_CLIENT_ANSWER_STATUS_H
