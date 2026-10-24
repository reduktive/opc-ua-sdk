// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_STATUS_ROUTING_H
#define UA_STATUS_ROUTING_H

#include <string>
#include <string_view>

#include "ua_data_value.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_logger.h"
#include "ua_node_id.h"
#include "ua_status_code.h"
#include "ua_to_result.h"
#include "ua_to_string.h"

namespace ua::server::detail
{

/// The ErrorDetail code of a lookup the SDK refuses because the namespace answered it Uncertain.
inline constexpr std::string_view lookupAnswerUncertain{"LookupAnswerUncertain"};
/// The ErrorDetail code of a Value or attribute read the SDK refuses because the namespace answered it
/// Uncertain.
inline constexpr std::string_view readAnswerUncertain{"ReadAnswerUncertain"};
/// The ErrorDetail code of a read of References the SDK refuses because the namespace answered it Uncertain.
inline constexpr std::string_view referencesAnswerUncertain{"ReferencesAnswerUncertain"};
/// The ErrorDetail code of any other answer the SDK acts on and refuses because it is Uncertain: an
/// application callback's answer that is not a lookup, a read or a monitoring answer, such as a node
/// management delegate's preparation of an AddNodes item.
inline constexpr std::string_view answerUncertain{"AnswerUncertain"};

/// The ErrorDetail summary of every refusal of an Uncertain answer.
inline constexpr std::string_view uncertainAnswerSummary{
  "The SDK does not act on an answer the namespace is uncertain of"};

/// The refusal of an Uncertain @p answer to a step the SDK acts on itself (a lookup whose Node it changes, a
/// read whose value decides a rule, a walk of References or types): `Bad_InternalError` with the ErrorDetail
/// @p code (one of the `*AnswerUncertain` codes above), the summary @ref uncertainAnswerSummary, @p nodeId as
/// context and @p answer, with its own detail, as the cause. The SDK refuses an Uncertain answer whether or
/// not it holds a value. A detail that cannot be built answers the allocation failure instead.
///
/// @param code   The ErrorDetail code.
/// @param answer The namespace's Uncertain answer.
/// @param source The ErrorDetail source: the component refusing.
/// @param nodeId The Node the step was about.
/// @return The refusal.
inline StatusCode uncertain_answer_refused(
  std::string_view code, const StatusCode& answer, std::string_view source, const NodeId& nodeId) noexcept
{
  try
  {
    return StatusCode{Status::BadInternalError,
      ErrorDetail::build(std::string{code}, std::string{uncertainAnswerSummary}, std::string{source})
        .context(ContextKeys::nodeId, nodeId)
        .cause(answer)};
  }
  catch (...)
  {
    return exception_to_status_code(std::current_exception());
  }
}

/// @ref uncertain_answer_refused for a step about no one Node, or one whose Node the refusing component does
/// not hold: the same refusal without the Node as context.
///
/// @param code   The ErrorDetail code.
/// @param answer The namespace's Uncertain answer.
/// @param source The ErrorDetail source: the component refusing.
/// @return The refusal.
inline StatusCode uncertain_answer_refused(
  std::string_view code, const StatusCode& answer, std::string_view source) noexcept
{
  try
  {
    return StatusCode{Status::BadInternalError,
      ErrorDetail::build(std::string{code}, std::string{uncertainAnswerSummary}, std::string{source})
        .cause(answer)};
  }
  catch (...)
  {
    return exception_to_status_code(std::current_exception());
  }
}

/// What a step the SDK acts on answers when the namespace's @p answer to it is not Good: a Bad answer is the
/// step's own, with its detail; an Uncertain answer, with or without a value, is refused as
/// @ref uncertain_answer_refused says. A Good subcode on such a step is consumed by the step, so a caller
/// tests `is_good()` and calls this otherwise.
///
/// @param code   The ErrorDetail code of the refusal of an Uncertain answer.
/// @param answer The namespace's answer; not Good.
/// @param source The ErrorDetail source: the component refusing.
/// @param nodeId The Node the step was about.
/// @return @p answer when it is Bad, otherwise the refusal.
inline StatusCode not_acted_on(
  std::string_view code, const StatusCode& answer, std::string_view source, const NodeId& nodeId) noexcept
{
  if (answer.is_bad())
  {
    return answer;
  }
  return uncertain_answer_refused(code, answer, source, nodeId);
}

/// @ref not_acted_on for a step about no one Node, or one whose Node the refusing component does not hold.
///
/// @param code   The ErrorDetail code of the refusal of an Uncertain answer.
/// @param answer The namespace's answer; not Good.
/// @param source The ErrorDetail source: the component refusing.
/// @return @p answer when it is Bad, otherwise the refusal.
inline StatusCode not_acted_on(
  std::string_view code, const StatusCode& answer, std::string_view source) noexcept
{
  if (answer.is_bad())
  {
    return answer;
  }
  return uncertain_answer_refused(code, answer, source);
}

/// The one status an item answers when its namespace's answer carries a code on the result that holds the
/// item (@p outer) and the item has a status of its own (@p inner), and the wire has room for one: the code
/// @ref ua::detail::combined_status gives. When @p outer has a SubCode, is not the one answered and is not
/// the code @p inner already answers, it is logged at Warning with @p site as the message, so the code the
/// namespace gave is not lost without trace.
///
/// @param outer  The code of the result holding the item.
/// @param inner  The item's own status.
/// @param logger The service's logger.
/// @param site   The log message naming the service and the item.
/// @param nodeId The Node the item is about.
/// @return The status the item answers.
inline StatusCode combined_item_status(const StatusCode& outer, const StatusCode& inner, const Logger& logger,
  std::string_view site, const NodeId& nodeId)
{
  if (ua::detail::outer_status_answered(outer, inner))
  {
    return outer;
  }
  if (ua::detail::has_subcode(outer) && outer.as_status() != inner.as_status() &&
      logger.is_enabled(LogLevel::Warning))
  {
    const std::string outerText = to_string(outer);
    const std::string innerText = to_string(inner);
    const std::string nodeText = to_string(nodeId);
    logger.warning({{"nodeId", std::string_view{nodeText}},
                     {"status", std::string_view{outerText}},
                     {"answered", std::string_view{innerText}}},
      "{}",
      site);
  }
  return inner;
}

/// Puts @p outer, the code of the result that holds @p value, on @p value's status as
/// @ref combined_item_status says. A DataValue without a status is Good, and keeps no status unless @p outer
/// is answered.
///
/// @param value  The item's DataValue.
/// @param outer  The code of the result holding it; not Bad, since a Bad result holds no DataValue.
/// @param logger The service's logger.
/// @param site   The log message naming the service and the item.
/// @param nodeId The Node the item is about.
inline void route_outer_status(DataValue& value, const StatusCode& outer, const Logger& logger,
  std::string_view site, const NodeId& nodeId)
{
  const StatusCode inner = value.status().value_or(StatusCode{Status::Good});
  if (ua::detail::outer_status_answered(outer, inner))
  {
    value.status() = outer;
    return;
  }
  (void)combined_item_status(outer, inner, logger, site, nodeId);
}

}  // namespace ua::server::detail

#endif  // !UA_STATUS_ROUTING_H
