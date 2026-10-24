// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_STRING_LEXICAL_VALIDATION_H
#define UA_STRING_LEXICAL_VALIDATION_H

#include "ua_node_id.h"
#include "ua_status_code.h"
#include "ua_variant.h"

namespace ua::server::string_lexical_validation
{

// =============================================================================================
// Lexical conformance for the NS0 String subtypes that constrain their own form
// (OPC 10000-3 section 8.43-section 8.47).
//
// `NormalizedString`, `DecimalString`, `DurationString`, `TimeString` and `DateString` are all
// subtypes of `String`, and the encoding carries none of what makes them different: on the wire and
// in a Variant each is a String and nothing more. So the write path's DataType check -- does the
// written built-in type match the built-in base type of the declared DataType -- compares String
// against String and accepts anything, and a malformed value is stored. It then surfaces at read
// time, on every Client that reads it, rather than at write time on the one that sent it.
//
// The rules are deliberately implemented against the lexical spaces the spec cites (ISO 8601-1:2019
// and W3C XSD 1.1 Part 2) rather than against a permissive parse. A validator that accepts whatever
// some parser happens to tolerate would admit exactly the values these clauses exist to keep out.
// =============================================================================================

/// The verdict on writing @p value to a Variable whose declared DataType is @p dataType.
///
/// Returns `Good` when the DataType imposes no lexical constraint this check knows about, when the
/// value is not a String at all (the built-in type check answers that case, and answering it twice
/// with two different statuses helps nobody), and when the value conforms. Returns
/// `Bad_TypeMismatch` when the DataType names a lexical space and the value is outside it: the value
/// is the wrong shape for its declared type, which is what that status says.
///
/// @param dataType The Variable's declared DataType.
/// @param value    The value the Client is writing.
/// @return `Good`, or `Bad_TypeMismatch` for a value outside its DataType's lexical space.
StatusCode validate(const NodeId& dataType, const Variant& value);

/// Whether @p dataType is one of the String subtypes @ref validate constrains.
///
/// Exposed so a caller can tell "this type has no lexical rule" from "this value passed the rule",
/// which the `Good` return of @ref validate deliberately conflates.
///
/// @param dataType The DataType to classify.
/// @return `true` when @ref validate applies a rule to this DataType.
bool constrains(const NodeId& dataType) noexcept;

}  // namespace ua::server::string_lexical_validation

#endif  // !UA_STRING_LEXICAL_VALIDATION_H
