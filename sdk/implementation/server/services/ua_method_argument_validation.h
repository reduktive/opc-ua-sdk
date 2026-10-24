// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_METHOD_ARGUMENT_VALIDATION_H
#define UA_METHOD_ARGUMENT_VALIDATION_H

#include "ua_argument.h"
#include "ua_array.h"
#include "ua_call_method_request.h"
#include "ua_call_method_result.h"
#include "ua_variant.h"

#include <cstddef>

namespace ua::server
{

// =============================================================================================
// Model-driven Call input-argument validation (OPC 10000-4 5.11.2).
//
// The batched Call flow validates the supplied input arguments against the method
// node's InputArguments Property BEFORE the handler runs. This is independent of the typed
// MethodAdapter tuple (the generic set_call_handler path does no validation), so the model
// is the single source of truth for what a Method accepts.
//
// A method with NO InputArguments Property is NOT validated here: there is nothing in the
// model to validate against, so validation is delegated to the handler. (Imposing an
// empty-expected rule on such methods would reject any method that relies on its handler /
// MethodAdapter for argument validation.)
// =============================================================================================

/// Synchronous validation core. Validates `request.input_arguments()` against the declared
/// `expectedArguments` (the decoded InputArguments Property value).
///
/// On failure, sets `result.status_code()` to the operation-level status and, for a
/// per-argument type/rank mismatch, fills `result.input_argument_results()` (sized to the
/// number of declared arguments) with `Bad_TypeMismatch` at each offending index and `Good`
/// elsewhere. Returns the validation status:
///   - Good                  -> arguments valid, handler may run
///   - Bad_ArgumentsMissing  -> fewer args than non-optional declared
///   - Bad_TooManyArguments  -> more args than declared
///   - Bad_InvalidArgument   -> at least one arg has the wrong data type / value rank
///
StatusCode validate_input_arguments(
  const Array<Argument>& expectedArguments, const CallMethodRequest& request, CallMethodResult& result);

/// As above, with the number of leading arguments that are required. Arguments from
/// `requiredArgumentCount` to the end of `expectedArguments` are an optional trailing suffix.
StatusCode validate_input_arguments(const Array<Argument>& expectedArguments, size_t requiredArgumentCount,
  const CallMethodRequest& request, CallMethodResult& result);

/// True iff `supplied` is acceptable for an Argument declaring data type `expectedDataType`
/// with value rank `expectedValueRank`. Handles the abstract supertypes (BaseDataType, Number,
/// Integer, UInteger, Enumeration) and the scalar/array rank families of Part 3 5.6.2.
bool argument_value_matches(
  const NodeId& expectedDataType, int32_t expectedValueRank, const Variant& supplied);

struct InputArgumentsMetadata
{
  Array<Argument> arguments;
  size_t requiredArgumentCount{0};
};

}  // namespace ua::server

#endif  // UA_METHOD_ARGUMENT_VALIDATION_H
