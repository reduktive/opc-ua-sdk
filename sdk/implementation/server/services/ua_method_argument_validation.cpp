// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_method_argument_validation.h"

#include "ua_datatype_id.h"
#include "ua_error_detail.h"
#include "ua_node_utilities.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_to_string.h"
#include "ua_value_rank.h"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ua::server
{

namespace
{

// Map a Variant's runtime built-in type to a representative NS0 DataType numeric id, used to
// compare the supplied argument against the Argument's declared data type. This mirrors the
// established type-matching in DynamicStructureTypeDescriptor (the inverse direction): the
// matcher only needs the concrete built-in identity of the supplied value.
uint32_t built_in_type_to_data_type_id(BuiltInTypeId type)
{
  switch (type)
  {
  case BuiltInTypeId::Boolean:
    return static_cast<uint32_t>(DataTypeId::Boolean);
  case BuiltInTypeId::SByte:
    return static_cast<uint32_t>(DataTypeId::SByte);
  case BuiltInTypeId::Byte:
    return static_cast<uint32_t>(DataTypeId::Byte);
  case BuiltInTypeId::Int16:
    return static_cast<uint32_t>(DataTypeId::Int16);
  case BuiltInTypeId::UInt16:
    return static_cast<uint32_t>(DataTypeId::UInt16);
  case BuiltInTypeId::Int32:
    return static_cast<uint32_t>(DataTypeId::Int32);
  case BuiltInTypeId::UInt32:
    return static_cast<uint32_t>(DataTypeId::UInt32);
  case BuiltInTypeId::Int64:
    return static_cast<uint32_t>(DataTypeId::Int64);
  case BuiltInTypeId::UInt64:
    return static_cast<uint32_t>(DataTypeId::UInt64);
  case BuiltInTypeId::Float:
    return static_cast<uint32_t>(DataTypeId::Float);
  case BuiltInTypeId::Double:
    return static_cast<uint32_t>(DataTypeId::Double);
  case BuiltInTypeId::String:
    return static_cast<uint32_t>(DataTypeId::String);
  case BuiltInTypeId::DateTime:
    return static_cast<uint32_t>(DataTypeId::DateTime);
  case BuiltInTypeId::Guid:
    return static_cast<uint32_t>(DataTypeId::Guid);
  case BuiltInTypeId::ByteString:
    return static_cast<uint32_t>(DataTypeId::ByteString);
  case BuiltInTypeId::XmlElement:
    return static_cast<uint32_t>(DataTypeId::XmlElement);
  case BuiltInTypeId::NodeId:
    return static_cast<uint32_t>(DataTypeId::NodeId);
  case BuiltInTypeId::ExpandedNodeId:
    return static_cast<uint32_t>(DataTypeId::ExpandedNodeId);
  case BuiltInTypeId::StatusCode:
    return static_cast<uint32_t>(DataTypeId::StatusCode);
  case BuiltInTypeId::QualifiedName:
    return static_cast<uint32_t>(DataTypeId::QualifiedName);
  case BuiltInTypeId::LocalizedText:
    return static_cast<uint32_t>(DataTypeId::LocalizedText);
  case BuiltInTypeId::ExtensionObject:
    return static_cast<uint32_t>(DataTypeId::Structure);
  case BuiltInTypeId::DataValue:
    return static_cast<uint32_t>(DataTypeId::DataValue);
  case BuiltInTypeId::DiagnosticInfo:
    return static_cast<uint32_t>(DataTypeId::DiagnosticInfo);
  case BuiltInTypeId::Variant:
    return static_cast<uint32_t>(DataTypeId::BaseDataType);
  case BuiltInTypeId::Null:
  default:
    return 0;
  }
}

bool is_integer_built_in(BuiltInTypeId type)
{
  switch (type)
  {
  case BuiltInTypeId::SByte:
  case BuiltInTypeId::Int16:
  case BuiltInTypeId::Int32:
  case BuiltInTypeId::Int64:
  case BuiltInTypeId::Byte:
  case BuiltInTypeId::UInt16:
  case BuiltInTypeId::UInt32:
  case BuiltInTypeId::UInt64:
    return true;
  default:
    return false;
  }
}

bool is_unsigned_built_in(BuiltInTypeId type)
{
  switch (type)
  {
  case BuiltInTypeId::Byte:
  case BuiltInTypeId::UInt16:
  case BuiltInTypeId::UInt32:
  case BuiltInTypeId::UInt64:
    return true;
  default:
    return false;
  }
}

bool is_number_built_in(BuiltInTypeId type)
{
  return is_integer_built_in(type) || type == BuiltInTypeId::Float || type == BuiltInTypeId::Double;
}

// True iff the supplied value's data type satisfies the declared abstract NS0 DataType.
bool matches_abstract_data_type(uint32_t declaredId, BuiltInTypeId suppliedType)
{
  switch (declaredId)
  {
  case static_cast<uint32_t>(DataTypeId::BaseDataType):
    return true;  // accepts any type
  case static_cast<uint32_t>(DataTypeId::Number):
    return is_number_built_in(suppliedType);
  case static_cast<uint32_t>(DataTypeId::Integer):
    return is_integer_built_in(suppliedType);
  case static_cast<uint32_t>(DataTypeId::UInteger):
    return is_unsigned_built_in(suppliedType);
  case static_cast<uint32_t>(DataTypeId::Enumeration):
    // Enumerations are transmitted as Int32 on the wire.
    return suppliedType == BuiltInTypeId::Int32;
  default:
    return false;
  }
}

// Value-rank compatibility (OPC 10000-3 5.6.2). A scalar value satisfies Scalar, Any, and
// ScalarOrOneDimension; an array satisfies array ranks, Any, and ScalarOrOneDimension.
bool rank_matches(int32_t expectedValueRank, const Variant& supplied)
{
  const ValueRank rank{expectedValueRank};
  if (rank.is_any())
  {
    return true;
  }
  if (rank.is_scalar())
  {
    return supplied.is_scalar();
  }
  if (rank.is_scalar_or_one_dimension())
  {
    return supplied.is_scalar() || supplied.is_array();
  }
  // Array ranks (OneDimension / OneOrMoreDimensions / n-dimensional).
  return supplied.is_array();
}

// True iff `declaredId` is a *primitive* built-in DataType id (one that maps 1:1 to a
// BuiltInTypeId, including Structure via ExtensionObject), as opposed to an abstract supertype
// (BaseDataType/Number/Integer/UInteger/Enumeration) or a concrete *named subtype* of a built-in
// (e.g. Duration, IntegerId, UtcTime). A supplied value carries only its built-in encoding on the
// wire, so a mismatch against a primitive declaration is a genuine type error, whereas a mismatch
// against a named subtype cannot be judged without resolving its built-in root through the
// DataType hierarchy.
bool is_built_in_primitive_data_type(uint32_t declaredId)
{
  for (auto type : {BuiltInTypeId::Boolean,
         BuiltInTypeId::SByte,
         BuiltInTypeId::Byte,
         BuiltInTypeId::Int16,
         BuiltInTypeId::UInt16,
         BuiltInTypeId::Int32,
         BuiltInTypeId::UInt32,
         BuiltInTypeId::Int64,
         BuiltInTypeId::UInt64,
         BuiltInTypeId::Float,
         BuiltInTypeId::Double,
         BuiltInTypeId::String,
         BuiltInTypeId::DateTime,
         BuiltInTypeId::Guid,
         BuiltInTypeId::ByteString,
         BuiltInTypeId::XmlElement,
         BuiltInTypeId::NodeId,
         BuiltInTypeId::ExpandedNodeId,
         BuiltInTypeId::StatusCode,
         BuiltInTypeId::QualifiedName,
         BuiltInTypeId::LocalizedText,
         BuiltInTypeId::ExtensionObject,
         BuiltInTypeId::DataValue,
         BuiltInTypeId::DiagnosticInfo})
  {
    if (built_in_type_to_data_type_id(type) == declaredId)
    {
      return true;
    }
  }
  return false;
}

}  // namespace

bool argument_value_matches(
  const NodeId& expectedDataType, int32_t expectedValueRank, const Variant& supplied)
{
  // A Null/empty supplied value is a valid Variant state - an omitted optional input or a
  // BaseDataType input passed as Null (e.g. GenerateFileForRead's GenerateOptions). Whether Null
  // is acceptable for a given argument is the handler's decision, not a model type-shape mismatch,
  // so it passes model validation. Checked before rank, since a Null Variant is neither scalar nor
  // array and would otherwise fail the rank test.
  if (supplied.empty())
  {
    return true;
  }

  // Part 4 5.11.2: ByteString is the compact wire representation of an array of Byte. Treat this
  // alias before the ordinary rank check because Variant correctly reports ByteString as scalar.
  if (expectedValueRank == 1 && expectedDataType == NodeId{DataTypeId::Byte} &&
      supplied.get_built_in_type() == BuiltInTypeId::ByteString)
  {
    return true;
  }

  if (!rank_matches(expectedValueRank, supplied))
  {
    return false;
  }

  // Non-NS0 declared types: defer to the handler (no model introspection of custom types in the
  // 2025 baseline). Accept so a server defining custom-typed inputs is not over-constrained.
  if (expectedDataType.namespace_index() != 0 || !expectedDataType.is_numeric())
  {
    return true;
  }

  const uint32_t declaredId = expectedDataType.identifier().get_numeric();
  const BuiltInTypeId suppliedType = supplied.get_built_in_type();
  const uint32_t suppliedAsDataTypeId = built_in_type_to_data_type_id(suppliedType);

  if (declaredId == suppliedAsDataTypeId)
  {
    return true;
  }

  // Abstract NS0 supertypes accept their concrete subtypes.
  if (matches_abstract_data_type(declaredId, suppliedType))
  {
    return true;
  }

  // Structure/ExtensionObject: any structure-typed value satisfies a Structure-typed declaration.
  if (declaredId == static_cast<uint32_t>(DataTypeId::Structure) &&
      suppliedType == BuiltInTypeId::ExtensionObject)
  {
    return true;
  }

  // Concrete NS0 *named subtypes* of a built-in (e.g. Duration->Double, IntegerId->UInt32) and
  // any non-NS0/custom concrete DataType arrive on the wire as their built-in encoding, so the
  // declared NodeId cannot be matched here without resolving its built-in root through the
  // DataType hierarchy (a documented follow-up). Reject only when the declared type is itself a
  // primitive built-in (a genuine mismatch like "declared Int32, got String"); otherwise accept
  // and defer the precise type check to the handler / MethodAdapter.
  return !is_built_in_primitive_data_type(declaredId);
}

StatusCode validate_input_arguments(
  const Array<Argument>& expectedArguments, const CallMethodRequest& request, CallMethodResult& result)
{
  return validate_input_arguments(expectedArguments, expectedArguments.size(), request, result);
}

StatusCode validate_input_arguments(const Array<Argument>& expectedArguments, size_t requiredArgumentCount,
  const CallMethodRequest& request, CallMethodResult& result)
{
  const auto& supplied = request.input_arguments();
  const size_t expectedCount = expectedArguments.size();
  const size_t suppliedCount = supplied.size();

  // Part 3 5.7.3 requires optional inputs to form a trailing suffix. The model reader derives the
  // required leading count from those references; too few means at least one non-optional input
  // is absent, while a count between required and total omits only optional inputs.
  if (suppliedCount < requiredArgumentCount)
  {
    result.status_code() = Status::BadArgumentsMissing;
    return Status::BadArgumentsMissing;
  }
  if (suppliedCount > expectedCount)
  {
    result.status_code() = Status::BadTooManyArguments;
    return Status::BadTooManyArguments;
  }

  // Per-argument data type / value rank check. Table 65 requires inputArgumentResults, when
  // populated, to match the supplied inputArguments length. Optional omitted slots have no result.
  result.input_argument_results().resize(suppliedCount);
  bool anyBad = false;
  for (size_t i = 0; i < suppliedCount; ++i)
  {
    const auto& argumentDefinition = expectedArguments[i];
    if (argument_value_matches(argumentDefinition.data_type(), argumentDefinition.value_rank(), supplied[i]))
    {
      result.input_argument_results()[i] = StatusCode{Status::Good};
    }
    else
    {
      result.input_argument_results()[i] = StatusCode{Status::BadTypeMismatch};
      anyBad = true;
    }
  }

  if (anyBad)
  {
    result.status_code() = Status::BadInvalidArgument;
    return Status::BadInvalidArgument;
  }

  // All declared inputs validated; clear the per-argument results (no diagnostics carried for a
  // successful operation).
  result.input_argument_results().payload().clear();
  return Status::Good;
}

}  // namespace ua::server
