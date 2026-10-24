// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_VARIABLETYPE_IDENTIFIERS_H
#define UA_VARIABLETYPE_IDENTIFIERS_H

#include "ua_includes.h"

namespace ua
{

/// Well-known OPC UA VariableTypeId identifiers (namespace 0).
/// @ingroup ua_node_ids
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
enum class VariableTypeId : uint32_t
{
  BaseVariableType = 62U,
  BaseDataVariableType = 63U,
  PropertyType = 68U,
  DataTypeDescriptionType = 69U,
  DataTypeDictionaryType = 72U,
  ServerVendorCapabilityType = 2137U,
  ServerStatusType = 2138U,
  ServerDiagnosticsSummaryType = 2150U,
  SamplingIntervalDiagnosticsArrayType = 2164U,
  SamplingIntervalDiagnosticsType = 2165U,
  SubscriptionDiagnosticsArrayType = 2171U,
  SubscriptionDiagnosticsType = 2172U,
  SessionDiagnosticsArrayType = 2196U,
  SessionDiagnosticsVariableType = 2197U,
  SessionSecurityDiagnosticsArrayType = 2243U,
  SessionSecurityDiagnosticsType = 2244U,
  DataItemType = 2365U,
  AnalogItemType = 2368U,
  DiscreteItemType = 2372U,
  TwoStateDiscreteType = 2373U,
  MultiStateDiscreteType = 2376U,
  ProgramDiagnosticType = 2380U,
  StateVariableType = 2755U,
  FiniteStateVariableType = 2760U,
  TransitionVariableType = 2762U,
  FiniteTransitionVariableType = 2767U,
  BuildInfoType = 3051U,
  TwoStateVariableType = 8995U,
  ConditionVariableType = 9002U,
  MultiStateValueDiscreteType = 11238U,
  OptionSetType = 11487U,
  ArrayItemType = 12021U,
  YArrayItemType = 12029U,
  XYArrayItemType = 12038U,
  ImageItemType = 12047U,
  CubeItemType = 12057U,
  NDimensionArrayItemType = 12068U,
  GuardVariableType = 15113U,
  ExpressionGuardVariableType = 15128U,
  ElseGuardVariableType = 15317U,
  BaseAnalogType = 15318U,
  ProgramDiagnostic2Type = 15383U,
  SelectionListType = 16309U,
  AlarmRateVariableType = 17277U,
  AnalogUnitType = 17497U,
  AnalogUnitRangeType = 17570U,
  RationalNumberType = 17709U,
  VectorType = 17714U,
  ThreeDVectorType = 17716U,
  AudioVariableType = 17986U,
  CartesianCoordinatesType = 18772U,
  ThreeDCartesianCoordinatesType = 18774U,
  OrientationType = 18779U,
  ThreeDOrientationType = 18781U,
  FrameType = 18786U,
  ThreeDFrameType = 18791U,
  MultiStateDictionaryEntryDiscreteBaseType = 19077U,
  MultiStateDictionaryEntryDiscreteType = 19084U,
  PubSubDiagnosticsCounterType = 19725U,
  AlarmStateVariableType = 32244U,
  BitFieldType = 32431U,
  ReferenceDescriptionVariableType = 32657U
};
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

}  // namespace ua

#endif  // UA_VARIABLETYPE_IDENTIFIERS_H
