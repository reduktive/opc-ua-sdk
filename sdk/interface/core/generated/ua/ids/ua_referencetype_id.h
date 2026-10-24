// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REFERENCETYPE_IDENTIFIERS_H
#define UA_REFERENCETYPE_IDENTIFIERS_H

#include "ua_includes.h"

namespace ua
{

/// Well-known OPC UA ReferenceTypeId identifiers (namespace 0).
/// @ingroup ua_node_ids
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
enum class ReferenceTypeId : uint32_t
{
  References = 31U,
  NonHierarchicalReferences = 32U,
  HierarchicalReferences = 33U,
  HasChild = 34U,
  Organizes = 35U,
  HasEventSource = 36U,
  HasModellingRule = 37U,
  HasEncoding = 38U,
  HasDescription = 39U,
  HasTypeDefinition = 40U,
  GeneratesEvent = 41U,
  Aggregates = 44U,
  HasSubtype = 45U,
  HasProperty = 46U,
  HasComponent = 47U,
  HasNotifier = 48U,
  HasOrderedComponent = 49U,
  FromState = 51U,
  ToState = 52U,
  HasCause = 53U,
  HasEffect = 54U,
  HasHistoricalConfiguration = 56U,
  HasSubStateMachine = 117U,
  HasArgumentDescription = 129U,
  HasOptionalInputArgumentDescription = 131U,
  AlwaysGeneratesEvent = 3065U,
  HasTrueSubState = 9004U,
  HasFalseSubState = 9005U,
  HasCondition = 9006U,
  HasPubSubConnection = 14476U,
  DataSetToWriter = 14936U,
  HasGuard = 15112U,
  HasDataSetWriter = 15296U,
  HasDataSetReader = 15297U,
  HasAlarmSuppressionGroup = 16361U,
  AlarmGroupMember = 16362U,
  HasEffectDisable = 17276U,
  HasDictionaryEntry = 17597U,
  HasInterface = 17603U,
  HasAddIn = 17604U,
  HasEffectEnable = 17983U,
  HasEffectSuppressed = 17984U,
  HasEffectUnsuppressed = 17985U,
  HasWriterGroup = 18804U,
  HasReaderGroup = 18805U,
  UsesDataTypeRefinement = 19814U,
  HasFieldDescription = 19815U,
  HasFieldDescriptionSetMandatory = 19816U,
  IsDisabledOptionalField = 19817U,
  UsesSubtypeRestriction = 19818U,
  AllowedSubtype = 19819U,
  HasSerializationEntity = 19845U,
  HasDataTypeRefinement = 19846U,
  AliasFor = 23469U,
  IsDeprecated = 23562U,
  HasStructuredComponent = 24136U,
  AssociatedWith = 24137U,
  UsesPriorityMappingTable = 25237U,
  HasLowerLayerInterface = 25238U,
  IsExecutableOn = 25253U,
  Controls = 25254U,
  Utilizes = 25255U,
  Requires = 25256U,
  IsPhysicallyConnectedTo = 25257U,
  RepresentsSameEntityAs = 25258U,
  RepresentsSameHardwareAs = 25259U,
  RepresentsSameFunctionalityAs = 25260U,
  IsHostedBy = 25261U,
  HasPhysicalComponent = 25262U,
  HasContainedComponent = 25263U,
  HasAttachedComponent = 25264U,
  IsExecutingOn = 25265U,
  HasPushedSecurityGroup = 25345U,
  AlarmSuppressionGroupMember = 32059U,
  HasKeyValueDescription = 32407U,
  HasEngineeringUnitDetails = 32558U,
  HasQuantity = 32559U,
  HasCurrentData = 32633U,
  HasCurrentEvent = 32634U,
  HasReferenceDescription = 32679U
};
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

}  // namespace ua

#endif  // UA_REFERENCETYPE_IDENTIFIERS_H
