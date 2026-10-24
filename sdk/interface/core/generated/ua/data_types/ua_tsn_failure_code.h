// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_TSN_FAILURE_CODE_H
#define UA_DATA_TYPE_TSN_FAILURE_CODE_H

#include <string>
#include <string_view>
#include "ua_data_type_trait.h"
#include "ua_includes.h"
#include "ua_namespace_uri.h"
#include "ua_datatype_id.h"

namespace ua
{

/// OPC UA TsnFailureCode enumeration data type.
/// @ingroup ua_data_types
enum class TsnFailureCode : int32_t
{
  NoFailure = 0,  ///< No failure.
  InsufficientBandwidth = 1,  ///< Insufficient bandwidth.
  InsufficientResources = 2,  ///< Insufficient bridge resources.
  InsufficientTrafficClassBandwidth = 3,  ///< Insufficient bandwidth for Traffic Class.
  StreamIdInUse = 4,  ///< StreamID in use by another Talker.
  StreamDestinationAddressInUse = 5,  ///< Stream destination address already in use.
  StreamPreemptedByHigherRank = 6,  ///< Stream pre-empted by higher rank.
  LatencyHasChanged = 7,  ///< Reported latency has changed.
  EgressPortNotAvbCapable = 8,  ///< Egress port is not AVBCapable.
  UseDifferentDestinationAddress = 9,  ///< Use a different destination address.
  OutOfMsrpResources = 10,  ///< Out of MSRP resources.
  OutOfMmrpResources = 11,  ///< Out of MMRP resources.
  CannotStoreDestinationAddress = 12,  ///< Cannot store destination address.
  PriorityIsNotAnSrcClass = 13,  ///< Requested priority is not an SR Class priority.
  MaxFrameSizeTooLarge = 14,  ///< MaxFrameSize is too large for media.
  MaxFanInPortsLimitReached = 15,  ///< MaxFanInPorts limit has been reached.
  FirstValueChangedForStreamId = 16,  ///< Changes in FirstValue for a registered StreamID.
  VlanBlockedOnEgress = 17,  ///< VLAN is blocked on this egress port (Registration Forbidden).
  VlanTaggingDisabledOnEgress = 18,  ///< VLAN tagging is disabled on this egress port (untagged set).
  SrClassPriorityMismatch = 19,  ///< SR class priority mismatch.
  FeatureNotPropagated = 20,  ///< Enhanced feature cannot be propagated to original Port.
  MaxLatencyExceeded = 21,  ///< MaxLatency exceeded.
  BridgeDoesNotProvideNetworkId =
    22,  ///< Nearest Bridge cannot provide network identification for stream transformation.
  StreamTransformNotSupported = 23,  ///< Stream transformation not supported.
  StreamIdTypeNotSupported = 24,  ///< Stream identification type not supported for stream transformation.
  FeatureNotSupported = 25,  ///< Enhanced feature cannot be supported without a CNC.
};

/// Converts an enumerator to its name.
/// @param value The enumerator to name.
/// @return The enumerator's name, or a numeric fallback if unrecognised.
std::string to_string(TsnFailureCode value);

/// Tests whether a value is a defined enumerator.
/// @param value The value to check.
/// @return `true` if `value` is a defined enumerator of TsnFailureCode.
bool is_valid(TsnFailureCode value);

}  // namespace ua

/// The OPC UA DataType of the TsnFailureCode enumeration, read by `ua::data_type_of`.
template<>
struct ua::DataTypeOf<ua::TsnFailureCode>
{
  /// The DataType's identifier in its namespace.
  static constexpr ua::DataTypeId id{ua::DataTypeId::TsnFailureCode};
  /// The namespace that owns the DataType.
  static constexpr std::string_view namespaceUri = ua::specNamespaceUri;
};

#endif  // !UA_DATA_TYPE_TSN_FAILURE_CODE_H
