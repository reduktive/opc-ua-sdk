// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_STATUS_H
#define UA_STATUS_H

#include <cstdint>

namespace ua
{

/// OPC UA status-code constants.
/// @ingroup ua_node_ids
enum class Status : uint32_t
{
  Good = 0x00000000U,  ///< The operation succeeded.
  GoodSubscriptionTransferred = 0x002D0000U,  ///< The subscription was transferred to another session.
  GoodCompletesAsynchronously = 0x002E0000U,  ///< The processing will complete asynchronously.
  GoodOverload = 0x002F0000U,  ///< Sampling has slowed down due to resource limitations.
  GoodClamped = 0x00300000U,  ///< The value written was accepted but was clamped.
  GoodLocalOverride = 0x00960000U,  ///< The value has been overridden.
  GoodEntryInserted =
    0x00A20000U,  ///< The data or event was successfully inserted into the historical database.
  GoodEntryReplaced =
    0x00A30000U,  ///< The data or event field was successfully replaced in the historical database.
  GoodNoData = 0x00A50000U,  ///< No data exists for the requested time range or event filter.
  GoodMoreData =
    0x00A60000U,  ///< More data is available in the time range beyond the number of values requested.
  GoodCommunicationEvent = 0x00A70000U,  ///< The communication layer has raised an event.
  GoodShutdownEvent = 0x00A80000U,  ///< The system is shutting down.
  GoodCallAgain = 0x00A90000U,  ///< The operation is not finished and needs to be called again.
  GoodNonCriticalTimeout = 0x00AA0000U,  ///< A non-critical timeout occurred.
  GoodResultsMayBeIncomplete = 0x00BA0000U,  ///< The server should have followed a reference to a node in a
                                             ///< remote server but did not. The result set may be incomplete.
  GoodDataIgnored = 0x00D90000U,  ///< The request specifies fields which are not valid for the EventType or
                                  ///< cannot be saved by the historian.
  GoodEdited =
    0x00DC0000U,  ///< The value does not come from the real source and has been edited by the server.
  GoodPostActionFailed = 0x00DD0000U,  ///< There was an error in execution of these post-actions.
  GoodRetransmissionQueueNotSupported =
    0x00DF0000U,  ///< The Server does not support retransmission queue and acknowledgement of sequence
                  ///< numbers is not available.
  GoodDependentValueChanged =
    0x00E00000U,  ///< A dependent value has been changed but the change has not been applied to the device.
  GoodSubNormal = 0x00EB0000U,  ///< The value is derived from multiple sources and has the required number of
                                ///< Good sources, but less than the full number of Good sources.
  GoodPasswordChangeRequired =
    0x00EF0000U,  ///< The log-on for the user succeeded but the user is required to change the password.
  GoodEdited_DependentValueChanged =
    0x01160000U,  ///< It is delivered with a dominant Variable value when a dependent Variable has changed
                  ///< but the change has not been applied.
  GoodEdited_DominantValueChanged =
    0x01170000U,  ///< It is delivered with a dependent Variable value when a dominant Variable has changed
                  ///< but the change has not been applied.
  GoodEdited_DominantValueChanged_DependentValueChanged =
    0x01180000U,  ///< It is delivered with a dependent Variable value when a dominant or dependent Variable
                  ///< has changed but change has not been applied.
  GoodCascadeInitializationAcknowledged =
    0x04010000U,  ///< The value source supports cascade handshaking and the value has been Initialized based
                  ///< on an initialization request from a cascade secondary.
  GoodCascadeInitializationRequest = 0x04020000U,  ///< The value source supports cascade handshaking and is
                                                   ///< requesting initialization of a cascade primary.
  GoodCascadeNotInvited = 0x04030000U,  ///< The value source supports cascade handshaking, however, the
                                        ///< source's current state does not allow for cascade.
  GoodCascadeNotSelected =
    0x04040000U,  ///< The value source supports cascade handshaking, however, the source has not selected the
                  ///< corresponding cascade primary for use.
  GoodFaultStateActive = 0x04070000U,  ///< There is a fault state condition active in the value source.
  GoodInitiateFaultState = 0x04080000U,  ///< A fault state condition is being requested of the destination.
  GoodCascade = 0x04090000U,  ///< The value is accurate, and the signal source supports cascade handshaking.
  Uncertain = 0x40000000U,  ///< The operation was uncertain.
  UncertainReferenceOutOfServer =
    0x406C0000U,  ///< One of the references to follow in the relative path references to a node in the
                  ///< address space in another server.
  UncertainNoCommunicationLastUsableValue =
    0x408F0000U,  ///< Communication to the data source has failed. The variable value is the last value that
                  ///< had a good quality.
  UncertainLastUsableValue = 0x40900000U,  ///< Whatever was updating this value has stopped doing so.
  UncertainSubstituteValue =
    0x40910000U,  ///< The value is an operational value that was manually overwritten.
  UncertainInitialValue = 0x40920000U,  ///< The value is an initial value for a variable that normally
                                        ///< receives its value from another variable.
  UncertainSensorNotAccurate = 0x40930000U,  ///< The value is at one of the sensor limits.
  UncertainEngineeringUnitsExceeded =
    0x40940000U,  ///< The value is outside of the range of values defined for this parameter.
  UncertainSubNormal = 0x40950000U,  ///< The data value is derived from multiple sources and has less than
                                     ///< the required number of Good sources.
  UncertainDataSubNormal = 0x40A40000U,  ///< The aggregate value is derived from multiple values and has less
                                         ///< than the required number of Good values.
  UncertainReferenceNotDeleted = 0x40BC0000U,  ///< The server was not able to delete all target references.
  UncertainNotAllNodesAvailable = 0x40C00000U,  ///< The list of references may not be complete because the
                                                ///< underlying system is not available.
  UncertainDominantValueChanged =
    0x40DE0000U,  ///< The related EngineeringUnit has been changed but the Variable Value is still provided
                  ///< based on the previous unit.
  UncertainDependentValueChanged =
    0x40E20000U,  ///< A dependent value has been changed but the change has not been applied to the device.
                  ///< The quality of the dominant variable is uncertain.
  UncertainTransducerInManual =
    0x42080000U,  ///< The value may not be accurate because the transducer is in manual mode.
  UncertainSimulatedValue = 0x42090000U,  ///< The value is simulated.
  UncertainSensorCalibration =
    0x420A0000U,  ///< The value may not be accurate due to a sensor calibration fault.
  UncertainConfigurationError = 0x420F0000U,  ///< The value may not be accurate due to a configuration issue.
  Bad = 0x80000000U,  ///< The operation failed.
  BadUnexpectedError = 0x80010000U,  ///< An unexpected error occurred.
  BadInternalError =
    0x80020000U,  ///< An internal error occurred as a result of a programming or configuration error.
  BadOutOfMemory = 0x80030000U,  ///< Not enough memory to complete the operation.
  BadResourceUnavailable = 0x80040000U,  ///< An operating system resource is not available.
  BadCommunicationError = 0x80050000U,  ///< A low level communication error occurred.
  BadEncodingError =
    0x80060000U,  ///< Encoding halted because of invalid data in the objects being serialized.
  BadDecodingError = 0x80070000U,  ///< Decoding halted because of invalid data in the stream.
  BadEncodingLimitsExceeded =
    0x80080000U,  ///< The message encoding/decoding limits imposed by the stack have been exceeded.
  BadUnknownResponse = 0x80090000U,  ///< An unrecognized response was received from the server.
  BadTimeout = 0x800A0000U,  ///< The operation timed out.
  BadServiceUnsupported = 0x800B0000U,  ///< The server does not support the requested service.
  BadShutdown = 0x800C0000U,  ///< The operation was cancelled because the application is shutting down.
  BadServerNotConnected =
    0x800D0000U,  ///< The operation could not complete because the client is not connected to the server.
  BadServerHalted = 0x800E0000U,  ///< The server has stopped and cannot process any requests.
  BadNothingToDo = 0x800F0000U,  ///< No processing could be done because there was nothing to do.
  BadTooManyOperations =
    0x80100000U,  ///< The request could not be processed because it specified too many operations.
  BadDataTypeIdUnknown = 0x80110000U,  ///< The extension object cannot be (de)serialized because the data
                                       ///< type id is not recognized.
  BadCertificateInvalid = 0x80120000U,  ///< The certificate provided as a parameter is not valid.
  BadSecurityChecksFailed = 0x80130000U,  ///< An error occurred verifying security.
  BadCertificateTimeInvalid = 0x80140000U,  ///< The certificate has expired or is not yet valid.
  BadCertificateIssuerTimeInvalid = 0x80150000U,  ///< An issuer certificate has expired or is not yet valid.
  BadCertificateHostNameInvalid =
    0x80160000U,  ///< The HostName used to connect to a server does not match a HostName in the certificate.
  BadCertificateUriInvalid = 0x80170000U,  ///< The URI specified in the ApplicationDescription does not match
                                           ///< the URI in the certificate.
  BadCertificateUseNotAllowed =
    0x80180000U,  ///< The certificate may not be used for the requested operation.
  BadCertificateIssuerUseNotAllowed =
    0x80190000U,  ///< The issuer certificate may not be used for the requested operation.
  BadCertificateUntrusted = 0x801A0000U,  ///< The certificate is not trusted.
  BadCertificateRevocationUnknown =
    0x801B0000U,  ///< It was not possible to determine if the certificate has been revoked.
  BadCertificateIssuerRevocationUnknown =
    0x801C0000U,  ///< It was not possible to determine if the issuer certificate has been revoked.
  BadCertificateRevoked = 0x801D0000U,  ///< The certificate has been revoked.
  BadCertificateIssuerRevoked = 0x801E0000U,  ///< The issuer certificate has been revoked.
  BadUserAccessDenied = 0x801F0000U,  ///< User does not have permission to perform the requested operation.
  BadIdentityTokenInvalid = 0x80200000U,  ///< The user identity token is not valid.
  BadIdentityTokenRejected =
    0x80210000U,  ///< The user identity token is valid but the server has rejected it.
  BadSecureChannelIdInvalid = 0x80220000U,  ///< The specified secure channel is no longer valid.
  BadInvalidTimestamp = 0x80230000U,  ///< The timestamp is outside the range allowed by the server.
  BadNonceInvalid =
    0x80240000U,  ///< The nonce does appear to be not a random value or it is not the correct length.
  BadSessionIdInvalid = 0x80250000U,  ///< The session id is not valid.
  BadSessionClosed = 0x80260000U,  ///< The session was closed by the client.
  BadSessionNotActivated =
    0x80270000U,  ///< The session cannot be used because ActivateSession has not been called.
  BadSubscriptionIdInvalid = 0x80280000U,  ///< The subscription id is not valid.
  BadRequestHeaderInvalid = 0x802A0000U,  ///< The header for the request is missing or invalid.
  BadTimestampsToReturnInvalid = 0x802B0000U,  ///< The timestamps to return parameter is invalid.
  BadRequestCancelledByClient = 0x802C0000U,  ///< The request was cancelled by the client.
  BadNoCommunication = 0x80310000U,  ///< Communication with the data source is defined, but not established,
                                     ///< and there is no last known value available.
  BadWaitingForInitialData =
    0x80320000U,  ///< Waiting for the server to obtain values from the underlying data source.
  BadNodeIdInvalid = 0x80330000U,  ///< The syntax the node id is not valid or refers to a node that is not
                                   ///< valid for the operation.
  BadNodeIdUnknown =
    0x80340000U,  ///< The node id refers to a node that does not exist in the server address space.
  BadAttributeIdInvalid = 0x80350000U,  ///< The attribute is not supported for the specified Node.
  BadIndexRangeInvalid = 0x80360000U,  ///< The syntax of the index range parameter is invalid.
  BadIndexRangeNoData = 0x80370000U,  ///< No data exists within the range of indexes specified.
  BadDataEncodingInvalid = 0x80380000U,  ///< The data encoding is invalid.
  BadDataEncodingUnsupported =
    0x80390000U,  ///< The server does not support the requested data encoding for the node.
  BadNotReadable = 0x803A0000U,  ///< The access level does not allow reading or subscribing to the Node.
  BadNotWritable = 0x803B0000U,  ///< The access level does not allow writing to the Node.
  BadOutOfRange = 0x803C0000U,  ///< The value was out of range.
  BadNotSupported = 0x803D0000U,  ///< The requested operation is not supported.
  BadNotFound = 0x803E0000U,  ///< A requested item was not found or a search operation ended without success.
  BadObjectDeleted = 0x803F0000U,  ///< The object cannot be used because it has been deleted.
  BadNotImplemented = 0x80400000U,  ///< Requested operation is not implemented.
  BadMonitoringModeInvalid = 0x80410000U,  ///< The monitoring mode is invalid.
  BadMonitoredItemIdInvalid =
    0x80420000U,  ///< The monitoring item id does not refer to a valid monitored item.
  BadMonitoredItemFilterInvalid = 0x80430000U,  ///< The monitored item filter parameter is not valid.
  BadMonitoredItemFilterUnsupported =
    0x80440000U,  ///< The server does not support the requested monitored item filter.
  BadFilterNotAllowed =
    0x80450000U,  ///< A monitoring filter cannot be used in combination with the attribute specified.
  BadStructureMissing = 0x80460000U,  ///< A mandatory structured parameter was missing or null.
  BadEventFilterInvalid = 0x80470000U,  ///< The event filter is not valid.
  BadContentFilterInvalid = 0x80480000U,  ///< The content filter is not valid.
  BadFilterOperandInvalid = 0x80490000U,  ///< The operand used in a content filter is not valid.
  BadContinuationPointInvalid = 0x804A0000U,  ///< The continuation point provide is longer valid.
  BadNoContinuationPoints = 0x804B0000U,  ///< The operation could not be processed because all continuation
                                          ///< points have been allocated.
  BadReferenceTypeIdInvalid =
    0x804C0000U,  ///< The reference type id does not refer to a valid reference type node.
  BadBrowseDirectionInvalid = 0x804D0000U,  ///< The browse direction is not valid.
  BadNodeNotInView = 0x804E0000U,  ///< The node is not part of the view.
  BadServerUriInvalid = 0x804F0000U,  ///< The ServerUri is not a valid URI.
  BadServerNameMissing = 0x80500000U,  ///< No ServerName was specified.
  BadDiscoveryUrlMissing = 0x80510000U,  ///< No DiscoveryUrl was specified.
  BadSemaphoreFileMissing = 0x80520000U,  ///< The semaphore file specified by the client is not valid.
  BadRequestTypeInvalid = 0x80530000U,  ///< The security token request type is not valid.
  BadSecurityModeRejected =
    0x80540000U,  ///< The security mode does not meet the requirements set by the server.
  BadSecurityPolicyRejected =
    0x80550000U,  ///< The security policy does not meet the requirements set by the server.
  BadTooManySessions = 0x80560000U,  ///< The server has reached its maximum number of sessions.
  BadUserSignatureInvalid = 0x80570000U,  ///< The user token signature is missing or invalid.
  BadApplicationSignatureInvalid =
    0x80580000U,  ///< The signature generated with the client certificate is missing or invalid.
  BadNoValidCertificates = 0x80590000U,  ///< The client did not provide at least one software certificate
                                         ///< that is valid and meets the profile requirements for the server.
  BadRequestCancelledByRequest =
    0x805A0000U,  ///< The request was cancelled by the client with the Cancel service.
  BadParentNodeIdInvalid = 0x805B0000U,  ///< The parent node id does not to refer to a valid node.
  BadReferenceNotAllowed = 0x805C0000U,  ///< The reference could not be created because it violates
                                         ///< constraints imposed by the data model.
  BadNodeIdRejected = 0x805D0000U,  ///< The requested node id was reject because it was either invalid or
                                    ///< server does not allow node ids to be specified by the client.
  BadNodeIdExists = 0x805E0000U,  ///< The requested node id is already used by another node.
  BadNodeClassInvalid = 0x805F0000U,  ///< The node class is not valid.
  BadBrowseNameInvalid = 0x80600000U,  ///< The browse name is invalid.
  BadBrowseNameDuplicated = 0x80610000U,  ///< The browse name is not unique among nodes that share the same
                                          ///< relationship with the parent.
  BadNodeAttributesInvalid = 0x80620000U,  ///< The node attributes are not valid for the node class.
  BadTypeDefinitionInvalid =
    0x80630000U,  ///< The type definition node id does not reference an appropriate type node.
  BadSourceNodeIdInvalid = 0x80640000U,  ///< The source node id does not reference a valid node.
  BadTargetNodeIdInvalid = 0x80650000U,  ///< The target node id does not reference a valid node.
  BadDuplicateReferenceNotAllowed =
    0x80660000U,  ///< The reference type between the nodes is already defined.
  BadInvalidSelfReference =
    0x80670000U,  ///< The server does not allow this type of self reference on this node.
  BadReferenceLocalOnly =
    0x80680000U,  ///< The reference type is not valid for a reference to a remote server.
  BadNoDeleteRights = 0x80690000U,  ///< The server will not allow the node to be deleted.
  BadServerIndexInvalid = 0x806A0000U,  ///< The server index is not valid.
  BadViewIdUnknown = 0x806B0000U,  ///< The view id does not refer to a valid view node.
  BadTooManyMatches = 0x806D0000U,  ///< The requested operation has too many matches to return.
  BadQueryTooComplex = 0x806E0000U,  ///< The requested operation requires too many resources in the server.
  BadNoMatch = 0x806F0000U,  ///< The requested operation has no match to return.
  BadMaxAgeInvalid = 0x80700000U,  ///< The max age parameter is invalid.
  BadHistoryOperationInvalid = 0x80710000U,  ///< The history details parameter is not valid.
  BadHistoryOperationUnsupported = 0x80720000U,  ///< The server does not support the requested operation.
  BadWriteNotSupported = 0x80730000U,  ///< The server does not support writing the combination of value,
                                       ///< status and timestamps provided.
  BadTypeMismatch =
    0x80740000U,  ///< The value supplied for the attribute is not of the same type as the attribute's value.
  BadMethodInvalid = 0x80750000U,  ///< The method id does not refer to a method for the specified object.
  BadArgumentsMissing =
    0x80760000U,  ///< The client did not specify all of the input arguments for the method.
  BadTooManySubscriptions = 0x80770000U,  ///< The server has reached its maximum number of subscriptions.
  BadTooManyPublishRequests =
    0x80780000U,  ///< The server has reached the maximum number of queued publish requests.
  BadNoSubscription = 0x80790000U,  ///< There is no subscription available for this session.
  BadSequenceNumberUnknown = 0x807A0000U,  ///< The sequence number is unknown to the server.
  BadMessageNotAvailable = 0x807B0000U,  ///< The requested notification message is no longer available.
  BadInsufficientClientProfile = 0x807C0000U,  ///< The client of the current session does not support one or
                                               ///< more Profiles that are necessary for the subscription.
  BadTcpServerTooBusy = 0x807D0000U,  ///< The server cannot process the request because it is too busy.
  BadTcpMessageTypeInvalid = 0x807E0000U,  ///< The type of the message specified in the header invalid.
  BadTcpSecureChannelUnknown = 0x807F0000U,  ///< The SecureChannelId and/or TokenId are not currently in use.
  BadTcpMessageTooLarge =
    0x80800000U,  ///< The size of the message chunk specified in the header is too large.
  BadTcpNotEnoughResources = 0x80810000U,  ///< There are not enough resources to process the request.
  BadTcpInternalError = 0x80820000U,  ///< An internal error occurred.
  BadTcpEndpointUrlInvalid = 0x80830000U,  ///< The server does not recognize the QueryString specified.
  BadRequestInterrupted = 0x80840000U,  ///< The request could not be sent because of a network interruption.
  BadRequestTimeout = 0x80850000U,  ///< Timeout occurred while processing the request.
  BadSecureChannelClosed = 0x80860000U,  ///< The secure channel has been closed.
  BadSecureChannelTokenUnknown = 0x80870000U,  ///< The token has expired or is not recognized.
  BadSequenceNumberInvalid = 0x80880000U,  ///< The sequence number is not valid.
  BadConfigurationError =
    0x80890000U,  ///< There is a problem with the configuration that affects the usefulness of the value.
  BadNotConnected = 0x808A0000U,  ///< The variable should receive its value from another variable, but has
                                  ///< never been configured to do so.
  BadDeviceFailure = 0x808B0000U,  ///< There has been a failure in the device/data source that generates the
                                   ///< value that has affected the value.
  BadSensorFailure = 0x808C0000U,  ///< There has been a failure in the sensor from which the value is derived
                                   ///< by the device/data source.
  BadOutOfService = 0x808D0000U,  ///< The source of the data is not operational.
  BadDeadbandFilterInvalid = 0x808E0000U,  ///< The deadband filter is not valid.
  BadRefreshInProgress =
    0x80970000U,  ///< This Condition refresh failed, a Condition refresh operation is already in progress.
  BadConditionAlreadyDisabled = 0x80980000U,  ///< This condition has already been disabled.
  BadConditionDisabled = 0x80990000U,  ///< Property not available, this condition is disabled.
  BadEventIdUnknown = 0x809A0000U,  ///< The specified event id is not recognized.
  BadNoData = 0x809B0000U,  ///< No data exists for the requested time range or event filter.
  BadDataLost = 0x809D0000U,  ///< Data is missing due to collection started/stopped/lost.
  BadDataUnavailable =
    0x809E0000U,  ///< Expected data is unavailable for the requested time range due to an un-mounted volume,
                  ///< an off-line archive or tape, or similar reason for temporary unavailability.
  BadEntryExists =
    0x809F0000U,  ///< The data or event was not successfully inserted because a matching entry exists.
  BadNoEntryExists =
    0x80A00000U,  ///< The data or event was not successfully updated because no matching entry exists.
  BadTimestampNotSupported =
    0x80A10000U,  ///< The Client requested history using a TimestampsToReturn the Server does not support.
  BadInvalidArgument = 0x80AB0000U,  ///< One or more arguments are invalid.
  BadConnectionRejected = 0x80AC0000U,  ///< Could not establish a network connection to remote server.
  BadDisconnect = 0x80AD0000U,  ///< The server has disconnected from the client.
  BadConnectionClosed = 0x80AE0000U,  ///< The network connection has been closed.
  BadInvalidState = 0x80AF0000U,  ///< The operation cannot be completed because the object is closed,
                                  ///< uninitialized or in some other invalid state.
  BadEndOfStream = 0x80B00000U,  ///< Cannot move beyond end of the stream.
  BadNoDataAvailable =
    0x80B10000U,  ///< No data is currently available for reading from a non-blocking stream.
  BadWaitingForResponse = 0x80B20000U,  ///< The asynchronous operation is waiting for a response.
  BadOperationAbandoned = 0x80B30000U,  ///< The asynchronous operation was abandoned by the caller.
  BadExpectedStreamToBlock = 0x80B40000U,  ///< The stream did not return all data requested (possibly because
                                           ///< it is a non-blocking stream).
  BadWouldBlock = 0x80B50000U,  ///< Non blocking behaviour is required and the operation would block.
  BadSyntaxError = 0x80B60000U,  ///< A value had an invalid syntax.
  BadMaxConnectionsReached =
    0x80B70000U,  ///< The operation could not be finished because all available connections are in use.
  BadRequestTooLarge = 0x80B80000U,  ///< The request message size exceeds limits set by the server.
  BadResponseTooLarge =
    0x80B90000U,  ///< The response message size exceeds limits set by the client or server.
  BadEventNotAcknowledgeable = 0x80BB0000U,  ///< The event cannot be acknowledged.
  BadInvalidTimestampArgument = 0x80BD0000U,  ///< The defined timestamp to return was invalid.
  BadProtocolVersionUnsupported =
    0x80BE0000U,  ///< The applications do not have compatible protocol versions.
  BadStateNotActive = 0x80BF0000U,  ///< The sub-state machine is not currently active.
  BadFilterOperatorInvalid = 0x80C10000U,  ///< An unrecognized operator was provided in a filter.
  BadFilterOperatorUnsupported = 0x80C20000U,  ///< A valid operator was provided, but the server does not
                                               ///< provide support for this filter operator.
  BadFilterOperandCountMismatch = 0x80C30000U,  ///< The number of operands provided for the filter operator
                                                ///< was less then expected for the operand provided.
  BadFilterElementInvalid =
    0x80C40000U,  ///< The referenced element is not a valid element in the content filter.
  BadFilterLiteralInvalid = 0x80C50000U,  ///< The referenced literal is not a valid value.
  BadIdentityChangeNotSupported =
    0x80C60000U,  ///< The server does not support changing the user identity assigned to the session.
  BadNotTypeDefinition = 0x80C80000U,  ///< The provided Nodeid was not a type definition nodeid.
  BadViewTimestampInvalid = 0x80C90000U,  ///< The view timestamp is not available or not supported.
  BadViewParameterMismatch = 0x80CA0000U,  ///< The view parameters are not consistent with each other.
  BadViewVersionInvalid = 0x80CB0000U,  ///< The view version is not available or not supported.
  BadConditionAlreadyEnabled = 0x80CC0000U,  ///< This condition has already been enabled.
  BadDialogNotActive = 0x80CD0000U,  ///< The dialog condition is not active.
  BadDialogResponseInvalid = 0x80CE0000U,  ///< The response is not valid for the dialog.
  BadConditionBranchAlreadyAcked = 0x80CF0000U,  ///< The condition branch has already been acknowledged.
  BadConditionBranchAlreadyConfirmed = 0x80D00000U,  ///< The condition branch has already been confirmed.
  BadConditionAlreadyShelved = 0x80D10000U,  ///< The condition has already been shelved.
  BadConditionNotShelved = 0x80D20000U,  ///< The condition is not currently shelved.
  BadShelvingTimeOutOfRange = 0x80D30000U,  ///< The shelving time not within an acceptable range.
  BadAggregateListMismatch =
    0x80D40000U,  ///< The requested number of Aggregates does not match the requested number of NodeIds.
  BadAggregateNotSupported = 0x80D50000U,  ///< The requested Aggregate is not support by the server.
  BadAggregateInvalidInputs =
    0x80D60000U,  ///< The aggregate value could not be derived due to invalid data inputs.
  BadBoundNotFound = 0x80D70000U,  ///< No data found to provide upper or lower bound value.
  BadBoundNotSupported = 0x80D80000U,  ///< The server cannot retrieve a bound for the variable.
  BadAggregateConfigurationRejected =
    0x80DA0000U,  ///< The aggregate configuration is not valid for specified node.
  BadTooManyMonitoredItems = 0x80DB0000U,  ///< The request could not be processed because there are too many
                                           ///< monitored items in the subscription.
  BadDominantValueChanged = 0x80E10000U,  ///< The related EngineeringUnit has been changed but this change
                                          ///< has not been applied to the device. The Variable Value is still
                                          ///< dependent on the previous unit but its status is currently Bad.
  BadDependentValueChanged =
    0x80E30000U,  ///< A dependent value has been changed but the change has not been applied to the device.
                  ///< The quality of the dominant variable is Bad.
  BadRequestNotAllowed = 0x80E40000U,  ///< The request was rejected by the server because it did not meet the
                                       ///< criteria set by the server.
  BadTooManyArguments = 0x80E50000U,  ///< Too many arguments were provided.
  BadSecurityModeInsufficient =
    0x80E60000U,  ///< The operation is not permitted over the current secure channel.
  BadDataSetIdInvalid = 0x80E70000U,  ///< The DataSet specified for the DataSetWriter creation is invalid.
  BadTransactionPending =
    0x80E80000U,  ///< The operation is not allowed because a transaction is in progress.
  BadLocked = 0x80E90000U,  ///< The requested operation is not allowed, because the Node is locked by a
                            ///< different application.
  BadIndexRangeDataMismatch = 0x80EA0000U,  ///< The written data does not match the IndexRange specified.
  BadRequiresLock = 0x80EC0000U,  ///< The requested operation is not allowed, because the Node is not locked
                                  ///< by the application.
  BadLocaleNotSupported = 0x80ED0000U,  ///< The locale in the requested write operation is not supported.
  BadServerTooBusy =
    0x80EE0000U,  ///< The Server does not have the resources to process the request at this time.
  BadNoValue = 0x80F00000U,  ///< The variable has no default value and no initial value.
  BadTransactionFailed = 0x80F10000U,  ///< The operation failed and all changes which were part of the
                                       ///< transaction are rolled back.
  BadCertificateChainIncomplete = 0x810D0000U,  ///< The certificate chain is incomplete.
  BadLicenseExpired = 0x810E0000U,  ///< The server requires a license to operate in general or to perform a
                                    ///< service or operation, but existing license is expired.
  BadLicenseLimitsExceeded =
    0x810F0000U,  ///< The server has limits on number of allowed operations / objects, based on installed
                  ///< licenses, and these limits where exceeded.
  BadLicenseNotAvailable = 0x81100000U,  ///< The server does not have a license which is required to operate
                                         ///< in general or to perform a service or operation.
  BadNotExecutable = 0x81110000U,  ///< The executable attribute does not allow the execution of the method.
  BadNumericOverflow = 0x81120000U,  ///< The number was not accepted because of a numeric overflow.
  BadRequestNotComplete = 0x81130000U,  ///< The request has not been processed by the server yet.
  BadCertificatePolicyCheckFailed =
    0x81140000U,  ///< The certificate does not meet the requirements of the security policy.
  BadAlreadyExists = 0x81150000U,  ///< An equivalent rule already exists.
  BadEdited_OutOfRange = 0x81190000U,  ///< It is delivered with a Variable value when Variable has changed
                                       ///< but the value is not legal.
  BadInitialValue_OutOfRange = 0x811A0000U,  ///< It is delivered with a Variable value when a source Variable
                                             ///< has changed but the value is not legal.
  BadOutOfRange_DominantValueChanged =
    0x811B0000U,  ///< It is delivered with a dependent Variable value when a dominant Variable has changed
                  ///< and the value is not legal.
  BadEdited_OutOfRange_DominantValueChanged =
    0x811C0000U,  ///< It is delivered with a dependent Variable value when a dominant Variable has changed,
                  ///< the value is not legal and the change has not been applied.
  BadOutOfRange_DominantValueChanged_DependentValueChanged =
    0x811D0000U,  ///< It is delivered with a dependent Variable value when a dominant or dependent Variable
                  ///< has changed and the value is not legal.
  BadEdited_OutOfRange_DominantValueChanged_DependentValueChanged =
    0x811E0000U,  ///< It is delivered with a dependent Variable value when a dominant or dependent Variable
                  ///< has changed, the value is not legal and the change has not been applied.
  BadTicketRequired = 0x811F0000U,  ///< The device identity needs a ticket before it can be accepted.
  BadTicketInvalid = 0x81200000U  ///< The device identity needs a ticket before it can be accepted.
};

}  // namespace ua

#endif  // UA_STATUS_H
