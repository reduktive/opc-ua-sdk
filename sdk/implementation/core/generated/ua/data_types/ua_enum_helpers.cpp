// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_naming_rule_type.h"
#include "ua_redundant_server_mode.h"
#include "ua_open_file_mode.h"
#include "ua_identity_criteria_type.h"
#include "ua_conversion_limit_enum.h"
#include "ua_trust_list_masks.h"
#include "ua_configuration_update_type.h"
#include "ua_diagnostics_level.h"
#include "ua_pub_sub_diagnostics_counter_classification.h"
#include "ua_duplex.h"
#include "ua_interface_admin_status.h"
#include "ua_interface_oper_status.h"
#include "ua_negotiation_status.h"
#include "ua_tsn_failure_code.h"
#include "ua_tsn_stream_state.h"
#include "ua_tsn_talker_status.h"
#include "ua_tsn_listener_status.h"
#include "ua_chassis_id_subtype.h"
#include "ua_port_id_subtype.h"
#include "ua_man_addr_if_subtype.h"
#include "ua_id_type.h"
#include "ua_node_class.h"
#include "ua_structure_type.h"
#include "ua_application_type.h"
#include "ua_message_security_mode.h"
#include "ua_user_token_type.h"
#include "ua_security_token_request_type.h"
#include "ua_node_attributes_mask.h"
#include "ua_filter_operator.h"
#include "ua_history_update_type.h"
#include "ua_perform_update_type.h"
#include "ua_redundancy_support.h"
#include "ua_server_state.h"
#include "ua_axis_scale_enumeration.h"
#include "ua_exception_deviation_format.h"
#include "ua_browse_direction.h"
#include "ua_browse_result_mask.h"
#include "ua_timestamps_to_return.h"
#include "ua_sort_order_type.h"
#include "ua_monitoring_mode.h"
#include "ua_data_change_trigger.h"
#include "ua_deadband_type.h"
#include "ua_model_change_structure_verb_mask.h"
#include "ua_utilities.h"

namespace ua
{

std::string to_string(NamingRuleType value)
{
  switch (value)
  {
  case NamingRuleType::Mandatory:
    return "Mandatory";
  case NamingRuleType::Optional:
    return "Optional";
  case NamingRuleType::Constraint:
    return "Constraint";
  default:
    return "NamingRuleType(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(NamingRuleType value)
{
  auto v = utils::as_int32(value);
  return v >= 1 && v <= 3;
}

std::string to_string(RedundantServerMode value)
{
  switch (value)
  {
  case RedundantServerMode::PrimaryWithBackup:
    return "PrimaryWithBackup";
  case RedundantServerMode::PrimaryOnly:
    return "PrimaryOnly";
  case RedundantServerMode::BackupReady:
    return "BackupReady";
  case RedundantServerMode::BackupNotReady:
    return "BackupNotReady";
  default:
    return "RedundantServerMode(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(RedundantServerMode value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 3;
}

std::string to_string(OpenFileMode value)
{
  switch (value)
  {
  case OpenFileMode::Read:
    return "Read";
  case OpenFileMode::Write:
    return "Write";
  case OpenFileMode::EraseExisting:
    return "EraseExisting";
  case OpenFileMode::Append:
    return "Append";
  default:
    return "OpenFileMode(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(OpenFileMode value)
{
  switch (value)
  {
  case OpenFileMode::Read:
  case OpenFileMode::Write:
  case OpenFileMode::EraseExisting:
  case OpenFileMode::Append:
    return true;
  default:
    return false;
  }
}

std::string to_string(IdentityCriteriaType value)
{
  switch (value)
  {
  case IdentityCriteriaType::UserName:
    return "UserName";
  case IdentityCriteriaType::Thumbprint:
    return "Thumbprint";
  case IdentityCriteriaType::Role:
    return "Role";
  case IdentityCriteriaType::GroupId:
    return "GroupId";
  case IdentityCriteriaType::Anonymous:
    return "Anonymous";
  case IdentityCriteriaType::AuthenticatedUser:
    return "AuthenticatedUser";
  case IdentityCriteriaType::Application:
    return "Application";
  case IdentityCriteriaType::X509Subject:
    return "X509Subject";
  case IdentityCriteriaType::TrustedApplication:
    return "TrustedApplication";
  default:
    return "IdentityCriteriaType(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(IdentityCriteriaType value)
{
  auto v = utils::as_int32(value);
  return v >= 1 && v <= 9;
}

std::string to_string(ConversionLimitEnum value)
{
  switch (value)
  {
  case ConversionLimitEnum::NoConversion:
    return "NoConversion";
  case ConversionLimitEnum::Limited:
    return "Limited";
  case ConversionLimitEnum::Unlimited:
    return "Unlimited";
  default:
    return "ConversionLimitEnum(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(ConversionLimitEnum value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 2;
}

std::string to_string(TrustListMasks value)
{
  switch (value)
  {
  case TrustListMasks::None:
    return "None";
  case TrustListMasks::TrustedCertificates:
    return "TrustedCertificates";
  case TrustListMasks::TrustedCrls:
    return "TrustedCrls";
  case TrustListMasks::IssuerCertificates:
    return "IssuerCertificates";
  case TrustListMasks::IssuerCrls:
    return "IssuerCrls";
  case TrustListMasks::All:
    return "All";
  default:
    return "TrustListMasks(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(TrustListMasks value)
{
  switch (value)
  {
  case TrustListMasks::None:
  case TrustListMasks::TrustedCertificates:
  case TrustListMasks::TrustedCrls:
  case TrustListMasks::IssuerCertificates:
  case TrustListMasks::IssuerCrls:
  case TrustListMasks::All:
    return true;
  default:
    return false;
  }
}

std::string to_string(ConfigurationUpdateType value)
{
  switch (value)
  {
  case ConfigurationUpdateType::Insert:
    return "Insert";
  case ConfigurationUpdateType::Replace:
    return "Replace";
  case ConfigurationUpdateType::InsertOrReplace:
    return "InsertOrReplace";
  case ConfigurationUpdateType::Delete:
    return "Delete";
  default:
    return "ConfigurationUpdateType(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(ConfigurationUpdateType value)
{
  auto v = utils::as_int32(value);
  return v >= 1 && v <= 4;
}

std::string to_string(DiagnosticsLevel value)
{
  switch (value)
  {
  case DiagnosticsLevel::Basic:
    return "Basic";
  case DiagnosticsLevel::Advanced:
    return "Advanced";
  case DiagnosticsLevel::Info:
    return "Info";
  case DiagnosticsLevel::Log:
    return "Log";
  case DiagnosticsLevel::Debug:
    return "Debug";
  default:
    return "DiagnosticsLevel(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(DiagnosticsLevel value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 4;
}

std::string to_string(PubSubDiagnosticsCounterClassification value)
{
  switch (value)
  {
  case PubSubDiagnosticsCounterClassification::Information:
    return "Information";
  case PubSubDiagnosticsCounterClassification::Error:
    return "Error";
  default:
    return "PubSubDiagnosticsCounterClassification(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(PubSubDiagnosticsCounterClassification value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 1;
}

std::string to_string(Duplex value)
{
  switch (value)
  {
  case Duplex::Full:
    return "Full";
  case Duplex::Half:
    return "Half";
  case Duplex::Unknown:
    return "Unknown";
  default:
    return "Duplex(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(Duplex value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 2;
}

std::string to_string(InterfaceAdminStatus value)
{
  switch (value)
  {
  case InterfaceAdminStatus::Up:
    return "Up";
  case InterfaceAdminStatus::Down:
    return "Down";
  case InterfaceAdminStatus::Testing:
    return "Testing";
  default:
    return "InterfaceAdminStatus(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(InterfaceAdminStatus value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 2;
}

std::string to_string(InterfaceOperStatus value)
{
  switch (value)
  {
  case InterfaceOperStatus::Up:
    return "Up";
  case InterfaceOperStatus::Down:
    return "Down";
  case InterfaceOperStatus::Testing:
    return "Testing";
  case InterfaceOperStatus::Unknown:
    return "Unknown";
  case InterfaceOperStatus::Dormant:
    return "Dormant";
  case InterfaceOperStatus::NotPresent:
    return "NotPresent";
  case InterfaceOperStatus::LowerLayerDown:
    return "LowerLayerDown";
  default:
    return "InterfaceOperStatus(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(InterfaceOperStatus value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 6;
}

std::string to_string(NegotiationStatus value)
{
  switch (value)
  {
  case NegotiationStatus::InProgress:
    return "InProgress";
  case NegotiationStatus::Complete:
    return "Complete";
  case NegotiationStatus::Failed:
    return "Failed";
  case NegotiationStatus::Unknown:
    return "Unknown";
  case NegotiationStatus::NoNegotiation:
    return "NoNegotiation";
  default:
    return "NegotiationStatus(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(NegotiationStatus value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 4;
}

std::string to_string(TsnFailureCode value)
{
  switch (value)
  {
  case TsnFailureCode::NoFailure:
    return "NoFailure";
  case TsnFailureCode::InsufficientBandwidth:
    return "InsufficientBandwidth";
  case TsnFailureCode::InsufficientResources:
    return "InsufficientResources";
  case TsnFailureCode::InsufficientTrafficClassBandwidth:
    return "InsufficientTrafficClassBandwidth";
  case TsnFailureCode::StreamIdInUse:
    return "StreamIdInUse";
  case TsnFailureCode::StreamDestinationAddressInUse:
    return "StreamDestinationAddressInUse";
  case TsnFailureCode::StreamPreemptedByHigherRank:
    return "StreamPreemptedByHigherRank";
  case TsnFailureCode::LatencyHasChanged:
    return "LatencyHasChanged";
  case TsnFailureCode::EgressPortNotAvbCapable:
    return "EgressPortNotAvbCapable";
  case TsnFailureCode::UseDifferentDestinationAddress:
    return "UseDifferentDestinationAddress";
  case TsnFailureCode::OutOfMsrpResources:
    return "OutOfMsrpResources";
  case TsnFailureCode::OutOfMmrpResources:
    return "OutOfMmrpResources";
  case TsnFailureCode::CannotStoreDestinationAddress:
    return "CannotStoreDestinationAddress";
  case TsnFailureCode::PriorityIsNotAnSrcClass:
    return "PriorityIsNotAnSrcClass";
  case TsnFailureCode::MaxFrameSizeTooLarge:
    return "MaxFrameSizeTooLarge";
  case TsnFailureCode::MaxFanInPortsLimitReached:
    return "MaxFanInPortsLimitReached";
  case TsnFailureCode::FirstValueChangedForStreamId:
    return "FirstValueChangedForStreamId";
  case TsnFailureCode::VlanBlockedOnEgress:
    return "VlanBlockedOnEgress";
  case TsnFailureCode::VlanTaggingDisabledOnEgress:
    return "VlanTaggingDisabledOnEgress";
  case TsnFailureCode::SrClassPriorityMismatch:
    return "SrClassPriorityMismatch";
  case TsnFailureCode::FeatureNotPropagated:
    return "FeatureNotPropagated";
  case TsnFailureCode::MaxLatencyExceeded:
    return "MaxLatencyExceeded";
  case TsnFailureCode::BridgeDoesNotProvideNetworkId:
    return "BridgeDoesNotProvideNetworkId";
  case TsnFailureCode::StreamTransformNotSupported:
    return "StreamTransformNotSupported";
  case TsnFailureCode::StreamIdTypeNotSupported:
    return "StreamIdTypeNotSupported";
  case TsnFailureCode::FeatureNotSupported:
    return "FeatureNotSupported";
  default:
    return "TsnFailureCode(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(TsnFailureCode value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 25;
}

std::string to_string(TsnStreamState value)
{
  switch (value)
  {
  case TsnStreamState::Disabled:
    return "Disabled";
  case TsnStreamState::Configuring:
    return "Configuring";
  case TsnStreamState::Ready:
    return "Ready";
  case TsnStreamState::Operational:
    return "Operational";
  case TsnStreamState::Error:
    return "Error";
  default:
    return "TsnStreamState(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(TsnStreamState value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 4;
}

std::string to_string(TsnTalkerStatus value)
{
  switch (value)
  {
  case TsnTalkerStatus::None:
    return "None";
  case TsnTalkerStatus::Ready:
    return "Ready";
  case TsnTalkerStatus::Failed:
    return "Failed";
  default:
    return "TsnTalkerStatus(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(TsnTalkerStatus value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 2;
}

std::string to_string(TsnListenerStatus value)
{
  switch (value)
  {
  case TsnListenerStatus::None:
    return "None";
  case TsnListenerStatus::Ready:
    return "Ready";
  case TsnListenerStatus::PartialFailed:
    return "PartialFailed";
  case TsnListenerStatus::Failed:
    return "Failed";
  default:
    return "TsnListenerStatus(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(TsnListenerStatus value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 3;
}

std::string to_string(ChassisIdSubtype value)
{
  switch (value)
  {
  case ChassisIdSubtype::ChassisComponent:
    return "ChassisComponent";
  case ChassisIdSubtype::InterfaceAlias:
    return "InterfaceAlias";
  case ChassisIdSubtype::PortComponent:
    return "PortComponent";
  case ChassisIdSubtype::MacAddress:
    return "MacAddress";
  case ChassisIdSubtype::NetworkAddress:
    return "NetworkAddress";
  case ChassisIdSubtype::InterfaceName:
    return "InterfaceName";
  case ChassisIdSubtype::Local:
    return "Local";
  default:
    return "ChassisIdSubtype(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(ChassisIdSubtype value)
{
  auto v = utils::as_int32(value);
  return v >= 1 && v <= 7;
}

std::string to_string(PortIdSubtype value)
{
  switch (value)
  {
  case PortIdSubtype::InterfaceAlias:
    return "InterfaceAlias";
  case PortIdSubtype::PortComponent:
    return "PortComponent";
  case PortIdSubtype::MacAddress:
    return "MacAddress";
  case PortIdSubtype::NetworkAddress:
    return "NetworkAddress";
  case PortIdSubtype::InterfaceName:
    return "InterfaceName";
  case PortIdSubtype::AgentCircuitId:
    return "AgentCircuitId";
  case PortIdSubtype::Local:
    return "Local";
  default:
    return "PortIdSubtype(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(PortIdSubtype value)
{
  auto v = utils::as_int32(value);
  return v >= 1 && v <= 7;
}

std::string to_string(ManAddrIfSubtype value)
{
  switch (value)
  {
  case ManAddrIfSubtype::None:
    return "None";
  case ManAddrIfSubtype::Unknown:
    return "Unknown";
  case ManAddrIfSubtype::PortRef:
    return "PortRef";
  case ManAddrIfSubtype::SystemPortNumber:
    return "SystemPortNumber";
  default:
    return "ManAddrIfSubtype(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(ManAddrIfSubtype value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 3;
}

std::string to_string(IdType value)
{
  switch (value)
  {
  case IdType::Numeric:
    return "Numeric";
  case IdType::String:
    return "String";
  case IdType::Guid:
    return "Guid";
  case IdType::Opaque:
    return "Opaque";
  default:
    return "IdType(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(IdType value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 3;
}

std::string to_string(NodeClass value)
{
  switch (value)
  {
  case NodeClass::Unspecified:
    return "Unspecified";
  case NodeClass::Object:
    return "Object";
  case NodeClass::Variable:
    return "Variable";
  case NodeClass::Method:
    return "Method";
  case NodeClass::ObjectType:
    return "ObjectType";
  case NodeClass::VariableType:
    return "VariableType";
  case NodeClass::ReferenceType:
    return "ReferenceType";
  case NodeClass::DataType:
    return "DataType";
  case NodeClass::View:
    return "View";
  default:
    return "NodeClass(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(NodeClass value)
{
  switch (value)
  {
  case NodeClass::Unspecified:
  case NodeClass::Object:
  case NodeClass::Variable:
  case NodeClass::Method:
  case NodeClass::ObjectType:
  case NodeClass::VariableType:
  case NodeClass::ReferenceType:
  case NodeClass::DataType:
  case NodeClass::View:
    return true;
  default:
    return false;
  }
}

std::string to_string(StructureType value)
{
  switch (value)
  {
  case StructureType::Structure:
    return "Structure";
  case StructureType::StructureWithOptionalFields:
    return "StructureWithOptionalFields";
  case StructureType::Union:
    return "Union";
  case StructureType::StructureWithSubtypedValues:
    return "StructureWithSubtypedValues";
  case StructureType::UnionWithSubtypedValues:
    return "UnionWithSubtypedValues";
  default:
    return "StructureType(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(StructureType value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 4;
}

std::string to_string(ApplicationType value)
{
  switch (value)
  {
  case ApplicationType::Server:
    return "Server";
  case ApplicationType::Client:
    return "Client";
  case ApplicationType::ClientAndServer:
    return "ClientAndServer";
  case ApplicationType::DiscoveryServer:
    return "DiscoveryServer";
  default:
    return "ApplicationType(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(ApplicationType value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 3;
}

std::string to_string(MessageSecurityMode value)
{
  switch (value)
  {
  case MessageSecurityMode::Invalid:
    return "Invalid";
  case MessageSecurityMode::None:
    return "None";
  case MessageSecurityMode::Sign:
    return "Sign";
  case MessageSecurityMode::SignAndEncrypt:
    return "SignAndEncrypt";
  default:
    return "MessageSecurityMode(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(MessageSecurityMode value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 3;
}

std::string to_string(UserTokenType value)
{
  switch (value)
  {
  case UserTokenType::Anonymous:
    return "Anonymous";
  case UserTokenType::UserName:
    return "UserName";
  case UserTokenType::Certificate:
    return "Certificate";
  case UserTokenType::IssuedToken:
    return "IssuedToken";
  default:
    return "UserTokenType(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(UserTokenType value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 3;
}

std::string to_string(SecurityTokenRequestType value)
{
  switch (value)
  {
  case SecurityTokenRequestType::Issue:
    return "Issue";
  case SecurityTokenRequestType::Renew:
    return "Renew";
  default:
    return "SecurityTokenRequestType(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(SecurityTokenRequestType value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 1;
}

std::string to_string(NodeAttributesMask value)
{
  switch (value)
  {
  case NodeAttributesMask::None:
    return "None";
  case NodeAttributesMask::AccessLevel:
    return "AccessLevel";
  case NodeAttributesMask::ArrayDimensions:
    return "ArrayDimensions";
  case NodeAttributesMask::BrowseName:
    return "BrowseName";
  case NodeAttributesMask::ContainsNoLoops:
    return "ContainsNoLoops";
  case NodeAttributesMask::DataType:
    return "DataType";
  case NodeAttributesMask::Description:
    return "Description";
  case NodeAttributesMask::DisplayName:
    return "DisplayName";
  case NodeAttributesMask::EventNotifier:
    return "EventNotifier";
  case NodeAttributesMask::Executable:
    return "Executable";
  case NodeAttributesMask::Historizing:
    return "Historizing";
  case NodeAttributesMask::InverseName:
    return "InverseName";
  case NodeAttributesMask::IsAbstract:
    return "IsAbstract";
  case NodeAttributesMask::MinimumSamplingInterval:
    return "MinimumSamplingInterval";
  case NodeAttributesMask::NodeClass:
    return "NodeClass";
  case NodeAttributesMask::NodeId:
    return "NodeId";
  case NodeAttributesMask::Symmetric:
    return "Symmetric";
  case NodeAttributesMask::UserAccessLevel:
    return "UserAccessLevel";
  case NodeAttributesMask::UserExecutable:
    return "UserExecutable";
  case NodeAttributesMask::UserWriteMask:
    return "UserWriteMask";
  case NodeAttributesMask::ValueRank:
    return "ValueRank";
  case NodeAttributesMask::WriteMask:
    return "WriteMask";
  case NodeAttributesMask::Value:
    return "Value";
  case NodeAttributesMask::DataTypeDefinition:
    return "DataTypeDefinition";
  case NodeAttributesMask::RolePermissions:
    return "RolePermissions";
  case NodeAttributesMask::AccessRestrictions:
    return "AccessRestrictions";
  case NodeAttributesMask::All:
    return "All";
  case NodeAttributesMask::BaseNode:
    return "BaseNode";
  case NodeAttributesMask::Object:
    return "Object";
  case NodeAttributesMask::ObjectType:
    return "ObjectType";
  case NodeAttributesMask::Variable:
    return "Variable";
  case NodeAttributesMask::VariableType:
    return "VariableType";
  case NodeAttributesMask::Method:
    return "Method";
  case NodeAttributesMask::ReferenceType:
    return "ReferenceType";
  case NodeAttributesMask::View:
    return "View";
  default:
    return "NodeAttributesMask(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(NodeAttributesMask value)
{
  switch (value)
  {
  case NodeAttributesMask::None:
  case NodeAttributesMask::AccessLevel:
  case NodeAttributesMask::ArrayDimensions:
  case NodeAttributesMask::BrowseName:
  case NodeAttributesMask::ContainsNoLoops:
  case NodeAttributesMask::DataType:
  case NodeAttributesMask::Description:
  case NodeAttributesMask::DisplayName:
  case NodeAttributesMask::EventNotifier:
  case NodeAttributesMask::Executable:
  case NodeAttributesMask::Historizing:
  case NodeAttributesMask::InverseName:
  case NodeAttributesMask::IsAbstract:
  case NodeAttributesMask::MinimumSamplingInterval:
  case NodeAttributesMask::NodeClass:
  case NodeAttributesMask::NodeId:
  case NodeAttributesMask::Symmetric:
  case NodeAttributesMask::UserAccessLevel:
  case NodeAttributesMask::UserExecutable:
  case NodeAttributesMask::UserWriteMask:
  case NodeAttributesMask::ValueRank:
  case NodeAttributesMask::WriteMask:
  case NodeAttributesMask::Value:
  case NodeAttributesMask::DataTypeDefinition:
  case NodeAttributesMask::RolePermissions:
  case NodeAttributesMask::AccessRestrictions:
  case NodeAttributesMask::All:
  case NodeAttributesMask::BaseNode:
  case NodeAttributesMask::Object:
  case NodeAttributesMask::ObjectType:
  case NodeAttributesMask::Variable:
  case NodeAttributesMask::VariableType:
  case NodeAttributesMask::Method:
  case NodeAttributesMask::ReferenceType:
  case NodeAttributesMask::View:
    return true;
  default:
    return false;
  }
}

std::string to_string(FilterOperator value)
{
  switch (value)
  {
  case FilterOperator::Equals:
    return "Equals";
  case FilterOperator::IsNull:
    return "IsNull";
  case FilterOperator::GreaterThan:
    return "GreaterThan";
  case FilterOperator::LessThan:
    return "LessThan";
  case FilterOperator::GreaterThanOrEqual:
    return "GreaterThanOrEqual";
  case FilterOperator::LessThanOrEqual:
    return "LessThanOrEqual";
  case FilterOperator::Like:
    return "Like";
  case FilterOperator::Not:
    return "Not";
  case FilterOperator::Between:
    return "Between";
  case FilterOperator::InList:
    return "InList";
  case FilterOperator::And:
    return "And";
  case FilterOperator::Or:
    return "Or";
  case FilterOperator::Cast:
    return "Cast";
  case FilterOperator::InView:
    return "InView";
  case FilterOperator::OfType:
    return "OfType";
  case FilterOperator::RelatedTo:
    return "RelatedTo";
  case FilterOperator::BitwiseAnd:
    return "BitwiseAnd";
  case FilterOperator::BitwiseOr:
    return "BitwiseOr";
  default:
    return "FilterOperator(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(FilterOperator value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 17;
}

std::string to_string(HistoryUpdateType value)
{
  switch (value)
  {
  case HistoryUpdateType::Insert:
    return "Insert";
  case HistoryUpdateType::Replace:
    return "Replace";
  case HistoryUpdateType::Update:
    return "Update";
  case HistoryUpdateType::Delete:
    return "Delete";
  default:
    return "HistoryUpdateType(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(HistoryUpdateType value)
{
  auto v = utils::as_int32(value);
  return v >= 1 && v <= 4;
}

std::string to_string(PerformUpdateType value)
{
  switch (value)
  {
  case PerformUpdateType::Insert:
    return "Insert";
  case PerformUpdateType::Replace:
    return "Replace";
  case PerformUpdateType::Update:
    return "Update";
  case PerformUpdateType::Remove:
    return "Remove";
  default:
    return "PerformUpdateType(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(PerformUpdateType value)
{
  auto v = utils::as_int32(value);
  return v >= 1 && v <= 4;
}

std::string to_string(RedundancySupport value)
{
  switch (value)
  {
  case RedundancySupport::None:
    return "None";
  case RedundancySupport::Cold:
    return "Cold";
  case RedundancySupport::Warm:
    return "Warm";
  case RedundancySupport::Hot:
    return "Hot";
  case RedundancySupport::Transparent:
    return "Transparent";
  case RedundancySupport::HotAndMirrored:
    return "HotAndMirrored";
  default:
    return "RedundancySupport(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(RedundancySupport value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 5;
}

std::string to_string(ServerState value)
{
  switch (value)
  {
  case ServerState::Running:
    return "Running";
  case ServerState::Failed:
    return "Failed";
  case ServerState::NoConfiguration:
    return "NoConfiguration";
  case ServerState::Suspended:
    return "Suspended";
  case ServerState::Shutdown:
    return "Shutdown";
  case ServerState::Test:
    return "Test";
  case ServerState::CommunicationFault:
    return "CommunicationFault";
  case ServerState::Unknown:
    return "Unknown";
  default:
    return "ServerState(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(ServerState value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 7;
}

std::string to_string(AxisScaleEnumeration value)
{
  switch (value)
  {
  case AxisScaleEnumeration::Linear:
    return "Linear";
  case AxisScaleEnumeration::Log:
    return "Log";
  case AxisScaleEnumeration::Ln:
    return "Ln";
  default:
    return "AxisScaleEnumeration(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(AxisScaleEnumeration value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 2;
}

std::string to_string(ExceptionDeviationFormat value)
{
  switch (value)
  {
  case ExceptionDeviationFormat::AbsoluteValue:
    return "AbsoluteValue";
  case ExceptionDeviationFormat::PercentOfValue:
    return "PercentOfValue";
  case ExceptionDeviationFormat::PercentOfRange:
    return "PercentOfRange";
  case ExceptionDeviationFormat::PercentOfEURange:
    return "PercentOfEURange";
  case ExceptionDeviationFormat::Unknown:
    return "Unknown";
  default:
    return "ExceptionDeviationFormat(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(ExceptionDeviationFormat value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 4;
}

std::string to_string(BrowseDirection value)
{
  switch (value)
  {
  case BrowseDirection::Forward:
    return "Forward";
  case BrowseDirection::Inverse:
    return "Inverse";
  case BrowseDirection::Both:
    return "Both";
  case BrowseDirection::Invalid:
    return "Invalid";
  default:
    return "BrowseDirection(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(BrowseDirection value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 3;
}

std::string to_string(BrowseResultMask value)
{
  switch (value)
  {
  case BrowseResultMask::None:
    return "None";
  case BrowseResultMask::ReferenceTypeId:
    return "ReferenceTypeId";
  case BrowseResultMask::IsForward:
    return "IsForward";
  case BrowseResultMask::NodeClass:
    return "NodeClass";
  case BrowseResultMask::BrowseName:
    return "BrowseName";
  case BrowseResultMask::DisplayName:
    return "DisplayName";
  case BrowseResultMask::TypeDefinition:
    return "TypeDefinition";
  case BrowseResultMask::All:
    return "All";
  case BrowseResultMask::ReferenceTypeInfo:
    return "ReferenceTypeInfo";
  case BrowseResultMask::TargetInfo:
    return "TargetInfo";
  default:
    return "BrowseResultMask(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(BrowseResultMask value)
{
  switch (value)
  {
  case BrowseResultMask::None:
  case BrowseResultMask::ReferenceTypeId:
  case BrowseResultMask::IsForward:
  case BrowseResultMask::NodeClass:
  case BrowseResultMask::BrowseName:
  case BrowseResultMask::DisplayName:
  case BrowseResultMask::TypeDefinition:
  case BrowseResultMask::All:
  case BrowseResultMask::ReferenceTypeInfo:
  case BrowseResultMask::TargetInfo:
    return true;
  default:
    return false;
  }
}

std::string to_string(TimestampsToReturn value)
{
  switch (value)
  {
  case TimestampsToReturn::Source:
    return "Source";
  case TimestampsToReturn::Server:
    return "Server";
  case TimestampsToReturn::Both:
    return "Both";
  case TimestampsToReturn::Neither:
    return "Neither";
  case TimestampsToReturn::Invalid:
    return "Invalid";
  default:
    return "TimestampsToReturn(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(TimestampsToReturn value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 4;
}

std::string to_string(SortOrderType value)
{
  switch (value)
  {
  case SortOrderType::Ascending:
    return "Ascending";
  case SortOrderType::Descending:
    return "Descending";
  default:
    return "SortOrderType(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(SortOrderType value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 1;
}

std::string to_string(MonitoringMode value)
{
  switch (value)
  {
  case MonitoringMode::Disabled:
    return "Disabled";
  case MonitoringMode::Sampling:
    return "Sampling";
  case MonitoringMode::Reporting:
    return "Reporting";
  default:
    return "MonitoringMode(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(MonitoringMode value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 2;
}

std::string to_string(DataChangeTrigger value)
{
  switch (value)
  {
  case DataChangeTrigger::Status:
    return "Status";
  case DataChangeTrigger::StatusValue:
    return "StatusValue";
  case DataChangeTrigger::StatusValueTimestamp:
    return "StatusValueTimestamp";
  default:
    return "DataChangeTrigger(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(DataChangeTrigger value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 2;
}

std::string to_string(DeadbandType value)
{
  switch (value)
  {
  case DeadbandType::None:
    return "None";
  case DeadbandType::Absolute:
    return "Absolute";
  case DeadbandType::Percent:
    return "Percent";
  default:
    return "DeadbandType(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(DeadbandType value)
{
  auto v = utils::as_int32(value);
  return v >= 0 && v <= 2;
}

std::string to_string(ModelChangeStructureVerbMask value)
{
  switch (value)
  {
  case ModelChangeStructureVerbMask::NodeAdded:
    return "NodeAdded";
  case ModelChangeStructureVerbMask::NodeDeleted:
    return "NodeDeleted";
  case ModelChangeStructureVerbMask::ReferenceAdded:
    return "ReferenceAdded";
  case ModelChangeStructureVerbMask::ReferenceDeleted:
    return "ReferenceDeleted";
  case ModelChangeStructureVerbMask::DataTypeChanged:
    return "DataTypeChanged";
  default:
    return "ModelChangeStructureVerbMask(" + std::to_string(utils::to_underlying(value)) + ")";
  }
}

bool is_valid(ModelChangeStructureVerbMask value)
{
  switch (value)
  {
  case ModelChangeStructureVerbMask::NodeAdded:
  case ModelChangeStructureVerbMask::NodeDeleted:
  case ModelChangeStructureVerbMask::ReferenceAdded:
  case ModelChangeStructureVerbMask::ReferenceDeleted:
  case ModelChangeStructureVerbMask::DataTypeChanged:
    return true;
  default:
    return false;
  }
}

}  // namespace ua
