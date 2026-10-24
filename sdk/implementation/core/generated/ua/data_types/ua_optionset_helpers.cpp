// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_alarm_mask.h"
#include "ua_trust_list_validation_options.h"
#include "ua_password_options_mask.h"
#include "ua_user_configuration_mask.h"
#include "ua_lldp_system_capabilities_map.h"
#include "ua_log_record_mask.h"
#include "ua_permission_type.h"
#include "ua_access_level_type.h"
#include "ua_access_level_ex_type.h"
#include "ua_event_notifier_type.h"
#include "ua_access_restriction_type.h"
#include "ua_attribute_write_mask.h"

#include <string>
#include <string_view>
#include <vector>

namespace ua
{

std::string to_string(const AlarmMask& value)
{
  std::vector<std::string_view> parts;
  if (value.test(AlarmMask::Bit::Active))
  {
    parts.push_back("Active");
  }
  if (value.test(AlarmMask::Bit::Unacknowledged))
  {
    parts.push_back("Unacknowledged");
  }
  if (value.test(AlarmMask::Bit::Unconfirmed))
  {
    parts.push_back("Unconfirmed");
  }
  std::string result = "AlarmMask{";
  for (std::size_t i = 0; i < parts.size(); ++i)
  {
    if (i != 0)
    {
      result += ", ";
    }
    result += parts[i];
  }
  result += "}";
  return result;
}

std::string to_string(const TrustListValidationOptions& value)
{
  std::vector<std::string_view> parts;
  if (value.test(TrustListValidationOptions::Bit::SuppressCertificateExpired))
  {
    parts.push_back("SuppressCertificateExpired");
  }
  if (value.test(TrustListValidationOptions::Bit::SuppressHostNameInvalid))
  {
    parts.push_back("SuppressHostNameInvalid");
  }
  if (value.test(TrustListValidationOptions::Bit::SuppressRevocationStatusUnknown))
  {
    parts.push_back("SuppressRevocationStatusUnknown");
  }
  if (value.test(TrustListValidationOptions::Bit::SuppressIssuerCertificateExpired))
  {
    parts.push_back("SuppressIssuerCertificateExpired");
  }
  if (value.test(TrustListValidationOptions::Bit::SuppressIssuerRevocationStatusUnknown))
  {
    parts.push_back("SuppressIssuerRevocationStatusUnknown");
  }
  if (value.test(TrustListValidationOptions::Bit::CheckRevocationStatusOnline))
  {
    parts.push_back("CheckRevocationStatusOnline");
  }
  if (value.test(TrustListValidationOptions::Bit::CheckRevocationStatusOffline))
  {
    parts.push_back("CheckRevocationStatusOffline");
  }
  std::string result = "TrustListValidationOptions{";
  for (std::size_t i = 0; i < parts.size(); ++i)
  {
    if (i != 0)
    {
      result += ", ";
    }
    result += parts[i];
  }
  result += "}";
  return result;
}

std::string to_string(const PasswordOptionsMask& value)
{
  std::vector<std::string_view> parts;
  if (value.test(PasswordOptionsMask::Bit::SupportInitialPasswordChange))
  {
    parts.push_back("SupportInitialPasswordChange");
  }
  if (value.test(PasswordOptionsMask::Bit::SupportDisableUser))
  {
    parts.push_back("SupportDisableUser");
  }
  if (value.test(PasswordOptionsMask::Bit::SupportDisableDeleteForUser))
  {
    parts.push_back("SupportDisableDeleteForUser");
  }
  if (value.test(PasswordOptionsMask::Bit::SupportNoChangeForUser))
  {
    parts.push_back("SupportNoChangeForUser");
  }
  if (value.test(PasswordOptionsMask::Bit::SupportDescriptionForUser))
  {
    parts.push_back("SupportDescriptionForUser");
  }
  if (value.test(PasswordOptionsMask::Bit::RequiresUpperCaseCharacters))
  {
    parts.push_back("RequiresUpperCaseCharacters");
  }
  if (value.test(PasswordOptionsMask::Bit::RequiresLowerCaseCharacters))
  {
    parts.push_back("RequiresLowerCaseCharacters");
  }
  if (value.test(PasswordOptionsMask::Bit::RequiresDigitCharacters))
  {
    parts.push_back("RequiresDigitCharacters");
  }
  if (value.test(PasswordOptionsMask::Bit::RequiresSpecialCharacters))
  {
    parts.push_back("RequiresSpecialCharacters");
  }
  std::string result = "PasswordOptionsMask{";
  for (std::size_t i = 0; i < parts.size(); ++i)
  {
    if (i != 0)
    {
      result += ", ";
    }
    result += parts[i];
  }
  result += "}";
  return result;
}

std::string to_string(const UserConfigurationMask& value)
{
  std::vector<std::string_view> parts;
  if (value.test(UserConfigurationMask::Bit::NoDelete))
  {
    parts.push_back("NoDelete");
  }
  if (value.test(UserConfigurationMask::Bit::Disabled))
  {
    parts.push_back("Disabled");
  }
  if (value.test(UserConfigurationMask::Bit::NoChangeByUser))
  {
    parts.push_back("NoChangeByUser");
  }
  if (value.test(UserConfigurationMask::Bit::MustChangePassword))
  {
    parts.push_back("MustChangePassword");
  }
  std::string result = "UserConfigurationMask{";
  for (std::size_t i = 0; i < parts.size(); ++i)
  {
    if (i != 0)
    {
      result += ", ";
    }
    result += parts[i];
  }
  result += "}";
  return result;
}

std::string to_string(const LldpSystemCapabilitiesMap& value)
{
  std::vector<std::string_view> parts;
  if (value.test(LldpSystemCapabilitiesMap::Bit::Other))
  {
    parts.push_back("Other");
  }
  if (value.test(LldpSystemCapabilitiesMap::Bit::Repeater))
  {
    parts.push_back("Repeater");
  }
  if (value.test(LldpSystemCapabilitiesMap::Bit::Bridge))
  {
    parts.push_back("Bridge");
  }
  if (value.test(LldpSystemCapabilitiesMap::Bit::WlanAccessPoint))
  {
    parts.push_back("WlanAccessPoint");
  }
  if (value.test(LldpSystemCapabilitiesMap::Bit::Router))
  {
    parts.push_back("Router");
  }
  if (value.test(LldpSystemCapabilitiesMap::Bit::Telephone))
  {
    parts.push_back("Telephone");
  }
  if (value.test(LldpSystemCapabilitiesMap::Bit::DocsisCableDevice))
  {
    parts.push_back("DocsisCableDevice");
  }
  if (value.test(LldpSystemCapabilitiesMap::Bit::StationOnly))
  {
    parts.push_back("StationOnly");
  }
  if (value.test(LldpSystemCapabilitiesMap::Bit::CvlanComponent))
  {
    parts.push_back("CvlanComponent");
  }
  if (value.test(LldpSystemCapabilitiesMap::Bit::SvlanComponent))
  {
    parts.push_back("SvlanComponent");
  }
  if (value.test(LldpSystemCapabilitiesMap::Bit::TwoPortMacRelay))
  {
    parts.push_back("TwoPortMacRelay");
  }
  std::string result = "LldpSystemCapabilitiesMap{";
  for (std::size_t i = 0; i < parts.size(); ++i)
  {
    if (i != 0)
    {
      result += ", ";
    }
    result += parts[i];
  }
  result += "}";
  return result;
}

std::string to_string(const LogRecordMask& value)
{
  std::vector<std::string_view> parts;
  if (value.test(LogRecordMask::Bit::EventType))
  {
    parts.push_back("EventType");
  }
  if (value.test(LogRecordMask::Bit::SourceNode))
  {
    parts.push_back("SourceNode");
  }
  if (value.test(LogRecordMask::Bit::SourceName))
  {
    parts.push_back("SourceName");
  }
  if (value.test(LogRecordMask::Bit::TraceContext))
  {
    parts.push_back("TraceContext");
  }
  if (value.test(LogRecordMask::Bit::AdditionalData))
  {
    parts.push_back("AdditionalData");
  }
  std::string result = "LogRecordMask{";
  for (std::size_t i = 0; i < parts.size(); ++i)
  {
    if (i != 0)
    {
      result += ", ";
    }
    result += parts[i];
  }
  result += "}";
  return result;
}

std::string to_string(const PermissionType& value)
{
  std::vector<std::string_view> parts;
  if (value.test(PermissionType::Bit::Browse))
  {
    parts.push_back("Browse");
  }
  if (value.test(PermissionType::Bit::ReadRolePermissions))
  {
    parts.push_back("ReadRolePermissions");
  }
  if (value.test(PermissionType::Bit::WriteAttribute))
  {
    parts.push_back("WriteAttribute");
  }
  if (value.test(PermissionType::Bit::WriteRolePermissions))
  {
    parts.push_back("WriteRolePermissions");
  }
  if (value.test(PermissionType::Bit::WriteHistorizing))
  {
    parts.push_back("WriteHistorizing");
  }
  if (value.test(PermissionType::Bit::Read))
  {
    parts.push_back("Read");
  }
  if (value.test(PermissionType::Bit::Write))
  {
    parts.push_back("Write");
  }
  if (value.test(PermissionType::Bit::ReadHistory))
  {
    parts.push_back("ReadHistory");
  }
  if (value.test(PermissionType::Bit::InsertHistory))
  {
    parts.push_back("InsertHistory");
  }
  if (value.test(PermissionType::Bit::ModifyHistory))
  {
    parts.push_back("ModifyHistory");
  }
  if (value.test(PermissionType::Bit::DeleteHistory))
  {
    parts.push_back("DeleteHistory");
  }
  if (value.test(PermissionType::Bit::ReceiveEvents))
  {
    parts.push_back("ReceiveEvents");
  }
  if (value.test(PermissionType::Bit::Call))
  {
    parts.push_back("Call");
  }
  if (value.test(PermissionType::Bit::AddReference))
  {
    parts.push_back("AddReference");
  }
  if (value.test(PermissionType::Bit::RemoveReference))
  {
    parts.push_back("RemoveReference");
  }
  if (value.test(PermissionType::Bit::DeleteNode))
  {
    parts.push_back("DeleteNode");
  }
  if (value.test(PermissionType::Bit::AddNode))
  {
    parts.push_back("AddNode");
  }
  std::string result = "PermissionType{";
  for (std::size_t i = 0; i < parts.size(); ++i)
  {
    if (i != 0)
    {
      result += ", ";
    }
    result += parts[i];
  }
  result += "}";
  return result;
}

std::string to_string(const AccessLevelType& value)
{
  std::vector<std::string_view> parts;
  if (value.test(AccessLevelType::Bit::CurrentRead))
  {
    parts.push_back("CurrentRead");
  }
  if (value.test(AccessLevelType::Bit::CurrentWrite))
  {
    parts.push_back("CurrentWrite");
  }
  if (value.test(AccessLevelType::Bit::HistoryRead))
  {
    parts.push_back("HistoryRead");
  }
  if (value.test(AccessLevelType::Bit::HistoryWrite))
  {
    parts.push_back("HistoryWrite");
  }
  if (value.test(AccessLevelType::Bit::SemanticChange))
  {
    parts.push_back("SemanticChange");
  }
  if (value.test(AccessLevelType::Bit::StatusWrite))
  {
    parts.push_back("StatusWrite");
  }
  if (value.test(AccessLevelType::Bit::TimestampWrite))
  {
    parts.push_back("TimestampWrite");
  }
  std::string result = "AccessLevelType{";
  for (std::size_t i = 0; i < parts.size(); ++i)
  {
    if (i != 0)
    {
      result += ", ";
    }
    result += parts[i];
  }
  result += "}";
  return result;
}

std::string to_string(const AccessLevelExType& value)
{
  std::vector<std::string_view> parts;
  if (value.test(AccessLevelExType::Bit::CurrentRead))
  {
    parts.push_back("CurrentRead");
  }
  if (value.test(AccessLevelExType::Bit::CurrentWrite))
  {
    parts.push_back("CurrentWrite");
  }
  if (value.test(AccessLevelExType::Bit::HistoryRead))
  {
    parts.push_back("HistoryRead");
  }
  if (value.test(AccessLevelExType::Bit::HistoryWrite))
  {
    parts.push_back("HistoryWrite");
  }
  if (value.test(AccessLevelExType::Bit::SemanticChange))
  {
    parts.push_back("SemanticChange");
  }
  if (value.test(AccessLevelExType::Bit::StatusWrite))
  {
    parts.push_back("StatusWrite");
  }
  if (value.test(AccessLevelExType::Bit::TimestampWrite))
  {
    parts.push_back("TimestampWrite");
  }
  if (value.test(AccessLevelExType::Bit::NonatomicRead))
  {
    parts.push_back("NonatomicRead");
  }
  if (value.test(AccessLevelExType::Bit::NonatomicWrite))
  {
    parts.push_back("NonatomicWrite");
  }
  if (value.test(AccessLevelExType::Bit::WriteFullArrayOnly))
  {
    parts.push_back("WriteFullArrayOnly");
  }
  if (value.test(AccessLevelExType::Bit::NoSubDataTypes))
  {
    parts.push_back("NoSubDataTypes");
  }
  if (value.test(AccessLevelExType::Bit::NonVolatile))
  {
    parts.push_back("NonVolatile");
  }
  if (value.test(AccessLevelExType::Bit::Constant))
  {
    parts.push_back("Constant");
  }
  std::string result = "AccessLevelExType{";
  for (std::size_t i = 0; i < parts.size(); ++i)
  {
    if (i != 0)
    {
      result += ", ";
    }
    result += parts[i];
  }
  result += "}";
  return result;
}

std::string to_string(const EventNotifierType& value)
{
  std::vector<std::string_view> parts;
  if (value.test(EventNotifierType::Bit::SubscribeToEvents))
  {
    parts.push_back("SubscribeToEvents");
  }
  if (value.test(EventNotifierType::Bit::HistoryRead))
  {
    parts.push_back("HistoryRead");
  }
  if (value.test(EventNotifierType::Bit::HistoryWrite))
  {
    parts.push_back("HistoryWrite");
  }
  std::string result = "EventNotifierType{";
  for (std::size_t i = 0; i < parts.size(); ++i)
  {
    if (i != 0)
    {
      result += ", ";
    }
    result += parts[i];
  }
  result += "}";
  return result;
}

std::string to_string(const AccessRestrictionType& value)
{
  std::vector<std::string_view> parts;
  if (value.test(AccessRestrictionType::Bit::SigningRequired))
  {
    parts.push_back("SigningRequired");
  }
  if (value.test(AccessRestrictionType::Bit::EncryptionRequired))
  {
    parts.push_back("EncryptionRequired");
  }
  if (value.test(AccessRestrictionType::Bit::SessionRequired))
  {
    parts.push_back("SessionRequired");
  }
  if (value.test(AccessRestrictionType::Bit::ApplyRestrictionsToBrowse))
  {
    parts.push_back("ApplyRestrictionsToBrowse");
  }
  std::string result = "AccessRestrictionType{";
  for (std::size_t i = 0; i < parts.size(); ++i)
  {
    if (i != 0)
    {
      result += ", ";
    }
    result += parts[i];
  }
  result += "}";
  return result;
}

std::string to_string(const AttributeWriteMask& value)
{
  std::vector<std::string_view> parts;
  if (value.test(AttributeWriteMask::Bit::AccessLevel))
  {
    parts.push_back("AccessLevel");
  }
  if (value.test(AttributeWriteMask::Bit::ArrayDimensions))
  {
    parts.push_back("ArrayDimensions");
  }
  if (value.test(AttributeWriteMask::Bit::BrowseName))
  {
    parts.push_back("BrowseName");
  }
  if (value.test(AttributeWriteMask::Bit::ContainsNoLoops))
  {
    parts.push_back("ContainsNoLoops");
  }
  if (value.test(AttributeWriteMask::Bit::DataType))
  {
    parts.push_back("DataType");
  }
  if (value.test(AttributeWriteMask::Bit::Description))
  {
    parts.push_back("Description");
  }
  if (value.test(AttributeWriteMask::Bit::DisplayName))
  {
    parts.push_back("DisplayName");
  }
  if (value.test(AttributeWriteMask::Bit::EventNotifier))
  {
    parts.push_back("EventNotifier");
  }
  if (value.test(AttributeWriteMask::Bit::Executable))
  {
    parts.push_back("Executable");
  }
  if (value.test(AttributeWriteMask::Bit::Historizing))
  {
    parts.push_back("Historizing");
  }
  if (value.test(AttributeWriteMask::Bit::InverseName))
  {
    parts.push_back("InverseName");
  }
  if (value.test(AttributeWriteMask::Bit::IsAbstract))
  {
    parts.push_back("IsAbstract");
  }
  if (value.test(AttributeWriteMask::Bit::MinimumSamplingInterval))
  {
    parts.push_back("MinimumSamplingInterval");
  }
  if (value.test(AttributeWriteMask::Bit::NodeClass))
  {
    parts.push_back("NodeClass");
  }
  if (value.test(AttributeWriteMask::Bit::NodeId))
  {
    parts.push_back("NodeId");
  }
  if (value.test(AttributeWriteMask::Bit::Symmetric))
  {
    parts.push_back("Symmetric");
  }
  if (value.test(AttributeWriteMask::Bit::UserAccessLevel))
  {
    parts.push_back("UserAccessLevel");
  }
  if (value.test(AttributeWriteMask::Bit::UserExecutable))
  {
    parts.push_back("UserExecutable");
  }
  if (value.test(AttributeWriteMask::Bit::UserWriteMask))
  {
    parts.push_back("UserWriteMask");
  }
  if (value.test(AttributeWriteMask::Bit::ValueRank))
  {
    parts.push_back("ValueRank");
  }
  if (value.test(AttributeWriteMask::Bit::WriteMask))
  {
    parts.push_back("WriteMask");
  }
  if (value.test(AttributeWriteMask::Bit::ValueForVariableType))
  {
    parts.push_back("ValueForVariableType");
  }
  if (value.test(AttributeWriteMask::Bit::DataTypeDefinition))
  {
    parts.push_back("DataTypeDefinition");
  }
  if (value.test(AttributeWriteMask::Bit::RolePermissions))
  {
    parts.push_back("RolePermissions");
  }
  if (value.test(AttributeWriteMask::Bit::AccessRestrictions))
  {
    parts.push_back("AccessRestrictions");
  }
  if (value.test(AttributeWriteMask::Bit::AccessLevelEx))
  {
    parts.push_back("AccessLevelEx");
  }
  std::string result = "AttributeWriteMask{";
  for (std::size_t i = 0; i < parts.size(); ++i)
  {
    if (i != 0)
    {
      result += ", ";
    }
    result += parts[i];
  }
  result += "}";
  return result;
}

}  // namespace ua
