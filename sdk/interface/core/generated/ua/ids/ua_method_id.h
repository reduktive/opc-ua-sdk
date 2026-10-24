// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_METHOD_IDENTIFIERS_H
#define UA_METHOD_IDENTIFIERS_H

#include "ua_includes.h"

namespace ua
{

/// Well-known OPC UA MethodId identifiers (namespace 0).
/// @ingroup ua_node_ids
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#endif
enum class MethodId : uint32_t
{
  ProgramStateMachineType_Start = 2426U,
  ProgramStateMachineType_Suspend = 2427U,
  ProgramStateMachineType_Resume = 2428U,
  ProgramStateMachineType_Halt = 2429U,
  ProgramStateMachineType_Reset = 2430U,
  ShelvedStateMachineType_Unshelve = 2947U,
  ShelvedStateMachineType_OneShotShelve = 2948U,
  ShelvedStateMachineType_TimedShelve = 2949U,
  AddCommentMethodType = 3863U,
  ConditionType_ConditionRefresh = 3875U,
  TimedShelveMethodType = 6102U,
  ConditionRefreshMethodType = 9007U,
  ConditionType_Enable = 9027U,
  ConditionType_Disable = 9028U,
  ConditionType_AddComment = 9029U,
  DialogResponseMethodType = 9031U,
  DialogConditionType_Respond = 9069U,
  AcknowledgeableConditionType_Acknowledge = 9111U,
  AcknowledgeableConditionType_Confirm = 9113U,
  AlarmConditionType_ShelvingState_Unshelve = 9211U,
  AlarmConditionType_ShelvingState_OneShotShelve = 9212U,
  AlarmConditionType_ShelvingState_TimedShelve = 9213U,
  ServerType_GetMonitoredItems = 11489U,
  Server_GetMonitoredItems = 11492U,
  GetMonitoredItemsMethodType = 11495U,
  FileType_Open = 11580U,
  FileType_Close = 11583U,
  FileType_Read = 11585U,
  FileType_Write = 11588U,
  FileType_GetPosition = 11590U,
  FileType_SetPosition = 11593U,
  AddressSpaceFileType_ExportNamespace = 11615U,
  NamespaceMetadataType_NamespaceFile_Open = 11629U,
  NamespaceMetadataType_NamespaceFile_Close = 11632U,
  NamespaceMetadataType_NamespaceFile_Read = 11634U,
  NamespaceMetadataType_NamespaceFile_Write = 11637U,
  NamespaceMetadataType_NamespaceFile_GetPosition = 11639U,
  NamespaceMetadataType_NamespaceFile_SetPosition = 11642U,
  NamespaceMetadataType_NamespaceFile_ExportNamespace = 11644U,
  NamespacesType_NamespaceIdentifier_Placeholder_NamespaceFile_Open = 11659U,
  NamespacesType_NamespaceIdentifier_Placeholder_NamespaceFile_Close = 11662U,
  NamespacesType_NamespaceIdentifier_Placeholder_NamespaceFile_Read = 11664U,
  NamespacesType_NamespaceIdentifier_Placeholder_NamespaceFile_Write = 11667U,
  NamespacesType_NamespaceIdentifier_Placeholder_NamespaceFile_GetPosition = 11669U,
  NamespacesType_NamespaceIdentifier_Placeholder_NamespaceFile_SetPosition = 11672U,
  NamespacesType_NamespaceIdentifier_Placeholder_NamespaceFile_ExportNamespace = 11674U,
  OpenMethodType = 11738U,
  CloseMethodType = 11741U,
  ReadMethodType = 11743U,
  WriteMethodType = 11746U,
  GetPositionMethodType = 11748U,
  SetPositionMethodType = 11751U,
  OpenWithMasksMethodType = 12513U,
  CloseAndUpdateMethodType = 12516U,
  AddCertificateMethodType = 12518U,
  RemoveCertificateMethodType = 12520U,
  TrustListType_OpenWithMasks = 12543U,
  TrustListType_CloseAndUpdate = 12546U,
  TrustListType_AddCertificate = 12548U,
  TrustListType_RemoveCertificate = 12550U,
  UpdateCertificateMethodType = 12578U,
  ServerConfigurationType_UpdateCertificate = 12616U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Open = 12647U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Close = 12650U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Read = 12652U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_Write = 12655U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_GetPosition = 12657U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_SetPosition = 12660U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_OpenWithMasks = 12663U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_CloseAndUpdate = 12666U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate = 12668U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustList_RemoveCertificate = 12670U,
  ServerConfigurationType_CreateSigningRequest = 12731U,
  ServerConfigurationType_ApplyChanges = 12734U,
  ServerConfiguration_CreateSigningRequest = 12737U,
  ServerConfiguration_ApplyChanges = 12740U,
  CreateSigningRequestMethodType = 12741U,
  ServerType_SetSubscriptionDurable = 12746U,
  Server_SetSubscriptionDurable = 12749U,
  SetSubscriptionDurableMethodType = 12752U,
  GetRejectedListMethodType = 12773U,
  ServerConfigurationType_GetRejectedList = 12775U,
  ServerConfiguration_GetRejectedList = 12777U,
  ServerType_ResendData = 12871U,
  Server_ResendData = 12873U,
  ResendDataMethodType = 12875U,
  ServerType_RequestServerStateChange = 12883U,
  Server_RequestServerStateChange = 12886U,
  RequestServerStateChangeMethodType = 12888U,
  ConditionType_ConditionRefresh2 = 12912U,
  ConditionRefresh2MethodType = 12914U,
  CreateDirectoryMethodType = 13342U,
  CreateFileMethodType = 13345U,
  DeleteFileMethodType = 13348U,
  MoveOrCopyMethodType = 13350U,
  FileDirectoryType_FileDirectoryName_Placeholder_CreateDirectory = 13355U,
  FileDirectoryType_FileDirectoryName_Placeholder_CreateFile = 13358U,
  FileDirectoryType_FileDirectoryName_Placeholder_MoveOrCopy = 13363U,
  FileDirectoryType_FileName_Placeholder_Open = 13372U,
  FileDirectoryType_FileName_Placeholder_Close = 13375U,
  FileDirectoryType_FileName_Placeholder_Read = 13377U,
  FileDirectoryType_FileName_Placeholder_Write = 13380U,
  FileDirectoryType_FileName_Placeholder_GetPosition = 13382U,
  FileDirectoryType_FileName_Placeholder_SetPosition = 13385U,
  FileDirectoryType_CreateDirectory = 13387U,
  FileDirectoryType_CreateFile = 13390U,
  FileDirectoryType_DeleteFileSystemObject = 13393U,
  FileDirectoryType_MoveOrCopy = 13395U,
  CertificateGroupType_TrustList_Open = 13605U,
  CertificateGroupType_TrustList_Close = 13608U,
  CertificateGroupType_TrustList_Read = 13610U,
  CertificateGroupType_TrustList_Write = 13613U,
  CertificateGroupType_TrustList_GetPosition = 13615U,
  CertificateGroupType_TrustList_SetPosition = 13618U,
  CertificateGroupType_TrustList_OpenWithMasks = 13621U,
  CertificateGroupType_TrustList_CloseAndUpdate = 13624U,
  CertificateGroupType_TrustList_AddCertificate = 13627U,
  CertificateGroupType_TrustList_RemoveCertificate = 13629U,
  ServerConfiguration_UpdateCertificate = 13737U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustList_Open = 13821U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustList_Close = 13824U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustList_Read = 13826U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustList_Write = 13829U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustList_GetPosition = 13831U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustList_SetPosition = 13834U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustList_OpenWithMasks = 13837U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustList_CloseAndUpdate = 13840U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustList_AddCertificate = 13843U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustList_RemoveCertificate = 13845U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustList_Open = 13855U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustList_Close = 13858U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustList_Read = 13860U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustList_Write = 13863U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustList_GetPosition = 13865U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustList_SetPosition = 13868U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustList_OpenWithMasks = 13871U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustList_CloseAndUpdate = 13874U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustList_AddCertificate = 13877U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustList_RemoveCertificate = 13879U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustList_Open = 13889U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustList_Close = 13892U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustList_Read = 13894U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustList_Write = 13897U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustList_GetPosition = 13899U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustList_SetPosition = 13902U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustList_OpenWithMasks = 13905U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustList_CloseAndUpdate = 13908U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustList_AddCertificate = 13911U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustList_RemoveCertificate = 13913U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustList_Open = 13923U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustList_Close = 13926U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustList_Read = 13928U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustList_Write = 13931U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustList_GetPosition = 13933U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustList_SetPosition = 13936U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustList_OpenWithMasks = 13939U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustList_CloseAndUpdate = 13942U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustList_AddCertificate = 13945U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustList_RemoveCertificate = 13947U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustList_Open = 13958U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustList_Close = 13961U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustList_Read = 13963U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustList_Write = 13966U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustList_GetPosition = 13968U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustList_SetPosition = 13971U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustList_OpenWithMasks = 13974U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustList_CloseAndUpdate = 13977U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate = 13980U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustList_RemoveCertificate = 13982U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustList_Open = 13992U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustList_Close = 13995U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustList_Read = 13997U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustList_Write = 14000U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustList_GetPosition = 14002U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustList_SetPosition = 14005U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustList_OpenWithMasks = 14008U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustList_CloseAndUpdate = 14011U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustList_AddCertificate = 14014U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustList_RemoveCertificate = 14016U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustList_Open = 14026U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustList_Close = 14029U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustList_Read = 14031U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustList_Write = 14034U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustList_GetPosition = 14036U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustList_SetPosition = 14039U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustList_OpenWithMasks = 14042U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustList_CloseAndUpdate = 14045U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustList_AddCertificate = 14048U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustList_RemoveCertificate = 14050U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustList_Open = 14095U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustList_Close = 14098U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustList_Read = 14100U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustList_Write = 14103U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustList_GetPosition = 14105U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustList_SetPosition = 14108U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustList_OpenWithMasks = 14111U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustList_CloseAndUpdate = 14114U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustList_AddCertificate = 14117U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustList_RemoveCertificate = 14119U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_Open = 14129U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_Close = 14132U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_Read = 14134U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_Write = 14137U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_GetPosition = 14139U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_SetPosition = 14142U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_OpenWithMasks = 14145U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_CloseAndUpdate = 14148U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_AddCertificate = 14151U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustList_RemoveCertificate = 14153U,
  RemoveConnectionMethodType = 14183U,
  PubSubConnectionType_RemoveGroup = 14225U,
  PublishSubscribeType_ConnectionName_Placeholder_Status_Enable = 14421U,
  PublishSubscribeType_ConnectionName_Placeholder_Status_Disable = 14422U,
  PublishSubscribeType_ConnectionName_Placeholder_RemoveGroup = 14424U,
  PublishSubscribeType_RemoveConnection = 14432U,
  PublishSubscribeType_PublishedDataSets_AddPublishedDataItems = 14435U,
  PublishSubscribeType_PublishedDataSets_AddPublishedEvents = 14438U,
  PublishSubscribeType_PublishedDataSets_RemovePublishedDataSet = 14441U,
  DataSetFolderType_DataSetFolderName_Placeholder_AddPublishedDataItems = 14479U,
  DataSetFolderType_DataSetFolderName_Placeholder_AddPublishedEvents = 14482U,
  DataSetFolderType_DataSetFolderName_Placeholder_RemovePublishedDataSet = 14485U,
  DataSetFolderType_AddPublishedDataItems = 14493U,
  DataSetFolderType_AddPublishedEvents = 14496U,
  DataSetFolderType_RemovePublishedDataSet = 14499U,
  AddPublishedDataItemsMethodType = 14501U,
  AddPublishedEventsMethodType = 14504U,
  RemovePublishedDataSetMethodType = 14507U,
  PublishedDataItemsType_AddVariables = 14555U,
  PublishedDataItemsType_RemoveVariables = 14558U,
  PublishedDataItemsAddVariablesMethodType = 14564U,
  PublishedDataItemsRemoveVariablesMethodType = 14567U,
  PubSubConnectionType_Status_Enable = 14602U,
  PubSubConnectionType_Status_Disable = 14603U,
  PubSubConnectionTypeRemoveGroupMethodType = 14604U,
  PubSubGroupTypeRemoveWriterMethodType = 14623U,
  PubSubGroupTypeRemoveReaderMethodType = 14625U,
  PubSubStatusType_Enable = 14645U,
  PubSubStatusType_Disable = 14646U,
  PublishedEventsType_ModifyFieldSelection = 15052U,
  PublishedEventsTypeModifyFieldSelectionMethodType = 15054U,
  TargetVariablesType_AddTargetVariables = 15115U,
  TargetVariablesType_RemoveTargetVariables = 15118U,
  TargetVariablesTypeAddTargetVariablesMethodType = 15121U,
  TargetVariablesTypeRemoveTargetVariablesMethodType = 15124U,
  PublishSubscribe_GetSecurityKeys = 15215U,
  GetSecurityKeysMethodType = 15218U,
  PublishedDataSetType_DataSetWriterName_Placeholder_Status_Enable = 15225U,
  PublishedDataSetType_DataSetWriterName_Placeholder_Status_Disable = 15226U,
  CreateCredentialMethodType = 15248U,
  PubSubGroupType_Status_Enable = 15267U,
  PubSubGroupType_Status_Disable = 15268U,
  DataSetWriterType_Status_Enable = 15301U,
  DataSetWriterType_Status_Disable = 15302U,
  DataSetReaderType_Status_Enable = 15309U,
  DataSetReaderType_Status_Disable = 15310U,
  PublishSubscribe_GetSecurityGroup = 15440U,
  PublishSubscribe_SecurityGroups_AddSecurityGroup = 15444U,
  PublishSubscribe_SecurityGroups_RemoveSecurityGroup = 15447U,
  GetSecurityGroupMethodType = 15449U,
  SecurityGroupFolderType_SecurityGroupFolderName_Placeholder_AddSecurityGroup = 15454U,
  SecurityGroupFolderType_SecurityGroupFolderName_Placeholder_RemoveSecurityGroup = 15457U,
  SecurityGroupFolderType_AddSecurityGroup = 15461U,
  SecurityGroupFolderType_RemoveSecurityGroup = 15464U,
  AddSecurityGroupMethodType = 15466U,
  RemoveSecurityGroupMethodType = 15469U,
  DataSetFolderType_PublishedDataSetName_Placeholder_ExtensionFields_AddExtensionField = 15474U,
  DataSetFolderType_PublishedDataSetName_Placeholder_ExtensionFields_RemoveExtensionField = 15477U,
  PublishedDataSetType_ExtensionFields_AddExtensionField = 15482U,
  PublishedDataSetType_ExtensionFields_RemoveExtensionField = 15485U,
  ExtensionFieldsType_AddExtensionField = 15491U,
  ExtensionFieldsType_RemoveExtensionField = 15494U,
  AddExtensionFieldMethodType = 15496U,
  RemoveExtensionFieldMethodType = 15499U,
  ConfigurationFileType_CloseAndUpdate = 15505U,
  ConfigurationFileType_ConfirmUpdate = 15508U,
  ConfigurationFileCloseAndUpdateMethodType = 15513U,
  ConfigurationFileConfirmUpdateMethodType = 15516U,
  ServerConfigurationType_ConfigurationFile_Open = 15572U,
  ServerConfigurationType_ConfigurationFile_Close = 15575U,
  RoleSetType_RoleName_Placeholder_AddIdentity = 15612U,
  RoleSetType_RoleName_Placeholder_RemoveIdentity = 15614U,
  RoleType_AddIdentity = 15624U,
  RoleType_RemoveIdentity = 15626U,
  AddIdentityMethodType = 15636U,
  RemoveIdentityMethodType = 15638U,
  WellKnownRole_Anonymous_AddIdentity = 15648U,
  WellKnownRole_Anonymous_RemoveIdentity = 15650U,
  WellKnownRole_AuthenticatedUser_AddIdentity = 15660U,
  WellKnownRole_AuthenticatedUser_RemoveIdentity = 15662U,
  WellKnownRole_Observer_AddIdentity = 15672U,
  WellKnownRole_Observer_RemoveIdentity = 15674U,
  WellKnownRole_Operator_AddIdentity = 15684U,
  WellKnownRole_Operator_RemoveIdentity = 15686U,
  WellKnownRole_Supervisor_AddIdentity = 15696U,
  WellKnownRole_Supervisor_RemoveIdentity = 15698U,
  WellKnownRole_SecurityAdmin_AddIdentity = 15708U,
  WellKnownRole_SecurityAdmin_RemoveIdentity = 15710U,
  WellKnownRole_ConfigureAdmin_AddIdentity = 15720U,
  WellKnownRole_ConfigureAdmin_RemoveIdentity = 15722U,
  TemporaryFileTransferType_GenerateFileForRead = 15746U,
  TemporaryFileTransferType_GenerateFileForWrite = 15749U,
  TemporaryFileTransferType_CloseAndCommit = 15751U,
  ServerConfigurationType_ConfigurationFile_Read = 15791U,
  TemporaryFileTransferType_TransferState_Placeholder_Reset = 15794U,
  GenerateFileForReadMethodType = 15795U,
  GenerateFileForWriteMethodType = 15798U,
  CloseAndCommitMethodType = 15800U,
  ServerConfigurationType_ConfigurationFile_Write = 15805U,
  ServerConfigurationType_ConfigurationFile_GetPosition = 15807U,
  ServerConfigurationType_ConfigurationFile_SetPosition = 15810U,
  FileTransferStateMachineType_Reset = 15843U,
  PublishSubscribeType_Status_Enable = 15846U,
  PublishSubscribeType_Status_Disable = 15847U,
  ServerConfigurationType_ConfigurationFile_CloseAndUpdate = 15849U,
  ServerConfigurationType_ConfigurationFile_ConfirmUpdate = 15863U,
  PubSubKeyServiceType_GetSecurityKeys = 15907U,
  PubSubKeyServiceType_GetSecurityGroup = 15910U,
  PubSubKeyServiceType_SecurityGroups_AddSecurityGroup = 15914U,
  PubSubKeyServiceType_SecurityGroups_RemoveSecurityGroup = 15917U,
  OPCUANamespaceMetadata_NamespaceFile_Open = 15971U,
  OPCUANamespaceMetadata_NamespaceFile_Close = 15974U,
  OPCUANamespaceMetadata_NamespaceFile_Read = 15976U,
  OPCUANamespaceMetadata_NamespaceFile_Write = 15979U,
  OPCUANamespaceMetadata_NamespaceFile_GetPosition = 15981U,
  OPCUANamespaceMetadata_NamespaceFile_SetPosition = 15984U,
  OPCUANamespaceMetadata_NamespaceFile_ExportNamespace = 15986U,
  RoleSetType_AddRole = 15997U,
  RoleSetType_RemoveRole = 16000U,
  AddRoleMethodType = 16002U,
  RemoveRoleMethodType = 16005U,
  ServerConfiguration_ConfigurationFile_Open = 16013U,
  WellKnownRole_Engineer_AddIdentity = 16041U,
  WellKnownRole_Engineer_RemoveIdentity = 16043U,
  ServerConfiguration_ConfigurationFile_Close = 16060U,
  ServerConfiguration_ConfigurationFile_Read = 16074U,
  ServerConfiguration_ConfigurationFile_Write = 16101U,
  ServerConfiguration_ConfigurationFile_GetPosition = 16103U,
  ServerConfiguration_ConfigurationFile_SetPosition = 16124U,
  RoleSetType_RoleName_Placeholder_AddApplication = 16165U,
  RoleSetType_RoleName_Placeholder_RemoveApplication = 16167U,
  RoleSetType_RoleName_Placeholder_AddEndpoint = 16169U,
  RoleSetType_RoleName_Placeholder_RemoveEndpoint = 16171U,
  RoleType_AddApplication = 16176U,
  RoleType_RemoveApplication = 16178U,
  RoleType_AddEndpoint = 16180U,
  RoleType_RemoveEndpoint = 16182U,
  AddApplicationMethodType = 16184U,
  RemoveApplicationMethodType = 16186U,
  AddEndpointMethodType = 16188U,
  RemoveEndpointMethodType = 16190U,
  WellKnownRole_Anonymous_AddApplication = 16195U,
  WellKnownRole_Anonymous_RemoveApplication = 16197U,
  WellKnownRole_Anonymous_AddEndpoint = 16199U,
  WellKnownRole_Anonymous_RemoveEndpoint = 16201U,
  WellKnownRole_AuthenticatedUser_AddApplication = 16206U,
  WellKnownRole_AuthenticatedUser_RemoveApplication = 16208U,
  WellKnownRole_AuthenticatedUser_AddEndpoint = 16210U,
  WellKnownRole_AuthenticatedUser_RemoveEndpoint = 16212U,
  WellKnownRole_Observer_AddApplication = 16217U,
  WellKnownRole_Observer_RemoveApplication = 16219U,
  WellKnownRole_Observer_AddEndpoint = 16221U,
  WellKnownRole_Observer_RemoveEndpoint = 16223U,
  WellKnownRole_Operator_AddApplication = 16228U,
  WellKnownRole_Operator_RemoveApplication = 16230U,
  WellKnownRole_Operator_AddEndpoint = 16232U,
  WellKnownRole_Operator_RemoveEndpoint = 16234U,
  WellKnownRole_Engineer_AddApplication = 16239U,
  WellKnownRole_Engineer_RemoveApplication = 16241U,
  WellKnownRole_Engineer_AddEndpoint = 16243U,
  WellKnownRole_Engineer_RemoveEndpoint = 16245U,
  WellKnownRole_Supervisor_AddApplication = 16250U,
  WellKnownRole_Supervisor_RemoveApplication = 16252U,
  WellKnownRole_Supervisor_AddEndpoint = 16254U,
  WellKnownRole_Supervisor_RemoveEndpoint = 16256U,
  WellKnownRole_SecurityAdmin_AddApplication = 16261U,
  WellKnownRole_SecurityAdmin_RemoveApplication = 16263U,
  WellKnownRole_SecurityAdmin_AddEndpoint = 16265U,
  WellKnownRole_SecurityAdmin_RemoveEndpoint = 16267U,
  WellKnownRole_ConfigureAdmin_AddApplication = 16272U,
  WellKnownRole_ConfigureAdmin_RemoveApplication = 16274U,
  WellKnownRole_ConfigureAdmin_AddEndpoint = 16276U,
  WellKnownRole_ConfigureAdmin_RemoveEndpoint = 16278U,
  ServerType_ServerCapabilities_RoleSet_AddRole = 16290U,
  ServerType_ServerCapabilities_RoleSet_RemoveRole = 16293U,
  ServerCapabilitiesType_RoleSet_AddRole = 16296U,
  ServerCapabilitiesType_RoleSet_RemoveRole = 16299U,
  Server_ServerCapabilities_RoleSet_AddRole = 16301U,
  Server_ServerCapabilities_RoleSet_RemoveRole = 16304U,
  ServerConfiguration_ConfigurationFile_CloseAndUpdate = 16317U,
  ServerConfiguration_ConfigurationFile_ConfirmUpdate = 16320U,
  ProvisionableDeviceType_ApplicationName_Placeholder_ConfigurationFile_Open = 16332U,
  ProvisionableDeviceType_ApplicationName_Placeholder_ConfigurationFile_Close = 16335U,
  ProvisionableDeviceType_ApplicationName_Placeholder_ConfigurationFile_Read = 16337U,
  ProvisionableDeviceType_ApplicationName_Placeholder_ConfigurationFile_Write = 16340U,
  ProvisionableDeviceType_ApplicationName_Placeholder_ConfigurationFile_GetPosition = 16342U,
  ProvisionableDeviceType_ApplicationName_Placeholder_ConfigurationFile_SetPosition = 16345U,
  FileSystem_CreateDirectory = 16348U,
  FileSystem_CreateFile = 16351U,
  FileSystem_DeleteFileSystemObject = 16354U,
  FileSystem_MoveOrCopy = 16356U,
  ProvisionableDeviceType_ApplicationName_Placeholder_ConfigurationFile_CloseAndUpdate = 16368U,
  AlarmConditionType_Silence = 16402U,
  AlarmConditionType_Suppress = 16403U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_Disable = 16439U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_Enable = 16440U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_AddComment = 16441U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_Acknowledge = 16461U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_Confirm = 16463U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_ShelvingState_Unshelve = 16515U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_ShelvingState_OneShotShelve = 16516U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_ShelvingState_TimedShelve = 16517U,
  ProvisionableDeviceType_ApplicationName_Placeholder_ConfigurationFile_ConfirmUpdate = 16523U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_Silence = 16533U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_Suppress = 16534U,
  PublishSubscribeType_ConnectionName_Placeholder_AddWriterGroup = 16535U,
  PublishSubscribeType_ConnectionName_Placeholder_AddReaderGroup = 16560U,
  PublishSubscribeType_AddConnection = 16598U,
  PublishSubscribeType_PublishedDataSets_AddPublishedDataItemsTemplate = 16601U,
  PublishSubscribeType_PublishedDataSets_AddPublishedEventsTemplate = 16639U,
  PublishSubscribeType_PublishedDataSets_AddDataSetFolder = 16651U,
  PublishSubscribeType_PublishedDataSets_RemoveDataSetFolder = 16680U,
  AddConnectionMethodType = 16691U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_Open =
    16717U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_Close =
    16724U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_Read =
    16726U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_Write =
    16729U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_GetPosition =
    16732U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_SetPosition =
    16735U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_OpenWithMasks =
    16741U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_CloseAndUpdate =
    16744U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate =
    16747U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_RemoveCertificate =
    16749U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_GetRejectedList =
    16752U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Disable =
    16790U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Enable =
    16791U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_AddComment =
    16792U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Acknowledge =
    16812U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Confirm =
    16814U,
  DataSetFolderType_DataSetFolderName_Placeholder_AddPublishedDataItemsTemplate = 16842U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_TimedShelve =
    16864U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_TimedShelve2 =
    16866U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_Unshelve =
    16868U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_Unshelve2 =
    16869U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_OneShotShelve =
    16871U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_OneShotShelve2 =
    16872U,
  DataSetFolderType_DataSetFolderName_Placeholder_AddPublishedEventsTemplate = 16881U,
  DataSetFolderType_DataSetFolderName_Placeholder_AddDataSetFolder = 16884U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Silence =
    16911U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Suppress =
    16912U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Suppress2 =
    16913U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Unsuppress =
    16915U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Unsuppress2 =
    16916U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_RemoveFromService =
    16918U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_RemoveFromService2 =
    16919U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_PlaceInService =
    16921U,
  DataSetFolderType_DataSetFolderName_Placeholder_RemoveDataSetFolder = 16923U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_PlaceInService2 =
    16926U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Reset =
    16928U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Reset2 =
    16929U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_GetGroupMemberships =
    16931U,
  DataSetFolderType_AddPublishedDataItemsTemplate = 16935U,
  DataSetFolderType_AddPublishedEventsTemplate = 16960U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Disable =
    16977U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Enable =
    16978U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_AddComment =
    16979U,
  DataSetFolderType_AddDataSetFolder = 16994U,
  DataSetFolderType_RemoveDataSetFolder = 16997U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Acknowledge =
    17003U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Confirm =
    17005U,
  AddPublishedDataItemsTemplateMethodType = 17030U,
  AddPublishedEventsTemplateMethodType = 17033U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_TimedShelve =
    17056U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    17058U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_Unshelve =
    17060U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_Unshelve2 =
    17061U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_OneShotShelve =
    17063U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    17064U,
  AddDataSetFolderMethodType = 17067U,
  RemoveDataSetFolderMethodType = 17079U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Silence =
    17103U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Suppress =
    17104U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Suppress2 =
    17105U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Unsuppress =
    17107U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Unsuppress2 =
    17108U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_RemoveFromService =
    17110U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_RemoveFromService2 =
    17111U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_PlaceInService =
    17113U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_PlaceInService2 =
    17114U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Reset =
    17116U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Reset2 =
    17117U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_GetGroupMemberships =
    17119U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_Open =
    17134U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_Close =
    17137U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_Read =
    17139U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_Write =
    17142U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_GetPosition =
    17144U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_SetPosition =
    17147U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_OpenWithMasks =
    17153U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_CloseAndUpdate =
    17156U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_AddCertificate =
    17159U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_RemoveCertificate =
    17161U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_GetRejectedList =
    17164U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Disable =
    17199U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Enable =
    17200U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_AddComment =
    17205U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Acknowledge =
    17237U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Confirm =
    17239U,
  PubSubConnectionType_WriterGroupName_Placeholder_AddDataSetWriter = 17293U,
  PublishSubscribeType_SetSecurityKeys = 17296U,
  SetSecurityKeysMethodType = 17298U,
  PubSubConnectionType_WriterGroupName_Placeholder_Status_Enable = 17316U,
  PubSubConnectionType_WriterGroupName_Placeholder_Status_Disable = 17317U,
  PubSubConnectionType_WriterGroupName_Placeholder_RemoveDataSetWriter = 17323U,
  PubSubConnectionType_ReaderGroupName_Placeholder_Status_Enable = 17331U,
  PubSubConnectionType_ReaderGroupName_Placeholder_Status_Disable = 17332U,
  PubSubConnectionType_ReaderGroupName_Placeholder_RemoveDataSetReader = 17333U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_TimedShelve =
    17340U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_TimedShelve2 =
    17342U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_Unshelve =
    17344U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_Unshelve2 =
    17345U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_OneShotShelve =
    17347U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_OneShotShelve2 =
    17348U,
  PubSubConnectionType_ReaderGroupName_Placeholder_AddDataSetReader = 17355U,
  PublishSubscribe_SetSecurityKeys = 17364U,
  PublishSubscribe_AddConnection = 17366U,
  PublishSubscribe_RemoveConnection = 17369U,
  PublishSubscribe_PublishedDataSets_AddPublishedDataItems = 17372U,
  PublishSubscribe_PublishedDataSets_AddPublishedEvents = 17375U,
  PublishSubscribe_PublishedDataSets_AddPublishedDataItemsTemplate = 17378U,
  PublishSubscribe_PublishedDataSets_AddPublishedEventsTemplate = 17381U,
  PublishSubscribe_PublishedDataSets_RemovePublishedDataSet = 17384U,
  DataSetReaderType_CreateTargetVariables = 17386U,
  DataSetReaderType_CreateDataSetMirror = 17389U,
  DataSetReaderTypeCreateTargetVariablesMethodType = 17392U,
  DataSetReaderTypeCreateDataSetMirrorMethodType = 17395U,
  PublishSubscribe_PublishedDataSets_AddDataSetFolder = 17398U,
  PublishSubscribe_PublishedDataSets_RemoveDataSetFolder = 17403U,
  PublishSubscribe_Status_Enable = 17407U,
  PublishSubscribe_Status_Disable = 17408U,
  PublishSubscribe_Diagnostics_Reset = 17421U,
  PubSubConnectionType_AddWriterGroup = 17427U,
  PubSubConnectionType_AddReaderGroup = 17465U,
  KeyCredentialConfigurationFolderType_ServiceName_Placeholder_GetEncryptingKey = 17516U,
  KeyCredentialConfigurationFolderType_ServiceName_Placeholder_UpdateCredential = 17519U,
  KeyCredentialConfigurationFolderType_ServiceName_Placeholder_DeleteCredential = 17521U,
  KeyCredentialConfigurationFolderType_CreateCredential = 17522U,
  KeyCredentialConfiguration_CreateCredential = 17528U,
  GetEncryptingKeyMethodType = 17531U,
  KeyCredentialConfigurationType_GetEncryptingKey = 17534U,
  PubSubConnectionTypeAddWriterGroupMethodType = 17561U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Silence =
    17572U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Suppress =
    17573U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Suppress2 =
    17574U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Unsuppress =
    17586U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Unsuppress2 =
    17587U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_RemoveFromService =
    17596U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_RemoveFromService2 =
    17599U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_PlaceInService =
    17616U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_PlaceInService2 =
    17617U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Reset =
    17619U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Reset2 =
    17620U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_GetGroupMemberships =
    17622U,
  PubSubConnectionAddReaderGroupGroupMethodType = 17630U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Disable =
    17678U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Enable =
    17679U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_AddComment =
    17680U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Acknowledge =
    17700U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Confirm =
    17702U,
  FileDirectoryType_FileDirectoryName_Placeholder_DeleteFileSystemObject = 17718U,
  WriterGroupType_DataSetWriterName_Placeholder_Status_Enable = 17751U,
  WriterGroupType_DataSetWriterName_Placeholder_Status_Disable = 17752U,
  WriterGroupType_DataSetWriterName_Placeholder_Diagnostics_Reset = 17765U,
  WriterGroupType_Diagnostics_Reset = 17824U,
  AlarmConditionType_Unsuppress = 17868U,
  AlarmConditionType_RemoveFromService = 17869U,
  AlarmConditionType_PlaceInService = 17870U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_Unsuppress = 17875U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_RemoveFromService = 17876U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_PlaceInService = 17877U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_TimedShelve =
    17917U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    17919U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_Unshelve =
    17922U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_Unshelve2 =
    17923U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_OneShotShelve =
    17925U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    17926U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Silence =
    17965U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Suppress =
    17966U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Suppress2 =
    17967U,
  WriterGroupType_AddDataSetWriter = 17969U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Unsuppress =
    17970U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Unsuppress2 =
    17971U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_RemoveFromService =
    17973U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_RemoveFromService2 =
    17974U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_PlaceInService =
    17977U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_PlaceInService2 =
    17978U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Reset =
    17980U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Reset2 =
    17981U,
  WriterGroupType_RemoveDataSetWriter = 17992U,
  PubSubGroupTypeAddWriterMethodType = 17994U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_GetGroupMemberships =
    18000U,
  KeyCredentialConfigurationType_UpdateCredential = 18006U,
  KeyCredentialConfigurationType_DeleteCredential = 18008U,
  KeyCredentialUpdateMethodType = 18009U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_Open =
    18024U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_Close =
    18027U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_Read =
    18031U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_Write =
    18034U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_GetPosition =
    18036U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_SetPosition =
    18039U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_OpenWithMasks =
    18045U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_CloseAndUpdate =
    18049U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_AddCertificate =
    18052U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_RemoveCertificate =
    18054U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_GetRejectedList =
    18057U,
  ReaderGroupType_DataSetReaderName_Placeholder_Status_Enable = 18090U,
  ReaderGroupType_DataSetReaderName_Placeholder_Status_Disable = 18091U,
  ReaderGroupType_DataSetReaderName_Placeholder_Diagnostics_Reset = 18104U,
  AlarmConditionType_Reset = 18199U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_Reset = 18212U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Disable =
    18225U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Enable =
    18226U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_AddComment =
    18227U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Acknowledge =
    18247U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Confirm =
    18249U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_TimedShelve =
    18294U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_TimedShelve2 =
    18296U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_Unshelve =
    18298U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_Unshelve2 =
    18299U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_OneShotShelve =
    18301U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_OneShotShelve2 =
    18302U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Silence =
    18335U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Suppress =
    18336U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Suppress2 =
    18337U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Unsuppress =
    18339U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Unsuppress2 =
    18340U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_RemoveFromService =
    18342U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_RemoveFromService2 =
    18343U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_PlaceInService =
    18345U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_PlaceInService2 =
    18346U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Reset =
    18349U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Reset2 =
    18350U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_GetGroupMemberships =
    18352U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Disable =
    18392U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Enable =
    18393U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_AddComment =
    18394U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Acknowledge =
    18414U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Confirm =
    18416U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_TimedShelve =
    18461U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    18463U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_Unshelve =
    18465U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_Unshelve2 =
    18466U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_OneShotShelve =
    18468U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    18469U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Silence =
    18503U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Suppress =
    18504U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Suppress2 =
    18505U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Unsuppress =
    18507U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Unsuppress2 =
    18508U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_RemoveFromService =
    18510U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_RemoveFromService2 =
    18511U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_PlaceInService =
    18513U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_PlaceInService2 =
    18514U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Reset =
    18516U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Reset2 =
    18517U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_GetGroupMemberships =
    18519U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_UpdateCertificate = 18533U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_GetCertificates = 18536U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_ApplyChanges = 18539U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CancelChanges = 18540U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CreateSigningRequest = 18541U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_GetRejectedList = 18544U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_ResetToServerDefaults = 18546U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_ConfigurationFile_Open = 18562U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_ConfigurationFile_Close = 18565U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_ConfigurationFile_Read = 18567U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_ConfigurationFile_Write = 18570U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_ConfigurationFile_GetPosition = 18572U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_ConfigurationFile_SetPosition = 18575U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_ConfigurationFile_CloseAndUpdate = 18581U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_ConfigurationFile_ConfirmUpdate = 18584U,
  WellKnownRole_TrustedApplication_AddIdentity = 18632U,
  WellKnownRole_TrustedApplication_RemoveIdentity = 18634U,
  WellKnownRole_TrustedApplication_AddApplication = 18636U,
  WellKnownRole_TrustedApplication_RemoveApplication = 18638U,
  WellKnownRole_TrustedApplication_AddEndpoint = 18640U,
  WellKnownRole_TrustedApplication_RemoveEndpoint = 18642U,
  AlarmMetricsType_Reset = 18666U,
  PublishSubscribeType_ConnectionName_Placeholder_Diagnostics_Reset = 18679U,
  PublishSubscribeType_Diagnostics_Reset = 18727U,
  PublishedDataSetType_DataSetWriterName_Placeholder_Diagnostics_Reset = 18883U,
  PubSubConnectionType_WriterGroupName_Placeholder_Diagnostics_Reset = 19119U,
  PubSubConnectionType_ReaderGroupName_Placeholder_Diagnostics_Reset = 19188U,
  PubSubConnectionType_Diagnostics_Reset = 19253U,
  CreateSelfSignedCertificateMethodType = 19327U,
  DeleteCertificateMethodType = 19330U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_CreateSelfSignedCertificate = 19332U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_DeleteCertificate = 19335U,
  ServerConfigurationType_CreateSelfSignedCertificate = 19337U,
  ServerConfigurationType_DeleteCertificate = 19340U,
  ServerConfiguration_CreateSelfSignedCertificate = 19342U,
  ServerConfiguration_DeleteCertificate = 19345U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CreateSelfSignedCertificate = 19347U,
  ProvisionableDeviceType_ApplicationName_Placeholder_DeleteCertificate = 19350U,
  LogObjectType_GetRecords = 19353U,
  GetRecordsMethodType = 19358U,
  ServerLog_GetRecords = 19373U,
  ApplicationConfigurationFolderType_ApplicationName_Placeholder_KeyCredentials_CreateCredential = 19410U,
  ApplicationConfigurationType_KeyCredentials_CreateCredential = 19424U,
  CertificateGroupType_CertificateExpired_Disable = 19483U,
  CertificateGroupType_CertificateExpired_Enable = 19484U,
  CertificateGroupType_CertificateExpired_AddComment = 19485U,
  CertificateGroupType_CertificateExpired_Acknowledge = 19505U,
  CertificateGroupType_CertificateExpired_Confirm = 19507U,
  DataSetWriterType_Diagnostics_Reset = 19562U,
  DataSetReaderType_Diagnostics_Reset = 19621U,
  PubSubDiagnosticsType_Reset = 19689U,
  ProvisionableDeviceType_ApplicationName_Placeholder_KeyCredentials_CreateCredential = 19740U,
  SerializationEntityType_ConfigureSerialization = 19839U,
  ConfigureSerializationMethodType = 19842U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_Disable = 20034U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_Enable = 20035U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_AddComment = 20036U,
  CertificateGroupType_CertificateExpired_ShelvingState_TimedShelve = 20097U,
  CertificateGroupType_CertificateExpired_ShelvingState_Unshelve = 20099U,
  CertificateGroupType_CertificateExpired_ShelvingState_OneShotShelve = 20100U,
  CertificateGroupType_CertificateExpired_Silence = 20132U,
  CertificateGroupType_CertificateExpired_Suppress = 20133U,
  CertificateGroupType_CertificateExpired_Unsuppress = 20134U,
  CertificateGroupType_CertificateExpired_RemoveFromService = 20135U,
  CertificateGroupType_CertificateExpired_PlaceInService = 20136U,
  CertificateGroupType_CertificateExpired_Reset = 20137U,
  CertificateGroupType_TrustListOutOfDate_Disable = 20176U,
  CertificateGroupType_TrustListOutOfDate_Enable = 20177U,
  CertificateGroupType_TrustListOutOfDate_AddComment = 20178U,
  CertificateGroupType_TrustListOutOfDate_Acknowledge = 20198U,
  CertificateGroupType_TrustListOutOfDate_Confirm = 20200U,
  CertificateGroupType_TrustListOutOfDate_ShelvingState_TimedShelve = 20245U,
  CertificateGroupType_TrustListOutOfDate_ShelvingState_Unshelve = 20247U,
  CertificateGroupType_TrustListOutOfDate_ShelvingState_OneShotShelve = 20248U,
  CertificateGroupType_TrustListOutOfDate_Silence = 20280U,
  CertificateGroupType_TrustListOutOfDate_Suppress = 20281U,
  CertificateGroupType_TrustListOutOfDate_Unsuppress = 20282U,
  CertificateGroupType_TrustListOutOfDate_RemoveFromService = 20283U,
  CertificateGroupType_TrustListOutOfDate_PlaceInService = 20284U,
  CertificateGroupType_TrustListOutOfDate_Reset = 20285U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_Disable = 20324U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_Enable = 20325U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_AddComment = 20326U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_Acknowledge = 20346U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_Confirm = 20348U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_ShelvingState_TimedShelve = 20393U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_ShelvingState_Unshelve = 20395U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_ShelvingState_OneShotShelve = 20396U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_Silence = 20430U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_Suppress = 20431U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_Unsuppress = 20432U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_RemoveFromService = 20433U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_PlaceInService = 20434U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_Reset = 20435U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_Disable = 20474U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_Enable = 20475U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_AddComment = 20476U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_Acknowledge = 20496U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_Confirm = 20498U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_TimedShelve = 20543U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_Unshelve = 20545U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_OneShotShelve = 20546U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_Silence = 20578U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_Suppress = 20579U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_Unsuppress = 20580U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_RemoveFromService = 20581U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_PlaceInService = 20582U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_Reset = 20583U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_Disable = 20622U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_Enable = 20623U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_AddComment = 20624U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_Acknowledge = 20644U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_Confirm = 20646U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_ShelvingState_TimedShelve = 20691U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_ShelvingState_Unshelve = 20693U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_ShelvingState_OneShotShelve = 20694U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_Silence = 20726U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_Suppress = 20727U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_Unsuppress = 20728U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_RemoveFromService = 20729U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_PlaceInService = 20730U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_Reset = 20731U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_Disable = 20770U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_Enable = 20771U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_AddComment = 20772U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_Acknowledge = 20792U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_Confirm = 20794U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_TimedShelve = 20839U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_Unshelve = 20841U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_OneShotShelve = 20842U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_Silence = 20874U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_Suppress = 20875U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_Unsuppress = 20876U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_RemoveFromService = 20877U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_PlaceInService = 20878U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_Reset = 20879U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_Disable = 20918U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_Enable = 20919U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_AddComment = 20920U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_Acknowledge = 20940U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_Confirm = 20942U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_ShelvingState_TimedShelve = 20987U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_ShelvingState_Unshelve = 20989U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_ShelvingState_OneShotShelve = 20990U,
  ReaderGroupType_DataSetReaderName_Placeholder_CreateTargetVariables = 21009U,
  ReaderGroupType_DataSetReaderName_Placeholder_CreateDataSetMirror = 21012U,
  ReaderGroupType_Diagnostics_Reset = 21027U,
  ReaderGroupType_AddDataSetReader = 21082U,
  ReaderGroupType_RemoveDataSetReader = 21085U,
  PubSubGroupTypeAddReaderMethodType = 21087U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_Silence = 21225U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_Suppress = 21226U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_Unsuppress = 21227U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_RemoveFromService = 21228U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_PlaceInService = 21229U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_Reset = 21230U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_Disable = 21269U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_Enable = 21270U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_AddComment = 21271U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_Acknowledge = 21291U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_Confirm = 21293U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_TimedShelve = 21338U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_Unshelve = 21340U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_OneShotShelve = 21341U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_Silence = 21373U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_Suppress = 21374U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_Unsuppress = 21375U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_RemoveFromService = 21376U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_PlaceInService = 21377U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_Reset = 21378U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_Disable = 21417U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_Enable = 21418U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_AddComment = 21419U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_Acknowledge = 21439U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_Confirm = 21441U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_ShelvingState_TimedShelve =
    21486U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_ShelvingState_Unshelve = 21488U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_ShelvingState_OneShotShelve =
    21489U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_Silence = 21521U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_Suppress = 21522U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_Unsuppress = 21523U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_RemoveFromService = 21524U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_PlaceInService = 21525U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_Reset = 21526U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_Disable = 21565U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_Enable = 21566U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_AddComment = 21567U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_Acknowledge = 21587U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_Confirm = 21589U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_ShelvingState_TimedShelve =
    21634U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_ShelvingState_Unshelve = 21636U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_ShelvingState_OneShotShelve =
    21637U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_Silence = 21669U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_Suppress = 21670U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_Unsuppress = 21671U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_RemoveFromService = 21672U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_PlaceInService = 21673U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_Reset = 21674U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Disable = 21713U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Enable = 21714U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_AddComment = 21715U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Acknowledge = 21735U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Confirm = 21737U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_TimedShelve =
    21782U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_Unshelve =
    21784U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_OneShotShelve =
    21785U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Silence = 21817U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Suppress = 21818U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Unsuppress = 21819U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_RemoveFromService =
    21820U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_PlaceInService =
    21821U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Reset = 21822U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Disable = 21861U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Enable = 21862U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_AddComment = 21863U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Acknowledge = 21883U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Confirm = 21885U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_TimedShelve =
    21930U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_Unshelve =
    21932U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_OneShotShelve =
    21933U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Silence = 21965U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Suppress = 21966U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Unsuppress = 21967U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_RemoveFromService =
    21968U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_PlaceInService =
    21969U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Reset = 21970U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Disable = 22009U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Enable = 22010U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_AddComment = 22011U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Acknowledge = 22031U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Confirm = 22033U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_TimedShelve =
    22078U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_Unshelve =
    22080U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_OneShotShelve =
    22081U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Silence = 22113U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Suppress = 22114U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Unsuppress = 22115U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_RemoveFromService = 22116U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_PlaceInService = 22117U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Reset = 22118U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Disable = 22157U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Enable = 22158U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_AddComment = 22159U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Acknowledge = 22179U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Confirm = 22181U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_TimedShelve =
    22226U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_Unshelve =
    22228U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_OneShotShelve =
    22229U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Silence = 22261U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Suppress = 22262U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Unsuppress = 22263U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_RemoveFromService = 22264U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_PlaceInService = 22265U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Reset = 22266U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Disable = 22305U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Enable = 22306U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_AddComment = 22307U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Acknowledge = 22327U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Confirm = 22329U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_TimedShelve =
    22374U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_Unshelve =
    22376U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_OneShotShelve =
    22377U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Silence = 22409U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Suppress = 22410U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Unsuppress = 22411U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_RemoveFromService =
    22412U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_PlaceInService = 22413U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Reset = 22414U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Disable = 22453U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Enable = 22454U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_AddComment = 22455U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Acknowledge = 22475U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Confirm = 22477U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_TimedShelve =
    22522U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_Unshelve =
    22524U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_OneShotShelve =
    22525U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Silence = 22557U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Suppress = 22558U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Unsuppress = 22559U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_RemoveFromService =
    22560U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_PlaceInService = 22561U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Reset = 22562U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Disable = 22601U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Enable = 22602U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_AddComment = 22603U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Acknowledge = 22623U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Confirm = 22625U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_TimedShelve =
    22670U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_Unshelve =
    22672U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_OneShotShelve =
    22673U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Silence = 22705U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Suppress = 22706U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Unsuppress = 22707U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_RemoveFromService = 22708U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_PlaceInService = 22709U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Reset = 22710U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Disable = 22749U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Enable = 22750U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_AddComment = 22751U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Acknowledge = 22771U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Confirm = 22773U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_TimedShelve =
    22818U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_Unshelve =
    22820U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_OneShotShelve =
    22821U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Silence = 22853U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Suppress = 22854U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Unsuppress = 22855U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_RemoveFromService = 22856U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_PlaceInService = 22857U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Reset = 22858U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Disable = 22897U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Enable = 22898U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_AddComment = 22899U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Acknowledge = 22919U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Confirm = 22921U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_TimedShelve =
    22966U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_Unshelve = 22968U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_OneShotShelve =
    22969U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Silence = 23001U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Suppress = 23002U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Unsuppress = 23003U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_RemoveFromService = 23004U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_PlaceInService = 23005U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Reset = 23006U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Disable = 23045U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Enable = 23046U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_AddComment = 23047U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Acknowledge = 23067U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Confirm = 23069U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_TimedShelve =
    23114U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_Unshelve = 23116U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_OneShotShelve =
    23117U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Silence = 23149U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Suppress = 23150U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Unsuppress = 23151U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_RemoveFromService = 23152U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_PlaceInService = 23153U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Reset = 23154U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Disable = 23193U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Enable = 23194U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_AddComment = 23195U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Acknowledge = 23215U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Confirm = 23217U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_TimedShelve =
    23262U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_Unshelve =
    23264U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_OneShotShelve =
    23265U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Silence = 23297U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Suppress = 23298U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Unsuppress = 23299U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_RemoveFromService = 23300U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_PlaceInService = 23301U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Reset = 23302U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Disable = 23341U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Enable = 23342U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_AddComment = 23343U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Acknowledge = 23363U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Confirm = 23365U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_TimedShelve =
    23410U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_Unshelve =
    23412U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_OneShotShelve =
    23413U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Silence = 23445U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Suppress = 23446U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Unsuppress = 23447U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_RemoveFromService = 23448U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_PlaceInService = 23449U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Reset = 23450U,
  AliasNameCategoryType_SubAliasNameCategories_Placeholder_FindAlias = 23459U,
  AliasNameCategoryType_FindAlias = 23462U,
  FindAliasMethodType = 23465U,
  Aliases_FindAlias = 23476U,
  TagVariables_FindAlias = 23485U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_Acknowledge = 23493U,
  Topics_FindAlias = 23494U,
  CertificateGroupType_GetRejectedList = 23526U,
  CertificateGroupFolderType_DefaultApplicationGroup_GetRejectedList = 23529U,
  CertificateGroupFolderType_DefaultHttpsGroup_GetRejectedList = 23531U,
  CertificateGroupFolderType_DefaultUserTokenGroup_GetRejectedList = 23533U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_GetRejectedList = 23535U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_GetRejectedList = 23544U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_GetRejectedList = 23546U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_GetRejectedList = 23548U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_GetRejectedList = 23550U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_GetRejectedList = 23552U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_GetRejectedList = 23554U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_Confirm = 23577U,
  PublishSubscribeType_SubscribedDataSets_AddDataSetFolder = 23637U,
  PublishSubscribeType_SubscribedDataSets_RemoveDataSetFolder = 23640U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_ShelvingState_TimedShelve = 23651U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_ShelvingState_TimedShelve2 = 23653U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_ShelvingState_Unshelve = 23655U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_ShelvingState_Unshelve2 = 23656U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_ShelvingState_OneShotShelve = 23659U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_ShelvingState_OneShotShelve2 = 23660U,
  PublishSubscribe_SubscribedDataSets_AddDataSetFolder = 23673U,
  PublishSubscribe_SubscribedDataSets_RemoveDataSetFolder = 23676U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_Silence = 23706U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_Suppress = 23707U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_Suppress2 = 23708U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_Unsuppress = 23710U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_Unsuppress2 = 23711U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_RemoveFromService = 23713U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_RemoveFromService2 = 23714U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_PlaceInService = 23716U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_PlaceInService2 = 23717U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_Reset = 23719U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_Reset2 = 23720U,
  AlarmSuppressionGroupType_AlarmCondition_Placeholder_GetGroupMemberships = 23722U,
  GetConnectionMethodType = 23726U,
  ModifyConnectionMethodType = 23729U,
  GetWriterGroupMethodType = 23745U,
  ModifyWriterGroupMethodType = 23748U,
  GetReaderGroupMethodType = 23767U,
  ModifyReaderGroupMethodType = 23770U,
  GetDataSetWriterMethodType = 23779U,
  ModifyDataSetWriterMethodType = 23781U,
  GetDataSetReaderMethodType = 23790U,
  ModifyDataSetReaderMethodType = 23792U,
  SubscribedDataSetFolderType_SubscribedDataSetFolderName_Placeholder_AddSubscribedDataSet = 23797U,
  SubscribedDataSetFolderType_SubscribedDataSetFolderName_Placeholder_RemoveSubscribedDataSet = 23800U,
  SubscribedDataSetFolderType_SubscribedDataSetFolderName_Placeholder_AddDataSetFolder = 23802U,
  SubscribedDataSetFolderType_SubscribedDataSetFolderName_Placeholder_RemoveDataSetFolder = 23805U,
  SubscribedDataSetFolderType_AddSubscribedDataSet = 23811U,
  SubscribedDataSetFolderType_RemoveSubscribedDataSet = 23814U,
  SubscribedDataSetFolderType_AddDataSetFolder = 23816U,
  SubscribedDataSetFolderType_RemoveDataSetFolder = 23819U,
  AddSubscribedDataSetMethodType = 23821U,
  RemoveSubscribedDataSetMethodType = 23824U,
  PublishSubscribeType_SubscribedDataSets_AddSubscribedDataSet = 24004U,
  PublishSubscribeType_SubscribedDataSets_RemoveSubscribedDataSet = 24007U,
  PublishSubscribe_SubscribedDataSets_AddSubscribedDataSet = 24010U,
  PublishSubscribe_SubscribedDataSets_RemoveSubscribedDataSet = 24013U,
  UserManagementType_AddUser = 24269U,
  UserManagementType_ModifyUser = 24271U,
  UserManagementType_RemoveUser = 24273U,
  UserManagementType_ChangePassword = 24275U,
  AddUserMethodType = 24282U,
  ModifyUserMethodType = 24284U,
  RemoveUserMethodType = 24286U,
  ChangePasswordMethodType = 24288U,
  UserManagement_AddUser = 24304U,
  UserManagement_ModifyUser = 24306U,
  UserManagement_RemoveUser = 24308U,
  UserManagement_ChangePassword = 24310U,
  DialogConditionType_Respond2 = 24312U,
  DialogResponse2MethodType = 24314U,
  AlarmConditionType_Suppress2 = 24316U,
  AlarmConditionType_Unsuppress2 = 24318U,
  AlarmConditionType_RemoveFromService2 = 24320U,
  AlarmConditionType_PlaceInService2 = 24322U,
  AlarmConditionType_Reset2 = 24324U,
  WithCommentMethodType = 24326U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_Suppress2 = 24328U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_Unsuppress2 = 24330U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_RemoveFromService2 = 24332U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_PlaceInService2 = 24334U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_Reset2 = 24336U,
  CertificateGroupType_CertificateExpired_Suppress2 = 24518U,
  CertificateGroupType_CertificateExpired_Unsuppress2 = 24520U,
  CertificateGroupType_CertificateExpired_RemoveFromService2 = 24522U,
  CertificateGroupType_CertificateExpired_PlaceInService2 = 24524U,
  CertificateGroupType_CertificateExpired_Reset2 = 24526U,
  CertificateGroupType_TrustListOutOfDate_Suppress2 = 24528U,
  CertificateGroupType_TrustListOutOfDate_Unsuppress2 = 24530U,
  CertificateGroupType_TrustListOutOfDate_RemoveFromService2 = 24532U,
  CertificateGroupType_TrustListOutOfDate_PlaceInService2 = 24534U,
  CertificateGroupType_TrustListOutOfDate_Reset2 = 24536U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_Suppress2 = 24538U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_Unsuppress2 = 24540U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_RemoveFromService2 = 24542U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_PlaceInService2 = 24544U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_Reset2 = 24546U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_Suppress2 = 24548U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_Unsuppress2 = 24550U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_RemoveFromService2 = 24552U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_PlaceInService2 = 24554U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_Reset2 = 24556U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_Suppress2 = 24558U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_Unsuppress2 = 24560U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_RemoveFromService2 = 24562U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_PlaceInService2 = 24564U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_Reset2 = 24566U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_Suppress2 = 24568U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_Unsuppress2 = 24570U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_RemoveFromService2 = 24572U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_PlaceInService2 = 24574U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_Reset2 = 24576U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_Suppress2 = 24578U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_Unsuppress2 = 24580U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_RemoveFromService2 = 24582U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_PlaceInService2 = 24584U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_Reset2 = 24586U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_Suppress2 = 24588U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_Unsuppress2 = 24590U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_RemoveFromService2 = 24592U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_PlaceInService2 = 24594U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_Reset2 = 24596U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_Suppress2 = 24598U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_Unsuppress2 = 24600U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_RemoveFromService2 = 24602U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_PlaceInService2 = 24604U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_Reset2 = 24606U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_Suppress2 = 24608U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_Unsuppress2 = 24610U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_RemoveFromService2 = 24612U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_PlaceInService2 = 24614U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_Reset2 = 24616U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Suppress2 = 24618U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Unsuppress2 = 24620U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_RemoveFromService2 =
    24622U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_PlaceInService2 =
    24624U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Reset2 = 24626U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Suppress2 = 24628U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Unsuppress2 = 24630U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_RemoveFromService2 =
    24632U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_PlaceInService2 =
    24634U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Reset2 = 24636U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Suppress2 = 24638U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Unsuppress2 = 24640U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_RemoveFromService2 = 24642U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_PlaceInService2 = 24644U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Reset2 = 24646U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Suppress2 = 24648U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Unsuppress2 = 24650U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_RemoveFromService2 = 24652U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_PlaceInService2 = 24654U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Reset2 = 24656U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Suppress2 = 24658U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Unsuppress2 = 24660U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_RemoveFromService2 =
    24662U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_PlaceInService2 = 24664U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Reset2 = 24666U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Suppress2 = 24668U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Unsuppress2 = 24670U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_RemoveFromService2 =
    24672U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_PlaceInService2 = 24674U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Reset2 = 24676U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Suppress2 = 24678U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Unsuppress2 = 24680U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_RemoveFromService2 =
    24682U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_PlaceInService2 = 24684U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Reset2 = 24686U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Suppress2 = 24688U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Unsuppress2 = 24690U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_RemoveFromService2 =
    24692U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_PlaceInService2 = 24694U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Reset2 = 24696U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Suppress2 = 24698U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Unsuppress2 = 24700U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_RemoveFromService2 = 24702U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_PlaceInService2 = 24704U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Reset2 = 24706U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Suppress2 = 24708U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Unsuppress2 = 24710U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_RemoveFromService2 = 24712U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_PlaceInService2 = 24714U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Reset2 = 24716U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Suppress2 = 24718U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Unsuppress2 = 24720U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_RemoveFromService2 = 24722U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_PlaceInService2 = 24724U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Reset2 = 24726U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Suppress2 = 24728U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Unsuppress2 = 24730U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_RemoveFromService2 = 24732U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_PlaceInService2 = 24734U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Reset2 = 24736U,
  AlarmConditionType_ShelvingState_TimedShelve2 = 24738U,
  AlarmConditionType_ShelvingState_Unshelve2 = 24740U,
  AlarmConditionType_ShelvingState_OneShotShelve2 = 24742U,
  AlarmConditionType_GetGroupMemberships = 24744U,
  GetGroupMembershipsMethodType = 24746U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_ShelvingState_TimedShelve2 = 24748U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_ShelvingState_Unshelve2 = 24750U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_ShelvingState_OneShotShelve2 = 24752U,
  AlarmGroupType_AlarmConditionInstance_Placeholder_GetGroupMemberships = 24754U,
  ShelvedStateMachineType_TimedShelve2 = 24756U,
  ShelvedStateMachineType_Unshelve2 = 24758U,
  ShelvedStateMachineType_OneShotShelve2 = 24760U,
  CertificateGroupType_CertificateExpired_ShelvingState_TimedShelve2 = 24978U,
  CertificateGroupType_CertificateExpired_ShelvingState_Unshelve2 = 24980U,
  CertificateGroupType_CertificateExpired_ShelvingState_OneShotShelve2 = 24982U,
  CertificateGroupType_CertificateExpired_GetGroupMemberships = 24984U,
  CertificateGroupType_TrustListOutOfDate_ShelvingState_TimedShelve2 = 24986U,
  CertificateGroupType_TrustListOutOfDate_ShelvingState_Unshelve2 = 24988U,
  CertificateGroupType_TrustListOutOfDate_ShelvingState_OneShotShelve2 = 24990U,
  CertificateGroupType_TrustListOutOfDate_GetGroupMemberships = 24992U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_ShelvingState_TimedShelve2 = 24994U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_ShelvingState_Unshelve2 = 24996U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_ShelvingState_OneShotShelve2 = 24998U,
  CertificateGroupFolderType_DefaultApplicationGroup_CertificateExpired_GetGroupMemberships = 25000U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 = 25002U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_Unshelve2 = 25004U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 = 25006U,
  CertificateGroupFolderType_DefaultApplicationGroup_TrustListOutOfDate_GetGroupMemberships = 25008U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_ShelvingState_TimedShelve2 = 25010U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_ShelvingState_Unshelve2 = 25012U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_ShelvingState_OneShotShelve2 = 25014U,
  CertificateGroupFolderType_DefaultHttpsGroup_CertificateExpired_GetGroupMemberships = 25016U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 = 25018U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_Unshelve2 = 25020U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 = 25022U,
  CertificateGroupFolderType_DefaultHttpsGroup_TrustListOutOfDate_GetGroupMemberships = 25024U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_ShelvingState_TimedShelve2 = 25026U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_ShelvingState_Unshelve2 = 25028U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_ShelvingState_OneShotShelve2 = 25030U,
  CertificateGroupFolderType_DefaultUserTokenGroup_CertificateExpired_GetGroupMemberships = 25032U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 = 25034U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_Unshelve2 = 25036U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 = 25038U,
  CertificateGroupFolderType_DefaultUserTokenGroup_TrustListOutOfDate_GetGroupMemberships = 25040U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_ShelvingState_TimedShelve2 =
    25042U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_ShelvingState_Unshelve2 = 25044U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_ShelvingState_OneShotShelve2 =
    25046U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_CertificateExpired_GetGroupMemberships = 25048U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    25050U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_ShelvingState_Unshelve2 = 25052U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    25054U,
  CertificateGroupFolderType_AdditionalGroup_Placeholder_TrustListOutOfDate_GetGroupMemberships = 25056U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_TimedShelve2 =
    25058U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_Unshelve2 =
    25060U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_OneShotShelve2 =
    25062U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_CertificateExpired_GetGroupMemberships =
    25064U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    25066U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_Unshelve2 =
    25068U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    25070U,
  ServerConfigurationType_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_GetGroupMemberships =
    25072U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_TimedShelve2 =
    25074U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_Unshelve2 =
    25076U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_OneShotShelve2 =
    25078U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_CertificateExpired_GetGroupMemberships = 25080U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    25082U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_Unshelve2 =
    25084U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    25086U,
  ServerConfigurationType_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_GetGroupMemberships = 25088U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_TimedShelve2 =
    25090U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_Unshelve2 =
    25092U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_OneShotShelve2 =
    25094U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_GetGroupMemberships =
    25096U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    25098U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_Unshelve2 =
    25100U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    25102U,
  ServerConfigurationType_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_GetGroupMemberships =
    25104U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_TimedShelve2 =
    25106U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_Unshelve2 =
    25108U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_OneShotShelve2 =
    25110U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_CertificateExpired_GetGroupMemberships =
    25112U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    25114U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_Unshelve2 =
    25116U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    25118U,
  ServerConfiguration_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_GetGroupMemberships =
    25120U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_TimedShelve2 =
    25122U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_Unshelve2 = 25124U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_OneShotShelve2 =
    25126U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_CertificateExpired_GetGroupMemberships = 25128U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    25130U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_Unshelve2 = 25132U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    25134U,
  ServerConfiguration_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_GetGroupMemberships = 25136U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_TimedShelve2 =
    25138U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_Unshelve2 =
    25140U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_OneShotShelve2 =
    25142U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_GetGroupMemberships = 25144U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    25146U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_Unshelve2 =
    25148U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    25150U,
  ServerConfiguration_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_GetGroupMemberships = 25152U,
  TimedShelve2MethodType = 25157U,
  PriorityMappingTableType_AddPriorityMappingEntry = 25229U,
  PriorityMappingTableType_DeletePriorityMappingEntry = 25231U,
  AddPriorityMappingEntryMethodType = 25233U,
  DeletePriorityMappingEntryMethodType = 25235U,
  PubSubKeyServiceType_SecurityGroups_AddSecurityGroupFolder = 25271U,
  PubSubKeyServiceType_SecurityGroups_RemoveSecurityGroupFolder = 25274U,
  PubSubKeyServiceType_KeyPushTargets_AddPushTarget = 25278U,
  PubSubKeyServiceType_KeyPushTargets_RemovePushTarget = 25281U,
  PubSubKeyServiceType_KeyPushTargets_AddPushTargetFolder = 25283U,
  PubSubKeyServiceType_KeyPushTargets_RemovePushTargetFolder = 25286U,
  AddSecurityGroupFolderMethodType = 25288U,
  RemoveSecurityGroupFolderMethodType = 25291U,
  SecurityGroupFolderType_SecurityGroupFolderName_Placeholder_AddSecurityGroupFolder = 25293U,
  SecurityGroupFolderType_SecurityGroupFolderName_Placeholder_RemoveSecurityGroupFolder = 25296U,
  SecurityGroupFolderType_AddSecurityGroupFolder = 25312U,
  SecurityGroupFolderType_RemoveSecurityGroupFolder = 25315U,
  ConnectSecurityGroupsMethodType = 25331U,
  DisconnectSecurityGroupsMethodType = 25334U,
  PubSubKeyPushTargetFolderType_PushTargetFolderName_Placeholder_AddPushTarget = 25348U,
  PubSubKeyPushTargetFolderType_PushTargetFolderName_Placeholder_RemovePushTarget = 25351U,
  PubSubKeyPushTargetFolderType_PushTargetFolderName_Placeholder_AddPushTargetFolder = 25353U,
  PubSubKeyPushTargetFolderType_PushTargetFolderName_Placeholder_RemovePushTargetFolder = 25356U,
  PubSubKeyPushTargetFolderType_AddPushTarget = 25366U,
  PubSubKeyPushTargetFolderType_RemovePushTarget = 25369U,
  PubSubKeyPushTargetFolderType_AddPushTargetFolder = 25371U,
  PubSubKeyPushTargetFolderType_RemovePushTargetFolder = 25374U,
  AddPushTargetMethodType = 25376U,
  RemovePushTargetMethodType = 25379U,
  AddPushTargetFolderMethodType = 25381U,
  RemovePushTargetFolderMethodType = 25384U,
  PublishSubscribeType_PubSubConfiguration_Open = 25411U,
  PublishSubscribeType_PubSubConfiguration_Close = 25414U,
  PublishSubscribeType_PubSubConfiguration_Read = 25416U,
  PublishSubscribeType_PubSubConfiguration_Write = 25419U,
  PublishSubscribeType_PubSubConfiguration_GetPosition = 25421U,
  PublishSubscribeType_PubSubConfiguration_SetPosition = 25424U,
  PublishSubscribeType_PubSubConfiguration_ReserveIds = 25426U,
  PublishSubscribeType_PubSubConfiguration_CloseAndUpdate = 25429U,
  PublishSubscribe_SecurityGroups_AddSecurityGroupFolder = 25434U,
  PublishSubscribe_SecurityGroups_RemoveSecurityGroupFolder = 25437U,
  PublishSubscribe_KeyPushTargets_AddPushTarget = 25441U,
  PublishSubscribe_KeyPushTargets_RemovePushTarget = 25444U,
  PublishSubscribe_KeyPushTargets_AddPushTargetFolder = 25446U,
  PublishSubscribe_KeyPushTargets_RemovePushTargetFolder = 25449U,
  PublishSubscribe_PubSubConfiguration_Open = 25459U,
  PublishSubscribe_PubSubConfiguration_Close = 25462U,
  PublishSubscribe_PubSubConfiguration_Read = 25464U,
  PublishSubscribe_PubSubConfiguration_Write = 25467U,
  PublishSubscribe_PubSubConfiguration_GetPosition = 25469U,
  PublishSubscribe_PubSubConfiguration_SetPosition = 25472U,
  PublishSubscribe_PubSubConfiguration_ReserveIds = 25474U,
  PublishSubscribe_PubSubConfiguration_CloseAndUpdate = 25477U,
  PubSubConfigurationType_ReserveIds = 25505U,
  PubSubConfigurationType_CloseAndUpdate = 25508U,
  PubSubConfigurationTypeReserveIdsMethodType = 25511U,
  PubSubConfigurationTypeCloseAndUpdateMethodType = 25514U,
  WellKnownRole_SecurityKeyServerAdmin_AddIdentity = 25572U,
  WellKnownRole_SecurityKeyServerAdmin_RemoveIdentity = 25574U,
  WellKnownRole_SecurityKeyServerAdmin_AddApplication = 25576U,
  WellKnownRole_SecurityKeyServerAdmin_RemoveApplication = 25578U,
  WellKnownRole_SecurityKeyServerAdmin_AddEndpoint = 25580U,
  WellKnownRole_SecurityKeyServerAdmin_RemoveEndpoint = 25582U,
  WellKnownRole_SecurityKeyServerPush_AddIdentity = 25591U,
  WellKnownRole_SecurityKeyServerPush_RemoveIdentity = 25593U,
  WellKnownRole_SecurityKeyServerPush_AddApplication = 25595U,
  WellKnownRole_SecurityKeyServerPush_RemoveApplication = 25597U,
  WellKnownRole_SecurityKeyServerPush_AddEndpoint = 25599U,
  WellKnownRole_SecurityKeyServerPush_RemoveEndpoint = 25601U,
  WellKnownRole_SecurityKeyServerAccess_AddIdentity = 25610U,
  WellKnownRole_SecurityKeyServerAccess_RemoveIdentity = 25612U,
  WellKnownRole_SecurityKeyServerAccess_AddApplication = 25614U,
  WellKnownRole_SecurityKeyServerAccess_RemoveApplication = 25616U,
  WellKnownRole_SecurityKeyServerAccess_AddEndpoint = 25618U,
  WellKnownRole_SecurityKeyServerAccess_RemoveEndpoint = 25620U,
  SecurityGroupFolderType_SecurityGroupName_Placeholder_InvalidateKeys = 25622U,
  SecurityGroupFolderType_SecurityGroupName_Placeholder_ForceKeyRotation = 25623U,
  SecurityGroupType_InvalidateKeys = 25624U,
  SecurityGroupType_ForceKeyRotation = 25625U,
  PubSubKeyPushTargetType_SecurityGroupName_Placeholder_InvalidateKeys = 25632U,
  PubSubKeyPushTargetType_SecurityGroupName_Placeholder_ForceKeyRotation = 25633U,
  PubSubKeyPushTargetType_ConnectSecurityGroups = 25641U,
  PubSubKeyPushTargetType_DisconnectSecurityGroups = 25644U,
  PubSubKeyPushTargetType_TriggerKeyUpdate = 25647U,
  PubSubKeyPushTargetFolderType_PushTargetName_Placeholder_ConnectSecurityGroups = 25655U,
  PubSubKeyPushTargetFolderType_PushTargetName_Placeholder_DisconnectSecurityGroups = 25658U,
  PubSubKeyPushTargetFolderType_PushTargetName_Placeholder_TriggerKeyUpdate = 25661U,
  ServerConfigurationType_CancelChanges = 25698U,
  ServerConfigurationType_ResetToServerDefaults = 25699U,
  ServerConfiguration_CancelChanges = 25708U,
  ServerConfiguration_ResetToServerDefaults = 25709U,
  RequestTicketsMethodType = 25727U,
  SetRegistrarEndpointsMethodType = 25729U,
  ProvisionableDeviceType_RequestTickets = 26873U,
  ProvisionableDeviceType_SetRegistrarEndpoints = 26875U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_Open =
    26889U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_Close =
    26892U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_Read =
    26894U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_Write =
    26897U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_GetPosition =
    26899U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_SetPosition =
    26902U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_OpenWithMasks =
    26907U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_CloseAndUpdate =
    26910U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_AddCertificate =
    26913U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustList_RemoveCertificate =
    26915U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_GetRejectedList =
    26919U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Disable =
    26954U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Enable =
    26955U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_AddComment =
    26956U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Acknowledge =
    26976U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Confirm =
    26978U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_TimedShelve =
    27023U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_TimedShelve2 =
    27025U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_Unshelve =
    27027U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_Unshelve2 =
    27028U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_OneShotShelve =
    27030U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_ShelvingState_OneShotShelve2 =
    27031U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Silence =
    27064U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Suppress =
    27065U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Suppress2 =
    27066U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Unsuppress =
    27068U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Unsuppress2 =
    27069U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_RemoveFromService =
    27071U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_RemoveFromService2 =
    27072U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_PlaceInService =
    27074U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_PlaceInService2 =
    27075U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Reset =
    27077U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_Reset2 =
    27078U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_CertificateExpired_GetGroupMemberships =
    27080U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Disable =
    27120U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Enable =
    27121U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_AddComment =
    27122U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Acknowledge =
    27142U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Confirm =
    27144U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_TimedShelve =
    27189U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    27191U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_Unshelve =
    27193U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_Unshelve2 =
    27194U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_OneShotShelve =
    27196U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    27197U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Silence =
    27230U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Suppress =
    27231U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Suppress2 =
    27232U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Unsuppress =
    27234U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Unsuppress2 =
    27235U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_RemoveFromService =
    27237U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_RemoveFromService2 =
    27238U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_PlaceInService =
    27240U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_PlaceInService2 =
    27241U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Reset =
    27243U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_Reset2 =
    27244U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultApplicationGroup_TrustListOutOfDate_GetGroupMemberships =
    27246U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_Open =
    27261U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_Close =
    27264U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_Read =
    27266U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_Write =
    27269U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_GetPosition =
    27271U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_SetPosition =
    27274U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_OpenWithMasks =
    27279U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_CloseAndUpdate =
    27282U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_AddCertificate =
    27285U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustList_RemoveCertificate =
    27287U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_GetRejectedList =
    27291U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Disable =
    27326U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Enable =
    27327U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_AddComment =
    27328U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Acknowledge =
    27348U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Confirm =
    27350U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_TimedShelve =
    27395U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_TimedShelve2 =
    27397U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_Unshelve =
    27399U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_Unshelve2 =
    27400U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_OneShotShelve =
    27402U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_ShelvingState_OneShotShelve2 =
    27403U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Silence =
    27436U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Suppress =
    27437U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Suppress2 =
    27438U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Unsuppress =
    27440U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Unsuppress2 =
    27441U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_RemoveFromService =
    27443U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_RemoveFromService2 =
    27444U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_PlaceInService =
    27446U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_PlaceInService2 =
    27447U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Reset =
    27449U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_Reset2 =
    27450U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_CertificateExpired_GetGroupMemberships =
    27452U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Disable =
    27492U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Enable =
    27493U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_AddComment =
    27494U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Acknowledge =
    27514U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Confirm =
    27516U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_TimedShelve =
    27561U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    27563U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_Unshelve =
    27565U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_Unshelve2 =
    27566U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_OneShotShelve =
    27568U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    27569U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Silence =
    27602U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Suppress =
    27603U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Suppress2 =
    27604U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Unsuppress =
    27606U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Unsuppress2 =
    27607U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_RemoveFromService =
    27609U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_RemoveFromService2 =
    27610U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_PlaceInService =
    27612U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_PlaceInService2 =
    27613U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Reset =
    27615U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_Reset2 =
    27616U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultHttpsGroup_TrustListOutOfDate_GetGroupMemberships =
    27618U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_Open =
    27633U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_Close =
    27636U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_Read =
    27638U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_Write =
    27641U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_GetPosition =
    27643U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_SetPosition =
    27646U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_OpenWithMasks =
    27651U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_CloseAndUpdate =
    27654U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_AddCertificate =
    27657U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustList_RemoveCertificate =
    27659U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_GetRejectedList =
    27663U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Disable =
    27698U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Enable =
    27699U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_AddComment =
    27700U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Acknowledge =
    27720U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Confirm =
    27722U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_TimedShelve =
    27767U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_TimedShelve2 =
    27769U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_Unshelve =
    27771U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_Unshelve2 =
    27772U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_OneShotShelve =
    27774U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_ShelvingState_OneShotShelve2 =
    27775U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Silence =
    27808U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Suppress =
    27809U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Suppress2 =
    27810U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Unsuppress =
    27812U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Unsuppress2 =
    27813U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_RemoveFromService =
    27815U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_RemoveFromService2 =
    27816U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_PlaceInService =
    27818U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_PlaceInService2 =
    27819U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Reset =
    27821U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_Reset2 =
    27822U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_CertificateExpired_GetGroupMemberships =
    27824U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Disable =
    27864U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Enable =
    27865U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_AddComment =
    27866U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Acknowledge =
    27886U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Confirm =
    27888U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_TimedShelve =
    27933U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_TimedShelve2 =
    27935U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_Unshelve =
    27937U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_Unshelve2 =
    27938U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_OneShotShelve =
    27940U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_ShelvingState_OneShotShelve2 =
    27941U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Silence =
    27974U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Suppress =
    27975U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Suppress2 =
    27976U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Unsuppress =
    27978U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Unsuppress2 =
    27979U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_RemoveFromService =
    27981U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_RemoveFromService2 =
    27982U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_PlaceInService =
    27984U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_PlaceInService2 =
    27985U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Reset =
    27987U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_Reset2 =
    27988U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CertificateGroups_DefaultUserTokenGroup_TrustListOutOfDate_GetGroupMemberships =
    27990U,
  ProvisionableDeviceType_ApplicationName_Placeholder_UpdateCertificate = 28005U,
  ProvisionableDeviceType_ApplicationName_Placeholder_ApplyChanges = 28008U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CancelChanges = 28009U,
  ProvisionableDeviceType_ApplicationName_Placeholder_CreateSigningRequest = 28010U,
  ProvisionableDeviceType_ApplicationName_Placeholder_GetRejectedList = 28013U,
  ProvisionableDeviceType_ApplicationName_Placeholder_ResetToServerDefaults = 28015U,
  ProvisionableDevice_RequestTickets = 29880U,
  ProvisionableDevice_SetRegistrarEndpoints = 29882U,
  GetCertificatesMethodType = 32282U,
  ServerConfigurationType_GetCertificates = 32296U,
  ServerConfiguration_GetCertificates = 32333U,
  ProvisionableDeviceType_ApplicationName_Placeholder_GetCertificates = 32359U,
  NonTransparentBackupRedundancyType_Failover = 32416U
};
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

}  // namespace ua

#endif  // UA_METHOD_IDENTIFIERS_H
