// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_diagnostic_info.h"
#include "ua_utilities.h"

namespace ua
{

DiagnosticInfo::DiagnosticInfo(const DiagnosticInfo& other)
{
  copy(other);
}

DiagnosticInfo& DiagnosticInfo::operator=(const DiagnosticInfo& other)
{
  copy(other);
  return *this;
}

bool DiagnosticInfo::operator==(const DiagnosticInfo& obj) const
{
  using namespace utils;

  return (compare(mSymbolicId, obj.mSymbolicId) && compare(mNamespaceUri, obj.mNamespaceUri) &&
          compare(mLocale, obj.mLocale) && compare(mLocalizedText, obj.mLocalizedText) &&
          compare(mAdditionalInfo, obj.mAdditionalInfo) && compare(mInnerStatusCode, obj.mInnerStatusCode) &&
          compare(mInnerDiagnosticInfo, obj.mInnerDiagnosticInfo));
}

const optional<int32_t>& DiagnosticInfo::symbolic_id() const
{
  return mSymbolicId;
}

optional<int32_t>& DiagnosticInfo::symbolic_id()
{
  return mSymbolicId;
}

const optional<int32_t>& DiagnosticInfo::namespace_uri() const
{
  return mNamespaceUri;
}

optional<int32_t>& DiagnosticInfo::namespace_uri()
{
  return mNamespaceUri;
}

const optional<int32_t>& DiagnosticInfo::locale() const
{
  return mLocale;
}

optional<int32_t>& DiagnosticInfo::locale()
{
  return mLocale;
}

const optional<int32_t>& DiagnosticInfo::localized_text() const
{
  return mLocalizedText;
}

optional<int32_t>& DiagnosticInfo::localized_text()
{
  return mLocalizedText;
}

const optional<std::string>& DiagnosticInfo::additional_info() const
{
  return mAdditionalInfo;
}

optional<std::string>& DiagnosticInfo::additional_info()
{
  return mAdditionalInfo;
}

const optional<StatusCode>& DiagnosticInfo::inner_status_code() const
{
  return mInnerStatusCode;
}

optional<StatusCode>& DiagnosticInfo::inner_status_code()
{
  return mInnerStatusCode;
}

const unique_ptr<DiagnosticInfo>& DiagnosticInfo::inner_diagnostic_info() const
{
  return mInnerDiagnosticInfo;
}

unique_ptr<DiagnosticInfo>& DiagnosticInfo::inner_diagnostic_info()
{
  return mInnerDiagnosticInfo;
}

bool DiagnosticInfo::is_null() const
{
  return !is_not_null();
}

bool DiagnosticInfo::is_not_null() const
{
  return (mSymbolicId || mNamespaceUri || mLocale || mLocalizedText || mAdditionalInfo || mInnerStatusCode ||
          mInnerDiagnosticInfo.get());
}

void DiagnosticInfo::clear()
{
  mSymbolicId.reset();
  mNamespaceUri.reset();
  mLocale.reset();
  mLocalizedText.reset();
  mAdditionalInfo.reset();
  mInnerStatusCode.reset();
  mInnerDiagnosticInfo.reset();
}

BuiltInTypeId DiagnosticInfo::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::DiagnosticInfo};
}

void DiagnosticInfo::copy(const DiagnosticInfo& other)
{
  mSymbolicId = other.mSymbolicId;
  mNamespaceUri = other.mNamespaceUri;
  mLocale = other.mLocale;
  mLocalizedText = other.mLocalizedText;
  mAdditionalInfo = other.mAdditionalInfo;
  mInnerStatusCode = other.mInnerStatusCode;
  if (other.mInnerDiagnosticInfo)
  {
    mInnerDiagnosticInfo = make_unique<DiagnosticInfo>(*other.mInnerDiagnosticInfo);
  }
}

}  // namespace ua
