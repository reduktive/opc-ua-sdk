// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_diagnostic_collector.h"

#include "ua_error_detail.h"

namespace ua::server
{

DiagnosticCollector::DiagnosticCollector(
  uint32_t clientReturnDiagnostics, const DiagnosticSecurityContext& security)
  : mMaskPreAuthErrors(security.maskPreAuthErrors)
{
  // Gate 1: SecurityPolicy None - no diagnostics ever.
  if (!security.securedChannel)
  {
    mReturnDiagnostics = 0;
    return;
  }

  // Gate 2: Pre-authentication - no diagnostics, mask StatusCodes.
  if (!security.authenticated)
  {
    mReturnDiagnostics = 0;
    return;
  }

  // Gate 3: Post-authentication - apply effective level (already resolved
  // from server policy + user claims via resolve_diagnostic_level).
  using Level = ServerConfig::DiagnosticPolicy::Level;

  switch (security.effectiveLevel)
  {
  case Level::None:
    mReturnDiagnostics = 0;
    break;

  case Level::Summary:
  {
    // Allow only symbolicId, locale, localizedText - suppress additionalInfo,
    // innerStatusCode, innerDiagnosticInfo.
    constexpr uint32_t summaryMask = diag::serviceSymbolicId | diag::serviceLocalizedText |
                                     diag::operationSymbolicId | diag::operationLocalizedText;
    mReturnDiagnostics = clientReturnDiagnostics & summaryMask;
    break;
  }

  case Level::Full:
    mReturnDiagnostics = clientReturnDiagnostics;
    break;
  }

  mMaskPreAuthErrors = false;  // post-auth, no masking
}

DiagnosticCollector::DiagnosticCollector(uint32_t returnDiagnostics) : mReturnDiagnostics(returnDiagnostics)
{}

bool DiagnosticCollector::wants_operation_diagnostics() const noexcept
{
  return (mReturnDiagnostics & diag::operationLevelMask) != 0;
}

bool DiagnosticCollector::wants_service_diagnostics() const noexcept
{
  return (mReturnDiagnostics & diag::serviceLevelMask) != 0;
}

bool DiagnosticCollector::should_mask_pre_auth_errors() const noexcept
{
  return mMaskPreAuthErrors;
}

uint32_t DiagnosticCollector::effective_return_diagnostics() const noexcept
{
  return mReturnDiagnostics;
}

void DiagnosticCollector::set_service_detail(StatusCode status)
{
  if (!wants_service_diagnostics())
  {
    return;
  }
  if (auto detail = status.shared_detail())
  {
    mServiceDetail = std::move(detail);
  }
}

void DiagnosticCollector::add_item_detail(size_t index, shared_ptr<const ua::ErrorDetail> detail)
{
  if (!wants_operation_diagnostics() || !detail)
  {
    return;
  }
  mItemDetails[index] = std::move(detail);
}

void DiagnosticCollector::add_operation_detail(
  size_t index, size_t operation, shared_ptr<const ua::ErrorDetail> detail)
{
  if (!wants_operation_diagnostics() || !detail)
  {
    return;
  }
  mOperationDetails[index][operation] = std::move(detail);
}

void DiagnosticCollector::apply_to(ua::ResponseHeader& header) const
{
  if (mReturnDiagnostics == 0)
  {
    return;
  }

  StringTableBuilder table;

  if (wants_service_diagnostics() && mServiceDetail)
  {
    header.service_diagnostics() =
      convert(*mServiceDetail, mReturnDiagnostics & diag::serviceLevelMask, table);
  }

  auto strings = table.build();
  if (!strings.empty())
  {
    header.string_table() = std::move(strings);
  }
}

void DiagnosticCollector::apply_to(
  ua::ResponseHeader& header, ua::Array<ua::DiagnosticInfo>& itemDiagnostics, size_t resultCount) const
{
  if (mReturnDiagnostics == 0)
  {
    return;
  }

  StringTableBuilder table;

  if (wants_service_diagnostics() && mServiceDetail)
  {
    header.service_diagnostics() =
      convert(*mServiceDetail, mReturnDiagnostics & diag::serviceLevelMask, table);
  }

  if (wants_operation_diagnostics() && !mItemDetails.empty())
  {
    auto& items = itemDiagnostics.payload();
    items.resize(resultCount);
    const uint32_t opBits = (mReturnDiagnostics & diag::operationLevelMask) >> 5;
    for (const auto& [index, detail] : mItemDetails)
    {
      if (detail && index < resultCount)
      {
        items[index] = convert(*detail, opBits, table);
      }
    }
  }

  auto strings = table.build();
  if (!strings.empty())
  {
    header.string_table() = std::move(strings);
  }
}

void DiagnosticCollector::apply_to(ua::ResponseHeader& header, ua::Array<ua::DiagnosticInfo>& itemDiagnostics,
  size_t resultCount, const std::function<ua::Array<ua::DiagnosticInfo>*(size_t)>& operationDiagnosticsFor,
  const std::function<size_t(size_t)>& operationCountFor) const
{
  if (mReturnDiagnostics == 0)
  {
    return;
  }

  StringTableBuilder table;

  if (wants_service_diagnostics() && mServiceDetail)
  {
    header.service_diagnostics() =
      convert(*mServiceDetail, mReturnDiagnostics & diag::serviceLevelMask, table);
  }

  const uint32_t opBits = (mReturnDiagnostics & diag::operationLevelMask) >> 5;

  if (wants_operation_diagnostics() && !mItemDetails.empty())
  {
    auto& items = itemDiagnostics.payload();
    items.resize(resultCount);
    for (const auto& [index, detail] : mItemDetails)
    {
      if (detail && index < resultCount)
      {
        items[index] = convert(*detail, opBits, table);
      }
    }
  }

  if (wants_operation_diagnostics() && operationDiagnosticsFor && operationCountFor)
  {
    for (const auto& [index, operations] : mOperationDetails)
    {
      if (index >= resultCount)
      {
        continue;
      }
      auto* slot = operationDiagnosticsFor(index);
      if (!slot)
      {
        continue;
      }
      auto& entries = slot->payload();
      entries.resize(operationCountFor(index));
      for (const auto& [operation, detail] : operations)
      {
        if (detail && operation < entries.size())
        {
          entries[operation] = convert(*detail, opBits, table);
        }
      }
    }
  }

  auto strings = table.build();
  if (!strings.empty())
  {
    header.string_table() = std::move(strings);
  }
}

void DiagnosticCollector::apply_to(ua::ResponseHeader& header, std::function<StatusCode(size_t)> itemStatus,
  size_t resultCount, ua::Array<ua::DiagnosticInfo>& itemDiagnostics) const
{
  if (mReturnDiagnostics == 0)
  {
    return;
  }

  StringTableBuilder table;

  // Service-level diagnostics.
  if (wants_service_diagnostics() && mServiceDetail)
  {
    header.service_diagnostics() =
      convert(*mServiceDetail, mReturnDiagnostics & diag::serviceLevelMask, table);
  }

  // Operation-level diagnostics - walk per-item StatusCodes.
  if (wants_operation_diagnostics() && resultCount > 0 && itemStatus)
  {
    const uint32_t opBits = (mReturnDiagnostics & diag::operationLevelMask) >> 5;
    auto& items = itemDiagnostics.payload();
    items.resize(resultCount);  // all-empty by default
    for (size_t i = 0; i < resultCount; ++i)
    {
      auto status = itemStatus(i);
      if (const auto& detail = status.shared_detail())
      {
        items[i] = convert(*detail, opBits, table);
      }
    }
  }

  // String table (shared across service + operation diagnostics).
  auto strings = table.build();
  if (!strings.empty())
  {
    header.string_table() = std::move(strings);
  }
}

void DiagnosticCollector::apply_to_notification_items(ua::Array<ua::String>& stringTable,
  std::function<StatusCode(size_t)> itemStatus, std::function<uint32_t(size_t)> itemReturnDiagnostics,
  size_t itemCount, ua::Array<ua::DiagnosticInfo>& itemDiagnostics) const
{
  if (mReturnDiagnostics == 0 || itemCount == 0 || !itemStatus || !itemReturnDiagnostics)
  {
    return;
  }

  StringTableBuilder table;
  bool emitted = false;

  for (size_t index = 0; index < itemCount; ++index)
  {
    const uint32_t permittedItemMask = itemReturnDiagnostics(index) & mReturnDiagnostics;
    const uint32_t operationBits = (permittedItemMask & diag::operationLevelMask) >> 5;
    if (operationBits == 0)
    {
      continue;
    }

    const auto detail = itemStatus(index).shared_detail();
    if (!detail)
    {
      continue;
    }

    auto diagnostic = convert(*detail, operationBits, table);
    if (diagnostic.is_null())
    {
      continue;
    }

    if (!emitted)
    {
      itemDiagnostics.payload().resize(itemCount);
      emitted = true;
    }
    itemDiagnostics[index] = std::move(diagnostic);
  }

  if (emitted)
  {
    stringTable = table.build();
  }
}

ua::DiagnosticInfo DiagnosticCollector::convert(
  const ua::ErrorDetail& detail, uint32_t levelBits, StringTableBuilder& table) const
{
  ua::DiagnosticInfo info;

  // ErrorDetail::code -> DiagnosticInfo::symbolicId
  if ((levelBits & 0x01) && !detail.code.empty())
  {
    info.symbolic_id() = table.intern(detail.code);
  }

  // ErrorDetail::source -> DiagnosticInfo::namespaceUri
  if ((levelBits & 0x01) && !detail.source.empty())
  {
    info.namespace_uri() = table.intern(detail.source);
  }

  // ErrorDetail::summary -> DiagnosticInfo::localizedText
  if ((levelBits & 0x02) && !detail.summary.empty())
  {
    info.localized_text() = table.intern(detail.summary);
  }

  // ErrorDetail::detail + mContext -> DiagnosticInfo::additionalInfo.
  // A layer carrying structured context is serialized as marker-tagged JSON;
  // a contextless layer emits plain prose. See ua_error_detail_context_json.h.
  if ((levelBits & 0x04) && (!detail.detail.empty() || !detail.context.empty()))
  {
    info.additional_info() = ua::detail::make_additional_info(detail);
  }

  // ErrorDetail::innerStatus -> DiagnosticInfo::innerStatusCode. Plain Good is the field's default, meaning
  // no inner status; any other code, a Good subcode or an Uncertain code included, is the cause's code and is
  // sent.
  if ((levelBits & 0x08) && detail.innerStatus != StatusCode{Status::Good}.value())
  {
    info.inner_status_code() = StatusCode{detail.innerStatus};
  }

  // ErrorDetail::cause -> DiagnosticInfo::innerDiagnosticInfo (recursive)
  if ((levelBits & 0x10) && detail.cause)
  {
    info.inner_diagnostic_info() =
      std::make_unique<ua::DiagnosticInfo>(convert(*detail.cause, levelBits, table));
  }

  return info;
}

}  // namespace ua::server
