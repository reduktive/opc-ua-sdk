// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DIAGNOSTIC_BITS_H
#define UA_DIAGNOSTIC_BITS_H

#include <cstdint>

namespace ua::server::diag
{

// Service-level bits (ResponseHeader.serviceDiagnostics)
constexpr uint32_t serviceSymbolicId = 0x0001;
constexpr uint32_t serviceLocalizedText = 0x0002;
constexpr uint32_t serviceAdditionalInfo = 0x0004;
constexpr uint32_t serviceInnerStatus = 0x0008;
constexpr uint32_t serviceInnerDiagnostics = 0x0010;

// Operation-level bits (per-item diagnosticInfos[])
constexpr uint32_t operationSymbolicId = 0x0020;
constexpr uint32_t operationLocalizedText = 0x0040;
constexpr uint32_t operationAdditionalInfo = 0x0080;
constexpr uint32_t operationInnerStatus = 0x0100;
constexpr uint32_t operationInnerDiagnostics = 0x0200;

// Convenience masks
constexpr uint32_t serviceLevelMask = 0x001F;
constexpr uint32_t operationLevelMask = 0x03E0;

}  // namespace ua::server::diag

#endif  // !UA_DIAGNOSTIC_BITS_H
