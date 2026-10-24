// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_TEST_NAMESPACE_CALLER_ALLOCATION_CONTROLLER_H
#define UA_TEST_NAMESPACE_CALLER_ALLOCATION_CONTROLLER_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ua::test::allocation
{

/// Fixed storage used by the replacement allocation functions while interception is armed.
struct Trace
{
  std::size_t bytes{0};
  std::size_t depth{0};
  std::array<std::uintptr_t, 96> addresses{};
};

struct Frame
{
  std::uintptr_t address{0};
  std::string function;
  std::string file;
  std::size_t line{0};
  std::string statement;
  std::string sourceLocation;
};

struct Evidence
{
  Trace allocation;
  Frame nearestSdkFrame;
  std::vector<Frame> copyWrappers;
  std::vector<Frame> inlineFrames;
};

/// These functions touch only this thread's fixed storage. No symbolization is permitted while armed.
void record() noexcept;
void fail_at(std::uintptr_t address) noexcept;
/// After allowing @p successfulAllocations allocations, reject every later allocation until disarm().
void fail_all(std::size_t successfulAllocations = 0) noexcept;
void disarm() noexcept;
bool armed() noexcept;
std::size_t injections() noexcept;
bool overflowed() noexcept;
Trace failed_allocation() noexcept;

/// Only called after disarming. A missing symbolizer, SDK symbols or source file is an infrastructure error.
std::vector<Evidence> recorded_sdk_allocations();
std::optional<Evidence> identify(const Trace& trace);
std::string describe(const Evidence& evidence);

/// Decode the address-delimited inline records, in the exact requested address order.
std::vector<std::vector<Frame>> parse_symbolizer_output(
  std::string_view output, std::span<const std::uintptr_t> expectedAddresses);

}  // namespace ua::test::allocation

#endif
