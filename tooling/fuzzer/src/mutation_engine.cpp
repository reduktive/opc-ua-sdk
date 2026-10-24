// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "mutation_engine.h"

#include <algorithm>
#include <cstring>

namespace fuzz
{

MutationEngine::MutationEngine(uint64_t seed)
{
  if (seed == 0)
  {
    std::random_device rd;
    mRng.seed(rd());
  }
  else
  {
    mRng.seed(seed);
  }
}

MutationStrategy MutationEngine::mutate(std::vector<uint8_t>& buffer)
{
  if (buffer.empty())
    return MutationStrategy::BitFlip;

  static constexpr MutationStrategy strategies[] = {
    MutationStrategy::BitFlip,
    MutationStrategy::ByteFlip,
    MutationStrategy::BoundaryCorrupt,
    MutationStrategy::LengthTamper,
    MutationStrategy::EdgeIntegerInject,
    MutationStrategy::EdgeInt16Inject,
    MutationStrategy::BlockDelete,
    MutationStrategy::BlockDuplicate,
    MutationStrategy::BlockShuffle,
    MutationStrategy::NullRun,
    MutationStrategy::HighByteRun,
    MutationStrategy::FormatStringInject,
    MutationStrategy::EncodingPrefixSwap,
  };

  auto idx = std::uniform_int_distribution<size_t>(0, std::size(strategies) - 1)(mRng);
  auto strategy = strategies[idx];
  apply(strategy, buffer);
  return strategy;
}

void MutationEngine::apply(MutationStrategy strategy, std::vector<uint8_t>& buffer)
{
  if (buffer.empty())
    return;

  switch (strategy)
  {
  case MutationStrategy::BitFlip:
    bit_flip(buffer);
    break;
  case MutationStrategy::ByteFlip:
    byte_flip(buffer);
    break;
  case MutationStrategy::BoundaryCorrupt:
    boundary_corrupt(buffer);
    break;
  case MutationStrategy::LengthTamper:
    length_tamper(buffer);
    break;
  case MutationStrategy::EdgeIntegerInject:
    edge_integer_inject(buffer);
    break;
  case MutationStrategy::EdgeInt16Inject:
    edge_int16_inject(buffer);
    break;
  case MutationStrategy::BlockDelete:
    block_delete(buffer);
    break;
  case MutationStrategy::BlockDuplicate:
    block_duplicate(buffer);
    break;
  case MutationStrategy::BlockShuffle:
    block_shuffle(buffer);
    break;
  case MutationStrategy::NullRun:
    null_run(buffer);
    break;
  case MutationStrategy::HighByteRun:
    high_byte_run(buffer);
    break;
  case MutationStrategy::FormatStringInject:
    format_string_inject(buffer);
    break;
  case MutationStrategy::EncodingPrefixSwap:
    encoding_prefix_swap(buffer);
    break;
  }
}

void MutationEngine::bit_flip(std::vector<uint8_t>& buf)
{
  if (buf.empty())
    return;

  auto numFlips = std::uniform_int_distribution<int>(1, 8)(mRng);
  for (int i = 0; i < numFlips; ++i)
  {
    auto pos = std::uniform_int_distribution<size_t>(0, buf.size() - 1)(mRng);
    auto bit = std::uniform_int_distribution<int>(0, 7)(mRng);
    buf[pos] ^= static_cast<uint8_t>(1u << bit);
  }
}

void MutationEngine::byte_flip(std::vector<uint8_t>& buf)
{
  if (buf.empty())
    return;

  auto pos = std::uniform_int_distribution<size_t>(0, buf.size() - 1)(mRng);
  buf[pos] = static_cast<uint8_t>(~buf[pos]);
}

void MutationEngine::boundary_corrupt(std::vector<uint8_t>& buf)
{
  if (buf.size() < 4)
    return;

  // Corrupt at a 4-byte aligned offset.
  auto maxAligned = (buf.size() - 1) / 4;
  auto alignedIdx = std::uniform_int_distribution<size_t>(0, maxAligned)(mRng);
  auto pos = alignedIdx * 4;
  if (pos < buf.size())
  {
    buf[pos] = static_cast<uint8_t>(std::uniform_int_distribution<int>(0, 255)(mRng));
  }
}

void MutationEngine::length_tamper(std::vector<uint8_t>& buf)
{
  if (buf.size() < 4)
    return;

  // Find a 4-byte aligned position and replace with an edge length value.
  auto maxPos = buf.size() - 4;
  auto pos = std::uniform_int_distribution<size_t>(0, maxPos)(mRng);
  pos = (pos / 4) * 4;

  static constexpr uint32_t edgeLengths[] = {0, 1, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE};
  auto val = edgeLengths[std::uniform_int_distribution<size_t>(0, std::size(edgeLengths) - 1)(mRng)];

  std::memcpy(&buf[pos], &val, 4);
}

void MutationEngine::edge_integer_inject(std::vector<uint8_t>& buf)
{
  if (buf.size() < 4)
    return;

  auto maxPos = buf.size() - 4;
  auto pos = std::uniform_int_distribution<size_t>(0, maxPos)(mRng);

  static constexpr uint32_t edges[] = {0, 1, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 0x7FFFFFFE, 2, 0xFFFFFFFE};
  auto val = edges[std::uniform_int_distribution<size_t>(0, std::size(edges) - 1)(mRng)];

  std::memcpy(&buf[pos], &val, 4);
}

void MutationEngine::edge_int16_inject(std::vector<uint8_t>& buf)
{
  if (buf.size() < 2)
    return;

  auto maxPos = buf.size() - 2;
  auto pos = std::uniform_int_distribution<size_t>(0, maxPos)(mRng);

  static constexpr uint16_t edges[] = {0, 1, 0xFFFF, 0x7FFF, 0x8000, 0x7FFE, 2, 0xFFFE};
  auto val = edges[std::uniform_int_distribution<size_t>(0, std::size(edges) - 1)(mRng)];

  std::memcpy(&buf[pos], &val, 2);
}

void MutationEngine::block_delete(std::vector<uint8_t>& buf)
{
  if (buf.size() < 2)
    return;

  auto maxLen = std::min(buf.size() / 2, size_t{64});
  auto len = std::uniform_int_distribution<size_t>(1, std::max(maxLen, size_t{1}))(mRng);
  auto start = std::uniform_int_distribution<size_t>(0, buf.size() - len)(mRng);

  buf.erase(buf.begin() + static_cast<ptrdiff_t>(start), buf.begin() + static_cast<ptrdiff_t>(start + len));
}

void MutationEngine::block_duplicate(std::vector<uint8_t>& buf)
{
  if (buf.empty())
    return;

  auto maxLen = std::min(buf.size(), size_t{64});
  auto len = std::uniform_int_distribution<size_t>(1, std::max(maxLen, size_t{1}))(mRng);
  auto start = std::uniform_int_distribution<size_t>(0, buf.size() - len)(mRng);

  std::vector<uint8_t> block(
    buf.begin() + static_cast<ptrdiff_t>(start), buf.begin() + static_cast<ptrdiff_t>(start + len));
  buf.insert(buf.end(), block.begin(), block.end());
}

void MutationEngine::block_shuffle(std::vector<uint8_t>& buf)
{
  if (buf.size() < 4)
    return;

  auto maxLen = std::min(buf.size() / 4, size_t{32});
  if (maxLen == 0)
    return;

  auto len = std::uniform_int_distribution<size_t>(1, maxLen)(mRng);
  auto pos1 = std::uniform_int_distribution<size_t>(0, buf.size() - len)(mRng);
  auto pos2 = std::uniform_int_distribution<size_t>(0, buf.size() - len)(mRng);

  if (pos1 == pos2)
    return;

  // Swap the two blocks.
  for (size_t i = 0; i < len; ++i)
  {
    std::swap(buf[pos1 + i], buf[pos2 + i]);
  }
}

void MutationEngine::null_run(std::vector<uint8_t>& buf)
{
  // Guarded here as well as in apply(): buf.size() - len underflows on an empty buffer and the
  // memset below would then write outside it. Every other mutation checks its own precondition.
  if (buf.empty())
    return;

  auto maxLen = std::min(buf.size(), size_t{32});
  auto len = std::uniform_int_distribution<size_t>(1, std::max(maxLen, size_t{1}))(mRng);
  auto start = std::uniform_int_distribution<size_t>(0, buf.size() - len)(mRng);

  std::memset(&buf[start], 0x00, len);
}

void MutationEngine::high_byte_run(std::vector<uint8_t>& buf)
{
  if (buf.empty())
    return;

  auto maxLen = std::min(buf.size(), size_t{32});
  auto len = std::uniform_int_distribution<size_t>(1, std::max(maxLen, size_t{1}))(mRng);
  auto start = std::uniform_int_distribution<size_t>(0, buf.size() - len)(mRng);

  std::memset(&buf[start], 0xFF, len);
}

void MutationEngine::format_string_inject(std::vector<uint8_t>& buf)
{
  static constexpr const char* fmtStrings[] = {"%s%n%x%p", "%d%d%d%d", "AAAA%08x", "%n%n%n%n"};
  auto fmtIdx = std::uniform_int_distribution<size_t>(0, std::size(fmtStrings) - 1)(mRng);
  auto fmt = fmtStrings[fmtIdx];
  auto fmtLen = std::strlen(fmt);

  if (buf.size() < fmtLen)
    return;

  auto pos = std::uniform_int_distribution<size_t>(0, buf.size() - fmtLen)(mRng);
  std::memcpy(&buf[pos], fmt, fmtLen);
}

void MutationEngine::encoding_prefix_swap(std::vector<uint8_t>& buf)
{
  if (buf.empty())
    return;

  // Change a random byte to a different NodeId/Variant encoding type prefix.
  static constexpr uint8_t prefixes[] = {0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0A,
    0x0B,
    0x0C,
    0x0D,
    0x0E,
    0x0F,
    0x10,
    0x11,
    0x12,
    0x13,
    0x14,
    0x15,
    0x16,
    0x17,
    0x18,
    0x19};
  auto pos = std::uniform_int_distribution<size_t>(0, buf.size() - 1)(mRng);
  buf[pos] = prefixes[std::uniform_int_distribution<size_t>(0, std::size(prefixes) - 1)(mRng)];
}

}  // namespace fuzz
