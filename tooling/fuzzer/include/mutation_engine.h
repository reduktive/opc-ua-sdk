// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_MUTATION_ENGINE_H
#define FUZZ_MUTATION_ENGINE_H

#include "fuzz_types.h"

#include <cstdint>
#include <random>
#include <vector>

namespace fuzz
{

class MutationEngine
{
public:
  explicit MutationEngine(uint64_t seed = 0);

  /// Apply a random mutation strategy to the buffer. Returns the strategy used.
  MutationStrategy mutate(std::vector<uint8_t>& buffer);

  /// Apply a specific mutation strategy.
  void apply(MutationStrategy strategy, std::vector<uint8_t>& buffer);

  /// Get the underlying RNG for external use.
  std::mt19937_64& rng()
  {
    return mRng;
  }

private:
  void bit_flip(std::vector<uint8_t>& buf);
  void byte_flip(std::vector<uint8_t>& buf);
  void boundary_corrupt(std::vector<uint8_t>& buf);
  void length_tamper(std::vector<uint8_t>& buf);
  void edge_integer_inject(std::vector<uint8_t>& buf);
  void edge_int16_inject(std::vector<uint8_t>& buf);
  void block_delete(std::vector<uint8_t>& buf);
  void block_duplicate(std::vector<uint8_t>& buf);
  void block_shuffle(std::vector<uint8_t>& buf);
  void null_run(std::vector<uint8_t>& buf);
  void high_byte_run(std::vector<uint8_t>& buf);
  void format_string_inject(std::vector<uint8_t>& buf);
  void encoding_prefix_swap(std::vector<uint8_t>& buf);

  std::mt19937_64 mRng;
};

}  // namespace fuzz

#endif  // !FUZZ_MUTATION_ENGINE_H
