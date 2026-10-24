// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Generator of uniformly distributed random integers over a fixed range.
/// @ingroup general

#ifndef UA_RANDOM_H
#define UA_RANDOM_H

#include <random>
#include "ua_includes.h"

namespace ua
{
/// A uniform random integer generator over a closed range.
///
/// Each instance owns its own seeded engine and distribution; draws are produced by
/// invoking the call operator. The generator is seeded from `std::random_device` on
/// construction but the engine is a Mersenne Twister: it is NOT cryptographically secure
/// and must never produce a nonce, a token, a key, a session id or anything else that
/// gates access. It is for request handles, jitter and identifiers that only need to be
/// unlikely to collide. Security-relevant randomness comes from `Crypto::get_entropy_async`
/// (OpenSSL's CSPRNG).
///
/// Not thread-safe: a single instance must not be invoked concurrently from multiple
/// threads. Use a separate instance per thread, or serialise access externally.
///
/// @tparam T Integer type produced by the generator; must be a type supported by
///           `std::uniform_int_distribution`.
/// @ingroup general
template<typename T>
class Random
{
public:
  /// Constructs a generator spanning the full non-negative range of `T`.
  ///
  /// The range is `[0, std::numeric_limits<T>::max()]`, inclusive at both ends.
  Random();

  /// Constructs a generator spanning the closed range `[min, max]`.
  ///
  /// @param[in] min Smallest value the generator may produce, inclusive.
  /// @param[in] max Largest value the generator may produce, inclusive.
  /// @pre `min <= max`.
  Random(T min, T max);

  /// Draws the next uniformly distributed value from the configured range.
  ///
  /// @return A value in the closed range fixed at construction.
  T operator()();

private:
  std::random_device mDevice;
  std::default_random_engine mGenerator;
  std::uniform_int_distribution<T> mDistribution;
};

template<typename T>
Random<T>::Random() : mGenerator{mDevice()}, mDistribution{0, std::numeric_limits<T>::max()}
{}

template<typename T>
Random<T>::Random(T min, T max) : mGenerator{mDevice()}, mDistribution{min, max}
{}

template<typename T>
T Random<T>::operator()()
{
  return mDistribution(mGenerator);
}

}  // namespace ua

#endif  // UA_RANDOM_H
