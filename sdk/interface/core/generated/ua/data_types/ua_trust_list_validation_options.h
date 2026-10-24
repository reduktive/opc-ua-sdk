// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_TRUST_LIST_VALIDATION_OPTIONS_H
#define UA_DATA_TYPE_TRUST_LIST_VALIDATION_OPTIONS_H

#include <bitset>
#include <string>
#include "ua_utilities.h"

namespace ua
{

/// OPC UA TrustListValidationOptions option-set (bit mask) data type.
/// @ingroup ua_data_types
class TrustListValidationOptions
{
public:
  /// The raw integer type backing this option set.
  using UnderlyingType = uint32_t;
  /// The fixed-width `std::bitset` representation of this option set.
  using BitSet = std::bitset<utils::no_of_bits<UnderlyingType>()>;

  /// The defined bit positions of this option set.
  enum class Bit : UnderlyingType
  {
    SuppressCertificateExpired = 0,  ///< Ignore errors related to the validity time of the Certificate.
    SuppressHostNameInvalid = 1,  ///< Ignore mismatches between the host name or ApplicationUri.
    SuppressRevocationStatusUnknown =
      2,  ///< Ignore errors if the revocation list cannot be found for the issuer of the Certificate.
    SuppressIssuerCertificateExpired = 3,  ///< Ignore errors if an issuer has an expired Certificate.
    SuppressIssuerRevocationStatusUnknown =
      4,  ///< Ignore errors if the revocation list cannot be found for any issuer of issuer Certificates.
    CheckRevocationStatusOnline = 5,  ///< Check the revocation status online.
    CheckRevocationStatusOffline = 6,  ///< Check the revocation status offline.
  };

  /// Constructs an empty `TrustListValidationOptions` with no bits set.
  TrustListValidationOptions() = default;

  /// Equality compares the underlying bit value.
  /// @param obj The value to compare against.
  /// @return `true` if the underlying bit values are equal.
  bool operator==(const TrustListValidationOptions& obj) const = default;

  /// Constructs from a raw underlying value.
  /// @param value The raw underlying integer whose bits seed the option set.
  explicit TrustListValidationOptions(UnderlyingType value) : mValue(value)
  {}

  /// Constructs with a set of bits initially set.
  /// @param bits The bits to set; all others are clear.
  explicit TrustListValidationOptions(std::initializer_list<Bit> bits)
  {
    for (auto bit : bits)
    {
      mValue.set(utils::to_underlying(bit));
    }
  }

  /// Sets a bit.
  /// @param bit The bit to set.
  void set(Bit bit)
  {
    mValue.set(utils::to_underlying(bit));
  }

  /// Clears a bit.
  /// @param bit The bit to clear.
  void reset(Bit bit)
  {
    mValue.reset(utils::to_underlying(bit));
  }

  /// Tests whether a bit is set.
  /// @param bit The bit to test.
  /// @return `true` if `bit` is set.
  bool test(Bit bit) const
  {
    return mValue.test(utils::to_underlying(bit));
  }

  /// @return The value as its raw underlying integer.
  UnderlyingType as_underlying_type() const
  {
    return numeric_cast<UnderlyingType>(mValue.to_ullong());
  }

  /// Replaces all bits from a raw underlying value.
  /// @param value The raw underlying integer whose bits replace the current set.
  void from_underlying_type(UnderlyingType value)
  {
    BitSet temp{value};
    mValue = temp;
  }

  /// @return The underlying bitset.
  BitSet value()
  {
    return mValue;
  }

  /// @return The underlying bitset.
  BitSet value() const
  {
    return mValue;
  }

private:
  BitSet mValue;
};

/// Formats an option set as a brace-listed string of its set bits.
/// @param value The option set to format.
/// @return A brace-listed string of the names of the set bits.
std::string to_string(const TrustListValidationOptions& value);

}  // namespace ua

#endif  // !UA_DATA_TYPE_TRUST_LIST_VALIDATION_OPTIONS_H
