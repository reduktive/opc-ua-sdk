// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_DATA_TYPE_PASSWORD_OPTIONS_MASK_H
#define UA_DATA_TYPE_PASSWORD_OPTIONS_MASK_H

#include <bitset>
#include <string>
#include "ua_utilities.h"

namespace ua
{

/// OPC UA PasswordOptionsMask option-set (bit mask) data type.
/// @ingroup ua_data_types
class PasswordOptionsMask
{
public:
  /// The raw integer type backing this option set.
  using UnderlyingType = uint32_t;
  /// The fixed-width `std::bitset` representation of this option set.
  using BitSet = std::bitset<utils::no_of_bits<UnderlyingType>()>;

  /// The defined bit positions of this option set.
  enum class Bit : UnderlyingType
  {
    SupportInitialPasswordChange = 0,  ///< Indicates if the server supports the feature to require a password
                                       ///< change after the creation of the user.
    SupportDisableUser = 1,  ///< Indicates if the server supports to disable a user.
    SupportDisableDeleteForUser =
      2,  ///< Indicates if the server supports the configuration NoDelete for a user.
    SupportNoChangeForUser =
      3,  ///< Indicates if the server supports the configuration NoChangeByUser for a user.
    SupportDescriptionForUser =
      4,  ///< Indicates if the server supports to management of a description for the user.
    RequiresUpperCaseCharacters =
      5,  ///< Indicates if a upper case ASCII character is required in a password.
    RequiresLowerCaseCharacters =
      6,  ///< Indicates if a lower case ASCII character is required in a password.
    RequiresDigitCharacters = 7,  ///< Indicates if a digit ASCII character is required in a password.
    RequiresSpecialCharacters = 8,  ///< Indicates if a special character is required in a password.
  };

  /// Constructs an empty `PasswordOptionsMask` with no bits set.
  PasswordOptionsMask() = default;

  /// Equality compares the underlying bit value.
  /// @param obj The value to compare against.
  /// @return `true` if the underlying bit values are equal.
  bool operator==(const PasswordOptionsMask& obj) const = default;

  /// Constructs from a raw underlying value.
  /// @param value The raw underlying integer whose bits seed the option set.
  explicit PasswordOptionsMask(UnderlyingType value) : mValue(value)
  {}

  /// Constructs with a set of bits initially set.
  /// @param bits The bits to set; all others are clear.
  explicit PasswordOptionsMask(std::initializer_list<Bit> bits)
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
std::string to_string(const PasswordOptionsMask& value);

}  // namespace ua

#endif  // !UA_DATA_TYPE_PASSWORD_OPTIONS_MASK_H
