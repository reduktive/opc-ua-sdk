// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Structured DataTypes whose *field semantics* the specification fixes, rather than only their shape.
//
// `CurrencyUnitType` and `PortableNodeId` are public classes an application constructs and the SDK
// encodes: `ua::CurrencyUnitType` with `numeric_code()` / `exponent()`, `ua::PortableNodeId` with
// `namespace_uri()` / `identifier()`, both with codecs the product registers and ships. Their
// generated round-trip tests prove the wire format; nothing proves the sentence in the table beside
// it - that an unknown currency code is -1 rather than 0, that the code renders three characters
// wide, that a PortableNodeId puts namespaceIndex 0 on the wire.
//
// These obligations were ruled `capability-absent` on 2026-08-11 and the ruling was overturned the
// same day (`qa_remediation_plan.md` section 2.50). The probe behind it was
// `grep -rn CurrencyUnit sdk/ | grep -v /generated/`, which returns nothing - and the filter removed
// exactly the public API that carries the subject. For a DataType the generated tree IS the shipped
// surface, so these tests live here, where a marker survives regeneration, and drive it directly.

#include <gtest/gtest.h>

#include "ua_currency_unit_type.h"
#include "ua_node_id.h"
#include "ua_portable_node_id.h"
#include "ua_string.h"
#include "ua_to_string.h"

#include <string>

namespace
{

// Part 3 Table 44 (CurrencyUnitType), NumericCode: "Three-digit code numeric code assigned to each
// currency in ISO 4217. **If unknown or not available this shall be -1.**"
//
// The value the SDK hands an application when it has not said otherwise is the value that ships in
// every DataItem whose currency the host could not resolve, so the default is the observable. 0 is
// not a null here: ISO 4217 codes are positive, so a consumer reading 0 has no way to tell "unknown"
// from a code, and `AC-SVR-ADDRSP-241`'s renderer turns it into the plausible-looking "000".
// @verifies AC-SVR-ADDRSP-240-CURRENCY-NUMERICCODE-UNKNOWN
TEST(CurrencyUnitTypeSentinels, AnUnsetNumericCodeIsTheUnknownSentinelRatherThanZero)
{
  const ua::CurrencyUnitType unresolved;
  EXPECT_EQ(unresolved.numeric_code(), -1)
    << "a CurrencyUnitType built without a resolved ISO 4217 code carries NumericCode "
    << unresolved.numeric_code()
    << ". Part 3 Table 44 reserves -1 for 'unknown or not available', and 0 is indistinguishable from "
       "a code to every consumer of the structure";
}

// Part 3 Table 44 (CurrencyUnitType), Exponent: "Number of digits after the decimal separator. **If
// unknown or not available this shall be -1.**"
//
// Sharper than the NumericCode case, because 0 is a MEANINGFUL exponent: JPY has one, and Table 44
// lists it. So a default of 0 does not merely fail to say "unknown", it asserts "this currency has no
// minor unit" - a claim about the money that a consumer will scale amounts by.
// @verifies AC-SVR-ADDRSP-243-CURRENCY-EXPONENT-UNKNOWN
TEST(CurrencyUnitTypeSentinels, AnUnsetExponentIsTheUnknownSentinelRatherThanZero)
{
  const ua::CurrencyUnitType unresolved;
  EXPECT_EQ(unresolved.exponent(), -1)
    << "a CurrencyUnitType built without a resolved subdivision carries Exponent "
    << static_cast<int>(unresolved.exponent())
    << ". Part 3 Table 44 reserves -1 for 'unknown or not available', and 0 is not a null here - it is "
       "the exponent of a currency with no minor unit, so the default asserts something false about "
       "the money rather than declining to assert";
}

// Part 3 Table 44 (CurrencyUnitType), NumericCode: "**Converting the number to a string shall always
// produce a 3 character string with leading zeros when necessary** (e.g. the number 36 shall be
// presented as 036)."
//
// The spec gives its own worked example and the SDK ships the converter the sentence binds:
// `CurrencyUnitType::to_string` renders the field through `ua::to_string(int16_t)`, which is
// `fmt::format("{}", value)`. AUD is 036 in ISO 4217 and a lookup against the standard table on "36"
// misses, so this is not cosmetic - it is the difference between a currency a consumer can name and
// one it cannot.
// @verifies AC-SVR-ADDRSP-241-CURRENCY-THREE-CHAR
TEST(CurrencyUnitTypeSentinels, ATwoDigitNumericCodeRendersThreeCharactersWide)
{
  ua::CurrencyUnitType australianDollar;
  australianDollar.numeric_code() = 36;
  australianDollar.exponent() = 2;
  australianDollar.alphabetic_code() = ua::String{"AUD"};

  const std::string rendered = australianDollar.to_string();
  EXPECT_NE(rendered.find("036"), std::string::npos)
    << "AUD's NumericCode 36 rendered as: " << rendered
    << ". Part 3 Table 44 requires three characters with leading zeros and gives 036 as its own "
       "example; an unpadded 36 does not match the ISO 4217 table a consumer looks it up in";
}

// Part 5 section 12.38 Table 283 (PortableNodeId), identifier: "The identifier portion of the NodeId. **The
// namespaceIndex parameter shall be 0 and is ignored in the Server.**"
//
// The type exists so a NodeId can travel outside the Server that defined it: the namespace travels as
// a URI and the index is local, meaningless elsewhere, and therefore fixed at 0. A PortableNodeId
// built from a NodeId in namespace 3 that keeps the 3 is a NodeId that has not been made portable -
// the receiver resolves through the URI, and the surviving index is at best noise and at worst the
// thing a careless peer resolves by.
//
// Constructed the way an application would, from a NodeId it already holds, because that is the path
// on which the index has to be dropped.
// @verifies AC-SVR-BASE-103-PORTABLE-NSINDEX
TEST(PortableNodeIdSentinels, TheIdentifierCarriesNamespaceIndexZeroWhateverTheSourceNodeIdCarried)
{
  ua::PortableNodeId portable;
  portable.namespace_uri() = ua::String{"urn:example:vendor-namespace"};
  portable.identifier() = ua::NodeId{uint16_t{3}, uint32_t{5001}};

  EXPECT_EQ(portable.identifier().namespace_index(), 0U)
    << "the identifier kept namespaceIndex " << portable.identifier().namespace_index()
    << ". Part 5 Table 283 says the parameter shall be 0, and the namespaceUri "
    << std::string{static_cast<std::string_view>(portable.namespace_uri())}
    << " is what a receiver resolves through - a surviving local index is the value this type exists "
       "to remove";
}

}  // namespace
