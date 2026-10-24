// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_decimal.h"

namespace ua
{

const int16_t& Decimal::scale() const
{
  return mScale;
}

int16_t& Decimal::scale()
{
  return mScale;
}

const ByteString& Decimal::value() const
{
  return mValue;
}

ByteString& Decimal::value()
{
  return mValue;
}

void Decimal::clear()
{
  mScale = 0;
  mValue.clear();
}

BuiltInTypeId Decimal::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::ExtensionObject};
}

}  // namespace ua
