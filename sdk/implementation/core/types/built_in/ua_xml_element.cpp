// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_xml_element.h"

namespace ua
{

XmlElement& XmlElement::operator=(std::string other)
{
  mValue = other;
  return *this;
}

XmlElement& XmlElement::operator=(string_view other)
{
  mValue = other;
  return *this;
}

bool XmlElement::empty() const
{
  return mValue.empty();
}

void XmlElement::clear()
{
  mValue.clear();
}

BuiltInTypeId XmlElement::built_in_type_id()
{
  return BuiltInTypeId{BuiltInTypeId::XmlElement};
}

const std::string& XmlElement::value() const
{
  return mValue;
}

std::string& XmlElement::value()
{
  return mValue;
}

}  // namespace ua
