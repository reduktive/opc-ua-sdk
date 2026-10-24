// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_CODEC_H
#define UA_CODEC_H

#include <variant>
#include "ua_includes.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_resource_budgets.h"

namespace ua
{

class UaBinaryEncoder;
class XmlEncoder;
class ArrayBase;

class Encoder
{
public:
  template<typename T>
  explicit Encoder(T& encoder) : mEncoder(&encoder)
  {}

  Encoder(const Encoder& other) = delete;
  Encoder(Encoder&& other) noexcept = delete;
  Encoder& operator=(const Encoder& other) = delete;
  Encoder& operator=(Encoder&& other) noexcept = delete;
  ~Encoder() = default;

  UaBinaryEncoder* get_ua_binary()
  {
    auto value = std::get_if<UaBinaryEncoder*>(&mEncoder);
    if (value)
    {
      return *value;
    }
    return nullptr;
  }

  XmlEncoder* get_xml()
  {
    auto value = std::get_if<XmlEncoder*>(&mEncoder);
    if (value)
    {
      return *value;
    }
    return nullptr;
  }

private:
  std::variant<UaBinaryEncoder*, XmlEncoder*> mEncoder;
};

class UaBinaryDecoder;
class XmlDecoder;

class Decoder
{
public:
  template<typename T>
  explicit Decoder(T& decoder) : mDecoder(&decoder)
  {}

  Decoder(const Decoder& other) = delete;
  Decoder(Decoder&& other) noexcept = delete;
  Decoder& operator=(const Decoder& other) = delete;
  Decoder& operator=(Decoder&& other) noexcept = delete;
  ~Decoder() = default;

  UaBinaryDecoder* get_ua_binary()
  {
    UaBinaryDecoder* result{nullptr};
    auto value = std::get_if<UaBinaryDecoder*>(&mDecoder);
    if (value)
    {
      result = *value;
    }
    return result;
  }

  XmlDecoder* get_xml()
  {
    XmlDecoder* result{nullptr};
    auto value = std::get_if<XmlDecoder*>(&mDecoder);
    if (value)
    {
      result = *value;
    }
    return result;
  }

private:
  std::variant<UaBinaryDecoder*, XmlDecoder*> mDecoder;
};

}  // namespace ua

#endif  //! UA_CODEC_H
