// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_binary_data_value_codec.h"

#include "ua_binary_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_data_value.h"
#include "ua_encoding_limits.h"
#include "ua_memory_stream.h"
#include "ua_to_result.h"

namespace ua
{

class UaBinaryDataValueCodecImpl
{
public:
  UaBinaryDataValueCodecImpl(StructureResolver structureResolver, CodecNamespaceContext namespaceConfig,
    const EncodingLimits& encodingLimits)
    : mStructureResolver(std::move(structureResolver)), mNamespaceConfig(std::move(namespaceConfig)),
      mEncodingLimits(encodingLimits)
  {}

  ByteString encode(const DataValue& value) const
  {
    memory_stream_device::Dynamic device;
    MemoryStream stream{device};
    UaBinaryEncoder encoder{mNamespaceConfig, stream};
    encoder.encode(mEncodingLimits.stack_depth(), value);

    auto bytes = device.move_storage_out();
    return ByteString{std::move(bytes)};
  }

  DataValueResult decode(std::span<const byte> data) const
  {
    try
    {
      memory_stream_device::ExternalReadOnly device{data};
      MemoryStream stream{device};
      UaBinaryDecoder decoder{mStructureResolver, stream, mEncodingLimits, mNamespaceConfig};

      DataValue result;
      decoder.decode(mEncodingLimits.stack_depth(), result);
      return result;
    }
    catch (...)
    {
      return DataValueResult{ua::exception_to_status_code(std::current_exception())};
    }
  }

private:
  StructureResolver mStructureResolver;
  CodecNamespaceContext mNamespaceConfig;
  EncodingLimits mEncodingLimits;
};

UaBinaryDataValueCodec::UaBinaryDataValueCodec(std::unique_ptr<UaBinaryDataValueCodecImpl> impl)
  : mImpl(std::move(impl))
{}

std::unique_ptr<UaBinaryDataValueCodec> UaBinaryDataValueCodec::create(
  StructureResolver structureResolver, CodecNamespaceContext namespaceConfig, EncodingLimits encodingLimits)
{
  auto impl = std::make_unique<UaBinaryDataValueCodecImpl>(
    std::move(structureResolver), std::move(namespaceConfig), encodingLimits);
  return std::unique_ptr<UaBinaryDataValueCodec>(new UaBinaryDataValueCodec(std::move(impl)));
}

UaBinaryDataValueCodec::~UaBinaryDataValueCodec() = default;

UaBinaryDataValueCodec::UaBinaryDataValueCodec(UaBinaryDataValueCodec&&) noexcept = default;
UaBinaryDataValueCodec& UaBinaryDataValueCodec::operator=(UaBinaryDataValueCodec&&) noexcept = default;

ByteString UaBinaryDataValueCodec::encode(const DataValue& value) const
{
  return mImpl->encode(value);
}

DataValueResult UaBinaryDataValueCodec::decode(std::span<const byte> data) const
{
  return mImpl->decode(data);
}

}  // namespace ua
