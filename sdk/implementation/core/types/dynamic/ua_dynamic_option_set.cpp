// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_dynamic_option_set.h"
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_exceptions.h"
#include "ua_error_detail.h"

namespace ua
{

DynamicOptionSet::DynamicOptionSet(shared_ptr<const DynamicEnumTypeDescriptor> descriptor)
  : mDescriptor(std::move(descriptor))
{}

bool DynamicOptionSet::operator==(const DynamicOptionSet& other) const
{
  return mDescriptor.get() == other.mDescriptor.get() && OptionSet::operator==(other);
}

bool DynamicOptionSet::is_of_type(const CodecNamespaceContext& ns, const NodeId& dataTypeId) const
{
  const NodeId myTypeId{ns.getNamespaceIndex(mDescriptor->type_id().namespace_uri()),
    mDescriptor->type_id().node_id().identifier().get_numeric()};
  if (dataTypeId == myTypeId)
  {
    return true;
  }
  return OptionSet::is_of_type(ns, dataTypeId);
}

NodeId DynamicOptionSet::type_id(const CodecNamespaceContext& ns) const
{
  const auto& expandedId = mDescriptor->type_id();
  if (ns.getNamespaceIndex)
  {
    return NodeId{
      ns.getNamespaceIndex(expandedId.namespace_uri()), expandedId.node_id().identifier().get_numeric()};
  }
  return expandedId.node_id();
}

ExpandedNodeId DynamicOptionSet::type_id() const
{
  return mDescriptor->type_id();
}

String DynamicOptionSet::type_name() const
{
  return mDescriptor->type_name();
}

void DynamicOptionSet::encode_id(StackDepth limit, const CodecNamespaceContext& ns, Encoder& encoder) const
{
  // DynamicOptionSet does not have its own encoding NodeId separate from OptionSet.
  // Encoding is handled by the base OptionSet encode.
  UA_UNUSED(limit);
  UA_UNUSED(ns);
  UA_UNUSED(encoder);
}

unique_ptr<Structure> DynamicOptionSet::clone() const
{
  return make_unique<DynamicOptionSet>(*this);
}

std::string DynamicOptionSet::to_string(int indent) const
{
  std::string result;
  const string_view descriptorTypeName = mDescriptor->type_name();
  result += descriptorTypeName;
  result += '{';

  const auto& fields = mDescriptor->definition().fields();
  bool first = true;
  for (size_t i = 0; i < fields.size(); ++i)
  {
    const int64_t bitNumber = fields[i].value();
    if (bitNumber >= 0 && get_bit(value(), bitNumber))
    {
      if (!first)
      {
        result += ", ";
      }
      result += string_view(fields[i].name());
      first = false;
    }
  }

  result += '}';

  if (indent > 0)
  {
    result += '\n';
  }

  return result;
}

bool DynamicOptionSet::is_set(string_view bitName) const
{
  const int64_t bitNumber = require_bit_number(bitName);
  return get_bit(value(), bitNumber);
}

void DynamicOptionSet::set_bit(string_view bitName, bool bitValue)
{
  const int64_t bitNumber = require_bit_number(bitName);
  set_bit_in(value(), bitNumber, bitValue);
}

bool DynamicOptionSet::is_valid(string_view bitName) const
{
  const int64_t bitNumber = require_bit_number(bitName);
  return get_bit(valid_bits(), bitNumber);
}

void DynamicOptionSet::set_valid(string_view bitName, bool valid)
{
  const int64_t bitNumber = require_bit_number(bitName);
  set_bit_in(valid_bits(), bitNumber, valid);
}

const DynamicEnumTypeDescriptor& DynamicOptionSet::descriptor() const
{
  return *mDescriptor;
}

int64_t DynamicOptionSet::require_bit_number(string_view bitName) const
{
  auto val = mDescriptor->value_for_name(bitName);
  if (!val.has_value())
  {
    throw UaException(Status::BadInvalidArgument,
      ErrorDetail::build("UnknownBitName", "Bit name not found in option set type", "DynamicOptionSet")
        .context(ua::ContextKeys::bitName, std::string(bitName)));
  }
  if (*val < 0)
  {
    throw UaException(Status::BadOutOfRange,
      ErrorDetail::build(
        "BitNumberOutOfRange", "Bit number for option-set bit name is negative", "DynamicOptionSet")
        .context(ua::ContextKeys::bitIndex, std::to_string(*val))
        .context(ua::ContextKeys::bitName, std::string(bitName)));
  }
  return *val;
}

bool DynamicOptionSet::get_bit(const ByteString& bytes, int64_t bitNumber)
{
  auto byteIndex = numeric_cast<size_t>(bitNumber / 8);
  auto bitIndex = numeric_cast<int>(bitNumber % 8);
  if (byteIndex >= bytes.size())
  {
    return false;
  }
  return (static_cast<uint8_t>(bytes[byteIndex]) & (1u << bitIndex)) != 0;
}

void DynamicOptionSet::set_bit_in(ByteString& bytes, int64_t bitNumber, bool bitValue)
{
  auto byteIndex = numeric_cast<size_t>(bitNumber / 8);
  auto bitIndex = numeric_cast<int>(bitNumber % 8);

  // Extend the ByteString if needed
  if (byteIndex >= bytes.size())
  {
    bytes.resize(byteIndex + 1);
  }

  if (bitValue)
  {
    bytes[byteIndex] = static_cast<uint8_t>(bytes[byteIndex] | (1u << bitIndex));
  }
  else
  {
    bytes[byteIndex] = static_cast<uint8_t>(bytes[byteIndex] & ~(1u << bitIndex));
  }
}

}  // namespace ua
