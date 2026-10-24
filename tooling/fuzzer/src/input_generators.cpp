// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "input_generators.h"

#include "ua_browse_direction.h"
#include "ua_data_value.h"
#include "ua_guid.h"
#include "ua_node_class.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_status_code.h"

namespace fuzz
{

// --- NodeIdGenerator ---

NodeIdGenerator::NodeIdGenerator(std::mt19937_64& rng) : mRng(rng)
{}

ua::NodeId NodeIdGenerator::generate()
{
  auto kind = std::uniform_int_distribution<int>(0, 5)(mRng);

  switch (kind)
  {
  case 0:
    // Null NodeId
    return ua::NodeId{};

  case 1:
  {
    // Numeric with random namespace and identifier
    auto ns = static_cast<uint16_t>(std::uniform_int_distribution<int>(0, 0xFFFF)(mRng));
    auto id = std::uniform_int_distribution<uint32_t>(0, 0xFFFFFFFF)(mRng);
    return ua::NodeId{ns, id};
  }

  case 2:
  {
    // Numeric with ns=0 and edge identifiers
    static constexpr uint32_t edges[] = {0, 1, 2, 84, 85, 255, 256, 2253, 0x7FFFFFFF, 0xFFFFFFFF};
    auto id = edges[std::uniform_int_distribution<size_t>(0, std::size(edges) - 1)(mRng)];
    return ua::NodeId{id};
  }

  case 3:
  {
    // String NodeId
    auto ns = static_cast<uint16_t>(std::uniform_int_distribution<int>(0, 5)(mRng));
    auto len = std::uniform_int_distribution<int>(0, 128)(mRng);
    std::string s(static_cast<size_t>(len), 'A');
    for (auto& c : s)
    {
      c = static_cast<char>(std::uniform_int_distribution<int>(0, 255)(mRng));
    }
    return ua::NodeId{ns, std::string_view{s}};
  }

  case 4:
  {
    // GUID NodeId
    auto ns = static_cast<uint16_t>(std::uniform_int_distribution<int>(0, 5)(mRng));
    auto guid = ua::Guid::create_and_generate();
    return ua::NodeId{ns, guid};
  }

  default:
  {
    // Opaque (ByteString) NodeId
    auto ns = static_cast<uint16_t>(std::uniform_int_distribution<int>(0, 5)(mRng));
    auto len = std::uniform_int_distribution<int>(0, 64)(mRng);
    ua::ByteString bs(static_cast<size_t>(len), uint8_t{0});
    for (auto& b : bs)
    {
      b = static_cast<uint8_t>(std::uniform_int_distribution<int>(0, 255)(mRng));
    }
    return ua::NodeId{ns, bs};
  }
  }
}

// --- VariantGenerator ---

VariantGenerator::VariantGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits)
  : mRng(rng), mLimits(limits)
{}

ua::Variant VariantGenerator::generate()
{
  // 0 = empty, 1-11 = scalars, 12-18 = arrays
  auto kind = std::uniform_int_distribution<int>(0, 18)(mRng);

  switch (kind)
  {
  case 0:
    return ua::Variant();  // empty

  case 1:
  {
    bool val = std::uniform_int_distribution<int>(0, 1)(mRng) != 0;
    return ua::Variant(val);
  }

  case 2:
  {
    auto val = static_cast<int8_t>(std::uniform_int_distribution<int>(-128, 127)(mRng));
    return ua::Variant(val);
  }

  case 3:
  {
    auto val = static_cast<uint8_t>(std::uniform_int_distribution<int>(0, 255)(mRng));
    return ua::Variant(val);
  }

  case 4:
  {
    auto val = static_cast<int16_t>(std::uniform_int_distribution<int>(-32768, 32767)(mRng));
    return ua::Variant(val);
  }

  case 5:
  {
    auto val = static_cast<uint16_t>(std::uniform_int_distribution<int>(0, 65535)(mRng));
    return ua::Variant(val);
  }

  case 6:
  {
    int32_t val = std::uniform_int_distribution<int32_t>()(mRng);
    return ua::Variant(val);
  }

  case 7:
  {
    uint32_t val = std::uniform_int_distribution<uint32_t>()(mRng);
    return ua::Variant(val);
  }

  case 8:
  {
    int64_t val = std::uniform_int_distribution<int64_t>()(mRng);
    return ua::Variant(val);
  }

  case 9:
  {
    float val = std::uniform_real_distribution<float>()(mRng);
    return ua::Variant(val);
  }

  case 10:
  {
    double val = std::uniform_real_distribution<double>()(mRng);
    return ua::Variant(val);
  }

  case 11:
  {
    // String scalar
    auto len =
      std::uniform_int_distribution<uint32_t>(0, std::min(mLimits.maxStringLen, uint32_t{256}))(mRng);
    std::string s(len, 'X');
    for (auto& c : s)
    {
      c = static_cast<char>(std::uniform_int_distribution<int>(0, 255)(mRng));
    }
    ua::String str(s);
    return ua::Variant(std::move(str));
  }

    // --- Array variants ---

  case 12:
  {
    // Array<int32_t>
    auto len = std::uniform_int_distribution<uint32_t>(0, std::min(mLimits.maxArrayLen, uint32_t{64}))(mRng);
    ua::Array<int32_t> arr;
    for (uint32_t i = 0; i < len; ++i)
    {
      arr.push_back(std::uniform_int_distribution<int32_t>()(mRng));
    }
    return ua::Variant(std::move(arr));
  }

  case 13:
  {
    // Array<uint32_t>
    auto len = std::uniform_int_distribution<uint32_t>(0, std::min(mLimits.maxArrayLen, uint32_t{64}))(mRng);
    ua::Array<uint32_t> arr;
    for (uint32_t i = 0; i < len; ++i)
    {
      arr.push_back(std::uniform_int_distribution<uint32_t>()(mRng));
    }
    return ua::Variant(std::move(arr));
  }

  case 14:
  {
    // Array<double>
    auto len = std::uniform_int_distribution<uint32_t>(0, std::min(mLimits.maxArrayLen, uint32_t{64}))(mRng);
    ua::Array<double> arr;
    for (uint32_t i = 0; i < len; ++i)
    {
      arr.push_back(std::uniform_real_distribution<double>()(mRng));
    }
    return ua::Variant(std::move(arr));
  }

  case 15:
  {
    // Array<bool>
    auto len = std::uniform_int_distribution<uint32_t>(0, std::min(mLimits.maxArrayLen, uint32_t{64}))(mRng);
    ua::Array<bool> arr;
    for (uint32_t i = 0; i < len; ++i)
    {
      arr.push_back(std::uniform_int_distribution<int>(0, 1)(mRng) != 0);
    }
    return ua::Variant(std::move(arr));
  }

  case 16:
  {
    // Array<String>
    auto len = std::uniform_int_distribution<uint32_t>(0, std::min(mLimits.maxArrayLen, uint32_t{16}))(mRng);
    ua::Array<ua::String> arr;
    for (uint32_t i = 0; i < len; ++i)
    {
      auto slen = std::uniform_int_distribution<uint32_t>(0, 64)(mRng);
      std::string s(slen, 'A');
      for (auto& c : s)
      {
        c = static_cast<char>(std::uniform_int_distribution<int>(0, 255)(mRng));
      }
      arr.push_back(ua::String(s));
    }
    return ua::Variant(std::move(arr));
  }

  case 17:
  {
    // Array<ByteString>
    auto len = std::uniform_int_distribution<uint32_t>(0, std::min(mLimits.maxArrayLen, uint32_t{16}))(mRng);
    ua::Array<ua::ByteString> arr;
    for (uint32_t i = 0; i < len; ++i)
    {
      auto blen = std::uniform_int_distribution<uint32_t>(0, 64)(mRng);
      ua::ByteString bs(blen, uint8_t{0});
      for (auto& b : bs)
      {
        b = static_cast<uint8_t>(std::uniform_int_distribution<int>(0, 255)(mRng));
      }
      arr.push_back(std::move(bs));
    }
    return ua::Variant(std::move(arr));
  }

  default:
  {
    // Array<int64_t>
    auto len = std::uniform_int_distribution<uint32_t>(0, std::min(mLimits.maxArrayLen, uint32_t{64}))(mRng);
    ua::Array<int64_t> arr;
    for (uint32_t i = 0; i < len; ++i)
    {
      arr.push_back(std::uniform_int_distribution<int64_t>()(mRng));
    }
    return ua::Variant(std::move(arr));
  }
  }
}

// --- AttributeIdGenerator ---

AttributeIdGenerator::AttributeIdGenerator(std::mt19937_64& rng) : mRng(rng)
{}

ua::AttributeId AttributeIdGenerator::generate()
{
  // Valid attribute IDs are 1-27, but also generate out-of-range values for fuzzing.
  auto kind = std::uniform_int_distribution<int>(0, 4)(mRng);

  if (kind == 0)
  {
    // Out-of-range value
    static constexpr uint32_t outOfRange[] = {0, 28, 100, 0xFFFFFFFF, 0x7FFFFFFF};
    auto val = outOfRange[std::uniform_int_distribution<size_t>(0, std::size(outOfRange) - 1)(mRng)];
    return static_cast<ua::AttributeId>(val);
  }

  // Valid attribute ID
  return static_cast<ua::AttributeId>(std::uniform_int_distribution<uint32_t>(1, 27)(mRng));
}

// --- StringGenerator ---

StringGenerator::StringGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits)
  : mRng(rng), mLimits(limits)
{}

std::string StringGenerator::generate()
{
  auto kind = std::uniform_int_distribution<int>(0, 4)(mRng);

  switch (kind)
  {
  case 0:
    return "";  // empty

  case 1:
  {
    // Random ASCII
    auto len = std::uniform_int_distribution<uint32_t>(1, 128)(mRng);
    std::string s(len, ' ');
    for (auto& c : s)
    {
      c = static_cast<char>(std::uniform_int_distribution<int>(32, 126)(mRng));
    }
    return s;
  }

  case 2:
  {
    // Embedded nulls
    auto len = std::uniform_int_distribution<uint32_t>(1, 64)(mRng);
    std::string s(len, '\0');
    return s;
  }

  case 3:
  {
    // Non-UTF-8 bytes
    auto len = std::uniform_int_distribution<uint32_t>(1, 64)(mRng);
    std::string s(len, ' ');
    for (auto& c : s)
    {
      c = static_cast<char>(std::uniform_int_distribution<int>(128, 255)(mRng));
    }
    return s;
  }

  default:
  {
    // Long string near max
    auto len = std::min(mLimits.maxStringLen, uint32_t{4096});
    return std::string(len, 'A');
  }
  }
}

// --- ReadRequestGenerator ---

ReadRequestGenerator::ReadRequestGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits)
  : mNodeIdGen(rng), mAttrIdGen(rng), mStringGen(rng, limits), mRng(rng)
{}

ua::ReadValueId ReadRequestGenerator::generate_read_value_id()
{
  ua::ReadValueId rv;
  rv.node_id() = mNodeIdGen.generate();
  rv.attribute_id() = static_cast<uint32_t>(mAttrIdGen.generate());

  // Occasionally set an index range.
  if (std::uniform_int_distribution<int>(0, 3)(mRng) == 0)
  {
    rv.index_range() = ua::String{mStringGen.generate()};
  }

  return rv;
}

ua::TimestampsToReturn ReadRequestGenerator::generate_timestamps_to_return()
{
  auto kind = std::uniform_int_distribution<int>(0, 5)(mRng);

  if (kind <= 3)
  {
    return static_cast<ua::TimestampsToReturn>(kind);
  }

  // Out-of-range values
  static constexpr int32_t edges[] = {-1, 4, 5, 100, 0x7FFFFFFF};
  return static_cast<ua::TimestampsToReturn>(
    edges[std::uniform_int_distribution<size_t>(0, std::size(edges) - 1)(mRng)]);
}

uint32_t ReadRequestGenerator::generate_max_age()
{
  static constexpr uint32_t values[] = {0, 1, 100, 1000, 0xFFFFFFFF, 0x7FFFFFFF};
  return values[std::uniform_int_distribution<size_t>(0, std::size(values) - 1)(mRng)];
}

// --- BrowseRequestGenerator ---

BrowseRequestGenerator::BrowseRequestGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& /*limits*/)
  : mNodeIdGen(rng), mRng(rng)
{}

ua::BrowseDescription BrowseRequestGenerator::generate_browse_description()
{
  ua::BrowseDescription bd;
  bd.node_id() = mNodeIdGen.generate();

  // Browse direction
  auto dir = std::uniform_int_distribution<int>(0, 4)(mRng);
  if (dir <= 3)
  {
    bd.browse_direction() = static_cast<ua::BrowseDirection>(dir);
  }
  else
  {
    bd.browse_direction() =
      static_cast<ua::BrowseDirection>(std::uniform_int_distribution<int>(4, 255)(mRng));
  }

  // Reference type
  if (std::uniform_int_distribution<int>(0, 1)(mRng) == 0)
  {
    bd.reference_type_id() = mNodeIdGen.generate();
  }

  bd.include_subtypes() = std::uniform_int_distribution<int>(0, 1)(mRng) != 0;

  // Node class mask: 0 = all, or random bits
  bd.node_class_mask() = std::uniform_int_distribution<uint32_t>(0, 0xFF)(mRng);

  // Result mask
  bd.result_mask() = std::uniform_int_distribution<uint32_t>(0, 63)(mRng);

  return bd;
}

uint32_t BrowseRequestGenerator::generate_requested_max_references_per_node()
{
  static constexpr uint32_t values[] = {0, 1, 10, 100, 1000, 0xFFFFFFFF};
  return values[std::uniform_int_distribution<size_t>(0, std::size(values) - 1)(mRng)];
}

// --- WriteRequestGenerator ---

WriteRequestGenerator::WriteRequestGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits)
  : mNodeIdGen(rng), mAttrIdGen(rng), mVariantGen(rng, limits), mRng(rng)
{}

ua::WriteValue WriteRequestGenerator::generate_write_value()
{
  ua::WriteValue wv;
  wv.node_id() = mNodeIdGen.generate();
  wv.attribute_id() = static_cast<uint32_t>(mAttrIdGen.generate());
  wv.value().value() = mVariantGen.generate();
  return wv;
}

// --- CallRequestGenerator ---

CallRequestGenerator::CallRequestGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits)
  : mNodeIdGen(rng), mVariantGen(rng, limits), mRng(rng)
{}

ua::CallMethodRequest CallRequestGenerator::generate_call_method_request()
{
  ua::CallMethodRequest req;
  req.object_id() = mNodeIdGen.generate();
  req.method_id() = mNodeIdGen.generate();

  auto argCount = std::uniform_int_distribution<int>(0, 5)(mRng);
  for (int i = 0; i < argCount; ++i)
  {
    req.input_arguments().push_back(mVariantGen.generate());
  }

  return req;
}

// --- TranslateBrowsePathsGenerator ---

TranslateBrowsePathsGenerator::TranslateBrowsePathsGenerator(
  std::mt19937_64& rng, const FuzzerConfig::Limits& limits)
  : mNodeIdGen(rng), mStringGen(rng, limits), mRng(rng)
{}

ua::BrowsePath TranslateBrowsePathsGenerator::generate_browse_path()
{
  ua::BrowsePath bp;
  bp.starting_node() = mNodeIdGen.generate();

  auto elementCount = std::uniform_int_distribution<int>(1, 5)(mRng);
  for (int i = 0; i < elementCount; ++i)
  {
    ua::RelativePathElement elem;
    elem.reference_type_id() = mNodeIdGen.generate();
    elem.is_inverse() = std::uniform_int_distribution<int>(0, 1)(mRng) != 0;
    elem.include_subtypes() = std::uniform_int_distribution<int>(0, 1)(mRng) != 0;

    auto ns = static_cast<uint16_t>(std::uniform_int_distribution<int>(0, 5)(mRng));
    elem.target_name() = ua::QualifiedName{ns, mStringGen.generate()};

    bp.relative_path().elements().push_back(std::move(elem));
  }

  return bp;
}

// --- RegisterNodesGenerator ---

RegisterNodesGenerator::RegisterNodesGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& /*limits*/)
  : mNodeIdGen(rng)
{}

ua::NodeId RegisterNodesGenerator::generate_node_to_register()
{
  return mNodeIdGen.generate();
}

// --- SubscriptionParamsGenerator ---

SubscriptionParamsGenerator::SubscriptionParamsGenerator(
  std::mt19937_64& rng, const FuzzerConfig::Limits& limits)
  : mRng(rng), mLimits(limits)
{}

ua::CreateSubscriptionRequest SubscriptionParamsGenerator::generate_create_subscription_request()
{
  static constexpr double publishingIntervals[] = {0.0, 1.0, 50.0, 100.0, 500.0, 1000.0, 4294967295.0};
  static constexpr uint32_t lifetimeCounts[] = {0, 1, 3, 10, 600, 0xFFFFFFFF};
  static constexpr uint32_t keepAliveCounts[] = {0, 1, 3, 5, 100};
  static constexpr uint32_t maxNotifications[] = {0, 1, 10, 100, 0xFFFFFFFF};
  static constexpr uint8_t priorities[] = {0, 1, 128, 255};

  ua::CreateSubscriptionRequest req;
  req.requested_publishing_interval() =
    publishingIntervals[std::uniform_int_distribution<size_t>(0, std::size(publishingIntervals) - 1)(mRng)];
  req.requested_lifetime_count() =
    lifetimeCounts[std::uniform_int_distribution<size_t>(0, std::size(lifetimeCounts) - 1)(mRng)];
  req.requested_max_keep_alive_count() =
    keepAliveCounts[std::uniform_int_distribution<size_t>(0, std::size(keepAliveCounts) - 1)(mRng)];
  req.max_notifications_per_publish() =
    maxNotifications[std::uniform_int_distribution<size_t>(0, std::size(maxNotifications) - 1)(mRng)];
  req.publishing_enabled() = std::uniform_int_distribution<int>(0, 1)(mRng) != 0;
  req.priority() = priorities[std::uniform_int_distribution<size_t>(0, std::size(priorities) - 1)(mRng)];

  return req;
}

ua::ModifySubscriptionRequest SubscriptionParamsGenerator::generate_modify_subscription_request(
  uint32_t subscriptionId)
{
  static constexpr double publishingIntervals[] = {0.0, 1.0, 50.0, 100.0, 500.0, 1000.0, 4294967295.0};
  static constexpr uint32_t lifetimeCounts[] = {0, 1, 3, 10, 600, 0xFFFFFFFF};
  static constexpr uint32_t keepAliveCounts[] = {0, 1, 3, 5, 100};
  static constexpr uint32_t maxNotifications[] = {0, 1, 10, 100, 0xFFFFFFFF};
  static constexpr uint8_t priorities[] = {0, 1, 128, 255};

  ua::ModifySubscriptionRequest req;
  req.subscription_id() = subscriptionId;
  req.requested_publishing_interval() =
    publishingIntervals[std::uniform_int_distribution<size_t>(0, std::size(publishingIntervals) - 1)(mRng)];
  req.requested_lifetime_count() =
    lifetimeCounts[std::uniform_int_distribution<size_t>(0, std::size(lifetimeCounts) - 1)(mRng)];
  req.requested_max_keep_alive_count() =
    keepAliveCounts[std::uniform_int_distribution<size_t>(0, std::size(keepAliveCounts) - 1)(mRng)];
  req.max_notifications_per_publish() =
    maxNotifications[std::uniform_int_distribution<size_t>(0, std::size(maxNotifications) - 1)(mRng)];
  req.priority() = priorities[std::uniform_int_distribution<size_t>(0, std::size(priorities) - 1)(mRng)];

  return req;
}

ua::SetPublishingModeRequest SubscriptionParamsGenerator::generate_set_publishing_mode_request(
  std::vector<uint32_t> subscriptionIds)
{
  ua::SetPublishingModeRequest req;
  req.publishing_enabled() = std::uniform_int_distribution<int>(0, 1)(mRng) != 0;

  for (auto id : subscriptionIds)
  {
    req.subscription_ids().push_back(id);
  }

  return req;
}

// --- MonitoredItemParamsGenerator ---

MonitoredItemParamsGenerator::MonitoredItemParamsGenerator(
  std::mt19937_64& rng, const FuzzerConfig::Limits& limits)
  : mNodeIdGen(rng), mAttrIdGen(rng), mRng(rng), mLimits(limits)
{}

ua::MonitoredItemCreateRequest MonitoredItemParamsGenerator::generate_monitored_item_create_request(
  uint32_t clientHandle)
{
  static constexpr double samplingIntervals[] = {-1.0, 0.0, 50.0, 100.0, 500.0, 1000.0, 1e9};
  static constexpr uint32_t queueSizes[] = {0, 1, 5, 10, 100, 0xFFFFFFFF};

  ua::MonitoredItemCreateRequest req;

  // item_to_monitor
  req.item_to_monitor().node_id() = mNodeIdGen.generate();
  req.item_to_monitor().attribute_id() = static_cast<uint32_t>(mAttrIdGen.generate());

  // monitoring_mode: 0-3 (3 is invalid)
  auto modeVal = std::uniform_int_distribution<int>(0, 3)(mRng);
  req.monitoring_mode() = static_cast<ua::MonitoringMode>(modeVal);

  // requested_parameters
  req.requested_parameters().client_handle() = clientHandle;
  req.requested_parameters().sampling_interval() =
    samplingIntervals[std::uniform_int_distribution<size_t>(0, std::size(samplingIntervals) - 1)(mRng)];
  req.requested_parameters().queue_size() =
    queueSizes[std::uniform_int_distribution<size_t>(0, std::size(queueSizes) - 1)(mRng)];
  req.requested_parameters().discard_oldest() = std::uniform_int_distribution<int>(0, 1)(mRng) != 0;

  return req;
}

ua::MonitoredItemModifyRequest MonitoredItemParamsGenerator::generate_monitored_item_modify_request(
  uint32_t monitoredItemId)
{
  static constexpr double samplingIntervals[] = {-1.0, 0.0, 50.0, 100.0, 500.0, 1000.0, 1e9};
  static constexpr uint32_t queueSizes[] = {0, 1, 5, 10, 100, 0xFFFFFFFF};

  ua::MonitoredItemModifyRequest req;
  req.monitored_item_id() = monitoredItemId;

  req.requested_parameters().sampling_interval() =
    samplingIntervals[std::uniform_int_distribution<size_t>(0, std::size(samplingIntervals) - 1)(mRng)];
  req.requested_parameters().queue_size() =
    queueSizes[std::uniform_int_distribution<size_t>(0, std::size(queueSizes) - 1)(mRng)];
  req.requested_parameters().discard_oldest() = std::uniform_int_distribution<int>(0, 1)(mRng) != 0;

  return req;
}

// --- PublishParamsGenerator ---

PublishParamsGenerator::PublishParamsGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits)
  : mRng(rng), mLimits(limits)
{}

ua::SubscriptionAcknowledgement PublishParamsGenerator::generate_subscription_acknowledgement(
  uint32_t subscriptionId)
{
  static constexpr uint32_t sequenceNumbers[] = {0, 1, 0xFFFFFFFF};

  ua::SubscriptionAcknowledgement ack;
  ack.subscription_id() = subscriptionId;

  // Choose between edge values and a random value.
  auto kind = std::uniform_int_distribution<int>(0, 3)(mRng);
  if (kind < 3)
  {
    ack.sequence_number() = sequenceNumbers[kind];
  }
  else
  {
    ack.sequence_number() = std::uniform_int_distribution<uint32_t>()(mRng);
  }

  return ack;
}

// --- NodeManagementGenerator ---

NodeManagementGenerator::NodeManagementGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits)
  : mNodeIdGen(rng), mStringGen(rng, limits), mRng(rng), mLimits(limits)
{}

ua::AddNodesItem NodeManagementGenerator::generate_add_nodes_item()
{
  // Valid NodeClass values plus some invalid ones for fuzzing.
  static constexpr int32_t nodeClassValues[] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 3, 255, -1};

  ua::AddNodesItem item;
  item.parent_node_id() = ua::ExpandedNodeId{mNodeIdGen.generate()};
  item.reference_type_id() = mNodeIdGen.generate();
  item.requested_new_node_id() = ua::ExpandedNodeId{mNodeIdGen.generate()};

  auto ns = static_cast<uint16_t>(std::uniform_int_distribution<int>(0, 5)(mRng));
  item.browse_name() = ua::QualifiedName{ns, mStringGen.generate()};

  auto ncVal =
    nodeClassValues[std::uniform_int_distribution<size_t>(0, std::size(nodeClassValues) - 1)(mRng)];
  item.node_class() = static_cast<ua::NodeClass>(ncVal);

  item.type_definition() = ua::ExpandedNodeId{mNodeIdGen.generate()};

  return item;
}

ua::DeleteNodesItem NodeManagementGenerator::generate_delete_nodes_item()
{
  ua::DeleteNodesItem item;
  item.node_id() = mNodeIdGen.generate();
  item.delete_target_references() = std::uniform_int_distribution<int>(0, 1)(mRng) != 0;

  return item;
}

ua::AddReferencesItem NodeManagementGenerator::generate_add_references_item()
{
  static constexpr int32_t nodeClassValues[] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 3, 255, -1};

  ua::AddReferencesItem item;
  item.source_node_id() = mNodeIdGen.generate();
  item.reference_type_id() = mNodeIdGen.generate();
  item.is_forward() = std::uniform_int_distribution<int>(0, 1)(mRng) != 0;
  item.target_node_id() = ua::ExpandedNodeId{mNodeIdGen.generate()};

  auto ncVal =
    nodeClassValues[std::uniform_int_distribution<size_t>(0, std::size(nodeClassValues) - 1)(mRng)];
  item.target_node_class() = static_cast<ua::NodeClass>(ncVal);

  return item;
}

ua::DeleteReferencesItem NodeManagementGenerator::generate_delete_references_item()
{
  ua::DeleteReferencesItem item;
  item.source_node_id() = mNodeIdGen.generate();
  item.reference_type_id() = mNodeIdGen.generate();
  item.is_forward() = std::uniform_int_distribution<int>(0, 1)(mRng) != 0;
  item.target_node_id() = ua::ExpandedNodeId{mNodeIdGen.generate()};
  item.delete_bidirectional() = std::uniform_int_distribution<int>(0, 1)(mRng) != 0;

  return item;
}

}  // namespace fuzz
