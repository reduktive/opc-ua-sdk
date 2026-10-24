// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef FUZZ_INPUT_GENERATORS_H
#define FUZZ_INPUT_GENERATORS_H

#include "fuzz_types.h"
#include "fuzzer_config.h"

#include "ua_add_nodes_item.h"
#include "ua_add_references_item.h"
#include "ua_attribute_id.h"
#include "ua_browse_description.h"
#include "ua_browse_path.h"
#include "ua_call_method_request.h"
#include "ua_create_subscription_request.h"
#include "ua_delete_nodes_item.h"
#include "ua_delete_references_item.h"
#include "ua_expanded_node_id.h"
#include "ua_modify_subscription_request.h"
#include "ua_monitored_item_create_request.h"
#include "ua_monitored_item_modify_request.h"
#include "ua_monitoring_parameters.h"
#include "ua_node_id.h"
#include "ua_qualified_name.h"
#include "ua_read_value_id.h"
#include "ua_set_publishing_mode_request.h"
#include "ua_subscription_acknowledgement.h"
#include "ua_timestamps_to_return.h"
#include "ua_variant.h"
#include "ua_write_value.h"

#include <random>
#include <vector>

namespace fuzz
{

/// Generates fuzzed NodeId values.
class NodeIdGenerator
{
public:
  explicit NodeIdGenerator(std::mt19937_64& rng);

  ua::NodeId generate();

private:
  std::mt19937_64& mRng;
};

/// Generates fuzzed Variant values.
class VariantGenerator
{
public:
  explicit VariantGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits);

  ua::Variant generate();

private:
  std::mt19937_64& mRng;
  FuzzerConfig::Limits mLimits;
};

/// Generates fuzzed AttributeId values.
class AttributeIdGenerator
{
public:
  explicit AttributeIdGenerator(std::mt19937_64& rng);

  ua::AttributeId generate();

private:
  std::mt19937_64& mRng;
};

/// Generates fuzzed string values.
class StringGenerator
{
public:
  explicit StringGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits);

  std::string generate();

private:
  std::mt19937_64& mRng;
  FuzzerConfig::Limits mLimits;
};

/// Generates fuzzed ReadValueId for Read requests.
class ReadRequestGenerator
{
public:
  explicit ReadRequestGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits);

  ua::ReadValueId generate_read_value_id();

  ua::TimestampsToReturn generate_timestamps_to_return();

  uint32_t generate_max_age();

private:
  NodeIdGenerator mNodeIdGen;
  AttributeIdGenerator mAttrIdGen;
  StringGenerator mStringGen;
  std::mt19937_64& mRng;
};

/// Generates fuzzed BrowseDescription for Browse requests.
class BrowseRequestGenerator
{
public:
  explicit BrowseRequestGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits);

  ua::BrowseDescription generate_browse_description();

  uint32_t generate_requested_max_references_per_node();

private:
  NodeIdGenerator mNodeIdGen;
  std::mt19937_64& mRng;
};

/// Generates fuzzed WriteValue for Write requests.
class WriteRequestGenerator
{
public:
  explicit WriteRequestGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits);

  ua::WriteValue generate_write_value();

private:
  NodeIdGenerator mNodeIdGen;
  AttributeIdGenerator mAttrIdGen;
  VariantGenerator mVariantGen;
  std::mt19937_64& mRng;
};

/// Generates fuzzed CallMethodRequest for Call service.
class CallRequestGenerator
{
public:
  explicit CallRequestGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits);

  ua::CallMethodRequest generate_call_method_request();

private:
  NodeIdGenerator mNodeIdGen;
  VariantGenerator mVariantGen;
  std::mt19937_64& mRng;
};

/// Generates fuzzed BrowsePath for TranslateBrowsePathsToNodeIds service.
class TranslateBrowsePathsGenerator
{
public:
  explicit TranslateBrowsePathsGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits);

  ua::BrowsePath generate_browse_path();

private:
  NodeIdGenerator mNodeIdGen;
  StringGenerator mStringGen;
  std::mt19937_64& mRng;
};

/// Generates fuzzed NodeIds for RegisterNodes/UnregisterNodes services.
class RegisterNodesGenerator
{
public:
  explicit RegisterNodesGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits);

  ua::NodeId generate_node_to_register();

private:
  NodeIdGenerator mNodeIdGen;
};

/// Generates fuzzed subscription parameters for Create/Modify/SetPublishingMode.
class SubscriptionParamsGenerator
{
public:
  explicit SubscriptionParamsGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits);

  ua::CreateSubscriptionRequest generate_create_subscription_request();

  ua::ModifySubscriptionRequest generate_modify_subscription_request(uint32_t subscriptionId);

  ua::SetPublishingModeRequest generate_set_publishing_mode_request(std::vector<uint32_t> subscriptionIds);

private:
  std::mt19937_64& mRng;
  FuzzerConfig::Limits mLimits;
};

/// Generates fuzzed monitored item parameters for CreateMonitoredItems/ModifyMonitoredItems.
class MonitoredItemParamsGenerator
{
public:
  explicit MonitoredItemParamsGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits);

  ua::MonitoredItemCreateRequest generate_monitored_item_create_request(uint32_t clientHandle);

  ua::MonitoredItemModifyRequest generate_monitored_item_modify_request(uint32_t monitoredItemId);

private:
  NodeIdGenerator mNodeIdGen;
  AttributeIdGenerator mAttrIdGen;
  std::mt19937_64& mRng;
  FuzzerConfig::Limits mLimits;
};

/// Generates fuzzed publish request parameters.
class PublishParamsGenerator
{
public:
  explicit PublishParamsGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits);

  ua::SubscriptionAcknowledgement generate_subscription_acknowledgement(uint32_t subscriptionId);

private:
  std::mt19937_64& mRng;
  FuzzerConfig::Limits mLimits;
};

/// Generates fuzzed node management items (AddNodes, DeleteNodes, AddReferences, DeleteReferences).
class NodeManagementGenerator
{
public:
  explicit NodeManagementGenerator(std::mt19937_64& rng, const FuzzerConfig::Limits& limits);

  ua::AddNodesItem generate_add_nodes_item();

  ua::DeleteNodesItem generate_delete_nodes_item();

  ua::AddReferencesItem generate_add_references_item();

  ua::DeleteReferencesItem generate_delete_references_item();

private:
  NodeIdGenerator mNodeIdGen;
  StringGenerator mStringGen;
  std::mt19937_64& mRng;
  FuzzerConfig::Limits mLimits;
};

}  // namespace fuzz

#endif  // !FUZZ_INPUT_GENERATORS_H
