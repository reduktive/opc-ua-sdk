// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
// The address space advances the model generation for a change that completes through it, whatever namespace
// holds the Nodes (NR-27 rule 1, NR-68 item 1; NR-70 B9c).
//
// The changes are made in a namespace wrapped in `HistoryNamespace`, which the address space reaches only through
// the members of `Namespace`.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_history_namespace.h"
#include "ua_node_accessor.h"
#include "ua_referencetype_id.h"
#include "ua_status_to_string.h"
#include "ua_to_string.h"
#include <boost/asio/thread_pool.hpp>

#include <memory>
#include <optional>
#include <string>

using namespace ua;

namespace
{

class ModelGeneration : public ::testing::Test
{
protected:
  void SetUp() override
  {
    mAddressSpace.emplace(AddressSpace::create("urn:test:model-generation", mThreadPool.get_executor()));
    auto inner = default_ns::Namespace::create("urn:test:model-generation:wrapped", mThreadPool.get_executor());
    auto index =
      mAddressSpace->try_add_namespace_sync(std::make_shared<history::HistoryNamespace>(std::move(inner), nullptr));
    ASSERT_TRUE(index.is_good()) << to_string(index.status_code());
    mIndex = index.value();
  }

  void TearDown() override
  {
    mAddressSpace.reset();
    ::ua::test_utils::drain_with_timeout(mThreadPool);
  }

  NodeAccessor create(const std::string& name, NodeClass nodeClass = NodeClass::Object)
  {
    auto created = mAddressSpace->try_create_node_sync(NodeId{mIndex, String{name}}, nodeClass, {});
    EXPECT_TRUE(created.is_good()) << name << ": " << to_string(created.status_code());
    return std::move(created).value();
  }

  uint64_t generation() const
  {
    return mAddressSpace->model_generation();
  }

  boost::asio::thread_pool mThreadPool{2};
  std::optional<AddressSpace> mAddressSpace;
  uint16_t mIndex{0};
};

// @relation(AC-COMP-ADDRSP-MODEL-GENERATION-01-A-REFERENCE-CHANGE-IN-ANOTHER-NAMESPACE-ADVANCES-IT, scope=function)
TEST_F(ModelGeneration, AReferenceAddInAnotherNamespaceAdvancesIt)
{
  auto folder = create("Folder");
  const auto target = create("Target");
  const NodeId organizes{ReferenceTypeId::Organizes};

  const auto beforeAdd = generation();
  ASSERT_TRUE(folder.try_add_reference_sync(organizes, ExpandedNodeId{target.get_node_id()}).is_good());
  EXPECT_GT(generation(), beforeAdd);

  const auto beforeRemove = generation();
  ASSERT_TRUE(folder.try_remove_reference_sync(organizes, ExpandedNodeId{target.get_node_id()}).is_good());
  EXPECT_GT(generation(), beforeRemove);
}

// @relation(AC-COMP-ADDRSP-MODEL-GENERATION-01-A-CREATE-AND-A-DELETE-IN-ANOTHER-NAMESPACE-ADVANCE-IT, scope=function)
TEST_F(ModelGeneration, ACreateAndADeleteInAnotherNamespaceAdvanceIt)
{
  const auto beforeCreate = generation();
  const auto created = create("Created");
  EXPECT_GT(generation(), beforeCreate);

  const auto beforeDelete = generation();
  ASSERT_TRUE(mAddressSpace->try_delete_node_sync(created.get_node_id(), false).is_good());
  EXPECT_GT(generation(), beforeDelete);
}

// @relation(AC-COMP-ADDRSP-MODEL-GENERATION-01-A-BROWSE-NAME-OR-DATA-TYPE-WRITE-ADVANCES-IT, scope=function)
TEST_F(ModelGeneration, ABrowseNameOrDataTypeWriteAdvancesItAndADescriptionWriteDoesNot)
{
  auto variable = create("Field", NodeClass::Variable);
  auto accessor = variable.as<VariableAccessor>();
  ASSERT_TRUE(accessor.has_value());

  // Other Attributes are not part of the model the generation counts (NR-27 rule 3).
  const auto beforeDescription = generation();
  accessor->set_description(LocalizedText{"en", "A field"});
  EXPECT_EQ(generation(), beforeDescription);

  const auto beforeBrowseName = generation();
  accessor->set_browse_name(QualifiedName{mIndex, "Renamed"});
  EXPECT_GT(generation(), beforeBrowseName);

  const auto beforeDataType = generation();
  accessor->set_data_type(NodeId{DataTypeId::Double});
  EXPECT_GT(generation(), beforeDataType);
}

}  // namespace
