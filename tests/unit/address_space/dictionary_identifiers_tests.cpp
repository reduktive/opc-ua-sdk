// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 19 sections 5.3 and 5.4: the identifier of an IRDI or URI dictionary entry is the external
// dictionary's, and it is the NodeId and the BrowseName of the entry. The identifier names one entry at a
// time (Part 4 section 5.7.2.4, Table 24: Bad_NodeIdExists while it is in use), and a Node created again
// under it after a delete denotes the same entry, so nothing requires the address space to refuse it.

#include <gtest/gtest.h>

#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_localized_text.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_variant.h"
#include <boost/asio/thread_pool.hpp>
#include <string>
#include <string_view>

using namespace ua;

namespace
{

// Creates a dictionary entry the way a dictionary loader publishes one: the identifier is the String
// identifier of the NodeId and the BrowseName, the DisplayName is the entry's, and the Node is typed by the
// entry type.
NodeAccessorResult create_dictionary_entry(
  AddressSpace& addressSpace, const NodeId& identifier, const NodeId& entryType, std::string_view displayName)
{
  InitialAttributes attributes;
  attributes.emplace_back(AttributeId::BrowseName,
    Variant{QualifiedName{identifier.namespace_index(),
      std::string{static_cast<std::string_view>(identifier.identifier().get_string())}}});
  attributes.emplace_back(AttributeId::DisplayName, Variant{LocalizedText{"", std::string{displayName}}});
  auto created = addressSpace.try_create_node_sync(identifier, NodeClass::Object, std::move(attributes));
  if (created.is_good())
  {
    const auto typed =
      created.value().try_add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, entryType);
    if (typed.is_bad())
    {
      return NodeAccessorResult{typed.status_code(), typed.shared_detail()};
    }
  }
  return created;
}

// The DisplayName text the address space holds for the Node, or an empty string when it holds no Node
// under the identifier or the Node carries no DisplayName.
std::string display_name_of(AddressSpace& addressSpace, const NodeId& identifier)
{
  auto found = addressSpace.try_find_node_sync(identifier);
  if (found.is_bad())
  {
    return {};
  }
  const auto value = found.value().read_attribute(AttributeId::DisplayName);
  const auto* text = value.try_as<LocalizedText>();
  return text == nullptr ? std::string{} : std::string{static_cast<std::string_view>(text->text())};
}

void expect_deleted_entry_can_be_created_again(const NodeId& identifier, const NodeId& entryType)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace = AddressSpace::create("urn:test:dictionary-identifiers", threadPool.get_executor());

  ASSERT_TRUE(create_dictionary_entry(addressSpace, identifier, entryType, "MassInKilograms").is_good());
  ASSERT_EQ(display_name_of(addressSpace, identifier), "MassInKilograms")
    << "the entry does not resolve under its identifier, so there is nothing to delete and create again";
  const auto deletion = addressSpace.try_delete_node_sync(identifier, false);
  ASSERT_TRUE(deletion.is_good()) << "the entry could not be deleted; status "
                                  << deletion.status_code().as_uint32();

  const auto recreation = create_dictionary_entry(addressSpace, identifier, entryType, "MassInKilograms");
  EXPECT_EQ(recreation.status_code().as_status(), Status::Good)
    << "a deleted dictionary entry was refused when created again under its own identifier"
    << (recreation.shared_detail() == nullptr ? std::string{} : ": " + recreation.shared_detail()->code);
  EXPECT_EQ(display_name_of(addressSpace, identifier), "MassInKilograms")
    << "the identifier does not resolve to the entry created again under it";

  ::ua::test_utils::drain_with_timeout(threadPool);
}

}  // namespace

// The unit arm on the address space: an IRDI entry, deleted and created again under the same identifier.
// @relation(AC-SVR-ADDRSP-253-IRDI-NOT-REASSIGNED, scope=function)
TEST(DictionaryIdentifiers, ADeletedIrdiEntryCanBeCreatedAgain)
{
  expect_deleted_entry_can_be_created_again(
    NodeId{1u, "0112/2///61987#ABA951"}, NodeId{ObjectTypeId::IrdiDictionaryEntryType});
}

// The URI twin of ADeletedIrdiEntryCanBeCreatedAgain.
// @relation(AC-SVR-ADDRSP-256-URI-NOT-REASSIGNED, scope=function)
TEST(DictionaryIdentifiers, ADeletedUriEntryCanBeCreatedAgain)
{
  expect_deleted_entry_can_be_created_again(NodeId{1u, "http://example.org/dictionary/2026#Temperature"},
    NodeId{ObjectTypeId::UriDictionaryEntryType});
}

// The negative the two re-creation arms are contrasted with: the same identifier, refused while it names an
// entry, and the entry it names left as it was.
// @relation(AC-SVR-ADDRSP-253-IRDI-NOT-REASSIGNED, scope=function)
// @relation(AC-SVR-ADDRSP-256-URI-NOT-REASSIGNED, scope=function)
TEST(DictionaryIdentifiers, ASecondEntryWithAnIdentifierInUseIsBadNodeIdExists)
{
  boost::asio::thread_pool threadPool{1};
  auto addressSpace =
    AddressSpace::create("urn:test:dictionary-identifier-in-use", threadPool.get_executor());

  const NodeId irdi{1u, "0112/2///61987#ABA951"};
  const NodeId uri{1u, "http://example.org/dictionary/2026#Temperature"};
  ASSERT_TRUE(create_dictionary_entry(
    addressSpace, irdi, NodeId{ObjectTypeId::IrdiDictionaryEntryType}, "MassInKilograms")
                .is_good());
  ASSERT_TRUE(create_dictionary_entry(
    addressSpace, uri, NodeId{ObjectTypeId::UriDictionaryEntryType}, "ProcessTemperature")
                .is_good());

  const auto secondIrdi = create_dictionary_entry(
    addressSpace, irdi, NodeId{ObjectTypeId::IrdiDictionaryEntryType}, "LengthInMetres");
  EXPECT_EQ(secondIrdi.status_code().as_status(), Status::BadNodeIdExists);
  EXPECT_EQ(display_name_of(addressSpace, irdi), "MassInKilograms")
    << "the refused creation changed the entry the IRDI already names";

  const auto secondUri = create_dictionary_entry(
    addressSpace, uri, NodeId{ObjectTypeId::UriDictionaryEntryType}, "AmbientPressure");
  EXPECT_EQ(secondUri.status_code().as_status(), Status::BadNodeIdExists);
  EXPECT_EQ(display_name_of(addressSpace, uri), "ProcessTemperature")
    << "the refused creation changed the entry the dictionary URI already names";

  ::ua::test_utils::drain_with_timeout(threadPool);
}
