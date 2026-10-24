// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Part 19 sections 5.3 and 5.4: the identifier of an IRDI or URI dictionary entry is the external
// dictionary's, and it is the NodeId and the BrowseName of the entry. It names one entry at a time (Part 4
// section 5.7.2.4, Table 24: Bad_NodeIdExists while it is in use), and a Node created again under it after
// a delete denotes the same entry. A Client holding the identifier reaches the entry created again.

#include "compliance_helpers.h"
#include "matchers.h"
#include "requests.h"

#include "ua_attribute_id.h"
#include "ua_localized_text.h"
#include "ua_node.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"

#include <string>
#include <string_view>

using namespace ua;
using namespace ua::test_helpers;

namespace
{

class DictionaryIdentifiers : public ComplianceWithNodes
{
protected:
  // Publishes a dictionary entry the way a dictionary loader does: the identifier is the String identifier of
  // the NodeId and the BrowseName, the DisplayName is the entry's, and the Node is typed by the entry type
  // and hung below the test folder.
  NodeAccessorResult publish_entry(
    const NodeId& identifier, const NodeId& entryType, std::string_view displayName)
  {
    auto addressSpace = mServer.server().address_space();
    InitialAttributes attributes;
    attributes.emplace_back(AttributeId::BrowseName,
      Variant{QualifiedName{identifier.namespace_index(),
        std::string{static_cast<std::string_view>(identifier.identifier().get_string())}}});
    attributes.emplace_back(AttributeId::DisplayName, Variant{LocalizedText{"", std::string{displayName}}});
    auto created = addressSpace.try_create_node_sync(identifier, NodeClass::Object, std::move(attributes));
    if (created.is_bad())
    {
      return created;
    }
    auto entry = created.value();
    entry.add_reference_sync(NodeId{ReferenceTypeId::HasTypeDefinition}, entryType);
    addressSpace.find_node_sync(mTestFolderId)
      .add_reference_sync(NodeId{ReferenceTypeId::Organizes}, identifier);
    entry.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, ExpandedNodeId{mTestFolderId}, false);
    return created;
  }

  // The DisplayName text a Client reads for the identifier; the test fails when the Read does not answer
  // Good.
  std::string client_reads_display_name(const NodeId& identifier)
  {
    auto response = mSession->attributes().read_sync(read_value(identifier, AttributeId::DisplayName));
    EXPECT_THAT(response, ServiceResultIsGood());
    if (response.results().size() != 1u)
    {
      ADD_FAILURE() << "the Read answered " << response.results().size() << " results for one item";
      return {};
    }
    EXPECT_THAT(response.results()[0], Good()) << "reading the DisplayName of " << ua::to_string(identifier);
    const auto* text = response.results()[0].value().try_as<LocalizedText>();
    return text == nullptr ? std::string{} : std::string{static_cast<std::string_view>(text->text())};
  }

  void expect_deleted_entry_can_be_created_again(const NodeId& identifier, const NodeId& entryType,
    std::string_view displayName, std::string_view otherEntryName)
  {
    ASSERT_TRUE(publish_entry(identifier, entryType, displayName).is_good())
      << "publishing the entry " << ua::to_string(identifier) << " failed";
    ASSERT_EQ(client_reads_display_name(identifier), displayName)
      << "the identifier does not name the entry published under it, so the stimulus never started";

    // While the identifier names the entry, a second Node under it is refused and the entry is unchanged.
    const auto second = publish_entry(identifier, entryType, otherEntryName);
    EXPECT_EQ(second.status_code().as_status(), Status::BadNodeIdExists);
    EXPECT_EQ(client_reads_display_name(identifier), displayName)
      << "the refused creation changed the entry the identifier names";

    auto addressSpace = mServer.server().address_space();
    const auto deletion = addressSpace.try_delete_node_sync(identifier, true);
    ASSERT_TRUE(deletion.is_good()) << "the entry could not be deleted; status "
                                    << deletion.status_code().as_uint32();

    // Created again under the same identifier and DisplayName, the entry is accepted and a Client reaches it.
    const auto recreation = publish_entry(identifier, entryType, displayName);
    EXPECT_EQ(recreation.status_code().as_status(), Status::Good)
      << "the deleted entry " << ua::to_string(identifier) << " was refused when created again"
      << (recreation.shared_detail() == nullptr ? std::string{} : ": " + recreation.shared_detail()->code);
    EXPECT_EQ(client_reads_display_name(identifier), displayName)
      << "a Client holding the identifier does not reach the entry created again under it";
  }
};

}  // namespace

// @relation(AC-SVR-ADDRSP-253-IRDI-NOT-REASSIGNED, scope=function)
// @relation(AC-SVR-ADDRSP-256-URI-NOT-REASSIGNED, scope=function)
TEST_F(DictionaryIdentifiers, ADeletedEntryCanBeCreatedAgain)
{
  {
    SCOPED_TRACE("IRDI dictionary entry");
    expect_deleted_entry_can_be_created_again(NodeId{mTestNamespaceIndex, "0112/2///61987#ABA951"},
      NodeId{ObjectTypeId::IrdiDictionaryEntryType},
      "MassInKilograms",
      "LengthInMetres");
  }
  {
    SCOPED_TRACE("URI dictionary entry");
    expect_deleted_entry_can_be_created_again(
      NodeId{mTestNamespaceIndex, "http://example.org/dictionary/2026#Temperature"},
      NodeId{ObjectTypeId::UriDictionaryEntryType},
      "ProcessTemperature",
      "AmbientPressure");
  }
}
