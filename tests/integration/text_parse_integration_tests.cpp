// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Text into built-in types (public API review 2026-10, item 7), against a live server: every NodeId,
// ExpandedNodeId and BrowseName a Browse returns reads back from its own text. The walk covers the NS0
// type definitions, whose placeholder BrowseNames (`<VendorCapability>`, `<ClientName>`) carry the
// reserved characters that QualifiedName text escapes with '&' (OPC 10000-4 Annex A).

#include <cstddef>
#include <deque>
#include <set>
#include <string>

#include "compliance_helpers.h"
#include "matchers.h"

#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_result_mask.h"
#include "ua_expanded_node_id.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_session_view_services.h"
#include "ua_to_string.h"

namespace
{
using namespace ua;

constexpr std::size_t nodeBudget = 4000;
constexpr std::size_t nodesPerRequest = 100;

bool has_reserved_character(const QualifiedName& name)
{
  for (const char c : static_cast<string_view>(name.name()))
  {
    if (c == '/' || c == '.' || c == '<' || c == '>' || c == ':' || c == '#' || c == '!' || c == '&')
    {
      return true;
    }
  }
  return false;
}

TEST_F(ComplianceBase, EveryBrowsedIdAndBrowseNameReadsBackFromItsText)
{
  auto channel = mClient->core().open_channel_sync({.endpointUrl = mEndpointUrl});
  auto session = channel.create_session_sync({.sessionName = "TextParse"});
  session.activate_sync();

  std::deque<NodeId> pending{NodeId{ObjectId::RootFolder}};
  std::set<NodeId> visited{NodeId{ObjectId::RootFolder}};
  std::size_t checked = 0;
  std::size_t reservedNames = 0;
  while (!pending.empty() && visited.size() < nodeBudget)
  {
    BrowseRequest request;
    while (!pending.empty() && request.nodes_to_browse().size() < nodesPerRequest)
    {
      BrowseDescription description;
      description.node_id() = pending.front();
      description.browse_direction() = BrowseDirection::Forward;
      description.reference_type_id() = NodeId{ReferenceTypeId::HierarchicalReferences};
      description.include_subtypes() = true;
      description.result_mask() = static_cast<uint32_t>(BrowseResultMask::All);
      request.nodes_to_browse().push_back(std::move(description));
      pending.pop_front();
    }
    const auto response = session.view().browse_sync(std::move(request));
    ASSERT_THAT(response, ::ua::test_helpers::ServiceResultIsGood());
    for (const auto& result : response.results())
    {
      for (const auto& reference : result.references())
      {
        const ExpandedNodeId& target = reference.node_id();
        EXPECT_EQ(ExpandedNodeId::parse(to_string(target)), target) << to_string(target);
        const NodeId& local = target.node_id();
        EXPECT_EQ(NodeId::parse(to_string(local)), local) << to_string(local);
        const QualifiedName& name = reference.browse_name();
        const auto parsedName = QualifiedName::try_parse(to_string(name));
        ASSERT_TRUE(parsedName.is_good()) << to_string(name);
        EXPECT_EQ(parsedName.value(), name) << to_string(name);
        ++checked;
        if (has_reserved_character(name))
        {
          ++reservedNames;
        }
        if (target.is_local() && visited.insert(local).second)
        {
          pending.push_back(local);
        }
      }
    }
  }

  EXPECT_GT(checked, 1000u) << "the walk must reach well into the address space";
  EXPECT_GT(reservedNames, 0u) << "the walk must meet BrowseNames that need escaping";
  session.close_sync();
  channel.close_sync();
}

}  // namespace
