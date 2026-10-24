// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// hierarchical_path (public API review 2026-10, item 8c section 10, API-8c.1): one element per name, each
// following forward HierarchicalReferences with subtypes to that BrowseName.

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "ua_hierarchical_path.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"

namespace
{

using ua::hierarchical_path;
using ua::NodeId;
using ua::QualifiedName;
using ua::ReferenceTypeId;

void expect_hierarchical_forward(const ua::RelativePathElement& element)
{
  EXPECT_EQ(element.reference_type_id(), NodeId{ReferenceTypeId::HierarchicalReferences});
  EXPECT_FALSE(element.is_inverse());
  EXPECT_TRUE(element.include_subtypes()) << "Organizes, HasComponent and HasProperty all match";
}

TEST(HierarchicalPath, NamesInOneNamespaceBecomeOneForwardElementEach)
{
  const ua::RelativePath path = hierarchical_path(uint16_t{3}, {"Plant", "Boiler", "Setpoint"});

  ASSERT_EQ(path.elements().size(), 3u);
  for (const auto& element : path.elements())
  {
    expect_hierarchical_forward(element);
  }
  EXPECT_EQ(path.elements()[0].target_name(), (QualifiedName{3, "Plant"}));
  EXPECT_EQ(path.elements()[1].target_name(), (QualifiedName{3, "Boiler"}));
  EXPECT_EQ(path.elements()[2].target_name(), (QualifiedName{3, "Setpoint"}));
}

TEST(HierarchicalPath, QualifiedNamesKeepTheirOwnNamespaces)
{
  const ua::RelativePath path =
    hierarchical_path({QualifiedName{2, "Plant"}, QualifiedName{0, "ServerStatus"}});

  ASSERT_EQ(path.elements().size(), 2u);
  expect_hierarchical_forward(path.elements()[1]);
  EXPECT_EQ(path.elements()[0].target_name(), (QualifiedName{2, "Plant"}));
  EXPECT_EQ(path.elements()[1].target_name(), (QualifiedName{0, "ServerStatus"}));
}

TEST(HierarchicalPath, NoNamesIsAnEmptyPath)
{
  EXPECT_TRUE(hierarchical_path(uint16_t{1}, {}).elements().empty());
}

}  // namespace
