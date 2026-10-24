// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_hierarchical_path.h"

#include "ua_referencetype_id.h"
#include "ua_relative_path_element.h"

#include <utility>

namespace ua
{

RelativePath hierarchical_path(uint16_t namespaceIndex, std::vector<std::string> names)
{
  std::vector<QualifiedName> qualified;
  qualified.reserve(names.size());
  for (auto& name : names)
  {
    qualified.emplace_back(namespaceIndex, std::move(name));
  }
  return hierarchical_path(std::move(qualified));
}

RelativePath hierarchical_path(std::vector<QualifiedName> names)
{
  RelativePath path;
  for (auto& name : names)
  {
    RelativePathElement element;
    element.reference_type_id() = NodeId{ReferenceTypeId::HierarchicalReferences};
    element.is_inverse() = false;
    element.include_subtypes() = true;
    element.target_name() = std::move(name);
    path.elements().push_back(std::move(element));
  }
  return path;
}

}  // namespace ua
