// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_structure_factory.h"
#include "ua_structure.h"

namespace ua
{

void StructureFactory::register_type(const NodeId& encodingId, StructureFactory::CreateMethod method) noexcept
{
  const WriteLock lk(mMutex);
  mCreateMethods.emplace(std::make_pair(encodingId, method));
}

unique_ptr<Structure> StructureFactory::create_instance(const NodeId& encodingId) const
{
  const ReadLock lk(mMutex);
  auto result = mCreateMethods.find(encodingId);
  if (result != mCreateMethods.end())
  {
    return result->second();
  }

  return unique_ptr<Structure>{};
}

StructureResolver StructureFactory::resolver() const
{
  return [this](const NodeId& encodingId)
  {
    return create_instance(encodingId);
  };
}

}  // namespace ua
