// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_default_reference.h"
#include "ua_status_code.h"
#include "ua_address_space.h"

namespace ua::default_ns
{

bool Reference::is_forward() const
{
  return mIsForward;
}

bool Reference::is_remote() const
{
  ExpandedNodeId targetId{target_id()};
  return targetId.is_remote();
}

NodeId Reference::type_id() const
{
  return mType;
}

ExpandedNodeId Reference::target_id() const
{
  return mTarget;
}

Reference::Reference(bool isForward, NodeId type, ExpandedNodeId target)
  : mIsForward(isForward), mType(type), mTarget(target)
{}

bool Reference::operator==(const ua::Reference& obj) const
{
  return (
    (is_forward() == obj.is_forward()) && (type_id() == obj.type_id()) && (target_id() == obj.target_id()));
}

}  // namespace ua::default_ns
