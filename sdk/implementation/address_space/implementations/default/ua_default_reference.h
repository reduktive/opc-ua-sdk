// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_REFERENCE_DEFAULT_H
#define UA_REFERENCE_DEFAULT_H

#include "ua_reference.h"
#include "ua_expanded_node_id.h"

namespace ua::default_ns
{

class Reference final : public ua::Reference
{
public:
  Reference() = delete;
  Reference(const Reference&) = default;
  Reference(Reference&&) noexcept = default;
  Reference& operator=(const Reference&) = default;
  Reference& operator=(Reference&&) noexcept = default;
  Reference(bool isForward, NodeId type, ExpandedNodeId target);

  bool operator==(const ua::Reference& obj) const override;

  bool is_forward() const override;

  bool is_remote() const override;

  NodeId type_id() const override;

  ExpandedNodeId target_id() const override;

private:
  bool mIsForward;
  NodeId mType;
  ExpandedNodeId mTarget;
};

}  // namespace ua::default_ns

#endif  // UA_REFERENCE_DEFAULT_H
