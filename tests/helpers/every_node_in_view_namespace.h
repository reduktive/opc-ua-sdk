// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Real-node test namespace whose View Nodes answer that every NodeId is in the View, or as a test
/// chooses.

#ifndef UA_TEST_EVERY_NODE_IN_VIEW_NAMESPACE_H
#define UA_TEST_EVERY_NODE_IN_VIEW_NAMESPACE_H

#include "ua_default_namespace.h"
#include "ua_node_id.h"
#include "ua_result.h"

#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <memory>
#include <span>

namespace ua::test
{

/// A namespace that keeps the default namespace's real node store, except that it answers whether a Node is
/// a member of one of its Views (`view_contains_async`) with the answer a test chose for each NodeId. By
/// default the answer is true for every NodeId, the Server Object included.
///
/// By default this is a namespace whose membership answer is wrong for the Server Object, which Part 3
/// section 5.4 says "shall never be part of any View". It lets a test show that the Browse service decides
/// that rule itself rather than trusting the namespace. A test that passes its own answer can also make the
/// namespace fail to say whether a Node is a member, with a Bad status and its ErrorDetail, and a test that
/// creates it with @ref create_deferred answers when it chooses, after the question was asked. A candidate of
/// another server is not a member, and a View this namespace does not hold is answered as the default
/// namespace answers it. Every other operation is the default namespace's.
class EveryNodeInViewNamespace final : public default_ns::Namespace
{
public:
  /// The answer the namespace gives, for any of its Views, when asked whether a NodeId is a member.
  using MembershipAnswer = std::function<BoolResult(const NodeId&)>;

  /// An answer given when the test chooses: called with the NodeId asked about and the callback that answers
  /// the question, which may be called later and from any thread, exactly once.
  using DeferredMembershipAnswer = std::function<void(const NodeId&, std::function<void(BoolResult)>)>;

  /// @param uri      The namespace URI.
  /// @param executor The executor the namespace runs on.
  /// @param answer   The membership answer for each NodeId; when empty, true for every NodeId. It is called
  /// on
  ///                 the Browse service's threads and must not block.
  static std::shared_ptr<EveryNodeInViewNamespace> create(
    string_view uri, boost::asio::any_io_executor executor, MembershipAnswer answer = {});

  /// @param uri      The namespace URI.
  /// @param executor The executor the namespace runs on.
  /// @param answer   Asked each membership question; it must not block, and answers through the callback
  ///                 it is given.
  static std::shared_ptr<EveryNodeInViewNamespace> create_deferred(
    string_view uri, boost::asio::any_io_executor executor, DeferredMembershipAnswer answer);

  /// Answers each local candidate with the test's answer when @p view is a View of this namespace; otherwise
  /// as the default namespace does.
  void view_contains_async(const RequestInfo& request, const NodeId& view,
    std::span<const ExpandedNodeId> nodes, std::function<void(BatchResult<BoolResult>)> complete) override;

private:
  EveryNodeInViewNamespace(
    string_view uri, boost::asio::any_io_executor executor, DeferredMembershipAnswer answer);

  std::shared_ptr<const DeferredMembershipAnswer> mAnswer;
};

}  // namespace ua::test

#endif  // UA_TEST_EVERY_NODE_IN_VIEW_NAMESPACE_H
