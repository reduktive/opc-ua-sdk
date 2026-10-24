// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Real-node test namespace whose attribute writes answer by a post to an executor.

#ifndef UA_TEST_POSTING_WRITES_NAMESPACE_H
#define UA_TEST_POSTING_WRITES_NAMESPACE_H

#include "ua_attribute_id.h"
#include "ua_default_namespace.h"
#include "ua_node_id.h"
#include "ua_status_code.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <utility>
#include <vector>
#include <thread>

namespace ua::test
{

/// A namespace that keeps the default namespace's real node store but answers every attribute write
/// by POSTING the completion to an executor, never inline.
///
/// This is the answer shape that exposes a blocking wait. SDK code that writes an attribute through a
/// `*_sync` setter waits on a future for the completion; when the completion is posted to the executor
/// that the waiting thread is the only thread of, it can never run, and the thread hangs. Code that
/// awaits the write instead returns to the executor, which then runs the posted completion. A test
/// that drives a request through this namespace on a one-thread executor therefore times out on the
/// blocking form and completes on the awaited one.
///
/// The write itself is applied to the real node inline; only its answer is deferred. The namespace hands out
/// its real nodes and answers through the in-memory namespace's batched members: a write batch holding any
/// write other than a Variable's Value answers by a post, and one holding only Variable Values answers as the
/// in-memory namespace does.
class PostingWritesNamespace final : public default_ns::Namespace
{
public:
  /// Whether the namespace's Method nodes accept a call handler: a namespace that does not is how a test
  /// reaches the Bad_NotSupported a handler installation answers there. A refusing namespace hands out each
  /// Method node behind a node of its own whose call source is absent, and unwraps it in its batched members.
  enum class CallHandlers
  {
    Accepted,
    Refused
  };

  /// Whether the namespace's Variable nodes accept a value source: a refusing namespace hands out each
  /// Variable behind a node of its own whose value source probe answers null, as a namespace whose Variables
  /// hold their Values themselves does, and unwraps it in its batched members.
  enum class ValueSources
  {
    Accepted,
    Refused
  };

  /// With ValueSources::Refused, an engaged refusal exposes a probe returning that rich status;
  /// without it, the refused probe remains null.
  static std::shared_ptr<PostingWritesNamespace> create(string_view uri,
    boost::asio::any_io_executor executor, CallHandlers callHandlers = CallHandlers::Accepted,
    ValueSources valueSources = ValueSources::Accepted,
    std::optional<StatusCode> valueSourceRefusal = std::nullopt);

  /// How many writes of @p attributeId have answered through the posted path: every write other than a
  /// Variable's Value. A test asserts this is non-zero, so that a request which never reached the write
  /// cannot pass vacuously.
  std::size_t posted_writes(AttributeId attributeId) const;

  /// Makes every attribute write of @p nodeId, the Value included, that the real node completes good answer
  /// @p status instead, the way a namespace whose node clamps or defers a write answers a Good subcode.
  /// @p status may be of any severity, with its ErrorDetail: an Uncertain or a Bad code is how a node that
  /// applied the write and then qualified or refused it answers. A bad completion of the real node is passed
  /// through unchanged, so a write the node did not apply is never reported as answered.
  void answer_good_writes_with(const NodeId& nodeId, StatusCode status);

  /// Records that one write of an attribute has answered.
  struct WriteLog
  {
    mutable std::mutex mutex;
    std::map<AttributeId, std::size_t> counts;
    std::vector<std::pair<NodeId, StatusCode>> goodAnswers;

    void record(AttributeId attributeId);
    std::size_t count(AttributeId attributeId) const;
    std::optional<StatusCode> good_answer_for(const NodeId& nodeId) const;
  };

  /// Creates through the in-memory namespace; a refusing namespace hands out each created Method node behind
  /// its own node (see @ref CallHandlers).
  void create_nodes_async(const RequestInfo& request, std::span<const NodeCreation> nodes,
    std::function<void(BatchResult<NodeResult>)> complete) override;

  /// Records and qualifies each write as described above, then answers by a post unless every item is a
  /// Variable's Value.
  void write_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueWriteItem> items,
    std::function<void(BatchResult<VoidResult>, std::vector<VersionedNode>)> complete) override;

  // The members that carry Nodes, with any Method node of a refusing namespace unwrapped.
  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override;
  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override;
  void call_async(const RequestInfo& request, const CallerInfo* caller, std::span<const CallItem> items,
    std::function<void(BatchResult<std::optional<CallResult>>)> complete) override;

protected:
  NodeResult resolve_here(const NodeId& nodeId) override;

private:
  PostingWritesNamespace(string_view uri, boost::asio::any_io_executor executor, CallHandlers callHandlers,
    ValueSources valueSources, std::optional<StatusCode> valueSourceRefusal);

  boost::asio::any_io_executor mAnswerExecutor;
  bool mAcceptsCallHandlers;
  bool mAcceptsValueSources;
  std::optional<StatusCode> mValueSourceRefusal;
  std::shared_ptr<WriteLog> mWriteLog = std::make_shared<WriteLog>();
};

/// A one-thread executor for tests that must observe a blocked thread. If the code under test blocks
/// the thread, the test fails on its own timeout; the context and thread are then leaked on purpose,
/// because a blocked thread cannot be joined and the failure must not become a hang.
struct OneThreadExecutor
{
  std::shared_ptr<boost::asio::io_context> context = std::make_shared<boost::asio::io_context>();
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work =
    boost::asio::make_work_guard(*context);
  std::thread thread{[context = context]
    {
      context->run();
    }};

  OneThreadExecutor() = default;
  OneThreadExecutor(const OneThreadExecutor&) = delete;
  OneThreadExecutor& operator=(const OneThreadExecutor&) = delete;

  boost::asio::any_io_executor executor() const
  {
    return context->get_executor();
  }

  ~OneThreadExecutor()
  {
    work.reset();
    context->stop();
    if (thread.joinable())
    {
      thread.detach();
    }
  }
};

}  // namespace ua::test

#endif  // UA_TEST_POSTING_WRITES_NAMESPACE_H
