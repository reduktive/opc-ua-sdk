// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.
#pragma once

#include "ua_default_base_node.h"
#include "ua_sampling_engine.h"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace ua::test_utils
{

/// A `SamplingEngine` reader for tests that build the engine without a namespace: reads each item with its
/// in-memory Node's own `read_value`, for the caller's identity, one item after another. An item whose Node
/// is not an in-memory `default_ns::BaseNode` is answered Bad_InternalError. Each next read starts on an
/// executor turn of its own, so a Node that answers inline neither recurses nor overlaps the next read, and a
/// tick of N items whose reads each take a fixed time takes N times as long.
inline default_ns::SamplingEngine::ValueReader node_value_reader(boost::asio::any_io_executor executor)
{
  using Engine = default_ns::SamplingEngine;

  struct Reads
  {
    boost::asio::any_io_executor executor;
    std::shared_ptr<const CallerInfo> caller;
    std::vector<Engine::ValueRead> items;
    std::vector<DataValueResult> results;
    std::function<void(std::optional<std::vector<DataValueResult>>)> complete;
  };

  struct Next
  {
    static void read(const std::shared_ptr<Reads>& reads)
    {
      const size_t index = reads->results.size();
      if (index == reads->items.size())
      {
        auto complete = std::move(reads->complete);
        complete(std::move(reads->results));
        return;
      }
      const auto& item = reads->items[index];
      const auto* node = dynamic_cast<const default_ns::BaseNode*>(item.node.get());
      if (node == nullptr)
      {
        reads->results.push_back(DataValueResult{StatusCode{Status::BadInternalError}});
        read(reads);
        return;
      }
      node->read_value(0,
        true,
        item.value,
        reads->caller ? reads->caller->identity.get() : nullptr,
        [reads](DataValueResult result)
        {
          reads->results.push_back(std::move(result));
          boost::asio::post(reads->executor, [reads] { read(reads); });
        });
    }
  };

  return [executor = std::move(executor)](std::shared_ptr<const CallerInfo> caller,
           std::vector<Engine::ValueRead>
             items,
           std::function<void(std::optional<std::vector<DataValueResult>>)>
             complete)
  {
    auto reads = std::make_shared<Reads>();
    reads->executor = executor;
    reads->caller = std::move(caller);
    reads->items = std::move(items);
    reads->results.reserve(reads->items.size());
    reads->complete = std::move(complete);
    Next::read(reads);
  };
}

}  // namespace ua::test_utils
