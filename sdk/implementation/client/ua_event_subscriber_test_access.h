// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_EVENT_SUBSCRIBER_TEST_ACCESS_H
#define UA_EVENT_SUBSCRIBER_TEST_ACCESS_H

/// @file
/// @brief Friend test interface for @ref ua::client::detail::EventSubscriberImpl (the design specification "no
/// public API
///        pollution for testing"). Exposes the strand-private backbone / consumer bookkeeping and the last
///        composite filter sent per backbone so unit tests can assert coalescing + demux + filter-union
///        outcomes without a public getter.
/// @ingroup client

#include "ua_event_filter.h"
#include "ua_event_subscriber_impl.h"
#include "ua_filter_operator.h"
#include "ua_literal_operand.h"
#include "ua_node_id.h"
#include "ua_on_strand.h"
#include "ua_result.h"
#include "ua_sync_wait.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <type_traits>

namespace ua::client::detail
{

struct EventSubscriberTestAccess
{
  [[nodiscard]] static std::size_t backbone_count(const EventSubscriberImpl& impl)
  {
    return impl.mBackbones.size();
  }

  [[nodiscard]] static std::size_t created_backbone_count(const EventSubscriberImpl& impl)
  {
    std::size_t count = 0;
    for (const auto& backbone : impl.mBackbones)
    {
      if (backbone.created)
      {
        ++count;
      }
    }
    return count;
  }

  [[nodiscard]] static std::size_t consumer_count(const EventSubscriberImpl& impl)
  {
    return impl.mConsumers.size();
  }

  [[nodiscard]] static std::size_t consumers_on_backbone(const EventSubscriberImpl& impl, std::size_t index)
  {
    return impl.mBackbones.at(index).consumers.size();
  }

  /// The last composite EventFilter sent to the (single default) backbone, or nullopt if none created.
  [[nodiscard]] static std::optional<ua::EventFilter> last_sent_filter(
    const EventSubscriberImpl& impl, std::size_t index = 0)
  {
    if (index >= impl.mBackbones.size() || !impl.mBackbones[index].created)
    {
      return std::nullopt;
    }
    return impl.mBackbones[index].lastSentFilter;
  }

  /// The index of the created backbone whose last-sent composite WhereClause carries an OfType(@p typeId)
  /// element, or nullopt. Lets an event test find the EventRouter's per-type dedicated backbone (General /
  /// Semantic) without racing the wire (Slice 2b).
  [[nodiscard]] static std::optional<std::size_t> backbone_index_for_of_type(
    const EventSubscriberImpl& impl, const ua::NodeId& typeId)
  {
    for (std::size_t i = 0; i < impl.mBackbones.size(); ++i)
    {
      if (!impl.mBackbones[i].created)
      {
        continue;
      }
      for (const auto& element : impl.mBackbones[i].lastSentFilter.where_clause().elements())
      {
        if (element.filter_operator() != ua::FilterOperator::OfType || element.filter_operands().empty())
        {
          continue;
        }
        const auto* literal = dynamic_cast<const ua::LiteralOperand*>(element.filter_operands()[0].get());
        if (literal == nullptr)
        {
          continue;
        }
        const ua::Result<ua::NodeId> asNode = literal->value().template to<ua::NodeId>();
        if (asNode.is_good() && asNode.value() == typeId)
        {
          return i;
        }
      }
    }
    return std::nullopt;
  }

  /// Thread-safe variants for tests that inspect while the subscriber executor is running.
  [[nodiscard]] static std::optional<ua::EventFilter> last_sent_filter_thread_safe(
    const EventSubscriberImpl& impl, std::size_t index = 0)
  {
    return read_on_strand(
      impl, [index](const auto& subscriber) { return last_sent_filter(subscriber, index); });
  }

  [[nodiscard]] static std::optional<std::size_t> backbone_index_for_of_type_thread_safe(
    const EventSubscriberImpl& impl, const ua::NodeId& typeId)
  {
    return read_on_strand(
      impl, [typeId](const auto& subscriber) { return backbone_index_for_of_type(subscriber, typeId); });
  }

  /// Whether the backbone MonitoredItem exists ON THE WIRE. A test that changes server state before
  /// this is true races the create, and the event it emits reaches nobody.
  [[nodiscard]] static std::size_t created_backbone_count_thread_safe(const EventSubscriberImpl& impl)
  {
    return read_on_strand(impl, [](const auto& subscriber) { return created_backbone_count(subscriber); });
  }

  [[nodiscard]] static std::uint32_t backbone_client_handle_thread_safe(
    const EventSubscriberImpl& impl, std::size_t index)
  {
    return read_on_strand(
      impl, [index](const auto& subscriber) { return backbone_client_handle(subscriber, index); });
  }

  /// The CLIENT-assigned backbone handle (the inbound-demux key the server echoes in
  /// `EventFieldList.client_handle`) of backbone @p index.
  [[nodiscard]] static std::uint32_t backbone_client_handle(
    const EventSubscriberImpl& impl, std::size_t index)
  {
    return impl.mBackbones.at(index).backboneClientHandle;
  }

  /// The create-time server subscription id of backbone @p index  -  the id `on_reconnect_recovered_async`
  /// matches against its affected-set argument to scope the tracker reset to the recreated backbones.
  [[nodiscard]] static std::uint32_t backbone_subscription_id(
    const EventSubscriberImpl& impl, std::size_t index)
  {
    return impl.mBackbones.at(index).subscriptionId;
  }

  [[nodiscard]] static bool closing(const EventSubscriberImpl& impl)
  {
    return impl.mClosing;
  }

private:
  template<typename Reader>
  static auto read_on_strand(const EventSubscriberImpl& impl,
    Reader reader) -> std::invoke_result_t<Reader, const EventSubscriberImpl&>
  {
    using Result = std::invoke_result_t<Reader, const EventSubscriberImpl&>;
    if (impl.mStrand.running_in_this_thread())
    {
      return std::invoke(std::move(reader), impl);
    }

    // Off the strand, the wait is blocking_call's: refused (thrown) on a thread of the subscriber's
    // executor, and answered with an error, not a hang, when the subscriber is gone before the hop runs.
    // An exception from @p reader is rethrown here as a UaException.
    auto held =
      ua::async::detail::blocking_call<ua::Result<Result>>(boost::asio::any_io_executor{impl.mStrand},
        [&impl, &reader](std::function<void(ua::Result<Result>)> complete)
        {
          ua::async::post_borrowing(&impl,
            impl.mStrand,
            impl.mLogger,
            [reader = std::move(reader), complete = std::move(complete)](
              const EventSubscriberImpl& strong) mutable
            {
              try
              {
                complete(ua::Result<Result>{std::invoke(std::move(reader), strong)});
              }
              catch (...)
              {
                complete(ua::Result<Result>{ua::exception_to_status_code(std::current_exception())});
              }
            })();
        });
    return std::move(held).value();
  }
};

}  // namespace ua::client::detail

#endif  // UA_EVENT_SUBSCRIBER_TEST_ACCESS_H
