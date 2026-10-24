// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The accessor's synchronous forms refuse on a thread of the address space's executor and complete
/// elsewhere (COMP-ADDRSP-ACCESSOR-SYNC-01).
///
/// The executor is a `boost::asio::io_context` run by one thread. Every object the posted handlers touch is
/// owned by a shared Rig, so a thread left behind by a timeout never touches the test's stack.

#include <gtest/gtest.h>

#include <chrono>
#include <exception>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>

#include "ua_address_space.h"
#include "ua_data_value.h"
#include "ua_exceptions.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_localized_text.h"
#include "ua_node_accessor.h"
#include "ua_node_class.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_to_string.h"
#include "ua_variant.h"
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/executor_work_guard.hpp>

using namespace ua;
using namespace std::chrono_literals;

namespace
{

/// An io_context run by one thread, an address space created on it, and a Variable V holding the Int32 1.
struct Rig
{
  explicit Rig(const std::string& uri)
    : io(std::make_shared<boost::asio::io_context>()), guard(boost::asio::make_work_guard(*io)),
      space(AddressSpace::create(uri, io->get_executor()))
  {
    auto ioRef = io;
    thread = std::thread([ioRef] { ioRef->run(); });
  }

  ~Rig()
  {
    guard.reset();
    io->stop();
    if (thread.joinable())
    {
      if (thread.get_id() == std::this_thread::get_id())
      {
        thread.detach();
      }
      else
      {
        thread.join();
      }
    }
  }

  Rig(const Rig&) = delete;
  Rig& operator=(const Rig&) = delete;

  /// Creates V with the Int32 1 from the test's thread; false when it cannot.
  bool create_variable()
  {
    auto created = space.try_create_sync<VariableAccessor>(NodeId{1, "accessor-sync:V"}, NodeClass::Variable);
    if (created.is_bad())
    {
      return false;
    }
    v.emplace(created.value());
    return v->try_write_value_sync(DataValue{Variant{int32_t{1}}}).is_good();
  }

  /// Gives up on a handler that did not finish: the thread is left to end on its own.
  void abandon()
  {
    guard.reset();
    io->stop();
    if (thread.joinable())
    {
      thread.detach();
    }
  }

  std::shared_ptr<boost::asio::io_context> io;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard;
  AddressSpace space;
  std::optional<VariableAccessor> v;
  std::thread thread;
};

/// V as the address space holds it, found from the test's thread.
std::optional<VariableAccessor> find_v(Rig& rig)
{
  auto looked = rig.space.try_find_sync<VariableAccessor>(NodeId{1, "accessor-sync:V"});
  if (looked.is_bad())
  {
    return std::nullopt;
  }
  return looked.value();
}

/// The Int32 in V's Value as read from the test's thread; nullopt when it is not an Int32.
std::optional<int32_t> value_of_v(Rig& rig)
{
  auto found = find_v(rig);
  if (!found)
  {
    return std::nullopt;
  }
  auto read = found->try_read_value_sync();
  if (read.is_bad() || !read.value().value().is_int32())
  {
    return std::nullopt;
  }
  return read.value().value().as<int32_t>();
}

/// What a refused form leaves for the test: the status and the ErrorDetail id, or the thrown pair.
struct Refusal
{
  Status status{Status::Good};
  std::string detailId;
  bool threw{false};
};

template<typename R>
Refusal refusal_of(const R& result)
{
  Refusal refusal;
  refusal.status = result.status_code().as_status();
  const ErrorDetail* detail = result.error_detail();
  refusal.detailId = detail != nullptr ? detail->code : std::string{"<no detail>"};
  return refusal;
}

template<typename F>
Refusal thrown_by(F&& form)
{
  Refusal refusal;
  try
  {
    form();
  }
  catch (const UaException& e)
  {
    refusal.threw = true;
    refusal.status = e.status();
    const ErrorDetail* detail = e.detail();
    refusal.detailId = detail != nullptr ? detail->code : std::string{"<no detail>"};
  }
  catch (...)
  {
    refusal.threw = true;
    refusal.status = Status::BadInternalError;
    refusal.detailId = "<not a UaException>";
  }
  return refusal;
}

}  // namespace

// @relation(AC-COMP-ADDRSP-ACCESSOR-SYNC-01-A-TRY-FORM-ON-AN-ADDRESS-SPACE-THREAD-ANSWERS-BAD-WOULDBLOCK, scope=function)
TEST(NodeAccessorSync, TryFormOnAnAddressSpaceThreadAnswersBadWouldBlock)
{
  auto rig = std::make_shared<Rig>("urn:test:node-accessor-sync-try");
  ASSERT_TRUE(rig->create_variable());

  auto promise = std::make_shared<std::promise<std::vector<Refusal>>>();
  auto future = promise->get_future();
  boost::asio::post(*rig->io,
    [rig, promise]
    {
      std::vector<Refusal> results;
      VariableAccessor& v = *rig->v;
      results.push_back(refusal_of(v.try_write_value_sync(DataValue{Variant{int32_t{2}}})));
      results.push_back(refusal_of(v.try_read_value_sync()));
      results.push_back(refusal_of(v.try_get_references_sync()));
      results.push_back(refusal_of(v.try_add_reference_sync(
        NodeId{ReferenceTypeId::HasComponent}, NodeId{ObjectId::ObjectsFolder}, true)));
      promise->set_value(std::move(results));
    });

  if (future.wait_for(5s) != std::future_status::ready)
  {
    rig->abandon();
    FAIL() << "the handler did not finish within 5 s";
  }
  const auto results = future.get();
  ASSERT_EQ(results.size(), 4u);
  const char* names[] = {
    "try_write_value_sync", "try_read_value_sync", "try_get_references_sync", "try_add_reference_sync"};
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    EXPECT_EQ(results[i].status, Status::BadWouldBlock) << names[i];
    EXPECT_EQ(results[i].detailId, "WouldBlock") << names[i];
  }

  const auto value = value_of_v(*rig);
  ASSERT_TRUE(value.has_value()) << "V's Value is not an Int32";
  EXPECT_EQ(*value, 1) << "V's Value was written by a refused form";

  auto found = find_v(*rig);
  ASSERT_TRUE(found.has_value());
  auto references = found->try_get_references_sync();
  ASSERT_TRUE(references.is_good()) << to_string(references.status_code());
  bool hasTarget = false;
  for (const auto& reference : references.value())
  {
    if (reference.target_id() == ExpandedNodeId{NodeId{ObjectId::ObjectsFolder}})
    {
      hasTarget = true;
    }
  }
  EXPECT_FALSE(hasTarget) << "V holds a Reference to i=85 added by a refused form";
}

// @relation(AC-COMP-ADDRSP-ACCESSOR-SYNC-01-A-SYNC-FORM-ON-AN-ADDRESS-SPACE-THREAD-THROWS-BAD-WOULDBLOCK, scope=function)
TEST(NodeAccessorSync, SyncFormOnAnAddressSpaceThreadThrowsBadWouldBlock)
{
  auto rig = std::make_shared<Rig>("urn:test:node-accessor-sync-throw");
  ASSERT_TRUE(rig->create_variable());
  rig->v->set_display_name(LocalizedText{"", "V"});

  auto promise = std::make_shared<std::promise<std::vector<Refusal>>>();
  auto future = promise->get_future();
  boost::asio::post(*rig->io,
    [rig, promise]
    {
      std::vector<Refusal> results;
      VariableAccessor& v = *rig->v;
      results.push_back(thrown_by([&v] { v.write_value_sync(DataValue{Variant{int32_t{2}}}); }));
      results.push_back(thrown_by([&v] { (void)v.read_value_sync(); }));
      results.push_back(thrown_by([&v] { v.set_display_name(LocalizedText{"", "W"}); }));
      promise->set_value(std::move(results));
    });

  if (future.wait_for(5s) != std::future_status::ready)
  {
    rig->abandon();
    FAIL() << "the handler did not finish within 5 s";
  }
  const auto results = future.get();
  ASSERT_EQ(results.size(), 3u);
  const char* names[] = {"write_value_sync", "read_value_sync", "set_display_name"};
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    EXPECT_TRUE(results[i].threw) << names[i] << " did not throw";
    EXPECT_EQ(results[i].status, Status::BadWouldBlock) << names[i];
  }

  const auto value = value_of_v(*rig);
  ASSERT_TRUE(value.has_value()) << "V's Value is not an Int32";
  EXPECT_EQ(*value, 1) << "V's Value was written by a refused form";

  auto found = find_v(*rig);
  ASSERT_TRUE(found.has_value());
  const Variant name = found->read_attribute(AttributeId::DisplayName);
  ASSERT_TRUE(name.is_localized_text());
  EXPECT_EQ(name.as<LocalizedText>().text(), "V") << "V's DisplayName was changed by a refused setter";
}

// @relation(AC-COMP-ADDRSP-ACCESSOR-SYNC-01-A-FORM-OFF-THE-EXECUTOR-COMPLETES, scope=function)
TEST(NodeAccessorSync, AFormOffTheExecutorCompletes)
{
  auto rig = std::make_shared<Rig>("urn:test:node-accessor-sync-off");
  ASSERT_TRUE(rig->create_variable());
  VariableAccessor& v = *rig->v;

  const auto written = v.try_write_value_sync(DataValue{Variant{int32_t{2}}});
  EXPECT_TRUE(written.is_good()) << to_string(written.status_code());

  const auto read = v.try_read_value_sync();
  ASSERT_TRUE(read.is_good()) << to_string(read.status_code());
  ASSERT_TRUE(read.value().value().is_int32());
  EXPECT_EQ(read.value().value().as<int32_t>(), 2);

  EXPECT_NO_THROW(v.set_display_name(LocalizedText{"", "W"}));
  const Variant name = v.read_attribute(AttributeId::DisplayName);
  ASSERT_TRUE(name.is_localized_text());
  EXPECT_EQ(name.as<LocalizedText>().text(), "W");
}
