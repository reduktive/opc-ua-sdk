// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// AddressSpace::codec_namespace_context (public API review D5, API-D5.1): the address space builds the
// codec's namespace context itself, resolving URIs through a weak reference, so the core codec header names
// no address-space type.

#include <gtest/gtest.h>

#include <boost/asio/thread_pool.hpp>

#include <chrono>
#include <optional>
#include <thread>

#include "ua_address_space.h"
#include "ua_codec_namespace_context.h"
#include "ua_exceptions.h"
#include "ua_namespace_array.h"

namespace
{

TEST(AddressSpaceCodecContext, ResolvesThroughTheAddressSpaceWithoutKeepingItAlive)
{
  boost::asio::thread_pool pool{1};
  std::optional<ua::AddressSpace> addressSpace{
    ua::AddressSpace::create("urn:test:codec-context", pool.get_executor())};
  const ua::CodecNamespaceContext context = addressSpace->codec_namespace_context();
  ASSERT_TRUE(context.getNamespaceIndex);
  EXPECT_EQ(context.getNamespaceIndex("urn:test:codec-context"),
    addressSpace->namespace_array().get_namespace_index("urn:test:codec-context"));
  EXPECT_EQ(context.getNamespaceIndex("http://opcfoundation.org/UA/"), 0u);

  addressSpace.reset();
  // Work already posted may hold the address space for a moment; the context must not be what keeps it.
  bool released = false;
  for (int attempt = 0; attempt < 200 && !released; ++attempt)
  {
    try
    {
      (void)context.getNamespaceIndex("urn:test:codec-context");
      std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    catch (const ua::UaException&)
    {
      released = true;
    }
  }
  EXPECT_TRUE(released) << "the context holds the address space weakly: once it is gone, resolution fails";
}

}  // namespace
