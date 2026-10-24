// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_structure.h"
#include "ua_binary_codec.h"
#include "ua_memory_stream.h"
#include "ua_codec_namespace_context.h"
#include "ua_resource_budgets.h"
#include "ua_expanded_node_id.h"
#include <cstring>

namespace ua
{

bool equivalent(const Structure& a, const Structure& b)
{
  // Quick check: if they are the same object, they are trivially equivalent.
  if (&a == &b)
  {
    return true;
  }

  // Compare type identities. If the types differ, they cannot be equivalent.
  if (a.type_id() != b.type_id())
  {
    return false;
  }

  try
  {
    // Encode both structures to binary and compare the byte sequences.
    constexpr size_t maxWork = 1024;
    const CodecNamespaceContext emptyConfig;

    memory_stream_device::Dynamic deviceA;
    MemoryStream streamA{deviceA};
    UaBinaryEncoder encoderA(emptyConfig, streamA);
    const StackDepth limitA{maxWork};
    encoderA.encode(limitA, a);

    memory_stream_device::Dynamic deviceB;
    MemoryStream streamB{deviceB};
    UaBinaryEncoder encoderB(emptyConfig, streamB);
    const StackDepth limitB{maxWork};
    encoderB.encode(limitB, b);

    auto bytesA = deviceA.get_data();
    auto bytesB = deviceB.get_data();

    if (bytesA.size() != bytesB.size())
    {
      return false;
    }

    return std::memcmp(bytesA.data(), bytesB.data(), bytesA.size()) == 0;
  }
  catch (...)
  {
    // If encoding fails for any reason, the structures are not equivalent.
    return false;
  }
}

}  // namespace ua
