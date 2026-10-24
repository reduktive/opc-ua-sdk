// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Precompiled-header payload for the SDK build (opt-in via UASDK_USE_PCH).
//
// CONTRACT: this header lists ONLY stable, expensive-to-parse THIRD-PARTY and
// standard-library headers. It deliberately contains NO SDK headers - editing an
// SDK header must not invalidate the PCH and force a full rebuild. Adding an SDK
// header here would couple every TU's incremental rebuild to that header's churn.
//
// Membership rule: a header belongs here only if it is (a) external or std, (b)
// effectively never edited, and (c) parsed by a large fraction of TUs. The list
// mirrors the SDK's actual Boost.Asio usage (fine-grained headers, not the
// `<boost/asio.hpp>` umbrella) so the PCH does not drag in unused Asio subsystems.

#ifndef UASDK_PCH_H
#define UASDK_PCH_H

// -- Boost.Asio (the executor/strand core is the dominant template-parse cost) --
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>

// -- fmt --
#include <fmt/format.h>

// -- Standard library (heavy and/or ubiquitous across the SDK) --
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#endif  // UASDK_PCH_H
