// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_SESSION_RESOURCE_REGISTRY_H
#define UA_SESSION_RESOURCE_REGISTRY_H

#include "ua_logger.h"
#include "ua_node_id.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>

namespace ua::detail
{

/// AddressSpace-owned bridge from a closed SessionId to implementation-private resource cleanup.
/// Registrations own their callback; the registry retains only a weak reference to each one.
class SessionResourceRegistry final : public std::enable_shared_from_this<SessionResourceRegistry>
{
public:
  using Cleanup = std::function<void(const NodeId&)>;

  class Registration final
  {
  public:
    Registration(const Registration&) = delete;
    Registration& operator=(const Registration&) = delete;
    Registration(Registration&&) = delete;
    Registration& operator=(Registration&&) = delete;
    ~Registration();

  private:
    struct Entry;

    Registration(std::weak_ptr<SessionResourceRegistry> registry, uint64_t id, std::shared_ptr<Entry> entry);

    std::weak_ptr<SessionResourceRegistry> mRegistry;
    uint64_t mId;
    std::shared_ptr<Entry> mEntry;

    friend class SessionResourceRegistry;
  };

  std::shared_ptr<Registration> register_cleanup(Cleanup cleanup);

  /// Publishes one closed SessionId to every registration that existed at publication start.
  /// Callbacks run outside the registry mutex; exceptions are contained, converted and logged.
  void release_session(const NodeId& sessionId) noexcept;

  void set_logger(Logger logger);

private:
  using Entry = Registration::Entry;

  void unregister(uint64_t id) noexcept;

  std::mutex mMutex;
  std::map<uint64_t, std::weak_ptr<Entry>> mEntries;
  uint64_t mNextId{1};
  Logger mLogger;
};

}  // namespace ua::detail

#endif  // UA_SESSION_RESOURCE_REGISTRY_H
