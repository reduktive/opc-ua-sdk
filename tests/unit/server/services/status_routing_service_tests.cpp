// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How the services answer the code a namespace puts on its answer. Where the service builds the client's
// result from the answer, the code reaches the client: Read answers a Good subcode or an Uncertain code with
// the Value, combined with the Value's own status, and an Uncertain answer without a Value as the item's
// status; a ValueAsText or ValueAsDictionaryEntries Read answers the code of its owner's Value read with the
// projection; Browse and TranslateBrowsePaths answer the code of a page of References with the References,
// and log a code with a SubCode they do not answer (COMP-SVR-STATUS-ROUTING-01). Where the SDK acts on the
// answer itself, an Uncertain answer is refused whether or not it holds a value: the Write service does not
// decide a null write on an AllowNulls Value the namespace is uncertain of, nor translate a
// ValueAsDictionaryEntries write from an owner Value it is uncertain of, and the access control grants
// nothing on an Uncertain answer about effective permissions (COMP-SVR-STATUS-ROUTING-02).
//
// The namespace is a default namespace whose answers to Value reads, References reads and
// effective-permission questions the test replaces for the Nodes it names; every other answer is the default
// namespace's. The services log to a sink the test reads.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "ua_access_level_type.h"
#include "ua_address_space.h"
#include "ua_attribute_id.h"
#include "ua_attribute_service_set.h"
#include "ua_browse_description.h"
#include "ua_browse_direction.h"
#include "ua_browse_path.h"
#include "ua_browse_path_result.h"
#include "ua_browse_path_target.h"
#include "ua_browse_request.h"
#include "ua_browse_response.h"
#include "ua_browse_service.h"
#include "ua_datatype_id.h"
#include "ua_default_namespace.h"
#include "ua_enum_value_type.h"
#include "ua_error_detail.h"
#include "ua_expanded_node_id.h"
#include "ua_localized_text.h"
#include "ua_log_entry.h"
#include "ua_log_level.h"
#include "ua_log_sink.h"
#include "ua_logger.h"
#include "ua_status_routing.h"
#include "ua_node.h"
#include "ua_node_accessor.h"
#include "ua_permission_type.h"
#include "ua_qualified_name.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_relative_path.h"
#include "ua_relative_path_element.h"
#include "ua_server.h"
#include "ua_service_fault.h"
#include "ua_to_string.h"
#include "ua_translate_browse_paths_service.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"
#include <boost/asio/thread_pool.hpp>

#include "access_control_test_support.h"
#include "stubs.h"
#include "test_components.h"
#include "test_utilities.h"

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;

namespace
{

/// A default namespace whose answers the test replaces for the Nodes it names: a read of a Node's Value, a
/// read of a Node's References (the References the store holds, with a code the test gives) and the
/// effective permissions of a Node (which the immediate form then declines, so the asynchronous form is
/// asked). Every other answer is the default namespace's.
class ScriptedAnswerNamespace final : public default_ns::Namespace
{
public:
  static std::shared_ptr<ScriptedAnswerNamespace> create(
    string_view uri, boost::asio::any_io_executor executor)
  {
    return std::shared_ptr<ScriptedAnswerNamespace>(new ScriptedAnswerNamespace(uri, std::move(executor)));
  }

  /// Answers every later read of @p nodeId's Value with @p answer.
  void answer_value_reads(const NodeId& nodeId, DataValueResult answer)
  {
    const std::lock_guard lock{mMutex};
    mValueAnswers.insert_or_assign(nodeId, std::move(answer));
  }

  /// Answers every later read of @p nodeId's References with the References the store answers and @p code.
  void code_reference_reads(const NodeId& nodeId, StatusCode code)
  {
    const std::lock_guard lock{mMutex};
    mReferenceCodes.insert_or_assign(nodeId, std::move(code));
  }

  /// Answers the next reads of @p nodeId's References, one each, with the References the store answers and
  /// the codes of @p codes in order; later reads are answered as @ref code_reference_reads says.
  void code_reference_pages(const NodeId& nodeId, const std::vector<StatusCode>& codes)
  {
    const std::lock_guard lock{mMutex};
    auto& queue = mReferencePageCodes[nodeId];
    queue.insert(queue.end(), codes.begin(), codes.end());
  }

  /// Answers every later question about @p nodeId's effective permissions with @p answer.
  void answer_permissions(const NodeId& nodeId, Result<PermissionType> answer)
  {
    const auto found = find_node(nodeId, std::nullopt);
    ASSERT_TRUE(found.has_value() && found->is_good()) << nodeId.as_definition();
    const std::lock_guard lock{mMutex};
    mPermissionAnswers.insert_or_assign(nodeId, std::move(answer));
    mPermissionNodes.insert(found->value().get());
  }

  std::optional<PermissionType> effective_permissions(
    const AccessIdentity& identity, const Node* node) const override
  {
    {
      const std::lock_guard lock{mMutex};
      if (mPermissionNodes.contains(node))
      {
        return std::nullopt;
      }
    }
    return default_ns::Namespace::effective_permissions(identity, node);
  }

  void effective_permissions_async(const RequestInfo& request, shared_ptr<const AccessIdentity> identity,
    std::optional<std::vector<NodeId>> nodes, EffectivePermissionsCallback callback) override
  {
    std::vector<std::optional<Result<PermissionType>>> scripted;
    if (nodes)
    {
      const std::lock_guard lock{mMutex};
      for (const auto& nodeId : *nodes)
      {
        const auto found = mPermissionAnswers.find(nodeId);
        scripted.push_back(found == mPermissionAnswers.end()
                             ? std::nullopt
                             : std::optional<Result<PermissionType>>{found->second});
      }
    }
    default_ns::Namespace::effective_permissions_async(request,
      std::move(identity),
      std::move(nodes),
      [scripted, callback](EffectivePermissionsResult answer)
      {
        if (!answer.batchStatus.is_bad())
        {
          for (std::size_t k = 0; k < answer.items.size() && k < scripted.size(); ++k)
          {
            if (scripted[k])
            {
              answer.items[k] = *scripted[k];
            }
          }
        }
        callback(std::move(answer));
      });
  }

  void read_values_async(const RequestInfo& request, const CallerInfo* caller,
    std::span<const ValueReadItem> items, Duration maxAge, bool setSourceTimestamp,
    std::function<void(BatchResult<DataValueResult>)> complete) override
  {
    std::vector<std::optional<DataValueResult>> scripted;
    {
      const std::lock_guard lock{mMutex};
      for (const auto& item : items)
      {
        const auto found = mValueAnswers.find(item.value.node_id());
        scripted.push_back(
          found == mValueAnswers.end() ? std::nullopt : std::optional<DataValueResult>{found->second});
      }
    }
    default_ns::Namespace::read_values_async(request,
      caller,
      items,
      maxAge,
      setSourceTimestamp,
      [scripted, complete](BatchResult<DataValueResult> answer)
      {
        if (!answer.batchStatus.is_bad())
        {
          for (std::size_t k = 0; k < answer.items.size() && k < scripted.size(); ++k)
          {
            if (scripted[k])
            {
              answer.items[k] = *scripted[k];
            }
          }
        }
        complete(std::move(answer));
      });
  }

  void read_references_async(const RequestInfo& request, std::span<const ReferenceQuery> queries,
    std::function<void(BatchResult<NodeReferencesResult>)> complete) override
  {
    std::vector<std::optional<StatusCode>> codes;
    {
      const std::lock_guard lock{mMutex};
      for (const auto& query : queries)
      {
        if (const auto paged = mReferencePageCodes.find(query.nodeId);
            paged != mReferencePageCodes.end() && !paged->second.empty())
        {
          codes.emplace_back(paged->second.front());
          paged->second.pop_front();
          continue;
        }
        const auto found = mReferenceCodes.find(query.nodeId);
        codes.push_back(
          found == mReferenceCodes.end() ? std::nullopt : std::optional<StatusCode>{found->second});
      }
    }
    default_ns::Namespace::read_references_async(request,
      queries,
      [codes, complete](BatchResult<NodeReferencesResult> answer)
      {
        if (!answer.batchStatus.is_bad())
        {
          for (std::size_t k = 0; k < answer.items.size() && k < codes.size(); ++k)
          {
            if (codes[k] && answer.items[k].is_good())
            {
              NodeReferences page = answer.items[k].value();
              answer.items[k] = NodeReferencesResult{std::move(page), *codes[k]};
            }
          }
        }
        complete(std::move(answer));
      });
  }

private:
  ScriptedAnswerNamespace(string_view uri, boost::asio::any_io_executor executor)
    : default_ns::Namespace(uri, std::move(executor))
  {}

  mutable std::mutex mMutex;
  std::unordered_map<NodeId, DataValueResult> mValueAnswers;
  std::unordered_map<NodeId, StatusCode> mReferenceCodes;
  std::unordered_map<NodeId, std::deque<StatusCode>> mReferencePageCodes;
  std::unordered_map<NodeId, Result<PermissionType>> mPermissionAnswers;
  std::unordered_set<const Node*> mPermissionNodes;
};

/// Records what is logged, its structured fields rendered as text.
class RecordingLogSink final : public LogSink
{
public:
  struct Entry
  {
    LogLevel level;
    std::string message;
    std::vector<std::string> fieldValues;
  };

  void log(const LogEntry& entry) override
  {
    Entry copy{entry.level, entry.message, {}};
    for (const auto& field : entry.fields)
    {
      std::visit(
        [&copy](const auto& value)
        {
          std::ostringstream rendered;
          rendered << value;
          copy.fieldValues.push_back(rendered.str());
        },
        field.value);
    }
    const std::lock_guard lock{mMutex};
    mEntries.push_back(std::move(copy));
  }

  /// Whether a Warning was logged with a field that renders as @p status.
  bool warned_of(const StatusCode& status) const
  {
    const std::string text = to_string(status);
    const std::lock_guard lock{mMutex};
    return std::ranges::any_of(mEntries,
      [&text](const Entry& entry)
      {
        return entry.level == LogLevel::Warning &&
               std::ranges::find(entry.fieldValues, text) != entry.fieldValues.end();
      });
  }

private:
  mutable std::mutex mMutex;
  std::vector<Entry> mEntries;
};

/// A Session whose services log to the logger it is given.
class LoggingSessionInfo final : public SessionInfoStub
{
public:
  LoggingSessionInfo(ua::server::Server server, boost::asio::any_io_executor executor, Logger logger)
    : SessionInfoStub(std::move(server), std::move(executor)), mLogger(std::move(logger))
  {}

  Logger logger() const override
  {
    return mLogger;
  }

private:
  Logger mLogger;
};

struct ServiceOutcome
{
  bool answered{false};
  StatusCode serviceResult;
};

struct ReadOutcome : ServiceOutcome
{
  std::vector<DataValue> results;
};

struct WriteOutcome : ServiceOutcome
{
  std::vector<StatusCode> results;
};

struct BrowseOutcome : ServiceOutcome
{
  std::vector<BrowseResult> results;
};

struct TranslateOutcome : ServiceOutcome
{
  std::vector<BrowsePathResult> results;
};

/// A server with one ScriptedAnswerNamespace registered, and a Session on it.
struct RoutingHarness
{
  RoutingHarness()
  {
    nameSpace = ScriptedAnswerNamespace::create("urn:test:status-routing", threadPool.get_executor());
    CreateConfig cfg{.identity = ApplicationIdentity::load_default(),
      .application = test_utils::create_test_config(),
      .server = ServerConfig{}};
    auto server = Server::create(threadPool.get_executor(),
      std::move(cfg),
      ua::server::ServerComponents{.crypto = ua::test_helpers::test_crypto()});
    index = server.address_space().add_namespace_sync(nameSpace);
    sessionInfo = make_shared<LoggingSessionInfo>(std::move(server),
      threadPool.get_executor(),
      Logger{log, std::make_shared<std::atomic<LogLevel>>(LogLevel::Warning), "test"});
  }

  ~RoutingHarness()
  {
    variables.clear();
    browses.clear();
    sessionInfo.reset();
    ::ua::test_utils::drain_with_timeout(threadPool);
  }

  boost::asio::thread_pool threadPool{4};
  /// What the services log, at Warning and above.
  std::shared_ptr<RecordingLogSink> log = std::make_shared<RecordingLogSink>();
  std::shared_ptr<ScriptedAnswerNamespace> nameSpace;
  uint16_t index{0};
  shared_ptr<SessionInfoStub> sessionInfo;
  std::map<NodeId, VariableAccessor> variables;
  std::vector<shared_ptr<BrowseService>> browses;

  /// A readable and writable Variable of @p dataType holding @p initial, named @p name.
  NodeId create_variable(uint32_t numericId, const std::string& name, NodeId dataType, Variant initial)
  {
    const NodeId nodeId{index, numericId};
    auto created =
      sessionInfo->address_space().try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    EXPECT_TRUE(created.is_good()) << "creating " << nodeId.as_definition();
    if (created.is_good())
    {
      AccessLevelType accessLevel;
      accessLevel.set(AccessLevelType::Bit::CurrentRead);
      accessLevel.set(AccessLevelType::Bit::CurrentWrite);
      created.value().set_access_level(accessLevel);
      created.value().set_browse_name(QualifiedName{index, name});
      created.value().set_display_name(LocalizedText{"", name});
      created.value().set_data_type(std::move(dataType));
      created.value().write_value_sync(DataValue{std::move(initial)});
      variables.insert_or_assign(nodeId, created.value());
    }
    return nodeId;
  }

  /// An Object named @p name.
  NodeId create_object(uint32_t numericId, const std::string& name)
  {
    const NodeId nodeId{index, numericId};
    auto created = sessionInfo->address_space().try_create_node_sync(nodeId, NodeClass::Object);
    EXPECT_TRUE(created.is_good()) << "creating " << nodeId.as_definition();
    if (created.is_good())
    {
      created.value().set_browse_name(QualifiedName{index, name});
    }
    return nodeId;
  }

  /// What @ref create_enumeration created.
  struct EnumerationModel
  {
    NodeId owner;
    NodeId valueAsText;
    NodeId valueAsDictionaryEntries;
    /// The EnumDictionaryEntries row of the owner's Value 2.
    NodeId currentEntry;
  };

  /// A MultiStateValueDiscrete-shaped Variable whose Int64 Value is 2, numbered from @p base, with the
  /// Properties its projections read: EnumValues (1 "Low", 2 "High"), EnumDictionaryEntries (one NodeId per
  /// row), and the ValueAsText and ValueAsDictionaryEntries Properties whose stored Values the projections
  /// replace.
  EnumerationModel create_enumeration(uint32_t base)
  {
    EnumerationModel model;
    model.owner = create_variable(base, "State", NodeId{DataTypeId::Int64}, Variant{int64_t{2}});
    Array<RefStructure<Structure>> entries;
    for (const auto& [value, label] : std::vector<std::pair<int64_t, std::string>>{{1, "Low"}, {2, "High"}})
    {
      auto entry = std::make_unique<EnumValueType>();
      entry->value() = value;
      entry->display_name() = LocalizedText{"", label};
      entries.push_back(RefStructure<Structure>{std::move(entry)});
    }
    const NodeId lowEntry{index, base + 10};
    model.currentEntry = NodeId{index, base + 11};
    const NodeId enumValues =
      create_variable(base + 1, "EnumValues", NodeId{DataTypeId::EnumValueType}, Variant{std::move(entries)});
    const NodeId dictionary = create_variable(base + 2,
      "EnumDictionaryEntries",
      NodeId{DataTypeId::NodeId},
      Variant{Array<NodeId>{Dimensions{2, 1}, {lowEntry, model.currentEntry}}});
    model.valueAsText = create_variable(
      base + 3, "ValueAsText", NodeId{DataTypeId::LocalizedText}, Variant{LocalizedText{"", "Low"}});
    model.valueAsDictionaryEntries = create_variable(
      base + 4, "ValueAsDictionaryEntries", NodeId{DataTypeId::NodeId}, Variant{Array<NodeId>{lowEntry}});
    for (const auto& [property, name] :
      std::vector<std::pair<NodeId, std::string>>{{enumValues, "EnumValues"},
        {dictionary, "EnumDictionaryEntries"},
        {model.valueAsText, "ValueAsText"},
        {model.valueAsDictionaryEntries, "ValueAsDictionaryEntries"}})
    {
      // The Properties are named in namespace 0, as the types define them.
      variables.at(property).set_browse_name(QualifiedName{uint16_t{0}, name});
      link(model.owner, ReferenceTypeId::HasProperty, property);
    }
    return model;
  }

  /// A Reference of @p type from @p source to @p target: the forward half held by the source and the inverse
  /// half held by the target.
  void link(const NodeId& source, ReferenceTypeId type, const NodeId& target)
  {
    auto addressSpace = sessionInfo->address_space();
    auto from = addressSpace.try_find_node_sync(source);
    auto to = addressSpace.try_find_node_sync(target);
    ASSERT_TRUE(from.is_good()) << source.as_definition();
    ASSERT_TRUE(to.is_good()) << target.as_definition();
    EXPECT_TRUE(from.value().try_add_reference_sync(NodeId{type}, ExpandedNodeId{target}, true).is_good())
      << source.as_definition() << " to " << target.as_definition();
    EXPECT_TRUE(to.value().try_add_reference_sync(NodeId{type}, ExpandedNodeId{source}, false).is_good())
      << target.as_definition() << " from " << source.as_definition();
  }

  /// The Value the store holds for @p nodeId, read past the namespace's scripted answers.
  Variant stored_value(const NodeId& nodeId)
  {
    const auto found = variables.find(nodeId);
    if (found == variables.end())
    {
      ADD_FAILURE() << "no Variable " << nodeId.as_definition();
      return {};
    }
    auto read = found->second.try_read_value_sync();
    EXPECT_TRUE(read.is_good()) << "reading " << nodeId.as_definition() << ": "
                                << to_string(read.status_code());
    return read.is_good() ? read.value().value() : Variant{};
  }

  ReadOutcome read(const std::vector<NodeId>& nodeIds)
  {
    ReadRequest request;
    request.request_header().request_handle() = 1;
    request.max_age() = 0;
    request.timestamps_to_return() = TimestampsToReturn::Neither;
    for (const auto& nodeId : nodeIds)
    {
      ReadValueId item;
      item.node_id() = nodeId;
      item.attribute_id() = utils::to_underlying(AttributeId::Value);
      request.nodes_to_read().payload().push_back(std::move(item));
    }
    auto promise = std::make_shared<std::promise<ReadOutcome>>();
    auto future = promise->get_future();
    auto service = AttributeServiceSet::create(sessionInfo,
      std::vector<LocaleId>{"en"},
      0,
      std::move(request),
      threadPool.get_executor(),
      [promise](Response response)
      {
        ReadOutcome outcome;
        outcome.answered = true;
        if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
        {
          outcome.serviceResult = fault->response_header().service_result();
        }
        else if (auto* read = dynamic_cast<ReadResponse*>(response.second.get()))
        {
          outcome.serviceResult = read->response_header().service_result();
          outcome.results.assign(read->results().begin(), read->results().end());
        }
        promise->set_value(std::move(outcome));
      });
    return wait_for(future, "Read");
  }

  /// Writes a null Variant to each of @p nodeIds' Value.
  WriteOutcome write_nulls(const std::vector<NodeId>& nodeIds)
  {
    WriteRequest request;
    request.request_header().request_handle() = 1;
    for (const auto& nodeId : nodeIds)
    {
      WriteValue item;
      item.node_id() = nodeId;
      item.attribute_id() = utils::to_underlying(AttributeId::Value);
      request.nodes_to_write().payload().push_back(std::move(item));
    }
    auto promise = std::make_shared<std::promise<WriteOutcome>>();
    auto future = promise->get_future();
    auto service = AttributeServiceSet::create(sessionInfo,
      1,
      std::move(request),
      threadPool.get_executor(),
      [promise](Response response)
      {
        WriteOutcome outcome;
        outcome.answered = true;
        if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
        {
          outcome.serviceResult = fault->response_header().service_result();
        }
        else if (auto* written = dynamic_cast<WriteResponse*>(response.second.get()))
        {
          outcome.serviceResult = written->response_header().service_result();
          outcome.results.assign(written->results().begin(), written->results().end());
        }
        promise->set_value(std::move(outcome));
      });
    return wait_for(future, "Write");
  }

  /// Browses the forward References of each of @p sources, without TypeDefinitions, at most
  /// @p maxReferencesPerNode of them (0: no limit) to Nodes of the classes in @p nodeClassMask (0: every
  /// class).
  BrowseOutcome browse(
    const std::vector<NodeId>& sources, uint32_t maxReferencesPerNode = 0, uint32_t nodeClassMask = 0)
  {
    BrowseRequest request;
    request.request_header().request_handle() = 1;
    request.requested_max_references_per_node() = maxReferencesPerNode;
    for (const auto& source : sources)
    {
      BrowseDescription description;
      description.node_id() = source;
      description.browse_direction() = BrowseDirection::Forward;
      description.reference_type_id() = NodeId{};
      description.include_subtypes() = true;
      description.node_class_mask() = nodeClassMask;
      // ReferenceType, IsForward, NodeClass, BrowseName and DisplayName (OPC 10000-4 Table 34).
      description.result_mask() = 0x1f;
      request.nodes_to_browse().push_back(std::move(description));
    }
    auto promise = std::make_shared<std::promise<BrowseOutcome>>();
    auto future = promise->get_future();
    browses.push_back(BrowseService::create(sessionInfo,
      std::vector<LocaleId>{"en"},
      1,
      std::move(request),
      threadPool.get_executor(),
      [promise](BrowseService::BrowseServiceResponse response)
      {
        BrowseOutcome outcome;
        outcome.answered = true;
        const auto& body = std::get<shared_ptr<Structure>>(response.response);
        if (auto* fault = dynamic_cast<ServiceFault*>(body.get()))
        {
          outcome.serviceResult = fault->response_header().service_result();
        }
        else if (auto* browsed = dynamic_cast<BrowseResponse*>(body.get()))
        {
          outcome.serviceResult = browsed->response_header().service_result();
          outcome.results.assign(browsed->results().begin(), browsed->results().end());
        }
        promise->set_value(std::move(outcome));
      }));
    return wait_for(future, "Browse");
  }

  /// Translates, for each of @p starts, the path of @p elements forward HasComponent elements, each to a
  /// target named "T".
  TranslateOutcome translate(const std::vector<NodeId>& starts, size_t elements = 1)
  {
    TranslateBrowsePathsToNodeIdsRequest request;
    request.request_header().request_handle() = 1;
    for (const auto& start : starts)
    {
      BrowsePath path;
      path.starting_node() = start;
      for (size_t e = 0; e < elements; ++e)
      {
        RelativePathElement element;
        element.reference_type_id() = NodeId{ReferenceTypeId::HasComponent};
        element.is_inverse() = false;
        element.include_subtypes() = true;
        element.target_name() = QualifiedName{index, "T"};
        path.relative_path().elements().payload().push_back(std::move(element));
      }
      request.browse_paths().payload().push_back(std::move(path));
    }
    auto promise = std::make_shared<std::promise<TranslateOutcome>>();
    auto future = promise->get_future();
    auto service = TranslateBrowsePathsService::create(sessionInfo,
      {"en"},
      1,
      std::move(request),
      threadPool.get_executor(),
      [promise](Response response)
      {
        TranslateOutcome outcome;
        outcome.answered = true;
        if (auto* fault = dynamic_cast<ServiceFault*>(response.second.get()))
        {
          outcome.serviceResult = fault->response_header().service_result();
        }
        else if (auto* translated =
                   dynamic_cast<TranslateBrowsePathsToNodeIdsResponse*>(response.second.get()))
        {
          outcome.serviceResult = translated->response_header().service_result();
          outcome.results.assign(translated->results().begin(), translated->results().end());
        }
        promise->set_value(std::move(outcome));
      });
    return wait_for(future, "TranslateBrowsePaths");
  }

private:
  template<typename Outcome>
  static Outcome wait_for(std::future<Outcome>& future, const char* service)
  {
    if (future.wait_for(10s) != std::future_status::ready)
    {
      ADD_FAILURE() << service << " did not complete";
      return {};
    }
    return future.get();
  }
};

/// A DataValue without a status is Good.
StatusCode status_of(const DataValue& value)
{
  return value.status().value_or(StatusCode{Status::Good});
}

/// The text of a LocalizedText Value, or "<no text>".
std::string text_of(const DataValue& value)
{
  const auto* text = value.value().try_as<LocalizedText>();
  return text != nullptr ? static_cast<std::string>(text->text()) : std::string{"<no text>"};
}

/// A DataValue holding @p value and the status @p status.
DataValue value_with_status(Variant value, Status status)
{
  DataValue dataValue{std::move(value)};
  dataValue.status() = StatusCode{status};
  return dataValue;
}

std::vector<NodeId> targets_of(const BrowseResult& result)
{
  std::vector<NodeId> targets;
  for (const auto& reference : result.references())
  {
    targets.push_back(reference.node_id().node_id());
  }
  return targets;
}

std::vector<NodeId> targets_of(const BrowsePathResult& result)
{
  std::vector<NodeId> targets;
  for (const auto& target : result.targets())
  {
    targets.push_back(target.target_id().node_id());
  }
  return targets;
}

/// Expects @p status to be the refusal of an Uncertain answer the SDK acts on: Bad_InternalError, the
/// ErrorDetail code @p code, and the namespace's @p uncertain as the inner status.
void expect_uncertain_refusal(
  const StatusCode& status, const std::string& code, Status uncertain, const std::string& subject)
{
  EXPECT_EQ(status.as_status(), Status::BadInternalError) << subject << ": " << to_string(status);
  const auto& detail = status.shared_detail();
  ASSERT_NE(detail, nullptr) << subject << ": the refusal carries no ErrorDetail";
  EXPECT_EQ(detail->code, code) << subject;
  EXPECT_EQ(detail->summary, "The SDK does not act on an answer the namespace is uncertain of") << subject;
  EXPECT_EQ(detail->innerStatus, StatusCode{uncertain}.value())
    << subject << ": the refusal does not carry the namespace's " << to_string(StatusCode{uncertain});
}

}  // namespace

// The code on a Value read's answer and the Value's own status share the item's one status: a Good subcode or
// an Uncertain code on an answer whose Value is Good is the item's status, with the Value; a Bad status on
// the Value is answered over a Good subcode on the answer. The fourth Variable is the control: a plain Good
// answer is answered Good.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST(ServiceStatusRouting, AReadAnswersTheCombinedCode)
{
  RoutingHarness harness;
  const NodeId int32Type{DataTypeId::Int32};
  const NodeId goodSubcode = harness.create_variable(100, "GoodSubcode", int32Type, Variant{int32_t{0}});
  const NodeId uncertain = harness.create_variable(101, "Uncertain", int32Type, Variant{int32_t{0}});
  const NodeId badValue = harness.create_variable(102, "BadValue", int32Type, Variant{int32_t{0}});
  const NodeId control = harness.create_variable(103, "Control", int32Type, Variant{int32_t{4}});
  harness.nameSpace->answer_value_reads(
    goodSubcode, DataValueResult{DataValue{Variant{int32_t{1}}}, StatusCode{Status::GoodLocalOverride}});
  harness.nameSpace->answer_value_reads(
    uncertain, DataValueResult{DataValue{Variant{int32_t{2}}}, StatusCode{Status::UncertainLastUsableValue}});
  harness.nameSpace->answer_value_reads(badValue,
    DataValueResult{value_with_status(Variant{int32_t{3}}, Status::BadDeviceFailure),
      StatusCode{Status::GoodLocalOverride}});

  const auto outcome = harness.read({goodSubcode, uncertain, badValue, control});

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good) << to_string(outcome.serviceResult);
  ASSERT_EQ(outcome.results.size(), 4U);
  EXPECT_EQ(status_of(outcome.results[0]).as_status(), Status::GoodLocalOverride)
    << "the Good subcode on the answer: " << to_string(status_of(outcome.results[0]));
  EXPECT_TRUE(outcome.results[0].value().is_int32() && outcome.results[0].value().as<int32_t>() == 1)
    << "the Value answered with the Good subcode";
  EXPECT_EQ(status_of(outcome.results[1]).as_status(), Status::UncertainLastUsableValue)
    << "the Uncertain code on the answer: " << to_string(status_of(outcome.results[1]));
  EXPECT_TRUE(outcome.results[1].value().is_int32() && outcome.results[1].value().as<int32_t>() == 2)
    << "the Value answered with the Uncertain code";
  EXPECT_EQ(status_of(outcome.results[2]).as_status(), Status::BadDeviceFailure)
    << "the Value's Bad status under a Good subcode: " << to_string(status_of(outcome.results[2]));
  EXPECT_EQ(status_of(outcome.results[3]).as_status(), Status::Good)
    << "the control: " << to_string(status_of(outcome.results[3]));
  EXPECT_TRUE(outcome.results[3].value().is_int32() && outcome.results[3].value().as<int32_t>() == 4);

  const NodeId sensorFailure = harness.create_variable(104, "SensorFailure", int32Type, Variant{int32_t{0}});
  harness.nameSpace->answer_value_reads(sensorFailure,
    DataValueResult{
      value_with_status(Variant{int32_t{5}}, Status::BadSensorFailure), StatusCode{Status::GoodClamped}});

  const auto declared = harness.read({goodSubcode, uncertain, sensorFailure});

  ASSERT_TRUE(declared.answered);
  EXPECT_EQ(declared.serviceResult.as_status(), Status::Good) << to_string(declared.serviceResult);
  ASSERT_EQ(declared.results.size(), 3U);
  EXPECT_EQ(status_of(declared.results[0]).as_status(), Status::GoodLocalOverride);
  EXPECT_EQ(declared.results[0].value(), Variant{int32_t{1}});
  EXPECT_EQ(status_of(declared.results[1]).as_status(), Status::UncertainLastUsableValue);
  EXPECT_EQ(declared.results[1].value(), Variant{int32_t{2}});
  EXPECT_EQ(status_of(declared.results[2]).as_status(), Status::BadSensorFailure);
}

// An Uncertain answer that holds no Value is the item's status, with no Value; the other item of the request
// is answered as it would be alone.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-AN-UNCERTAIN-READ-WITHOUT-A-VALUE-IS-ANSWERED, scope=function)
TEST(ServiceStatusRouting, AnUncertainReadWithoutAValueIsAnswered)
{
  RoutingHarness harness;
  const NodeId int32Type{DataTypeId::Int32};
  const NodeId uncertain = harness.create_variable(110, "Uncertain", int32Type, Variant{int32_t{1}});
  const NodeId control = harness.create_variable(111, "Control", int32Type, Variant{int32_t{2}});
  harness.nameSpace->answer_value_reads(
    uncertain, DataValueResult{StatusCode{Status::UncertainNoCommunicationLastUsableValue}});

  const auto outcome = harness.read({uncertain, control});

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good) << to_string(outcome.serviceResult);
  ASSERT_EQ(outcome.results.size(), 2U);
  EXPECT_EQ(status_of(outcome.results[0]).as_status(), Status::UncertainNoCommunicationLastUsableValue)
    << to_string(status_of(outcome.results[0]));
  EXPECT_TRUE(outcome.results[0].value().empty()) << "a Value was answered for an answer that holds none";
  EXPECT_EQ(status_of(outcome.results[1]).as_status(), Status::Good)
    << to_string(status_of(outcome.results[1]));
  EXPECT_TRUE(outcome.results[1].value().is_int32() && outcome.results[1].value().as<int32_t>() == 2);
}

// A page of References answered with a Good subcode or an Uncertain code answers its References, and its code
// is the BrowseResult's status. The third source is the control: a plain Good page is answered Good.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-BROWSE-ANSWERS-THE-PAGES-CODE, scope=function)
TEST(ServiceStatusRouting, BrowseAnswersThePagesCode)
{
  RoutingHarness harness;
  const NodeId goodSubcode = harness.create_object(200, "GoodSubcode");
  const NodeId uncertain = harness.create_object(201, "Uncertain");
  const NodeId control = harness.create_object(202, "Control");
  const NodeId t1 = harness.create_object(210, "T");
  const NodeId t2 = harness.create_object(211, "T");
  const NodeId t3 = harness.create_object(212, "T");
  harness.link(goodSubcode, ReferenceTypeId::HasComponent, t1);
  harness.link(uncertain, ReferenceTypeId::HasComponent, t2);
  harness.link(control, ReferenceTypeId::HasComponent, t3);
  harness.nameSpace->code_reference_reads(goodSubcode, StatusCode{Status::GoodResultsMayBeIncomplete});
  harness.nameSpace->code_reference_reads(
    uncertain, StatusCode{Status::UncertainNoCommunicationLastUsableValue});

  const auto outcome = harness.browse({goodSubcode, uncertain, control});

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good) << to_string(outcome.serviceResult);
  ASSERT_EQ(outcome.results.size(), 3U);
  EXPECT_EQ(outcome.results[0].status_code().as_status(), Status::GoodResultsMayBeIncomplete)
    << to_string(outcome.results[0].status_code());
  EXPECT_EQ(targets_of(outcome.results[0]), std::vector<NodeId>{t1})
    << "the References of the Good subcode page";
  EXPECT_EQ(outcome.results[1].status_code().as_status(), Status::UncertainNoCommunicationLastUsableValue)
    << to_string(outcome.results[1].status_code());
  EXPECT_EQ(targets_of(outcome.results[1]), std::vector<NodeId>{t2})
    << "the References of the Uncertain page";
  EXPECT_EQ(outcome.results[2].status_code().as_status(), Status::Good)
    << "the control: " << to_string(outcome.results[2].status_code());
  EXPECT_EQ(targets_of(outcome.results[2]), std::vector<NodeId>{t3});

  const NodeId localOverride = harness.create_object(203, "LocalOverride");
  const NodeId firstTarget = harness.create_object(213, "FirstTarget");
  const NodeId secondTarget = harness.create_object(214, "SecondTarget");
  harness.link(localOverride, ReferenceTypeId::HasComponent, firstTarget);
  harness.link(localOverride, ReferenceTypeId::HasComponent, secondTarget);
  harness.nameSpace->code_reference_reads(localOverride, StatusCode{Status::GoodLocalOverride});

  const auto declared = harness.browse({localOverride, uncertain});

  ASSERT_TRUE(declared.answered);
  EXPECT_EQ(declared.serviceResult.as_status(), Status::Good) << to_string(declared.serviceResult);
  ASSERT_EQ(declared.results.size(), 2U);
  EXPECT_EQ(declared.results[0].status_code().as_status(), Status::GoodLocalOverride);
  const auto declaredTargets = targets_of(declared.results[0]);
  ASSERT_EQ(declaredTargets.size(), 2U);
  EXPECT_NE(std::find(declaredTargets.begin(), declaredTargets.end(), firstTarget), declaredTargets.end());
  EXPECT_NE(std::find(declaredTargets.begin(), declaredTargets.end(), secondTarget), declaredTargets.end());
  EXPECT_EQ(declared.results[1].status_code().as_status(), Status::UncertainNoCommunicationLastUsableValue);
  EXPECT_EQ(targets_of(declared.results[1]), std::vector<NodeId>{t2});
}

// A path whose References were answered with a Good subcode or an Uncertain code answers its targets, and the
// code is the BrowsePathResult's status. The third path is the control: plain Good pages answer Good.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-TRANSLATE-ANSWERS-THE-PAGES-CODE, scope=function)
TEST(ServiceStatusRouting, TranslateAnswersThePagesCode)
{
  RoutingHarness harness;
  const NodeId goodSubcode = harness.create_object(300, "GoodSubcode");
  const NodeId uncertain = harness.create_object(301, "Uncertain");
  const NodeId control = harness.create_object(302, "Control");
  const NodeId t1 = harness.create_object(310, "T");
  const NodeId t2 = harness.create_object(311, "T");
  const NodeId t3 = harness.create_object(312, "T");
  harness.link(goodSubcode, ReferenceTypeId::HasComponent, t1);
  harness.link(uncertain, ReferenceTypeId::HasComponent, t2);
  harness.link(control, ReferenceTypeId::HasComponent, t3);
  harness.nameSpace->code_reference_reads(goodSubcode, StatusCode{Status::GoodResultsMayBeIncomplete});
  harness.nameSpace->code_reference_reads(
    uncertain, StatusCode{Status::UncertainNoCommunicationLastUsableValue});

  const auto outcome = harness.translate({goodSubcode, uncertain, control});

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good) << to_string(outcome.serviceResult);
  ASSERT_EQ(outcome.results.size(), 3U);
  EXPECT_EQ(outcome.results[0].status_code().as_status(), Status::GoodResultsMayBeIncomplete)
    << to_string(outcome.results[0].status_code());
  EXPECT_EQ(targets_of(outcome.results[0]), std::vector<NodeId>{t1}) << "the target reached through the page";
  EXPECT_EQ(outcome.results[1].status_code().as_status(), Status::UncertainNoCommunicationLastUsableValue)
    << to_string(outcome.results[1].status_code());
  EXPECT_EQ(targets_of(outcome.results[1]), std::vector<NodeId>{t2}) << "the target reached through the page";
  EXPECT_EQ(outcome.results[2].status_code().as_status(), Status::Good)
    << "the control: " << to_string(outcome.results[2].status_code());
  EXPECT_EQ(targets_of(outcome.results[2]), std::vector<NodeId>{t3});
}

// The Write service decides a null write from the Variable's AllowNulls Property, so an Uncertain answer to
// the read of its Value is refused whether or not it holds a Value: Bad_InternalError (ReadAnswerUncertain)
// with the namespace's code as the inner status, and the null is not written. The third Variable is the
// control: an AllowNulls Property read Good as true lets the null be written.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(ServiceStatusRouting, AnUncertainAllowNullsAnswerIsRefusedWithOrWithoutAValue)
{
  RoutingHarness harness;
  const NodeId int32Type{DataTypeId::Int32};
  const NodeId booleanType{DataTypeId::Boolean};
  const NodeId withValue = harness.create_variable(400, "WithValue", int32Type, Variant{int32_t{1}});
  const NodeId withoutValue = harness.create_variable(401, "WithoutValue", int32Type, Variant{int32_t{1}});
  const NodeId control = harness.create_variable(402, "Control", int32Type, Variant{int32_t{1}});
  const NodeId p1 = harness.create_variable(410, "AllowNulls", booleanType, Variant{bool{true}});
  const NodeId p2 = harness.create_variable(411, "AllowNulls", booleanType, Variant{bool{true}});
  const NodeId p3 = harness.create_variable(412, "AllowNulls", booleanType, Variant{bool{true}});
  for (const auto& [variable, property] :
    {std::pair{withValue, p1}, std::pair{withoutValue, p2}, std::pair{control, p3}})
  {
    // The AllowNulls Property is named in namespace 0, as the type defines it.
    harness.variables.at(property).set_browse_name(QualifiedName{uint16_t{0}, "AllowNulls"});
    harness.link(variable, ReferenceTypeId::HasProperty, property);
  }
  harness.nameSpace->answer_value_reads(
    p1, DataValueResult{DataValue{Variant{bool{true}}}, StatusCode{Status::UncertainLastUsableValue}});
  harness.nameSpace->answer_value_reads(p2, DataValueResult{StatusCode{Status::UncertainLastUsableValue}});

  const auto outcome = harness.write_nulls({withValue, withoutValue, control});

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good) << to_string(outcome.serviceResult);
  ASSERT_EQ(outcome.results.size(), 3U);
  expect_uncertain_refusal(outcome.results[0],
    "ReadAnswerUncertain",
    Status::UncertainLastUsableValue,
    "an Uncertain answer with true");
  expect_uncertain_refusal(outcome.results[1],
    "ReadAnswerUncertain",
    Status::UncertainLastUsableValue,
    "an Uncertain answer without a Value");
  EXPECT_EQ(outcome.results[2].as_status(), Status::Good) << "the control: " << to_string(outcome.results[2]);
  for (const auto& refused : {withValue, withoutValue})
  {
    const auto stored = harness.stored_value(refused);
    EXPECT_TRUE(stored.is_int32() && stored.as<int32_t>() == 1)
      << refused.as_definition() << " no longer holds 1: the null was written";
  }
  EXPECT_TRUE(harness.stored_value(control).empty()) << "the control's null was not written";
}

// A Write's null policy is decided from a Good AllowNulls Value only, so a Value whose own status is
// Uncertain is refused as an Uncertain answer is: Bad_InternalError (ReadAnswerUncertain) with that status as
// the inner status, and the null is not written. The second Variable is the control: an AllowNulls Value
// whose own status is Good lets the null be written.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(ServiceStatusRouting, AWriteIsNotDecidedOnAnAllowNullsValueWhoseOwnStatusIsUncertain)
{
  RoutingHarness harness;
  const NodeId int32Type{DataTypeId::Int32};
  const NodeId booleanType{DataTypeId::Boolean};
  const NodeId uncertain = harness.create_variable(420, "UncertainPolicy", int32Type, Variant{int32_t{1}});
  const NodeId control = harness.create_variable(421, "Control", int32Type, Variant{int32_t{1}});
  const NodeId p1 = harness.create_variable(430, "AllowNulls", booleanType, Variant{bool{true}});
  const NodeId p2 = harness.create_variable(431, "AllowNulls", booleanType, Variant{bool{true}});
  for (const auto& [variable, property] : {std::pair{uncertain, p1}, std::pair{control, p2}})
  {
    harness.variables.at(property).set_browse_name(QualifiedName{uint16_t{0}, "AllowNulls"});
    harness.link(variable, ReferenceTypeId::HasProperty, property);
  }
  harness.variables.at(p1).write_value_sync(
    DataValue{Variant{bool{true}}, StatusCode{Status::UncertainLastUsableValue}});

  const auto outcome = harness.write_nulls({uncertain, control});

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good) << to_string(outcome.serviceResult);
  ASSERT_EQ(outcome.results.size(), 2U);
  expect_uncertain_refusal(outcome.results[0],
    "ReadAnswerUncertain",
    Status::UncertainLastUsableValue,
    "an AllowNulls Value whose own status is Uncertain");
  EXPECT_EQ(outcome.results[1].as_status(), Status::Good) << "the control: " << to_string(outcome.results[1]);
  const auto stored = harness.stored_value(uncertain);
  EXPECT_TRUE(stored.is_int32() && stored.as<int32_t>() == 1) << "the null was written";
  EXPECT_TRUE(harness.stored_value(control).empty()) << "the control's null was not written";
}

// A Read of a null Value is decided from a Good AllowNulls Value only: with AllowNulls FALSE it is
// Bad_NoData, and with an AllowNulls Value whose own status is Uncertain it is refused Bad_InternalError
// (ReadAnswerUncertain) with that status as the inner status. The second Variable is the control.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(ServiceStatusRouting, ANullReadIsNotDecidedOnAnAllowNullsValueWhoseOwnStatusIsUncertain)
{
  RoutingHarness harness;
  const NodeId int32Type{DataTypeId::Int32};
  const NodeId booleanType{DataTypeId::Boolean};
  const NodeId uncertain = harness.create_variable(440, "UncertainPolicy", int32Type, Variant{});
  const NodeId control = harness.create_variable(441, "Control", int32Type, Variant{});
  const NodeId p1 = harness.create_variable(450, "AllowNulls", booleanType, Variant{bool{false}});
  const NodeId p2 = harness.create_variable(451, "AllowNulls", booleanType, Variant{bool{false}});
  for (const auto& [variable, property] : {std::pair{uncertain, p1}, std::pair{control, p2}})
  {
    harness.variables.at(property).set_browse_name(QualifiedName{uint16_t{0}, "AllowNulls"});
    harness.link(variable, ReferenceTypeId::HasProperty, property);
  }
  harness.variables.at(p1).write_value_sync(
    DataValue{Variant{bool{false}}, StatusCode{Status::UncertainLastUsableValue}});

  const auto outcome = harness.read({uncertain, control});

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good) << to_string(outcome.serviceResult);
  ASSERT_EQ(outcome.results.size(), 2U);
  expect_uncertain_refusal(status_of(outcome.results[0]),
    "ReadAnswerUncertain",
    Status::UncertainLastUsableValue,
    "a null Read decided on an AllowNulls Value whose own status is Uncertain");
  EXPECT_EQ(status_of(outcome.results[1]).as_status(), Status::BadNoData)
    << "the control: " << to_string(status_of(outcome.results[1]));
}

// The access control decides from the namespace's effective permissions, so an Uncertain answer grants
// nothing whether or not it holds a mask: the Read of the Node is denied Bad_UserAccessDenied, and the
// refusal of the Uncertain answer (AnswerUncertain, the namespace's code as its inner status) is the denial's
// cause. The third Variable is the control: every permission answered Good is granted.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(ServiceStatusRouting, AnUncertainPermissionAnswerGrantsNothingWithOrWithoutAMask)
{
  RoutingHarness harness;
  const NodeId int32Type{DataTypeId::Int32};
  const NodeId withMask = harness.create_variable(500, "WithMask", int32Type, Variant{int32_t{1}});
  const NodeId withoutMask = harness.create_variable(501, "WithoutMask", int32Type, Variant{int32_t{2}});
  const NodeId control = harness.create_variable(502, "Control", int32Type, Variant{int32_t{3}});
  harness.nameSpace->answer_permissions(withMask,
    Result<PermissionType>{
      ua::test_helpers::all_permissions(), StatusCode{Status::UncertainLastUsableValue}});
  harness.nameSpace->answer_permissions(
    withoutMask, Result<PermissionType>{StatusCode{Status::UncertainLastUsableValue}});
  harness.nameSpace->answer_permissions(control, Result<PermissionType>{ua::test_helpers::all_permissions()});

  const auto outcome = harness.read({withMask, withoutMask, control});

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good) << to_string(outcome.serviceResult);
  ASSERT_EQ(outcome.results.size(), 3U);
  for (std::size_t k = 0; k < 2; ++k)
  {
    const std::string subject =
      k == 0 ? "an Uncertain answer with every permission" : "an Uncertain answer without a mask";
    const StatusCode denied = status_of(outcome.results[k]);
    EXPECT_EQ(denied.as_status(), Status::BadUserAccessDenied) << subject << ": " << to_string(denied);
    EXPECT_TRUE(outcome.results[k].value().empty()) << subject << ": a Value was read";
    const auto& detail = denied.shared_detail();
    ASSERT_NE(detail, nullptr) << subject << ": the denial carries no ErrorDetail";
    ASSERT_NE(detail->cause, nullptr) << subject << ": the denial has no cause";
    EXPECT_EQ(detail->cause->code, "AnswerUncertain") << subject << ": " << to_string(*detail);
    EXPECT_EQ(detail->cause->innerStatus, StatusCode{Status::UncertainLastUsableValue}.value())
      << subject << ": " << to_string(*detail);
  }
  EXPECT_EQ(status_of(outcome.results[2]).as_status(), Status::Good)
    << "the control: " << to_string(status_of(outcome.results[2]));
  EXPECT_TRUE(outcome.results[2].value().is_int32() && outcome.results[2].value().as<int32_t>() == 3);
}

// A ValueAsText Read answers the text projected from its owner's Value, so the code the namespace answered
// the owner's Value read with reaches the client with the text: an Uncertain code with the Value it held
// gives the text with that code, and an Uncertain code without a Value gives that code and no Value. The
// third owner is the control: a plain Good owner gives the text, Good.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-AN-UNCERTAIN-READ-WITHOUT-A-VALUE-IS-ANSWERED, scope=function)
TEST(ServiceStatusRouting, AValueAsTextReadAnswersTheOwnersCodeWithTheText)
{
  RoutingHarness harness;
  const auto withValue = harness.create_enumeration(600);
  const auto withoutValue = harness.create_enumeration(620);
  const auto control = harness.create_enumeration(640);
  harness.nameSpace->answer_value_reads(withValue.owner,
    DataValueResult{DataValue{Variant{int64_t{2}}}, StatusCode{Status::UncertainLastUsableValue}});
  harness.nameSpace->answer_value_reads(
    withoutValue.owner, DataValueResult{StatusCode{Status::UncertainLastUsableValue}});

  const auto outcome = harness.read({withValue.valueAsText, withoutValue.valueAsText, control.valueAsText});

  ASSERT_TRUE(outcome.answered);
  EXPECT_EQ(outcome.serviceResult.as_status(), Status::Good) << to_string(outcome.serviceResult);
  ASSERT_EQ(outcome.results.size(), 3U);
  EXPECT_EQ(status_of(outcome.results[0]).as_status(), Status::UncertainLastUsableValue)
    << "the owner's Uncertain code with its Value: " << to_string(status_of(outcome.results[0]));
  EXPECT_EQ(text_of(outcome.results[0]), "High") << "the text projected from the Uncertain Value";
  EXPECT_EQ(status_of(outcome.results[1]).as_status(), Status::UncertainLastUsableValue)
    << "the owner's Uncertain code without a Value: " << to_string(status_of(outcome.results[1]));
  EXPECT_TRUE(outcome.results[1].value().empty()) << "a text was answered for an owner Value never read";
  EXPECT_EQ(status_of(outcome.results[2]).as_status(), Status::Good)
    << "the control: " << to_string(status_of(outcome.results[2]));
  EXPECT_EQ(text_of(outcome.results[2]), "High");
}

// A ValueAsDictionaryEntries Read answers the EnumDictionaryEntries row of its owner's Value, so the code the
// namespace answered the owner's Value read with reaches the client with the row. The second owner is the
// control: a plain Good owner gives the row, Good.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST(ServiceStatusRouting, AValueAsDictionaryEntriesReadAnswersTheOwnersCodeWithTheEntries)
{
  RoutingHarness harness;
  const auto uncertain = harness.create_enumeration(700);
  const auto control = harness.create_enumeration(720);
  harness.nameSpace->answer_value_reads(uncertain.owner,
    DataValueResult{DataValue{Variant{int64_t{2}}}, StatusCode{Status::UncertainLastUsableValue}});

  const auto outcome = harness.read({uncertain.valueAsDictionaryEntries, control.valueAsDictionaryEntries});

  ASSERT_TRUE(outcome.answered);
  ASSERT_EQ(outcome.results.size(), 2U);
  const auto entriesOf = [](const DataValue& value)
  {
    const auto* entries = value.value().try_as<Array<NodeId>>();
    return entries != nullptr ? std::vector<NodeId>(entries->begin(), entries->end()) : std::vector<NodeId>{};
  };
  EXPECT_EQ(status_of(outcome.results[0]).as_status(), Status::UncertainLastUsableValue)
    << to_string(status_of(outcome.results[0]));
  EXPECT_EQ(entriesOf(outcome.results[0]), std::vector<NodeId>{uncertain.currentEntry})
    << "the row of the Uncertain Value";
  EXPECT_EQ(status_of(outcome.results[1]).as_status(), Status::Good)
    << "the control: " << to_string(status_of(outcome.results[1]));
  EXPECT_EQ(entriesOf(outcome.results[1]), std::vector<NodeId>{control.currentEntry});
}

// A Write of ValueAsDictionaryEntries is translated into a write of its owner from the tables the projection
// reads, so the SDK acts on those reads: an owner Value answered Uncertain, with or without the Value,
// refuses the write with Bad_InternalError (ReadAnswerUncertain) and the namespace's code as the inner
// status, never with the bare Uncertain code. The third owner is the control: its tables are read Good, so
// the null written reaches the translation and is refused for its shape.
// @relation(AC-COMP-SVR-STATUS-ROUTING-02-AN-UNCERTAIN-ANSWER-THE-SDK-ACTS-ON-IS-REFUSED-WITH-OR-WITHOUT-A-VALUE, scope=function)
TEST(ServiceStatusRouting, AValueAsDictionaryEntriesWriteRefusesAnUncertainOwnerValue)
{
  RoutingHarness harness;
  const auto withValue = harness.create_enumeration(800);
  const auto withoutValue = harness.create_enumeration(820);
  const auto control = harness.create_enumeration(840);
  harness.nameSpace->answer_value_reads(withValue.owner,
    DataValueResult{DataValue{Variant{int64_t{2}}}, StatusCode{Status::UncertainLastUsableValue}});
  harness.nameSpace->answer_value_reads(
    withoutValue.owner, DataValueResult{StatusCode{Status::UncertainLastUsableValue}});

  const auto outcome = harness.write_nulls({withValue.valueAsDictionaryEntries,
    withoutValue.valueAsDictionaryEntries,
    control.valueAsDictionaryEntries});

  ASSERT_TRUE(outcome.answered);
  ASSERT_EQ(outcome.results.size(), 3U);
  expect_uncertain_refusal(outcome.results[0],
    "ReadAnswerUncertain",
    Status::UncertainLastUsableValue,
    "an owner Value answered Uncertain with the Value");
  expect_uncertain_refusal(outcome.results[1],
    "ReadAnswerUncertain",
    Status::UncertainLastUsableValue,
    "an owner Value answered Uncertain without the Value");
  EXPECT_EQ(outcome.results[2].as_status(), Status::BadTypeMismatch)
    << "the control: " << to_string(outcome.results[2]);
}

// A Browse operation whose pages of References were answered with two different Good subcodes answers the
// later page's code (OPC 10000-4 7.39.1 has room for one) and logs the earlier one, so no code a namespace
// gave is lost without trace. The first page's Reference is filtered out by the NodeClass mask, so the
// operation reads the second page.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-READ-ANSWERS-THE-COMBINED-CODE, scope=function)
TEST(ServiceStatusRouting, AResultsCodeIsLoggedOnlyWhenTheItemAnswersAnotherCode)
{
  // The result's code and the item's are both Good_Clamped: the item answers it, nothing is lost, nothing is
  // logged. The result's Good_LocalOverride under an item's Good_Clamped is not answered and is logged.
  auto sink = std::make_shared<RecordingLogSink>();
  const Logger logger{sink, std::make_shared<std::atomic<LogLevel>>(LogLevel::Trace), "test"};
  const NodeId node{2, 7};
  const StatusCode clamped{Status::GoodClamped};
  const StatusCode overridden{Status::GoodLocalOverride};

  EXPECT_EQ(
    server::detail::combined_item_status(clamped, clamped, logger, "Read", node).value(), clamped.value());
  EXPECT_FALSE(sink->warned_of(clamped)) << "a code the item already answers was logged";

  EXPECT_EQ(
    server::detail::combined_item_status(overridden, clamped, logger, "Read", node).value(), clamped.value());
  EXPECT_TRUE(sink->warned_of(overridden)) << "a code the item does not answer was not logged";
}

// @relation(AC-COMP-SVR-STATUS-ROUTING-01-BROWSE-ANSWERS-THE-PAGES-CODE, scope=function)
TEST(ServiceStatusRouting, BrowseLogsAPagesCodeItDoesNotAnswer)
{
  RoutingHarness harness;
  const NodeId source = harness.create_object(900, "Source");
  const NodeId object = harness.create_object(901, "Object");
  const NodeId variable =
    harness.create_variable(902, "Variable", NodeId{DataTypeId::Int32}, Variant{int32_t{0}});
  harness.link(source, ReferenceTypeId::HasComponent, object);
  harness.link(source, ReferenceTypeId::HasComponent, variable);
  harness.nameSpace->code_reference_pages(
    source, {StatusCode{Status::GoodLocalOverride}, StatusCode{Status::GoodResultsMayBeIncomplete}});

  const auto outcome =
    harness.browse({source}, /*maxReferencesPerNode*/ 1, static_cast<uint32_t>(NodeClass::Variable));

  ASSERT_TRUE(outcome.answered);
  ASSERT_EQ(outcome.results.size(), 1U);
  ASSERT_EQ(targets_of(outcome.results[0]), std::vector<NodeId>{variable})
    << "the Variable is on the second page, after the Object the mask filters out";
  EXPECT_EQ(outcome.results[0].status_code().as_status(), Status::GoodResultsMayBeIncomplete)
    << to_string(outcome.results[0].status_code());
  EXPECT_TRUE(harness.log->warned_of(StatusCode{Status::GoodLocalOverride}))
    << "the first page's Good_LocalOverride was dropped without a log";
}

// A TranslateBrowsePaths path answers one code for the pages it walked and the walk's own code. When both
// carry a SubCode the later one is answered and the earlier one logged: a page's Uncertain code under the
// walk's Uncertain_ReferenceOutOfServer, and the first element's page code under the second element's.
// @relation(AC-COMP-SVR-STATUS-ROUTING-01-TRANSLATE-ANSWERS-THE-PAGES-CODE, scope=function)
TEST(ServiceStatusRouting, TranslateLogsAPagesCodeItDoesNotAnswer)
{
  RoutingHarness harness;
  const NodeId remoteStart = harness.create_object(950, "RemoteStart");
  harness.sessionInfo->address_space()
    .find_node_sync(remoteStart)
    .add_reference_sync(NodeId{ReferenceTypeId::HasComponent}, ExpandedNodeId{NodeId{5, 999}, 1});
  harness.nameSpace->code_reference_reads(
    remoteStart, StatusCode{Status::UncertainNoCommunicationLastUsableValue});

  const auto remote = harness.translate({remoteStart});

  ASSERT_TRUE(remote.answered);
  ASSERT_EQ(remote.results.size(), 1U);
  EXPECT_EQ(remote.results[0].status_code().as_status(), Status::UncertainReferenceOutOfServer)
    << to_string(remote.results[0].status_code());
  EXPECT_TRUE(harness.log->warned_of(StatusCode{Status::UncertainNoCommunicationLastUsableValue}))
    << "the page's Uncertain code was dropped without a log";

  const NodeId start = harness.create_object(960, "Start");
  const NodeId middle = harness.create_object(961, "T");
  const NodeId target = harness.create_object(962, "T");
  harness.link(start, ReferenceTypeId::HasComponent, middle);
  harness.link(middle, ReferenceTypeId::HasComponent, target);
  harness.nameSpace->code_reference_reads(start, StatusCode{Status::GoodLocalOverride});
  harness.nameSpace->code_reference_reads(middle, StatusCode{Status::GoodResultsMayBeIncomplete});

  const auto local = harness.translate({start}, 2);

  ASSERT_TRUE(local.answered);
  ASSERT_EQ(local.results.size(), 1U);
  EXPECT_EQ(targets_of(local.results[0]), std::vector<NodeId>{target});
  EXPECT_EQ(local.results[0].status_code().as_status(), Status::GoodResultsMayBeIncomplete)
    << to_string(local.results[0].status_code());
  EXPECT_TRUE(harness.log->warned_of(StatusCode{Status::GoodLocalOverride}))
    << "the first element's Good_LocalOverride was dropped without a log";
}
