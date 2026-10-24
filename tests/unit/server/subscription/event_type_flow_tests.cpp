// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// How CreateMonitoredItems resolves the event types its EventFilters name (COMP-SVR-NAMESPACE-CALLS-16 rules
// 1 and 2): once per request, a type level and then a declaration depth per round, each round one batched
// lookup and one References read per namespace, with the request's RequestInfo; a type that cannot be
// resolved fails only the items whose type reaches it.
//
// The Subscription is driven as the pipeline drives it, through its asynchronous entry, on a Server's address
// space, whose namespace 0 holds BaseEventType. The event type T, its Properties and the notifier are held by
// a recording in-memory namespace that declines its immediate lookups and permissions, so that every lookup
// reaches the batched member, where it is counted.

#include <gtest/gtest.h>

#include "create_flow_fixture.h"

#include "ua_compiled_event_filter.h"
#include "ua_event_filter_result.h"
#include "ua_object_id.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace ua;
using namespace ua::server;
using namespace std::chrono_literals;
using namespace ua::test::create_flow;

namespace
{

class EventTypeFlow : public MonitoringFlow
{
protected:
  /// N's event model: an ObjectType T, a subtype of BaseEventType, with the Properties F1 and F2, and an
  /// Object O whose EventNotifier has SubscribeToEvents.
  struct EventModel
  {
    NodeId t;
    NodeId f1;
    NodeId f2;
    NodeId o;
    QualifiedName f1Name;
    QualifiedName f2Name;
  };

  EventModel create_event_model(uint16_t index)
  {
    EventModel model{.t = NodeId{index, uint32_t{300}},
      .f1 = NodeId{index, uint32_t{301}},
      .f2 = NodeId{index, uint32_t{302}},
      .o = NodeId{index, uint32_t{310}},
      .f1Name = QualifiedName{index, "F1"},
      .f2Name = QualifiedName{index, "F2"}};
    auto eventType =
      create_event_type(model.t, QualifiedName{index, "T"}, NodeId{ObjectTypeId::BaseEventType});
    if (!eventType)
    {
      return model;
    }
    create_property(*eventType, model.f1, model.f1Name);
    create_property(*eventType, model.f2, model.f2Name);
    create_notifier(model.o);
    return model;
  }

  /// An ObjectType @p nodeId named @p name, a subtype of @p supertype; `nullopt` when it was not created.
  std::optional<ObjectTypeAccessor> create_event_type(
    const NodeId& nodeId, const QualifiedName& name, const NodeId& supertype)
  {
    auto created = mAddressSpace->try_create_sync<ObjectTypeAccessor>(nodeId, NodeClass::ObjectType);
    if (!created.is_good())
    {
      ADD_FAILURE() << "creating " << to_string(name) << ": " << to_string(created.status_code());
      return std::nullopt;
    }
    auto eventType = created.value();
    eventType.set_browse_name(name);
    EXPECT_TRUE(
      eventType.try_add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, ExpandedNodeId{supertype}, false)
        .is_good())
      << to_string(name) << " was not made a subtype of " << supertype.as_definition();
    return eventType;
  }

  /// The select clauses of the item @p monitoredItemId holds, as compiled; empty when it holds none.
  static std::vector<ResolvedSelectClause> compiled_clauses(Subscription& target, IntegerId monitoredItemId)
  {
    return STA::on_strand(target,
      [monitoredItemId](auto& guard) -> std::vector<ResolvedSelectClause>
      {
        const auto* item = guard.find_monitored_item(monitoredItemId);
        if (item == nullptr || !item->eventFilter)
        {
          return {};
        }
        return item->eventFilter->select_clauses();
      });
  }

  /// The codes of @p detail and of each cause below it, outermost first.
  static std::vector<std::string> detail_chain(const ErrorDetail* detail)
  {
    std::vector<std::string> codes;
    for (; detail != nullptr; detail = detail->cause.get())
    {
      codes.push_back(detail->code);
    }
    return codes;
  }

  static std::string chain_text(const std::vector<std::string>& codes)
  {
    std::string text;
    for (const auto& code : codes)
    {
      text += (text.empty() ? "" : " <- ") + code;
    }
    return text.empty() ? std::string{"(no ErrorDetail)"} : text;
  }

  /// The status the EventFilterResult of @p result gives its select clause @p clause; `nullopt` when it gives
  /// none.
  static std::optional<StatusCode> clause_result(const MonitoredItemCreateResult& result, std::size_t clause)
  {
    const auto* filterResult = dynamic_cast<const EventFilterResult*>(result.filter_result().get());
    if (filterResult == nullptr || clause >= filterResult->select_clause_results().size())
    {
      return std::nullopt;
    }
    return filterResult->select_clause_results()[clause];
  }

  /// A Mandatory String Property @p nodeId of @p owner named @p name.
  void create_property(ObjectTypeAccessor& owner, const NodeId& nodeId, const QualifiedName& name)
  {
    auto created = mAddressSpace->try_create_sync<VariableAccessor>(nodeId, NodeClass::Variable);
    if (!created.is_good())
    {
      ADD_FAILURE() << "creating " << to_string(name) << ": " << to_string(created.status_code());
      return;
    }
    auto property = created.value();
    property.set_browse_name(name);
    property.set_data_type(NodeId{DataTypeId::String});
    EXPECT_TRUE(property
                  .try_add_reference_sync(
                    NodeId{ReferenceTypeId::HasModellingRule}, NodeId{ObjectId::ModellingRule_Mandatory})
                  .is_good())
      << to_string(name) << " was not made Mandatory";
    EXPECT_TRUE(owner.try_add_reference_sync(NodeId{ReferenceTypeId::HasProperty}, nodeId).is_good())
      << to_string(name) << " was not made a Property of its type";
  }

  /// @p nodeIds in ascending order, as one line of their definitions.
  static std::string list_text(std::vector<NodeId> nodeIds)
  {
    std::string text;
    for (const auto& nodeId : sorted(std::move(nodeIds)))
    {
      text += (text.empty() ? "" : " ") + nodeId.as_definition();
    }
    return text;
  }

  /// The NodeIds each call of the kind @p kind that names one of @p nodeIds names, one line per call (@ref
  /// list_text), the lines in ascending order.
  static std::vector<std::string> named_lists(const std::vector<Call>& calls,
    const std::function<bool(const Call&)>& kind, const std::vector<NodeId>& nodeIds)
  {
    std::vector<std::string> lists;
    for (const auto& call : naming(calls, kind, nodeIds))
    {
      lists.push_back(list_text(call.nodeIds));
    }
    std::sort(lists.begin(), lists.end());
    return lists;
  }

  static bool is_reference_read(const Call& call)
  {
    return call.member == Member::ReadReferences;
  }
};

}  // namespace

// COMP-SVR-NAMESPACE-CALLS-16 rule 1, NR-28 rule 3: T, which both items' filters name, is looked up and its
// References read once for the request, and its two Properties, a depth below it, together in one call of
// each kind.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-16-A-REQUEST-RESOLVES-EACH-EVENT-TYPE-ONCE-WITH-ONE-CALL-PER-ROUND, scope=function)
TEST_F(EventTypeFlow, ARequestResolvesEachEventTypeOnceWithOneCallPerRound)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const auto model = create_event_model(index);
  measure(n);
  mEventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto sub = subscription(1);

  const auto results = create(*sub,
    list_of(event_item(model.o, 1, model.t, model.f1Name), event_item(model.o, 2, model.t, model.f2Name)),
    mSecurity,
    0,
    mEventBus);

  const auto calls = n.calls();
  const std::vector<NodeId> typeNodes{model.t, model.f1, model.f2};
  std::vector<std::string> expected{list_text({model.t}), list_text({model.f1, model.f2})};
  std::sort(expected.begin(), expected.end());
  EXPECT_EQ(named_lists(calls, is_batched_lookup, typeNodes), expected)
    << "the batched lookups naming T, F1 or F2 are not one naming T and one naming F1 and F2"
    << describe(calls);
  EXPECT_EQ(named_lists(calls, is_reference_read, typeNodes), expected)
    << "the References reads naming T, F1 or F2 are not one naming T and one naming F1 and F2"
    << describe(calls);
  ASSERT_EQ(results.size(), 2u);
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    EXPECT_EQ(results[i].status_code().as_status(), Status::Good)
      << "row " << i + 1 << ": " << to_string(results[i].status_code());
  }
}

// COMP-SVR-NAMESPACE-CALLS-16 rule 1: the event-type lookups and reads serve the request, so they carry the
// deadline its timeoutHint gives. Hold the first event-type lookup and fix the originating request's
// arrival interval before allowing later lookups and reference reads.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-16-THE-REQUESTS-DEADLINE-REACHES-THE-EVENT-TYPE-CALLS, scope=function)
TEST_F(EventTypeFlow, TheRequestsDeadlineReachesTheEventTypeCalls)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const auto model = create_event_model(index);
  measure(n);
  mEventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto sub = subscription(1);

  n.hold_lookups_of({model.t});
  auto pending =
    start_create(*sub, list_of(event_item(model.o, 1, model.t, model.f1Name)), mSecurity, 5000, mEventBus);
  const auto requestSubmittedBy = std::chrono::steady_clock::now();
  ASSERT_TRUE(n.wait_for_held_lookups(1, 3s));
  EXPECT_EQ(pending.wait_for(100ms), std::future_status::timeout);
  EXPECT_EQ(n.release_held_lookups(), 1u);
  finish_create(pending, 1);

  const auto calls = n.calls();
  const std::vector<NodeId> typeNodes{model.t, model.f1};
  const auto lookups = naming(calls, is_batched_lookup, typeNodes);
  const auto reads = naming(calls, is_reference_read, typeNodes);
  ASSERT_FALSE(lookups.empty()) << "no batched lookup named T or F1" << describe(calls);
  ASSERT_FALSE(reads.empty()) << "no References read named T or F1" << describe(calls);
  for (const auto& group : {lookups, reads})
  {
    for (const auto& call : group)
    {
      EXPECT_TRUE(call.hasRequest) << member_name(call.member) << " #" << call.sequence
                                   << " carried no RequestInfo" << describe(calls);
      EXPECT_NE(call.deadline, std::chrono::steady_clock::time_point::max())
        << member_name(call.member) << " #" << call.sequence << " carried no deadline" << describe(calls);
      EXPECT_LE(call.deadline, call.entered + 5000ms)
        << member_name(call.member) << " #" << call.sequence
        << "'s deadline is later than 5000 ms after the request arrived";
      EXPECT_LE(call.deadline, requestSubmittedBy + 5000ms)
        << member_name(call.member) << " #" << call.sequence << " renewed the originating request's deadline";
    }
  }
}

// COMP-SVR-NAMESPACE-CALLS-16 rule 2: T's References cannot be read, so the item whose filter names T is
// refused; the item whose filter names only BaseEventType, in the same request, is created.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-16-A-TYPE-THAT-FAILS-TO-RESOLVE-FAILS-ONLY-THE-ITEMS-THAT-REACH-IT, scope=function)
TEST_F(EventTypeFlow, ATypeThatFailsToResolveFailsOnlyTheItemsThatReachIt)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const auto model = create_event_model(index);
  // The scripted read is counted among every read naming T since N was constructed.
  const std::size_t earlierReads = times_named(n.calls(), is_reference_read, model.t);
  measure(n);
  n.answer_reference_query_of(model.t,
    earlierReads + 1,
    StatusCode{Status::BadInternalError,
      ErrorDetail::build(
        "TypeReferencesUnreadable", "N could not read T's References", "EventTypeFlowTest")});
  mEventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto sub = subscription(1);

  const auto results = create(*sub,
    list_of(event_item(model.o, 1, model.t, model.f1Name),
      event_item(model.o, 2, NodeId{ObjectTypeId::BaseEventType}, QualifiedName{0, "Message"})),
    mSecurity,
    0,
    mEventBus);

  const auto calls = n.calls();
  EXPECT_GE(times_named(calls, is_reference_read, model.t), 1u)
    << "the scripted answer was never used" << describe(calls);
  ASSERT_EQ(results.size(), 2u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadMonitoredItemFilterInvalid)
    << "row 1: " << to_string(results[0].status_code());
  EXPECT_EQ(detail_code(results[0].status_code()), "MonitoredItemFilterInvalid")
    << "row 1: " << to_string(results[0].status_code());
  EXPECT_TRUE(StatusCode{detail_cause(results[0].status_code())}.is_bad())
    << "row 1's ErrorDetail carries no cause: " << to_string(results[0].status_code());
  const auto clause = clause_result(results[0], 0);
  ASSERT_TRUE(clause.has_value()) << "row 1 carries no result for its select clause";
  const auto clauseChain = detail_chain(clause->detail());
  EXPECT_EQ(clause->as_status(), Status::BadInternalError)
    << "row 1's select clause: " << to_string(*clause) << ", " << chain_text(clauseChain);
  EXPECT_EQ(
    clauseChain, (std::vector<std::string>{"EventTypeReferencesUnavailable", "TypeReferencesUnreadable"}))
    << "row 1's select clause: " << chain_text(clauseChain);
  EXPECT_EQ(detail_cause(*clause), StatusCode{Status::BadInternalError}.value())
    << "row 1's select clause's cause is not the scripted status: " << chain_text(clauseChain);
  EXPECT_EQ(results[1].status_code().as_status(), Status::Good)
    << "row 2: " << to_string(results[1].status_code());
}

// COMP-SVR-NAMESPACE-CALLS-16 rule 1, NR-28 rule 3: T1 and T2 both reach their supertype S and its Property
// P, and a Node fetched for one type is not fetched again for the other.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-16-TWO-TYPES-SHARE-THE-NODES-THEY-BOTH-REACH, scope=function)
TEST_F(EventTypeFlow, TwoTypesShareTheNodesTheyBothReach)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const NodeId s{index, uint32_t{320}};
  const NodeId p{index, uint32_t{321}};
  const NodeId t1{index, uint32_t{322}};
  const NodeId t2{index, uint32_t{323}};
  const NodeId o{index, uint32_t{330}};
  const QualifiedName pName{index, "P"};
  auto supertype = create_event_type(s, QualifiedName{index, "S"}, NodeId{ObjectTypeId::BaseEventType});
  ASSERT_TRUE(supertype.has_value());
  create_property(*supertype, p, pName);
  ASSERT_TRUE(create_event_type(t1, QualifiedName{index, "T1"}, s).has_value());
  ASSERT_TRUE(create_event_type(t2, QualifiedName{index, "T2"}, s).has_value());
  create_notifier(o);
  measure(n);
  mEventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto sub = subscription(1);

  const auto results =
    create(*sub, list_of(event_item(o, 1, t1, pName), event_item(o, 2, t2, pName)), mSecurity, 0, mEventBus);

  const auto calls = n.calls();
  EXPECT_EQ(times_named(calls, is_batched_lookup, s), 1u) << "batched lookups naming S" << describe(calls);
  EXPECT_EQ(times_named(calls, is_reference_read, s), 1u) << "References reads naming S" << describe(calls);
  EXPECT_EQ(times_named(calls, is_batched_lookup, p), 1u) << "batched lookups naming P" << describe(calls);
  EXPECT_EQ(times_named(calls, is_reference_read, p), 1u) << "References reads naming P" << describe(calls);
  ASSERT_EQ(results.size(), 2u);
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    EXPECT_EQ(results[i].status_code().as_status(), Status::Good)
      << "row " << i + 1 << ": " << to_string(results[i].status_code());
  }
}

// COMP-SVR-NAMESPACE-CALLS-16 rule 1 ("tokens followed"), as a guard: T's References answered one per page
// are followed to the end, so F1 and F2 are each found as T's declarations, as when they come in one answer.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-16-A-TYPE-READ-IN-PAGES-IS-READ-TO-THE-END, scope=function)
TEST_F(EventTypeFlow, ATypeReadInPagesIsReadToTheEnd)
{
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const auto model = create_event_model(index);
  measure(n);
  n.page_references(1);
  mEventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto sub = subscription(1);

  const auto results = create(*sub,
    list_of(event_item(model.o, 1, model.t, model.f1Name), event_item(model.o, 2, model.t, model.f2Name)),
    mSecurity,
    0,
    mEventBus);

  const auto calls = n.calls();
  bool paged = false;
  for (const auto& call : naming(calls, is_reference_read, {model.t}))
  {
    for (const auto& query : call.referenceQueries)
    {
      paged = paged || (query.nodeId == model.t && !query.answeredToken.empty());
    }
  }
  ASSERT_TRUE(paged) << "T's References were not answered in pages" << describe(calls);
  ASSERT_EQ(results.size(), 2u);
  const std::vector<NodeId> fields{model.f1, model.f2};
  for (std::size_t i = 0; i < results.size(); ++i)
  {
    ASSERT_EQ(results[i].status_code().as_status(), Status::Good)
      << "row " << i + 1 << ": " << to_string(results[i].status_code());
    const auto clauses = compiled_clauses(*sub, results[i].monitored_item_id());
    ASSERT_EQ(clauses.size(), 1u) << "row " << i + 1 << "'s compiled select clauses";
    EXPECT_EQ(clauses[0].validationStatus.as_status(), Status::Good)
      << "row " << i + 1 << "'s select clause: " << to_string(clauses[0].validationStatus);
    ASSERT_TRUE(clauses[0].declarationAccessor.has_value())
      << "row " << i + 1 << "'s select clause was not resolved to a declaration of T";
    EXPECT_EQ(clauses[0].declarationAccessor->get_node_id(), fields[i])
      << "row " << i + 1 << "'s select clause was resolved to another declaration";
  }
}

// COMP-SVR-NAMESPACE-CALLS-16 rule 1 ("bounded as the climb does"): a read of T's References that answers a
// resume token and no References without end is given up, the item refused, and the last token released once.
// @relation(AC-COMP-SVR-NAMESPACE-CALLS-16-A-TYPE-READ-THAT-PAGES-WITHOUT-END-IS-REFUSED-AND-ITS-TOKEN-RELEASED, scope=function)
TEST_F(EventTypeFlow, ATypeReadThatPagesWithoutEndIsRefusedAndItsTokenReleased)
{
  constexpr std::size_t emptyPageBound = 1024;
  const uint16_t index = setup(1).at(0);
  auto& n = *mNamespaces.at(0);
  const auto model = create_event_model(index);
  measure(n);
  n.page_without_end_of({model.t});
  mEventBus = std::make_shared<EventBus>(*mAddressSpace);
  auto sub = subscription(1);

  const auto queriesOfT = [&n, &model]()
  {
    std::vector<BatchRecordingNamespace::ReferenceQueryRecord> queries;
    for (const auto& call : n.calls(Member::ReadReferences))
    {
      for (const auto& query : call.referenceQueries)
      {
        if (query.nodeId == model.t)
        {
          queries.push_back(query);
        }
      }
    }
    return queries;
  };

  auto future =
    start_create(*sub, list_of(event_item(model.o, 1, model.t, model.f1Name)), mSecurity, 0, mEventBus);
  // Waits for the answer for at most 5 s, and gives up early once T has been read well past the bound.
  const auto until = std::chrono::steady_clock::now() + 5s;
  bool answered = false;
  while (std::chrono::steady_clock::now() < until)
  {
    if (future.wait_for(10ms) == std::future_status::ready)
    {
      answered = true;
      break;
    }
    if (n.count(Member::ReadReferences) > emptyPageBound + 100)
    {
      break;
    }
  }
  const std::size_t readsWhenWaitEnded = queriesOfT().size();
  // Stops the answers without end, so that a read still paging ends and the fixture drains.
  n.page_without_end_of({});
  ASSERT_TRUE(answered) << "the create did not answer; T had been read in " << readsWhenWaitEnded
                        << " queries when the wait ended";
  const auto results = future.get();

  // The release may follow the answer; it is given a moment to arrive.
  const auto releaseBy = std::chrono::steady_clock::now() + 1s;
  while (n.count(Member::ReleaseResumeToken) == 0 && std::chrono::steady_clock::now() < releaseBy)
  {
    std::this_thread::sleep_for(10ms);
  }

  ASSERT_EQ(results.size(), 1u);
  EXPECT_EQ(results[0].status_code().as_status(), Status::BadMonitoredItemFilterInvalid)
    << "row 1: " << to_string(results[0].status_code());
  const auto clause = clause_result(results[0], 0);
  ASSERT_TRUE(clause.has_value()) << "row 1 carries no result for its select clause";
  const auto clauseChain = detail_chain(clause->detail());
  ASSERT_GE(clauseChain.size(), 2u) << "row 1's select clause: " << chain_text(clauseChain);
  EXPECT_EQ(clauseChain[0], "EventTypeReferencesUnavailable")
    << "row 1's select clause: " << chain_text(clauseChain);
  EXPECT_EQ(clauseChain[1], "NamespacePagingDidNotEnd")
    << "row 1's select clause: " << chain_text(clauseChain);

  const auto ofT = queriesOfT();
  const auto releases = n.calls(Member::ReleaseResumeToken);
  EXPECT_EQ(releases.size(), 1u) << "release_resume_token calls; T was read in " << ofT.size() << " queries";
  if (releases.size() == 1u && !ofT.empty())
  {
    EXPECT_EQ(releases[0].token, ofT.back().answeredToken)
      << "the token released is not the last token N gave for T";
  }
}
