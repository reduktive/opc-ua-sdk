// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Behaviour pins for sub-phase 4.12 (ConditionInstance) - ErrorDetail
// propagation across failure boundaries.
//
// ErrorDetail propagation is the highest priority: every failure boundary
// in initialize_address_space / attach_address_space must forward both the
// status code and the ErrorDetail of the underlying failure. The {b} flip
// converts these coroutines into callback-shape continuations; the
// rewrite must preserve detail forwarding at every is_bad() check.
//
// What is pinned (4 pins):
//   ED-A: InitializeFlowInstantiateObjectFailureForwardsStatusAndDetail
//   ED-C: AttachFlowConditionFindFailureForwardsStatusAndDetail
//   ED-F: ActivateAsyncCatchAllConvertsUaExceptionToBadResultPreservingDetail
//   ED-G: AddCommentMethodHandlerForwardsThrownErrorDetailIntoCallResult
//
// Pins NOT covered (and why):
//   ED-B (register_methods failure forwarding) - driving a method-handler
//     registration failure without a fake AddressSpace requires either
//     (a) a custom type definition with no Enable/Disable/AddComment children,
//     or (b) staging a bad set_method_handler result through fake injection.
//     The 4.4a `FakeAsyncNamespace` pattern would unlock this; deferred to a
//     follow-up that brings that fake into 4.12.
//   ED-D (wire-loop optional-not-found silent skip) - same constraint.
//     Optional variables are present in the standard NodeSet2 ConditionType,
//     so naturally driving "optional not found" requires custom type definition.
//   ED-E (register_methods optional-registration silent skip) - same constraint.
//
// ED-G regression context. Prior to this pin, the per-method-handler closure
// tails in `register_methods()` packaged `run_method_on_strand`'s VoidResult
// into a CallMethodResult by copying ONLY the status_code, then wrapped that
// inside a *good* outer CallResult - silently dropping `shared_detail()` at
// every method-handler boundary (15 sites). The fix re-routes the bad path
// through `CallResult{vr.status_code(), vr.shared_detail()}` so the outer
// Result is bad and carries the detail. ED-G plants a sentinel ErrorDetail
// inside a UaException thrown from a custom ConditionLogic override and
// asserts pointer-identity through MethodAccessor::try_call_sync - the
// strongest guarantee at this boundary.
//
// Pointer-identity vs non-null. ED-F uses a custom logic that throws a
// UaException with a sentinel ErrorDetail; the resulting Result is checked
// for pointer-identity preservation through `exception_to_status_code`. ED-A and
// ED-C drive natural failures through the production AddressSpace; the
// resulting detail's pointer-identity is whatever the AS layer attaches
// (verified non-null per 4.4a's NV-D / IN-B pins) but is not a sentinel
// the test planted. The pins assert non-null on those paths and rely on
// the structural pattern at ua_condition_instance.cpp:809-812 / :532-535
// (forwarding `result.shared_detail()` directly) to be reviewable
// independently. A regression that synthesises a fresh detail at the
// continuation boundary instead of forwarding the input would still
// produce non-null detail and pass the pin - so the pin is weaker than
// pointer-identity. The {b} reviewer's prompt should include an explicit
// "every is_bad() forwards shared_detail() pointer-identity" structural
// audit.

#include <future>
#include <memory>
#include <utility>

#include <gtest/gtest.h>

#include "concrete_condition_type.h"
#include "fmt/format.h"

#include "ua_acknowledgeable_condition_logic.h"
#include "ua_address_space.h"
#include "ua_alarm_condition_logic.h"
#include "ua_application_configuration.h"
#include "ua_byte_string.h"
#include "ua_call_method_request.h"
#include "ua_condition_instance.h"
#include "ua_condition_logic.h"
#include "ua_data_type_registration.h"
#include "ua_encoding_limits.h"
#include "ua_error_detail.h"
#include "ua_sinks.h"
#include "ua_exceptions.h"
#include "ua_file_stream.h"
#include "ua_instance_utils.h"
#include "ua_localized_text.h"
#include "ua_namespace_array.h"
#include "ua_node_accessor.h"
#include "ua_node_id.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_qualified_name.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_string.h"
#include "ua_structure_factory.h"
#include <boost/asio/thread_pool.hpp>
#include "ua_variant.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"

namespace ua::test::behaviour_pins
{
namespace
{

class FakeEventSink : public EventSink
{
public:
  void emit(BaseEvent& /*event*/) override
  {}
};

// Test fixture with a real AddressSpace populated from NodeSet2.xml. Uses
// a static suite-level setup so the ~1-2s NodeSet2 import only runs once.
// NodeSet2.xml is copied next to the test binary by tests/behaviour_pins/
// CMakeLists.txt's POST_BUILD step.
class ConditionInstanceErrorDetailPin : public ::testing::Test
{
protected:
  static void SetUpTestSuite()
  {
    const auto cfg = ApplicationConfig::load_default();
    sLimits = make_encoding_limits(cfg);

    sAddressSpace.emplace(AddressSpace::create("uri:test:ed-pin", sPool.executor()));

    StructureFactory factory;
    auto lookupFn = namespace_array_utils::get_index_lookup_function(*sAddressSpace);
    const CodecNamespaceContext nsConfig{std::move(lookupFn), {}, {}, {}};
    register_ua_data_types_with_factory(nsConfig, &factory, &factory);

    FileStream input{"NodeSet2.xml"};
    input.open_for_read();
    auto nodeSets = xml::nodeset::Parser::parse(sLimits,
      input,
      factory,
      sAddressSpace->namespace_array(),
      sAddressSpace->server_array(),
      xml::nodeset::Parser::GetDependentModelCallback{});
    auto importer = xml::nodeset::ImportEngine::create(sLimits, *sAddressSpace, nodeSets, {});
    importer->import_all_sync({}, {});
  }

  static void TearDownTestSuite()
  {
    // Release the address space, but do NOT join the static `sPool` here.
    // Under `--gtest_repeat`, gtest runs TearDownTestSuite then SetUpTestSuite
    // again for the next iteration; a joined `thread_pool` is terminal and
    // cannot be revived, so the next iteration would post to dead workers and
    // every sync call would hang forever. The pool's destructor performs the
    // final join at process exit. (Same convention as condition_instance_tests.)
    sAddressSpace.reset();
  }

  static AddressSpace& as()
  {
    return *sAddressSpace;
  }

  // Produce a unique condition NodeId per call so tests can run repeatedly
  // without instance collisions in the static AddressSpace.
  static NodeId fresh_condition_id()
  {
    return NodeId{1u, sNextId++};
  }

  static boost::asio::thread_pool sPool;
  static std::optional<AddressSpace> sAddressSpace;
  static EncodingLimits sLimits;
  static uint32_t sNextId;

  std::shared_ptr<FakeEventSink> mSink = std::make_shared<FakeEventSink>();
};

boost::asio::thread_pool ConditionInstanceErrorDetailPin::sPool{2};
std::optional<AddressSpace> ConditionInstanceErrorDetailPin::sAddressSpace{};
EncodingLimits ConditionInstanceErrorDetailPin::sLimits{};
uint32_t ConditionInstanceErrorDetailPin::sNextId{8000};

}  // namespace

// ---------------------------------------------------------------------------
// Pin ED-A: a Tier-B `instantiate_object_coro` failure inside
// `initialize_address_space` forwards both the status code and a non-null
// `shared_detail()` to the user's callback.
// ---------------------------------------------------------------------------
//
// Property: at ua_condition_instance.cpp:809-812, when
// `instantiate_object_coro` returns bad, the coroutine forwards
// `subtreeResult.shared_detail()` directly into the resulting VoidResult.
// We drive a natural instantiate failure by giving the new condition a
// parent NodeId that does not exist in the AddressSpace. The AddressSpace
// instantiation service emits an ErrorDetail for the missing parent (per
// 4.4a NV-D / IN-* pins) and ConditionInstance is required to forward it.
// Falsifies a regression where the {b}-flip continuation reconstructs the
// VoidResult with only the status code and drops the detail.

TEST_F(ConditionInstanceErrorDetailPin, InitializeFlowInstantiateObjectFailureForwardsStatusAndDetail)
{
  // Source-node refers to a non-existent NodeId in NS=1; instantiate_object
  // will fail because the parent cannot be resolved.
  const NodeId nonexistentParent{1u, 999001u};
  auto instance = ConditionInstance::create(sPool.executor(),
    std::make_unique<ConditionLogic>(),
    fresh_condition_id(),
    nonexistentParent,
    String{"EdAMissingParent"},
    mSink,
    as(),
    ::ua::test_helpers::concrete_condition_type(as(), 1));

  auto result = instance->try_initialize_sync();

  ASSERT_TRUE(result.is_bad()) << "initialize_async must fail when the parent does not exist";
  ASSERT_NE(result.shared_detail(), nullptr)
    << "instantiate_object failure must propagate ErrorDetail (the error-propagation contract) - "
       "regression: {b}-flip continuation drops the detail when reconstructing VoidResult";
}

// ---------------------------------------------------------------------------
// Pin ED-C: a Tier-B `find_node_async` failure inside
// `attach_address_space` forwards both the status code and a non-null
// `shared_detail()` to the user's callback.
// ---------------------------------------------------------------------------
//
// Property: at ua_condition_instance.cpp:532-535, when the initial
// `find_node_async` for the condition node returns bad, the coroutine
// forwards `nodeResult.shared_detail()` directly. We drive a natural
// failure by passing a non-existent condition NodeId. Per 4.4a NV-D, the
// default-namespace `find_node` failure carries a non-null detail with
// `mSource = "DefaultNamespace"`. ConditionInstance must preserve that.
// Falsifies a regression where the {b}-flip continuation discards the
// detail at the find-node check.

TEST_F(ConditionInstanceErrorDetailPin, AttachFlowConditionFindFailureForwardsStatusAndDetail)
{
  // Condition NodeId that has not been instantiated - find_node_async will
  // resolve to BadNodeIdUnknown (or similar) on attach.
  const NodeId missingCondition{1u, 999002u};
  auto instance = ConditionInstance::create(sPool.executor(),
    std::make_unique<ConditionLogic>(),
    missingCondition,
    NodeId{ObjectId::ObjectsFolder},
    String{"EdCMissingCondition"},
    mSink,
    as(),
    NodeId{ObjectTypeId::ConditionType});

  auto result = instance->try_attach_sync();

  ASSERT_TRUE(result.is_bad()) << "attach_async must fail when the condition node does not exist";
  ASSERT_NE(result.shared_detail(), nullptr)
    << "find_node failure must propagate ErrorDetail (the error-propagation contract) - "
       "regression: {b}-flip continuation drops the detail when reconstructing VoidResult";
}

namespace
{

// Custom AlarmConditionLogic that throws a UaException with a sentinel
// ErrorDetail when activate() is called. Used by ED-F to verify that the
// public-async `activate_async` catch-all routes through
// `ua::exception_to_status_code`, which preserves the UaException's detail
// pointer-identity. Inherits AlarmConditionLogic so that the dynamic_cast
// in activate_async (`:1849`) succeeds and the catch path is reached.
class ThrowingAlarmLogic : public AlarmConditionLogic
{
public:
  explicit ThrowingAlarmLogic(std::shared_ptr<const ErrorDetail> sentinel) : mSentinel(std::move(sentinel))
  {}

  ConditionStateTransition activate(uint16_t /*severity*/) override
  {
    throw UaException{Status::BadOutOfMemory, mSentinel};
  }

  std::shared_ptr<const ErrorDetail> sentinel() const
  {
    return mSentinel;
  }

private:
  std::shared_ptr<const ErrorDetail> mSentinel;
};

}  // namespace

// ---------------------------------------------------------------------------
// Pin ED-F: when an `*_async` catch-all (here `activate_async`) fires,
// the resulting bad VoidResult preserves the inner UaException's
// ErrorDetail by pointer-identity.
// ---------------------------------------------------------------------------
//
// Property: ua_condition_instance.cpp:1894-1903 wraps `alarmLogic->activate`
// in `try { ... } catch (...) { callback(ua::exception_to_status_code(...)); }`.
// `exception_to_status_code` (sdk/interface/core/general/ua_to_result.h:91-100)
// catches `UaException` and constructs the Result with the UaException's
// `take_detail()` - so the SAME `shared_ptr<const ErrorDetail>` instance
// flows through. Falsifies a regression where the {b} flip replaces the
// catch site with bare-status-code construction (e.g.
// `callback(VoidResult{Status::BadInternalError})`) and silently drops
// the detail. Pin asserts pointer-identity (the sentinel detail flows
// through) - the strongest guarantee at this boundary.

TEST_F(ConditionInstanceErrorDetailPin, ActivateAsyncCatchAllConvertsUaExceptionToBadResultPreservingDetail)
{
  auto sentinel =
    std::shared_ptr<const ErrorDetail>{make_error_detail("EdFSentinel", "ED-F sentinel detail", "PinTest")};
  auto logic = std::make_unique<ThrowingAlarmLogic>(sentinel);

  // No AddressSpace - Tier-A fast path only. activate_async runs entirely on
  // the strand and does not touch initialize_address_space.
  auto instance = ConditionInstance::create(
    sPool.executor(), std::move(logic), fresh_condition_id(), NodeId{1u, 100u}, String{"EdFSource"}, mSink);
  instance->enable_sync();

  std::promise<VoidResult> activatePromise;
  instance->activate_async(/*severity=*/500,
    [&activatePromise](VoidResult result) { activatePromise.set_value(std::move(result)); });
  auto result = activatePromise.get_future().get();

  ASSERT_TRUE(result.is_bad()) << "activate_async must surface the thrown UaException as bad";
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadOutOfMemory})
    << "status from UaException must flow through exception_to_status_code unchanged";
  ASSERT_NE(result.shared_detail(), nullptr) << "ErrorDetail must not be lost across the catch boundary";
  EXPECT_EQ(result.shared_detail(), sentinel) << "exception_to_status_code must forward the SAME ErrorDetail "
                                                 "pointer (pointer-identity) - regression: {b}-flip "
                                                 "catch swaps in a freshly-constructed detail";
}

namespace
{

// Custom ConditionLogic that throws a UaException with a sentinel
// ErrorDetail when add_comment() is called. add_comment is virtual on
// ConditionLogic (enable/disable are not), so this is the natural hook for
// driving a thrown UaException through `run_method_on_strand` from a
// real method-handler invocation. The handler closure at
// ua_condition_instance.cpp register_methods()'s AddComment site routes
// `run_method_on_strand`'s try/catch via `ua::exception_to_status_code`,
// which preserves the UaException's detail pointer-identity.
class ThrowingConditionLogic : public ConditionLogic
{
public:
  explicit ThrowingConditionLogic(std::shared_ptr<const ErrorDetail> sentinel)
    : mSentinel(std::move(sentinel))
  {}

  ConditionStateTransition add_comment(
    const ByteString& /*eventId*/, const LocalizedText& /*comment*/) override
  {
    throw UaException{Status::BadOutOfMemory, mSentinel};
  }

  std::shared_ptr<const ErrorDetail> sentinel() const
  {
    return mSentinel;
  }

private:
  std::shared_ptr<const ErrorDetail> mSentinel;
};

}  // namespace

// ---------------------------------------------------------------------------
// Pin ED-G: a method-handler invocation whose `run_method_on_strand`
// operation throws UaException with a sentinel ErrorDetail surfaces that
// sentinel detail by pointer-identity through the outer CallResult.
// ---------------------------------------------------------------------------
//
// Property: each per-method-handler closure tail in `register_methods()`
// (15 sites - Enable, Disable, AddComment, Acknowledge, Confirm, Suppress,
// Unsuppress, RemoveFromService, PlaceInService, Silence, Reset,
// TimedShelve, OneShotShelve, Unshelve, Respond) must forward the inner
// VoidResult's `shared_detail()` to the outer CallResult on the bad path.
// The pre-fix shape - `CallResult{CallMethodResult{r.status_code() = ...}}`
// using the good-path Result(T) ctor - silently dropped the detail at
// every site. The fix routes bad through
// `CallResult{vr.status_code(), vr.shared_detail()}`.
//
// AddComment is the only handler whose underlying logic method is virtual
// on the base ConditionLogic class (enable/disable are non-virtual), so it
// is the only site reachable via subclass override without driving a
// dynamic_cast'd subclass logic. The 14 sibling sites share the identical
// closure-tail shape; pinning AddComment exercises the shape that the
// other 14 sites copy verbatim.
//
// Falsifies a regression where any of the 15 closure tails reverts to
// good-outer-Result + status-only-CallMethodResult (the pre-fix bug) - at
// minimum at the AddComment site; review of the other 14 closure tails
// is a structural audit per the {b} runbook section 9 reviewer prompt.

TEST_F(ConditionInstanceErrorDetailPin, AddCommentMethodHandlerForwardsThrownErrorDetailIntoCallResult)
{
  auto sentinel =
    std::shared_ptr<const ErrorDetail>{make_error_detail("EdGSentinel", "ED-G sentinel detail", "PinTest")};
  auto logic = std::make_unique<ThrowingConditionLogic>(sentinel);

  // Initialize a real ConditionInstance so register_methods() runs and the
  // AddComment method handler is wired. Note: instantiate_object_coro
  // assigns a fresh NodeId to the new instance, so we must use
  // `instance->condition_id()` (post-init) - not the requested id - when
  // resolving children.
  auto instance = ConditionInstance::create(sPool.executor(),
    std::move(logic),
    fresh_condition_id(),
    NodeId{ObjectId::ObjectsFolder},
    String{"EdGSource"},
    mSink,
    as(),
    ::ua::test_helpers::concrete_condition_type(as(), 1));
  ASSERT_TRUE(instance->try_initialize_sync().is_good())
    << "initialize_sync must succeed so the AddComment method handler is registered";
  const auto conditionId = instance->condition_id();

  // Resolve the AddComment method node under the freshly-instantiated
  // condition instance and invoke it. The MethodAdapter routes the call
  // through ConditionInstance::run_method_on_strand -> ThrowingConditionLogic
  // ::add_comment (throws) -> exception_to_status_code (preserves sentinel
  // pointer-identity) -> closure tail (forwards to outer CallResult).
  std::promise<MethodAccessorResult> resolveP;
  instance_utils::find_child_method_accessor_by_browse_name_async(as(),
    conditionId,
    NodeId{ReferenceTypeId::HasComponent},
    QualifiedName{0u, "AddComment"},

    [&resolveP](MethodAccessorResult r) { resolveP.set_value(std::move(r)); });
  auto resolveResult = resolveP.get_future().get();
  ASSERT_TRUE(resolveResult.is_good())
    << "AddComment method must be reachable on the freshly-instantiated condition; status 0x" << std::hex
    << resolveResult.status_code().as_uint32();
  auto method = std::move(resolveResult).value();

  CallMethodRequest request;
  request.object_id() = conditionId;
  request.method_id() = method.get_node_id();
  request.input_arguments().resize(2);
  request.input_arguments()[0] = Variant{ByteString{}};
  request.input_arguments()[1] = Variant{LocalizedText{}};

  auto callResult = method.try_call_sync(request);

  ASSERT_TRUE(callResult.is_bad()) << "AddComment must surface the thrown UaException as a bad outer "
                                      "CallResult - regression: closure tail wraps a bad "
                                      "CallMethodResult inside a good outer CallResult, dropping the "
                                      "outer Result's bad-path slot entirely";
  EXPECT_EQ(callResult.status_code(), StatusCode{Status::BadOutOfMemory})
    << "status from UaException must flow through exception_to_status_code and the closure tail unchanged";
  ASSERT_NE(callResult.shared_detail(), nullptr)
    << "method-handler ErrorDetail must not be lost at the closure tail (the error-propagation contract) - "
       "regression: closure tail packages only status_code into CallMethodResult and drops the detail";
  EXPECT_EQ(callResult.shared_detail(), sentinel)
    << "closure tail must forward the SAME ErrorDetail pointer (pointer-identity) - "
       "regression: closure tail copies status only or synthesises a fresh detail";
}

}  // namespace ua::test::behaviour_pins
