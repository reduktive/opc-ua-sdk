// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_instance_utils.h"
#include "ua_numeric_range_parser.h"

#include "ua_self_owning_operation.h"

#include <boost/asio/strand.hpp>

#include "ua_attribute_id.h"
#include "ua_attribute_wire.h"
#include "ua_enum_value_type.h"
#include "ua_error_detail.h"
#include "ua_callback_safety.h"
#include "ua_namespace.h"
#include "ua_namespace_array.h"
#include "ua_namespace_route.h"
#include "ua_node_accessor_route.h"
#include "ua_on_strand.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_to_result.h"
#include "ua_to_string.h"
#include <limits>
#include <optional>
#include <utility>

namespace ua
{
namespace instance_utils
{

namespace
{

/// Answers the node's local HasTypeDefinition target, or nothing when it has none.
///
/// A plain function with one callback, where there used to be a self-owning flow struct with a
/// three-value `Step` enum. The struct existed to hold state BETWEEN steps, and this has one step:
/// fetch the references, scan them, answer. Nothing was ever held.
///
/// It stays callback-shaped rather than becoming a body because `NodeAccessor` exposes no executor,
/// and a body needs a strand to keep its own suspended handle on. Its callers all hold an
/// `AddressSpace`, so each of them awaits THIS through its own `await_step` and gets the post, the
/// strand and the ownership from the operation that called it.
void local_type_definition_id_async(NodeAccessor node, std::function<void(OptionalNodeIdResult)> onComplete)
{
  try
  {
    // The accessor is copied into the completion so the node outlives the call it is making.
    auto accessor = node;
    accessor.get_references_async(
      [node = std::move(node), onComplete = std::move(onComplete)](
        NodeAccessor::ReferencesResult result) mutable
      {
        // The answer carries the References read's code: a Good subcode, or an Uncertain code with the
        // References it holds.
        if (!result.has_value())
        {
          onComplete(OptionalNodeIdResult{result.status_code(), result.shared_detail()});
          return;
        }

        for (const auto& reference : result.value())
        {
          if (!reference.is_forward() || reference.is_remote())
          {
            continue;
          }
          if (reference.type_id() != NodeId{ReferenceTypeId::HasTypeDefinition})
          {
            continue;
          }
          const auto& target = reference.target_id();
          if (target.is_local())
          {
            onComplete(OptionalNodeIdResult{optional<NodeId>{target.node_id()}, result.status_code()});
            return;
          }
        }
        onComplete(OptionalNodeIdResult{optional<NodeId>{}, result.status_code()});
      });
  }
  catch (...)
  {
    const VoidResult bad = ua::exception_to_status_code(std::current_exception());
    onComplete(OptionalNodeIdResult{bad.status_code(), bad.shared_detail()});
  }
}

/// The parent-then-children walk behind `find_child_id_by_browse_name_async`, as one body.
///
/// A free function's operation has no component to hold its task, so it is owned by the work
/// outstanding on it. @see ua::async::SelfOwningOperation
class FindChildIdOperation final : public ua::async::SelfOwningOperation<FindChildIdOperation>
{
public:
  FindChildIdOperation(AddressSpace addressSpace, NodeId parent, NodeId refType, QualifiedName browseName,
    std::function<void(NodeIdResult)> onComplete)
    : ua::async::SelfOwningOperation<FindChildIdOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mParent(std::move(parent)), mRefType(std::move(refType)),
      mBrowseName(std::move(browseName)), mOnComplete(std::move(onComplete))
  {}

  static void start(AddressSpace addressSpace, NodeId parent, NodeId refType, QualifiedName browseName,
    std::function<void(NodeIdResult)> onComplete)
  {
    launch(std::make_shared<FindChildIdOperation>(std::move(addressSpace),
      std::move(parent),
      std::move(refType),
      std::move(browseName),
      std::move(onComplete)));
  }

private:
  friend class ua::async::SelfOwningOperation<FindChildIdOperation>;

  ua::async::Task<> run()
  {
    // A ROOT task: nobody awaits it, so an exception that escaped would be stored in a promise
    // nobody reads and the caller would never be answered.
    try
    {
      // EVERY lock of the address space is taken inside the initiate lambda, which runs
      // synchronously, so none of them is still held at a suspension point (R7). A body's locals
      // live to the end of their scope; a single body-scope lock here would keep the address space
      // alive across every await of the walk and make each later "has it gone?" check dead code.
      auto parentResult = co_await await_step<NodeAccessorResult>(
        [this](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            addressSpace->find_node_async(mParent, std::move(completion));
          }
          else
          {
            completion(
              NodeAccessorResult{ua::detail::address_space_gone("find_child_id_by_browse_name_async")});
          }
        });

      if (!parentResult.is_good())
      {
        const StatusCode refused = ua::detail::lookup_failure(
          mParent, parentResult.status_code(), "find_child_id_by_browse_name_async");
        fail(refused, refused.shared_detail());
        co_return;
      }

      NodeAccessor parent = std::move(parentResult).value();
      auto referencesResult = co_await await_step<NodeAccessor::ReferencesResult>(
        [this, &parent](auto completion) {
          ua::detail::NodeAccessorRoute::read_all_references(parent, std::move(completion), mAddressSpace);
        });

      if (!referencesResult.is_good())
      {
        const StatusCode refused = ua::detail::references_failure(
          referencesResult.status_code(), "find_child_id_by_browse_name_async");
        fail(refused, refused.shared_detail());
        co_return;
      }

      // The chain needed a `step_iteration` trampoline here, and said why: `find_node_async` fires
      // inline for in-memory namespaces, so a long walk over non-matching references recursed on one
      // stack and overflowed - visible under ASan, which inflates frame sizes. A loop cannot recurse,
      // and `await_step` posts each answer, so the trampoline is not replaced by anything: it stops
      // being a thing that has to exist.
      const ua::References references = std::move(referencesResult).value();
      // The first candidate that could not be resolved for a reason other than not existing: it may be the
      // child asked for, so when no candidate matches, the answer is its failure, not "no such child".
      std::optional<VoidResult> unresolved;
      for (const auto& reference : references.span())
      {
        if (!reference.is_forward() || reference.is_remote() || reference.type_id() != mRefType)
        {
          continue;
        }
        const auto target = reference.target_id();
        if (!target.is_local())
        {
          continue;
        }

        NodeId candidateId = target.node_id();
        auto candidate = co_await await_step<NodeAccessorResult>(
          [this, &candidateId](auto completion)
          {
            if (auto addressSpace = mAddressSpace.lock())
            {
              addressSpace->find_node_async(candidateId, std::move(completion));
            }
            else
            {
              completion(
                NodeAccessorResult{ua::detail::address_space_gone("find_child_id_by_browse_name_async")});
            }
          });

        if (candidate.is_good() && candidate.value().get_browse_name() == mBrowseName)
        {
          complete(NodeIdResult{std::move(candidateId)});
          co_return;
        }
        if (!candidate.is_good() && !unresolved &&
            candidate.status_code().as_status() != Status::BadNodeIdUnknown)
        {
          // A Bad answer is the target's failure; an Uncertain one, with or without the Node, is not acted
          // on, so the target was not resolved.
          unresolved.emplace(ua::detail::lookup_failure(
            candidateId, candidate.status_code(), "find_child_id_by_browse_name_async"));
        }
      }

      if (unresolved)
      {
        fail(unresolved->status_code(), unresolved->shared_detail());
        co_return;
      }
      fail(StatusCode{Status::BadNodeIdUnknown},
        ErrorDetail::build("BadNodeIdUnknown",
          "No child with matching browse name found",
          "find_child_id_by_browse_name_async")
          .context(ua::ContextKeys::nodeBrowseName, ua::to_string(mBrowseName))
          .context(ua::ContextKeys::nodeId, ua::to_string(mParent)));
    }
    catch (const ua::async::Abandoned&)
    {
      // This operation carries no withdrawal token, so nothing can throw this - but a root task says
      // what it does with one rather than letting the catch-all answer a caller who is not there.
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      fail(bad.status_code(), bad.shared_detail());
    }
  }

  /// Answers when the body's frame could not be allocated. @see ua::async::SelfOwningOperation
  void fail_to_start(StatusCode status)
  {
    fail(status, status.shared_detail());
  }

  /// Answers the caller exactly once and contains consumer exceptions.
  void complete(NodeIdResult result)
  {
    if (auto onComplete = std::exchange(mOnComplete, nullptr))
    {
      ua::detail::invoke_user_callback(mLogger, onComplete, std::move(result));
    }
  }

  void fail(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    complete(NodeIdResult{status, std::move(detail)});
  }

  WeakAddressSpace mAddressSpace;
  NodeId mParent;
  NodeId mRefType;
  QualifiedName mBrowseName;
  std::function<void(NodeIdResult)> mOnComplete;
};

/// Walks up HasSubtype from the node's own type definition until it reaches @p baseTypeDef.
///
/// @see ua::async::SelfOwningOperation
class AttachSubtypeOperation final : public ua::async::SelfOwningOperation<AttachSubtypeOperation>
{
public:
  AttachSubtypeOperation(AddressSpace addressSpace, NodeId existingNode, NodeId baseTypeDef,
    std::function<void(VoidResult)> onComplete)
    : ua::async::SelfOwningOperation<AttachSubtypeOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mExistingNode(std::move(existingNode)),
      mBaseTypeDef(std::move(baseTypeDef)), mOnComplete(std::move(onComplete))
  {}

  static void start(AddressSpace addressSpace, NodeId existingNode, NodeId baseTypeDef,
    std::function<void(VoidResult)> onComplete)
  {
    launch(std::make_shared<AttachSubtypeOperation>(
      std::move(addressSpace), std::move(existingNode), std::move(baseTypeDef), std::move(onComplete)));
  }

private:
  friend class ua::async::SelfOwningOperation<AttachSubtypeOperation>;

  ua::async::Task<> run()
  {
    try
    {
      // Every lock of the weak address space is taken inside an initiate lambda, which runs
      // synchronously, so none is held at a suspension point (R7).
      auto existing = co_await await_step<NodeAccessorResult>(
        [this](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            addressSpace->find_node_async(mExistingNode, std::move(completion));
          }
          else
          {
            completion(NodeAccessorResult{ua::detail::address_space_gone("attach_subtype_async")});
          }
        });

      if (!existing.is_good())
      {
        const StatusCode refused =
          ua::detail::lookup_failure(mExistingNode, existing.status_code(), "attach_subtype_async");
        fail(refused, refused.shared_detail());
        co_return;
      }

      auto typeDefinition = co_await await_step<OptionalNodeIdResult>(
        [node = std::move(existing).value()](auto completion) mutable
        { local_type_definition_id_async(std::move(node), std::move(completion)); });

      if (!typeDefinition.is_good())
      {
        const StatusCode refused =
          ua::detail::references_failure(typeDefinition.status_code(), "attach_subtype_async");
        fail(refused, refused.shared_detail());
        co_return;
      }
      const auto& existingType = typeDefinition.value();
      if (!existingType)
      {
        fail(StatusCode{Status::BadTypeMismatch},
          ErrorDetail::build("BadTypeMismatch", "Node has no type definition", "attach_subtype_async")
            .context(ua::ContextKeys::nodeId, ua::to_string(mExistingNode)));
        co_return;
      }

      // The chain expressed this walk as `walk_step` calling itself back through the executor, for
      // the same reason every walk in this file did: an inline `find_node_async` would otherwise
      // recurse on one stack. A loop cannot, and `await_step` still posts each answer.
      NodeId currentTypeId = existingType.value();
      while (currentTypeId != mBaseTypeDef)
      {
        auto typeNode = co_await await_step<NodeAccessorResult>(
          [this, &currentTypeId](auto completion)
          {
            if (auto addressSpace = mAddressSpace.lock())
            {
              addressSpace->find_node_async(currentTypeId, std::move(completion));
            }
            else
            {
              completion(NodeAccessorResult{ua::detail::address_space_gone("attach_subtype_async")});
            }
          });

        // Documented best-effort: a type node that cannot be resolved ENDS the walk with
        // BadTypeMismatch rather than surfacing the lookup failure, and so does a reference fetch
        // that fails. Both are the pre-flip behaviour and both are kept. The walk decides whether the
        // type is compatible, so an Uncertain answer to either is refused, not read as a mismatch.
        if (typeNode.is_uncertain())
        {
          const StatusCode refused =
            ua::detail::lookup_failure(currentTypeId, typeNode.status_code(), "attach_subtype_async");
          fail(refused, refused.shared_detail());
          co_return;
        }
        if (!typeNode.is_good())
        {
          mismatch(currentTypeId);
          co_return;
        }

        auto typeReferences = co_await await_step<NodeAccessor::ReferencesResult>(
          [node = std::move(typeNode).value()](auto completion) mutable
          { node.get_references_async(std::move(completion)); });

        if (typeReferences.is_uncertain())
        {
          const StatusCode refused =
            ua::detail::references_failure(typeReferences.status_code(), "attach_subtype_async");
          fail(refused, refused.shared_detail());
          co_return;
        }
        if (!typeReferences.is_good())
        {
          mismatch(currentTypeId);
          co_return;
        }

        // The INVERSE HasSubtype reference is the one that names the parent type.
        optional<NodeId> parentType;
        for (const auto& reference : typeReferences.value())
        {
          if (reference.is_forward() || reference.is_remote())
          {
            continue;
          }
          if (reference.type_id() != NodeId{ReferenceTypeId::HasSubtype})
          {
            continue;
          }
          const auto& target = reference.target_id();
          if (target.is_local())
          {
            parentType = target.node_id();
            break;
          }
        }

        if (!parentType)
        {
          mismatch(currentTypeId);
          co_return;
        }
        currentTypeId = *parentType;
      }

      complete(VoidResult{});
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      fail(bad.status_code(), bad.shared_detail());
    }
  }

  void fail_to_start(StatusCode status)
  {
    fail(status, status.shared_detail());
  }

  void mismatch(const NodeId& actual)
  {
    fail(StatusCode{Status::BadTypeMismatch},
      ErrorDetail::build("BadTypeMismatch",
        "Type definition is not a subtype of the expected base type",
        "attach_subtype_async")
        .context(ua::ContextKeys::nodeId, ua::to_string(mExistingNode))
        .context(ua::ContextKeys::expected, ua::to_string(mBaseTypeDef))
        .context(ua::ContextKeys::actual, ua::to_string(actual)));
  }

  void complete(VoidResult result)
  {
    if (auto onComplete = std::move(mOnComplete))
    {
      onComplete(std::move(result));
    }
  }

  void fail(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    complete(VoidResult{status, std::move(detail)});
  }

  WeakAddressSpace mAddressSpace;
  NodeId mExistingNode;
  NodeId mBaseTypeDef;
  std::function<void(VoidResult)> mOnComplete;
};

/// Requires the node's type definition to be exactly @p expectedTypeDef.
///
/// @see ua::async::SelfOwningOperation
class AttachExactOperation final : public ua::async::SelfOwningOperation<AttachExactOperation>
{
public:
  AttachExactOperation(AddressSpace addressSpace, NodeId existingNode, NodeId expectedTypeDef,
    std::function<void(VoidResult)> onComplete)
    : ua::async::SelfOwningOperation<AttachExactOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mExistingNode(std::move(existingNode)),
      mExpectedTypeDef(std::move(expectedTypeDef)), mOnComplete(std::move(onComplete))
  {}

  static void start(AddressSpace addressSpace, NodeId existingNode, NodeId expectedTypeDef,
    std::function<void(VoidResult)> onComplete)
  {
    launch(std::make_shared<AttachExactOperation>(
      std::move(addressSpace), std::move(existingNode), std::move(expectedTypeDef), std::move(onComplete)));
  }

private:
  friend class ua::async::SelfOwningOperation<AttachExactOperation>;

  ua::async::Task<> run()
  {
    try
    {
      auto existing = co_await await_step<NodeAccessorResult>(
        [this](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            addressSpace->find_node_async(mExistingNode, std::move(completion));
          }
          else
          {
            completion(NodeAccessorResult{ua::detail::address_space_gone("attach_exact_async")});
          }
        });

      if (!existing.is_good())
      {
        const StatusCode refused =
          ua::detail::lookup_failure(mExistingNode, existing.status_code(), "attach_exact_async");
        fail(refused, refused.shared_detail());
        co_return;
      }

      auto typeDefinition = co_await await_step<OptionalNodeIdResult>(
        [node = std::move(existing).value()](auto completion) mutable
        { local_type_definition_id_async(std::move(node), std::move(completion)); });

      if (!typeDefinition.is_good())
      {
        const StatusCode refused =
          ua::detail::references_failure(typeDefinition.status_code(), "attach_exact_async");
        fail(refused, refused.shared_detail());
        co_return;
      }

      const auto& actual = typeDefinition.value();
      if (!actual || *actual != mExpectedTypeDef)
      {
        fail(StatusCode{Status::BadTypeMismatch},
          ErrorDetail::build(
            "BadTypeMismatch", "Type definition does not match expected type", "attach_exact_async")
            .context(ua::ContextKeys::nodeId, ua::to_string(mExistingNode))
            .context(ua::ContextKeys::expected, ua::to_string(mExpectedTypeDef))
            .context(ua::ContextKeys::actual, actual ? ua::to_string(*actual) : std::string{"(none)"}));
        co_return;
      }

      complete(VoidResult{});
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      fail(bad.status_code(), bad.shared_detail());
    }
  }

  void fail_to_start(StatusCode status)
  {
    fail(status, status.shared_detail());
  }

  void complete(VoidResult result)
  {
    if (auto onComplete = std::move(mOnComplete))
    {
      onComplete(std::move(result));
    }
  }

  void fail(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    complete(VoidResult{status, std::move(detail)});
  }

  WeakAddressSpace mAddressSpace;
  NodeId mExistingNode;
  NodeId mExpectedTypeDef;
  std::function<void(VoidResult)> mOnComplete;
};

/// Resolves a node, requires it to be a Variable, and reads its Value.
///
/// @see ua::async::SelfOwningOperation
class ReadVariableValueOperation final : public ua::async::SelfOwningOperation<ReadVariableValueOperation>
{
public:
  ReadVariableValueOperation(AddressSpace addressSpace, NodeId target,
    std::function<void(DataValueResult)> onComplete, ValueQualityPolicy qualityPolicy)
    : ua::async::SelfOwningOperation<ReadVariableValueOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mTarget(std::move(target)), mOnComplete(std::move(onComplete)),
      mQualityPolicy(qualityPolicy)
  {}

  static void start(AddressSpace addressSpace, NodeId target, std::function<void(DataValueResult)> onComplete,
    ValueQualityPolicy qualityPolicy)
  {
    launch(std::make_shared<ReadVariableValueOperation>(
      std::move(addressSpace), std::move(target), std::move(onComplete), qualityPolicy));
  }

private:
  friend class ua::async::SelfOwningOperation<ReadVariableValueOperation>;

  ua::async::Task<> run()
  {
    try
    {
      auto found = co_await await_step<NodeAccessorResult>(
        [this](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            addressSpace->find_node_async(mTarget, std::move(completion));
          }
          else
          {
            completion(NodeAccessorResult{ua::detail::address_space_gone("read_variable_value_async")});
          }
        });

      if (!found.has_value())
      {
        fail(found.status_code(), found.shared_detail());
        co_return;
      }

      auto variable = found.value().as<VariableAccessor>();
      if (!variable)
      {
        fail(StatusCode{Status::BadTypeMismatch},
          ErrorDetail::build("BadTypeMismatch", "Node is not a VariableAccessor", "read_variable_value_async")
            .context(ua::ContextKeys::nodeId, ua::to_string(mTarget)));
        co_return;
      }

      ReadValueId readValueId;
      readValueId.node_id() = mTarget;
      readValueId.attribute_id() = utils::to_underlying(AttributeId::Value);

      auto readResult = co_await await_step<DataValueResult>(
        [&variable, &readValueId](auto completion)
        {
          // Instantiation-time read: no Session, so no per-caller projection applies.
          variable->read_value_async(Duration{}, true, readValueId, nullptr, std::move(completion));
        });

      // The answer carries the lookup's code and the read's, combined as and_then combines two steps: a Good
      // subcode or an Uncertain code of either reaches the caller.
      readResult = ua::detail::carried(std::move(readResult), found.status_code());
      if (!readResult.has_value())
      {
        fail(readResult.status_code(), readResult.shared_detail());
        co_return;
      }

      const StatusCode answered = readResult.status_code();
      auto dataValue = std::move(readResult).value();
      // The two-layer model (OPC 10000-4: a Read succeeds while the VALUE it returns is bad) is what
      // a caller reading a value sees, and it is what the book teaches. Only the FlattenBadQuality
      // policy collapses the layers, for the SDK's own callers - alarm evaluation - which must not treat
      // a bad reading as a usable number.
      if (mQualityPolicy == ValueQualityPolicy::FlattenBadQuality)
      {
        const auto status = dataValue.status().value_or(StatusCode{Status::Good});
        if (status.is_bad())
        {
          fail(status,
            ErrorDetail::build(
              "BadVariableStatus", "Variable value has bad status", "read_variable_value_async")
              .context(ua::ContextKeys::nodeId, ua::to_string(mTarget)));
          co_return;
        }
      }

      complete(DataValueResult{std::move(dataValue), answered});
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      fail(bad.status_code(), bad.shared_detail());
    }
  }

  void fail_to_start(StatusCode status)
  {
    fail(status, status.shared_detail());
  }

  void complete(DataValueResult result)
  {
    if (auto onComplete = std::move(mOnComplete))
    {
      onComplete(std::move(result));
    }
  }

  void fail(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    complete(DataValueResult{status, std::move(detail)});
  }

  WeakAddressSpace mAddressSpace;
  NodeId mTarget;
  std::function<void(DataValueResult)> mOnComplete;
  ValueQualityPolicy mQualityPolicy{ValueQualityPolicy::PreserveQuality};
};

/// Resolves a node, requires it to be a Variable, and writes its Value.
///
/// @see ua::async::SelfOwningOperation
class WriteVariableValueOperation final : public ua::async::SelfOwningOperation<WriteVariableValueOperation>
{
public:
  WriteVariableValueOperation(
    AddressSpace addressSpace, NodeId target, DataValue value, std::function<void(VoidResult)> onComplete)
    : ua::async::SelfOwningOperation<WriteVariableValueOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mTarget(std::move(target)), mValue(std::move(value)),
      mOnComplete(std::move(onComplete))
  {}

  static void start(
    AddressSpace addressSpace, NodeId target, DataValue value, std::function<void(VoidResult)> onComplete)
  {
    launch(std::make_shared<WriteVariableValueOperation>(
      std::move(addressSpace), std::move(target), std::move(value), std::move(onComplete)));
  }

private:
  friend class ua::async::SelfOwningOperation<WriteVariableValueOperation>;

  ua::async::Task<> run()
  {
    try
    {
      auto found = co_await await_step<NodeAccessorResult>(
        [this](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            addressSpace->find_node_async(mTarget, std::move(completion));
          }
          else
          {
            completion(NodeAccessorResult{ua::detail::address_space_gone("write_variable_value_async")});
          }
        });

      if (!found.is_good())
      {
        const StatusCode refused =
          ua::detail::lookup_failure(mTarget, found.status_code(), "write_variable_value_async");
        fail(refused, refused.shared_detail());
        co_return;
      }

      auto variable = found.value().as<VariableAccessor>();
      if (!variable)
      {
        fail(StatusCode{Status::BadTypeMismatch},
          ErrorDetail::build(
            "BadTypeMismatch", "Node is not a VariableAccessor", "write_variable_value_async")
            .context(ua::ContextKeys::nodeId, ua::to_string(mTarget)));
        co_return;
      }

      // The write's own answer IS this operation's answer, good or bad: the chain forwarded it
      // unexamined and so does this.
      auto writeResult = co_await await_step<VoidResult>([&variable, this](auto completion)
        { variable->write_value_async(std::move(mValue), std::move(completion)); });

      complete(std::move(writeResult));
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      fail(bad.status_code(), bad.shared_detail());
    }
  }

  void fail_to_start(StatusCode status)
  {
    fail(status, status.shared_detail());
  }

  void complete(VoidResult result)
  {
    if (auto onComplete = std::move(mOnComplete))
    {
      onComplete(std::move(result));
    }
  }

  void fail(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    complete(VoidResult{status, std::move(detail)});
  }

  WeakAddressSpace mAddressSpace;
  NodeId mTarget;
  DataValue mValue;
  std::function<void(VoidResult)> mOnComplete;
};

/// Finds a Method child by browse name, resolves it, and installs its call handler.
///
/// @see ua::async::SelfOwningOperation
class ResolveAndSetMethodHandlerOperation final
  : public ua::async::SelfOwningOperation<ResolveAndSetMethodHandlerOperation>
{
public:
  ResolveAndSetMethodHandlerOperation(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    MethodCallSource::CallHandler handler, std::function<void(VoidResult)> onComplete)
    : ua::async::SelfOwningOperation<ResolveAndSetMethodHandlerOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mParent(std::move(parent)), mBrowseName(std::move(browseName)),
      mHandler(std::move(handler)), mOnComplete(std::move(onComplete))
  {}

  static void start(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
    MethodCallSource::CallHandler handler, std::function<void(VoidResult)> onComplete)
  {
    launch(std::make_shared<ResolveAndSetMethodHandlerOperation>(std::move(addressSpace),
      std::move(parent),
      std::move(browseName),
      std::move(handler),
      std::move(onComplete)));
  }

private:
  friend class ua::async::SelfOwningOperation<ResolveAndSetMethodHandlerOperation>;

  ua::async::Task<> run()
  {
    try
    {
      auto childId = co_await await_step<NodeIdResult>(
        [this](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            find_child_id_by_browse_name_async(*addressSpace,
              mParent,
              NodeId{ReferenceTypeId::HasComponent},
              mBrowseName,
              std::move(completion));
          }
          else
          {
            completion(NodeIdResult{ua::detail::address_space_gone("resolve_and_set_method_handler_async")});
          }
        });

      if (!childId.is_good())
      {
        fail(childId.status_code(), childId.shared_detail());
        co_return;
      }

      const NodeId resolvedChild = std::move(childId).value();
      auto found = co_await await_step<NodeAccessorResult>(
        [this, &resolvedChild](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            addressSpace->find_node_async(resolvedChild, std::move(completion));
          }
          else
          {
            completion(
              NodeAccessorResult{ua::detail::address_space_gone("resolve_and_set_method_handler_async")});
          }
        });

      if (!found.is_good())
      {
        const StatusCode refused = ua::detail::lookup_failure(
          resolvedChild, found.status_code(), "resolve_and_set_method_handler_async");
        fail(refused, refused.shared_detail());
        co_return;
      }

      auto* target = found.value()->method_call_source();
      if (!target)
      {
        fail(StatusCode{Status::BadNotSupported},
          ErrorDetail::build("BadNotSupported",
            "Node does not implement MethodCallSource",
            "resolve_and_set_method_handler_async")
            .context(ua::ContextKeys::nodeId, ua::to_string(resolvedChild)));
        co_return;
      }

      // The setter's own answer IS this operation's answer, its code whatever it is.
      complete(VoidResult{target->set_call_handler(std::move(mHandler))});
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      fail(bad.status_code(), bad.shared_detail());
    }
  }

  void fail_to_start(StatusCode status)
  {
    fail(status, status.shared_detail());
  }

  void complete(VoidResult result)
  {
    if (auto onComplete = std::move(mOnComplete))
    {
      onComplete(std::move(result));
    }
  }

  void fail(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    complete(VoidResult{status, std::move(detail)});
  }

  WeakAddressSpace mAddressSpace;
  NodeId mParent;
  QualifiedName mBrowseName;
  MethodCallSource::CallHandler mHandler;
  std::function<void(VoidResult)> mOnComplete;
};

/// Resolves a Variable and installs a read or a write value handler on it.
///
/// Templated over the SETTER because that is the only thing the two differ in - the resolve step,
/// the ExternalValueSource check and the answer are identical.
/// @see ua::async::SelfOwningOperation
template<typename Handler, typename Setter>
class ResolveAndSetValueHandlerOperation final
  : public ua::async::SelfOwningOperation<ResolveAndSetValueHandlerOperation<Handler, Setter>>
{
public:
  using Base = ua::async::SelfOwningOperation<ResolveAndSetValueHandlerOperation<Handler, Setter>>;

  ResolveAndSetValueHandlerOperation(AddressSpace addressSpace, NodeId variableNode, Handler handler,
    Setter setter, std::function<void(VoidResult)> onComplete, const char* opName)
    : Base(boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mVariableNode(std::move(variableNode)),
      mHandler(std::move(handler)), mSetter(std::move(setter)), mOnComplete(std::move(onComplete)),
      mOpName(opName)
  {}

  static void start(AddressSpace addressSpace, NodeId variableNode, Handler handler, Setter setter,
    std::function<void(VoidResult)> onComplete, const char* opName)
  {
    Base::launch(std::make_shared<ResolveAndSetValueHandlerOperation>(std::move(addressSpace),
      std::move(variableNode),
      std::move(handler),
      std::move(setter),
      std::move(onComplete),
      opName));
  }

private:
  friend class ua::async::SelfOwningOperation<ResolveAndSetValueHandlerOperation<Handler, Setter>>;

  ua::async::Task<> run()
  {
    try
    {
      auto found = co_await this->template await_step<NodeAccessorResult>(
        [this](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            addressSpace->find_node_async(mVariableNode, std::move(completion));
          }
          else
          {
            completion(
              NodeAccessorResult{ua::detail::address_space_gone("resolve_and_set_value_handler_async")});
          }
        });

      if (!found.is_good())
      {
        const StatusCode refused = ua::detail::lookup_failure(mVariableNode, found.status_code(), mOpName);
        fail(refused, refused.shared_detail());
        co_return;
      }

      auto* target = found.value()->external_value_source();
      if (!target)
      {
        fail(StatusCode{Status::BadNotSupported},
          ErrorDetail::build("BadNotSupported", "Node does not implement ExternalValueSource", mOpName)
            .context(ua::ContextKeys::nodeId, ua::to_string(mVariableNode)));
        co_return;
      }

      // The setter's own answer IS this operation's answer, good or bad.
      complete(mSetter(*target, std::move(mHandler)));
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      fail(bad.status_code(), bad.shared_detail());
    }
  }

  void fail_to_start(StatusCode status)
  {
    fail(status, status.shared_detail());
  }

  void complete(VoidResult result)
  {
    if (auto onComplete = std::move(mOnComplete))
    {
      onComplete(std::move(result));
    }
  }

  void fail(StatusCode status, std::shared_ptr<const ErrorDetail> detail)
  {
    complete(VoidResult{status, std::move(detail)});
  }

  WeakAddressSpace mAddressSpace;
  NodeId mVariableNode;
  Handler mHandler;
  Setter mSetter;
  std::function<void(VoidResult)> mOnComplete;
  const char* mOpName;
};

}  // namespace

// =====================================================================
// Public API - *_async (callback-canonical)
// =====================================================================

void get_local_type_definition_id_async(
  NodeAccessor node, std::function<void(OptionalNodeIdResult)> onComplete) noexcept
{
  local_type_definition_id_async(std::move(node), std::move(onComplete));
}

void attach_exact_async(AddressSpace addressSpace, NodeId existingNode, NodeId expectedTypeDef,
  std::function<void(VoidResult)> onComplete) noexcept
{
  AttachExactOperation::start(
    std::move(addressSpace), std::move(existingNode), std::move(expectedTypeDef), std::move(onComplete));
}

void attach_subtype_async(AddressSpace addressSpace, NodeId existingNode, NodeId baseTypeDef,
  std::function<void(VoidResult)> onComplete) noexcept
{
  AttachSubtypeOperation::start(
    std::move(addressSpace), std::move(existingNode), std::move(baseTypeDef), std::move(onComplete));
}

void read_variable_value_async(
  AddressSpace addressSpace, NodeId target, std::function<void(DataValueResult)> onComplete) noexcept
{
  ReadVariableValueOperation::start(
    std::move(addressSpace), std::move(target), std::move(onComplete), ValueQualityPolicy::FlattenBadQuality);
}

void read_variable_data_value_async(
  AddressSpace addressSpace, NodeId target, std::function<void(DataValueResult)> onComplete) noexcept
{
  ReadVariableValueOperation::start(
    std::move(addressSpace), std::move(target), std::move(onComplete), ValueQualityPolicy::PreserveQuality);
}

void write_variable_value_async(AddressSpace addressSpace, NodeId target, DataValue value,
  std::function<void(VoidResult)> onComplete) noexcept
{
  WriteVariableValueOperation::start(
    std::move(addressSpace), std::move(target), std::move(value), std::move(onComplete));
}

void find_child_id_by_browse_name_async(AddressSpace addressSpace, NodeId parent, NodeId refType,
  QualifiedName browseName, std::function<void(NodeIdResult)> onComplete) noexcept
{
  FindChildIdOperation::start(std::move(addressSpace),
    std::move(parent),
    std::move(refType),
    std::move(browseName),
    std::move(onComplete));
}

void find_child_by_browse_name_async(AddressSpace addressSpace, NodeId parent, NodeId refType,
  QualifiedName browseName, std::function<void(NodeAccessorResult)> onComplete) noexcept
{
  Logger logger;
  try
  {
    logger = addressSpace.logger();
    const auto weakAddressSpace = addressSpace.weak();
    // Resolving the final accessor is a new operation; the child-id completion retains no owner.
    auto findCb = [weakAddressSpace, logger, onComplete](NodeIdResult idResult) mutable
    {
      try
      {
        if (!idResult.is_good())
        {
          ua::detail::invoke_user_callback(
            logger, onComplete, NodeAccessorResult{idResult.status_code(), idResult.shared_detail()});
          return;
        }
        if (auto locked = weakAddressSpace.lock())
        {
          locked->find_node_async(idResult.value(),
            [logger, onComplete](NodeAccessorResult result) mutable
            { ua::detail::invoke_user_callback(logger, onComplete, std::move(result)); });
        }
        else
        {
          ua::detail::invoke_user_callback(logger,
            onComplete,
            NodeAccessorResult{ua::detail::address_space_gone("find_child_by_browse_name_async")});
        }
      }
      catch (...)
      {
        ua::detail::invoke_user_callback(
          logger, onComplete, NodeAccessorResult{ua::exception_to_status_code(std::current_exception())});
      }
    };
    find_child_id_by_browse_name_async(std::move(addressSpace),
      std::move(parent),
      std::move(refType),
      std::move(browseName),
      std::move(findCb));
  }
  catch (...)
  {
    ua::detail::invoke_user_callback(
      logger, onComplete, NodeAccessorResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void find_child_method_accessor_by_browse_name_async(AddressSpace addressSpace, NodeId parent, NodeId refType,
  QualifiedName browseName, std::function<void(MethodAccessorResult)> onComplete) noexcept
{
  auto cb = [onComplete = std::move(onComplete)](NodeAccessorResult childResult) mutable
  {
    if (!childResult.has_value())
    {
      onComplete(MethodAccessorResult{childResult.status_code(), childResult.shared_detail()});
      return;
    }
    auto methodOpt = childResult.value().as<MethodAccessor>();
    if (!methodOpt)
    {
      onComplete(MethodAccessorResult{StatusCode{Status::BadTypeMismatch},
        ErrorDetail::build("BadTypeMismatch",
          "Node is not a MethodAccessor",
          "find_child_method_accessor_by_browse_name_async")
          .context(ua::ContextKeys::nodeId, ua::to_string(childResult.value().get_node_id()))});
      return;
    }
    onComplete(MethodAccessorResult{*methodOpt, childResult.status_code()});
  };
  find_child_by_browse_name_async(
    std::move(addressSpace), std::move(parent), std::move(refType), std::move(browseName), std::move(cb));
}

void find_child_variable_accessor_by_browse_name_async(AddressSpace addressSpace, NodeId parent,
  NodeId refType, QualifiedName browseName, std::function<void(VariableAccessorResult)> onComplete) noexcept
{
  Logger logger;
  try
  {
    logger = addressSpace.logger();
    auto cb = [logger, onComplete](NodeAccessorResult childResult) mutable
    {
      VariableAccessorResult result{StatusCode{Status::BadInternalError}};
      try
      {
        if (!childResult.has_value())
        {
          result = VariableAccessorResult{childResult.status_code(), childResult.shared_detail()};
        }
        else if (auto variable = childResult.value().as<VariableAccessor>())
        {
          result = VariableAccessorResult{*variable, childResult.status_code()};
        }
        else
        {
          result = VariableAccessorResult{StatusCode{Status::BadTypeMismatch,
            ErrorDetail::build("BadTypeMismatch",
              "Node is not a VariableAccessor",
              "find_child_variable_accessor_by_browse_name_async")
              .context(ua::ContextKeys::nodeId, ua::to_string(childResult.value().get_node_id()))}};
        }
      }
      catch (...)
      {
        result = VariableAccessorResult{ua::exception_to_status_code(std::current_exception())};
      }
      ua::detail::invoke_user_callback(logger, onComplete, std::move(result));
    };
    find_child_by_browse_name_async(
      std::move(addressSpace), std::move(parent), std::move(refType), std::move(browseName), std::move(cb));
  }
  catch (...)
  {
    ua::detail::invoke_user_callback(
      logger, onComplete, VariableAccessorResult{ua::exception_to_status_code(std::current_exception())});
  }
}

void resolve_and_set_method_handler_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  MethodCallSource::CallHandler handler, std::function<void(VoidResult)> onComplete) noexcept
{
  ResolveAndSetMethodHandlerOperation::start(std::move(addressSpace),
    std::move(parent),
    std::move(browseName),
    std::move(handler),
    std::move(onComplete));
}

void resolve_and_set_value_source_async(AddressSpace addressSpace, NodeId variableNode,
  std::shared_ptr<ValueSource> source, std::function<void(VoidResult)> onComplete) noexcept
{
  auto setter = [](ExternalValueSource& target, std::shared_ptr<ValueSource> attached) -> VoidResult
  {
    return target.set_value_source(std::move(attached));
  };
  ResolveAndSetValueHandlerOperation<std::shared_ptr<ValueSource>, decltype(setter)>::start(
    std::move(addressSpace),
    std::move(variableNode),
    std::move(source),
    std::move(setter),
    std::move(onComplete),
    "resolve_and_set_value_source_async");
}

namespace
{

/// The current value of a MultiStateValueDiscrete Variable as the Int64 its EnumValues entries are keyed by.
///
/// Part 8 section 5.3.3.5 lets the Variable's DataType be any integer Number type, so the value is widened
/// from whichever one it holds; `Variant::to<int64_t>` extracts only an Int64. A UInt64 above the Int64
/// range, or anything not an integer, has no entry to match.
std::optional<int64_t> enumeration_value(const Variant& value)
{
  if (value.is_int8())
    return value.as<int8_t>();
  if (value.is_uint8())
    return value.as<uint8_t>();
  if (value.is_int16())
    return value.as<int16_t>();
  if (value.is_uint16())
    return value.as<uint16_t>();
  if (value.is_int32())
    return value.as<int32_t>();
  if (value.is_uint32())
    return value.as<uint32_t>();
  if (value.is_int64())
    return value.as<int64_t>();
  if (value.is_uint64() && value.as<uint64_t>() <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
    return static_cast<int64_t>(value.as<uint64_t>());
  return std::nullopt;
}

/// Reads a MultiStateValueDiscrete Variable's Value and EnumValues and answers the matching entry's text.
/// @see project_value_as_text_async
class ProjectValueAsTextOperation final : public ua::async::SelfOwningOperation<ProjectValueAsTextOperation>
{
public:
  ProjectValueAsTextOperation(
    AddressSpace addressSpace, NodeId dataItem, std::function<void(DataValueResult)> onComplete)
    : ua::async::SelfOwningOperation<ProjectValueAsTextOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mDataItem(std::move(dataItem)), mOnComplete(std::move(onComplete))
  {}

  static void start(
    AddressSpace addressSpace, NodeId dataItem, std::function<void(DataValueResult)> onComplete)
  {
    launch(std::make_shared<ProjectValueAsTextOperation>(
      std::move(addressSpace), std::move(dataItem), std::move(onComplete)));
  }

private:
  friend class ua::async::SelfOwningOperation<ProjectValueAsTextOperation>;

  ua::async::Task<> run()
  {
    try
    {
      // The address space is locked only inside each step's initiation, so the operation - which every
      // completion it hands out owns - never keeps it alive across a suspension (ua_namespace.h, Ownership).
      auto owner = co_await await_step<DataValueResult>(
        [this](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
            read_variable_data_value_async(std::move(*addressSpace), mDataItem, std::move(completion));
          else
            completion(DataValueResult{ua::detail::address_space_gone("project_value_as_text_async")});
        });
      if (!owner.has_value())
      {
        complete(std::move(owner));
        co_return;
      }
      // The text carries the code of the reads it is made from: a Good subcode, or an Uncertain code with the
      // Value it holds.
      StatusCode answered = owner.status_code();

      // The text carries the Value's timestamps: the text changes exactly when the Value does, and a
      // sampler comparing timestamps must not see a change the Value did not make.
      DataValue projected;
      projected.source_timestamp() = owner.value().source_timestamp();
      projected.server_timestamp() = owner.value().server_timestamp();

      const auto& ownerStatus = owner.value().status();
      const auto numeric =
        ownerStatus && ownerStatus->is_bad() ? std::nullopt : enumeration_value(owner.value().value());
      if (!numeric)
      {
        complete(DataValueResult{std::move(projected), answered});
        co_return;
      }

      auto enumValuesId = co_await await_step<NodeIdResult>(
        [this](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            find_child_id_by_browse_name_async(std::move(*addressSpace),
              mDataItem,
              NodeId{ReferenceTypeId::HasProperty},
              QualifiedName{0, "EnumValues"},
              std::move(completion));
          }
          else
          {
            completion(NodeIdResult{ua::detail::address_space_gone("project_value_as_text_async")});
          }
        });
      if (!enumValuesId.is_good())
      {
        // No EnumValues Property (the lookup's Bad_NodeIdUnknown) leaves the text empty; any other failure, a
        // refusal or an address space that is gone, is the answer.
        if (enumValuesId.status_code() == StatusCode{Status::BadNodeIdUnknown})
          complete(DataValueResult{std::move(projected), answered});
        else
          complete(DataValueResult{enumValuesId.status_code(), enumValuesId.shared_detail()});
        co_return;
      }

      auto enumValues = co_await await_step<DataValueResult>(
        [this, id = enumValuesId.value()](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
            read_variable_data_value_async(std::move(*addressSpace), id, std::move(completion));
          else
            completion(DataValueResult{ua::detail::address_space_gone("project_value_as_text_async")});
        });
      if (!enumValues.has_value())
      {
        complete(DataValueResult{enumValues.status_code(), enumValues.shared_detail()});
        co_return;
      }
      answered = ua::detail::combined_status(answered, enumValues.status_code());

      const auto& enumStatus = enumValues.value().status();
      auto entries = enumStatus && enumStatus->is_bad()
                       ? Result<std::vector<RefStructure<Structure>>>{StatusCode{Status::BadNoData}}
                       : enumValues.value().value().to_vector<RefStructure<Structure>>();
      if (entries.is_good())
      {
        for (const auto& value : entries.value())
        {
          const auto* entry = dynamic_cast<const EnumValueType*>(value.get());
          if (entry != nullptr && entry->value() == *numeric)
          {
            projected.value() = Variant{entry->display_name()};
            break;
          }
        }
      }
      complete(DataValueResult{std::move(projected), answered});
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      const VoidResult bad = ua::exception_to_status_code(std::current_exception());
      complete(DataValueResult{bad.status_code(), bad.shared_detail()});
    }
  }

  void fail_to_start(StatusCode status)
  {
    complete(DataValueResult{status});
  }

  void complete(DataValueResult result)
  {
    if (auto onComplete = std::move(mOnComplete))
    {
      ua::detail::invoke_user_callback(onComplete, std::move(result));
    }
  }

  WeakAddressSpace mAddressSpace;
  NodeId mDataItem;
  std::function<void(DataValueResult)> mOnComplete;
};

/// Finds a MultiStateValueDiscrete Variable's ValueAsText Property and installs the projecting read handler.
/// @see wire_value_as_text_async
class WireValueAsTextOperation final : public ua::async::SelfOwningOperation<WireValueAsTextOperation>
{
public:
  WireValueAsTextOperation(
    AddressSpace addressSpace, NodeId dataItem, std::function<void(VoidResult)> onComplete)
    : ua::async::SelfOwningOperation<WireValueAsTextOperation>(
        boost::asio::make_strand(addressSpace.executor()), addressSpace.logger()),
      mAddressSpace(addressSpace.weak()), mDataItem(std::move(dataItem)), mOnComplete(std::move(onComplete))
  {}

  static void start(AddressSpace addressSpace, NodeId dataItem, std::function<void(VoidResult)> onComplete)
  {
    launch(std::make_shared<WireValueAsTextOperation>(
      std::move(addressSpace), std::move(dataItem), std::move(onComplete)));
  }

private:
  friend class ua::async::SelfOwningOperation<WireValueAsTextOperation>;

  ua::async::Task<> run()
  {
    try
    {
      // The address space is locked only inside each step's initiation, so the operation - which every
      // completion it hands out owns - never keeps it alive across a suspension (ua_namespace.h, Ownership).
      auto property = co_await await_step<NodeIdResult>(
        [this](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            find_child_id_by_browse_name_async(std::move(*addressSpace),
              mDataItem,
              NodeId{ReferenceTypeId::HasProperty},
              QualifiedName{0, "ValueAsText"},
              std::move(completion));
          }
          else
          {
            completion(NodeIdResult{ua::detail::address_space_gone("wire_value_as_text_async")});
          }
        });
      if (!property.is_good())
      {
        // No ValueAsText Property to wire (the lookup's Bad_NodeIdUnknown): it is Mandatory on the type, but
        // an instance built by other means may lack it, and that is the instance's shape rather than a
        // failure to report here. Any other failure, a refusal or an address space that is gone, is the
        // answer.
        if (property.status_code() == StatusCode{Status::BadNodeIdUnknown})
          complete(VoidResult{});
        else
          complete(VoidResult{property.status_code(), property.shared_detail()});
        co_return;
      }

      // Weak: the handler is owned by a node the address space owns, so a strong capture would keep
      // the address space alive through its own node.
      auto source = make_value_source(
        [weak = mAddressSpace, dataItem = mDataItem](const ValueSource::ReadContext& /*context*/,
          const Node& /*node*/,
          const ReadValueId& read,
          std::function<void(DataValueResult)>
            done)
        {
          auto addressSpace = weak.lock();
          if (!addressSpace)
          {
            done(DataValueResult{ua::detail::address_space_gone("wire_value_as_text_async")});
            return;
          }
          // The Property is a Mandatory LocalizedText, so where there is no text to give it holds an empty
          // one rather than a null a typed reader would refuse. The source applies the read's IndexRange.
          project_value_as_text_async(std::move(*addressSpace),
            dataItem,
            [done = std::move(done), range = read.index_range()](DataValueResult projected) mutable
            {
              if (projected.has_value())
              {
                if (projected.value().value().empty())
                  projected.value().value() = Variant{LocalizedText{}};
                index_range_utils::apply_to_value(projected.value(), range);
              }
              done(std::move(projected));
            });
        });

      auto installed = co_await await_step<VoidResult>(
        [this, id = property.value(), source = std::move(source)](auto completion) mutable
        {
          if (auto addressSpace = mAddressSpace.lock())
          {
            resolve_and_set_value_source_async(
              std::move(*addressSpace), id, std::move(source), std::move(completion));
          }
          else
          {
            completion(VoidResult{ua::detail::address_space_gone("wire_value_as_text_async")});
          }
        });
      // A namespace whose nodes offer no ExternalValueSource keeps the Property as a plain value.
      if (installed.is_bad() && installed.status_code() == StatusCode{Status::BadNotSupported})
      {
        complete(VoidResult{});
        co_return;
      }
      if (installed.is_bad())
      {
        complete(std::move(installed));
        co_return;
      }

      // The Property's value now changes without anything being written to it, so it can no longer
      // claim the MinimumSamplingInterval of 0 that promises continuous (write-driven) monitoring; a
      // MonitoredItem relying on that promise would never see the text change. -1 is Part 3's
      // "indeterminate", which has its MonitoredItems sampled.
      auto node = co_await await_step<NodeAccessorResult>(
        [this, id = property.value()](auto completion)
        {
          if (auto addressSpace = mAddressSpace.lock())
            addressSpace->find_node_async(id, std::move(completion));
          else
            completion(NodeAccessorResult{ua::detail::address_space_gone("wire_value_as_text_async")});
        });
      if (!node.is_good())
      {
        complete(VoidResult{
          ua::detail::lookup_failure(property.value(), node.status_code(), "wire_value_as_text_async")});
        co_return;
      }
      auto sampling = co_await await_step<VoidResult>(
        [&node](auto completion)
        {
          node.value().write_attribute_async(AttributeId::MinimumSamplingInterval,
            attribute_wire::minimum_sampling_interval(Duration{-1}),
            std::move(completion));
        });
      complete(std::move(sampling));
    }
    catch (const ua::async::Abandoned&)
    {
      ua::detail::ignore_expected_exception();
    }
    catch (...)
    {
      complete(VoidResult{ua::exception_to_status_code(std::current_exception())});
    }
  }

  void fail_to_start(StatusCode status)
  {
    complete(VoidResult{status});
  }

  void complete(VoidResult result)
  {
    if (auto onComplete = std::move(mOnComplete))
    {
      ua::detail::invoke_user_callback(onComplete, std::move(result));
    }
  }

  WeakAddressSpace mAddressSpace;
  NodeId mDataItem;
  std::function<void(VoidResult)> mOnComplete;
};

}  // namespace

void project_value_as_text_async(
  AddressSpace addressSpace, NodeId dataItem, std::function<void(DataValueResult)> onComplete) noexcept
{
  auto guarded = ua::detail::make_fire_once(std::move(onComplete));
  try
  {
    ProjectValueAsTextOperation::start(std::move(addressSpace), std::move(dataItem), guarded);
  }
  catch (...)
  {
    const VoidResult failure = ua::exception_to_status_code(std::current_exception());
    ua::detail::invoke_user_callback(
      guarded, DataValueResult{failure.status_code(), failure.shared_detail()});
  }
}

void wire_value_as_text_async(
  AddressSpace addressSpace, NodeId dataItem, std::function<void(VoidResult)> onComplete) noexcept
{
  auto guarded = ua::detail::make_fire_once(std::move(onComplete));
  try
  {
    WireValueAsTextOperation::start(std::move(addressSpace), std::move(dataItem), guarded);
  }
  catch (...)
  {
    const VoidResult failure = ua::exception_to_status_code(std::current_exception());
    ua::detail::invoke_user_callback(guarded, failure);
  }
}

namespace detail
{

template<typename T>
void read_property_value_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  bool (Variant::*holdsExpectedType)() const, PropertyReadNames names,
  std::function<void(Result<T>)> onComplete) noexcept
{
  find_child_for_accessor_async(std::move(addressSpace),
    std::move(parent),
    NodeId{ReferenceTypeId::HasProperty},
    std::move(browseName),
    names.owner,
    [holdsExpectedType, names, complete = std::move(onComplete)](Result<FoundChild> found) mutable
    {
      if (!found.has_value())
      {
        complete(Result<T>{found.status_code(), found.shared_detail()});
        return;
      }
      auto& child = found.value();
      read_variable_value_async(std::move(child.addressSpace),
        std::move(child.nodeId),
        [holdsExpectedType, names, complete = std::move(complete)](DataValueResult dvResult) mutable
        {
          if (!dvResult.has_value())
          {
            complete(Result<T>{dvResult.status_code(), dvResult.shared_detail()});
            return;
          }
          const DataValue& dataValue = dvResult.value();
          const StatusCode code = ua::detail::combined_status(
            dvResult.status_code(), dataValue.status().value_or(StatusCode{Status::Good}));
          if (code.is_bad() || (code.is_not_good() && dataValue.value().empty()))
          {
            complete(Result<T>{code});
            return;
          }
          if (!(dataValue.value().*holdsExpectedType)())
          {
            complete(Result<T>{StatusCode{Status::BadTypeMismatch},
              make_error_detail("BadTypeMismatch",
                std::string{"Property '"} + names.property + "' value is not the expected type",
                names.operation)});
            return;
          }
          // Result<StatusCode>'s single-argument constructor means an error, so a value takes with_value().
          if constexpr (std::is_same_v<T, StatusCode>)
          {
            complete(Result<T>::with_value(dataValue.value().as<T>(), code));
          }
          else
          {
            complete(Result<T>{dataValue.value().as<T>(), code});
          }
        });
    });
}

template void read_property_value_async<bool>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<bool>)>) noexcept;
template void read_property_value_async<uint8_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<uint8_t>)>) noexcept;
template void read_property_value_async<int8_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<int8_t>)>) noexcept;
template void read_property_value_async<uint16_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<uint16_t>)>) noexcept;
template void read_property_value_async<uint32_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<uint32_t>)>) noexcept;
template void read_property_value_async<uint64_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<uint64_t>)>) noexcept;
template void read_property_value_async<int16_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<int16_t>)>) noexcept;
template void read_property_value_async<int32_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<int32_t>)>) noexcept;
template void read_property_value_async<int64_t>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<int64_t>)>) noexcept;
template void read_property_value_async<double>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<double>)>) noexcept;
template void read_property_value_async<float>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<float>)>) noexcept;
template void read_property_value_async<String>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<String>)>) noexcept;
template void read_property_value_async<DateTime>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<DateTime>)>) noexcept;
template void read_property_value_async<ByteString>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<ByteString>)>) noexcept;
template void read_property_value_async<Guid>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<Guid>)>) noexcept;
template void read_property_value_async<NodeId>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<NodeId>)>) noexcept;
template void read_property_value_async<StatusCode>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<StatusCode>)>) noexcept;
template void read_property_value_async<QualifiedName>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<QualifiedName>)>) noexcept;
template void read_property_value_async<LocalizedText>(AddressSpace, NodeId, QualifiedName,
  bool (Variant::*)() const, PropertyReadNames, std::function<void(Result<LocalizedText>)>) noexcept;

void write_property_value_async(AddressSpace addressSpace, NodeId parent, QualifiedName browseName,
  const char* owner, Variant value, std::function<void(VoidResult)> onComplete) noexcept
{
  find_child_for_accessor_async(std::move(addressSpace),
    std::move(parent),
    NodeId{ReferenceTypeId::HasProperty},
    std::move(browseName),
    owner,
    [value = std::move(value), complete = std::move(onComplete)](Result<FoundChild> found) mutable
    {
      if (!found.has_value())
      {
        complete(VoidResult{found.status_code(), found.shared_detail()});
        return;
      }
      auto& child = found.value();
      DataValue dv;
      dv.value() = std::move(value);
      write_variable_value_async(
        std::move(child.addressSpace), std::move(child.nodeId), std::move(dv), std::move(complete));
    });
}

void find_child_for_accessor_async(AddressSpace addressSpace, NodeId parent, NodeId refType,
  QualifiedName browseName, const char* owner, std::function<void(Result<FoundChild>)> onComplete) noexcept
{
  auto weakAddressSpace = addressSpace.weak();
  find_child_id_by_browse_name_async(std::move(addressSpace),
    std::move(parent),
    std::move(refType),
    std::move(browseName),
    [weakAddressSpace = std::move(weakAddressSpace), owner, complete = std::move(onComplete)](
      NodeIdResult childIdResult) mutable
    {
      if (!childIdResult.is_good())
      {
        complete(Result<FoundChild>{childIdResult.status_code(), childIdResult.shared_detail()});
        return;
      }
      auto lockedAddressSpace = weakAddressSpace.lock();
      if (!lockedAddressSpace)
      {
        complete(Result<FoundChild>{ua::detail::address_space_gone(owner)});
        return;
      }
      complete(Result<FoundChild>{FoundChild{std::move(*lockedAddressSpace), std::move(childIdResult).value()}});
    });
}

bool begin_handler_registration(const optional<AddressSpace>& addressSpace, bool hasHandler, const char* owner,
  const char* operation, std::function<void(VoidResult)>& done) noexcept
{
  // An unbound handle (default-constructed or moved-from) has no address space to register in.
  if (!addressSpace)
  {
    if (done)
    {
      done(VoidResult{StatusCode{Status::BadInvalidState}});
    }
    return false;
  }
  // A caller that passes no callback still has the handler registered; a failure is logged instead.
  done = ua::detail::completion_or_log(std::move(done), addressSpace->logger(), operation);
  if (!hasHandler)
  {
    done(VoidResult{StatusCode{Status::BadInvalidArgument,
      ErrorDetail::build("MethodHandlerEmpty", "A method handler to register is empty", owner)}});
    return false;
  }
  return true;
}

}  // namespace detail

}  // namespace instance_utils
}  // namespace ua
