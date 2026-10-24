// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_VARIABLE_NODE_DEFAULT_H
#define UA_VARIABLE_NODE_DEFAULT_H

#include "ua_default_base_node.h"
#include "ua_access_level_type.h"
#include "ua_result.h"
#include "ua_access_level_ex_type.h"
#include "ua_duration.h"
#include "ua_value_source.h"
#include "ua_default_value_source.h"

#include <functional>
#include <memory>
#include <mutex>
#include <span>

namespace ua::default_ns
{

class VariableNode : public BaseNode, public ExternalValueSource
{
public:
  using BaseNode::ReadValueCompleteCallback;
  using BaseNode::WriteValueCompleteCallback;

  VariableNode() = delete;
  VariableNode(const VariableNode&) = delete;
  VariableNode(VariableNode&&) noexcept = delete;
  VariableNode& operator=(const VariableNode&) = delete;
  VariableNode& operator=(VariableNode&&) noexcept = delete;
  ~VariableNode() override = default;

  NodeClass get_node_class() const override;

  void write_attribute_async(
    AttributeId attributeId, Variant attributeValue, WriteAttributeCompleteCallback callback) override;

  void read_value(Duration maxAge, bool setSourceTimestamp, const ReadValueId& nodeToRead,
    const AccessIdentity* identity, ReadValueCompleteCallback callback) const override;

  /// A write made on this Node directly, not through its namespace's `write_async`: once it is committed, the
  /// namespace's steps for a changed Value run for it (NR-37, NR-38, NR-40), as for a Write.
  void write_value_async(const WriteValue& nodeToWrite, const AccessIdentity* identity,
    WriteValueCompleteCallback callback) override;

  /// Tells the Reported registrations on this Node that its Value is now @p value (DL-68), once a write of it
  /// is committed.
  void report_committed_value(const DataValue& value) const;

  /// Writes @p write to @p source, this Variable's default source (@ref DefaultValueSource::write), and once
  /// it is committed tells the Reported registrations on this Node of the Value held, both under this
  /// Variable's commit lock, so that two writes are reported in the order they were committed (NR-48 rule
  /// 4). The default source keeps exactly what it is given, so the Value reported is the one written, or
  /// the whole Value a merge left, with no read-back (DL-115 (3)). The write stays committed whatever the
  /// report does, which fails only to allocate.
  ///
  /// @param source     The Variable's default source.
  /// @param write      The write, possibly with an IndexRange or ValidBits.
  /// @param serversOwn As for @ref DefaultValueSource::write.
  /// @return The source's answer.
  Result<DefaultValueSource::Stored> commit_to_default_source(
    DefaultValueSource& source, const WriteValue& write, bool serversOwn) const;

  /// A Value write's answer to the namespace that made it: the result and, for a committed write, whether it
  /// gave the Variable its first Value (NR-38 rule 1), as the source answered it in
  /// `ValueSource::Written::initial`. The namespace runs its steps for a changed Value on it.
  using ValueWritten = std::function<void(VoidResult, bool initial)>;

  ExternalValueSource* external_value_source() noexcept override
  {
    return this;
  }

  // ExternalValueSource
  VoidResult set_value_source(std::shared_ptr<ValueSource> source) override;
  void notify_value_changed(DataValue newValue) override;

  /// The source an application attached with @ref set_value_source; null while the Variable has its default
  /// source, or none.
  std::shared_ptr<ValueSource> application_source() const;

  /// The default source while it is the Variable's source; null while an application source is attached, or
  /// before the Variable's first write.
  std::shared_ptr<DefaultValueSource> default_source() const;

  /// The default source, installed when the Variable has no source (the install rule,
  /// COMP-DEFAULT-NODE-ATTR-STORAGE-03); null when an application source is attached.
  std::shared_ptr<DefaultValueSource> default_source_for_write();

  /// The Value as the Variable's default source answers a read of it, whole
  /// (@ref DefaultValueSource::read); a Variable with no source, never written, answers a null Value. Called
  /// when no application source is attached.
  DataValue read_default_source(Duration maxAge, bool setSourceTimestamp) const;

  /// Calls @p source with the one write @p write, as given, a partial Value and its IndexRange or ValidBits
  /// included (NR-11 rule 3); once it has committed it, the Reported registrations on this Node are told, and
  /// @p written receives the source's answer. @p caller is valid only until this returns.
  void write_to_source_async(const std::shared_ptr<ValueSource>& source, const RequestInfo& request,
    const WriteValue& write, const CallerInfo* caller, ValueWritten written);

  /// The completion of a Value write that @p source, an application source, applies: once the source has
  /// committed it, and while a Reported registration is on this Node, the Value @p source then holds is read
  /// back (@ref report_values_held) and the registrations are told of it, so that a Value the source clamped,
  /// rounded or converted is reported as a Read sees it (DL-115 (3)); @p written then receives the source's
  /// answer. Moves from @p written only once nothing can throw.
  ValueWritten source_write_completion(const std::shared_ptr<ValueSource>& source, ValueWritten& written);

  /// Whether a Reported registration is on this Node now; only then is a committed Value reported to the
  /// monitoring helper.
  bool has_reported_registrations() const noexcept;

  /// Reads the Value @p source holds for each of @p variables, whole, with no caller and maxAge 0, in one
  /// call, and tells each Variable's Reported registrations of the Value read, its status the code
  /// `combined_status` gives for the read's code and the Value's own status (a read's code with a SubCode
  /// that is not the one reported is logged); then calls @p then once. A Value that cannot be read back is
  /// not reported: its write stays committed. Moves from @p then only once
  /// nothing can throw; never throws.
  static void report_values_held(const std::shared_ptr<ValueSource>& source,
    std::span<const shared_ptr<const VariableNode>> variables, std::function<void()>& then) noexcept;

  /// Writes @p write to the Variable's default source (@ref DefaultValueSource::write): its Value whole, or
  /// its IndexRange or ValidBits applied to the Value held, atomically (NR-11 rule 4). A Variable with no
  /// source gets its default source first (the install rule, COMP-DEFAULT-NODE-ATTR-STORAGE-03). Then the
  /// Reported registrations on this Node are told of the Value held, and @p written receives the answer.
  /// Returns false, and leaves @p written untouched, when an application source is attached.
  ///
  /// @param write      The write, possibly with an IndexRange or ValidBits.
  /// @param serversOwn Whether this is the server's own write, which stores an OptionSet as given when the
  ///                   Variable holds none.
  /// @param written    The write's answer.
  bool write_to_default_source_async(const WriteValue& write, bool serversOwn, ValueWritten& written);

  static shared_ptr<VariableNode> create(const NodeId& nodeId);

  /// Stores the Value @p next makes of the current one through the default source
  /// (@ref DefaultValueSource::update), so that two updates never start from the same Value; answered through
  /// @p callback as a write, a refusal of @p next included. The namespace's steps for a changed Value do not
  /// run: it is the namespace's own version update. Returns false, leaving @p callback untouched, when an
  /// application source is attached.
  bool update_default_source_async(
    const std::function<Result<Variant>(const Variant& current)>& next, WriteValueCompleteCallback& callback);

private:
  /// The Variable's source: the one an application attached, or the default source its first write installed
  /// when none was attached; null before either. The Variable holds no Value itself (DL-115 (2)). Guarded by
  /// mMutex; a read or write copies the pointer under it, which also keeps a source replaced mid-call alive
  /// until that call answers.
  std::shared_ptr<ValueSource> mSource;
  /// `mSource` itself while it is the default source, null otherwise; owned by `mSource`. Guarded by mMutex.
  DefaultValueSource* mDefaultSource{nullptr};
  /// Held across a write or update of the default source and the report of the Value it committed, so that
  /// the Reported registrations are told of the Values in the order they were committed (NR-48 rule 4).
  /// Taken before mMutex, never while holding it.
  mutable std::mutex mValueCommitMutex;

  explicit VariableNode(const NodeId& nodeId);

  bool is_attribute_id_valid(AttributeId attributeId) const override;

  /// @ref report_committed_value, called under mValueCommitMutex; a failure to allocate reports nothing.
  void report_commit(const DataValue& value) const noexcept;

  /// Logs @p outer, the code with a SubCode a value source answered the read-back of this Variable's Value
  /// with, when the Value's own status @p inner is the one reported (@ref report_values_held): at Warning, on
  /// the logger of the namespace that created this Node, so the source's code is not lost without trace.
  void log_code_not_reported(const StatusCode& outer, const StatusCode& inner) const noexcept;

  /// @ref default_source_for_write, called under mMutex's write lock.
  std::shared_ptr<DefaultValueSource> default_source_for_write_locked();

  /// The completion of a write made on this Node directly, or of a change its source reported: once
  /// committed, the namespace that created this Node runs its steps for a changed Value, then @p callback
  /// receives the answer.
  ValueWritten own_change_completion(WriteValueCompleteCallback callback);
};

}  // namespace ua::default_ns

#endif  // UA_VARIABLE_NODE_DEFAULT_H
