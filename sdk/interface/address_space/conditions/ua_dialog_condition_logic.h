// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief Pure state machine for the OPC UA DialogConditionType (Part 9).
/// @ingroup address_space

#ifndef UA_DIALOG_CONDITION_LOGIC_H
#define UA_DIALOG_CONDITION_LOGIC_H

#include "ua_condition_logic.h"
#include "ua_array.h"
#include "ua_variable_states.h"

#include <cstdint>

namespace ua
{

namespace test
{
class DialogConditionLogicTestAccess;
}  // namespace test

/// Pure state machine for the OPC UA DialogConditionType (Part 9).
///
/// Extends @ref ConditionLogic with dialog-specific state: the prompt, the
/// response-option set, and the DialogState two-state variable. Dialogs are not
/// alarms - they derive directly from @ref ConditionLogic. A dialog is activated
/// with a prompt and is then awaiting a response; responses are validated against
/// the configured number of options.
///
/// Like its base, this is a synchronous, side-effect-free logic object: it holds
/// no I/O, address space, or strands. Each mutation returns a
/// @ref ConditionStateTransition that the owning strand-serialized shell inspects
/// to decide whether to emit an event and what status to report to the caller.
/// @ingroup address_space
class DialogConditionLogic : public ConditionLogic
{
public:
  ~DialogConditionLogic() override = default;

  // Polymorphic logic object held only via unique_ptr; copying/moving would slice (C.67).
  DialogConditionLogic(const DialogConditionLogic&) = delete;
  DialogConditionLogic& operator=(const DialogConditionLogic&) = delete;
  DialogConditionLogic(DialogConditionLogic&&) = delete;
  DialogConditionLogic& operator=(DialogConditionLogic&&) = delete;

  /// Default constructor: the deleted copy/move members above suppress the implicit
  /// default ctor; this concrete logic type is default-constructed directly and by subclasses.
  DialogConditionLogic() = default;
  // --- Dialog operations ---

  /// Activates the dialog with the given prompt, entering the active DialogState.
  ///
  /// Sets DialogState to active (Id = true) and records @p prompt as the text
  /// presented to the client.
  ///
  /// @param prompt Text shown to the client for this dialog. Taken by value.
  /// @return The resulting state transition for the shell to apply.
  ConditionStateTransition activate_dialog(LocalizedText prompt);

  /// Responds to the active dialog with the selected option.
  ///
  /// Validates @p selectedResponse against the configured option count and, on
  /// success, clears the active DialogState and records the selection.
  ///
  /// @param selectedResponse Zero-based option index in the range
  ///                         `0 .. numOptions - 1` (see set_response_options()).
  /// @return The resulting state transition. Its status is `BadDialogNotActive`
  ///         when the dialog is not currently active, or
  ///         `BadDialogResponseInvalid` when @p selectedResponse is out of range.
  /// @see respond(int32_t, LocalizedText), set_response_options
  ConditionStateTransition respond(int32_t selectedResponse);

  /// Responds to the active dialog and updates the condition comment.
  ///
  /// Behaves as respond(int32_t) and additionally sets the condition's comment to
  /// @p comment.
  ///
  /// @param selectedResponse Zero-based option index, validated as in respond(int32_t).
  /// @param comment          Comment to record alongside the response. Taken by value.
  /// @return The resulting state transition, with the same status semantics as
  ///         respond(int32_t).
  /// @see respond(int32_t)
  ConditionStateTransition respond(int32_t selectedResponse, LocalizedText comment);

  // --- Configuration ---

  /// Sets the number of valid response options accepted by respond().
  ///
  /// @param numOptions Count of selectable options; valid response indices are
  ///                   `0 .. numOptions - 1`.
  void set_response_options(int32_t numOptions);

  /// Sets the default response option index.
  ///
  /// @param index Zero-based option index, or -1 for none.
  void set_default_response(int32_t index);

  /// Sets the option index that represents the OK response.
  ///
  /// @param index Zero-based option index, or -1 for none.
  void set_ok_response(int32_t index);

  /// Sets the option index that represents the Cancel response.
  ///
  /// @param index Zero-based option index, or -1 for none.
  void set_cancel_response(int32_t index);

  // --- Event building ---

  /// Builds a dialog-condition event populated from the current state.
  ///
  /// @return A newly allocated event carrying the dialog fields plus the inherited
  ///         condition fields. Ownership transfers to the caller.
  std::unique_ptr<BaseEvent> build_event() const override;

protected:
  /// Computes whether the condition should retain, including dialog activity.
  ///
  /// @return `true` while the dialog requires the condition to remain retained.
  bool compute_retain() const override;

  /// Returns the DialogState two-state variable.
  ///
  /// @return Reference valid for the lifetime of this object.
  const TwoStateVariableState& dialog_state() const;

  /// Returns the most recently selected response index.
  ///
  /// @return Zero-based option index of the last response, or -1 if none.
  int32_t last_response() const;

private:
  friend class test::DialogConditionLogicTestAccess;

  TwoStateVariableState mDialogState{};
  LocalizedText mPrompt{};
  Array<LocalizedText> mResponseOptionSet{};
  int32_t mDefaultResponse{-1};
  int32_t mOkResponse{-1};
  int32_t mCancelResponse{-1};
  int32_t mLastResponse{-1};
  int32_t mNumOptions{0};
};

}  // namespace ua

#endif  // !UA_DIALOG_CONDITION_LOGIC_H
