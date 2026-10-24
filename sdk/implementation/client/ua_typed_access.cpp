// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_typed_access.h"

#include "ua_browse_cursor_state.h"
#include "ua_browse_path.h"
#include "ua_call_method_request.h"
#include "ua_call_request.h"
#include "ua_call_response.h"
#include "ua_client_answer_status.h"
#include "ua_sync_wait.h"
#include "ua_connection_impl.h"
#include "ua_error_detail.h"
#include "ua_error_detail_keys.h"
#include "ua_data_value.h"
#include "ua_diagnostic_info_decoder.h"
#include "ua_encoding_limits.h"
#include "ua_expanded_node_id.h"
#include "ua_logger.h"
#include "ua_namespace_table.h"
#include "ua_numeric_range_validation.h"
#include "ua_objecttype_id.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_referencetype_id.h"
#include "ua_status.h"
#include "ua_translate_browse_paths_to_node_ids_request.h"
#include "ua_translate_browse_paths_to_node_ids_response.h"
#include "ua_to_string.h"
#include "ua_type_reify_consumer.h"
#include "ua_type_registry.h"
#include "ua_type_resolver.h"
#include "ua_unknown_structure.h"
#include "ua_value_shape_validation.h"
#include "ua_variant.h"
#include "ua_write_request.h"
#include "ua_write_response.h"
#include "ua_write_value.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace ua::client
{

namespace
{

/// The status a forwarding call completes with when the handle has been moved-from (null pimpl). A
/// programming error (using a moved-from handle), distinct from a runtime `Bad_ConnectionClosed`.
constexpr ua::Status emptyHandleStatus = ua::Status::BadInvalidState;

/// Source tags for the typed-sugar manufactured boundary failures (the design specification).
constexpr std::string_view readAttributeSource = "client.tier2.typed_access.read_attribute";
constexpr std::string_view readValuesSource = "client.tier2.typed_access.read_values";
constexpr std::string_view variableMetadataSource = "client.tier2.typed_access.variable_metadata";
constexpr std::string_view readValueEncodingSource = "client.tier2.typed_access.read_value_encoding";
constexpr std::string_view writeAttributeSource = "client.tier2.typed_access.write_attribute";
constexpr std::string_view writeValuesSource = "client.tier2.typed_access.write_values";
constexpr std::string_view callMethodSource = "client.tier2.typed_access.call_method";
constexpr std::string_view translateSource = "client.tier2.typed_access.translate_browse_path";
constexpr std::string_view resolveSource = "client.tier2.typed_access.resolve_path";
constexpr std::string_view dictionaryEntriesSource = "client.tier2.typed_access.dictionary_entries";
constexpr std::string_view methodInputsSource = "client.tier2.typed_access.method_inputs";

using CursorFactory = std::function<BrowseCursor(ua::NodeId, BrowseOptions)>;
using SubtypeCallback = std::function<void(ua::Result<bool>)>;

/// Returns a copy of @p head whose terminal cause is @p tail. Both inputs come from the bounded
/// DiagnosticInfo decoder, so this preserves two independent wire diagnostic arrays without exposing
/// mutable ErrorDetail nodes or creating an unbounded walk.
std::shared_ptr<const ua::ErrorDetail> append_diagnostic_chain(
  const std::shared_ptr<const ua::ErrorDetail>& head, std::shared_ptr<const ua::ErrorDetail> tail)
{
  if (!head)
  {
    return tail;
  }
  auto copy = std::make_shared<ua::ErrorDetail>(*head);
  copy->cause = append_diagnostic_chain(head->cause, std::move(tail));
  return copy;
}

void check_dictionary_subtype(
  CursorFactory makeCursor, ua::NodeId type, std::vector<ua::NodeId> visited, SubtypeCallback callback);
ua::ReadRequest make_attribute_read(ua::NodeId node, ua::AttributeId attribute, ua::String indexRange = {});
ua::Result<ua::DataValue> flatten_attribute_read(ua::Result<ua::ReadResponse> result);

template<typename T>
ua::Variant wrap_scalar_value(const ua::Variant& value)
{
  ua::Array<T> wrapped;
  wrapped.payload().push_back(value.as<T>());
  return ua::Variant{std::move(wrapped)};
}

ua::Variant wrap_index_range_scalar(const ua::Variant& value)
{
  if (!value.is_scalar())
  {
    return value;
  }
  if (value.is_decimal())
  {
    return wrap_scalar_value<ua::Decimal>(value);
  }

  switch (value.get_built_in_type())
  {
  case ua::BuiltInTypeId::Boolean:
    return wrap_scalar_value<bool>(value);
  case ua::BuiltInTypeId::SByte:
    return wrap_scalar_value<std::int8_t>(value);
  case ua::BuiltInTypeId::Byte:
    return wrap_scalar_value<std::uint8_t>(value);
  case ua::BuiltInTypeId::Int16:
    return wrap_scalar_value<std::int16_t>(value);
  case ua::BuiltInTypeId::UInt16:
    return wrap_scalar_value<std::uint16_t>(value);
  case ua::BuiltInTypeId::Int32:
    return wrap_scalar_value<std::int32_t>(value);
  case ua::BuiltInTypeId::UInt32:
    return wrap_scalar_value<std::uint32_t>(value);
  case ua::BuiltInTypeId::Int64:
    return wrap_scalar_value<std::int64_t>(value);
  case ua::BuiltInTypeId::UInt64:
    return wrap_scalar_value<std::uint64_t>(value);
  case ua::BuiltInTypeId::Float:
    return wrap_scalar_value<float>(value);
  case ua::BuiltInTypeId::Double:
    return wrap_scalar_value<double>(value);
  case ua::BuiltInTypeId::String:
    return wrap_scalar_value<ua::String>(value);
  case ua::BuiltInTypeId::DateTime:
    return wrap_scalar_value<ua::DateTime>(value);
  case ua::BuiltInTypeId::Guid:
    return wrap_scalar_value<ua::Guid>(value);
  case ua::BuiltInTypeId::ByteString:
    return wrap_scalar_value<ua::ByteString>(value);
  case ua::BuiltInTypeId::XmlElement:
    return wrap_scalar_value<ua::XmlElement>(value);
  case ua::BuiltInTypeId::NodeId:
    return wrap_scalar_value<ua::NodeId>(value);
  case ua::BuiltInTypeId::ExpandedNodeId:
    return wrap_scalar_value<ua::ExpandedNodeId>(value);
  case ua::BuiltInTypeId::StatusCode:
    return wrap_scalar_value<ua::StatusCode>(value);
  case ua::BuiltInTypeId::QualifiedName:
    return wrap_scalar_value<ua::QualifiedName>(value);
  case ua::BuiltInTypeId::LocalizedText:
    return wrap_scalar_value<ua::LocalizedText>(value);
  case ua::BuiltInTypeId::ExtensionObject:
    return wrap_scalar_value<ua::RefStructure<ua::Structure>>(value);
  case ua::BuiltInTypeId::DataValue:
    return wrap_scalar_value<ua::DataValue>(value);
  case ua::BuiltInTypeId::Null:
  case ua::BuiltInTypeId::Variant:
  case ua::BuiltInTypeId::DiagnosticInfo:
    return value;
  }
  return value;
}

struct SubtypeWalk : std::enable_shared_from_this<SubtypeWalk>
{
  CursorFactory makeCursor;
  std::vector<ua::NodeId> visited;
  SubtypeCallback callback;
  std::optional<BrowseCursor> cursor;
  std::vector<ua::NodeId> parents;
  std::size_t parentIndex{0};

  void collect()
  {
    if (!cursor->has_more())
    {
      check_parent();
      return;
    }
    auto self = shared_from_this();
    cursor->next_async(
      [self](ua::Result<BrowseCursor::Entry> result)
      {
        // The supertype walk decides whether a type is a DictionaryEntryType: it acts on Good References
        // only, and refuses an Uncertain page.
        if (!result.is_good())
        {
          if (result.status_code() == ua::Status::BadNoData)
          {
            self->check_parent();
            return;
          }
          self->callback(ua::Result<bool>{detail::answer_refused(
            result.status_code(), "ReferencesAnswerUncertain", dictionaryEntriesSource)});
          return;
        }
        const auto& target = result.value().targetNodeId;
        if (target.server_index() == 0 && target.namespace_uri().empty())
        {
          self->parents.push_back(target.node_id());
        }
        self->collect();
      });
  }

  void check_parent()
  {
    if (parentIndex == parents.size())
    {
      callback(ua::Result<bool>{false});
      return;
    }
    auto self = shared_from_this();
    check_dictionary_subtype(makeCursor,
      parents[parentIndex++],
      visited,
      [self](ua::Result<bool> result)
      {
        if (!result.has_value() || result.value())
        {
          self->callback(std::move(result));
          return;
        }
        self->check_parent();
      });
  }
};

void check_dictionary_subtype(
  CursorFactory makeCursor, ua::NodeId type, std::vector<ua::NodeId> visited, SubtypeCallback callback)
{
  const ua::NodeId dictionaryEntry{ua::ObjectTypeId::DictionaryEntryType};
  if (type == dictionaryEntry)
  {
    callback(ua::Result<bool>{true});
    return;
  }
  if (std::ranges::find(visited, type) != visited.end())
  {
    callback(ua::Result<bool>{false});
    return;
  }
  visited.push_back(type);

  BrowseOptions options;
  options.direction = ua::BrowseDirection::Inverse;
  options.referenceTypeId = ua::NodeId{ua::ReferenceTypeId::HasSubtype};
  options.includeSubtypes = false;
  options.nodeClassMask = static_cast<std::uint32_t>(ua::NodeClass::ObjectType);

  auto walk = std::make_shared<SubtypeWalk>();
  walk->makeCursor = std::move(makeCursor);
  walk->visited = std::move(visited);
  walk->callback = std::move(callback);
  walk->cursor.emplace(walk->makeCursor(std::move(type), std::move(options)));
  walk->collect();
}

struct DictionaryEntriesWalk : std::enable_shared_from_this<DictionaryEntriesWalk>
{
  CursorFactory makeCursor;
  std::weak_ptr<detail::ObserverSink> observer;
  std::function<void(ua::Result<std::vector<BrowseCursor::Entry>>)> callback;
  std::optional<BrowseCursor> cursor;
  std::vector<BrowseCursor::Entry> candidates;
  std::vector<BrowseCursor::Entry> accepted;
  std::size_t candidateIndex{0};
  /// The code the HasDictionaryEntry pages were answered with: a Good subcode or an Uncertain code of a
  /// page is kept for the entries returned.
  ua::StatusCode answered{ua::Status::Good};

  void collect()
  {
    if (!cursor->has_more())
    {
      validate();
      return;
    }
    auto self = shared_from_this();
    cursor->next_async(
      [self](ua::Result<BrowseCursor::Entry> result)
      {
        if (!result.has_value())
        {
          if (result.status_code() == ua::Status::BadNoData)
          {
            self->validate();
            return;
          }
          self->callback(
            ua::Result<std::vector<BrowseCursor::Entry>>{result.status_code(), result.shared_detail()});
          return;
        }
        self->answered = ua::detail::combined_status(self->answered, result.status_code());
        self->candidates.push_back(std::move(result).value());
        self->collect();
      });
  }

  void validate()
  {
    if (candidateIndex == candidates.size())
    {
      callback(ua::detail::held(std::move(accepted), answered));
      return;
    }
    const auto index = candidateIndex++;
    const auto& candidate = candidates[index];
    if (candidate.nodeClass != ua::NodeClass::Object)
    {
      reject(index, "the HasDictionaryEntry target is not an Object");
      return;
    }
    auto self = shared_from_this();
    check_dictionary_subtype(makeCursor,
      candidate.typeDefinition,
      {},
      [self, index](ua::Result<bool> result)
      {
        if (!result.has_value())
        {
          self->callback(
            ua::Result<std::vector<BrowseCursor::Entry>>{result.status_code(), result.shared_detail()});
          return;
        }
        if (!result.value())
        {
          self->reject(
            index, "the HasDictionaryEntry target TypeDefinition is not DictionaryEntryType or a subtype");
          return;
        }
        self->accepted.push_back(std::move(self->candidates[index]));
        self->validate();
      });
  }

  void reject(std::size_t index, std::string_view reason)
  {
    if (auto sink = observer.lock())
    {
      sink->fire_advisory_diagnostic(
        ua::ErrorDetail::build("NonConformantDictionaryEntryTarget",
          "The dictionary entry target does not satisfy the required model",
          std::string{dictionaryEntriesSource})
          .context(ua::ContextKeys::nodeId, ua::to_string(candidates[index].targetNodeId.node_id()))
          .context(ua::ContextKeys::errorMessage, std::string{reason}));
    }
    validate();
  }
};

struct MethodInputsWalk : std::enable_shared_from_this<MethodInputsWalk>
{
  std::shared_ptr<detail::ConnectionImpl> impl;
  std::function<void(ua::Result<MethodInputMetadata>)> callback;
  std::optional<BrowseCursor> properties;
  std::optional<BrowseCursor> optionals;
  std::optional<ua::NodeId> inputArgumentsNode;
  std::set<std::string> optionalNames;
  /// The code the Method's References and its InputArguments were answered with: a Good subcode or an
  /// Uncertain code is kept for the metadata returned.
  ua::StatusCode answered{ua::Status::Good};

  void fail(ua::StatusCode status)
  {
    auto completion = std::move(callback);
    completion(ua::Result<MethodInputMetadata>{std::move(status)});
  }

  void fail(ua::Status status, std::shared_ptr<const ua::ErrorDetail> detail)
  {
    auto completion = std::move(callback);
    completion(ua::Result<MethodInputMetadata>{status, std::move(detail)});
  }

  void collect_properties()
  {
    if (!properties->has_more())
    {
      collect_optionals();
      return;
    }
    auto self = shared_from_this();
    properties->next_async(
      [self](ua::Result<BrowseCursor::Entry> result)
      {
        if (!result.has_value())
        {
          if (result.status_code() == ua::Status::BadNoData)
          {
            self->collect_optionals();
            return;
          }
          self->fail(result.status_code());
          return;
        }
        self->answered = ua::detail::combined_status(self->answered, result.status_code());
        const auto& entry = result.value();
        if (entry.browseName.namespace_index() == 0 && entry.browseName.name() == "InputArguments")
        {
          if (entry.nodeClass != ua::NodeClass::Variable)
          {
            self->fail(ua::Status::BadDecodingError,
              ua::make_error_detail("InputArgumentsPropertyNotVariable",
                "Method InputArguments Property target is not a Variable",
                std::string{methodInputsSource}));
            return;
          }
          if (entry.targetNodeId.server_index() != 0 || !entry.targetNodeId.namespace_uri().empty())
          {
            self->fail(ua::Status::BadDecodingError,
              ua::make_error_detail("RemoteInputArgumentsProperty",
                "Method InputArguments Property is not a local Node",
                std::string{methodInputsSource}));
            return;
          }
          if (self->inputArgumentsNode.has_value())
          {
            self->fail(ua::Status::BadDecodingError,
              ua::make_error_detail("DuplicateInputArgumentsProperty",
                "Method exposes more than one InputArguments Property",
                std::string{methodInputsSource}));
            return;
          }
          self->inputArgumentsNode = entry.targetNodeId.node_id();
        }
        self->collect_properties();
      });
  }

  void collect_optionals()
  {
    if (!optionals->has_more())
    {
      read_arguments();
      return;
    }
    auto self = shared_from_this();
    optionals->next_async(
      [self](ua::Result<BrowseCursor::Entry> result)
      {
        if (!result.has_value())
        {
          if (result.status_code() == ua::Status::BadNoData)
          {
            self->read_arguments();
            return;
          }
          self->fail(result.status_code());
          return;
        }
        self->answered = ua::detail::combined_status(self->answered, result.status_code());
        const auto& entry = result.value();
        if (entry.nodeClass != ua::NodeClass::Variable)
        {
          self->fail(ua::Status::BadDecodingError,
            ua::make_error_detail("OptionalArgumentDescriptionNotVariable",
              "Optional argument description target is not a Variable",
              std::string{methodInputsSource}));
          return;
        }
        const std::string name{entry.browseName.name()};
        if (name.empty() || !self->optionalNames.insert(name).second)
        {
          self->fail(ua::Status::BadDecodingError,
            ua::make_error_detail("DuplicateOptionalArgumentDescription",
              "Method exposes duplicate or unnamed optional argument metadata",
              std::string{methodInputsSource}));
          return;
        }
        self->collect_optionals();
      });
  }

  void read_arguments()
  {
    if (!inputArgumentsNode.has_value())
    {
      if (!optionalNames.empty())
      {
        fail(ua::Status::BadDecodingError,
          ua::make_error_detail("OptionalDescriptionWithoutInputArguments",
            "Method exposes optional argument metadata without an InputArguments Property",
            std::string{methodInputsSource}));
        return;
      }
      auto completion = std::move(callback);
      completion(ua::detail::held(MethodInputMetadata{}, answered));
      return;
    }
    auto self = shared_from_this();
    impl->read_async(make_attribute_read(*inputArgumentsNode, ua::AttributeId::Value),
      [self](ua::Result<ua::ReadResponse> response)
      {
        auto value = flatten_attribute_read(std::move(response));
        if (!value.has_value())
        {
          self->fail(value.status_code());
          return;
        }
        // The read's one code: its ServiceResult and the DataValue's own status combined. A Bad code, or an
        // Uncertain code with no value, is the answer; otherwise the value is decoded and the code kept.
        const ua::StatusCode code = ua::detail::combined_status(
          value.status_code(), value.value().status().value_or(ua::StatusCode{ua::Status::Good}));
        if (code.is_bad() || (code.is_uncertain() && value.value().value().empty()))
        {
          self->fail(code);
          return;
        }
        self->answered = ua::detail::combined_status(self->answered, code);
        self->decode(value.value().value());
      });
  }

  void decode(const ua::Variant& value)
  {
    MethodInputMetadata metadata;
    if (!value.empty())
    {
      if (!value.is_array_of_structure())
      {
        fail(ua::Status::BadDecodingError,
          ua::make_error_detail("InputArgumentsTypeMismatch",
            "Method InputArguments Value is not an Argument array",
            std::string{methodInputsSource}));
        return;
      }
      for (const auto& structure : value.as<ua::Array<ua::RefStructure<ua::Structure>>>().payload())
      {
        const auto* argument = dynamic_cast<const ua::Argument*>(structure.get());
        if (!argument)
        {
          fail(ua::Status::BadDecodingError,
            ua::make_error_detail("InputArgumentElementTypeMismatch",
              "Method InputArguments contains a non-Argument element",
              std::string{methodInputsSource}));
          return;
        }
        metadata.inputArguments.push_back(*argument);
      }
    }

    std::set<std::string> argumentNames;
    for (const auto& argument : metadata.inputArguments)
    {
      const std::string name{argument.name()};
      if (name.empty() || !argumentNames.insert(name).second)
      {
        fail(ua::Status::BadDecodingError,
          ua::make_error_detail("InvalidInputArgumentNames",
            "Method InputArguments contains duplicate or unnamed arguments",
            std::string{methodInputsSource}));
        return;
      }
    }
    for (const auto& optional : optionalNames)
    {
      if (!argumentNames.contains(optional))
      {
        fail(ua::Status::BadDecodingError,
          ua::make_error_detail("UnmatchedOptionalArgumentDescription",
            "Optional argument metadata does not match an InputArguments name",
            std::string{methodInputsSource}));
        return;
      }
    }
    for (auto position = metadata.inputArguments.rbegin(); position != metadata.inputArguments.rend();
         ++position)
    {
      if (!optionalNames.contains(std::string{position->name()}))
        break;
      ++metadata.trailingOptionalCount;
    }
    if (metadata.trailingOptionalCount != optionalNames.size())
    {
      fail(ua::Status::BadDecodingError,
        ua::make_error_detail("NonTrailingOptionalArguments",
          "Optional input arguments do not form a trailing suffix",
          std::string{methodInputsSource}));
      return;
    }
    auto completion = std::move(callback);
    completion(ua::detail::held(std::move(metadata), answered));
  }
};

ua::ReadValueId make_attribute_read_target(
  ua::NodeId node, ua::AttributeId attribute, ua::String indexRange = {})
{
  ua::ReadValueId target;
  target.node_id() = std::move(node);
  target.attribute_id() = static_cast<ua::IntegerId>(attribute);
  target.index_range() = std::move(indexRange);
  return target;
}

/// Builds a single-attribute Read request.
ua::ReadRequest make_attribute_read(ua::NodeId node, ua::AttributeId attribute, ua::String indexRange)
{
  ua::ReadRequest request;
  request.nodes_to_read().push_back(
    make_attribute_read_target(std::move(node), attribute, std::move(indexRange)));
  return request;
}

ua::ReadRequest make_encoded_value_read(ua::NodeId node, ua::QualifiedName dataEncoding)
{
  ua::ReadRequest request;
  auto target = make_attribute_read_target(std::move(node), ua::AttributeId::Value);
  target.data_encoding() = std::move(dataEncoding);
  request.nodes_to_read().push_back(std::move(target));
  return request;
}

enum class ExtensionBodyEncoding
{
  Binary,
  Xml,
  Other,
};

ExtensionBodyEncoding requested_body_encoding(const ua::QualifiedName& requested)
{
  if (requested.namespace_index() == 0 && std::string_view{requested.name()} == "Default Binary")
  {
    return ExtensionBodyEncoding::Binary;
  }
  if (requested.namespace_index() == 0 && std::string_view{requested.name()} == "Default XML")
  {
    return ExtensionBodyEncoding::Xml;
  }
  return ExtensionBodyEncoding::Other;
}

std::string_view body_encoding_name(ExtensionBodyEncoding encoding)
{
  switch (encoding)
  {
  case ExtensionBodyEncoding::Binary:
    return "Default Binary";
  case ExtensionBodyEncoding::Xml:
    return "Default XML";
  case ExtensionBodyEncoding::Other:
    return "Other";
  }
  return "Other";
}

ExtensionBodyEncoding decoded_body_encoding(const ua::Structure& structure)
{
  const auto* unknown = dynamic_cast<const ua::UnknownStructure*>(&structure);
  if (!unknown)
  {
    // On the UA Binary message codec a resolved concrete Structure is created only for
    // ExtensionObject encoding byte 1. Encoding byte 2 is retained as UnknownStructure/Xml.
    return ExtensionBodyEncoding::Binary;
  }
  return unknown->body_encoding() == ua::UnknownStructure::BodyEncoding::Xml ? ExtensionBodyEncoding::Xml
                                                                             : ExtensionBodyEncoding::Binary;
}

ua::VoidResult validate_returned_body_encoding(const ua::Variant& value, const ua::QualifiedName& requested)
{
  const auto expected = requested_body_encoding(requested);
  const auto validateOne = [&](const ua::Structure& structure) -> ua::VoidResult
  {
    const auto actual = decoded_body_encoding(structure);
    if (expected == actual)
    {
      return ua::VoidResult{};
    }
    return ua::VoidResult{ua::Status::BadDecodingError,
      ua::ErrorDetail::build("DataEncodingMismatch",
        "the Server returned an ExtensionObject body in a different encoding than requested",
        std::string{readValueEncodingSource})
        .context(ua::ContextKeys::expected, std::string{body_encoding_name(expected)})
        .context(ua::ContextKeys::actual, std::string{body_encoding_name(actual)})};
  };

  if (value.is_structure())
  {
    return validateOne(value.as<ua::Structure>());
  }
  if (value.is_array_of_structure())
  {
    for (const auto& structure : value.as<ua::Array<ua::RefStructure<ua::Structure>>>().payload())
    {
      if (!structure)
      {
        continue;
      }
      auto validation = validateOne(*structure);
      if (validation.is_bad())
      {
        return validation;
      }
    }
    return ua::VoidResult{};
  }
  return ua::VoidResult{ua::Status::BadDecodingError,
    ua::make_error_detail("DataEncodingNonStructureResponse",
      "the Server returned a non-Structure Value for an explicit DataEncoding request",
      std::string{readValueEncodingSource})};
}

ua::ReadRequest make_attributes_read(const std::vector<ua::NodeId>& nodes, ua::AttributeId attribute)
{
  ua::ReadRequest request;
  request.nodes_to_read().reserve(nodes.size());
  for (const auto& node : nodes)
  {
    request.nodes_to_read().push_back(make_attribute_read_target(node, attribute));
  }
  return request;
}

/// Builds a single-attribute Write request.
ua::WriteRequest make_attribute_write(
  ua::NodeId node, ua::AttributeId attribute, ua::DataValue value, ua::String indexRange = {})
{
  ua::WriteValue target;
  target.node_id() = std::move(node);
  target.attribute_id() = static_cast<ua::IntegerId>(attribute);
  target.index_range() = std::move(indexRange);
  target.value() = std::move(value);
  ua::WriteRequest request;
  request.nodes_to_write().push_back(std::move(target));
  return request;
}

/// Builds a bulk Value Read request (one ReadValueId per node, Value attribute).
ua::ReadRequest make_values_read(std::vector<ua::NodeId> nodes)
{
  ua::ReadRequest request;
  for (auto& node : nodes)
  {
    ua::ReadValueId target;
    target.node_id() = std::move(node);
    target.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
    request.nodes_to_read().push_back(std::move(target));
  }
  return request;
}

/// Builds a bulk Value Write request (one WriteValue per pair, Value attribute).
ua::WriteRequest make_values_write(std::vector<std::pair<ua::NodeId, ua::Variant>> pairs)
{
  ua::WriteRequest request;
  for (auto& [node, value] : pairs)
  {
    ua::WriteValue target;
    target.node_id() = std::move(node);
    target.attribute_id() = static_cast<ua::IntegerId>(ua::AttributeId::Value);
    target.value() = ua::DataValue{std::move(value)};
    request.nodes_to_write().push_back(std::move(target));
  }
  return request;
}

/// Builds the Part 3 shape metadata Read used to validate a tier-2 Value write. Results are ordered
/// [ValueRank, ArrayDimensions] for each outgoing pair.
ua::ReadRequest make_value_shapes_read(const std::vector<std::pair<ua::NodeId, ua::Variant>>& pairs)
{
  ua::ReadRequest request;
  request.nodes_to_read().reserve(pairs.size() * 2);
  for (const auto& [node, value] : pairs)
  {
    static_cast<void>(value);
    request.nodes_to_read().push_back(make_attribute_read_target(node, ua::AttributeId::ValueRank));
    request.nodes_to_read().push_back(make_attribute_read_target(node, ua::AttributeId::ArrayDimensions));
  }
  return request;
}

/// The shapes a Value write is checked against. The write's preflight acts on the metadata itself, so an
/// Uncertain ServiceResult or attribute status is refused (ReadAnswerUncertain), as a Bad one is.
ua::Result<std::vector<detail::VariableShape>> parse_value_shapes(
  ua::ReadResponse response, std::size_t requestedCount, std::string_view source)
{
  const ua::StatusCode serviceResult = response.response_header().service_result();
  if (serviceResult.is_uncertain())
  {
    return ua::Result<std::vector<detail::VariableShape>>{
      detail::uncertain_answer_refused(serviceResult, "ReadAnswerUncertain", source)};
  }
  if (serviceResult.is_bad())
  {
    return ua::Result<std::vector<detail::VariableShape>>{serviceResult,
      ua::make_error_detail("WriteShapeMetadataServiceFault",
        "the shape metadata Read returned a service-level error",
        std::string{source},
        serviceResult)};
  }

  const auto& results = response.results();
  if (results.size() != requestedCount * 2)
  {
    return ua::Result<std::vector<detail::VariableShape>>{ua::Status::BadUnexpectedError,
      ua::make_error_detail("WriteShapeMetadataResultCountMismatch",
        "the shape metadata Read returned a result count different from the requested attribute count",
        std::string{source})};
  }

  std::vector<detail::VariableShape> shapes;
  shapes.reserve(requestedCount);
  for (std::size_t pairIndex = 0; pairIndex < requestedCount; ++pairIndex)
  {
    const auto& valueRank = results[pairIndex * 2];
    const auto& arrayDimensions = results[pairIndex * 2 + 1];
    const auto& valueRankStatus = valueRank.status();
    if (valueRankStatus && valueRankStatus.value().is_uncertain())
    {
      return ua::Result<std::vector<detail::VariableShape>>{
        detail::uncertain_answer_refused(valueRankStatus.value(), "ReadAnswerUncertain", source)};
    }
    if (valueRankStatus && valueRankStatus.value().is_bad())
    {
      return ua::Result<std::vector<detail::VariableShape>>{valueRankStatus.value(),
        ua::ErrorDetail::build("WriteValueRankReadFailed",
          "the Variable ValueRank attribute could not be read",
          std::string{source})
          .context(ua::ContextKeys::index, pairIndex)
          .cause(valueRankStatus.value())};
    }

    const auto* rank = valueRank.value().try_as<std::int32_t>();
    if (!rank)
    {
      return ua::Result<std::vector<detail::VariableShape>>{ua::Status::BadTypeMismatch,
        ua::ErrorDetail::build("WriteValueRankTypeMismatch",
          "the Variable ValueRank attribute is not an Int32",
          std::string{source})
          .context(ua::ContextKeys::index, pairIndex)};
    }

    detail::VariableShape shape;
    shape.valueRank = *rank;
    const auto& dimensionsStatus = arrayDimensions.status();
    if (dimensionsStatus && dimensionsStatus.value().is_uncertain())
    {
      return ua::Result<std::vector<detail::VariableShape>>{
        detail::uncertain_answer_refused(dimensionsStatus.value(), "ReadAnswerUncertain", source)};
    }
    if (dimensionsStatus && dimensionsStatus.value().is_bad())
    {
      // Part 3 section 5.6.2 marks ArrayDimensions optional for every Variable. An omitted attribute
      // therefore contributes no maxima regardless of ValueRank; Bad_AttributeIdInvalid is the wire
      // representation of that omission, not a failed metadata read.
      if (dimensionsStatus.value().as_status() == ua::Status::BadAttributeIdInvalid)
      {
        shapes.push_back(std::move(shape));
        continue;
      }
      return ua::Result<std::vector<detail::VariableShape>>{dimensionsStatus.value(),
        ua::ErrorDetail::build("WriteArrayDimensionsReadFailed",
          "the Variable ArrayDimensions attribute could not be read",
          std::string{source})
          .context(ua::ContextKeys::index, pairIndex)
          .cause(*arrayDimensions.status())};
    }
    if (!arrayDimensions.value().empty())
    {
      auto dimensions = arrayDimensions.value().to_vector<std::uint32_t>();
      if (!dimensions.has_value())
      {
        return ua::Result<std::vector<detail::VariableShape>>{dimensions.status_code(),
          ua::ErrorDetail::build("WriteArrayDimensionsTypeMismatch",
            "the Variable ArrayDimensions attribute is not a UInt32 array",
            std::string{source})
            .context(ua::ContextKeys::index, pairIndex)
            .cause(dimensions.status_code())};
      }
      shape.arrayDimensions = std::move(dimensions).value();
    }
    shapes.push_back(std::move(shape));
  }
  return ua::Result<std::vector<detail::VariableShape>>{std::move(shapes)};
}

/// The encoding limits the post-decode reify pass re-decodes preserved bodies under. Bounded-floor
/// defaults (1 MB string / 16 MB byte-string / 65535 array)  -  fail-closed against a hostile body. A body
/// exceeding a floor stays opaque (reify is best-effort, never fatal); threading the Connection's own
/// configured limits is a follow-up (section 9.2 / Slice T1 judgment call). NOTE: the body already
/// round-tripped through the secure-channel decoder under the real client limits, so a floor rejection here
/// only downgrades a large-but-legitimate structure to opaque, never fails the read.
ua::EncodingLimits reify_limits()
{
  return ua::EncodingLimits{};
}

/// Builds the reify support adapter over @p impl's live TypeResolver + current NamespaceTable snapshot, or
/// null when the resolver is unavailable (reify then delivers the values un-reified  -  never dropped).
std::shared_ptr<detail::ReifySupport> make_reify_support(const std::shared_ptr<detail::ConnectionImpl>& impl)
{
  auto resolver = impl->type_resolver();
  if (!resolver)
  {
    return nullptr;
  }
  const bool waitForResolution = resolver->policy().tier2WaitForResolution;
  return std::make_shared<detail::ResolverReifySupport>(
    std::move(resolver), impl->namespace_table_snapshot(), waitForResolution);
}

/// Flattens a per-item write StatusCode into a VoidResult (carrying any ErrorDetail). A Good subcode such
/// as Good_Clamped or Good_CompletesAsynchronously is kept.
ua::VoidResult to_void_result(const ua::StatusCode& status)
{
  return ua::VoidResult{status};
}

std::string describe_attempted_write_tuple(const ua::DataValue& value)
{
  std::string tuple;
  tuple.reserve(96);
  tuple.append("value=").append(value.is_null() ? "null" : "present");
  tuple.append(";status=").append(value.status().has_value() ? "present" : "absent");
  tuple.append(";sourceTimestamp=").append(value.source_timestamp().has_value() ? "present" : "absent");
  tuple.append(";serverTimestamp=").append(value.server_timestamp().has_value() ? "present" : "absent");
  return tuple;
}

/// The ValueRank a NumericRange is checked against. The check acts on the metadata itself, so an Uncertain
/// ServiceResult or attribute status is refused (ReadAnswerUncertain), as a Bad one is.
ua::Result<std::int32_t> parse_value_rank(ua::ReadResponse response, std::string_view source)
{
  const ua::StatusCode serviceResult = response.response_header().service_result();
  if (serviceResult.is_uncertain())
  {
    return ua::Result<std::int32_t>{
      detail::uncertain_answer_refused(serviceResult, "ReadAnswerUncertain", source)};
  }
  if (serviceResult.is_bad())
  {
    return ua::Result<std::int32_t>{serviceResult,
      ua::make_error_detail("NumericRangeValueRankServiceFault",
        "the ValueRank metadata Read returned a service-level error",
        std::string{source},
        serviceResult)};
  }
  const auto& results = response.results();
  if (results.size() != 1)
  {
    return ua::Result<std::int32_t>{ua::Status::BadUnexpectedError,
      ua::make_error_detail("NumericRangeValueRankResultCountMismatch",
        "the ValueRank metadata Read returned a result count other than one",
        std::string{source})};
  }
  const auto& valueRank = results[0];
  const auto& valueRankStatus = valueRank.status();
  if (valueRankStatus && valueRankStatus.value().is_uncertain())
  {
    return ua::Result<std::int32_t>{
      detail::uncertain_answer_refused(valueRankStatus.value(), "ReadAnswerUncertain", source)};
  }
  if (valueRankStatus && valueRankStatus.value().is_bad())
  {
    return ua::Result<std::int32_t>{valueRankStatus.value(),
      ua::ErrorDetail::build("NumericRangeValueRankReadFailed",
        "the Variable ValueRank attribute could not be read for NumericRange validation",
        std::string{source})
        .cause(valueRankStatus.value())};
  }
  const auto* rank = valueRank.value().try_as<std::int32_t>();
  if (!rank)
  {
    return ua::Result<std::int32_t>{ua::Status::BadTypeMismatch,
      ua::make_error_detail("NumericRangeValueRankTypeMismatch",
        "the Variable ValueRank attribute is not an Int32",
        std::string{source})};
  }
  return ua::Result<std::int32_t>{*rank};
}

/// The DataValue of a single-attribute Read. Two layers: the Read's ServiceResult (a Good subcode or an
/// Uncertain code included) is the status of the Result, the DataValue keeps its own.
ua::Result<ua::DataValue> flatten_attribute_read(ua::Result<ua::ReadResponse> result)
{
  if (!result.has_value())
  {
    return ua::Result<ua::DataValue>{result.status_code(), result.shared_detail()};
  }
  const ua::StatusCode serviceResult = result.value().response_header().service_result();
  if (serviceResult.is_bad())
  {
    return ua::Result<ua::DataValue>{serviceResult,
      ua::make_error_detail("ReadAttributeServiceFault",
        "the Read service returned a service-level error for the single requested attribute",
        std::string{readAttributeSource},
        serviceResult)};
  }
  auto& results = result.value().results();
  if (results.empty())
  {
    return ua::Result<ua::DataValue>{ua::Status::BadUnexpectedError,
      ua::make_error_detail("ReadAttributeEmptyResults",
        "the server returned a Good Read response with no result for the single requested attribute",
        std::string{readAttributeSource})};
  }
  return ua::detail::held(std::move(results[0]), serviceResult);
}

void complete_attribute_read(
  std::function<void(ua::Result<ua::DataValue>)> callback, ua::Result<ua::ReadResponse> result)
{
  callback(flatten_attribute_read(std::move(result)));
}

void complete_attribute_read_and_observe(std::weak_ptr<detail::ConnectionImpl> weakImpl, ua::NodeId node,
  ua::AttributeId attribute, std::function<void(ua::Result<ua::DataValue>)> callback,
  ua::Result<ua::ReadResponse> result)
{
  auto flattened = flatten_attribute_read(std::move(result));
  // The answer reaches the caller as it is; the Connection records an observed AccessLevelEx or ValueRank
  // only from a Good answer.
  if (!flattened.is_good())
  {
    callback(std::move(flattened));
    return;
  }
  const auto& valueStatus = flattened.value().status();
  if (valueStatus && !valueStatus.value().is_good())
  {
    callback(std::move(flattened));
    return;
  }
  auto impl = weakImpl.lock();
  if (!impl)
  {
    callback(std::move(flattened));
    return;
  }
  std::optional<std::uint32_t> accessLevelEx;
  std::optional<std::int32_t> valueRank;
  if (attribute == ua::AttributeId::AccessLevelEx)
  {
    if (const auto* observed = flattened.value().value().try_as<std::uint32_t>())
      accessLevelEx = *observed;
  }
  else if (attribute == ua::AttributeId::ValueRank)
  {
    if (const auto* observed = flattened.value().value().try_as<std::int32_t>())
      valueRank = *observed;
  }
  auto finish = [callback = std::move(callback), flattened = std::move(flattened)](ua::VoidResult) mutable
  {
    callback(std::move(flattened));
  };
  if (accessLevelEx)
  {
    impl->observe_access_level_ex_async(std::move(node), *accessLevelEx, std::move(finish));
    return;
  }
  if (valueRank)
  {
    impl->observe_value_rank_async(std::move(node), *valueRank, std::move(finish));
    return;
  }
  finish(ua::VoidResult{});
}

void complete_attribute_write(bool rangedWrite, std::string attemptedTuple,
  std::function<void(ua::VoidResult)> callback, ua::Result<ua::WriteResponse> result)
{
  if (!result.has_value())
  {
    callback(ua::VoidResult{result.status_code(), result.shared_detail()});
    return;
  }
  const ua::StatusCode serviceResult = result.value().response_header().service_result();
  if (serviceResult.is_bad())
  {
    callback(ua::VoidResult{serviceResult,
      ua::make_error_detail("WriteAttributeServiceFault",
        "the Write service returned a service-level error",
        std::string{writeAttributeSource},
        serviceResult)});
    return;
  }
  auto& results = result.value().results();
  if (results.size() != 1)
  {
    callback(ua::VoidResult{ua::Status::BadUnexpectedError,
      ua::make_error_detail("WriteAttributeResultCountMismatch",
        "the server returned a Write response whose result count is not exactly one for the single "
        "requested attribute",
        std::string{writeAttributeSource})});
    return;
  }
  if (results[0].value() == ua::StatusCode{ua::Status::BadWriteNotSupported}.value())
  {
    if (rangedWrite)
    {
      // For an IndexRange write this is the server-authoritative WriteFullArrayOnly / ranged-write verdict,
      // not a Value+Status+timestamp tuple rejection. Preserve its exact rich StatusCode and ErrorDetail.
      callback(to_void_result(results[0]));
      return;
    }
    callback(ua::VoidResult{results[0],
      ua::ErrorDetail::build("WriteAttributeCombinationUnsupported",
        "the server rejected the requested Value, StatusCode, and timestamp combination",
        std::string{writeAttributeSource})
        .context(ua::ContextKeys::value, std::move(attemptedTuple))
        .cause(results[0])});
    return;
  }
  // One place for two codes: the write's own status and the ServiceResult combined, so a Good subcode or an
  // Uncertain code of either reaches the caller.
  callback(to_void_result(ua::detail::combined_status(serviceResult, results[0])));
}

void complete_values_write(std::size_t requestedCount,
  std::function<void(ua::Result<std::vector<ua::VoidResult>>)> callback, ua::Result<ua::WriteResponse> result)
{
  if (!result.has_value())
  {
    callback(ua::Result<std::vector<ua::VoidResult>>{result.status_code(), result.shared_detail()});
    return;
  }
  const ua::StatusCode serviceResult = result.value().response_header().service_result();
  if (serviceResult.is_bad())
  {
    callback(ua::Result<std::vector<ua::VoidResult>>{serviceResult,
      ua::make_error_detail("WriteValuesServiceFault",
        "the bulk Write service returned a service-level error",
        std::string{writeValuesSource},
        serviceResult)});
    return;
  }
  const auto& results = result.value().results();
  if (results.size() != requestedCount)
  {
    callback(ua::Result<std::vector<ua::VoidResult>>{ua::Status::BadUnexpectedError,
      ua::make_error_detail("WriteValuesResultCountMismatch",
        "the bulk Write returned a result count different from the number of requested (Node, value) "
        "pairs",
        std::string{writeValuesSource})});
    return;
  }
  std::vector<ua::VoidResult> flattened;
  flattened.reserve(results.size());
  for (const auto& itemStatus : results)
  {
    flattened.push_back(to_void_result(itemStatus));
  }
  // Two layers: the ServiceResult (a Good subcode or an Uncertain code included) is the status of the outer
  // Result, each write keeps its own.
  callback(ua::detail::held(std::move(flattened), serviceResult));
}

void write_attribute_after_index_preflight(std::shared_ptr<detail::ConnectionImpl> impl, ua::NodeId node,
  ua::AttributeId attribute, ua::String indexRange, ua::DataValue value,
  std::function<void(ua::VoidResult)> callback)
{
  std::string attemptedTuple = describe_attempted_write_tuple(value);
  if (attribute != ua::AttributeId::Value)
  {
    const bool rangedWrite = !indexRange.empty();
    impl->write_async(
      make_attribute_write(std::move(node), attribute, std::move(value), std::move(indexRange)),
      [rangedWrite, attemptedTuple = std::move(attemptedTuple), callback = std::move(callback)](
        ua::Result<ua::WriteResponse> result) mutable
      {
        complete_attribute_write(
          rangedWrite, std::move(attemptedTuple), std::move(callback), std::move(result));
      });
    return;
  }

  if (!indexRange.empty())
  {
    // Part 4 section 5.10.4.2 requires the Value to be an array whenever IndexRange is specified, including
    // a write selecting one element. Tier 2 owns this normalization; tier 1 remains wire-shaped.
    value.value() = wrap_index_range_scalar(value.value());
    auto parsedRange =
      detail::validate_client_numeric_range(node, indexRange, std::nullopt, detail::NumericRangeUse::Write);
    if (!parsedRange.has_value())
    {
      callback(ua::VoidResult{parsedRange.status_code(), parsedRange.shared_detail()});
      return;
    }
    auto cardinality =
      detail::validate_client_numeric_range_write_cardinality(node, parsedRange.value(), value.value());
    if (cardinality.is_bad())
    {
      callback(std::move(cardinality));
      return;
    }
    impl->write_async(
      make_attribute_write(std::move(node), attribute, std::move(value), std::move(indexRange)),
      [attemptedTuple = std::move(attemptedTuple), callback = std::move(callback)](
        ua::Result<ua::WriteResponse> result) mutable
      { complete_attribute_write(true, std::move(attemptedTuple), std::move(callback), std::move(result)); });
    return;
  }

  std::vector<std::pair<ua::NodeId, ua::Variant>> shapePair;
  shapePair.emplace_back(node, value.value());
  std::weak_ptr<detail::ConnectionImpl> weakImpl = impl;
  impl->read_async(make_value_shapes_read(shapePair),
    [weakImpl,
      node = std::move(node),
      indexRange = std::move(indexRange),
      value = std::move(value),
      attemptedTuple = std::move(attemptedTuple),
      callback = std::move(callback)](ua::Result<ua::ReadResponse> metadataResult) mutable
    {
      if (!metadataResult.has_value())
      {
        callback(ua::VoidResult{metadataResult.status_code(), metadataResult.shared_detail()});
        return;
      }
      auto shapes = parse_value_shapes(std::move(metadataResult).value(), 1, writeAttributeSource);
      if (!shapes.has_value())
      {
        callback(ua::VoidResult{shapes.status_code(), shapes.shared_detail()});
        return;
      }
      auto validation = detail::validate_variable_write_shape(node, value.value(), shapes.value().front());
      if (validation.is_bad())
      {
        callback(std::move(validation));
        return;
      }
      auto liveImpl = weakImpl.lock();
      if (!liveImpl)
      {
        callback(ua::VoidResult{ua::Status::BadConnectionClosed,
          ua::make_error_detail("WriteConnectionGoneAfterShapeRead",
            "the Connection ended after shape metadata was read and before the Value Write",
            std::string{writeAttributeSource})});
        return;
      }
      liveImpl->write_async(
        make_attribute_write(
          std::move(node), ua::AttributeId::Value, std::move(value), std::move(indexRange)),
        [attemptedTuple = std::move(attemptedTuple), callback = std::move(callback)](
          ua::Result<ua::WriteResponse> result) mutable {
          complete_attribute_write(false, std::move(attemptedTuple), std::move(callback), std::move(result));
        });
    });
}

}  // namespace

TypedAccess::TypedAccess(std::shared_ptr<detail::ConnectionImpl> impl) : mImpl(std::move(impl))
{}

// ============ Arbitrary attribute ============

void TypedAccess::read_attribute_async(ua::NodeId node, ua::AttributeId attribute,
  std::function<void(ua::Result<ua::DataValue>)> callback) noexcept
{
  read_attribute_async(std::move(node), attribute, ua::String{}, std::move(callback));
}

void TypedAccess::read_attribute_async(ua::NodeId node, ua::AttributeId attribute, ua::String indexRange,
  std::function<void(ua::Result<ua::DataValue>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::DataValue>{emptyHandleStatus});
    return;
  }
  auto syntax =
    detail::validate_client_numeric_range(node, indexRange, std::nullopt, detail::NumericRangeUse::Read);
  if (!syntax.has_value())
  {
    callback(ua::Result<ua::DataValue>{syntax.status_code(), syntax.shared_detail()});
    return;
  }

  if (indexRange.empty() || attribute != ua::AttributeId::Value)
  {
    std::weak_ptr<detail::ConnectionImpl> weakImpl = mImpl;
    ua::NodeId observedNode = node;
    mImpl->read_async(make_attribute_read(std::move(node), attribute, std::move(indexRange)),
      [weakImpl, node = std::move(observedNode), attribute, callback = std::move(callback)](
        ua::Result<ua::ReadResponse> result) mutable
      {
        complete_attribute_read_and_observe(
          weakImpl, std::move(node), attribute, std::move(callback), std::move(result));
      });
    return;
  }

  auto metadataRequest = make_attribute_read(node, ua::AttributeId::ValueRank);
  std::weak_ptr<detail::ConnectionImpl> weakImpl = mImpl;
  mImpl->read_async(std::move(metadataRequest),
    [weakImpl,
      node = std::move(node),
      attribute,
      indexRange = std::move(indexRange),
      callback = std::move(callback)](ua::Result<ua::ReadResponse> metadataResult) mutable
    {
      if (!metadataResult.has_value())
      {
        callback(ua::Result<ua::DataValue>{metadataResult.status_code(), metadataResult.shared_detail()});
        return;
      }
      auto valueRank = parse_value_rank(std::move(metadataResult).value(), readAttributeSource);
      if (!valueRank.has_value())
      {
        callback(ua::Result<ua::DataValue>{valueRank.status_code(), valueRank.shared_detail()});
        return;
      }
      auto validation = detail::validate_client_numeric_range(
        node, indexRange, valueRank.value(), detail::NumericRangeUse::Read);
      if (validation.is_bad() && validation.status_code().as_status() == ua::Status::BadIndexRangeNoData)
      {
        // Answered as the server's Read answers it: the Read succeeds and the value's status says the range
        // selects nothing, with the value null (Part 4 7.11.1 Table 135).
        ua::DataValue selectsNothing;
        selectsNothing.status() = validation.status_code();
        callback(ua::Result<ua::DataValue>{std::move(selectsNothing)});
        return;
      }
      if (validation.is_bad())
      {
        callback(ua::Result<ua::DataValue>{validation.status_code(), validation.shared_detail()});
        return;
      }
      auto impl = weakImpl.lock();
      if (!impl)
      {
        callback(ua::Result<ua::DataValue>{ua::Status::BadConnectionClosed,
          ua::make_error_detail("ReadConnectionGoneAfterRangeValidation",
            "the Connection ended after NumericRange validation and before the Value Read",
            std::string{readAttributeSource})});
        return;
      }
      impl->read_async(make_attribute_read(std::move(node), attribute, std::move(indexRange)),
        [callback = std::move(callback)](ua::Result<ua::ReadResponse> result) mutable
        { complete_attribute_read(std::move(callback), std::move(result)); });
    });
}

ua::DataValue TypedAccess::read_attribute_sync(ua::NodeId node, ua::AttributeId attribute)
{
  return ua::detail::good_data_value(try_read_attribute_sync(std::move(node), attribute));
}

ua::DataValue TypedAccess::read_attribute_sync(
  ua::NodeId node, ua::AttributeId attribute, ua::String indexRange)
{
  return ua::detail::good_data_value(
    try_read_attribute_sync(std::move(node), attribute, std::move(indexRange)));
}

ua::Result<ua::DataValue> TypedAccess::try_read_attribute_sync(
  ua::NodeId node, ua::AttributeId attribute) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::DataValue>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, node = std::move(node), attribute](auto completion) mutable
    { read_attribute_async(std::move(node), attribute, std::move(completion)); });
}

void TypedAccess::read_value_with_encoding_async(ua::NodeId node, ua::QualifiedName dataEncoding,
  std::function<void(ua::Result<ua::DataValue>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::DataValue>{emptyHandleStatus});
    return;
  }
  if (dataEncoding.is_null())
  {
    callback(ua::Result<ua::DataValue>{ua::Status::BadInvalidArgument,
      ua::make_error_detail("NullExplicitDataEncoding",
        "the explicit DataEncoding read requires a non-null QualifiedName",
        std::string{readValueEncodingSource})});
    return;
  }

  auto requested = dataEncoding;
  mImpl->read_async(make_encoded_value_read(std::move(node), std::move(dataEncoding)),
    [requested = std::move(requested), callback = std::move(callback)](
      ua::Result<ua::ReadResponse> response) mutable
    {
      auto value = flatten_attribute_read(std::move(response));
      if (!value.has_value() || (value.value().status() && value.value().status()->is_bad()))
      {
        callback(std::move(value));
        return;
      }
      auto validation = validate_returned_body_encoding(value.value().value(), requested);
      if (validation.is_bad())
      {
        callback(ua::Result<ua::DataValue>{validation.status_code(), validation.shared_detail()});
        return;
      }
      callback(std::move(value));
    });
}

ua::DataValue TypedAccess::read_value_with_encoding_sync(ua::NodeId node, ua::QualifiedName dataEncoding)
{
  return ua::detail::good_data_value(
    try_read_value_with_encoding_sync(std::move(node), std::move(dataEncoding)));
}

ua::Result<ua::DataValue> TypedAccess::try_read_value_with_encoding_sync(
  ua::NodeId node, ua::QualifiedName dataEncoding) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::DataValue>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, node = std::move(node), dataEncoding = std::move(dataEncoding)](auto completion) mutable
    { read_value_with_encoding_async(std::move(node), std::move(dataEncoding), std::move(completion)); });
}

void TypedAccess::read_variable_metadata_async(
  ua::NodeId node, std::function<void(ua::Result<VariableMetadata>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<VariableMetadata>{emptyHandleStatus});
    return;
  }
  mImpl->read_async(make_attribute_read(std::move(node), ua::AttributeId::AccessLevelEx),
    [callback = std::move(callback)](ua::Result<ua::ReadResponse> response) mutable
    {
      auto attribute = flatten_attribute_read(std::move(response));
      if (!attribute.has_value())
      {
        callback(ua::Result<VariableMetadata>{attribute.status_code(), attribute.shared_detail()});
        return;
      }
      if (attribute.value().status() && *attribute.value().status() == ua::Status::BadAttributeIdInvalid)
      {
        callback(ua::detail::held(VariableMetadata{}, attribute.status_code()));
        return;
      }
      if (attribute.value().status() && attribute.value().status()->is_bad())
      {
        callback(ua::Result<VariableMetadata>{*attribute.value().status(),
          ua::make_error_detail("AccessLevelExReadFailed",
            "the Server rejected the Variable AccessLevelEx attribute read",
            std::string{variableMetadataSource})});
        return;
      }
      // The read's one code: the ServiceResult and the attribute's own status combined, kept with the
      // metadata; an Uncertain code with no value is the answer.
      const ua::StatusCode code = ua::detail::combined_status(
        attribute.status_code(), attribute.value().status().value_or(ua::StatusCode{ua::Status::Good}));
      if (code.is_uncertain() && attribute.value().value().empty())
      {
        callback(ua::Result<VariableMetadata>{code});
        return;
      }
      const auto* raw = attribute.value().value().try_as<std::uint32_t>();
      if (!raw)
      {
        callback(ua::Result<VariableMetadata>{ua::Status::BadTypeMismatch,
          ua::make_error_detail("AccessLevelExTypeMismatch",
            "the AccessLevelEx attribute was not encoded as UInt32",
            std::string{variableMetadataSource})});
        return;
      }
      callback(ua::detail::held(VariableMetadata{.accessLevelEx = ua::AccessLevelExType{*raw}}, code));
    });
}

VariableMetadata TypedAccess::read_variable_metadata_sync(ua::NodeId node)
{
  return ua::detail::good_value(try_read_variable_metadata_sync(std::move(node)));
}

ua::Result<VariableMetadata> TypedAccess::try_read_variable_metadata_sync(ua::NodeId node) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<VariableMetadata>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, node = std::move(node)](auto completion) mutable
    { read_variable_metadata_async(std::move(node), std::move(completion)); });
}

ua::Result<ua::DataValue> TypedAccess::try_read_attribute_sync(
  ua::NodeId node, ua::AttributeId attribute, ua::String indexRange) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::DataValue>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, node = std::move(node), attribute, indexRange = std::move(indexRange)](auto completion) mutable
    { read_attribute_async(std::move(node), attribute, std::move(indexRange), std::move(completion)); });
}

void TypedAccess::write_attribute_async(ua::NodeId node, ua::AttributeId attribute, ua::DataValue value,
  std::function<void(ua::VoidResult)> callback) noexcept
{
  write_attribute_async(std::move(node), attribute, ua::String{}, std::move(value), std::move(callback));
}

void TypedAccess::write_attribute_async(ua::NodeId node, ua::AttributeId attribute, ua::String indexRange,
  ua::DataValue value, std::function<void(ua::VoidResult)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::VoidResult{emptyHandleStatus});
    return;
  }
  auto syntax =
    detail::validate_client_numeric_range(node, indexRange, std::nullopt, detail::NumericRangeUse::Write);
  if (syntax.is_bad())
  {
    callback(ua::VoidResult{syntax.status_code(), syntax.shared_detail()});
    return;
  }
  if (indexRange.empty() || attribute != ua::AttributeId::Value)
  {
    write_attribute_after_index_preflight(
      mImpl, std::move(node), attribute, std::move(indexRange), std::move(value), std::move(callback));
    return;
  }

  std::weak_ptr<detail::ConnectionImpl> weakImpl = mImpl;
  const ua::NodeId preflightNode = node;
  ua::String preflightIndexRange = indexRange;
  mImpl->validate_index_range_write_async(preflightNode,
    std::move(preflightIndexRange),
    [weakImpl,
      node = std::move(node),
      attribute,
      indexRange = std::move(indexRange),
      value = std::move(value),
      callback = std::move(callback)](ua::VoidResult preflight) mutable
    {
      if (preflight.is_bad())
      {
        callback(std::move(preflight));
        return;
      }
      auto impl = weakImpl.lock();
      if (!impl)
      {
        callback(ua::VoidResult{ua::Status::BadConnectionClosed,
          ua::make_error_detail("WriteConnectionGoneAfterIndexRangePreflight",
            "the Connection ended after cached IndexRange validation and before the Write",
            std::string{writeAttributeSource})});
        return;
      }
      write_attribute_after_index_preflight(std::move(impl),
        std::move(node),
        attribute,
        std::move(indexRange),
        std::move(value),
        std::move(callback));
    });
}

void TypedAccess::write_attribute_sync(ua::NodeId node, ua::AttributeId attribute, ua::DataValue value)
{
  try_write_attribute_sync(std::move(node), attribute, std::move(value)).value();
}

void TypedAccess::write_attribute_sync(
  ua::NodeId node, ua::AttributeId attribute, ua::String indexRange, ua::DataValue value)
{
  try_write_attribute_sync(std::move(node), attribute, std::move(indexRange), std::move(value)).value();
}

ua::VoidResult TypedAccess::try_write_attribute_sync(
  ua::NodeId node, ua::AttributeId attribute, ua::DataValue value) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, node = std::move(node), attribute, value = std::move(value)](auto completion) mutable
    { write_attribute_async(std::move(node), attribute, std::move(value), std::move(completion)); });
}

ua::VoidResult TypedAccess::try_write_attribute_sync(
  ua::NodeId node, ua::AttributeId attribute, ua::String indexRange, ua::DataValue value) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<void>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, node = std::move(node), attribute, indexRange = std::move(indexRange), value = std::move(value)](
      auto completion) mutable
    {
      write_attribute_async(
        std::move(node), attribute, std::move(indexRange), std::move(value), std::move(completion));
    });
}

// ============ Bulk value reads / writes ============

void TypedAccess::read_values_async(std::vector<ua::NodeId> nodes,
  std::function<void(ua::Result<std::vector<ua::DataValue>>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<std::vector<ua::DataValue>>{emptyHandleStatus});
    return;
  }
  const std::size_t requestedCount = nodes.size();
  std::weak_ptr<detail::ConnectionImpl> weakImpl = mImpl;
  mImpl->read_async(make_values_read(std::move(nodes)),
    [callback = std::move(callback), requestedCount, weakImpl](ua::Result<ua::ReadResponse> result) mutable
    {
      if (!result.has_value())
      {
        callback(ua::Result<std::vector<ua::DataValue>>{result.status_code(), result.shared_detail()});
        return;
      }
      // Facade flatten (CL-ATTR-004): the tier-0 funnel returns a normal response verbatim; a bad
      // ResponseHeader.serviceResult is a service-level failure the bulk facade surfaces as bad.
      const ua::StatusCode serviceResult = result.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        callback(ua::Result<std::vector<ua::DataValue>>{serviceResult,
          ua::make_error_detail("ReadValuesServiceFault",
            "the bulk Read service returned a service-level error",
            std::string{readValuesSource},
            serviceResult)});
        return;
      }
      auto& results = result.value().results();
      if (results.size() != requestedCount)
      {
        // Slot alignment (CL-ATTR-004): a bulk Read MUST return exactly one DataValue per requested
        // Node; a count mismatch means the results cannot be positionally stitched to the request, so
        // reject it rather than mis-map or index an empty/short array.
        callback(ua::Result<std::vector<ua::DataValue>>{ua::Status::BadUnexpectedError,
          ua::make_error_detail("ReadValuesResultCountMismatch",
            "the bulk Read returned a result count different from the number of requested Nodes",
            std::string{readValuesSource})});
        return;
      }
      // Positional per-node DataValues; each carries its own value quality (two-layer). Run the gated-lazy
      // reify pass (section 9.2) so a structured value the wire decoder left as an UnknownStructure is
      // upgraded to its typed Structure via the Connection TypeRegistry BEFORE the caller sees it. The fast
      // path (no placeholder) delivers immediately with zero resolver access; a reify failure is non-fatal
      // (the type stays opaque, the read still succeeds). The values live in a shared vector so the reify
      // pass can mutate them in place across the async resolve barrier before `deliver` moves them to the
      // caller.
      auto values = std::make_shared<std::vector<ua::DataValue>>(results.payload());
      std::vector<ua::Variant*> variants;
      variants.reserve(values->size());
      for (auto& dataValue : *values)
      {
        variants.push_back(&dataValue.value());
      }
      // Two layers: the ServiceResult (a Good subcode or an Uncertain code included) is the status of the
      // outer Result, each DataValue keeps its own.
      auto deliver = [callback = std::move(callback), values, serviceResult]() mutable
      {
        callback(ua::detail::held(std::move(*values), serviceResult));
      };

      std::shared_ptr<detail::ReifySupport> support;
      if (auto impl = weakImpl.lock())
      {
        support = make_reify_support(impl);
      }
      detail::reify_and_deliver(std::move(variants), std::move(support), reify_limits(), std::move(deliver));
    });
}

std::vector<ua::DataValue> TypedAccess::read_values_sync(std::vector<ua::NodeId> nodes)
{
  return ua::detail::good_value(try_read_values_sync(std::move(nodes)));
}

ua::Result<std::vector<ua::DataValue>> TypedAccess::try_read_values_sync(
  std::vector<ua::NodeId> nodes) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<ua::DataValue>>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, nodes = std::move(nodes)](auto completion) mutable
    { read_values_async(std::move(nodes), std::move(completion)); });
}

void TypedAccess::read_values_atomicity_checked_async(std::vector<ua::NodeId> nodes,
  std::function<void(ua::Result<std::vector<ua::DataValue>>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<std::vector<ua::DataValue>>{emptyHandleStatus});
    return;
  }
  auto impl = mImpl;
  const std::size_t requestedCount = nodes.size();
  auto metadataRequest = make_attributes_read(nodes, ua::AttributeId::AccessLevelEx);
  impl->read_async(std::move(metadataRequest),
    [impl, nodes = std::move(nodes), requestedCount, callback = std::move(callback)](
      ua::Result<ua::ReadResponse> metadataResult) mutable
    {
      if (!metadataResult.has_value())
      {
        callback(ua::Result<std::vector<ua::DataValue>>{
          metadataResult.status_code(), metadataResult.shared_detail()});
        return;
      }
      // The AccessLevelEx batch decides the non-atomic advisory, so an Uncertain answer is refused.
      const auto serviceStatus = metadataResult.value().response_header().service_result();
      if (serviceStatus.is_uncertain())
      {
        callback(ua::Result<std::vector<ua::DataValue>>{
          detail::uncertain_answer_refused(serviceStatus, "ReadAnswerUncertain", variableMetadataSource)});
        return;
      }
      if (serviceStatus.is_bad())
      {
        callback(ua::Result<std::vector<ua::DataValue>>{serviceStatus,
          ua::make_error_detail("AccessLevelExBatchServiceFault",
            "the AccessLevelEx metadata batch returned a service-level failure",
            std::string{variableMetadataSource})});
        return;
      }
      const auto& metadata = metadataResult.value().results();
      if (metadata.size() != requestedCount)
      {
        callback(ua::Result<std::vector<ua::DataValue>>{ua::Status::BadUnexpectedError,
          ua::make_error_detail("AccessLevelExBatchCountMismatch",
            "the AccessLevelEx metadata result count did not match the Value batch",
            std::string{variableMetadataSource})});
        return;
      }
      bool nonatomicRead = false;
      for (const auto& value : metadata.payload())
      {
        if (value.status() && *value.status() == ua::Status::BadAttributeIdInvalid)
        {
          continue;
        }
        if (value.status() && value.status()->is_uncertain())
        {
          callback(ua::Result<std::vector<ua::DataValue>>{detail::uncertain_answer_refused(
            *value.status(), "ReadAnswerUncertain", variableMetadataSource)});
          return;
        }
        if (value.status() && value.status()->is_bad())
        {
          callback(ua::Result<std::vector<ua::DataValue>>{*value.status(),
            ua::make_error_detail("AccessLevelExBatchItemFailed",
              "an AccessLevelEx metadata item failed",
              std::string{variableMetadataSource})});
          return;
        }
        const auto* raw = value.value().try_as<std::uint32_t>();
        if (!raw)
        {
          callback(ua::Result<std::vector<ua::DataValue>>{ua::Status::BadTypeMismatch,
            ua::make_error_detail("AccessLevelExBatchTypeMismatch",
              "an AccessLevelEx metadata item was not encoded as UInt32",
              std::string{variableMetadataSource})});
          return;
        }
        nonatomicRead =
          nonatomicRead || ua::AccessLevelExType{*raw}.test(ua::AccessLevelExType::Bit::NonatomicRead);
      }

      TypedAccess valuesAccess{impl};
      valuesAccess.read_values_async(std::move(nodes),
        [sink = std::weak_ptr<detail::ObserverSink>{impl->observer_sink()},
          nonatomicRead,
          callback = std::move(callback)](ua::Result<std::vector<ua::DataValue>> values) mutable
        {
          if (values.has_value() && nonatomicRead)
          {
            if (auto observerSink = sink.lock())
            {
              observerSink->fire_advisory_diagnostic(ua::make_error_detail("NonatomicReadBatch",
                "batch contains a non-atomic member; internal consistency is not guaranteed",
                "client.tier2.typed_access.read_values_atomicity_checked"));
            }
          }
          callback(std::move(values));
        });
    });
}

std::vector<ua::DataValue> TypedAccess::read_values_atomicity_checked_sync(std::vector<ua::NodeId> nodes)
{
  return ua::detail::good_value(try_read_values_atomicity_checked_sync(std::move(nodes)));
}

ua::Result<std::vector<ua::DataValue>> TypedAccess::try_read_values_atomicity_checked_sync(
  std::vector<ua::NodeId> nodes) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<ua::DataValue>>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, nodes = std::move(nodes)](auto completion) mutable
    { read_values_atomicity_checked_async(std::move(nodes), std::move(completion)); });
}

void TypedAccess::dictionary_entries_for_async(
  ua::NodeId source, std::function<void(ua::Result<std::vector<BrowseCursor::Entry>>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<std::vector<BrowseCursor::Entry>>{emptyHandleStatus});
    return;
  }
  auto impl = mImpl;
  CursorFactory makeCursor = [impl](ua::NodeId node, BrowseOptions options)
  {
    TypedAccess access{impl};
    return access.browse(std::move(node), std::move(options));
  };

  BrowseOptions options;
  options.direction = ua::BrowseDirection::Forward;
  options.referenceTypeId = ua::NodeId{ua::ReferenceTypeId::HasDictionaryEntry};
  options.includeSubtypes = false;

  auto walk = std::make_shared<DictionaryEntriesWalk>();
  walk->makeCursor = std::move(makeCursor);
  walk->observer = impl->observer_sink();
  walk->callback = std::move(callback);
  walk->cursor.emplace(walk->makeCursor(std::move(source), std::move(options)));
  walk->collect();
}

std::vector<BrowseCursor::Entry> TypedAccess::dictionary_entries_for_sync(ua::NodeId source)
{
  return ua::detail::good_value(try_dictionary_entries_for_sync(std::move(source)));
}

ua::Result<std::vector<BrowseCursor::Entry>> TypedAccess::try_dictionary_entries_for_sync(
  ua::NodeId source) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<BrowseCursor::Entry>>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, source = std::move(source)](auto completion) mutable
    { dictionary_entries_for_async(std::move(source), std::move(completion)); });
}

void TypedAccess::write_values_async(std::vector<std::pair<ua::NodeId, ua::Variant>> pairs,
  std::function<void(ua::Result<std::vector<ua::VoidResult>>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<std::vector<ua::VoidResult>>{emptyHandleStatus});
    return;
  }
  const std::size_t requestedCount = pairs.size();
  if (pairs.empty())
  {
    mImpl->write_async(make_values_write({}),
      [callback = std::move(callback)](ua::Result<ua::WriteResponse> result) mutable
      { complete_values_write(0, std::move(callback), std::move(result)); });
    return;
  }

  std::weak_ptr<detail::ConnectionImpl> weakImpl = mImpl;
  auto metadataRequest = make_value_shapes_read(pairs);
  mImpl->read_async(std::move(metadataRequest),
    [weakImpl, pairs = std::move(pairs), callback = std::move(callback), requestedCount](
      ua::Result<ua::ReadResponse> metadataResult) mutable
    {
      if (!metadataResult.has_value())
      {
        callback(ua::Result<std::vector<ua::VoidResult>>{
          metadataResult.status_code(), metadataResult.shared_detail()});
        return;
      }
      auto shapes = parse_value_shapes(std::move(metadataResult).value(), requestedCount, writeValuesSource);
      if (!shapes.has_value())
      {
        callback(ua::Result<std::vector<ua::VoidResult>>{shapes.status_code(), shapes.shared_detail()});
        return;
      }
      for (std::size_t index = 0; index < requestedCount; ++index)
      {
        auto validation = detail::validate_variable_write_shape(
          pairs[index].first, pairs[index].second, shapes.value()[index]);
        if (validation.is_bad())
        {
          callback(
            ua::Result<std::vector<ua::VoidResult>>{validation.status_code(), validation.shared_detail()});
          return;
        }
      }
      auto impl = weakImpl.lock();
      if (!impl)
      {
        callback(ua::Result<std::vector<ua::VoidResult>>{ua::Status::BadConnectionClosed,
          ua::make_error_detail("WriteConnectionGoneAfterShapeRead",
            "the Connection ended after shape metadata was read and before the bulk Value Write",
            std::string{writeValuesSource})});
        return;
      }
      impl->write_async(make_values_write(std::move(pairs)),
        [callback = std::move(callback), requestedCount](ua::Result<ua::WriteResponse> result) mutable
        { complete_values_write(requestedCount, std::move(callback), std::move(result)); });
    });
}

std::vector<ua::VoidResult> TypedAccess::write_values_sync(
  std::vector<std::pair<ua::NodeId, ua::Variant>> pairs)
{
  return ua::detail::good_value(try_write_values_sync(std::move(pairs)));
}

ua::Result<std::vector<ua::VoidResult>> TypedAccess::try_write_values_sync(
  std::vector<std::pair<ua::NodeId, ua::Variant>> pairs) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<ua::VoidResult>>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, pairs = std::move(pairs)](auto completion) mutable
    { write_values_async(std::move(pairs), std::move(completion)); });
}

// ============ Translate browse path ============

void TypedAccess::translate_browse_path_async(ua::NodeId start, ua::RelativePath relativePath,
  std::function<void(ua::Result<std::vector<TranslatedNodeId>>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<std::vector<TranslatedNodeId>>{emptyHandleStatus});
    return;
  }
  const auto& elements = relativePath.elements();
  if (!elements.empty() && elements[elements.size() - 1].target_name().name().empty())
  {
    callback(ua::Result<std::vector<TranslatedNodeId>>{ua::Status::BadInvalidArgument,
      ua::make_error_detail("TranslateBrowsePathMissingFinalTargetName",
        "the final relative path element must specify a target name",
        std::string{translateSource})});
    return;
  }
  ua::BrowsePath path;
  path.starting_node() = std::move(start);
  path.relative_path() = std::move(relativePath);
  ua::TranslateBrowsePathsToNodeIdsRequest request;
  request.browse_paths().push_back(std::move(path));

  mImpl->translate_browse_paths_async(std::move(request),
    [callback = std::move(callback)](ua::Result<ua::TranslateBrowsePathsToNodeIdsResponse> result) mutable
    {
      if (!result.has_value())
      {
        callback(ua::Result<std::vector<TranslatedNodeId>>{result.status_code(), result.shared_detail()});
        return;
      }
      // Facade flatten: a bad ResponseHeader.serviceResult is a service-level failure the facade surfaces as
      // bad (single-wrap, preserving the status + ErrorDetail). Post CL-DIAG-005 the funnel already collapses
      // this to result.is_bad() above; this branch is a defensive guard.
      const ua::StatusCode serviceResult = result.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        callback(ua::Result<std::vector<TranslatedNodeId>>{serviceResult,
          ua::make_error_detail("TranslateBrowsePathServiceFault",
            "the TranslateBrowsePaths service returned a service-level error",
            std::string{translateSource},
            serviceResult)});
        return;
      }
      const auto& results = result.value().results();
      if (results.empty())
      {
        callback(ua::Result<std::vector<TranslatedNodeId>>{ua::Status::BadUnexpectedError,
          ua::make_error_detail("TranslateBrowsePathEmptyResults",
            "the server returned a Good TranslateBrowsePaths response with no result for the single path",
            std::string{translateSource})});
        return;
      }
      const ua::BrowsePathResult& browsePathResult = results[0];
      // CL-VIEW-014: a bad per-path status (e.g. the server's Bad_NoMatch / Bad_BrowseNameInvalid) propagates
      // as the bad Result, preserving the exact status + any ErrorDetail.
      if (browsePathResult.status_code().is_bad())
      {
        callback(ua::Result<std::vector<TranslatedNodeId>>{
          browsePathResult.status_code(), browsePathResult.status_code().shared_detail()});
        return;
      }
      // CL-VIEW-014: a Good per-path status with NO targets resolved to nothing -> synthesise Bad_NoMatch.
      if (browsePathResult.targets().empty())
      {
        callback(ua::Result<std::vector<TranslatedNodeId>>{ua::Status::BadNoMatch,
          ua::make_error_detail("TranslateBrowsePathNoMatch",
            "the relative path resolved to no target node",
            std::string{translateSource})});
        return;
      }
      // CL-VIEW-015 / CL-VIEW-019 (OPEN-VIEW-4 = success-with-partial): every target, in the server's order.
      // A PARTIAL resolution (remainingPathIndex != fullyResolved) or a CROSS-SERVER target (serverIndex !=
      // 0) is data its TranslatedNodeId records (is_fully_resolved()/is_local() are false); the SDK never
      // connects to another server to resolve a residual.
      std::vector<TranslatedNodeId> targets;
      targets.reserve(browsePathResult.targets().size());
      for (const ua::BrowsePathTarget& target : browsePathResult.targets())
      {
        targets.push_back(TranslatedNodeId{target.target_id(), target.remaining_path_index()});
      }
      // One place for two codes: the path's own status and the ServiceResult combined, so a Good subcode or
      // an Uncertain code of either is the status of the targets returned.
      callback(ua::detail::held(
        std::move(targets), ua::detail::combined_status(serviceResult, browsePathResult.status_code())));
    });
}

std::vector<TranslatedNodeId> TypedAccess::translate_browse_path_sync(
  ua::NodeId start, ua::RelativePath relativePath)
{
  return ua::detail::good_value(try_translate_browse_path_sync(std::move(start), std::move(relativePath)));
}

ua::Result<std::vector<TranslatedNodeId>> TypedAccess::try_translate_browse_path_sync(
  ua::NodeId start, ua::RelativePath relativePath) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<TranslatedNodeId>>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, start = std::move(start), relativePath = std::move(relativePath)](auto completion) mutable
    { translate_browse_path_async(std::move(start), std::move(relativePath), std::move(completion)); });
}

void TypedAccess::translate_browse_path_async(ua::ExpandedNodeId start, ua::RelativePath relativePath,
  std::function<void(ua::Result<std::vector<TranslatedNodeId>>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<std::vector<TranslatedNodeId>>{emptyHandleStatus});
    return;
  }
  if (start.server_index() != 0)
  {
    callback(ua::Result<std::vector<TranslatedNodeId>>{ua::Status::BadInvalidArgument,
      ua::ErrorDetail::build("RemoteStartingNode",
        "Starting node must be local; connect to remote server first",
        std::string{translateSource})
        .context(ua::ContextKeys::value, start.server_index())});
    return;
  }

  const auto namespaceTable = mImpl->namespace_table_snapshot();
  if (!namespaceTable)
  {
    callback(ua::Result<std::vector<TranslatedNodeId>>{ua::Status::BadInvalidState,
      ua::make_error_detail("NamespaceTableUnavailable",
        "the Connection has no NamespaceArray snapshot for ExpandedNodeId resolution",
        std::string{translateSource})});
    return;
  }
  auto localStart = namespaceTable->resolve_local(start);
  if (!localStart.has_value())
  {
    callback(ua::Result<std::vector<TranslatedNodeId>>{localStart.status_code(), localStart.shared_detail()});
    return;
  }
  translate_browse_path_async(std::move(localStart).value(), std::move(relativePath), std::move(callback));
}

std::vector<TranslatedNodeId> TypedAccess::translate_browse_path_sync(
  ua::ExpandedNodeId start, ua::RelativePath relativePath)
{
  return ua::detail::good_value(try_translate_browse_path_sync(std::move(start), std::move(relativePath)));
}

ua::Result<std::vector<TranslatedNodeId>> TypedAccess::try_translate_browse_path_sync(
  ua::ExpandedNodeId start, ua::RelativePath relativePath) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<std::vector<TranslatedNodeId>>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, start = std::move(start), relativePath = std::move(relativePath)](auto completion) mutable
    { translate_browse_path_async(std::move(start), std::move(relativePath), std::move(completion)); });
}

namespace
{

/// The one local node of a translation, or why there is not exactly one (section 10, API-8c.2).
ua::NodeIdResult single_local_target(
  ua::Result<std::vector<TranslatedNodeId>> translated, const std::vector<ua::QualifiedName>& names)
{
  if (!translated.has_value())
  {
    return ua::NodeIdResult{translated.status_code(), translated.shared_detail()};
  }
  const std::vector<TranslatedNodeId>& targets = translated.value();
  if (targets.size() > 1)
  {
    return ua::NodeIdResult{ua::Status::BadTooManyMatches,
      ua::ErrorDetail::build("ResolvePathTooManyMatches",
        "the relative path resolved to more than one node; translate_browse_path returns them all",
        std::string{resolveSource})
        .context(ua::ContextKeys::countActual, targets.size())};
  }
  const TranslatedNodeId& target = targets.front();
  if (!target.is_fully_resolved() || !target.is_local())
  {
    auto detail = ua::ErrorDetail::build("ResolvePathNotLocal",
      "the relative path leads to another server; the SDK does not connect to it",
      std::string{resolveSource})
                    .context(ua::ContextKeys::serverIndex, target.targetId.server_index());
    if (!target.is_fully_resolved())
    {
      detail.context(ua::ContextKeys::index, target.remainingPathIndex);
      if (target.remainingPathIndex < names.size())
      {
        detail.context(ua::ContextKeys::nodeBrowseName, names[target.remainingPathIndex]);
      }
    }
    return ua::NodeIdResult{ua::Status::BadNoMatch, std::move(detail)};
  }
  return ua::detail::held(target.local_node_id(), translated.status_code());
}

}  // namespace

void TypedAccess::resolve_path_async(
  ua::NodeId start, ua::RelativePath relativePath, std::function<void(ua::NodeIdResult)> callback) noexcept
{
  std::vector<ua::QualifiedName> names;
  names.reserve(relativePath.elements().size());
  for (const ua::RelativePathElement& element : relativePath.elements())
  {
    names.push_back(element.target_name());
  }
  translate_browse_path_async(std::move(start),
    std::move(relativePath),
    [names = std::move(names), callback = std::move(callback)](
      ua::Result<std::vector<TranslatedNodeId>> translated) mutable
    { callback(single_local_target(std::move(translated), names)); });
}

ua::NodeId TypedAccess::resolve_path_sync(ua::NodeId start, ua::RelativePath relativePath)
{
  return ua::detail::good_value(try_resolve_path_sync(std::move(start), std::move(relativePath)));
}

ua::NodeIdResult TypedAccess::try_resolve_path_sync(ua::NodeId start, ua::RelativePath relativePath) noexcept
{
  return ua::async::detail::blocking_call<ua::NodeIdResult>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, start = std::move(start), relativePath = std::move(relativePath)](auto completion) mutable
    { resolve_path_async(std::move(start), std::move(relativePath), std::move(completion)); });
}

// ============ Browse ============

BrowseCursor TypedAccess::browse(ua::NodeId start, BrowseOptions options)
{
  auto state = std::make_shared<detail::BrowseCursorState>();
  if (mImpl)
  {
    // The cursor holds the wire interface WEAK (locked per advance, bail if gone) and posts buffered yields /
    // boundary failures on the Connection executor (section 7.5).
    state->wireOps = mImpl->wire_ops();
    state->executor = mImpl->executor();
    state->sessionGeneration = mImpl->session_generation_token();
    // CL-VIEW-017: wire the advisory interface to the Connection's ObserverSink (weak-captured  -  no
    // ownership cycle back into the orchestrator; a gone sink is a silent no-op) so a non-conformant remote
    // reference emits on_advisory_diagnostic.
    state->emitAdvisory = [sink = std::weak_ptr<detail::ObserverSink>(mImpl->observer_sink())](
                            std::shared_ptr<const ua::ErrorDetail> detail)
    {
      if (auto observerSink = sink.lock())
      {
        observerSink->fire_advisory_diagnostic(std::move(detail));
      }
    };
    // CL-VIEW-018: take the current NamespaceTable snapshot so a LOCAL target's URI-bearing ExpandedNodeId is
    // resolved to a local NamespaceIndex during flattening (null before the namespace array is read -> the
    // cursor preserves the URI verbatim; a strict no-op).
    state->namespaceTable = mImpl->namespace_table_snapshot();
    if (mImpl->address_space_cache_enabled())
    {
      // Enabled read-surface cache (section 8.7): wire the cache (held WEAK  -  no cycle) + the connection
      // strand the initial-browse lookup/install hops onto (shared with the cache's own invalidation path).
      // Gated on the IMMUTABLE policy so a DISABLED Connection (the default) never force-constructs or
      // consults the cache
      //  -  the cursor stays a strict pass-through no-op (state->cache empty, state->strand nullopt).
      state->cache = mImpl->address_space_cache();
      state->strand = mImpl->strand();
    }
  }
  state->startNode = std::move(start);
  state->options = std::move(options);
  // TypedAccess is a friend of BrowseCursor: construct it directly from the shared walk state.
  return BrowseCursor{std::move(state)};
}

// ============ Method call ============

static void dispatch_call_method_async(std::shared_ptr<detail::ConnectionImpl> connection, ua::NodeId object,
  ua::NodeId method, std::vector<ua::Variant> arguments,
  std::function<void(ua::Result<ua::CallResult>)> callback) noexcept
{
  if (!connection)
  {
    callback(ua::Result<ua::CallResult>{emptyHandleStatus});
    return;
  }
  ua::CallMethodRequest methodRequest;
  methodRequest.object_id() = std::move(object);
  methodRequest.method_id() = std::move(method);
  for (auto& argument : arguments)
  {
    methodRequest.input_arguments().push_back(std::move(argument));
  }
  ua::CallRequest request;
  request.methods_to_call().push_back(std::move(methodRequest));

  std::weak_ptr<detail::ConnectionImpl> weakImpl = connection;
  connection->call_async(std::move(request),
    [callback = std::move(callback), weakImpl](ua::Result<ua::CallResponse> result) mutable
    {
      if (!result.has_value())
      {
        callback(ua::Result<ua::CallResult>{result.status_code(), result.shared_detail()});
        return;
      }
      // Facade flatten (CL-METH-005 / section 7.10.3): the tier-0 wire-op funnel returns the CallResponse
      // verbatim - a bad ResponseHeader.serviceResult is a service-level failure the facade must surface
      // as a bad outer Result with a source-tagged ErrorDetail (mirrors the read/write value facades),
      // never processed as if the single method call succeeded.
      const ua::StatusCode serviceResult = result.value().response_header().service_result();
      if (serviceResult.is_bad())
      {
        callback(ua::Result<ua::CallResult>{serviceResult,
          ua::make_error_detail("CallMethodServiceFault",
            "the Call service returned a bad ResponseHeader.serviceResult",
            std::string{callMethodSource},
            serviceResult)});
        return;
      }
      auto& results = result.value().results();
      if (results.size() != 1)
      {
        // Slot alignment (CL-METH-005): a single-method Call MUST return exactly one CallMethodResult;
        // an empty, short, or over-long results array cannot be stitched to the one requested method, so
        // reject it rather than index a missing slot or silently drop extra results.
        callback(ua::Result<ua::CallResult>{ua::Status::BadUnexpectedError,
          ua::make_error_detail("CallMethodResultCountMismatch",
            "the server returned a Good Call response whose result count is not one for the single "
            "requested method",
            std::string{callMethodSource})});
        return;
      }
      // Two-layer: the outer Result carries the ServiceResult (a Good subcode or an Uncertain code
      // included); the inner CallResult carries the per-method status and output arguments (or the bad
      // per-method status). Only a Bad-Severity per-method status collapses the inner CallResult; a Good OR
      // Uncertain status keeps the full CallMethodResult (with its outputArguments) - CL-METH-006 mandates
      // dropping outputArguments only when Severity is Bad, so an Uncertain result must still expose its
      // outputs to the caller. The inner CallResult's status is the per-method status, a Good subcode or an
      // Uncertain code included.
      ua::CallMethodResult methodResult = std::move(results[0]);
      if (!methodResult.status_code().is_bad())
      {
        // Run the gated-lazy reify pass (section 9.2) over the output arguments so a structured output the
        // wire decoder left as an UnknownStructure is upgraded to its typed Structure via the Connection
        // TypeRegistry BEFORE the caller sees it (mirrors read_values). The fast path (no placeholder)
        // delivers immediately with zero resolver access; a reify failure is non-fatal (the output stays
        // opaque, the call still succeeds). The method result is held in a shared holder so the reify pass
        // can mutate its outputArguments in place across the async resolve barrier before `deliver` moves it
        // out.
        auto held = std::make_shared<ua::CallMethodResult>(std::move(methodResult));
        std::vector<ua::Variant*> variants;
        variants.reserve(held->output_arguments().size());
        for (auto& output : held->output_arguments())
        {
          variants.push_back(&output);
        }
        auto deliver = [callback = std::move(callback), held, serviceResult]() mutable
        {
          const ua::StatusCode methodStatus = held->status_code();
          callback(ua::detail::held(ua::detail::held(std::move(*held), methodStatus), serviceResult));
        };

        std::shared_ptr<detail::ReifySupport> support;
        if (auto impl = weakImpl.lock())
        {
          support = make_reify_support(impl);
        }
        detail::reify_and_deliver(
          std::move(variants), std::move(support), reify_limits(), std::move(deliver));
        return;
      }
      // Bad per-method status: preserve both diagnostic planes carried by CallResponse:
      // diagnosticInfos[0] describes this method operation, while CallMethodResult's
      // inputArgumentDiagnosticInfos describe individual arguments. They are independent and neither may
      // erase the other.
      std::shared_ptr<const ua::ErrorDetail> operationDiagnosticChain;
      const auto& operationDiagnostics = result.value().diagnostic_infos();
      if (!operationDiagnostics.empty() && !operationDiagnostics[0].is_null())
      {
        try
        {
          detail::DiagnosticInfoDecoder decoder{};
          if (auto impl = weakImpl.lock())
          {
            decoder.namespaceTable = impl->namespace_table_snapshot();
          }
          operationDiagnosticChain = decoder.decode_operation(operationDiagnostics[0],
            result.value().response_header().string_table(),
            methodResult.status_code(),
            0);
        }
        catch (const std::exception& decodeError)
        {
          if (auto impl = weakImpl.lock())
          {
            impl->logger().warning(
              "CL-METH-005: decoding the per-method DiagnosticInfo failed ({}); falling back to the "
              "per-method status",
              decodeError.what());
          }
        }
        catch (...)
        {
          if (auto impl = weakImpl.lock())
          {
            impl->logger().warning(
              "CL-METH-005: decoding the per-method DiagnosticInfo threw a non-standard exception; "
              "falling back to the per-method status");
          }
        }
      }

      // Do not collapse to the bare method status: inputArgumentResults identify which arguments the
      // server rejected. The outer detail records the first bad index and total count.
      const auto& argumentResults = methodResult.input_argument_results();
      std::size_t badArgumentCount = 0;
      std::size_t firstBadArgumentIndex = 0;
      bool haveFirstBadArgument = false;
      ua::StatusCode firstBadArgumentStatus;
      for (std::size_t index = 0; index < argumentResults.size(); ++index)
      {
        if (argumentResults[index].is_bad())
        {
          ++badArgumentCount;
          if (!haveFirstBadArgument)
          {
            firstBadArgumentIndex = index;
            firstBadArgumentStatus = argumentResults[index];
            haveFirstBadArgument = true;
          }
        }
      }

      auto detail = ua::ErrorDetail::build("CallMethodBadPerMethodStatus",
        "the server returned a bad per-method Call status; the per-input-argument results identify the "
        "rejected argument",
        std::string{callMethodSource});
      std::shared_ptr<const ua::ErrorDetail> inheritedStatusChain;
      std::shared_ptr<const ua::ErrorDetail> argumentDiagnosticChain;
      if (haveFirstBadArgument)
      {
        detail.context(ua::ContextKeys::operationIndex, static_cast<std::uint64_t>(firstBadArgumentIndex))
          .context(ua::ContextKeys::countTotal, static_cast<std::uint64_t>(badArgumentCount))
          .cause(firstBadArgumentStatus);
        inheritedStatusChain = firstBadArgumentStatus.shared_detail();

        // CL-METH-005 (the per-operation twin of CL-BASEDIAG-001): thread the server's per-ARGUMENT
        // DiagnosticInfo for the first-bad argument into the cause chain rather than discarding it
        // (the design specification: never silently drop an ErrorDetail). The decoded chain crosses the
        // wire-boundary marker (DiagnosticInfoDecoder) and preserves the bare status set above as the
        // inner status, so the breadcrumb is a strict superset of the pre-existing cause.
        //   - Strict no-op when the server omitted per-arg diagnostics: the bare-status cause above
        //     stands unchanged, so every existing bad-Call test is byte-for-byte identical.
        //   - Bounds-checked: a non-conformant server may send fewer inputArgumentDiagnosticInfos than
        //     inputArgumentResults, so the first-bad index must be inside the diag-info array before it
        //     is indexed (section 3.1 index-bounds - never index OOB, never misuse a sibling argument's
        //     diag).
        //   - noexcept-guarded: a malformed per-arg DiagnosticInfo must never throw out of the accessor
        //     (process-abort class - the reverse-connect lesson); a decode failure logs and falls back
        //     to the bare-status cause already set above.
        const auto& argumentDiagnostics = methodResult.input_argument_diagnostic_infos();
        if (firstBadArgumentIndex < argumentDiagnostics.size() &&
            !argumentDiagnostics[firstBadArgumentIndex].is_null())
        {
          try
          {
            detail::DiagnosticInfoDecoder decoder{};
            if (auto impl = weakImpl.lock())
            {
              // CL-DIAG-007: map a server NamespaceURI to its source tag (snapshot read is thread-safe).
              decoder.namespaceTable = impl->namespace_table_snapshot();
            }
            argumentDiagnosticChain = decoder.decode_operation(argumentDiagnostics[firstBadArgumentIndex],
              result.value().response_header().string_table(),
              firstBadArgumentStatus,
              static_cast<std::uint32_t>(firstBadArgumentIndex));
          }
          catch (const std::exception& decodeError)
          {
            if (auto impl = weakImpl.lock())
            {
              impl->logger().warning(
                "CL-METH-005: decoding the per-argument DiagnosticInfo for input argument {} failed "
                "({}); falling back to the bare-status cause",
                firstBadArgumentIndex,
                decodeError.what());
            }
          }
          catch (...)
          {
            if (auto impl = weakImpl.lock())
            {
              impl->logger().warning(
                "CL-METH-005: decoding the per-argument DiagnosticInfo for input "
                "argument {} threw a non-standard exception; falling back to the "
                "bare-status cause",
                firstBadArgumentIndex);
            }
          }
        }
      }
      else
      {
        // No per-argument breadcrumb (e.g. a method-level rejection); still preserve the per-method
        // status chain rather than dropping it.
        detail.cause(methodResult.status_code());
        inheritedStatusChain = methodResult.status_code().shared_detail();
      }

      // Keep the operation diagnostic first because it describes the CallMethodResult itself; append the
      // optional per-argument chain and any detail already attached to the causal StatusCode beneath it.
      // append_diagnostic_chain copies decoder-owned immutable links rather than mutating a shared chain.
      auto wireDiagnosticChain =
        append_diagnostic_chain(operationDiagnosticChain, std::move(argumentDiagnosticChain));
      wireDiagnosticChain = append_diagnostic_chain(wireDiagnosticChain, std::move(inheritedStatusChain));
      if (wireDiagnosticChain)
      {
        detail.cause(std::move(wireDiagnosticChain));
      }
      callback(ua::detail::held(ua::CallResult{methodResult.status_code(), detail}, serviceResult));
    });
}

static ua::Result<ua::NodeId> structured_value_datatype(
  const ua::Structure& structure, const detail::TypeRegistry& registry, const NamespaceTable& namespaces)
{
  if (const auto* unknown = dynamic_cast<const ua::UnknownStructure*>(&structure))
  {
    const auto* registered = registry.find_by_encoding(unknown->encoding_id());
    if (!registered)
    {
      return ua::Result<ua::NodeId>{ua::Status::BadDataEncodingInvalid,
        ua::make_error_detail("MethodStructuredArgumentEncodingUnknown",
          "the structured Method argument's encoding NodeId is not registered",
          std::string{callMethodSource})};
    }
    return ua::Result<ua::NodeId>{registered->dataTypeId};
  }
  try
  {
    auto resolved = namespaces.resolve_local(structure.type_id());
    if (!resolved.has_value())
    {
      return ua::Result<ua::NodeId>{resolved.status_code(), resolved.shared_detail()};
    }
    return resolved;
  }
  catch (const ua::UaException& error)
  {
    return ua::Result<ua::NodeId>{error.status_code(), error.take_detail()};
  }
  catch (...)
  {
    return ua::Result<ua::NodeId>{ua::Status::BadDataEncodingInvalid,
      ua::make_error_detail("MethodStructuredArgumentTypeUnknown",
        "determining the structured Method argument's DataType threw",
        std::string{callMethodSource})};
  }
}

static ua::VoidResult validate_structured_method_arguments(const std::vector<ua::Variant>& arguments,
  const MethodInputMetadata& metadata, const std::shared_ptr<detail::ConnectionImpl>& connection)
{
  auto resolver = connection->type_resolver();
  auto registry = resolver->registry();
  auto namespaces = connection->namespace_table_snapshot();
  if (!registry || !namespaces)
  {
    return ua::VoidResult{ua::Status::BadInvalidState,
      ua::make_error_detail("MethodStructuredArgumentResolverUnavailable",
        "structured Method argument validation requires TypeResolver and NamespaceTable snapshots",
        std::string{callMethodSource})};
  }

  const auto validateStructure = [&metadata, &registry, &namespaces](
                                   const ua::Structure& structure, std::size_t index) -> ua::VoidResult
  {
    auto concreteType = structured_value_datatype(structure, *registry, *namespaces);
    if (!concreteType.has_value())
    {
      return ua::VoidResult{concreteType.status_code(), concreteType.shared_detail()};
    }
    if (index >= metadata.inputArguments.size())
    {
      return ua::VoidResult{ua::Status::BadTypeMismatch,
        ua::ErrorDetail::build("MethodStructuredArgumentMetadataMissing",
          "the Method has no declared InputArgument for a supplied structured value",
          std::string{callMethodSource})
          .context(ua::ContextKeys::operationIndex, static_cast<std::uint64_t>(index))};
    }
    const ua::NodeId& declaredType = metadata.inputArguments[index].data_type();
    const auto relation = registry->is_subtype_of(concreteType.value(), declaredType);
    const bool hasSelfDescribedType = dynamic_cast<const ua::UnknownStructure*>(&structure) == nullptr;
    const bool selfDescribedMatch =
      hasSelfDescribedType &&
      (declaredType == ua::NodeId{ua::DataTypeId::Structure} ||
        structure.is_of_type(ua::CodecNamespaceContext{[namespaces](ua::string_view uri)
                               {
                                 return namespaces->lookup_index(uri).value_or(std::uint16_t{0});
                               }},
          declaredType));
    if (relation == std::optional<bool>{true} || selfDescribedMatch)
    {
      return ua::VoidResult{};
    }
    const bool relationDecidable = relation.has_value() || hasSelfDescribedType;
    const ua::StatusCode failure{
      relationDecidable ? ua::Status::BadTypeMismatch : ua::Status::BadDataEncodingInvalid};
    return ua::VoidResult{failure,
      ua::ErrorDetail::build("MethodStructuredArgumentTypeMismatch",
        "The structured Method argument is incompatible with the declared DataType",
        std::string{callMethodSource})
        .context(ua::ContextKeys::operationIndex, static_cast<std::uint64_t>(index))
        .context(ua::ContextKeys::typeActual, concreteType.value())
        .context(ua::ContextKeys::typeExpected, declaredType)};
  };

  for (std::size_t index = 0; index < arguments.size(); ++index)
  {
    if (arguments[index].is_structure())
    {
      const auto& reference = arguments[index].as<ua::RefStructure<ua::Structure>>();
      if (reference.get())
      {
        auto result = validateStructure(*reference.get(), index);
        if (result.is_bad())
          return result;
      }
      continue;
    }
    if (!arguments[index].is_array_of_structure())
      continue;

    const auto& structures = arguments[index].as<ua::Array<ua::RefStructure<ua::Structure>>>();
    for (const auto& reference : structures.payload())
    {
      if (!reference.get())
        continue;
      auto result = validateStructure(*reference.get(), index);
      if (result.is_bad())
        return result;
    }
  }
  return ua::VoidResult{};
}

void TypedAccess::call_method_async(ua::NodeId object, ua::NodeId method, std::vector<ua::Variant> arguments,
  std::function<void(ua::Result<ua::CallResult>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<ua::CallResult>{emptyHandleStatus});
    return;
  }
  const bool hasStructuredArgument = std::any_of(arguments.begin(),
    arguments.end(),
    [](const ua::Variant& value) { return value.is_structure() || value.is_array_of_structure(); });
  if (!hasStructuredArgument)
  {
    dispatch_call_method_async(
      mImpl, std::move(object), std::move(method), std::move(arguments), std::move(callback));
    return;
  }

  auto impl = mImpl;
  TypedAccess inspector{impl};
  inspector.inspect_method_inputs_async(method,
    [impl,
      object = std::move(object),
      method = std::move(method),
      arguments = std::move(arguments),
      callback = std::move(callback)](ua::Result<MethodInputMetadata> metadata) mutable
    {
      // The structured-argument check acts on the Method's declared inputs, so it uses a Good answer only.
      if (!metadata.is_good())
      {
        callback(ua::Result<ua::CallResult>{
          detail::answer_refused(metadata.status_code(), "ReadAnswerUncertain", callMethodSource)});
        return;
      }
      auto validation = validate_structured_method_arguments(arguments, metadata.value(), impl);
      if (validation.is_bad())
      {
        callback(ua::Result<ua::CallResult>{validation.status_code(), validation.shared_detail()});
        return;
      }
      dispatch_call_method_async(
        std::move(impl), std::move(object), std::move(method), std::move(arguments), std::move(callback));
    });
}

ua::CallResult TypedAccess::call_method_sync(
  ua::NodeId object, ua::NodeId method, std::vector<ua::Variant> arguments)
{
  return ua::detail::good_value(
    try_call_method_sync(std::move(object), std::move(method), std::move(arguments)));
}

ua::Result<ua::CallResult> TypedAccess::try_call_method_sync(
  ua::NodeId object, ua::NodeId method, std::vector<ua::Variant> arguments) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<ua::CallResult>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, object = std::move(object), method = std::move(method), arguments = std::move(arguments)](
      auto completion) mutable {
      call_method_async(std::move(object), std::move(method), std::move(arguments), std::move(completion));
    });
}

void TypedAccess::inspect_method_inputs_async(
  ua::NodeId method, std::function<void(ua::Result<MethodInputMetadata>)> callback) noexcept
{
  if (!mImpl)
  {
    callback(ua::Result<MethodInputMetadata>{emptyHandleStatus});
    return;
  }

  BrowseOptions propertyOptions;
  propertyOptions.referenceTypeId = ua::NodeId{ua::ReferenceTypeId::HasProperty};
  propertyOptions.includeSubtypes = false;

  BrowseOptions optionalOptions;
  optionalOptions.referenceTypeId = ua::NodeId{ua::ReferenceTypeId::HasOptionalInputArgumentDescription};
  optionalOptions.includeSubtypes = false;

  auto walk = std::make_shared<MethodInputsWalk>();
  walk->impl = mImpl;
  walk->callback = std::move(callback);
  walk->properties.emplace(browse(method, std::move(propertyOptions)));
  walk->optionals.emplace(browse(std::move(method), std::move(optionalOptions)));
  walk->collect_properties();
}

MethodInputMetadata TypedAccess::inspect_method_inputs_sync(ua::NodeId method)
{
  return ua::detail::good_value(try_inspect_method_inputs_sync(std::move(method)));
}

ua::Result<MethodInputMetadata> TypedAccess::try_inspect_method_inputs_sync(ua::NodeId method) noexcept
{
  return ua::async::detail::blocking_call<ua::Result<MethodInputMetadata>>(
    (mImpl ? mImpl->executor() : boost::asio::any_io_executor{}),
    [this, method = std::move(method)](auto completion) mutable
    { inspect_method_inputs_async(std::move(method), std::move(completion)); });
}

ua::VoidResult TypedAccess::wait_sync(const std::function<void(std::function<void()>)>& start) const noexcept
{
  return ua::async::detail::blocking_call<ua::VoidResult>(
    mImpl ? mImpl->executor() : boost::asio::any_io_executor{},
    [&start](std::function<void(ua::VoidResult)> complete)
    { start([complete = std::move(complete)]() { complete(ua::VoidResult{}); }); });
}

}  // namespace ua::client
