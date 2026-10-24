// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_to_string.h"

#include "ua_utilities.h"
#include "fmt/format.h"

namespace ua
{

std::string to_string(bool value)
{
  return value ? "true" : "false";
}

std::string to_string(int8_t value)
{
  return fmt::format("{}", numeric_cast<int>(value));
}

std::string to_string(uint8_t value)
{
  return fmt::format("{}", numeric_cast<int>(value));
}

std::string to_string(int16_t value)
{
  return fmt::format("{}", value);
}

std::string to_string(uint16_t value)
{
  return fmt::format("{}", value);
}

std::string to_string(int32_t value)
{
  return fmt::format("{}", value);
}

std::string to_string(uint32_t value)
{
  return fmt::format("{}", value);
}

std::string to_string(int64_t value)
{
  return fmt::format("{}", value);
}

std::string to_string(uint64_t value)
{
  return fmt::format("{}", value);
}

std::string to_string(float value)
{
  return fmt::format("{}", value);
}

std::string to_string(double value)
{
  return fmt::format("{}", value);
}

std::string to_string(const String& value)
{
  return std::string{static_cast<string_view>(value)};
}

std::string to_string(const DateTime& value)
{
  return value.as_iso_string();
}

std::string to_string(const Guid& value)
{
  return value.as_string();
}

std::string to_string(const ByteString& value)
{
  return utils::base64_encode(value);
}

std::string to_string(const XmlElement& value)
{
  return std::string{value.value()};
}

std::string to_string(const NodeId& value)
{
  return value.as_definition();
}

std::string to_string(const ExpandedNodeId& value)
{
  return value.as_definition();
}

std::string to_string(const StatusCode& value)
{
  return fmt::format("{} (0x{:08X})", to_string(value.as_status()), value.as_uint32());
}

std::string to_string(const QualifiedName& value)
{
  // OPC 10000-4 Annex A: `[<namespace-index>:]<name>`, with '&' before each reserved character of the
  // name, so QualifiedName::parse reads it back: {0, "2:Foo"} is "2&:Foo", {2, "Foo"} is "2:Foo".
  std::string text;
  if (value.namespace_index() != 0)
  {
    text = fmt::format("{}:", value.namespace_index());
  }
  for (const char c : static_cast<string_view>(value.name()))
  {
    if (c == '/' || c == '.' || c == '<' || c == '>' || c == ':' || c == '#' || c == '!' || c == '&')
    {
      text.push_back('&');
    }
    text.push_back(c);
  }
  return text;
}

std::string to_string(const LocalizedText& value)
{
  auto locale = static_cast<string_view>(value.locale());
  auto text = static_cast<string_view>(value.text());
  if (locale.empty())
  {
    return std::string{text};
  }
  return fmt::format("[{}]{}", locale, text);
}

namespace
{

std::string built_in_type_name(BuiltInTypeId id)
{
  return to_string(id);
}

template<typename T>
std::string scalar_to_string(const Variant& value)
{
  return fmt::format("{}({})", built_in_type_name(built_in_type<T>()), to_string(value.as<T>()));
}

template<typename T>
std::string array_to_string(const Variant& value)
{
  const auto& arr = value.as<Array<T>>();
  std::string result = fmt::format("Array<{}>[", built_in_type_name(built_in_type<T>()));
  const auto& payload = arr.payload();
  for (size_t i = 0; i < payload.size(); ++i)
  {
    if (i > 0)
    {
      result += ", ";
    }
    if constexpr (std::is_same_v<T, bool>)
    {
      result += to_string(static_cast<bool>(payload[i]));
    }
    else
    {
      result += to_string(payload[i]);
    }
  }
  result += "]";
  return result;
}

template<typename T>
std::string array_to_summary_string(const Variant& value)
{
  const auto& arr = value.as<Array<T>>();
  return fmt::format("Array<{}>[{} element{}]",
    built_in_type_name(built_in_type<T>()),
    arr.size(),
    arr.size() == 1 ? "" : "s");
}

std::string variant_scalar_to_string(const Variant& value)
{
  switch (value.get_built_in_type())
  {
  case BuiltInTypeId::Boolean:
    return scalar_to_string<bool>(value);
  case BuiltInTypeId::SByte:
    return scalar_to_string<int8_t>(value);
  case BuiltInTypeId::Byte:
    return scalar_to_string<uint8_t>(value);
  case BuiltInTypeId::Int16:
    return scalar_to_string<int16_t>(value);
  case BuiltInTypeId::UInt16:
    return scalar_to_string<uint16_t>(value);
  case BuiltInTypeId::Int32:
    return scalar_to_string<int32_t>(value);
  case BuiltInTypeId::UInt32:
    return scalar_to_string<uint32_t>(value);
  case BuiltInTypeId::Int64:
    return scalar_to_string<int64_t>(value);
  case BuiltInTypeId::UInt64:
    return scalar_to_string<uint64_t>(value);
  case BuiltInTypeId::Float:
    return scalar_to_string<float>(value);
  case BuiltInTypeId::Double:
    return scalar_to_string<double>(value);
  case BuiltInTypeId::String:
    return scalar_to_string<String>(value);
  case BuiltInTypeId::DateTime:
    return scalar_to_string<DateTime>(value);
  case BuiltInTypeId::Guid:
    return scalar_to_string<Guid>(value);
  case BuiltInTypeId::ByteString:
    return scalar_to_string<ByteString>(value);
  case BuiltInTypeId::XmlElement:
    return scalar_to_string<XmlElement>(value);
  case BuiltInTypeId::NodeId:
    return scalar_to_string<NodeId>(value);
  case BuiltInTypeId::ExpandedNodeId:
    return scalar_to_string<ExpandedNodeId>(value);
  case BuiltInTypeId::StatusCode:
    return scalar_to_string<StatusCode>(value);
  case BuiltInTypeId::QualifiedName:
    return scalar_to_string<QualifiedName>(value);
  case BuiltInTypeId::LocalizedText:
    return scalar_to_string<LocalizedText>(value);
  case BuiltInTypeId::ExtensionObject:
  {
    const auto& ref = value.as<RefStructure<Structure>>();
    return ref ? ref->to_string(0) : "ExtensionObject(null)";
  }
  case BuiltInTypeId::DataValue:
    return fmt::format("DataValue({})", to_string(value.as<DataValue>()));
  case BuiltInTypeId::Variant:
    return "Variant(...)";
  case BuiltInTypeId::DiagnosticInfo:
    return "DiagnosticInfo(...)";
  default:
    return "Unknown";
  }
}

using ArrayToStringFn = std::string (*)(const Variant&);

struct ArrayDispatchEntry
{
  BuiltInTypeId type;
  ArrayToStringFn toStringFn;
  ArrayToStringFn toSummaryFn;
};

template<typename T>
constexpr ArrayDispatchEntry make_array_entry()
{
  return {built_in_type<T>(), &array_to_string<T>, &array_to_summary_string<T>};
}

const ArrayDispatchEntry& find_array_dispatch(BuiltInTypeId type)
{
  static const ArrayDispatchEntry entries[] = {
    make_array_entry<bool>(),
    make_array_entry<int8_t>(),
    make_array_entry<uint8_t>(),
    make_array_entry<int16_t>(),
    make_array_entry<uint16_t>(),
    make_array_entry<int32_t>(),
    make_array_entry<uint32_t>(),
    make_array_entry<int64_t>(),
    make_array_entry<uint64_t>(),
    make_array_entry<float>(),
    make_array_entry<double>(),
    make_array_entry<String>(),
    make_array_entry<DateTime>(),
    make_array_entry<Guid>(),
    make_array_entry<ByteString>(),
    make_array_entry<XmlElement>(),
    make_array_entry<NodeId>(),
    make_array_entry<ExpandedNodeId>(),
    make_array_entry<StatusCode>(),
    make_array_entry<QualifiedName>(),
    make_array_entry<LocalizedText>(),
    make_array_entry<DataValue>(),
    make_array_entry<Variant>(),
    {BuiltInTypeId::ExtensionObject,
      [](const Variant& v) -> std::string
      {
        const auto& arr = v.as<Array<RefStructure<Structure>>>();
        std::string result = "Array<ExtensionObject>[";
        for (size_t i = 0; i < arr.size(); ++i)
        {
          if (i > 0)
          {
            result += ", ";
          }
          const auto& elem = arr.payload()[i];
          result += elem ? elem->to_string(0) : "null";
        }
        result += "]";
        return result;
      },
      [](const Variant& v) -> std::string
      {
        const auto& arr = v.as<Array<RefStructure<Structure>>>();
        return fmt::format("Array<ExtensionObject>[{} element{}]", arr.size(), arr.size() == 1 ? "" : "s");
      }},
  };

  for (const auto& entry : entries)
  {
    if (entry.type == type)
    {
      return entry;
    }
  }

  static const ArrayDispatchEntry fallback{BuiltInTypeId::Null, nullptr, nullptr};
  return fallback;
}

}  // namespace

std::string to_string(const Variant& value, int indent)
{
  if (value.empty())
  {
    return "Null";
  }
  if (value.is_scalar())
  {
    if (indent > 0 && value.get_built_in_type() == BuiltInTypeId::ExtensionObject)
    {
      const auto& ref = value.as<RefStructure<Structure>>();
      return ref ? ref->to_string(indent) : "ExtensionObject(null)";
    }
    if (indent > 0 && value.get_built_in_type() == BuiltInTypeId::DataValue)
    {
      return fmt::format("DataValue({})", to_string(value.as<DataValue>(), indent));
    }
    return variant_scalar_to_string(value);
  }
  if (indent > 0 && value.get_built_in_type() == BuiltInTypeId::ExtensionObject)
  {
    const auto& arr = value.as<Array<RefStructure<Structure>>>();
    return to_string(arr, indent);
  }
  const auto& dispatch = find_array_dispatch(value.get_built_in_type());
  if (dispatch.toStringFn)
  {
    return dispatch.toStringFn(value);
  }
  return fmt::format("Array<{}>[...]", to_string(value.get_built_in_type()));
}

std::string to_summary_string(const Variant& value)
{
  if (value.empty())
  {
    return "Null";
  }
  if (value.is_scalar())
  {
    return variant_scalar_to_string(value);
  }
  const auto& dispatch = find_array_dispatch(value.get_built_in_type());
  if (dispatch.toSummaryFn)
  {
    return dispatch.toSummaryFn(value);
  }
  return fmt::format("Array<{}>[...]", to_string(value.get_built_in_type()));
}

std::string to_string(const DataValue& value, int indent)
{
  if (indent > 0)
  {
    const std::string pad(numeric_cast<size_t>(indent), ' ');
    std::string fieldPad(numeric_cast<size_t>(indent + 2), ' ');
    std::string result = "{\n";
    bool first = true;

    auto append = [&](string_view name, const std::string& val)
    {
      if (!first)
      {
        result += ",\n";
      }
      result += fmt::format("{}{}={}", fieldPad, name, val);
      first = false;
    };

    if (!value.value().empty())
    {
      append("value", to_string(value.value(), indent + 2));
    }
    if (const auto& status = value.status())
    {
      append("status", to_string(*status));
    }
    if (const auto& sourceTimestamp = value.source_timestamp())
    {
      append("sourceTimestamp", to_string(*sourceTimestamp));
    }
    if (const auto& sourcePicoSeconds = value.source_pico_seconds())
    {
      append("sourcePicoSeconds", to_string(*sourcePicoSeconds));
    }
    if (const auto& serverTimestamp = value.server_timestamp())
    {
      append("serverTimestamp", to_string(*serverTimestamp));
    }
    if (const auto& serverPicoSeconds = value.server_pico_seconds())
    {
      append("serverPicoSeconds", to_string(*serverPicoSeconds));
    }

    if (first)
    {
      return "{}";
    }
    result += "\n";
    result += pad;
    result += "}";
    return result;
  }

  std::string result = "{";
  bool first = true;

  auto append = [&](string_view name, const std::string& val)
  {
    if (!first)
    {
      result += ", ";
    }
    result += fmt::format("{}={}", name, val);
    first = false;
  };

  if (!value.value().empty())
  {
    append("value", to_string(value.value()));
  }
  if (const auto& status = value.status())
  {
    append("status", to_string(*status));
  }
  if (const auto& sourceTimestamp = value.source_timestamp())
  {
    append("sourceTimestamp", to_string(*sourceTimestamp));
  }
  if (const auto& sourcePicoSeconds = value.source_pico_seconds())
  {
    append("sourcePicoSeconds", to_string(*sourcePicoSeconds));
  }
  if (const auto& serverTimestamp = value.server_timestamp())
  {
    append("serverTimestamp", to_string(*serverTimestamp));
  }
  if (const auto& serverPicoSeconds = value.server_pico_seconds())
  {
    append("serverPicoSeconds", to_string(*serverPicoSeconds));
  }

  result += "}";
  return result;
}

std::string to_summary_string(const DataValue& value)
{
  std::string result = "{";
  bool first = true;

  auto append = [&](string_view name, const std::string& val)
  {
    if (!first)
    {
      result += ", ";
    }
    result += fmt::format("{}={}", name, val);
    first = false;
  };

  if (!value.value().empty())
  {
    append("value", to_summary_string(value.value()));
  }
  if (const auto& status = value.status())
  {
    append("status", to_string(*status));
  }
  if (value.source_timestamp().has_value())
  {
    append("sourceTimestamp", "...");
  }
  if (value.source_pico_seconds().has_value())
  {
    append("sourcePicoSeconds", "...");
  }
  if (value.server_timestamp().has_value())
  {
    append("serverTimestamp", "...");
  }
  if (value.server_pico_seconds().has_value())
  {
    append("serverPicoSeconds", "...");
  }

  result += "}";
  return result;
}

std::string to_string(const DiagnosticInfo& value, int indent)
{
  if (indent > 0)
  {
    const std::string pad(numeric_cast<size_t>(indent), ' ');
    std::string fieldPad(numeric_cast<size_t>(indent + 2), ' ');
    std::string result = "{\n";
    bool first = true;

    auto append = [&](string_view name, const std::string& val)
    {
      if (!first)
      {
        result += ",\n";
      }
      result += fmt::format("{}{}={}", fieldPad, name, val);
      first = false;
    };

    if (const auto& symbolicId = value.symbolic_id())
    {
      append("symbolicId", to_string(*symbolicId));
    }
    if (const auto& namespaceUri = value.namespace_uri())
    {
      append("namespaceUri", to_string(*namespaceUri));
    }
    if (const auto& locale = value.locale())
    {
      append("locale", to_string(*locale));
    }
    if (const auto& localizedText = value.localized_text())
    {
      append("localizedText", to_string(*localizedText));
    }
    if (const auto& additionalInfo = value.additional_info())
    {
      append("additionalInfo", *additionalInfo);
    }
    if (const auto& innerStatusCode = value.inner_status_code())
    {
      append("innerStatus", to_string(*innerStatusCode));
    }
    if (value.inner_diagnostic_info())
    {
      append("innerDiagnosticInfo", to_string(*value.inner_diagnostic_info(), indent + 2));
    }

    if (first)
    {
      return "{}";
    }
    result += "\n";
    result += pad;
    result += "}";
    return result;
  }

  std::string result = "{";
  bool first = true;

  auto append = [&](string_view name, const std::string& val)
  {
    if (!first)
    {
      result += ", ";
    }
    result += fmt::format("{}={}", name, val);
    first = false;
  };

  if (const auto& symbolicId = value.symbolic_id())
  {
    append("symbolicId", to_string(*symbolicId));
  }
  if (const auto& namespaceUri = value.namespace_uri())
  {
    append("namespaceUri", to_string(*namespaceUri));
  }
  if (const auto& locale = value.locale())
  {
    append("locale", to_string(*locale));
  }
  if (const auto& localizedText = value.localized_text())
  {
    append("localizedText", to_string(*localizedText));
  }
  if (const auto& additionalInfo = value.additional_info())
  {
    append("additionalInfo", *additionalInfo);
  }
  if (const auto& innerStatusCode = value.inner_status_code())
  {
    append("innerStatus", to_string(*innerStatusCode));
  }
  if (value.inner_diagnostic_info())
  {
    append("innerDiagnosticInfo", to_string(*value.inner_diagnostic_info()));
  }

  result += "}";
  return result;
}

std::string to_summary_string(const DiagnosticInfo& value)
{
  std::string result = "{";
  bool first = true;

  auto append = [&](string_view name)
  {
    if (!first)
    {
      result += ", ";
    }
    result += fmt::format("{}=...", name);
    first = false;
  };

  if (value.symbolic_id().has_value())
  {
    append("symbolicId");
  }
  if (value.namespace_uri().has_value())
  {
    append("namespaceUri");
  }
  if (value.locale().has_value())
  {
    append("locale");
  }
  if (value.localized_text().has_value())
  {
    append("localizedText");
  }
  if (value.additional_info().has_value())
  {
    append("additionalInfo");
  }
  if (value.inner_status_code().has_value())
  {
    append("innerStatus");
  }
  if (value.inner_diagnostic_info())
  {
    append("innerDiagnosticInfo");
  }

  result += "}";
  return result;
}

std::string to_string(const Decimal& value)
{
  return fmt::format("Decimal(scale={}, value={})", value.scale(), to_string(value.value()));
}

std::string to_string(BuiltInTypeId value)
{
  switch (value)
  {
  case BuiltInTypeId::Null:
    return "Null";
  case BuiltInTypeId::Boolean:
    return "Boolean";
  case BuiltInTypeId::SByte:
    return "SByte";
  case BuiltInTypeId::Byte:
    return "Byte";
  case BuiltInTypeId::Int16:
    return "Int16";
  case BuiltInTypeId::UInt16:
    return "UInt16";
  case BuiltInTypeId::Int32:
    return "Int32";
  case BuiltInTypeId::UInt32:
    return "UInt32";
  case BuiltInTypeId::Int64:
    return "Int64";
  case BuiltInTypeId::UInt64:
    return "UInt64";
  case BuiltInTypeId::Float:
    return "Float";
  case BuiltInTypeId::Double:
    return "Double";
  case BuiltInTypeId::String:
    return "String";
  case BuiltInTypeId::DateTime:
    return "DateTime";
  case BuiltInTypeId::Guid:
    return "Guid";
  case BuiltInTypeId::ByteString:
    return "ByteString";
  case BuiltInTypeId::XmlElement:
    return "XmlElement";
  case BuiltInTypeId::NodeId:
    return "NodeId";
  case BuiltInTypeId::ExpandedNodeId:
    return "ExpandedNodeId";
  case BuiltInTypeId::StatusCode:
    return "StatusCode";
  case BuiltInTypeId::QualifiedName:
    return "QualifiedName";
  case BuiltInTypeId::LocalizedText:
    return "LocalizedText";
  case BuiltInTypeId::ExtensionObject:
    return "ExtensionObject";
  case BuiltInTypeId::DataValue:
    return "DataValue";
  case BuiltInTypeId::Variant:
    return "Variant";
  case BuiltInTypeId::DiagnosticInfo:
    return "DiagnosticInfo";
  default:
    return fmt::format("Unknown({})", utils::to_underlying(value));
  }
}

std::string to_string(AttributeId value)
{
  switch (value)
  {
  case AttributeId::NodeId:
    return "NodeId";
  case AttributeId::NodeClass:
    return "NodeClass";
  case AttributeId::BrowseName:
    return "BrowseName";
  case AttributeId::DisplayName:
    return "DisplayName";
  case AttributeId::Description:
    return "Description";
  case AttributeId::WriteMask:
    return "WriteMask";
  case AttributeId::UserWriteMask:
    return "UserWriteMask";
  case AttributeId::IsAbstract:
    return "IsAbstract";
  case AttributeId::Symmetric:
    return "Symmetric";
  case AttributeId::InverseName:
    return "InverseName";
  case AttributeId::ContainsNoLoops:
    return "ContainsNoLoops";
  case AttributeId::EventNotifier:
    return "EventNotifier";
  case AttributeId::Value:
    return "Value";
  case AttributeId::DataType:
    return "DataType";
  case AttributeId::ValueRank:
    return "ValueRank";
  case AttributeId::ArrayDimensions:
    return "ArrayDimensions";
  case AttributeId::AccessLevel:
    return "AccessLevel";
  case AttributeId::UserAccessLevel:
    return "UserAccessLevel";
  case AttributeId::MinimumSamplingInterval:
    return "MinimumSamplingInterval";
  case AttributeId::Historizing:
    return "Historizing";
  case AttributeId::Executable:
    return "Executable";
  case AttributeId::UserExecutable:
    return "UserExecutable";
  case AttributeId::DataTypeDefinition:
    return "DataTypeDefinition";
  case AttributeId::RolePermissions:
    return "RolePermissions";
  case AttributeId::UserRolePermissions:
    return "UserRolePermissions";
  case AttributeId::AccessRestrictions:
    return "AccessRestrictions";
  case AttributeId::AccessLevelEx:
    return "AccessLevelEx";
  default:
    return fmt::format("Unknown({})", utils::to_underlying(value));
  }
}

}  // namespace ua
