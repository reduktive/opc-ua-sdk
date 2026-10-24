// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The OPC UA `NodeId` built-in type and its identifier value.
/// @ingroup core_types

#ifndef UA_NODE_ID_H
#define UA_NODE_ID_H

#include <compare>
#include <variant>
#include "ua_built_in_types_fwd_decl.h"
#include "ua_result.h"
#include "ua_byte_string.h"
#include "ua_includes.h"
#include "ua_guid.h"
#include "ua_string.h"
#include "ua_object_id.h"
#include "ua_objecttype_id.h"
#include "ua_referencetype_id.h"
#include "ua_method_id.h"
#include "ua_variable_id.h"
#include "ua_variabletype_id.h"
#include "ua_id_type.h"

namespace ua
{

/// An OPC UA node identifier (OPC 10000-6 5.2.2.9).
///
/// Identifies a node within an OPC UA address space. A NodeId pairs a namespace
/// index with an @ref Identifier whose value is one of four OPC UA identifier
/// types: numeric, string, GUID, or opaque (ByteString). The numerous typed
/// constructors accept the generated NS0 identifier enums (@ref ObjectId,
/// @ref VariableId, etc.) as a convenience for referring to standard nodes.
///
/// This is a plain value type: copyable, movable, comparable, and hashable. It
/// holds no external resources and is not tied to any thread or strand.
/// @ingroup core_types
class NodeId
{
public:
  /// The identifier portion of a @ref NodeId - a numeric, string, GUID, or opaque value.
  ///
  /// Holds exactly one of the four OPC UA identifier types at a time. Use
  /// @ref type or the `is_*` predicates to discover which is held, then the
  /// matching `get_*` accessor to read it; calling the wrong accessor throws.
  class Identifier
  {
  public:
    /// Constructs a numeric identifier holding the value 0.
    Identifier();

    /// Copy-constructs from another identifier, preserving its held type and value.
    Identifier(const Identifier&) = default;

    /// Move-constructs from another identifier; the source is left in a valid but
    /// unspecified state.
    Identifier(Identifier&&) noexcept = default;

    /// Constructs a numeric identifier from @p identifier.
    ///
    /// @param identifier The numeric value to hold.
    explicit Identifier(uint32_t identifier);

    /// Constructs a numeric identifier from a standard NS0 @ref DataTypeId.
    explicit Identifier(DataTypeId);

    /// Constructs a numeric identifier from a standard NS0 @ref ObjectTypeId.
    explicit Identifier(ObjectTypeId);

    /// Constructs a numeric identifier from a standard NS0 @ref ObjectId.
    explicit Identifier(ObjectId);

    /// Constructs a numeric identifier from a standard NS0 @ref VariableTypeId.
    explicit Identifier(VariableTypeId);

    /// Constructs a numeric identifier from a standard NS0 @ref VariableId.
    explicit Identifier(VariableId);

    /// Constructs a numeric identifier from a standard NS0 @ref ReferenceTypeId.
    explicit Identifier(ReferenceTypeId);

    /// Constructs a numeric identifier from a standard NS0 @ref MethodId.
    explicit Identifier(MethodId);

    /// Constructs a string identifier holding a copy of @p identifier.
    ///
    /// @param identifier The string value to copy.
    explicit Identifier(string_view identifier);

    /// Constructs a GUID identifier holding a copy of @p identifier.
    ///
    /// @param identifier The GUID value to copy.
    explicit Identifier(const Guid& identifier);

    /// Constructs a GUID identifier, moving from @p identifier.
    ///
    /// @param identifier The GUID value to move from.
    explicit Identifier(Guid&& identifier);

    /// Constructs an opaque identifier holding a copy of @p identifier.
    ///
    /// @param identifier The opaque (ByteString) value to copy.
    explicit Identifier(const ByteString& identifier);

    /// Constructs an opaque identifier, taking ownership of @p identifier.
    ///
    /// @param identifier Owning pointer to the ByteString value; must not be null.
    explicit Identifier(unique_ptr<ByteString> identifier);

    /// Copy-assigns from another identifier, replacing the held type and value.
    ///
    /// @return A reference to this identifier.
    Identifier& operator=(const Identifier&) = default;

    /// Move-assigns from another identifier; the source is left in a valid but
    /// unspecified state.
    ///
    /// @return A reference to this identifier.
    Identifier& operator=(Identifier&&) noexcept = default;

    /// Destroys the identifier, releasing any held value.
    ~Identifier() = default;

    /// Assigns a numeric value, replacing any previously held identifier.
    ///
    /// @param value The numeric value to assign.
    /// @return A reference to this identifier.
    Identifier& operator=(uint32_t value);

    /// Assigns a string value, replacing any previously held identifier.
    ///
    /// @param value The string value to assign.
    /// @return A reference to this identifier.
    Identifier& operator=(string_view value);

    /// Assigns a GUID value, replacing any previously held identifier.
    ///
    /// @param value The GUID value to assign.
    /// @return A reference to this identifier.
    Identifier& operator=(const Guid& value);

    /// Assigns a GUID value by move, replacing any previously held identifier.
    ///
    /// @param value The GUID value to move-assign.
    /// @return A reference to this identifier.
    Identifier& operator=(Guid&& value);

    /// Assigns an opaque value, replacing any previously held identifier.
    ///
    /// @param value The opaque (ByteString) value to assign.
    /// @return A reference to this identifier.
    Identifier& operator=(const ByteString& value);

    /// Assigns an opaque value by taking ownership, replacing any previously held identifier.
    ///
    /// @param value Owning pointer to the ByteString value; must not be null.
    /// @return A reference to this identifier.
    Identifier& operator=(unique_ptr<ByteString> value);

    /// Compares two identifiers for equality.
    ///
    /// Identifiers are equal only when they hold the same identifier type and an
    /// equal value of that type.
    ///
    /// @param obj The identifier to compare against.
    /// @return true if the identifiers are equal, false otherwise.
    bool operator==(const Identifier& obj) const;

    /// Orders two identifiers, first by identifier type then by value.
    ///
    /// Identifier types order in their @ref IdType enumeration order (numeric,
    /// string, GUID, opaque); within a type, values compare naturally.
    ///
    /// @param other The identifier to compare against.
    /// @return The ordering of this identifier relative to @p other.
    std::strong_ordering operator<=>(const Identifier& other) const;

    // These five are the most-executed functions in a server: a Read compares, hashes and copies a
    // NodeId several times per operation, and each of those asks which alternative is held. They are
    // defined here rather than in the .cpp so a caller in another translation unit can inline them -
    // out of line, `type()` cost a call that made up to four more, and it measured 5.7% of a server's
    // CPU on its own. `mValue`'s alternatives are declared in IdType order, which the ordering
    // contract on operator<=> already relies on, so the variant's index IS the type.

    /// Returns whether this identifier holds a numeric value.
    ///
    /// @return true if a numeric value is held, false otherwise.
    bool is_numeric() const
    {
      return mValue.index() == static_cast<std::size_t>(IdType::Numeric);
    }

    /// Returns whether this identifier holds a string value.
    ///
    /// @return true if a string value is held, false otherwise.
    bool is_string() const
    {
      return mValue.index() == static_cast<std::size_t>(IdType::String);
    }

    /// Returns whether this identifier holds a GUID value.
    ///
    /// @return true if a GUID value is held, false otherwise.
    bool is_guid() const
    {
      return mValue.index() == static_cast<std::size_t>(IdType::Guid);
    }

    /// Returns whether this identifier holds an opaque (ByteString) value.
    ///
    /// @return true if an opaque (ByteString) value is held, false otherwise.
    bool is_opaque() const
    {
      return mValue.index() == static_cast<std::size_t>(IdType::Opaque);
    }

    /// Returns the @ref IdType discriminating which value is held.
    ///
    /// @return The @ref IdType of the held value.
    IdType type() const
    {
      return static_cast<IdType>(mValue.index());
    }

    /// Returns the held numeric value.
    ///
    /// @return The numeric identifier.
    /// @throws UaException with @ref Status::BadInvalidState if the held value is
    ///         not numeric.
    uint32_t get_numeric() const
    {
      // get_if rather than std::get: the throwing form obliged this to carry a try/catch, which kept
      // the common case - a numeric id, which is nearly all of them - from being a load and a branch.
      if (const auto* numeric = std::get_if<uint32_t>(&mValue))
      {
        return *numeric;
      }
      throw_not_numeric();
    }

    /// Returns a reference to the held string value.
    ///
    /// The reference is valid until this identifier is reassigned or destroyed.
    ///
    /// @return The string identifier.
    /// @throws UaException with @ref Status::BadInvalidState if the held value is
    ///         not a string.
    const String& get_string() const;

    /// Returns a reference to the held GUID value.
    ///
    /// The reference is valid until this identifier is reassigned or destroyed.
    ///
    /// @return The GUID identifier.
    /// @throws UaException with @ref Status::BadInvalidState if the held value is
    ///         not a GUID.
    const Guid& get_guid() const;

    /// Returns a reference to the held opaque (ByteString) value.
    ///
    /// The reference is valid until this identifier is reassigned or destroyed.
    ///
    /// @return The opaque identifier.
    /// @throws UaException with @ref Status::BadInvalidState if the held value is
    ///         not opaque.
    const ByteString& get_opaque() const;

    /// Returns a hash of the identifier's type and value.
    ///
    /// @return The hash of the identifier's type and value.
    /// @see std::hash<ua::NodeId::Identifier>
    size_t hash() const;

  private:
    /// Reports a numeric read of a non-numeric identifier. Out of line and never returns, so the
    /// accessor above inlines to a load and a branch.
    [[noreturn]] void throw_not_numeric() const;

    // ByteString is held BY VALUE, not behind a unique_ptr. String is the widest alternative
    // either way, so the pointer bought no space (the variant is 40 bytes with or without it) and
    // cost a heap allocation on every copy of an opaque id - plus, because unique_ptr is not
    // copyable, a hand-written copy for ALL four alternatives. By value the variant copies itself.
    using Value = std::variant<uint32_t, String, Guid, ByteString>;

    Value mValue;

  };

  /// Constructs a null NodeId in namespace 0 (numeric identifier 0).
  NodeId() = default;

  /// Constructs a numeric NodeId in namespace 0.
  ///
  /// @param identifier The numeric identifier value.
  explicit NodeId(uint32_t identifier);

  /// Constructs a numeric NodeId in the given namespace.
  ///
  /// @param namespaceIndex The namespace index in which the node resides.
  /// @param identifier The numeric identifier value.
  NodeId(uint16_t namespaceIndex, uint32_t identifier);

  /// Constructs a numeric NodeId in namespace 0 from a standard NS0 @ref DataTypeId.
  explicit NodeId(DataTypeId);

  /// Constructs a numeric NodeId in the given namespace from a @ref DataTypeId.
  ///
  /// @param namespaceIndex The namespace index in which the node resides.
  /// @param identifier The standard NS0 @ref DataTypeId whose numeric value becomes the identifier.
  NodeId(uint16_t namespaceIndex, DataTypeId identifier);

  /// Constructs a numeric NodeId in namespace 0 from a standard NS0 @ref ObjectTypeId.
  explicit NodeId(ObjectTypeId);

  /// Constructs a numeric NodeId in the given namespace from an @ref ObjectTypeId.
  ///
  /// @param namespaceIndex The namespace index in which the node resides.
  /// @param identifier The standard NS0 @ref ObjectTypeId whose numeric value becomes the identifier.
  NodeId(uint16_t namespaceIndex, ObjectTypeId identifier);

  /// Constructs a numeric NodeId in namespace 0 from a standard NS0 @ref ObjectId.
  explicit NodeId(ObjectId);

  /// Constructs a numeric NodeId in the given namespace from an @ref ObjectId.
  ///
  /// @param namespaceIndex The namespace index in which the node resides.
  /// @param identifier The standard NS0 @ref ObjectId whose numeric value becomes the identifier.
  NodeId(uint16_t namespaceIndex, ObjectId identifier);

  /// Constructs a numeric NodeId in namespace 0 from a standard NS0 @ref VariableTypeId.
  explicit NodeId(VariableTypeId);

  /// Constructs a numeric NodeId in the given namespace from a @ref VariableTypeId.
  ///
  /// @param namespaceIndex The namespace index in which the node resides.
  /// @param identifier The standard NS0 @ref VariableTypeId whose numeric value becomes the identifier.
  NodeId(uint16_t namespaceIndex, VariableTypeId identifier);

  /// Constructs a numeric NodeId in namespace 0 from a standard NS0 @ref VariableId.
  explicit NodeId(VariableId);

  /// Constructs a numeric NodeId in the given namespace from a @ref VariableId.
  ///
  /// @param namespaceIndex The namespace index in which the node resides.
  /// @param identifier The standard NS0 @ref VariableId whose numeric value becomes the identifier.
  NodeId(uint16_t namespaceIndex, VariableId identifier);

  /// Constructs a numeric NodeId in namespace 0 from a standard NS0 @ref ReferenceTypeId.
  explicit NodeId(ReferenceTypeId);

  /// Constructs a numeric NodeId in the given namespace from a @ref ReferenceTypeId.
  ///
  /// @param namespaceIndex The namespace index in which the node resides.
  /// @param identifier The standard NS0 @ref ReferenceTypeId whose numeric value becomes the identifier.
  NodeId(uint16_t namespaceIndex, ReferenceTypeId identifier);

  /// Constructs a numeric NodeId in namespace 0 from a standard NS0 @ref MethodId.
  explicit NodeId(MethodId);

  /// Constructs a numeric NodeId in the given namespace from a @ref MethodId.
  ///
  /// @param namespaceIndex The namespace index in which the node resides.
  /// @param identifier The standard NS0 @ref MethodId whose numeric value becomes the identifier.
  NodeId(uint16_t namespaceIndex, MethodId identifier);

  /// Removed (API-7.3): it read like a parser but made a namespace-0 string id from any text, so
  /// `NodeId{"ns=2;s=Foo"}` named a different node. Write `NodeId{0, "x"}` for a namespace-0 string id
  /// and @ref parse for text. Deleted rather than absent, so a call does not convert silently to another
  /// constructor.
  explicit NodeId(string_view identifier) = delete;
  explicit NodeId(const char* identifier) = delete;

  /// Constructs a string NodeId in the given namespace holding a copy of @p identifier.
  ///
  /// @param namespaceIndex The namespace index in which the node resides.
  /// @param identifier The string identifier value to copy.
  NodeId(uint16_t namespaceIndex, string_view identifier);

  /// Constructs a GUID NodeId in namespace 0 holding a copy of @p identifier.
  ///
  /// @param identifier The GUID identifier value to copy.
  explicit NodeId(const Guid& identifier);

  /// Constructs a GUID NodeId in the given namespace holding a copy of @p identifier.
  ///
  /// @param namespaceIndex The namespace index in which the node resides.
  /// @param identifier The GUID identifier value to copy.
  NodeId(uint16_t namespaceIndex, const Guid& identifier);

  /// Constructs an opaque NodeId in namespace 0 holding a copy of @p identifier.
  ///
  /// @param identifier The opaque (ByteString) identifier value to copy.
  explicit NodeId(const ByteString& identifier);

  /// Constructs an opaque NodeId in the given namespace holding a copy of @p identifier.
  ///
  /// @param namespaceIndex The namespace index in which the node resides.
  /// @param identifier The opaque (ByteString) identifier value to copy.
  NodeId(uint16_t namespaceIndex, const ByteString& identifier);

  /// Copy-constructs a NodeId, preserving its namespace and identifier.
  ///
  /// @param obj The NodeId to copy.
  NodeId(const NodeId& obj);

  /// Move-constructs a NodeId; the source is left in a valid but unspecified state.
  ///
  /// @param obj The NodeId to move from.
  NodeId(NodeId&& obj) noexcept = default;

  /// Constructs a NodeId from a local, index-based @ref ExpandedNodeId.
  ///
  /// @param obj Source ExpandedNodeId; copied into this NodeId.
  /// @throws UaException with @ref Status::BadInvalidArgument if @p obj is
  ///         URI-based (namespace given as a URI rather than an index) or refers
  ///         to a remote server, neither of which a plain NodeId can represent.
  NodeId(const ExpandedNodeId& obj);

  /// Constructs a NodeId by moving from a local, index-based @ref ExpandedNodeId.
  ///
  /// @param obj Source ExpandedNodeId; its identifier is moved into this NodeId.
  /// @throws UaException with @ref Status::BadInvalidArgument if @p obj is
  ///         URI-based or refers to a remote server.
  NodeId(ExpandedNodeId&& obj);

  /// Copy-assigns a NodeId, replacing the namespace and identifier.
  ///
  /// @param other The NodeId to copy-assign from.
  /// @return A reference to this NodeId.
  NodeId& operator=(const NodeId& other);

  /// Move-assigns a NodeId; the source is left in a valid but unspecified state.
  ///
  /// @param other The NodeId to move-assign from.
  /// @return A reference to this NodeId.
  NodeId& operator=(NodeId&& other) noexcept = default;

  /// Destroys the NodeId, releasing its identifier value.
  ~NodeId() = default;

  /// Compares two NodeIds for equality.
  ///
  /// Two NodeIds are equal when they share the same namespace index and an equal
  /// @ref Identifier.
  ///
  /// @param obj The NodeId to compare against.
  /// @return true if the NodeIds are equal, false otherwise.
  bool operator==(const NodeId& obj) const;

  /// Orders two NodeIds, first by namespace index then by @ref Identifier.
  ///
  /// @param other The NodeId to compare against.
  /// @return The ordering of this NodeId relative to @p other.
  std::strong_ordering operator<=>(const NodeId& other) const;

  /// Returns the @ref IdType of the identifier (numeric, string, GUID, or opaque).
  ///
  /// @return The @ref IdType of the identifier.
  IdType id_type() const;

  /// Returns whether this is the null NodeId.
  ///
  /// The null NodeId lives at NamespaceIndex 0 (OPC 10000-3 section 8.2.4, Table 23): the
  /// canonical null (IdType Numeric, NamespaceIndex 0, Identifier 0) and every
  /// alternative null value (null/empty String, all-zero GUID, null/empty Opaque)
  /// are defined "at NamespaceIndex 0". A NodeId in any other namespace with an
  /// otherwise-null identifier (e.g. ns=1,i=0) is an ordinary reference to that
  /// namespace, not the null NodeId. Identifier null values per OPC 10000-6 section 5.2.2.9.
  ///
  /// @return true if this is the null NodeId, false otherwise.
  bool is_null() const;

  /// Returns whether the identifier satisfies the structural NodeId rules.
  ///
  /// Numeric and GUID identifiers are always structurally valid. String identifiers must
  /// contain canonical UTF-8 and no more than 4096 Unicode characters; Opaque identifiers may
  /// contain no more than 4096 bytes. Null NodeIds are structurally valid; services define any
  /// special null handling separately.
  ///
  /// @return true if the identifier is structurally valid, false otherwise.
  bool is_structurally_valid() const noexcept;

  /// Returns whether the identifier holds a numeric value.
  ///
  /// @return true if the identifier holds a numeric value, false otherwise.
  bool is_numeric() const;

  /// Returns whether the identifier holds a string value.
  ///
  /// @return true if the identifier holds a string value, false otherwise.
  bool is_string() const;

  /// Returns whether the identifier holds a GUID value.
  ///
  /// @return true if the identifier holds a GUID value, false otherwise.
  bool is_guid() const;

  /// Returns whether the identifier holds an opaque (ByteString) value.
  ///
  /// @return true if the identifier holds an opaque (ByteString) value, false otherwise.
  bool is_opaque() const;

  /// Returns the namespace index.
  ///
  /// @return The namespace index.
  uint16_t namespace_index() const;

  /// Returns a mutable reference to the namespace index for in-place modification.
  ///
  /// @return A mutable reference to the namespace index.
  uint16_t& namespace_index();

  /// Returns a reference to the @ref Identifier.
  ///
  /// The reference is valid until this NodeId is reassigned or destroyed.
  ///
  /// @return A reference to the @ref Identifier.
  const Identifier& identifier() const;

  /// Returns a mutable reference to the @ref Identifier for in-place modification.
  ///
  /// The reference is valid until this NodeId is reassigned or destroyed.
  ///
  /// @return A mutable reference to the @ref Identifier.
  Identifier& identifier();

  /// Parses the text @ref ua::to_string writes for a NodeId (OPC 10000-6 5.3.1.10): an optional
  /// `ns=<index>;` prefix, never used for namespace 0, followed by exactly one identifier token -
  /// `i=<numeric>`, `s=<string>`, `g=<guid>` or `b=<base64>`. `parse(to_string(id)) == id` for every
  /// NodeId.
  ///
  /// @param text The textual NodeId.
  /// @return The NodeId @p text names.
  /// @throws UaException with @ref Status::BadDecodingError if @p text is not that form.
  /// @see try_parse, as_definition
  static NodeId parse(string_view text);

  /// Parses like @ref parse and reports a malformed text as a bad result instead of throwing.
  ///
  /// @param text The textual NodeId.
  /// @return The NodeId, or Bad_DecodingError with an @ref ErrorDetail naming the fault.
  [[nodiscard]] static NodeIdResult try_parse(string_view text) noexcept;

  /// Returns the OPC UA textual representation of this NodeId.
  ///
  /// Emits the form @ref parse reads - an `ns=<index>;` prefix
  /// (omitted for namespace 0) followed by the identifier token (`i=`, `s=`,
  /// `g=`, or `b=<base64>`).
  ///
  /// @return The textual NodeId definition.
  /// @throws UaException with @ref Status::BadNodeIdInvalid if the identifier
  ///         holds an unknown type.
  /// @see parse
  std::string as_definition() const;

  /// Resets this NodeId to the null NodeId in namespace 0.
  void clear();

  /// Returns a hash combining the namespace index and identifier.
  ///
  /// @return The hash of the namespace index and identifier.
  /// @see std::hash<ua::NodeId>
  size_t hash() const;

  /// Returns the OPC UA built-in type id for NodeId.
  ///
  /// @return The @ref BuiltInTypeId for NodeId.
  static BuiltInTypeId built_in_type_id();

private:
  friend class ExpandedNodeId;

  /// The parser behind @ref parse. @p namespaceIndexAllowed is false for the NodeId part of an
  /// ExpandedNodeId that names its namespace by URI, where an `ns=` prefix would contradict it.
  static NodeId parse_definition(string_view text, bool namespaceIndexAllowed);
  void assign_definition(string_view definition, bool namespaceIndexAllowed);

  uint16_t mNamespaceIndex{0};
  Identifier mIdentifier;
};

/// Maps `NodeId` to the OPC UA type name "NodeId".
///
/// @return The OPC UA type name "NodeId".
template<>
inline string_view get_typename<NodeId>()
{
  return "NodeId";
}

}  // namespace ua

namespace std
{

/// `std::hash` specialization enabling @ref ua::NodeId as an unordered-container key.
template<>
struct hash<ua::NodeId>
{
  /// Returns @ref ua::NodeId::hash for @p obj.
  ///
  /// @param obj The NodeId to hash.
  /// @return The hash value of @p obj.
  size_t operator()(const ua::NodeId& obj) const
  {
    return obj.hash();
  }
};

/// `std::hash` specialization enabling @ref ua::NodeId::Identifier as an unordered-container key.
template<>
struct hash<ua::NodeId::Identifier>
{
  /// Returns @ref ua::NodeId::Identifier::hash for @p obj.
  ///
  /// @param obj The identifier to hash.
  /// @return The hash value of @p obj.
  size_t operator()(const ua::NodeId::Identifier& obj) const
  {
    return obj.hash();
  }
};

}  // namespace std

#endif  // !UA_NODE_ID_H
