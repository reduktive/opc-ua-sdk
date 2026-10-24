// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_XML_PARSER_H
#define UA_XML_PARSER_H

#include <string>
#include "ua_includes.h"
#include "ua_built_in_types_fwd_decl.h"
#include "ua_status_code.h"

namespace ua
{

namespace xml
{

// The XML backend (rapidxml) is confined to the implementation TUs. The node/attribute handles
// below are opaque, non-owning pointers into the parsed document arena (owned by the `Context`);
// the `Context` owns the document via a handle whose deleter is bound in the implementation. They
// are distinct, incomplete types - defined nowhere in this header - so a node handle cannot be
// silently confused with an attribute handle, and no XML-library type (nor `void*`, nor
// `std::any`) appears in this public header. The backend can be swapped without touching any
// customer-visible ABI.
namespace detail
{
struct NodeHandle;
struct AttributeHandle;
struct DocumentHandle;
}  // namespace detail

class Attribute
{
private:
  detail::AttributeHandle* mHandle;

public:
  explicit Attribute(detail::AttributeHandle* handle);

  detail::AttributeHandle* handle() const
  {
    return mHandle;
  }

  string_view get_value() const;

  string_view get_name() const;

  optional<Attribute> get_next() const;

  optional<Attribute> get_next(string_view nextAttributeName) const;
};

class Element
{
private:
  detail::NodeHandle* mHandle;

public:
  explicit Element(detail::NodeHandle* handle);

  detail::NodeHandle* handle() const
  {
    return mHandle;
  }

  string_view get_name() const;

  string_view get_value() const;

  optional<Element> get_first_child() const;

  optional<Element> get_first_child(string_view childName) const;

  optional<Element> get_parent() const;

  optional<Element> get_next() const;

  optional<Element> get_next(string_view nextElementName) const;

  optional<string_view> get_first_attribute_value(string_view attributeName) const;

  optional<Attribute> get_first_attribute() const;

  optional<Attribute> get_first_attribute(string_view attributeName) const;

  size_t get_number_of_children() const;

  size_t get_number_of_children(string_view name) const;
};

class Context
{
private:
  // Owns the parsed document. The held type is incomplete here; its deleter is bound in the
  // implementation, so no XML-library type leaks into this header.
  shared_ptr<detail::DocumentHandle> mXmlDocument;

public:
  Context() = delete;
  Context(const Context&) = delete;
  Context(Context&& other) noexcept;
  Context& operator=(const Context& other) = delete;
  Context& operator=(Context&& other) noexcept;
  ~Context() = default;

  explicit Context(shared_ptr<detail::DocumentHandle> document);

  Element xml_element() const;
};

/// The element-nesting depth `parse(const char*)` admits. The backing parser recurses once per open
/// element, so an unbounded document is a stack overflow the process cannot catch; every parse is
/// bounded, and callers that decode nested values pass the bound their own limits imply.
inline constexpr std::size_t defaultMaxXmlElementDepth = 256;

// Parses a NUL-terminated XML buffer non-destructively: rapidxml neither writes string terminators
// nor expands entities in place, so the buffer is never modified and may live in read-only storage
// (e.g. the `const` NS0 `.rodata` array). The returned `Context` owns the parse arena; node/attribute
// string_views borrow either from @p input directly or, for entity-bearing values, from that arena.
// A document whose element nesting exceeds @p maxElementDepth is refused with Bad_EncodingLimitsExceeded
// BEFORE the parser recurses into it.
Context parse(const char* nullTerminatedInput, std::size_t maxElementDepth);
Context parse(const char* nullTerminatedInput);

/// The outcome of parse_well_formed_payload: the parsed payload, or the XML 1.0 rule it breaks.
struct WellFormedPayload
{
  optional<Context> context;  ///< The parse, when the payload broke no rule.
  const char* violation{nullptr};  ///< The rule the payload breaks (a static string), or nullptr.
};

/// Parses a raw XML payload that must be strictly well-formed XML 1.0 beginning with its element (an
/// XmlElement value or a preserved ExtensionObject body, written into an export verbatim). One pass over
/// the whole of @p payload, embedded NULs included, checks the lexical rules the non-validating parser
/// does not enforce (legal UTF-8 characters, well-formed names and attributes, distinct attribute names,
/// references, comments, no declaration or DOCTYPE, no "]]>" in text) and, from the same tags, the
/// nesting rules `parse` enforces; the parse follows only a payload that passes, and the returned
/// `Context` borrows from @p payload, which must outlive it.
/// @return The parsed payload, or the first broken rule with no parse.
/// @throws UaException Bad_EncodingLimitsExceeded (XmlNestingTooDeep) when a payload that breaks no rule
///         nests deeper than @p maxElementDepth, Bad_DecodingError (XmlUnbalancedCloseTag) when it closes
///         an element it never opened, as `parse` refuses them; or a parser error.
WellFormedPayload parse_well_formed_payload(const std::string& payload, std::size_t maxElementDepth);

namespace parser
{

void parse(string_view input, bool& result);

void parse(string_view input, uint8_t& result);

void parse(string_view input, int8_t& result);

void parse(string_view input, uint16_t& result);

void parse(string_view input, int16_t& result);

void parse(string_view input, uint32_t& result);

void parse(string_view input, int32_t& result);

void parse(string_view input, uint64_t& result);

void parse(string_view input, int64_t& result);

void parse(string_view input, float& result);

void parse(string_view input, double& result);

void parse(string_view input, String& result);

void parse(string_view input, DateTime& result);

void parse(string_view input, Guid& result);

void parse(string_view input, ByteString& result);

void parse(string_view input, NodeId& result);

void parse(string_view input, ExpandedNodeId& result);

void parse(string_view input, StatusCode& result);

void parse(string_view input, QualifiedName& result);

}  // namespace parser

}  // namespace xml

}  // namespace ua

#endif  //! UA_XML_PARSER_H
