// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <limits>
#include <chrono>
#include <charconv>
#include "ua_xml_parser.h"
#include "ua_error_detail.h"
#include "ua_xml_escape.h"
#include <algorithm>
#include <cstdint>
#include <functional>
#include <iterator>
#include <string>
#include <cstring>
#include <vector>
#include "ua_error_detail_keys.h"
#include "ua_exceptions.h"
#include "fmt/format.h"
#include "ua_string.h"
#include "ua_date_time.h"
#include "ua_guid.h"
#include "ua_byte_string.h"
#include "ua_node_id.h"
#include "ua_expanded_node_id.h"
#include "ua_status_code.h"
#include "ua_qualified_name.h"

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:4100)
#endif
#include "rapidxml/rapidxml.hpp"
#ifdef _WIN32
#pragma warning(pop)
#endif

using namespace rapidxml;

namespace ua
{

namespace xml
{

static void clear_string_if_empty(string_view& str)
{
  if (str.empty())
  {
    str = {};
  }
}

namespace
{

// Reinterpret between the opaque public handles and the rapidxml types. The handles are only ever
// pointer values produced by `to_handle(...)` from a real rapidxml object, so the round-trip is
// well-defined and the casts stay confined to this TU.
xml_node<>* cast_to_element(detail::NodeHandle* handle)
{
  return reinterpret_cast<xml_node<>*>(handle);
}

xml_attribute<>* cast_to_attribute(detail::AttributeHandle* handle)
{
  return reinterpret_cast<xml_attribute<>*>(handle);
}

detail::NodeHandle* to_handle(xml_node<>* node)
{
  return reinterpret_cast<detail::NodeHandle*>(node);
}

detail::AttributeHandle* to_handle(xml_attribute<>* attribute)
{
  return reinterpret_cast<detail::AttributeHandle*>(attribute);
}

// Returns the local (prefix-stripped) part of an XML qualified name.
//
// OPC UA NodeSets and value contents bind the same Types.xsd URI either to the
// default namespace (unprefixed, e.g. `<ListOfDouble>`) or to a prefix (e.g.
// `<uax:ListOfDouble>`). The two forms are namespace-identical, so element-name
// lookup must compare local names, ignoring any prefix. For unprefixed names
// this is exactly an exact-match, so behaviour for default-namespace documents
// is unchanged.
string_view local_name(string_view name)
{
  if (auto pos = name.find(':'); pos != string_view::npos)
  {
    return name.substr(pos + 1);
  }
  return name;
}

// nosemgrep: raw-pointer-param-deref-no-null-check (param non-null by contract; internal rapidxml helper)
string_view node_local_name(xml_node<>* node)
{
  return local_name(string_view{node->name(), node->name_size()});
}

// Finds the first child of `parent` whose local name matches `wantedLocalName`.
// `wantedLocalName` is itself reduced to its local part so callers may pass
// either a bare or prefixed name.
xml_node<>* find_child_by_local_name(xml_node<>* parent, string_view wantedName)
{
  const string_view wanted = local_name(wantedName);
  for (xml_node<>* child = parent->first_node(); child; child = child->next_sibling())
  {
    if (node_local_name(child) == wanted)
    {
      return child;
    }
  }
  return nullptr;
}

// Finds the first sibling after `node` whose local name matches `wantedName`.
xml_node<>* find_sibling_by_local_name(xml_node<>* node, string_view wantedName)
{
  const string_view wanted = local_name(wantedName);
  for (xml_node<>* sibling = node->next_sibling(); sibling; sibling = sibling->next_sibling())
  {
    if (node_local_name(sibling) == wanted)
    {
      return sibling;
    }
  }
  return nullptr;
}

}  // namespace

Context::Context(shared_ptr<detail::DocumentHandle> document) : mXmlDocument(std::move(document))
{
  check_true(static_cast<bool>(mXmlDocument), Status::BadInvalidArgument);
}

Element Context::xml_element() const
{
  auto* document = reinterpret_cast<xml_document<>*>(mXmlDocument.get());
  xml_node<>* root = document;  // proper derived->base conversion before forming the opaque handle
  return Element(to_handle(root));
}

Context::Context(Context&& other) noexcept : mXmlDocument(std::move(other.mXmlDocument))
{}

Context& Context::operator=(Context&& other) noexcept
{
  mXmlDocument = std::move(other.mXmlDocument);
  return *this;
}

// Non-destructive parse flags. `parse_non_destructive` (= parse_no_string_terminators |
// parse_no_entity_translation) guarantees rapidxml performs NO writes to the source buffer: it
// neither inserts NUL terminators nor expands entities in place. This is what makes it sound to
// parse a `const`/.rodata buffer. `parse_normalize_whitespace` is deliberately NOT requested - it
// mutates the buffer in place. Dropping it is behaviour-preserving for our inputs: it only collapsed
// *internal* runs of whitespace (scalar values have none) and never trimmed leading/trailing
// whitespace, so the scalar parsers reject surrounding whitespace exactly as before.
// `parse_validate_closing_tags` only reads.
static constexpr int nonDestructiveParseFlags = parse_non_destructive | parse_validate_closing_tags;

namespace
{

// The nesting refusals of check_element_depth and well_formed_payload_violation, built in one place so
// both pre-parse scans refuse with the same status and detail.
[[noreturn]] void throw_nesting_too_deep(std::size_t maxElementDepth, std::size_t depth)
{
  throw UaException{Status::BadEncodingLimitsExceeded,
    ErrorDetail::build(
      "XmlNestingTooDeep", "XML element nesting exceeds the depth the decoder admits", "XmlParser")
      .context(ContextKeys::limit, std::to_string(maxElementDepth))
      .context(ContextKeys::countTotal, std::to_string(depth))};
}

[[noreturn]] void throw_unbalanced_close_tag()
{
  throw UaException{Status::BadDecodingError,
    ErrorDetail::build("XmlUnbalancedCloseTag", "An XML close tag has no matching open tag", "XmlParser")};
}

/// Counts element nesting the way rapidxml's parse_node will descend it, without recursing, and
/// throws once the depth passes @p maxElementDepth. Mirrors the parser's skip rules so no lexical
/// construct (a quoted attribute, CDATA, a comment, a processing instruction, a DOCTYPE with an
/// internal subset, another declaration) can hide an open tag from the count or fake a close.
void check_element_depth(const char* input, std::size_t maxElementDepth)
{
  const auto reject = [maxElementDepth](std::size_t depth)
  {
    throw_nesting_too_deep(maxElementDepth, depth);
  };
  const auto skipTo = [](const char* p, const char* marker) -> const char*
  {
    const char* found = std::strstr(p, marker);
    return found ? found + std::strlen(marker) : p + std::strlen(p);
  };

  std::size_t depth = 0;
  const char* p = input;
  while (*p != '\0')
  {
    if (*p != '<')
    {
      ++p;
      continue;
    }
    const char next = p[1];
    if (next == '/')
    {
      // A close tag. One that outruns its opens is malformed: refused here as a decoding error, so it
      // can neither pre-pay depth nor reach the parser.
      if (depth == 0)
      {
        throw_unbalanced_close_tag();
      }
      --depth;
      p = skipTo(p + 2, ">");
    }
    else if (next == '?')
    {
      p = skipTo(p + 2, "?>");
    }
    else if (next == '!')
    {
      if (std::strncmp(p, "<!--", 4) == 0)
      {
        p = skipTo(p + 4, "-->");
      }
      else if (std::strncmp(p, "<![CDATA[", 9) == 0)
      {
        p = skipTo(p + 9, "]]>");
      }
      else if (std::strncmp(p, "<!DOCTYPE", 9) == 0 &&
               (p[9] == ' ' || p[9] == '\t' || p[9] == '\n' || p[9] == '\r'))
      {
        // Exactly the form the parser treats as a DOCTYPE (whitespace after the keyword); any other
        // "<!" is skipped to its first '>' like the parser's unrecognised-declaration rule.
        // Skip to the '>' at bracket depth zero: the internal subset may nest '[' ... ']'.
        int brackets = 0;
        p += 9;
        while (*p != '\0')
        {
          if (*p == '[')
          {
            ++brackets;
          }
          else if (*p == ']')
          {
            --brackets;
          }
          else if (*p == '>' && brackets <= 0)
          {
            ++p;
            break;
          }
          ++p;
        }
      }
      else
      {
        p = skipTo(p + 2, ">");
      }
    }
    else
    {
      // A start tag, read the way the parser reads it: the element name runs to the first whitespace,
      // '/', '>' or '?' (a quote is an ordinary name character); attributes are name '=' quoted-value
      // pairs and only a quoted VALUE may hide a '>' or '/'. The tag ends at the first '>' outside a
      // quoted value; "/>" opens nothing. A tag the parser would refuse (no '>', an unquoted value) is
      // never counted: the parser stops before recursing into it.
      const auto isSpace = [](char c)
      {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
      };
      const auto isNameEnd = [&](char c)
      {
        return c == '\0' || isSpace(c) || c == '/' || c == '>' || c == '?';
      };
      p += 1;
      while (!isNameEnd(*p))
      {
        ++p;
      }
      bool selfClosing = false;
      bool closed = false;
      while (*p != '\0' && !closed)
      {
        while (isSpace(*p))
        {
          ++p;
        }
        if (*p == '\0')
        {
          break;
        }
        if (*p == '>')
        {
          selfClosing = p[-1] == '/';
          ++p;
          closed = true;
          break;
        }
        if (*p == '/' && p[1] == '>')
        {
          selfClosing = true;
          p += 2;
          closed = true;
          break;
        }
        if (*p == '/' || *p == '?')
        {
          ++p;
          continue;
        }
        // An attribute: name, '=', quoted value.
        while (!isNameEnd(*p) && *p != '=')
        {
          ++p;
        }
        while (isSpace(*p))
        {
          ++p;
        }
        if (*p != '=')
        {
          continue;
        }
        ++p;
        while (isSpace(*p))
        {
          ++p;
        }
        if (*p == '"' || *p == '\'')
        {
          const char quote = *p++;
          while (*p != '\0' && *p != quote)
          {
            ++p;
          }
          if (*p == quote)
          {
            ++p;
          }
        }
      }
      if (closed && !selfClosing)
      {
        ++depth;
        if (depth > maxElementDepth)
        {
          reject(depth);
        }
      }
    }
  }
}

// The XML 1.0 rules rapidxml does not enforce (it is non-validating and stops at a NUL), checked for a
// raw payload in the same single pass that bounds its nesting: every character is a legal Char in well-formed
// UTF-8 (a NUL, a forbidden control or a malformed sequence would let the parser check a prefix while the
// whole payload is written); the payload begins with its element (no declaration, DOCTYPE, processing
// instruction, comment or text ahead of it); no DOCTYPE or XML declaration appears inside it; every tag
// is a well-formed Name followed, in a start tag, by whitespace-separated attributes Name = "value"
// with distinct names; no '<' appears in an attribute value; every '&' starts a predefined entity or a
// character reference to a legal Char; a comment holds no "--"; and "]]>" never appears in text.
// Returns the broken rule, or nullptr. A payload that breaks none of them is then held to the nesting
// rules check_element_depth enforces on any document, counted from the same tags, and refused with the
// same status and detail: its first close tag without an open tag (Bad_DecodingError) or its first
// element deeper than @p maxElementDepth (Bad_EncodingLimitsExceeded). A broken rule wins over a nesting
// refusal anywhere in the payload. On a payload that breaks no rule both counts agree: such a payload
// has no construct on which the two scans read a tag differently. Cost: one pass over the payload,
// plus a sort of each tag's own attribute names (O(k log k) for a tag with k attributes).
const char* well_formed_payload_violation(string_view p, std::size_t maxElementDepth)
{
  constexpr auto npos = string_view::npos;
  static constexpr const char* badChar = "a character XML 1.0 forbids, or a byte sequence that is not UTF-8";
  static constexpr const char* badReference = "an '&' that starts no entity or character reference";
  const auto isSpace = [](char c)
  {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
  };
  const auto starts = [&p](std::size_t at, string_view s)
  {
    return p.substr(at, s.size()) == s;
  };
  const auto legalChar = [](std::uint32_t c)
  {
    return c == 0x9 || c == 0xA || c == 0xD || (c >= 0x20 && c <= 0xD7FF) || (c >= 0xE000 && c <= 0xFFFD) ||
           (c >= 0x10000 && c <= 0x10FFFF);
  };
  // The length of the legal character at `at`, or 0.
  const auto charLength = [&](std::size_t at) -> std::size_t
  {
    const auto ch = static_cast<unsigned char>(p[at]);
    if (ch < 0x80u)
    {
      return legalChar(ch) ? 1 : 0;
    }
    return ua::xml_detail::utf8_sequence_length(p, at);
  };
  // The length of the entity or character reference starting at the '&' at `at`, or 0. A character
  // reference may carry any number of leading zeros; at most eight significant digits are read, and
  // every character is consumed once, so the scan stays linear.
  const auto referenceLength = [&](std::size_t at) -> std::size_t
  {
    std::size_t k = at + 1;
    for (const string_view name : {string_view{"amp;"},
           string_view{"lt;"},
           string_view{"gt;"},
           string_view{"quot;"},
           string_view{"apos;"}})
    {
      if (starts(k, name))
      {
        return 1 + name.size();
      }
    }
    if (k >= p.size() || p[k] != '#')
    {
      return 0;
    }
    ++k;
    const bool hex = k < p.size() && p[k] == 'x';
    if (hex)
    {
      ++k;
    }
    const auto digitValue = [hex](char c) -> int
    {
      if (c >= '0' && c <= '9')
        return c - '0';
      if (hex && c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      if (hex && c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      return -1;
    };
    const std::size_t digitsStart = k;
    while (k < p.size() && p[k] == '0')
    {
      ++k;
    }
    std::uint32_t value = 0;
    std::size_t significant = 0;
    while (k < p.size() && digitValue(p[k]) >= 0)
    {
      if (++significant > 8)
      {
        return 0;
      }
      value = value * (hex ? 16u : 10u) + static_cast<std::uint32_t>(digitValue(p[k]));
      ++k;
    }
    if (k == digitsStart || k >= p.size() || p[k] != ';' || !legalChar(value))
    {
      return 0;
    }
    return k + 1 - at;
  };
  // The code point of the well-formed UTF-8 sequence of `length` bytes at `at`.
  const auto codePoint = [&p](std::size_t at, std::size_t length) -> std::uint32_t
  {
    const auto byte = [&](std::size_t k)
    {
      return static_cast<std::uint32_t>(static_cast<unsigned char>(p[at + k]));
    };
    switch (length)
    {
    case 1:
      return byte(0);
    case 2:
      return ((byte(0) & 0x1Fu) << 6) | (byte(1) & 0x3Fu);
    case 3:
      return ((byte(0) & 0x0Fu) << 12) | ((byte(1) & 0x3Fu) << 6) | (byte(2) & 0x3Fu);
    default:
      return ((byte(0) & 0x07u) << 18) | ((byte(1) & 0x3Fu) << 12) | ((byte(2) & 0x3Fu) << 6) |
             (byte(3) & 0x3Fu);
    }
  };
  // The Name productions of XML 1.0 (fifth edition), on code points.
  const auto isNameStartChar = [](std::uint32_t c)
  {
    return c == ':' || (c >= 'A' && c <= 'Z') || c == '_' || (c >= 'a' && c <= 'z') ||
           (c >= 0xC0 && c <= 0xD6) || (c >= 0xD8 && c <= 0xF6) || (c >= 0xF8 && c <= 0x2FF) ||
           (c >= 0x370 && c <= 0x37D) || (c >= 0x37F && c <= 0x1FFF) || (c >= 0x200C && c <= 0x200D) ||
           (c >= 0x2070 && c <= 0x218F) || (c >= 0x2C00 && c <= 0x2FEF) || (c >= 0x3001 && c <= 0xD7FF) ||
           (c >= 0xF900 && c <= 0xFDCF) || (c >= 0xFDF0 && c <= 0xFFFD) || (c >= 0x10000 && c <= 0xEFFFF);
  };
  const auto nameChar = [&isNameStartChar](std::uint32_t c)
  {
    return isNameStartChar(c) || c == '-' || c == '.' || (c >= '0' && c <= '9') || c == 0xB7 ||
           (c >= 0x300 && c <= 0x36F) || (c >= 0x203F && c <= 0x2040);
  };
  // The end of the Name starting at `at`, or npos when none starts there.
  const auto scanName = [&](std::size_t at) -> std::size_t
  {
    bool first = true;
    while (at < p.size())
    {
      const auto length = charLength(at);
      if (length == 0)
      {
        return first ? npos : at;
      }
      const auto c = codePoint(at, length);
      if (!(first ? isNameStartChar(c) : nameChar(c)))
      {
        return first ? npos : at;
      }
      first = false;
      at += length;
    }
    return first ? npos : at;
  };

  const char* reason = nullptr;
  // The current tag's attribute names; checked for repeats when the tag ends, by sorting, so a tag costs
  // O(k log k) in its own k attributes and nothing in any earlier tag's (a hash set cleared per tag
  // paid for its largest earlier size on every tag: panel K round 4).
  std::vector<string_view> attributeNames;
  const auto attributeNamesDistinct = [&attributeNames]
  {
    std::sort(attributeNames.begin(), attributeNames.end());
    return std::adjacent_find(attributeNames.begin(), attributeNames.end()) == attributeNames.end();
  };
  // Whether the tag scanTag last read ended "/>" (opens nothing).
  bool selfClosing = false;
  // Scans the start or end tag whose '<' is at `at`; returns the index after its '>', or npos with
  // `reason` set.
  const auto scanTag = [&](std::size_t at) -> std::size_t
  {
    ++at;
    const bool endTag = at < p.size() && p[at] == '/';
    if (endTag)
    {
      ++at;
    }
    auto next = scanName(at);
    if (next == npos)
    {
      reason = "a tag without a well-formed name";
      return npos;
    }
    at = next;
    attributeNames.clear();
    for (;;)
    {
      const auto spaceStart = at;
      while (at < p.size() && isSpace(p[at]))
      {
        ++at;
      }
      if (at >= p.size())
      {
        reason = "the payload ends inside a tag";
        return npos;
      }
      const bool closes = p[at] == '>' || (!endTag && p[at] == '/' && at + 1 < p.size() && p[at + 1] == '>');
      if (closes)
      {
        if (!attributeNamesDistinct())
        {
          reason = "an attribute repeated on one element";
          return npos;
        }
        selfClosing = p[at] != '>';
        return at + (p[at] == '>' ? 1 : 2);
      }
      if (endTag || at == spaceStart)
      {
        reason = "a malformed tag";
        return npos;
      }
      const auto nameStart = at;
      next = scanName(at);
      if (next == npos)
      {
        reason = "an attribute without a well-formed name";
        return npos;
      }
      attributeNames.push_back(p.substr(nameStart, next - nameStart));
      at = next;
      while (at < p.size() && isSpace(p[at]))
      {
        ++at;
      }
      if (at >= p.size() || p[at] != '=')
      {
        reason = "an attribute without '='";
        return npos;
      }
      ++at;
      while (at < p.size() && isSpace(p[at]))
      {
        ++at;
      }
      if (at >= p.size() || (p[at] != '"' && p[at] != '\''))
      {
        reason = "an attribute value without quotes";
        return npos;
      }
      const char quote = p[at++];
      while (at < p.size() && p[at] != quote)
      {
        if (p[at] == '<')
        {
          reason = "a '<' inside an attribute value";
          return npos;
        }
        const auto length = p[at] == '&' ? referenceLength(at) : charLength(at);
        if (length == 0)
        {
          reason = p[at] == '&' ? badReference : badChar;
          return npos;
        }
        at += length;
      }
      if (at >= p.size())
      {
        reason = "the payload ends inside an attribute value";
        return npos;
      }
      ++at;  // the closing quote
    }
  };
  // Advances over the characters up to and including `terminator`; returns npos when a character is
  // illegal or the terminator is missing. `forbidden` (may be empty) must not occur before it.
  const auto scanUntil = [&](std::size_t at, string_view terminator, string_view forbidden) -> std::size_t
  {
    while (at < p.size())
    {
      if (starts(at, terminator))
      {
        return at + terminator.size();
      }
      if (!forbidden.empty() && starts(at, forbidden))
      {
        return npos;
      }
      const auto length = charLength(at);
      if (length == 0)
      {
        return npos;
      }
      at += length;
    }
    return npos;
  };

  // The nesting count, and the first nesting refusal found (refused only once no rule is broken).
  std::size_t depth = 0;
  bool unbalancedClose = false;
  std::size_t excessDepth = 0;
  std::size_t i = 0;
  while (i < p.size() && isSpace(p[i]))
  {
    ++i;
  }
  if (i + 1 >= p.size() || p[i] != '<' || scanName(i + 1) == npos)
  {
    return "the payload must begin with its element";
  }
  while (i < p.size())
  {
    if (p[i] == '<')
    {
      if (starts(i, "<!--"))
      {
        // "--" may appear only as the start of "-->", and "--->" is not a comment end.
        i = scanUntil(i + 4, "-->", "--");
        if (i == npos)
        {
          return "a malformed comment";
        }
        continue;
      }
      if (starts(i, "<![CDATA["))
      {
        i = scanUntil(i + 9, "]]>", {});
        if (i == npos)
        {
          return "a malformed CDATA section";
        }
        continue;
      }
      if (starts(i, "<!"))
      {
        return "a declaration inside the element";
      }
      if (starts(i, "<?"))
      {
        const auto targetEnd = scanName(i + 2);
        if (targetEnd == npos)
        {
          return "a processing instruction without a target";
        }
        const auto target = p.substr(i + 2, targetEnd - i - 2);
        if (target.size() == 3 && (target[0] | 0x20) == 'x' && (target[1] | 0x20) == 'm' &&
            (target[2] | 0x20) == 'l')
        {
          return "an XML declaration inside the element";
        }
        if (targetEnd >= p.size() || !(isSpace(p[targetEnd]) || starts(targetEnd, "?>")))
        {
          return "a processing instruction whose target is not followed by whitespace";
        }
        i = scanUntil(targetEnd, "?>", {});
        if (i == npos)
        {
          return "a malformed processing instruction";
        }
        continue;
      }
      const bool endTag = starts(i, "</");
      i = scanTag(i);
      if (i == npos)
      {
        return reason;
      }
      if (!unbalancedClose && excessDepth == 0)
      {
        if (endTag)
        {
          if (depth == 0)
          {
            unbalancedClose = true;
          }
          else
          {
            --depth;
          }
        }
        else if (!selfClosing && ++depth > maxElementDepth)
        {
          excessDepth = depth;
        }
      }
      continue;
    }
    if (p[i] == ']' && starts(i, "]]>"))
    {
      return "\"]]>\" in text";
    }
    const auto length = p[i] == '&' ? referenceLength(i) : charLength(i);
    if (length == 0)
    {
      return p[i] == '&' ? badReference : badChar;
    }
    i += length;
  }
  if (unbalancedClose)
  {
    throw_unbalanced_close_tag();
  }
  if (excessDepth != 0)
  {
    throw_nesting_too_deep(maxElementDepth, excessDepth);
  }
  return nullptr;
}

// Parses a buffer whose nesting a pre-scan (check_element_depth or well_formed_payload_violation) has
// already bounded, so the parser's recursion is bounded too.
Context parse_bounded(const char* nullTerminatedInput)
{
  // Own the document immediately: rapidxml's parse() throws parse_error on malformed input, so the
  // unique_ptr frees the document during stack unwinding rather than leaking it. Ownership is
  // transferred to the shared_ptr handle only after a successful parse. The deleter (bound here,
  // where the rapidxml type is complete) casts back before deleting, so DocumentHandle never needs
  // to be a complete type at the Context's use sites.
  auto document = std::make_unique<xml_document<>>();
  // SAFETY: rapidxml's parse() signature takes a non-const Ch*, but kNonDestructiveParseFlags
  // guarantees it never writes to the buffer (no terminator insertion, no entity expansion), so the
  // const_cast is sound even when @p nullTerminatedInput points into read-only (.rodata) storage.
  // The static_assert guards against a future edit re-introducing a mutating flag, which would turn
  // this into a silent write to .rodata (SIGSEGV) rather than a compile error.
  static_assert((nonDestructiveParseFlags & parse_no_string_terminators) != 0 &&
                  (nonDestructiveParseFlags & parse_no_entity_translation) != 0,
    "xml::parse flags must remain non-destructive: the buffer may live in read-only memory");
  document->parse<nonDestructiveParseFlags>(const_cast<char*>(nullTerminatedInput));
  shared_ptr<detail::DocumentHandle> handle(reinterpret_cast<detail::DocumentHandle*>(document.release()),
    [](detail::DocumentHandle* owned)
    {
      // nosemgrep: manual-delete (shared_ptr custom deleter, correct RAII)
      delete reinterpret_cast<xml_document<>*>(owned);
    });
  return Context{std::move(handle)};
}

}  // namespace

Context parse(const char* nullTerminatedInput)
{
  return parse(nullTerminatedInput, defaultMaxXmlElementDepth);
}

Context parse(const char* nullTerminatedInput, std::size_t maxElementDepth)
{
  check_element_depth(nullTerminatedInput, maxElementDepth);
  return parse_bounded(nullTerminatedInput);
}

WellFormedPayload parse_well_formed_payload(const std::string& payload, std::size_t maxElementDepth)
{
  if (const char* violation = well_formed_payload_violation(payload, maxElementDepth))
  {
    return WellFormedPayload{std::nullopt, violation};
  }
  // The scan admitted every character, so the payload holds no NUL and the parser reads all of it.
  return WellFormedPayload{parse_bounded(payload.c_str()), nullptr};
}

// --- Entity decoding -----------------------------------------------------------------------------
// With parse_no_entity_translation, rapidxml leaves character/entity references (`&amp;`, `&#x41;`,
// ...) verbatim in node values. We expand them lazily at the value accessors: values with no '&' (the
// overwhelming majority) are returned as zero-copy string_views into the source buffer; only
// entity-bearing values are decoded into the document's own memory pool, so the decoded text lives
// exactly as long as the owning Context and the borrowed-string_view contract is preserved.

namespace
{

// Appends the UTF-8 encoding of code point `cp` to `out`; returns the number of bytes written (1..4).
size_t append_utf8(uint32_t cp, char* out)
{
  if (cp <= 0x7f)
  {
    out[0] = static_cast<char>(cp);
    return 1;
  }
  if (cp <= 0x7ff)
  {
    out[0] = static_cast<char>(0xc0 | (cp >> 6));
    out[1] = static_cast<char>(0x80 | (cp & 0x3f));
    return 2;
  }
  if (cp <= 0xffff)
  {
    out[0] = static_cast<char>(0xe0 | (cp >> 12));
    out[1] = static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
    out[2] = static_cast<char>(0x80 | (cp & 0x3f));
    return 3;
  }
  out[0] = static_cast<char>(0xf0 | (cp >> 18));
  out[1] = static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
  out[2] = static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
  out[3] = static_cast<char>(0x80 | (cp & 0x3f));
  return 4;
}

// Parses a numeric character-reference body ("#1234" decimal or "#x1A2b" hex); throws on malformed
// input. `body` excludes the leading '&' and trailing ';' and starts with '#'.
uint32_t parse_char_ref(string_view body)
{
  const bool hex = body.size() > 1 && (body[1] == 'x' || body[1] == 'X');
  const string_view digits = body.substr(hex ? 2 : 1);
  uint32_t codePoint = 0;
  const char* last = digits.data() + digits.size();
  const auto result = std::from_chars(digits.data(), last, codePoint, hex ? 16 : 10);
  if (digits.empty() || result.ec != std::errc{} || result.ptr != last || codePoint > 0x10ffff)
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("XmlBadCharRef", "Malformed numeric character reference", "XmlParser")
        .context(ua::ContextKeys::value, std::string(body)));
  }
  return codePoint;
}

// Expands the five predefined entities and numeric character references in `raw` into `out` (whose
// capacity must be >= raw.size(); decoded length is always <= raw.size()). Returns bytes written.
size_t expand_entities(string_view raw, char* out)
{
  size_t written = 0;
  for (size_t i = 0; i < raw.size();)
  {
    if (raw[i] != '&')
    {
      out[written++] = raw[i++];
      continue;
    }
    const size_t semicolon = raw.find(';', i + 1);
    const string_view body =
      (semicolon == string_view::npos) ? string_view{} : raw.substr(i + 1, semicolon - i - 1);
    if (body == "amp")
      out[written++] = '&';
    else if (body == "lt")
      out[written++] = '<';
    else if (body == "gt")
      out[written++] = '>';
    else if (body == "quot")
      out[written++] = '"';
    else if (body == "apos")
      out[written++] = '\'';
    else if (!body.empty() && body[0] == '#')
      written += append_utf8(parse_char_ref(body), out + written);
    else
    {
      // Stray '&' or an entity reference we do not recognise: copy the '&' verbatim and rescan from
      // the next character (do not consume up to the ';', which may belong to later content).
      out[written++] = raw[i++];
      continue;
    }
    i = semicolon + 1;
  }
  return written;
}

// Returns the node/attribute value as a string_view, expanding XML entities only when present.
// nosemgrep: raw-pointer-param-deref-no-null-check (param non-null by contract; internal rapidxml helper)
string_view decoded_value(xml_document<>* document, const char* data, size_t size)
{
  const string_view raw{data, size};
  if (document == nullptr || raw.find('&') == string_view::npos)
  {
    // No entities to expand (the common case) - return a zero-copy view into the source buffer. A
    // null document only arises for a detached node, which the parser never produces.
    return raw;
  }
  // Decoded text is never longer than the source; allocate uninitialised pool storage (owned by the
  // document, freed with the Context) and fill it.
  char* out = document->allocate_string(nullptr, size);
  return string_view{out, expand_entities(raw, out)};
}

}  // namespace

string_view Element::get_value() const
{
  xml_node<>* element = cast_to_element(mHandle);
  return decoded_value(element->document(), element->value(), element->value_size());
}

optional<Element> Element::get_first_child() const
{
  return get_first_child(string_view{});
}

optional<Element> Element::get_first_child(string_view childName) const
{
  clear_string_if_empty(childName);
  xml_node<>* element = cast_to_element(mHandle);
  xml_node<>* firstChild =
    childName.empty() ? element->first_node() : find_child_by_local_name(element, childName);

  optional<Element> result;
  if (firstChild)
  {
    result.emplace(Element(to_handle(firstChild)));
  }
  return result;
}

optional<Element> Element::get_parent() const
{
  xml_node<>* element = cast_to_element(mHandle);
  xml_node<>* parent = element->parent();

  optional<Element> result;
  if (parent)
  {
    result.emplace(Element(to_handle(parent)));
  }
  return result;
}

optional<string_view> Element::get_first_attribute_value(string_view attributeName) const
{
  clear_string_if_empty(attributeName);
  xml_node<>* element = cast_to_element(mHandle);
  xml_attribute<>* attribute = element->first_attribute(attributeName.data(), attributeName.size());

  optional<string_view> result;
  if (attribute)
  {
    result.emplace(decoded_value(attribute->document(), attribute->value(), attribute->value_size()));
  }
  return result;
}

optional<Element> Element::get_next() const
{
  return get_next(string_view{});
}

optional<Element> Element::get_next(string_view nextElementName) const
{
  clear_string_if_empty(nextElementName);
  xml_node<>* element = cast_to_element(mHandle);
  xml_node<>* nextElement =
    nextElementName.empty() ? element->next_sibling() : find_sibling_by_local_name(element, nextElementName);

  optional<Element> result;
  if (nextElement)
  {
    result.emplace(Element(to_handle(nextElement)));
  }
  return result;
}

optional<Attribute> Element::get_first_attribute() const
{
  return get_first_attribute(string_view{});
}

optional<Attribute> Element::get_first_attribute(string_view attributeName) const
{
  clear_string_if_empty(attributeName);
  xml_node<>* element = cast_to_element(mHandle);
  xml_attribute<>* attribute = element->first_attribute(attributeName.data(), attributeName.size());

  optional<Attribute> result;
  if (attribute)
  {
    result.emplace(Attribute(to_handle(attribute)));
  }
  return result;
}

size_t Element::get_number_of_children() const
{
  return get_number_of_children(string_view{});
}

size_t Element::get_number_of_children(string_view name) const
{
  clear_string_if_empty(name);
  xml_node<>* parent = cast_to_element(mHandle);

  size_t result{0};
  if (name.empty())
  {
    for (xml_node<>* child = parent->first_node(); child; child = child->next_sibling())
    {
      ++result;
    }
  }
  else
  {
    const string_view wanted = local_name(name);
    for (xml_node<>* child = parent->first_node(); child; child = child->next_sibling())
    {
      if (node_local_name(child) == wanted)
      {
        ++result;
      }
    }
  }

  return result;
}

string_view Element::get_name() const
{
  xml_node<>* element = cast_to_element(mHandle);
  return string_view(element->name(), element->name_size());
}

Element::Element(detail::NodeHandle* handle) : mHandle(handle)
{
  check_true(handle != nullptr, Status::BadInvalidArgument);
}

Attribute::Attribute(detail::AttributeHandle* handle) : mHandle(handle)
{
  check_true(handle != nullptr, Status::BadInvalidArgument);
}

string_view Attribute::get_value() const
{
  xml_attribute<>* attribute = cast_to_attribute(mHandle);
  return decoded_value(attribute->document(), attribute->value(), attribute->value_size());
}

optional<Attribute> Attribute::get_next() const
{
  return get_next(string_view{});
}

optional<Attribute> Attribute::get_next(string_view nextAttributeName) const
{
  clear_string_if_empty(nextAttributeName);
  xml_attribute<>* attribute = cast_to_attribute(mHandle);
  xml_attribute<>* nextAttribute =
    attribute->next_attribute(nextAttributeName.data(), nextAttributeName.size());

  optional<Attribute> result;
  if (nextAttribute)
  {
    result.emplace(Attribute(to_handle(nextAttribute)));
  }
  return result;
}

string_view Attribute::get_name() const
{
  xml_attribute<>* attribute = cast_to_attribute(mHandle);
  return string_view(attribute->name(), attribute->name_size());
}

namespace parser
{

namespace
{

template<typename T>
size_t parse_number(string_view input, bool allowPlusSign, T& result)
{
  if (input.empty())
  {
    throw UaException(
      Status::BadInvalidArgument, make_error_detail("XmlParseEmptyInput", "Input is empty", "XmlParser"));
  }

  string_view strippedInput = input;
  if (allowPlusSign && input.starts_with('+'))
  {
    strippedInput.remove_prefix(1);
  }

  // The end of the STRIPPED view: with a '+' removed, `input.size()` reached one byte past the view
  // (security review XML-6).
  const char* last = strippedInput.data() + strippedInput.size();
  auto re = ::std::from_chars(strippedInput.data(), last, result);
  if (re.ec != ::std::errc{})
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("XmlParseNumberFailed", "Could not parse value as numeric type", "XmlParser")
        .context(ua::ContextKeys::value, std::string(strippedInput))
        .context(ua::ContextKeys::typeName, typeid(T).name()));
  }
  assert(re.ptr > input.data());

  // re.ptr > input.data() proven by the assert above, so the difference is positive
  return static_cast<size_t>(re.ptr - input.data());
}

template<typename T>
void parse_number(string_view input, T& result)
{
  const size_t noOfChars = parse_number(input, true, result);
  if (noOfChars != input.size())
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("XmlParseNumberFailed",
        "Could not parse a complete number from input (trailing characters remain)",
        "XmlParser")
        .context(ua::ContextKeys::value, std::string(input)));
  }
}

string_view skip_separator(char separator, string_view value)
{
  if (!value.starts_with(separator))
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("XmlParseSeparatorNotFound", "Expected separator not found in input", "XmlParser")
        .context(ua::ContextKeys::expected, std::string(1, separator))
        .context(ua::ContextKeys::value, std::string(value)));
  }
  return value.substr(1);
}

template<typename T>
struct ParseTimeResult
{
  T value{};
  string_view remainder;
};

template<typename T>
ParseTimeResult<T> parse_time_part(
  string_view input, size_t minChars, size_t maxChars, T min, T max, bool allowPlusSign)
{
  ParseTimeResult<T> result;

  const size_t noOfChars = parse_number(input, allowPlusSign, result.value);
  if ((result.value < min) || (result.value > max))
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build("XmlParseTimePartFailed", "Value out of range when parsing time part", "XmlParser")
        .context(ua::ContextKeys::value, std::string(input))
        .context(ua::ContextKeys::actual, std::to_string(result.value))
        .context(ua::ContextKeys::min, std::to_string(min))
        .context(ua::ContextKeys::max, std::to_string(max)));
  }
  result.remainder = input.substr(noOfChars);

  if ((noOfChars < minChars) || (noOfChars > maxChars))
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "XmlParseTimePartFailed", "Parsed invalid number of characters for time part", "XmlParser")
        .context(ua::ContextKeys::value, std::string(input))
        .context(ua::ContextKeys::sizeActual, std::to_string(noOfChars))
        .context(ua::ContextKeys::sizeMin, std::to_string(minChars))
        .context(ua::ContextKeys::sizeMax, std::to_string(maxChars)));
  }

  return result;
}

DateTime create_utc_time(const string_view xsDateTime)
{
  string_view remainder = xsDateTime;

  // Parse year
  auto result = parse_time_part(remainder, 4, 4, uint16_t{1}, uint16_t{9999}, false);
  const std::chrono::year year{result.value};
  remainder = result.remainder;

  remainder = skip_separator('-', remainder);

  // Parse month
  result = parse_time_part(remainder, 2, 2, uint16_t{1}, uint16_t{12}, false);
  const std::chrono::month month{result.value};
  remainder = result.remainder;

  remainder = skip_separator('-', remainder);

  // Parse day
  result = parse_time_part(remainder, 2, 2, uint16_t{1}, uint16_t{31}, false);
  const std::chrono::day day{result.value};
  remainder = result.remainder;

  remainder = skip_separator('T', remainder);

  // Parse hours
  result = parse_time_part(remainder, 2, 2, uint16_t{0}, uint16_t{23}, false);
  const std::chrono::hours hours{result.value};
  remainder = result.remainder;

  remainder = skip_separator(':', remainder);

  // Parse minutes
  result = parse_time_part(remainder, 2, 2, uint16_t{0}, uint16_t{59}, false);
  const std::chrono::minutes minutes{result.value};
  remainder = result.remainder;

  remainder = skip_separator(':', remainder);

  // Parse seconds
  auto secsResults = parse_time_part(remainder, 2, 15, double{0}, double{59.999'999'999'999}, false);
  remainder = secsResults.remainder;
  const double seconds{secsResults.value};

  // Parse offset
  std::chrono::minutes offset{0};
  // What follows the seconds is nothing, exactly "Z", or a whole +hh:mm / -hh:mm offset; the check
  // used to accept any tail ending in 'Z' and ignore anything after the offset (security review
  // XML-11).
  if (remainder == "Z")
  {
    remainder = {};
  }
  else if (!remainder.empty())
  {
    auto signedResult = parse_time_part(remainder, 2, 3, int16_t{-14}, int16_t{14}, true);
    offset = std::chrono::hours{signedResult.value};
    remainder = signedResult.remainder;

    remainder = skip_separator(':', remainder);

    result = parse_time_part(remainder, 2, 2, uint16_t{0}, uint16_t{59}, false);
    if (offset < std::chrono::minutes{0})
    {
      offset -= std::chrono::minutes{result.value};
    }
    else
    {
      offset += std::chrono::minutes{result.value};
    }
    remainder = result.remainder;
  }
  if (!remainder.empty())
  {
    throw UaException(Status::BadDecodingError,
      ErrorDetail::build(
        "XmlParseDateTimeFailed", "Unexpected characters after the time or its offset", "XmlParser")
        .context(ua::ContextKeys::value, std::string(xsDateTime)));
  }

  return DateTime(year, month, day, hours, minutes, seconds, offset);
}

}  // namespace

void parse(string_view input, bool& result)
{
  const string_view trueText = "true";
  const string_view falseText = "false";

  if (input == trueText)
  {
    result = true;
    return;
  }
  else if (input == falseText)
  {
    result = false;
    return;
  }
  else
  {
    int value{};
    parse_number(input, value);

    if (value == 1)
    {
      result = true;
      return;
    }
    else if (value == 0)
    {
      result = false;
      return;
    }
  }

  throw UaException(Status::BadDecodingError,
    ErrorDetail::build("XmlParseBoolFailed",
      "Could not parse value as xs:boolean (expected 'true', 'false', '0', or '1')",
      "XmlParser")
      .context(ua::ContextKeys::value, std::string(input)));
}

void parse(string_view input, uint8_t& result)
{
  parse_number(input, result);
}

void parse(string_view input, int8_t& result)
{
  parse_number(input, result);
}

void parse(string_view input, uint16_t& result)
{
  parse_number(input, result);
}

void parse(string_view input, int16_t& result)
{
  parse_number(input, result);
}

void parse(string_view input, uint32_t& result)
{
  parse_number(input, result);
}

void parse(string_view input, int32_t& result)
{
  parse_number(input, result);
}

void parse(string_view input, uint64_t& result)
{
  parse_number(input, result);
}

void parse(string_view input, int64_t& result)
{
  parse_number(input, result);
}

template<typename T>
static bool get_non_numeric(string_view text, T& value)
{
  const string_view nan = "NaN";
  const string_view positiveInf = "INF";
  const string_view negativeInf = "-INF";

  if (text == nan)
  {
    value = ::std::numeric_limits<T>::quiet_NaN();
    return true;
  }
  else if (text == positiveInf)
  {
    value = ::std::numeric_limits<T>::infinity();
    return true;
  }
  else if (text == negativeInf)
  {
    value = -::std::numeric_limits<T>::infinity();
    return true;
  }

  return false;
}

template<typename T>
static void parse_floating_point(string_view input, T& result)
{
  if (!get_non_numeric(input, result))
  {
    parse_number(input, result);
  }
}

void parse(string_view input, float& result)
{
  parse_floating_point(input, result);
}

void parse(string_view input, double& result)
{
  parse_floating_point(input, result);
}

void parse(string_view input, String& result)
{
  result = input;
}

void parse(string_view input, DateTime& result)
{
  result = create_utc_time(input);
}

void parse(string_view input, Guid& result)
{
  result = Guid::parse(input);
}

void parse(string_view input, ByteString& result)
{
  // OPC 10000-6 5.3.1.8 encodes a ByteString as xs:base64Binary, whose whitespace XML Schema collapses before
  // the value is read: a value wrapped across lines is the same value.
  const auto isXmlWhitespace = [](char c)
  {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  };
  std::string compacted;
  if (std::any_of(input.begin(), input.end(), isXmlWhitespace))
  {
    compacted.reserve(input.size());
    std::copy_if(input.begin(), input.end(), std::back_inserter(compacted), std::not_fn(isXmlWhitespace));
    input = compacted;
  }
  if (input.empty())
  {
    result.clear();
    return;
  }
  result = utils::base64_decode(input);
}

void parse(string_view input, NodeId& result)
{
  result = NodeId::parse(input);
}

void parse(string_view input, ExpandedNodeId& result)
{
  result = ExpandedNodeId::parse(input);
}

void parse(string_view input, StatusCode& result)
{
  uint32_t value{};
  parse(input, value);
  result = StatusCode(value);
}

void parse(string_view input, QualifiedName& result)
{
  string_view name = input;
  auto colon = input.find(':');
  if (colon != string_view::npos)
  {
    auto index = input.substr(0, colon);
    parse(index, result.namespace_index());
    name = input.substr(colon + 1);
  }
  result.name() = name;
}

}  // namespace parser

}  // namespace xml

}  // namespace ua
