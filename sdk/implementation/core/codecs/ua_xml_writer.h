// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_XML_WRITER_H
#define UA_XML_WRITER_H

#include "ua_includes.h"

namespace ua
{

class Stream;

/// Low-level, attribute-capable XML emitter.
///
/// `XmlEncoder` writes element *content* (`<NodeId>...`); it cannot emit element *attributes*. The
/// NodeSet envelope, however, is attribute-heavy (`<UAVariable NodeId="..." BrowseName="...">`), so
/// this primitive provides the missing capability. It is a pure synchronous emitter over a
/// `Stream&` and shares the XML escaping path with `XmlEncoder` (see `ua_xml_escape.h`).
///
/// The writer uses a *pending-open-tag* model: `start_element` writes `<name` but defers the closing
/// `>` so attributes can be appended incrementally and conditionally. The pending tag is flushed (the
/// `>` emitted) the moment text, a child, or raw bytes are written, or when the element is closed.
/// An element closed while still pending and with no content self-closes as `<name/>`.
///
/// Like `Stream`, it is not thread-safe and surfaces I/O failures by propagating the `UaException`
/// thrown by the underlying stream.
class XmlWriter
{
public:
  explicit XmlWriter(Stream& stream);

  /// Emits the XML prolog: `<?xml version="1.0" encoding="UTF-8"?>` followed by a newline.
  void write_declaration();

  /// Opens an element. Writes `<name` and marks the start tag pending; the closing `>` is deferred
  /// until content is written or the element is closed.
  void start_element(string_view name);

  /// Writes ` name="value"` (value XML-escaped) into the currently pending start tag.
  ///
  /// @throws UaException with `Status::BadInvalidState` if no start tag is pending.
  void attribute(string_view name, string_view value);

  /// Flushes the pending start tag (emits `>`) and writes `value` as escaped element text.
  void text(string_view value);

  /// Closes the element named `name`. If the matching start tag is still pending and no content has
  /// been written since, emits a self-closing ` />`; otherwise flushes `>` (if pending) and writes
  /// `</name>`.
  void end_element(string_view name);

  /// Flushes the pending start tag (emits `>`) and writes `xml` verbatim - no escaping. Used to
  /// embed a pre-rendered subtree (e.g. an `XmlEncoder`-produced `<Value>` body).
  void raw(string_view xml);

  /// RAII guard pairing `start_element` / `end_element`, mirroring `XmlEncoder::ElementScope`.
  class ElementScope
  {
  public:
    ElementScope(XmlWriter& writer, string_view name);
    ~ElementScope();

    ElementScope(const ElementScope&) = delete;
    ElementScope& operator=(const ElementScope&) = delete;
    ElementScope(ElementScope&&) = delete;
    ElementScope& operator=(ElementScope&&) = delete;

  private:
    XmlWriter& mWriter;
    std::string mName;
  };

private:
  // Flushes a deferred start tag by writing the closing `>`. No-op when no tag is pending.
  void close_start_tag();

  Stream& mStream;

  // True between start_element and the point its `>` (or self-closing `/>`) is emitted.
  bool mStartTagPending{false};

  // True once text, a child element, or raw bytes have been written into the currently open element,
  // which forbids self-closing it.
  bool mHasContent{false};
};

}  // namespace ua

#endif  //! UA_XML_WRITER_H
