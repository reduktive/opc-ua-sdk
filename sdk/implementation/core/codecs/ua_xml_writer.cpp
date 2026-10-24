// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_xml_writer.h"
#include "ua_error_detail.h"
#include "ua_stream.h"
#include "ua_xml_escape.h"

namespace ua
{

using ua::xml_detail::write_raw;
using ua::xml_detail::xml_escape;

XmlWriter::XmlWriter(Stream& stream) : mStream(stream)
{}

void XmlWriter::write_declaration()
{
  write_raw(mStream, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
}

void XmlWriter::start_element(string_view name)
{
  // A new child flushes the parent's pending start tag and marks the parent as having content.
  close_start_tag();
  mHasContent = true;

  write_raw(mStream, "<");
  write_raw(mStream, name);
  mStartTagPending = true;
  mHasContent = false;
}

void XmlWriter::attribute(string_view name, string_view value)
{
  if (!mStartTagPending)
  {
    throw UaException(Status::BadInvalidState,
      ErrorDetail::build("XmlWriterError", "Attribute written outside of a pending start tag", "XmlWriter")
        .context(ua::ContextKeys::fieldName, std::string(name)));
  }

  write_raw(mStream, " ");
  write_raw(mStream, name);
  write_raw(mStream, "=\"");
  write_raw(mStream, xml_escape(value, /*attribute*/ true));
  write_raw(mStream, "\"");
}

void XmlWriter::text(string_view value)
{
  close_start_tag();
  mHasContent = true;
  write_raw(mStream, xml_escape(value));
}

void XmlWriter::end_element(string_view name)
{
  if (mStartTagPending && !mHasContent)
  {
    write_raw(mStream, "/>");
    mStartTagPending = false;
  }
  else
  {
    close_start_tag();
    write_raw(mStream, "</");
    write_raw(mStream, name);
    write_raw(mStream, ">");
  }

  // The closed element is now content of its parent.
  mHasContent = true;
}

void XmlWriter::raw(string_view xml)
{
  close_start_tag();
  mHasContent = true;
  write_raw(mStream, xml);
}

void XmlWriter::close_start_tag()
{
  if (mStartTagPending)
  {
    write_raw(mStream, ">");
    mStartTagPending = false;
  }
}

XmlWriter::ElementScope::ElementScope(XmlWriter& writer, string_view name) : mWriter(writer), mName(name)
{
  mWriter.start_element(mName);
}

XmlWriter::ElementScope::~ElementScope()
{
  mWriter.end_element(mName);
}

}  // namespace ua
