// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Header hygiene for the split public NodeSet surface (D-I).
//
// `ua_nodeset_document.h` (tier b: parse + inspect) is included as the FIRST include in this
// translation unit - before gtest or anything else - so that any missing `#include` in the header
// fails to compile HERE rather than silently relying on a consumer's include order. The import
// header (tier a) is then included on top; it must layer cleanly on the document header.
//
// The real assertion of this file is that it *compiles*. The runtime TEST below is a token so the
// TU registers as a genuine (non-empty) test.
#include "ua_nodeset_document.h"
#include "ua_nodeset_import.h"

#include <gtest/gtest.h>

namespace
{

// Compile-time guard: the document header's public vocabulary is usable on its own (it was included
// first, so reaching this point means the header is self-contained).
[[maybe_unused]] void document_header_vocabulary_compiles()
{
  ua::NodeSetParseOptions parseOptions;
  parseOptions.decodeValues = false;
  ua::NamespaceMapping mapping{ua::String{"urn:x"}, 1};
  ua::ModelRef model{ua::String{"urn:x"}, ua::String{"1.0"}};
  (void)parseOptions;
  (void)mapping;
  (void)model;
}

// Compile-time guard: the import header's public vocabulary is usable when layered on the document.
[[maybe_unused]] void import_header_vocabulary_compiles()
{
  ua::NodeSetImportOptions importOptions;
  importOptions.scope = ua::NodeSetImportOptions::Scope::TypeDefinitionsOnly;
  importOptions.onUnknownStructure = ua::NodeSetImportOptions::OnUnknownStructure::ImportOpaque;
  ua::NodeSetImportSummary summary;
  (void)importOptions;
  (void)summary;
}

}  // namespace

TEST(NodeSetHeaderHygiene, PublicHeadersAreSelfContained)
{
  ua::NodeSetImportOptions options;
  EXPECT_EQ(options.scope, ua::NodeSetImportOptions::Scope::Full);
  EXPECT_EQ(options.onUnknownStructure, ua::NodeSetImportOptions::OnUnknownStructure::Fail);
}
