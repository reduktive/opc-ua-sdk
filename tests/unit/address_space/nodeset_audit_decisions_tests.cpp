// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Tests for the NodeSet import audit decisions wired in step F:
//   D-Q - `release_status` exposed on the public NodeView.
//   D-N - `<Extensions>` preserved verbatim and exposed on the views.
//   D-L - `HasNoPermissions` applied as an explicit empty role-permission set (and the latent
//          `.value()`-on-empty-optional throw is gone - every imported node now consults it).
//   D-K - the `<RequiredModel>` dependency loader is cycle-safe, deduped, bounded, null-safe.
//
// All drive the public facade (`try_parse_nodeset_sync` / `try_import_nodeset_sync`) against
// in-memory NodeSet XML, so they exercise the real parse + import code paths.

#include <gtest/gtest.h>

#include <deque>
#include <span>
#include <string_view>

#include "test_utilities.h"
#include "ua_address_space.h"
#include "ua_memory_stream.h"
#include "ua_nodeset_document.h"
#include "ua_nodeset_import.h"

#include <boost/asio/thread_pool.hpp>

using namespace ua;

namespace
{

// A Stream over a program-lifetime string_view. `MemoryStream` holds its device BY REFERENCE, so the
// device must outlive the stream - we park devices in a function-static deque (stable addresses,
// process lifetime). The XML fixtures are all static constexpr, so the spans stay valid too.
std::unique_ptr<Stream> make_stream(std::string_view xml)
{
  static std::deque<memory_stream_device::ExternalReadOnly> devices;
  devices.emplace_back(
    std::span<const std::byte>{reinterpret_cast<const std::byte*>(xml.data()), xml.size()});
  return std::make_unique<MemoryStream<memory_stream_device::ExternalReadOnly>>(devices.back());
}

shared_ptr<const NodeSetDocument> parse(std::string_view xml, NodeSetParseOptions options = {})
{
  auto stream = make_stream(xml);
  auto result = try_parse_nodeset_sync(*stream, std::move(options));
  EXPECT_TRUE(result.is_good()) << "parse failed: 0x" << std::hex
                                << static_cast<uint32_t>(result.status_code().value());
  return result.is_good() ? result.value() : nullptr;
}

// --- Fixtures ---------------------------------------------------------------------------------

// A Draft Variable carrying an <Extensions> block (D-Q + D-N).
constexpr std::string_view draftWithExtensions = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:audit</Uri></NamespaceUris>
  <UAVariable NodeId="ns=1;i=5000" BrowseName="1:DraftVar" DataType="i=6" ReleaseStatus="Draft">
    <Extensions><VendorTag xmlns="urn:vendor">payload-42</VendorTag></Extensions>
  </UAVariable>
</UANodeSet>
)";

// A node with <HasNoPermissions>true</HasNoPermissions> (D-L).
constexpr std::string_view hasNoPermissions = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:test:audit</Uri></NamespaceUris>
  <UAVariable NodeId="ns=1;i=5001" BrowseName="1:LockedVar" DataType="i=6">
    <HasNoPermissions>true</HasNoPermissions>
  </UAVariable>
</UANodeSet>
)";

// Two mutually-dependent nodesets (D-K cycle). A requires B; B requires A.
constexpr std::string_view cycleA = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:A</Uri></NamespaceUris>
  <Models>
    <Model ModelUri="urn:A" Version="1.0" PublicationDate="2020-01-01T00:00:00Z">
      <RequiredModel ModelUri="urn:B" Version="1.0" PublicationDate="2020-01-01T00:00:00Z"/>
    </Model>
  </Models>
</UANodeSet>
)";
constexpr std::string_view cycleB = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:B</Uri></NamespaceUris>
  <Models>
    <Model ModelUri="urn:B" Version="1.0" PublicationDate="2020-01-01T00:00:00Z">
      <RequiredModel ModelUri="urn:A" Version="1.0" PublicationDate="2020-01-01T00:00:00Z"/>
    </Model>
  </Models>
</UANodeSet>
)";

// A nodeset requiring a model the resolver cannot supply (D-K null/missing).
constexpr std::string_view requiresMissing = R"(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris><Uri>urn:needs</Uri></NamespaceUris>
  <Models>
    <Model ModelUri="urn:needs" Version="1.0" PublicationDate="2020-01-01T00:00:00Z">
      <RequiredModel ModelUri="urn:missing" Version="1.0" PublicationDate="2020-01-01T00:00:00Z"/>
    </Model>
  </Models>
</UANodeSet>
)";

}  // namespace

// --- D-Q --------------------------------------------------------------------------------------

TEST(NodeSetAuditDecisions, ReleaseStatusExposedOnNodeView)
{
  auto doc = parse(draftWithExtensions);
  ASSERT_NE(doc, nullptr);
  auto node = doc->find(NodeId{1, 5000u});
  ASSERT_TRUE(node.has_value());
  auto status = node->release_status();
  ASSERT_TRUE(status.has_value()) << "ReleaseStatus=\"Draft\" must surface on NodeView";
  EXPECT_EQ(*status, NodeReleaseStatus::Draft);
}

// --- D-N --------------------------------------------------------------------------------------

TEST(NodeSetAuditDecisions, ExtensionsPreservedOnNodeView)
{
  auto doc = parse(draftWithExtensions);
  ASSERT_NE(doc, nullptr);
  auto node = doc->find(NodeId{1, 5000u});
  ASSERT_TRUE(node.has_value());
  auto extensions = node->extensions();
  ASSERT_TRUE(extensions.has_value()) << "<Extensions> must be preserved on NodeView (D-N)";
  EXPECT_NE(std::string{extensions->value()}.find("payload-42"), std::string::npos)
    << "extensions content preserved verbatim, got: " << extensions->value();
}

TEST(NodeSetAuditDecisions, NoExtensionsYieldsEmptyOptional)
{
  auto doc = parse(hasNoPermissions);
  ASSERT_NE(doc, nullptr);
  auto node = doc->find(NodeId{1, 5001u});
  ASSERT_TRUE(node.has_value());
  EXPECT_FALSE(node->extensions().has_value()) << "a node without <Extensions> reports none";
  EXPECT_FALSE(node->release_status().has_value()) << "a node without ReleaseStatus reports none";
}

// --- D-L --------------------------------------------------------------------------------------

TEST(NodeSetAuditDecisions, HasNoPermissionsImportsCleanly)
{
  // Pre-fix, `Node::has_no_permissions()` called `.value()` on an empty optional for any node WITHOUT
  // the element - and the engine now consults it for every node - so this import would throw. The
  // node WITH <HasNoPermissions>true</HasNoPermissions> also gets an explicit empty permission set.
  boost::asio::thread_pool pool{2};
  // Create the AddressSpace with the fixture's own namespace URI so the file's ns=1 maps to the
  // server's ns=1 - no namespace_factory needed to allocate it.
  auto addressSpace = AddressSpace::create("urn:test:audit", pool.get_executor());

  auto stream = make_stream(hasNoPermissions);
  NodeSetImportOptions options;
  auto result = try_import_nodeset_sync(addressSpace, *stream, std::move(options));
  EXPECT_TRUE(result.is_good()) << "import of a HasNoPermissions node must not throw; status 0x" << std::hex
                                << static_cast<uint32_t>(result.status_code().value());

  pool.join();
}

// --- D-K --------------------------------------------------------------------------------------

TEST(NodeSetAuditDecisions, RequiredModelCycleTerminates)
{
  // A<->B mutual dependency. The pre-fix recursive loader would recurse until the stack overflowed;
  // the cycle-safe loader loads each once and terminates.
  NodeSetParseOptions options;
  options.resolveRequiredModel = [](const ModelRef& ref) -> std::unique_ptr<Stream>
  {
    if (ref.uri == String{"urn:B"})
    {
      return make_stream(cycleB);
    }
    if (ref.uri == String{"urn:A"})
    {
      return make_stream(cycleA);
    }
    return nullptr;
  };

  auto stream = make_stream(cycleA);
  auto result = try_parse_nodeset_sync(*stream, std::move(options));
  EXPECT_TRUE(result.is_good()) << "a RequiredModel cycle must terminate, not recurse forever; 0x" << std::hex
                                << static_cast<uint32_t>(result.status_code().value());
}

TEST(NodeSetAuditDecisions, MissingRequiredModelIsCleanError)
{
  // The resolver returns null for the dependency. Pre-fix this dereferenced a null stream (UB/crash);
  // now it is a clean Result error.
  NodeSetParseOptions options;
  options.resolveRequiredModel = [](const ModelRef&) -> std::unique_ptr<Stream>
  {
    return nullptr;
  };

  auto stream = make_stream(requiresMissing);
  auto result = try_parse_nodeset_sync(*stream, std::move(options));
  ASSERT_TRUE(result.is_bad()) << "a missing RequiredModel must be a clean error, not a crash";
  const auto* detail = result.status_code().detail();
  ASSERT_NE(detail, nullptr);
  EXPECT_NE(
    ::ua::test_utils::error_context(detail, ua::ContextKeys::namespaceUri.value()).find("urn:missing"),
    std::string::npos)
    << "error should name the missing model in the namespace.uri context, got summary: " << detail->summary;
}
