// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <boost/asio/thread_pool.hpp>
#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_address_space.h"
#include "ua_argument.h"
#include "ua_default_namespace.h"
#include "ua_file_stream.h"
#include "ua_structure_factory.h"
#include "ua_nodeset_import.h"
#include "ua_nodeset_import_engine.h"
#include "ua_nodeset_parser.h"

using namespace ua;
using namespace ua::xml::nodeset;

namespace
{

// D-R: NamespaceFactory is a callable. A test factory is just a lambda that creates a default_ns
// namespace for the requested URI.
NamespaceFactory make_test_namespace_factory(boost::asio::any_io_executor executor)
{
  return [executor = std::move(executor)](string_view uri) -> shared_ptr<Namespace>
  {
    return default_ns::Namespace::create(uri, executor);
  };
}

}  // namespace

TEST(XmlNodeSetImporterTranslationTests, TranslatesNodeIdQualifiedNameReferencesAndDataType)
{
  // Minimal, synthetic nodeset that uses a custom namespace (ns=1) to prove translation.
  static constexpr string_view customUri = "urn:example:custom";
  static constexpr string_view otherUri = "urn:example:other";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;

  FileStream inputStream{"MultiNamespaceFixture.NodeSet2.xml"};
  inputStream.open_for_read();

  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto nodeSets = Parser::parse(limits,
    inputStream,
    structureFactory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    Parser::GetDependentModelCallback{});

  ASSERT_EQ(nodeSets.size(), 1);

  auto factory = make_test_namespace_factory(tp.get_executor());
  auto importer = ImportEngine::create(limits, addressSpace, nodeSets, factory);
  importer->import_all_sync({}, {});

  const auto importedNsIndex = addressSpace.namespace_array().get_namespace_index(customUri);
  ASSERT_NE(importedNsIndex, 0);

  const auto otherNsIndex = addressSpace.namespace_array().get_namespace_index(otherUri);
  ASSERT_NE(otherNsIndex, 0);
  ASSERT_NE(otherNsIndex, importedNsIndex);

  const NodeId objectId{importedNsIndex, 5001u};
  const NodeId varId{importedNsIndex, 5002u};
  const NodeId dataTypeId{importedNsIndex, 6001u};

  const NodeId otherObjectId{otherNsIndex, 7001u};
  const NodeId otherVarId{otherNsIndex, 7002u};

  {
    auto objResult = addressSpace.try_find_sync<ObjectAccessor>(objectId);
    ASSERT_TRUE(objResult.is_good());
    auto& obj = objResult.value();
    ASSERT_EQ(obj.get_node_id(), objectId);

    const QualifiedName expectedBrowseName{importedNsIndex, "MyObject"};
    ASSERT_EQ(obj.get_browse_name(), expectedBrowseName);

    bool hasComponentRef = false;
    bool hasOtherComponentRef = false;
    for (const auto& ref : obj.get_references_sync())
    {
      const auto targetId = ref.target_id();
      if (ref.is_forward() && ref.type_id() == NodeId{ReferenceTypeId::HasComponent} && targetId.is_local() &&
          targetId.node_id() == varId)
      {
        hasComponentRef = true;
        continue;
      }

      if (ref.is_forward() && ref.type_id() == NodeId{ReferenceTypeId::HasComponent} && targetId.is_local() &&
          targetId.node_id() == otherVarId)
      {
        hasOtherComponentRef = true;
      }
    }
    ASSERT_TRUE(hasComponentRef);
    ASSERT_TRUE(hasOtherComponentRef);
  }

  {
    auto varResult = addressSpace.try_find_sync<VariableAccessor>(varId);
    ASSERT_TRUE(varResult.is_good());
    auto& var = varResult.value();
    ASSERT_EQ(var.get_node_id(), varId);

    const QualifiedName expectedBrowseName{importedNsIndex, "MyVar"};
    ASSERT_EQ(var.get_browse_name(), expectedBrowseName);
    ASSERT_EQ(var.get_data_type(), NodeId{DataTypeId::NodeId});

    // Value contains a NodeId using NodeSet-local ns index (ns=1) and must be translated.
    auto dvResult = var.try_read_value_sync();
    ASSERT_TRUE(dvResult.is_good());
    const auto& dv = dvResult.value();
    ASSERT_FALSE(dv.value().empty());
    const auto embedded = dv.value().template as<NodeId>();
    ASSERT_EQ(embedded.identifier().get_numeric(), 5001u);
    ASSERT_EQ(embedded.namespace_index(), importedNsIndex);
  }

  {
    auto otherObjResult = addressSpace.try_find_sync<ObjectAccessor>(otherObjectId);
    ASSERT_TRUE(otherObjResult.is_good());
    auto& otherObj = otherObjResult.value();
    ASSERT_EQ(otherObj.get_node_id(), otherObjectId);

    const QualifiedName expectedBrowseName{otherNsIndex, "OtherObject"};
    ASSERT_EQ(otherObj.get_browse_name(), expectedBrowseName);
  }

  {
    auto otherVarResult = addressSpace.try_find_sync<VariableAccessor>(otherVarId);
    ASSERT_TRUE(otherVarResult.is_good());
    auto& otherVar = otherVarResult.value();
    ASSERT_EQ(otherVar.get_node_id(), otherVarId);

    const QualifiedName expectedBrowseName{otherNsIndex, "OtherVar"};
    ASSERT_EQ(otherVar.get_browse_name(), expectedBrowseName);
    ASSERT_EQ(otherVar.get_data_type(), NodeId{DataTypeId::NodeId});

    auto dvResult2 = otherVar.try_read_value_sync();
    ASSERT_TRUE(dvResult2.is_good());
    const auto& dv2 = dvResult2.value();
    ASSERT_FALSE(dv2.value().empty());
    const auto embedded = dv2.value().template as<NodeId>();
    ASSERT_EQ(embedded.identifier().get_numeric(), 7001u);
    ASSERT_EQ(embedded.namespace_index(), otherNsIndex);
  }
  ::ua::test_utils::drain_with_timeout(tp);
}

// Motivating gap for translate-at-source: a NodeId embedded inside a STRUCTURE
// value field. The old post-decode `translate_variant` walk enumerated only
// top-level containers (scalars, arrays, DataValue) and never recursed into
// structure fields, so a struct-embedded id was written with its file-local
// namespace index. Decoding with the importer's translation config translates
// the id as it is decoded, transitively through the structure.
TEST(XmlNodeSetImporterTranslationTests, TranslatesNodeIdInsideStructureValueField)
{
  static constexpr string_view customUri = "urn:example:custom";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());

  // Argument carries a NodeId-typed `DataType` field; register it so the value decodes.
  StructureFactory structureFactory;
  structureFactory.register_type(
    NodeId{Argument::defaultXmlEncodingId}, []() { return make_unique<Argument>(); });

  FileStream inputStream{"StructValueTranslationFixture.NodeSet2.xml"};
  inputStream.open_for_read();

  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto nodeSets = Parser::parse(limits,
    inputStream,
    structureFactory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    Parser::GetDependentModelCallback{});

  ASSERT_EQ(nodeSets.size(), 1);

  auto factory = make_test_namespace_factory(tp.get_executor());
  auto importer = ImportEngine::create(limits, addressSpace, nodeSets, factory);
  importer->import_all_sync({}, {});

  const auto importedNsIndex = addressSpace.namespace_array().get_namespace_index(customUri);
  ASSERT_NE(importedNsIndex, 0);
  // Falsifiability: the file-local index of urn:example:custom is 1. The server index must
  // differ, otherwise asserting == importedNsIndex below could not distinguish a translated id
  // from an untranslated (file-local) one.
  ASSERT_NE(importedNsIndex, 1);

  const NodeId structVarId{importedNsIndex, 5003u};
  auto varResult = addressSpace.try_find_sync<VariableAccessor>(structVarId);
  ASSERT_TRUE(varResult.is_good());
  auto& var = varResult.value();

  auto dvResult = var.try_read_value_sync();
  ASSERT_TRUE(dvResult.is_good());
  const auto& dv = dvResult.value();
  ASSERT_TRUE(dv.value().is_structure());

  const auto* argument = dynamic_cast<const Argument*>(&dv.value().as<Structure>());
  ASSERT_NE(argument, nullptr);
  EXPECT_EQ(argument->name(), "EmbeddedField");

  // The struct-embedded DataType id (ns=1;i=6001 file-local) must carry the SERVER index.
  EXPECT_EQ(argument->data_type().namespace_index(), importedNsIndex);
  EXPECT_EQ(argument->data_type().identifier().get_numeric(), 6001u);

  ::ua::test_utils::drain_with_timeout(tp);
}

// P3: RolePermissions role ids are structural ids and must be translated from the
// NodeSet-local namespace to the server namespace at the write boundary. A custom-namespace
// role would otherwise be written with its file-local index and never match a server role
// node; a well-known NS0 role must remain a no-op.
TEST(XmlNodeSetImporterTranslationTests, TranslatesCustomNamespaceRolePermissionRoleId)
{
  static constexpr string_view rolesUri = "urn:example:roles";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;

  FileStream inputStream{"RolePermissionTranslationFixture.NodeSet2.xml"};
  inputStream.open_for_read();

  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto nodeSets = Parser::parse(limits,
    inputStream,
    structureFactory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    Parser::GetDependentModelCallback{});

  ASSERT_EQ(nodeSets.size(), 1);

  auto factory = make_test_namespace_factory(tp.get_executor());
  auto importer = ImportEngine::create(limits, addressSpace, nodeSets, factory);
  importer->import_all_sync({}, {});

  const auto rolesNsIndex = addressSpace.namespace_array().get_namespace_index(rolesUri);
  ASSERT_NE(rolesNsIndex, 0);
  // Falsifiability: the file-local index is 1; the server index must differ.
  ASSERT_NE(rolesNsIndex, 1);

  const NodeId guardedObjectId{rolesNsIndex, 5001u};
  auto objResult = addressSpace.try_find_sync<ObjectAccessor>(guardedObjectId);
  ASSERT_TRUE(objResult.is_good());
  auto& obj = objResult.value();

  const auto rolePermissions = obj.get_role_permissions();
  ASSERT_TRUE(rolePermissions.has_value());
  ASSERT_EQ(rolePermissions->size(), 3u);

  // The custom-namespace role id carries the SERVER index.
  const NodeId expectedCustomRole{rolesNsIndex, 100u};
  // The well-known NS0 role id is untouched.
  const NodeId expectedWellKnownRole{0, 15656u};

  bool sawCustomRole = false;
  bool sawWellKnownRole = false;
  for (const auto& rolePermission : *rolePermissions)
  {
    if (rolePermission.role_id() == expectedCustomRole)
    {
      sawCustomRole = true;
    }
    else if (rolePermission.role_id() == expectedWellKnownRole)
    {
      sawWellKnownRole = true;
    }
  }
  EXPECT_TRUE(sawCustomRole) << "custom-namespace role id was not translated to the server index";
  EXPECT_TRUE(sawWellKnownRole) << "well-known NS0 role id should be a no-op";

  ::ua::test_utils::drain_with_timeout(tp);
}

namespace
{

LocalizedText read_display_name_from_node(const ua::NodeAccessor& accessor)
{
  auto variant = accessor.read_attribute(AttributeId::DisplayName);
  if (variant.empty() || !variant.is_localized_text())
  {
    return {};
  }
  return variant.as<LocalizedText>();
}

}  // namespace

TEST(XmlNodeSetImporterTranslationTests, MultipleDisplayNameTranslationsProduceAggregateLocalizedText)
{
  static constexpr string_view translationsUri = "urn:example:translations";

  boost::asio::thread_pool tp{1};
  auto addressSpace = AddressSpace::create("", tp.get_executor());
  StructureFactory structureFactory;

  FileStream inputStream{"MultiTranslationFixture.NodeSet2.xml"};
  inputStream.open_for_read();

  const auto cfg = ApplicationConfig::load_default();
  const auto limits = make_encoding_limits(cfg);

  auto nodeSets = Parser::parse(limits,
    inputStream,
    structureFactory,
    addressSpace.namespace_array(),
    addressSpace.server_array(),
    Parser::GetDependentModelCallback{});

  ASSERT_EQ(nodeSets.size(), 1);

  auto factory = make_test_namespace_factory(tp.get_executor());
  auto importer = ImportEngine::create(limits, addressSpace, nodeSets, factory);
  importer->import_all_sync({}, {});

  const auto nsIndex = addressSpace.namespace_array().get_namespace_index(translationsUri);
  ASSERT_NE(nsIndex, 0);

  const NodeId objectId{nsIndex, 5001u};
  auto objResult = addressSpace.try_find_sync<ObjectAccessor>(objectId);
  ASSERT_TRUE(objResult.is_good()) << "Node ns=" << nsIndex << ";i=5001 not found";
  auto& obj = objResult.value();

  const auto displayName = read_display_name_from_node(obj);

  // The imported node had three <DisplayName> elements with distinct locales,
  // so the stored LocalizedText must be an aggregate carrying all three.
  EXPECT_TRUE(displayName.is_aggregate());
  EXPECT_EQ(displayName.translation_count(), 3u);

  // Verify each translation is retrievable by locale.
  EXPECT_EQ(displayName.text_for_locale("en-US"), "English Name");
  EXPECT_EQ(displayName.text_for_locale("de-DE"), "Deutscher Name");
  EXPECT_EQ(displayName.text_for_locale("fr-FR"), "Nom Fran\u00e7ais");

  // Resolve with a matching locale list picks the correct translation.
  {
    const std::vector<LocaleId> enLocales{LocaleId{"en-US"}};
    const auto resolved = displayName.resolve(enLocales);
    EXPECT_TRUE(resolved.is_scalar());
    EXPECT_EQ(resolved.text(), "English Name");
  }
  {
    const std::vector<LocaleId> deLocales{LocaleId{"de-DE"}};
    const auto resolved = displayName.resolve(deLocales);
    EXPECT_TRUE(resolved.is_scalar());
    EXPECT_EQ(resolved.text(), "Deutscher Name");
  }
  {
    const std::vector<LocaleId> frLocales{LocaleId{"fr-FR"}};
    const auto resolved = displayName.resolve(frLocales);
    EXPECT_TRUE(resolved.is_scalar());
    EXPECT_EQ(resolved.text(), "Nom Fran\u00e7ais");
  }

  // Resolve with an unmatched locale falls back to the first-inserted entry.
  {
    const std::vector<LocaleId> jpLocales{LocaleId{"ja-JP"}};
    const auto resolved = displayName.resolve(jpLocales);
    EXPECT_TRUE(resolved.is_scalar());
    EXPECT_EQ(resolved.text(), "English Name");
  }
  ::ua::test_utils::drain_with_timeout(tp);
}
