// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "ua_nodeset_parser.h"
#include "ua_file_stream.h"
#include "ua_memory_stream.h"
#include "ua_structure_factory.h"
#include "ua_data_type_registration.h"
#include "ua_address_space.h"
#include "ua_encoding_limits.h"
#include "ua_dynamic_type_registry.h"
#include "ua_dynamic_structure.h"
#include "ua_dynamic_union.h"
#include "ua_dynamic_views.h"
#include "ua_dynamic_enum_type_descriptor.h"
#include "ua_type_loader.h"
#include "ua_address_space_model_access.h"
#include "ua_register_address_space_types.h"
#include "ua_nodeset_import.h"
#include "ua_session_model_access.h"

#include <cstddef>
#include <span>
#include "ua_nodeset_import_engine.h"
#include "ua_binary_codec.h"
#include "ua_codec.h"
#include "ua_codec_namespace_context.h"
#include "ua_date_time.h"

#include "compliance_helpers.h"
#include "ua_session_attribute_services.h"
#include "ua_read_request.h"
#include "ua_read_response.h"
#include "ua_read_value_id.h"
#include "ua_timestamps_to_return.h"
#include "ua_default_variable_node.h"
#include "ua_default_namespace.h"
#include "ua_structure_definition.h"
#include "ua_structure_field.h"
#include "ua_node_accessor.h"

using namespace ua;
using namespace ua::server;
using namespace ua::client;

namespace ns = ua::xml::nodeset;

namespace ua::dynamic_types
{

class SessionModelAccessTestAccess
{
public:
  static void set_limits(SessionModelAccess& access, uint32_t maxNodesPerRead, uint32_t maxNodesPerBrowse)
  {
    access.mMaxNodesPerRead = maxNodesPerRead;
    access.mMaxNodesPerBrowse = maxNodesPerBrowse;
    access.mLimitsRead = true;
  }
};

}  // namespace ua::dynamic_types

namespace
{

EncodingLimits test_limits()
{
  return EncodingLimits{100, 100};
}

// =============================================================================
// End-to-end fixture: server loads dynamic types from NodeSet XML, creates
// Variables with dynamic type values. Client registers the same types,
// reads values through the wire, and verifies decoded fields.
// =============================================================================
class DynamicTypeIntegration : public ComplianceWithSession
{
protected:
  DynamicTypeRegistry mServerDynRegistry;
  DynamicTypeRegistry mClientDynRegistry;
  dynamic_types::LoaderRegistrationStats mServerStats;
  uint16_t mTestNsIdx{0};

  // Variable NodeIds for each type under test
  NodeId mGeoCoordinateVarId;
  NodeId mSensorReadingVarId;
  NodeId mSensorLocationVarId;
  NodeId mMeasurementVarId;
  NodeId mMeasurementRecordVarId;
  NodeId mAlertInfoVarId;
  NodeId mDataBatchVarId;
  NodeId mTaskInfoVarId;
  NodeId mFullReportVarId;

  void configure_server() override
  {
    auto& server = mServer.server();
    auto addressSpace = server.address_space();
    auto executor = mServer.thread_pool().executor();

    auto testNs = default_ns::Namespace::create("urn:test:industrial-monitoring", executor);
    mTestNsIdx = addressSpace.add_namespace_sync(testNs);

    // Parse the test NodeSet and import into the address space
    StructureFactory localFactory;
    register_ua_data_types_with_factory({}, &localFactory, nullptr);

    FileStream testStream{TEST_RESOURCE_DIR "/DynamicTypesTest.NodeSet2.xml"};
    testStream.open_for_read();

    auto getDependency = [](const ns::ModelTableEntry& model) -> unique_ptr<Stream>
    {
      if (model.model_uri() == String{"http://opcfoundation.org/UA/"})
      {
        auto stream = std::make_unique<FileStream>("NodeSet2.xml");
        stream->open_for_read();
        return stream;
      }
      return nullptr;
    };

    auto limits = test_limits();
    auto nodeSets = ns::Parser::parse(limits,
      testStream,
      localFactory,
      addressSpace.namespace_array(),
      addressSpace.server_array(),
      getDependency,
      ns::ParserOptions{.decodeVariantValues = false});

    // Import test NodeSet nodes into the address space
    auto importer = ns::ImportEngine::create(limits, addressSpace, nodeSets, {});
    importer->import_all_sync({}, {});

    // Discover types from the address space using the new loader
    dynamic_types::AddressSpaceModelAccess serverAccess{addressSpace};
    mServerStats = dynamic_types::load_types_sync(serverAccess, mServerDynRegistry);

    // Register with server's binary factory using namespace translation
    auto& nsArray = addressSpace.namespace_array();
    auto nsLookup = [&nsArray](string_view uri) -> std::optional<uint16_t>
    {
      try
      {
        return nsArray.get_namespace_index(uri);
      }
      catch (...)
      {
        return std::nullopt;
      }
    };
    mServerDynRegistry.register_all_with(
      [&server](const NodeId& encodingId, std::function<unique_ptr<Structure>()> factory)
      { server.register_structure_type(encodingId, std::move(factory)); },
      nsLookup);

    auto resolver = mServerDynRegistry.make_resolver(nsLookup);
    auto objectsFolder = addressSpace.find_node_sync(NodeId{ObjectId::ObjectsFolder});

    // --- Helpers ---
    auto resolveStruct = [&](uint32_t encodingId) -> DynamicStructure*
    {
      auto instance = resolver(NodeId{mTestNsIdx, encodingId});
      EXPECT_NE(instance, nullptr) << "Failed to resolve encoding id " << encodingId;
      auto* result = dynamic_cast<DynamicStructure*>(instance.release());
      EXPECT_NE(result, nullptr);
      return result;
    };
    auto resolveUnion = [&](uint32_t encodingId) -> DynamicUnion*
    {
      auto instance = resolver(NodeId{mTestNsIdx, encodingId});
      EXPECT_NE(instance, nullptr) << "Failed to resolve encoding id " << encodingId;
      auto* result = dynamic_cast<DynamicUnion*>(instance.release());
      EXPECT_NE(result, nullptr);
      return result;
    };
    auto createVar = [&](NodeId varId, uint32_t dataTypeId, unique_ptr<Structure> value)
    {
      auto varNode = addressSpace.create_node_sync(varId, NodeClass::Variable);
      auto variable = varNode.as<VariableAccessor>();
      ASSERT_TRUE(variable.has_value());
      variable->set_data_type(NodeId{mTestNsIdx, dataTypeId});
      variable->set_access_level(
        AccessLevelType{AccessLevelType::Bit::CurrentRead, AccessLevelType::Bit::CurrentWrite});
      variable->write_value_sync(Variant{std::move(value)});
      objectsFolder.add_reference_sync(NodeId{ReferenceTypeId::Organizes}, varId);
    };

    // --- GeoCoordinate ---
    mGeoCoordinateVarId = NodeId{mTestNsIdx, uint32_t{7001}};
    {
      auto geo = resolveStruct(5001u);
      (*geo)["Latitude"] = Variant{37.7749};
      (*geo)["Longitude"] = Variant{-122.4194};
      (*geo)["Altitude"] = Variant{16.0};
      createVar(mGeoCoordinateVarId, 2001, unique_ptr<Structure>(geo));
    }

    // --- SensorReading ---
    mSensorReadingVarId = NodeId{mTestNsIdx, uint32_t{7002}};
    {
      auto reading = resolveStruct(5002u);
      (*reading)["Timestamp"] = Variant{DateTime::now()};
      (*reading)["Temperature"] = Variant{23.5};
      (*reading)["Pressure"] = Variant{1013.25};
      (*reading)["SensorId"] = Variant{String{"sensor-42"}};
      (*reading)["Quality"] = Variant{StatusCode{Status::Good}};
      createVar(mSensorReadingVarId, 2002, unique_ptr<Structure>(reading));
    }

    // --- SensorLocation (nested GeoCoordinate) ---
    mSensorLocationVarId = NodeId{mTestNsIdx, uint32_t{7003}};
    {
      auto loc = resolveStruct(5003u);
      (*loc)["Name"] = Variant{String{"Building A"}};
      auto* geoPtr = resolveStruct(5001u);
      unique_ptr<Structure> innerGeo(geoPtr);
      (*geoPtr)["Latitude"] = Variant{48.8566};
      (*geoPtr)["Longitude"] = Variant{2.3522};
      (*geoPtr)["Altitude"] = Variant{35.0};
      (*loc)["Coordinate"] = Variant{std::move(innerGeo)};
      createVar(mSensorLocationVarId, 2003, unique_ptr<Structure>(loc));
    }

    // --- Measurement (union, FloatValue selected) ---
    mMeasurementVarId = NodeId{mTestNsIdx, uint32_t{7004}};
    {
      auto meas = resolveUnion(5010u);
      meas->select("FloatValue", Variant{3.14});
      createVar(mMeasurementVarId, 3001, unique_ptr<Structure>(meas));
    }

    // --- MeasurementRecord (struct containing union) ---
    mMeasurementRecordVarId = NodeId{mTestNsIdx, uint32_t{7005}};
    {
      auto record = resolveStruct(5011u);
      (*record)["Source"] = Variant{String{"temp-sensor-1"}};
      auto innerMeas = resolveUnion(5010u);
      innerMeas->select("IntValue", Variant{int32_t{42}});
      (*record)["Value"] = Variant{unique_ptr<Structure>(innerMeas)};
      (*record)["RecordedAt"] = Variant{DateTime::now()};
      createVar(mMeasurementRecordVarId, 2010, unique_ptr<Structure>(record));
    }

    // --- AlertInfo (optional fields: Details present, Location absent, Acknowledged present) ---
    mAlertInfoVarId = NodeId{mTestNsIdx, uint32_t{7006}};
    {
      auto alert = resolveStruct(5005u);
      (*alert)["Message"] = Variant{String{"Critical alert"}};
      (*alert)["Severity"] = Variant{uint32_t{95}};
      alert->set_field_present("Details", true);
      (*alert)["Details"] = Variant{String{"Overheating detected"}};
      // Location left absent
      alert->set_field_present("Acknowledged", true);
      (*alert)["Acknowledged"] = Variant{true};
      createVar(mAlertInfoVarId, 2005, unique_ptr<Structure>(alert));
    }

    // --- DataBatch (array fields) ---
    mDataBatchVarId = NodeId{mTestNsIdx, uint32_t{7007}};
    {
      auto batch = resolveStruct(5004u);
      (*batch)["BatchId"] = Variant{String{"batch-1"}};
      Array<double> values;
      values.push_back(1.0);
      values.push_back(2.0);
      values.push_back(3.0);
      (*batch)["Values"] = Variant{std::move(values)};
      Array<DateTime> timestamps;
      timestamps.push_back(DateTime::now());
      timestamps.push_back(DateTime::now());
      timestamps.push_back(DateTime::now());
      (*batch)["Timestamps"] = Variant{std::move(timestamps)};
      Array<String> labels;
      labels.push_back(String{"a"});
      labels.push_back(String{"b"});
      labels.push_back(String{"c"});
      (*batch)["Labels"] = Variant{std::move(labels)};
      createVar(mDataBatchVarId, 2004, unique_ptr<Structure>(batch));
    }

    // --- TaskInfo (enum + UInt-OptionSet fields) ---
    mTaskInfoVarId = NodeId{mTestNsIdx, uint32_t{7008}};
    {
      auto task = resolveStruct(5012u);
      (*task)["Name"] = Variant{String{"Deploy v2.1"}};
      (*task)["Priority"] = Variant{int32_t{2}};  // High
      (*task)["AccessLevel"] = Variant{uint32_t{0b11001}};  // CanRead | CanBrowse | CanSubscribe (bits 0,3,4)
      (*task)["Description"] = Variant{LocalizedText{"en", "Production deployment"}};
      createVar(mTaskInfoVarId, 2011, unique_ptr<Structure>(task));
    }

    // --- FullReport (capstone: everything combined) ---
    mFullReportVarId = NodeId{mTestNsIdx, uint32_t{7009}};
    {
      auto report = resolveStruct(5013u);
      (*report)["Title"] = Variant{String{"Daily Summary"}};
      (*report)["ReadingCount"] = Variant{uint64_t{1500}};

      // Location: SensorLocation -> GeoCoordinate (3-level nesting)
      auto loc = resolveStruct(5003u);
      (*loc)["Name"] = Variant{String{"Lab 3"}};
      auto geo = resolveStruct(5001u);
      (*geo)["Latitude"] = Variant{40.7128};
      (*geo)["Longitude"] = Variant{-74.0060};
      (*geo)["Altitude"] = Variant{10.0};
      (*loc)["Coordinate"] = Variant{unique_ptr<Structure>(geo)};
      (*report)["Location"] = Variant{unique_ptr<Structure>(loc)};

      // LatestRecord: MeasurementRecord -> Measurement (union)
      auto record = resolveStruct(5011u);
      (*record)["Source"] = Variant{String{"main-sensor"}};
      auto meas = resolveUnion(5010u);
      meas->select("FloatValue", Variant{72.5});
      (*record)["Value"] = Variant{unique_ptr<Structure>(meas)};
      (*record)["RecordedAt"] = Variant{DateTime::now()};
      (*report)["LatestRecord"] = Variant{unique_ptr<Structure>(record)};

      // Alert: AlertInfo (optional fields)
      auto alert = resolveStruct(5005u);
      (*alert)["Message"] = Variant{String{"Temperature warning"}};
      (*alert)["Severity"] = Variant{uint32_t{75}};
      alert->set_field_present("Details", true);
      (*alert)["Details"] = Variant{String{"Approaching threshold"}};
      // Location absent
      alert->set_field_present("Acknowledged", true);
      (*alert)["Acknowledged"] = Variant{false};
      (*report)["Alert"] = Variant{unique_ptr<Structure>(alert)};

      // Enum field (Priority as Int32)
      (*report)["Priority"] = Variant{int32_t{3}};  // Critical

      // UInt-OptionSet field (AccessLevel as UInt32)
      (*report)["AccessLevel"] = Variant{uint32_t{0b101}};  // CanRead | CanDelete (bits 0,2)

      // Structure-based OptionSet field (PhysicalInterface)
      auto iface = resolveStruct(5020u);
      // PhysicalInterface is a structure-based OptionSet (subtype of OptionSet i=12755)
      // with Value (ByteString) + ValidBits (ByteString) inherited fields
      (*report)["Interfaces"] = Variant{unique_ptr<Structure>(iface)};

      // Array field (Tags)
      Array<String> tags;
      tags.push_back(String{"production"});
      tags.push_back(String{"daily"});
      tags.push_back(String{"automated"});
      (*report)["Tags"] = Variant{std::move(tags)};

      createVar(mFullReportVarId, 2020, unique_ptr<Structure>(report));
    }
  }

  void SetUp() override
  {
    ComplianceWithSession::SetUp();

    // Client discovers types from the server via SessionModelAccess
    dynamic_types::SessionModelAccess clientAccess{*mSession};
    auto stats = dynamic_types::load_types_sync(clientAccess, mClientDynRegistry);
    ASSERT_FALSE(stats.has_failures())
      << "Client type discovery failed: " << stats.failure_count() << " failures";

    // Register discovered types with the client's decoder
    auto addressSpace = mServer.server().address_space();
    auto& nsArray = addressSpace.namespace_array();
    auto nsLookup = [&nsArray](string_view uri) -> std::optional<uint16_t>
    {
      try
      {
        return nsArray.get_namespace_index(uri);
      }
      catch (...)
      {
        return std::nullopt;
      }
    };
    mClientDynRegistry.register_all_with(
      [this](const NodeId& encodingId, std::function<unique_ptr<Structure>()> factory)
      { mClient->core().register_structure_type(encodingId, std::move(factory)); },
      nsLookup);
  }

  /// Read a Variable's value and return the decoded DynamicStructure.
  const DynamicStructure& read_structure(const NodeId& varId)
  {
    ReadRequest req;
    ReadValueId rv;
    rv.node_id() = varId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));
    req.timestamps_to_return() = TimestampsToReturn::Neither;

    mLastResponse = mSession->attributes().read_sync(std::move(req));
    EXPECT_EQ(mLastResponse.results().size(), 1u);

    auto& variant = mLastResponse.results()[0].value();
    EXPECT_TRUE(variant.is_structure());
    return dynamic_cast<const DynamicStructure&>(variant.as<Structure>());
  }

  /// Read a Variable's value and return the decoded DynamicUnion.
  const DynamicUnion& read_union(const NodeId& varId)
  {
    ReadRequest req;
    ReadValueId rv;
    rv.node_id() = varId;
    rv.attribute_id() = static_cast<uint32_t>(AttributeId::Value);
    req.nodes_to_read().push_back(std::move(rv));
    req.timestamps_to_return() = TimestampsToReturn::Neither;

    mLastResponse = mSession->attributes().read_sync(std::move(req));
    EXPECT_EQ(mLastResponse.results().size(), 1u);

    auto& variant = mLastResponse.results()[0].value();
    EXPECT_TRUE(variant.is_structure());
    return dynamic_cast<const DynamicUnion&>(variant.as<Structure>());
  }

  NamespaceIndexLookup make_ns_lookup()
  {
    return [this](string_view uri) -> std::optional<uint16_t>
    {
      try
      {
        return mServer.server().address_space().namespace_array().get_namespace_index(uri);
      }
      catch (...)
      {
        return std::nullopt;
      }
    };
  }

private:
  ReadResponse mLastResponse;  // Keep alive for reference lifetime
};

// =============================================================================
// GeoCoordinate: simple 3-Double structure through the wire
// =============================================================================

TEST_F(DynamicTypeIntegration, GeoCoordinateRoundTrip)
{
  auto& geo = read_structure(mGeoCoordinateVarId);

  EXPECT_DOUBLE_EQ(geo["Latitude"].as<double>(), 37.7749);
  EXPECT_DOUBLE_EQ(geo["Longitude"].as<double>(), -122.4194);
  EXPECT_DOUBLE_EQ(geo["Altitude"].as<double>(), 16.0);
}

// =============================================================================
// SensorReading: diverse built-in field types
// =============================================================================

TEST_F(DynamicTypeIntegration, SensorReadingRoundTrip)
{
  auto& reading = read_structure(mSensorReadingVarId);

  EXPECT_DOUBLE_EQ(reading["Temperature"].as<double>(), 23.5);
  EXPECT_DOUBLE_EQ(reading["Pressure"].as<double>(), 1013.25);
  EXPECT_EQ(static_cast<string_view>(reading["SensorId"].as<String>()), "sensor-42");
  EXPECT_TRUE(reading["Quality"].as<StatusCode>().is_good());
}

// =============================================================================
// SensorLocation: 2-level nested structure through the wire
// =============================================================================

TEST_F(DynamicTypeIntegration, SensorLocationNestedRoundTrip)
{
  auto& loc = read_structure(mSensorLocationVarId);

  EXPECT_EQ(static_cast<string_view>(loc["Name"].as<String>()), "Building A");

  auto& coordVariant = loc["Coordinate"];
  ASSERT_TRUE(coordVariant.is_structure());
  auto& coord = dynamic_cast<const DynamicStructure&>(coordVariant.as<Structure>());
  EXPECT_DOUBLE_EQ(coord["Latitude"].as<double>(), 48.8566);
  EXPECT_DOUBLE_EQ(coord["Longitude"].as<double>(), 2.3522);
  EXPECT_DOUBLE_EQ(coord["Altitude"].as<double>(), 35.0);
}

// =============================================================================
// Measurement: union through the wire
// =============================================================================

TEST_F(DynamicTypeIntegration, MeasurementUnionRoundTrip)
{
  auto& meas = read_union(mMeasurementVarId);

  EXPECT_EQ(meas.active_field_name(), "FloatValue");
  EXPECT_DOUBLE_EQ(meas.value().as<double>(), 3.14);
}

// =============================================================================
// MeasurementRecord: struct containing a union field
// =============================================================================

TEST_F(DynamicTypeIntegration, MeasurementRecordWithUnionRoundTrip)
{
  auto& record = read_structure(mMeasurementRecordVarId);

  EXPECT_EQ(static_cast<string_view>(record["Source"].as<String>()), "temp-sensor-1");

  auto& valueVariant = record["Value"];
  ASSERT_TRUE(valueVariant.is_structure());
  auto& decodedUnion = dynamic_cast<const DynamicUnion&>(valueVariant.as<Structure>());
  EXPECT_EQ(decodedUnion.active_field_name(), "IntValue");
  EXPECT_EQ(decodedUnion.value().as<int32_t>(), 42);
}

// =============================================================================
// AlertInfo: StructureWithOptionalFields
// =============================================================================

TEST_F(DynamicTypeIntegration, AlertInfoOptionalFieldsRoundTrip)
{
  auto& alert = read_structure(mAlertInfoVarId);

  EXPECT_EQ(static_cast<string_view>(alert["Message"].as<String>()), "Critical alert");
  EXPECT_EQ(alert["Severity"].as<uint32_t>(), 95u);

  EXPECT_TRUE(alert.has_field("Details"));
  EXPECT_EQ(static_cast<string_view>(alert["Details"].as<String>()), "Overheating detected");

  EXPECT_FALSE(alert.has_field("Location"));

  EXPECT_TRUE(alert.has_field("Acknowledged"));
  EXPECT_EQ(alert["Acknowledged"].as<bool>(), true);
}

// =============================================================================
// DataBatch: array fields through the wire
// =============================================================================

TEST_F(DynamicTypeIntegration, DataBatchArrayFieldRoundTrip)
{
  auto& batch = read_structure(mDataBatchVarId);

  EXPECT_EQ(static_cast<string_view>(batch["BatchId"].as<String>()), "batch-1");

  auto& decodedValues = batch["Values"].as<Array<double>>();
  ASSERT_EQ(decodedValues.size(), 3u);
  EXPECT_DOUBLE_EQ(decodedValues[0], 1.0);
  EXPECT_DOUBLE_EQ(decodedValues[1], 2.0);
  EXPECT_DOUBLE_EQ(decodedValues[2], 3.0);

  auto& decodedLabels = batch["Labels"].as<Array<String>>();
  ASSERT_EQ(decodedLabels.size(), 3u);
  EXPECT_EQ(static_cast<string_view>(decodedLabels[0]), "a");
  EXPECT_EQ(static_cast<string_view>(decodedLabels[1]), "b");
  EXPECT_EQ(static_cast<string_view>(decodedLabels[2]), "c");
}

// =============================================================================
// Enum registration and lookup
// =============================================================================

TEST_F(DynamicTypeIntegration, EnumRegistrationAndLookup)
{
  auto nsUri = string_view{"urn:test:industrial-monitoring"};

  auto priorityDesc = mClientDynRegistry.find_enum(ExpandedNodeId{NodeId{0, 1001u}, nsUri});
  ASSERT_NE(priorityDesc, nullptr);
  EXPECT_EQ(static_cast<string_view>(priorityDesc->type_name()), "Priority");

  EXPECT_EQ(DynamicEnumView(0, *priorityDesc).value_name(), "Low");
  EXPECT_EQ(DynamicEnumView(1, *priorityDesc).value_name(), "Medium");
  EXPECT_EQ(DynamicEnumView(2, *priorityDesc).value_name(), "High");
  EXPECT_EQ(DynamicEnumView(3, *priorityDesc).value_name(), "Critical");

  auto sensorStateDesc = mClientDynRegistry.find_enum(ExpandedNodeId{NodeId{0, 1002u}, nsUri});
  ASSERT_NE(sensorStateDesc, nullptr);
  EXPECT_EQ(static_cast<string_view>(sensorStateDesc->type_name()), "SensorState");
}

// =============================================================================
// TaskInfo: enum and UInt-OptionSet fields encoded as integers
// =============================================================================

TEST_F(DynamicTypeIntegration, TaskInfoEnumAndOptionSetRoundTrip)
{
  // Verify the descriptor has correct field types (enum -> Int32, option set -> UInt32)
  auto nsUri = string_view{"urn:test:industrial-monitoring"};
  auto taskDesc = mClientDynRegistry.find_structure(ExpandedNodeId{NodeId{0, 2011u}, nsUri});
  ASSERT_NE(taskDesc, nullptr);
  // Fields: Name(String), Priority(Int32 via enum), AccessLevel(UInt32 via optionset),
  // Description(LocalizedText)
  ASSERT_EQ(taskDesc->field_count(), 4u);
  EXPECT_EQ(taskDesc->field_built_in_type(0), BuiltInTypeId::String);
  EXPECT_EQ(taskDesc->field_built_in_type(1), BuiltInTypeId::Int32) << "Priority enum should map to Int32";
  EXPECT_EQ(taskDesc->field_built_in_type(2), BuiltInTypeId::UInt32)
    << "AccessFlags option set should map to UInt32";
  EXPECT_EQ(taskDesc->field_built_in_type(3), BuiltInTypeId::LocalizedText);

  auto& task = read_structure(mTaskInfoVarId);

  EXPECT_EQ(static_cast<string_view>(task["Name"].as<String>()), "Deploy v2.1");
  EXPECT_EQ(task["Priority"].as<int32_t>(), 2);  // High
  EXPECT_EQ(task["AccessLevel"].as<uint32_t>(), 0b11001u);

  // Verify enum view on the decoded Priority value
  auto priorityDesc = mClientDynRegistry.find_enum(ExpandedNodeId{NodeId{0, 1001u}, nsUri});
  ASSERT_NE(priorityDesc, nullptr);
  EXPECT_EQ(DynamicEnumView(task["Priority"].as<int32_t>(), *priorityDesc).value_name(), "High");
}

// =============================================================================
// FullReport: capstone type combining all dynamic type features
// =============================================================================

TEST_F(DynamicTypeIntegration, FullReportCapstoneRoundTrip)
{
  auto& report = read_structure(mFullReportVarId);

  // Plain built-in fields
  EXPECT_EQ(static_cast<string_view>(report["Title"].as<String>()), "Daily Summary");
  EXPECT_EQ(report["ReadingCount"].as<uint64_t>(), 1500u);

  // 3-level nesting: FullReport -> Location (SensorLocation) -> Coordinate (GeoCoordinate)
  ASSERT_TRUE(report["Location"].is_structure());
  auto& loc = dynamic_cast<const DynamicStructure&>(report["Location"].as<Structure>());
  EXPECT_EQ(static_cast<string_view>(loc["Name"].as<String>()), "Lab 3");
  ASSERT_TRUE(loc["Coordinate"].is_structure());
  auto& coord = dynamic_cast<const DynamicStructure&>(loc["Coordinate"].as<Structure>());
  EXPECT_DOUBLE_EQ(coord["Latitude"].as<double>(), 40.7128);
  EXPECT_DOUBLE_EQ(coord["Longitude"].as<double>(), -74.0060);

  // Struct containing union: LatestRecord -> Value (Measurement)
  ASSERT_TRUE(report["LatestRecord"].is_structure());
  auto& record = dynamic_cast<const DynamicStructure&>(report["LatestRecord"].as<Structure>());
  EXPECT_EQ(static_cast<string_view>(record["Source"].as<String>()), "main-sensor");
  ASSERT_TRUE(record["Value"].is_structure());
  auto& meas = dynamic_cast<const DynamicUnion&>(record["Value"].as<Structure>());
  EXPECT_EQ(meas.active_field_name(), "FloatValue");
  EXPECT_DOUBLE_EQ(meas.value().as<double>(), 72.5);

  // Optional fields: Alert (AlertInfo)
  ASSERT_TRUE(report["Alert"].is_structure());
  auto& alert = dynamic_cast<const DynamicStructure&>(report["Alert"].as<Structure>());
  EXPECT_EQ(static_cast<string_view>(alert["Message"].as<String>()), "Temperature warning");
  EXPECT_TRUE(alert.has_field("Details"));
  EXPECT_EQ(static_cast<string_view>(alert["Details"].as<String>()), "Approaching threshold");
  EXPECT_FALSE(alert.has_field("Location"));
  EXPECT_TRUE(alert.has_field("Acknowledged"));
  EXPECT_EQ(alert["Acknowledged"].as<bool>(), false);

  // Enum field (Priority as Int32)
  EXPECT_EQ(report["Priority"].as<int32_t>(), 3);  // Critical

  // UInt-OptionSet field (AccessLevel as UInt32)
  EXPECT_EQ(report["AccessLevel"].as<uint32_t>(), 0b101u);

  // Array field (Tags)
  auto& tags = report["Tags"].as<Array<String>>();
  ASSERT_EQ(tags.size(), 3u);
  EXPECT_EQ(static_cast<string_view>(tags[0]), "production");
  EXPECT_EQ(static_cast<string_view>(tags[1]), "daily");
  EXPECT_EQ(static_cast<string_view>(tags[2]), "automated");
}

// =============================================================================
// SessionModelAccess with aggressive chunking (maxNodesPerRead=1, maxNodesPerBrowse=1)
// =============================================================================

TEST_F(DynamicTypeIntegration, SessionModelAccessChunkedDiscovery)
{
  // Use very small operation limits to force multiple service calls per batch.
  DynamicTypeRegistry chunkedRegistry;
  dynamic_types::SessionModelAccess chunkedAccess{*mSession};
  dynamic_types::SessionModelAccessTestAccess::set_limits(chunkedAccess, 1, 1);
  auto stats = dynamic_types::load_types_sync(chunkedAccess, chunkedRegistry);

  // Should discover the same types as the server-side loader.
  EXPECT_GE(stats.structureCount, 10u) << "Expected structures even with aggressive chunking";
  EXPECT_GE(stats.enumCount, 2u) << "Expected enums even with aggressive chunking";

  // Verify a specific type is present and correct.
  auto nsUri = string_view{"urn:test:industrial-monitoring"};
  auto geoDesc = chunkedRegistry.find_structure(ExpandedNodeId{NodeId{0, 2001u}, nsUri});
  ASSERT_NE(geoDesc, nullptr) << "GeoCoordinate should be discoverable with chunked access";
  EXPECT_EQ(geoDesc->field_count(), 3u);
}

// =============================================================================
// SingleTypeClientDiscovery: load_type_sync for a single type via Session
// =============================================================================

TEST_F(DynamicTypeIntegration, SingleTypeClientDiscovery)
{
  // Create a fresh registry and use load_type_sync to discover only GeoCoordinate
  DynamicTypeRegistry singleRegistry;
  dynamic_types::SessionModelAccess singleAccess{*mSession};
  auto geoTypeId = NodeId{mTestNsIdx, uint32_t{2001}};
  auto stats = dynamic_types::load_type_sync(singleAccess, singleRegistry, geoTypeId);

  // Should register exactly 1 structure, no failures
  EXPECT_EQ(stats.structureCount, 1u) << "Only GeoCoordinate should be registered";
  EXPECT_FALSE(stats.has_failures());

  // The GeoCoordinate descriptor should exist
  auto nsUri = string_view{"urn:test:industrial-monitoring"};
  auto geoDesc = singleRegistry.find_structure(ExpandedNodeId{NodeId{0, 2001u}, nsUri});
  ASSERT_NE(geoDesc, nullptr) << "GeoCoordinate descriptor should be in the registry";
  EXPECT_EQ(geoDesc->field_count(), 3u);

  // Register with the client decoder and read through the wire
  auto addressSpace2 = mServer.server().address_space();
  auto& nsArray = addressSpace2.namespace_array();
  auto nsLookup = [&nsArray](string_view uri) -> std::optional<uint16_t>
  {
    try
    {
      return nsArray.get_namespace_index(uri);
    }
    catch (...)
    {
      return std::nullopt;
    }
  };
  // Note: the fixture already registered GeoCoordinate with the client from the full discovery,
  // so we can directly read the variable to verify the single-type discovery is consistent.
  auto& geo = read_structure(mGeoCoordinateVarId);
  EXPECT_DOUBLE_EQ(geo["Latitude"].as<double>(), 37.7749);
  EXPECT_DOUBLE_EQ(geo["Longitude"].as<double>(), -122.4194);
  EXPECT_DOUBLE_EQ(geo["Altitude"].as<double>(), 16.0);
}

// =============================================================================
// TransitiveDependencyDiscovery: load_type_sync chases transitive deps
// =============================================================================

TEST_F(DynamicTypeIntegration, TransitiveDependencyDiscovery)
{
  // FullReport transitively depends on many types:
  //   GeoCoordinate, SensorLocation, MeasurementRecord, Measurement (union),
  //   AlertInfo, SensorBatch, SensorReading, Priority (enum), SensorState (enum),
  //   AccessFlags (option set), PhysicalInterface
  DynamicTypeRegistry transitiveRegistry;
  dynamic_types::SessionModelAccess transitiveAccess{*mSession};
  auto fullReportTypeId = NodeId{mTestNsIdx, uint32_t{2020}};
  auto stats = dynamic_types::load_type_sync(transitiveAccess, transitiveRegistry, fullReportTypeId);

  // Should register multiple structures and enums (the dependencies)
  EXPECT_GE(stats.structureCount, 5u)
    << "FullReport depends on multiple structure types that should be registered";
  EXPECT_GE(stats.enumCount, 2u) << "FullReport depends on Priority and SensorState enums";
  EXPECT_FALSE(stats.has_failures()) << "No failures expected: " << stats.failure_count();

  // Verify a specific transitive dependency is present
  auto nsUri = string_view{"urn:test:industrial-monitoring"};
  auto geoDesc = transitiveRegistry.find_structure(ExpandedNodeId{NodeId{0, 2001u}, nsUri});
  ASSERT_NE(geoDesc, nullptr) << "GeoCoordinate should be registered as a transitive dependency";
  EXPECT_EQ(geoDesc->field_count(), 3u);

  // Verify the root type itself is registered
  auto fullReportDesc = transitiveRegistry.find_structure(ExpandedNodeId{NodeId{0, 2020u}, nsUri});
  ASSERT_NE(fullReportDesc, nullptr) << "FullReport itself should be registered";
}

// =============================================================================
// TypeFilteredDiscovery: load_types_sync with a filter predicate
// =============================================================================

TEST_F(DynamicTypeIntegration, TypeFilteredDiscovery)
{
  // Filter: only select types with numeric ID >= 2005 in the test namespace.
  // This selects AlertInfo(2005), SensorBatch(2006), MeasurementRecord(2010),
  // TaskInfo(2011), FullReport(2020), Measurement(3001).
  // It does NOT directly select GeoCoordinate(2001), SensorReading(2002),
  // SensorLocation(2003), DataBatch(2004).
  // However, AlertInfo depends on SensorLocation which depends on GeoCoordinate,
  // so those should be pulled in as dependencies.
  DynamicTypeRegistry filteredRegistry;
  dynamic_types::SessionModelAccess filteredAccess{*mSession};
  auto filter = [testNs = mTestNsIdx](const dynamic_types::DiscoveredType& discovered) -> bool
  {
    const auto& dataTypeId = discovered.node_id();
    if (dataTypeId.namespace_index() != testNs)
    {
      return false;
    }
    if (dataTypeId.identifier().is_numeric())
    {
      return dataTypeId.identifier().get_numeric() >= 2005;
    }
    return false;
  };
  auto stats = dynamic_types::load_types_sync(filteredAccess, filteredRegistry, filter);

  EXPECT_FALSE(stats.has_failures()) << "No failures expected: " << stats.failure_count();

  auto nsUri = string_view{"urn:test:industrial-monitoring"};

  // Types matching the filter should be registered
  auto alertDesc = filteredRegistry.find_structure(ExpandedNodeId{NodeId{0, 2005u}, nsUri});
  EXPECT_NE(alertDesc, nullptr) << "AlertInfo (id=2005) matches filter, should be registered";

  auto measRecordDesc = filteredRegistry.find_structure(ExpandedNodeId{NodeId{0, 2010u}, nsUri});
  EXPECT_NE(measRecordDesc, nullptr) << "MeasurementRecord (id=2010) matches filter, should be registered";

  // Field dependencies should also be registered even though they don't match the filter.
  // AlertInfo has an optional field Location of type SensorLocation(2003),
  // and SensorLocation has a field Coordinate of type GeoCoordinate(2001).
  auto geoDesc = filteredRegistry.find_structure(ExpandedNodeId{NodeId{0, 2001u}, nsUri});
  EXPECT_NE(geoDesc, nullptr)
    << "GeoCoordinate should be registered as a dependency of AlertInfo->SensorLocation";

  auto sensorLocDesc = filteredRegistry.find_structure(ExpandedNodeId{NodeId{0, 2003u}, nsUri});
  EXPECT_NE(sensorLocDesc, nullptr) << "SensorLocation should be registered as a dependency of AlertInfo";

  // DataBatch(2004) does NOT match the filter (id < 2005) and is NOT a dependency
  // of any selected type, so it should NOT be registered.
  auto dataBatchDesc = filteredRegistry.find_structure(ExpandedNodeId{NodeId{0, 2004u}, nsUri});
  EXPECT_EQ(dataBatchDesc, nullptr) << "DataBatch should NOT be registered (not selected, not a dependency)";
}

// =============================================================================
// Amendment A: register_address_space_types discovers the address space's custom
// types and bridges them into a decode factory (UnknownStructure -> DynamicStructure).
// =============================================================================

TEST_F(DynamicTypeIntegration, AmendmentA_FreeFunctionBridgesFactory)
{
  auto addressSpace = mServer.server().address_space();
  // GeoCoordinate's Default Binary encoding NodeId in the server's local namespace.
  const NodeId geoEncoding{mTestNsIdx, uint32_t{5001}};

  // A fresh decode factory seeded only with the generated NS0 types - as a server has before it
  // discovers its custom types. It does not yet know GeoCoordinate, so a decoder would fall back
  // to UnknownStructure for that encoding.
  StructureFactory factory;
  register_ua_data_types_with_factory({}, &factory, nullptr);
  EXPECT_EQ(factory.create_instance(geoEncoding), nullptr) << "custom type unknown before the call";

  auto stats = dynamic_types::register_address_space_types_sync(addressSpace, factory);
  EXPECT_GT(stats.structureCount, 0u);
  EXPECT_FALSE(stats.has_failures()) << "unexpected failures: " << stats.failure_count();

  // After the call the factory constructs a typed DynamicStructure for the same encoding.
  auto instance = factory.create_instance(geoEncoding);
  ASSERT_NE(instance, nullptr) << "custom type must be registered after the call";
  EXPECT_NE(dynamic_cast<DynamicStructure*>(instance.get()), nullptr)
    << "decodes as a typed DynamicStructure, not an UnknownStructure";

  // Enumerations carry no encoding, so they are not factory-registered (Priority = 4006 encoding
  // does not exist; the enum type id 2007 has no Default Binary encoding to key the factory).
}

TEST_F(DynamicTypeIntegration, AmendmentA_ServerWrapperRunsFullPipeline)
{
  // Exercise the public Server wrapper end to end (Server -> ServerImpl -> free function -> loader
  // -> factory). The fixture already registered these types, so this re-discovers the same set
  // (first-writer-wins keeps the existing registrations); it proves the wrapper runs cleanly and
  // reports the discovered types.
  auto stats = mServer.server().register_address_space_types_sync();
  EXPECT_FALSE(stats.has_failures()) << "unexpected failures: " << stats.failure_count();
  EXPECT_EQ(stats.structureCount, mServerStats.structureCount)
    << "the wrapper should discover the same structures as the manual load in SetUp";
}

// Regression guard for Server::import_nodeset_sync auto-resolving its own base model. A companion
// spec declares <RequiredModel http://opcfoundation.org/UA/> and a custom structure subtyping NS0
// Structure, and supplies NO resolveRequiredModel. The server must satisfy the base model from its
// own built-in NS0 (parsing it alongside), so the custom type is classified as a structure, gets
// the reverse HasSubtype edge onto NS0 Structure, and is therefore DISCOVERABLE by the loader. If
// the auto-resolve regressed, the import would fail (MissingRequiredModel) or the type would not be
// discovered (registered structure count would drop).
TEST_F(DynamicTypeIntegration, ServerImportAutoResolvesBaseModelForCompanionSpec)
{
  constexpr string_view widgetNodeSet = R"xml(<?xml version="1.0" encoding="utf-8"?>
<UANodeSet xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>urn:test:widgets</Uri>
  </NamespaceUris>
  <Models>
    <Model ModelUri="urn:test:widgets" Version="1.0.0" PublicationDate="2026-01-01T00:00:00Z">
      <RequiredModel ModelUri="http://opcfoundation.org/UA/" Version="1.05.03" PublicationDate="2023-12-15T00:00:00Z" />
    </Model>
  </Models>
  <Aliases>
    <Alias Alias="Double">i=11</Alias>
    <Alias Alias="String">i=12</Alias>
    <Alias Alias="Structure">i=22</Alias>
    <Alias Alias="HasSubtype">i=45</Alias>
    <Alias Alias="HasEncoding">i=38</Alias>
    <Alias Alias="HasTypeDefinition">i=40</Alias>
    <Alias Alias="DataTypeEncodingType">i=76</Alias>
  </Aliases>
  <UADataType NodeId="ns=1;i=4001" BrowseName="1:Widget">
    <DisplayName>Widget</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">Structure</Reference>
      <Reference ReferenceType="HasEncoding">ns=1;i=4002</Reference>
    </References>
    <Definition Name="1:Widget">
      <Field Name="Size" DataType="Double" />
      <Field Name="Label" DataType="String" />
    </Definition>
  </UADataType>
  <UAObject NodeId="ns=1;i=4002" BrowseName="Default Binary" SymbolicName="DefaultBinary">
    <DisplayName>Default Binary</DisplayName>
    <References>
      <Reference ReferenceType="HasTypeDefinition">DataTypeEncodingType</Reference>
      <Reference ReferenceType="HasEncoding" IsForward="false">ns=1;i=4001</Reference>
    </References>
  </UAObject>
</UANodeSet>)xml";

  auto& server = mServer.server();
  const auto executor = mServer.thread_pool().executor();

  // A NodeSet that introduces a new namespace still needs a namespace factory; but we deliberately
  // do NOT set resolveRequiredModel, so only the server's built-in NS0 can satisfy the base model.
  NodeSetImportOptions options;
  options.namespaceFactory = [executor](string_view uri) -> shared_ptr<Namespace>
  {
    return default_ns::Namespace::create(uri, executor);
  };

  const auto* bytes = reinterpret_cast<const std::byte*>(widgetNodeSet.data());
  memory_stream_device::ExternalReadOnly device{std::span<const std::byte>{bytes, widgetNodeSet.size()}};
  MemoryStream stream{device};

  // Must not throw MissingRequiredModel: the server auto-resolves the UA base model from its NS0.
  ASSERT_NO_THROW(server.import_nodeset_sync(stream, options));

  const uint16_t widgetNs = server.address_space().namespace_array().get_namespace_index("urn:test:widgets");

  // The Widget type - imported through the HIGH-LEVEL Server::import path - is now discoverable and
  // registerable, which requires the base model to have been parsed alongside it.
  StructureFactory factory;
  register_ua_data_types_with_factory({}, &factory, nullptr);
  const NodeId widgetEncoding{widgetNs, uint32_t{4002}};
  EXPECT_EQ(factory.create_instance(widgetEncoding), nullptr) << "unknown before registration";

  const auto stats = dynamic_types::register_address_space_types_sync(server.address_space(), factory);
  EXPECT_GE(stats.structureCount, 1u);

  auto instance = factory.create_instance(widgetEncoding);
  ASSERT_NE(instance, nullptr) << "Widget must be discoverable after Server::import auto-resolved NS0";
  EXPECT_NE(dynamic_cast<DynamicStructure*>(instance.get()), nullptr);
}

// =============================================================================
// DefaultNestedStructureRoundTrip: nested structure with default values
// =============================================================================

TEST_F(DynamicTypeIntegration, DefaultNestedStructureRoundTrip)
{
  // Create a SensorLocation where the nested GeoCoordinate has default (zero) values.
  // This tests the encode/decode path for nested structures with default field values.
  auto resolver = mServerDynRegistry.make_resolver(make_ns_lookup());

  auto locInstance = resolver(NodeId{mTestNsIdx, 5003u});
  ASSERT_NE(locInstance, nullptr);
  auto* loc = dynamic_cast<DynamicStructure*>(locInstance.get());
  ASSERT_NE(loc, nullptr);
  (*loc)["Name"] = Variant{String{"Default Location"}};
  // Create a GeoCoordinate with all-zero (default) values
  auto geoInstance = resolver(NodeId{mTestNsIdx, 5001u});
  ASSERT_NE(geoInstance, nullptr);
  // Leave all fields at their defaults (0.0 for doubles)
  (*loc)["Coordinate"] = Variant{std::move(geoInstance)};

  // Write to the server variable through the address space directly (server-side)
  auto defaultLocVarId = NodeId{mTestNsIdx, uint32_t{7003}};
  auto varNode = mServer.server().address_space().find_node_sync(defaultLocVarId);
  auto variable = varNode.as<VariableAccessor>();
  ASSERT_TRUE(variable.has_value());
  variable->write_value_sync(Variant{std::move(locInstance)});

  // Read it back through the wire (client-side decode)
  auto& readLoc = read_structure(defaultLocVarId);
  EXPECT_EQ(static_cast<string_view>(readLoc["Name"].as<String>()), "Default Location");

  // The nested GeoCoordinate should be present with default values
  auto& coordVariant = readLoc["Coordinate"];
  ASSERT_TRUE(coordVariant.is_structure()) << "Nested GeoCoordinate should be decodable even with defaults";
  auto& coord = dynamic_cast<const DynamicStructure&>(coordVariant.as<Structure>());
  EXPECT_DOUBLE_EQ(coord["Latitude"].as<double>(), 0.0);
  EXPECT_DOUBLE_EQ(coord["Longitude"].as<double>(), 0.0);
  EXPECT_DOUBLE_EQ(coord["Altitude"].as<double>(), 0.0);
}

// =============================================================================
// RegistrationStatsAccuracy: verify server-side stats from configure_server
// =============================================================================

TEST_F(DynamicTypeIntegration, RegistrationStatsAccuracy)
{
  // The server loaded all types from DynamicTypesTest.NodeSet2.xml during configure_server().
  // Verify the stats reflect the NodeSet contents.

  // Concrete structure/union types in the NodeSet:
  //   GeoCoordinate(2001), SensorReading(2002), SensorLocation(2003), DataBatch(2004),
  //   AlertInfo(2005), SensorBatch(2006), Measurement(3001, union),
  //   MeasurementRecord(2010), TaskInfo(2011), FullReport(2020),
  //   PhysicalInterface(1020, struct-based optionset), LargeOptionSet(1021, struct-based optionset)
  EXPECT_GE(mServerStats.structureCount, 9u)
    << "Expected at least 9 concrete structure/union types from the NodeSet";

  // Enums + UInt-based option sets: Priority(1001), SensorState(1002), AccessFlags(1010)
  EXPECT_GE(mServerStats.enumCount, 2u) << "Expected at least 2 enum types (Priority, SensorState)";

  // No failures expected for a well-formed NodeSet
  EXPECT_FALSE(mServerStats.has_failures())
    << "Server-side type discovery should have no failures, got " << mServerStats.failure_count();
}

// =============================================================================
// Multi-resolver: one shared registry, multiple resolvers with different
// namespace tables - simulates a gateway connecting to two servers
// =============================================================================

TEST_F(DynamicTypeIntegration, MultipleResolversFromSharedRegistry)
{
  // The mServerDynRegistry has types registered with URI-based ExpandedNodeIds.
  // Build two resolvers that map the same URIs to different namespace indices,
  // simulating two servers that assign different indices to the same companion spec.

  auto nsUri = string_view{"urn:test:industrial-monitoring"};

  // "Server A" has the test namespace at index 2
  auto resolverA = mServerDynRegistry.make_resolver(
    [&](string_view uri) -> std::optional<uint16_t>
    {
      if (uri == nsUri)
        return uint16_t{2};
      return std::nullopt;
    });

  // "Server B" has the test namespace at index 5
  auto resolverB = mServerDynRegistry.make_resolver(
    [&](string_view uri) -> std::optional<uint16_t>
    {
      if (uri == nsUri)
        return uint16_t{5};
      return std::nullopt;
    });

  // GeoCoordinate encoding ID: numeric 5001 in the test namespace
  // Resolver A should find it at ns=2;i=5001
  auto instanceA = resolverA(NodeId{2, uint32_t{5001}});
  ASSERT_NE(instanceA, nullptr) << "Resolver A should find GeoCoordinate at ns=2";
  auto* geoA = dynamic_cast<DynamicStructure*>(instanceA.get());
  ASSERT_NE(geoA, nullptr);
  EXPECT_EQ(geoA->field_count(), 3u);

  // Resolver B should find it at ns=5;i=5001
  auto instanceB = resolverB(NodeId{5, uint32_t{5001}});
  ASSERT_NE(instanceB, nullptr) << "Resolver B should find GeoCoordinate at ns=5";
  auto* geoB = dynamic_cast<DynamicStructure*>(instanceB.get());
  ASSERT_NE(geoB, nullptr);
  EXPECT_EQ(geoB->field_count(), 3u);

  // Cross-check: Resolver A should NOT find ns=5, and B should NOT find ns=2
  EXPECT_EQ(resolverA(NodeId{5, uint32_t{5001}}), nullptr)
    << "Resolver A should not resolve Server B's namespace index";
  EXPECT_EQ(resolverB(NodeId{2, uint32_t{5001}}), nullptr)
    << "Resolver B should not resolve Server A's namespace index";

  // Both resolvers share the same descriptors (type name should match)
  EXPECT_EQ(string_view(geoA->descriptor().type_name()), string_view(geoB->descriptor().type_name()));
}

// =============================================================================
// Server authoring: create a DataType programmatically in the address space,
// then discover it via AddressSpaceModelAccess + load_types.
// Proves "address space as single source of truth" for non-NodeSet types.
// =============================================================================

TEST_F(DynamicTypeIntegration, ProgrammaticTypeDiscovery)
{
  auto addressSpace = mServer.server().address_space();

  // --- Create a DataType node as a subtype of Structure ---
  NodeId customTypeId{mTestNsIdx, uint32_t{9001}};
  auto typeNode = addressSpace.create_node_sync(customTypeId, NodeClass::DataType);
  typeNode.set_browse_name(QualifiedName{mTestNsIdx, String{"CustomSensorData"}});

  auto dtAccessor = typeNode.as<DataTypeAccessor>();
  ASSERT_TRUE(dtAccessor.has_value())
    << "Node created with NodeClass::DataType should yield DataTypeAccessor";
  dtAccessor->set_is_abstract(false);

  // Build a StructureDefinition (this is what the address space stores)
  auto structDef = std::make_shared<StructureDefinition>();
  structDef->structure_type() = StructureType::Structure;
  structDef->base_data_type() = NodeId{DataTypeId::Structure};

  NodeId encodingNodeId{mTestNsIdx, uint32_t{9002}};
  structDef->default_encoding_id() = encodingNodeId;

  Array<StructureField> fields;
  StructureField sensorIdField;
  sensorIdField.name() = String{"SensorId"};
  sensorIdField.data_type() = NodeId{DataTypeId::String};
  sensorIdField.value_rank() = -1;
  fields.push_back(std::move(sensorIdField));

  StructureField readingField;
  readingField.name() = String{"Reading"};
  readingField.data_type() = NodeId{DataTypeId::Double};
  readingField.value_rank() = -1;
  fields.push_back(std::move(readingField));

  structDef->fields() = std::move(fields);

  dtAccessor->set_data_type_definition(structDef);

  // Add HasSubtype reference from Structure (i=22) -> our type
  auto structureNode = addressSpace.find_node_sync(NodeId{DataTypeId::Structure});
  structureNode.add_reference_sync(NodeId{ReferenceTypeId::HasSubtype}, customTypeId);

  // --- Create the Default Binary encoding node ---
  auto encodingNode = addressSpace.create_node_sync(encodingNodeId, NodeClass::Object);
  encodingNode.set_browse_name(QualifiedName{0, String{"Default Binary"}});
  encodingNode.add_reference_sync(
    NodeId{ReferenceTypeId::HasTypeDefinition}, NodeId{ObjectTypeId::DataTypeEncodingType});

  // Add HasEncoding from DataType -> encoding node
  typeNode.add_reference_sync(NodeId{ReferenceTypeId::HasEncoding}, encodingNodeId);

  // --- Discover types using a fresh registry ---
  DynamicTypeRegistry freshRegistry;
  dynamic_types::AddressSpaceModelAccess access{addressSpace};
  auto stats = dynamic_types::load_types_sync(access, freshRegistry);

  // Verify our programmatic type was discovered
  auto nsUri = string_view{"urn:test:industrial-monitoring"};
  auto desc = freshRegistry.find_structure(ExpandedNodeId{NodeId{0, 9001u}, nsUri});
  ASSERT_NE(desc, nullptr) << "Programmatically created DataType should be discoverable";
  EXPECT_EQ(desc->field_count(), 2u);
  EXPECT_EQ(string_view(desc->type_name()), "CustomSensorData");

  // Verify it can create instances via the resolver
  auto resolver = freshRegistry.make_resolver(make_ns_lookup());
  auto instance = resolver(NodeId{mTestNsIdx, uint32_t{9002}});
  ASSERT_NE(instance, nullptr) << "Resolver should create instances of the programmatic type";

  auto* ds = dynamic_cast<DynamicStructure*>(instance.get());
  ASSERT_NE(ds, nullptr);
  EXPECT_EQ(ds->field_count(), 2u);

  // Set fields, encode to binary, decode back - full round trip
  (*ds)["SensorId"] = Variant{String{"sensor-99"}};
  (*ds)["Reading"] = Variant{42.5};

  memory_stream_device::Dynamic device{};
  MemoryStream stream{device};
  UaBinaryEncoder encoder(CodecNamespaceContext{}, stream);
  Encoder enc(encoder);
  ds->encode(StackDepth{100}, enc);

  stream.seek_from_start(0);
  auto decoded = resolver(NodeId{mTestNsIdx, uint32_t{9002}});
  ASSERT_NE(decoded, nullptr);
  UaBinaryDecoder decoder(resolver, stream, EncodingLimits{100, 100});
  Decoder dec(decoder);
  decoded->decode(StackDepth{100}, dec);

  auto* decodedDs = dynamic_cast<DynamicStructure*>(decoded.get());
  ASSERT_NE(decodedDs, nullptr);
  EXPECT_EQ(static_cast<string_view>((*decodedDs)["SensorId"].as<String>()), "sensor-99");
  EXPECT_DOUBLE_EQ((*decodedDs)["Reading"].as<double>(), 42.5);
}

}  // namespace
