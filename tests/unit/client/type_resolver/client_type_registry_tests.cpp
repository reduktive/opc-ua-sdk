// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// Unit tests for the client-side precedence registry (ua::client::detail::StructureFactory, client
// design section 8.6 / section 9.8.3) and its immutable snapshot (ua::client::detail::TypeRegistry).
//
// Covers the section 9.8.3 "define StructureFactory as a real type" deliverable: the four-source provenance +
// precedence ladder (user-registered beats the application overlay beats server-DataTypeDefinition beats
// dictionary beats built-in), first-wins on an equal-precedence collision, the consultation point
// (find_by_encoding), the outbound encoding_for_datatype path, and the frozen snapshot's generation.
//
// Falsifiability: a registry that ignores precedence fails UserRegistrationBeatsDictionary; one that lets
// a lower source clobber a higher fails BuiltInDoesNotOverrideUser; one that mutates a published snapshot
// fails SnapshotIsIndependentOfLaterInstalls.

#include "ua_type_registry.h"

#include "ua_array.h"
#include "ua_datatype_id.h"
#include "ua_node_id.h"
#include "ua_string.h"
#include "ua_variant.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string>

namespace
{

using ua::client::detail::StructureFactory;
using ua::client::detail::StructureType;
using ua::client::detail::TypeRegistry;
using ua::client::detail::TypeSource;

ua::NodeId node(std::uint32_t identifier)
{
  return ua::NodeId{1, identifier};
}

StructureType entry(std::uint32_t encoding, std::uint32_t dataType, TypeSource source)
{
  return StructureType{node(dataType), node(encoding), nullptr, source};
}

// ---- precedence ladder (CL-BASE-008 / section 9.6.18.2) ----

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeRegistry, InstallInsertsAndFindByEncodingReturnsIt)
{
  StructureFactory factory;
  EXPECT_EQ(
    factory.install(entry(100, 200, TypeSource::BuiltIn)), StructureFactory::InstallResult::Installed);
  const auto* found = factory.find_by_encoding(node(100));
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->dataTypeId, node(200));
  EXPECT_EQ(found->source, TypeSource::BuiltIn);
}

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeRegistry, FindByEncodingMissReturnsNull)
{
  StructureFactory factory;
  EXPECT_EQ(factory.find_by_encoding(node(999)), nullptr);
  EXPECT_EQ(factory.source_of(node(999)), std::nullopt);
}

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeRegistry, UserRegistrationBeatsDictionary)
{
  // The Slice-7 task's precedence check: a user register_structure_type wins over a dictionary-derived
  // entry for the same encoding NodeId.
  StructureFactory factory;
  factory.install(entry(100, 200, TypeSource::ServerDataTypeDictionary));
  EXPECT_EQ(factory.register_structure_type(node(100), node(200), nullptr),
    StructureFactory::InstallResult::Installed);
  EXPECT_EQ(factory.source_of(node(100)), TypeSource::UserRegistered);
}

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeRegistry, DictionaryBeatsBuiltIn)
{
  StructureFactory factory;
  factory.install(entry(100, 200, TypeSource::BuiltIn));
  EXPECT_EQ(factory.install(entry(100, 200, TypeSource::ServerDataTypeDictionary)),
    StructureFactory::InstallResult::Installed);
  EXPECT_EQ(factory.source_of(node(100)), TypeSource::ServerDataTypeDictionary);
}

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeRegistry, OverlayRanksBetweenUserAndServer)
{
  // section 9.8.3 / checklist: the application overlay ranks between user-registered and server-discovered.
  StructureFactory factory;
  factory.install(entry(100, 200, TypeSource::ServerDataTypeDefinition));
  EXPECT_EQ(factory.install(entry(100, 200, TypeSource::ClientOverlay)),
    StructureFactory::InstallResult::Installed);  // overlay > server definition
  EXPECT_EQ(factory.source_of(node(100)), TypeSource::ClientOverlay);
  EXPECT_EQ(factory.register_structure_type(node(100), node(200), nullptr),
    StructureFactory::InstallResult::Installed);  // user > overlay
  EXPECT_EQ(factory.source_of(node(100)), TypeSource::UserRegistered);
}

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeRegistry, LowerPrecedenceIsShadowedNotInstalled)
{
  StructureFactory factory;
  factory.register_structure_type(node(100), node(200), nullptr);  // UserRegistered
  EXPECT_EQ(factory.install(entry(100, 200, TypeSource::ServerDataTypeDictionary)),
    StructureFactory::InstallResult::ShadowedByHigher);
  EXPECT_EQ(factory.source_of(node(100)), TypeSource::UserRegistered);  // unchanged
}

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeRegistry, BuiltInDoesNotOverrideUser)
{
  StructureFactory factory;
  factory.register_structure_type(node(100), node(200), nullptr);
  EXPECT_EQ(
    factory.install(entry(100, 200, TypeSource::BuiltIn)), StructureFactory::InstallResult::ShadowedByHigher);
  EXPECT_EQ(factory.source_of(node(100)), TypeSource::UserRegistered);
}

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeRegistry, FirstUserRegistrationWinsOnEqualPrecedence)
{
  StructureFactory factory;
  factory.register_structure_type(node(100), node(200), nullptr);
  // Second user registration for the same encoding is rejected (first wins, section 9.6.18.2).
  EXPECT_EQ(factory.register_structure_type(node(100), node(201), nullptr),
    StructureFactory::InstallResult::ShadowedByHigher);
  EXPECT_EQ(factory.find_by_encoding(node(100))->dataTypeId, node(200));
}

// ---- outbound encode path (CL-METH-007) ----

// @verifies CL-METH-007
// @relation(CL-METH-007, scope=function)
TEST(TypeRegistry, EncodingForDataTypeReturnsRegisteredEncoding)
{
  StructureFactory factory;
  factory.install(entry(100, 200, TypeSource::ServerDataTypeDefinition));
  EXPECT_EQ(factory.encoding_for_datatype(node(200)), node(100));
  EXPECT_EQ(factory.encoding_for_datatype(node(999)), std::nullopt);
}

// ---- merge (overlay fold) ----

// @verifies CL-BASE-008
// @relation(CL-BASE-008, scope=function)
TEST(TypeRegistry, MergeFromRespectsPrecedence)
{
  StructureFactory base;
  base.register_structure_type(node(100), node(200), nullptr);  // user in base
  base.install(entry(101, 201, TypeSource::BuiltIn));
  StructureFactory other;
  other.install(entry(100, 200, TypeSource::ServerDataTypeDictionary));  // loses to base's user
  other.install(entry(102, 202, TypeSource::ServerDataTypeDefinition));  // new
  base.merge_from(other);
  EXPECT_EQ(base.source_of(node(100)), TypeSource::UserRegistered);  // kept
  EXPECT_EQ(base.source_of(node(102)), TypeSource::ServerDataTypeDefinition);  // added
  EXPECT_EQ(base.size(), 3U);
}

// @verifies CL-MULTI-001
// @relation(CL-MULTI-001, scope=function)
TEST(TypeRegistry, ForEachVisitsEveryEntry)
{
  StructureFactory factory;
  factory.install(entry(100, 200, TypeSource::BuiltIn));
  factory.install(entry(101, 201, TypeSource::ServerDataTypeDefinition));
  std::size_t count = 0;
  factory.for_each([&count](const StructureType&) { ++count; });
  EXPECT_EQ(count, 2U);
}

// ---- immutable snapshot ----

// @verifies CL-ADDRSP-012
// @relation(CL-ADDRSP-012, scope=function)
TEST(TypeRegistry, CreateFreezesGenerationAndDelegatesLookup)
{
  StructureFactory factory;
  factory.install(entry(100, 200, TypeSource::ServerDataTypeDefinition));
  auto snapshot = TypeRegistry::create(factory, 7);
  ASSERT_NE(snapshot, nullptr);
  EXPECT_EQ(snapshot->generation(), 7U);
  ASSERT_NE(snapshot->find_by_encoding(node(100)), nullptr);
  EXPECT_EQ(snapshot->source_of(node(100)), TypeSource::ServerDataTypeDefinition);
  EXPECT_EQ(snapshot->encoding_for_datatype(node(200)), node(100));
}

// @verifies CL-ADDRSP-012
// @relation(CL-ADDRSP-012, scope=function)
TEST(TypeRegistry, SnapshotIsIndependentOfLaterInstalls)
{
  StructureFactory factory;
  factory.install(entry(100, 200, TypeSource::ServerDataTypeDefinition));
  auto snapshot = TypeRegistry::create(factory, 1);
  factory.install(entry(300, 400, TypeSource::ServerDataTypeDefinition));  // mutate AFTER freezing
  EXPECT_EQ(snapshot->find_by_encoding(node(300)), nullptr);  // the frozen copy did not see it
}

// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, IsSubtypeOfReflexiveElseUndecidable)
{
  auto snapshot = TypeRegistry::create(StructureFactory{}, 1);
  EXPECT_EQ(snapshot->is_subtype_of(node(1), node(1)), std::optional<bool>{true});
  EXPECT_EQ(snapshot->is_subtype_of(node(1), node(2)), std::nullopt);  // no graph yet: undecidable
}

// ---- CL-ADDRSP-009 DataType subtype graph (the real is_subtype_of walk) ----

// The BaseDataType hierarchy root (Part 3 section 5.8.3), the sentinel where an upward walk terminates.
ua::NodeId base()
{
  return ua::NodeId{ua::DataTypeId::BaseDataType};
}

// A discovered chain Int32(32) -> Integer(28) -> Number(26) -> BaseDataType resolves subtype relations along
// it (true), including reflexive and subtype-of-BaseDataType, and is directional (Number is NOT a subtype of
// Int32 - the walk from Number reaches the root without meeting Int32). Falsifiable: a stub that only checked
// equality returns nullopt for Int32-vs-Number.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, IsSubtypeOfWalksDiscoveredChain)
{
  StructureFactory factory;
  factory.add_subtype_edge(node(32), node(28));  // Int32 -> Integer
  factory.add_subtype_edge(node(28), node(26));  // Integer -> Number
  factory.add_subtype_edge(node(26), base());  // Number -> BaseDataType
  auto snapshot = TypeRegistry::create(factory, 1);

  EXPECT_EQ(snapshot->is_subtype_of(node(32), node(26)), std::optional<bool>{true}) << "Int32 <: Number";
  EXPECT_EQ(snapshot->is_subtype_of(node(32), node(28)), std::optional<bool>{true}) << "Int32 <: Integer";
  EXPECT_EQ(snapshot->is_subtype_of(node(32), base()), std::optional<bool>{true}) << "Int32 <: BaseDataType";
  EXPECT_EQ(snapshot->is_subtype_of(node(32), node(32)), std::optional<bool>{true}) << "reflexive";
  EXPECT_EQ(snapshot->is_subtype_of(node(26), node(32)), std::optional<bool>{false})
    << "Number is NOT a subtype of Int32 (directional)";
}

// A sibling type is definitively NOT a subtype: both chains are fully known to BaseDataType, so the walk from
// Int32 reaches the root without meeting UInt32 -> false (not nullopt).
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, IsSubtypeOfSiblingIsFalseWhenChainFullyKnown)
{
  StructureFactory factory;
  factory.add_subtype_edge(node(32), node(28));  // Int32 -> Integer
  factory.add_subtype_edge(node(28), base());  // Integer -> BaseDataType
  factory.add_subtype_edge(node(33), node(29));  // UInt32 -> UInteger
  factory.add_subtype_edge(node(29), base());  // UInteger -> BaseDataType
  auto snapshot = TypeRegistry::create(factory, 1);

  EXPECT_EQ(snapshot->is_subtype_of(node(32), node(33)), std::optional<bool>{false})
    << "Int32 is not <: UInt32";
}

// An UNDISCOVERED edge partway up the chain leaves the relation undecidable from this snapshot (nullopt) -
// the signal for the caller to drive an async supertype resolution and re-check the next generation.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, IsSubtypeOfUndiscoveredEdgeIsNullopt)
{
  StructureFactory factory;
  factory.add_subtype_edge(node(32), node(28));  // Int32 -> Integer, but Integer's supertype is unknown
  auto snapshot = TypeRegistry::create(factory, 1);

  EXPECT_EQ(snapshot->is_subtype_of(node(32), node(26)), std::nullopt)
    << "Int32 -> Integer -> ? : undecidable until Integer's supertype is discovered";
}

// A cycle in the recorded edges (a malformed / hostile hierarchy) is undecidable, not an infinite loop.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, IsSubtypeOfCycleIsNulloptNotHang)
{
  StructureFactory factory;
  factory.add_subtype_edge(node(50), node(51));
  factory.add_subtype_edge(node(51), node(50));  // 50 -> 51 -> 50
  auto snapshot = TypeRegistry::create(factory, 1);

  EXPECT_EQ(snapshot->is_subtype_of(node(50), node(99)), std::nullopt) << "a cyclic chain is undecidable";
}

// The subtype graph is frozen with the snapshot: edges added to the factory AFTER create() do not appear in
// the already-published snapshot (parity with the structure-registry freeze).
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, IsSubtypeOfEdgesFrozenWithSnapshot)
{
  StructureFactory factory;
  factory.add_subtype_edge(node(32), node(28));  // Int32 -> Integer
  auto snapshot = TypeRegistry::create(factory, 1);
  factory.add_subtype_edge(node(28), base());  // discovered AFTER freezing

  EXPECT_EQ(snapshot->is_subtype_of(node(32), base()), std::nullopt)
    << "the frozen snapshot did not see the later-discovered Integer -> BaseDataType edge";
}

// merge_from folds another factory's discovered subtype edges (used to combine the overlay + built-in base).
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, MergeFoldsSubtypeEdges)
{
  StructureFactory a;
  a.add_subtype_edge(node(32), node(28));  // Int32 -> Integer
  StructureFactory b;
  b.add_subtype_edge(node(28), node(26));  // Integer -> Number
  b.add_subtype_edge(node(26), base());  // Number -> BaseDataType
  a.merge_from(b);
  auto snapshot = TypeRegistry::create(a, 1);

  EXPECT_EQ(snapshot->is_subtype_of(node(32), node(26)), std::optional<bool>{true})
    << "the merged edges complete the Int32 -> Number chain";
}

// ---- CL-ADDRSP-009 value-vs-declared-DataType validation (check_value_subtype) ----

using ua::client::detail::check_value_subtype;
using ua::client::detail::SubtypeCheck;

ua::NodeId ns0(ua::DataTypeId id)
{
  return ua::NodeId{id};
}

// A registry whose subtype graph knows the NS0 numeric hierarchy Int32 -> Integer -> Number -> BaseDataType
// and String -> BaseDataType, so is_subtype_of over those built-in types is decidable.
StructureFactory numeric_hierarchy()
{
  StructureFactory factory;
  factory.add_subtype_edge(ns0(ua::DataTypeId::Int32), ns0(ua::DataTypeId::Integer));
  factory.add_subtype_edge(ns0(ua::DataTypeId::Integer), ns0(ua::DataTypeId::Number));
  factory.add_subtype_edge(ns0(ua::DataTypeId::Number), ns0(ua::DataTypeId::BaseDataType));
  factory.add_subtype_edge(ns0(ua::DataTypeId::String), ns0(ua::DataTypeId::BaseDataType));
  return factory;
}

// A concrete Int32 value satisfies a Variable declared with the abstract Number DataType (Int32 <: Number).
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, CheckValueSubtypeAcceptsConcreteSubtypeOfAbstractDeclared)
{
  auto snapshot = TypeRegistry::create(numeric_hierarchy(), 1);
  EXPECT_EQ(check_value_subtype(ua::Variant{std::int32_t{7}}, ns0(ua::DataTypeId::Number), *snapshot),
    SubtypeCheck::Accept);
}

// A String value does NOT satisfy a Variable declared with Number - its chain reaches BaseDataType without
// meeting Number, a definitive Reject.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, CheckValueSubtypeRejectsUnrelatedConcreteType)
{
  auto snapshot = TypeRegistry::create(numeric_hierarchy(), 1);
  EXPECT_EQ(check_value_subtype(ua::Variant{ua::String{"x"}}, ns0(ua::DataTypeId::Number), *snapshot),
    SubtypeCheck::Reject);
}

// The reflexive case needs no hierarchy: a value whose concrete type equals the declared type is accepted.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, CheckValueSubtypeAcceptsExactType)
{
  auto snapshot = TypeRegistry::create(StructureFactory{}, 1);
  EXPECT_EQ(check_value_subtype(ua::Variant{std::int32_t{7}}, ns0(ua::DataTypeId::Int32), *snapshot),
    SubtypeCheck::Accept);
}

// When the subtype graph does not yet know the relation, the result is Undecidable (the caller drives
// discovery and re-checks; it must NOT reject a possibly-valid value).
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, CheckValueSubtypeUndecidableWhenGraphIncomplete)
{
  auto snapshot = TypeRegistry::create(StructureFactory{}, 1);  // no edges
  EXPECT_EQ(check_value_subtype(ua::Variant{std::int32_t{7}}, ns0(ua::DataTypeId::Number), *snapshot),
    SubtypeCheck::Undecidable);
}

// An empty value and an array value cannot be classified here - Undecidable (fail-open), never Reject.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, CheckValueSubtypeUndecidableForEmptyAndArray)
{
  auto snapshot = TypeRegistry::create(numeric_hierarchy(), 1);
  EXPECT_EQ(
    check_value_subtype(ua::Variant{}, ns0(ua::DataTypeId::Number), *snapshot), SubtypeCheck::Undecidable);
  ua::Array<std::int32_t> array{1, 2, 3};
  EXPECT_EQ(check_value_subtype(ua::Variant{array}, ns0(ua::DataTypeId::Number), *snapshot),
    SubtypeCheck::Undecidable);
}

// section 3.1 HIGH regression: an Enumeration value wires as Int32 but its DataType is under Enumeration
// (i=29), a branch disjoint from the integer types. A read of an enum-typed Variable must NOT be Rejected
// just because Int32 is not a subtype of the enum - it must fail-open (Undecidable). Falsifiable: the naive
// is_subtype_of(Int32, MyEnum)==false -> Reject would wrongly reject every enum read.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, CheckValueSubtypeIntegerEncodedEnumIsUndecidableNotRejected)
{
  StructureFactory factory = numeric_hierarchy();  // Int32 -> Integer -> Number -> Base is fully known
  const ua::NodeId myEnum{std::uint16_t{1}, 9000U};
  factory.add_subtype_edge(myEnum, ns0(ua::DataTypeId::Enumeration));
  factory.add_subtype_edge(ns0(ua::DataTypeId::Enumeration), ns0(ua::DataTypeId::BaseDataType));
  auto snapshot = TypeRegistry::create(factory, 1);

  EXPECT_EQ(check_value_subtype(ua::Variant{std::int32_t{2}}, myEnum, *snapshot), SubtypeCheck::Undecidable)
    << "an Int32-encoded enum value must not be rejected against its Enumeration-subtype declared type";
}

// section 3.1 HIGH regression: a refined built-in (e.g. Duration <: Double) wires as its base built-in
// (Double). The declared refined type IS a subtype of the wire built-in, so the encoding cannot distinguish
// it - fail-open, never Reject. Falsifiable: is_subtype_of(Double, Duration)==false -> Reject would wrongly
// reject a valid Duration read.
// @verifies CL-ADDRSP-009
// @relation(CL-ADDRSP-009, scope=function)
TEST(TypeRegistry, CheckValueSubtypeRefinedBuiltInIsUndecidableNotRejected)
{
  StructureFactory factory;
  const ua::NodeId duration{std::uint16_t{0}, 290U};  // NS0 Duration i=290, a subtype of Double
  factory.add_subtype_edge(duration, ns0(ua::DataTypeId::Double));
  factory.add_subtype_edge(ns0(ua::DataTypeId::Double), ns0(ua::DataTypeId::Number));
  factory.add_subtype_edge(ns0(ua::DataTypeId::Number), ns0(ua::DataTypeId::BaseDataType));
  auto snapshot = TypeRegistry::create(factory, 1);

  EXPECT_EQ(check_value_subtype(ua::Variant{double{1.5}}, duration, *snapshot), SubtypeCheck::Undecidable)
    << "a Double-encoded Duration value must not be rejected against its Double-subtype declared type";
}

}  // namespace
