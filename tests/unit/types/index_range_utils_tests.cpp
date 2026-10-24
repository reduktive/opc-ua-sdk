// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "gtest/gtest.h"
#include "ua_error_detail.h"
#include "ua_numeric_range_parser.h"
#include "ua_result.h"
#include "ua_variant.h"
#include "ua_data_value.h"

using namespace ua;

namespace
{

ParsedNumericRange make_range(std::initializer_list<DimensionRange> dims)
{
  ParsedNumericRange range;
  range.dimensions = dims;
  return range;
}

ParsedNumericRange range_1d(uint32_t low, uint32_t high)
{
  return make_range({{low, high}});
}

ParsedNumericRange range_2d(uint32_t low1, uint32_t high1, uint32_t low2, uint32_t high2)
{
  return make_range({{low1, high1}, {low2, high2}});
}

}  // namespace

// ===== Read tests =====

TEST(IndexRangeUtilsRead, ArrayInt32SliceMiddle)
{
  Array<int32_t> arr{10, 20, 30, 40, 50};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 3));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<int32_t>>();
  ASSERT_EQ(sliced.size(), 3u);
  EXPECT_EQ(sliced[0], 20);
  EXPECT_EQ(sliced[1], 30);
  EXPECT_EQ(sliced[2], 40);
}

TEST(IndexRangeUtilsRead, ArrayInt32ClampHighBound)
{
  Array<int32_t> arr{10, 20, 30};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 10));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<int32_t>>();
  ASSERT_EQ(sliced.size(), 2u);
  EXPECT_EQ(sliced[0], 20);
  EXPECT_EQ(sliced[1], 30);
}

// Covers SVR-ATTR-READ-028 (coverage-audit retag).
TEST(IndexRangeUtilsRead, ArrayInt32OutOfBounds)
{
  Array<int32_t> arr{10, 20, 30};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(5, 5));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

TEST(IndexRangeUtilsRead, ScalarStringSlice)
{
  Variant source{String{"Hello World"}};
  auto result = index_range_utils::apply_read(source, range_1d(0, 4));
  ASSERT_TRUE(result.is_good());
  string_view sliced = result.value().as<String>();
  EXPECT_EQ(sliced, "Hello");
}

TEST(IndexRangeUtilsRead, ScalarStringOutOfBounds)
{
  Variant source{String{"Hello"}};
  auto result = index_range_utils::apply_read(source, range_1d(10, 10));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

TEST(IndexRangeUtilsRead, ScalarByteStringSlice)
{
  ByteString bs{uint8_t{0x10}, uint8_t{0x20}, uint8_t{0x30}, uint8_t{0x40}};
  Variant source{std::move(bs)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 2));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<ByteString>();
  ASSERT_EQ(sliced.size(), 2u);
  EXPECT_EQ(sliced[0], uint8_t{0x20});
  EXPECT_EQ(sliced[1], uint8_t{0x30});
}

TEST(IndexRangeUtilsRead, ScalarInt32WithRangeReturnsNoData)
{
  Variant source{int32_t{42}};
  auto result = index_range_utils::apply_read(source, range_1d(0, 0));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

TEST(IndexRangeUtilsRead, StringArray2D)
{
  Array<String> arr{String{"abc"}, String{"def"}, String{"ghi"}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_2d(0, 1, 1, 2));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<String>>();
  ASSERT_EQ(sliced.size(), 2u);
  EXPECT_EQ(string_view{sliced[0]}, "bc");
  EXPECT_EQ(string_view{sliced[1]}, "ef");
}

TEST(IndexRangeUtilsRead, EmptyArrayReturnsNoData)
{
  Array<int32_t> arr;
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(0, 0));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

TEST(IndexRangeUtilsRead, ArrayInt32With2DRangeReturnsNoData)
{
  Array<int32_t> arr{10, 20, 30};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_2d(0, 1, 0, 1));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

TEST(IndexRangeUtilsRead, ScalarStringWith2DRangeReturnsNoData)
{
  Variant source{String{"Hello"}};
  auto result = index_range_utils::apply_read(source, range_2d(0, 1, 0, 1));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

TEST(IndexRangeUtilsRead, EmptyRangeReturnsSourceCopy)
{
  Variant source{int32_t{42}};
  ParsedNumericRange emptyRange;
  auto result = index_range_utils::apply_read(source, emptyRange);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<int32_t>(), 42);
}

TEST(IndexRangeUtilsRead, SingleElementRange)
{
  Array<int32_t> arr{10, 20, 30};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<int32_t>>();
  ASSERT_EQ(sliced.size(), 1u);
  EXPECT_EQ(sliced[0], 20);
}

// ===== Write tests =====

TEST(IndexRangeUtilsWrite, ArrayInt32ReplaceMiddle)
{
  Array<int32_t> existing{10, 20, 30, 40, 50};
  Variant existingV{std::move(existing)};
  Array<int32_t> partial{99, 88};
  Variant partialV{std::move(partial)};

  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 2));
  ASSERT_TRUE(result.is_good());
  const auto& merged = result.value().as<Array<int32_t>>();
  ASSERT_EQ(merged.size(), 5u);
  EXPECT_EQ(merged[0], 10);
  EXPECT_EQ(merged[1], 99);
  EXPECT_EQ(merged[2], 88);
  EXPECT_EQ(merged[3], 40);
  EXPECT_EQ(merged[4], 50);
}

TEST(IndexRangeUtilsWrite, ArraySizeMismatch)
{
  Array<int32_t> existing{10, 20, 30, 40, 50};
  Variant existingV{std::move(existing)};
  Array<int32_t> partial{99, 88, 77};
  Variant partialV{std::move(partial)};

  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 2));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeInvalid});
}

TEST(IndexRangeUtilsWrite, ArrayWriteOutOfBounds)
{
  Array<int32_t> existing{10, 20, 30};
  Variant existingV{std::move(existing)};
  Array<int32_t> partial{99};
  Variant partialV{std::move(partial)};

  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(5, 5));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

TEST(IndexRangeUtilsWrite, ScalarStringReplace)
{
  Variant existingV{String{"Hello World"}};
  Variant partialV{String{"XY"}};

  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 1));
  ASSERT_TRUE(result.is_good());
  string_view merged = result.value().as<String>();
  EXPECT_EQ(merged, "XYllo World");
}

TEST(IndexRangeUtilsWrite, ScalarInt32ReturnsNoData)
{
  Variant existingV{int32_t{42}};
  Variant partialV{int32_t{99}};

  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

TEST(IndexRangeUtilsWrite, TypeMismatchReturnsError)
{
  Array<int32_t> existing{10, 20, 30};
  Variant existingV{std::move(existing)};
  Array<String> partial{String{"a"}};
  Variant partialV{std::move(partial)};

  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTypeMismatch});
}

TEST(IndexRangeUtilsWrite, EmptyRangeReturnsPartial)
{
  Variant existingV{int32_t{42}};
  Variant partialV{int32_t{99}};
  ParsedNumericRange emptyRange;

  auto result = index_range_utils::apply_write(existingV, partialV, emptyRange);
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<int32_t>(), 99);
}

TEST(IndexRangeUtilsWrite, ScalarByteStringReplace)
{
  ByteString existing{uint8_t{0x10}, uint8_t{0x20}, uint8_t{0x30}, uint8_t{0x40}};
  Variant existingV{std::move(existing)};
  ByteString partial{uint8_t{0xAA}, uint8_t{0xBB}};
  Variant partialV{std::move(partial)};

  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 2));
  ASSERT_TRUE(result.is_good());
  const auto& merged = result.value().as<ByteString>();
  ASSERT_EQ(merged.size(), 4u);
  EXPECT_EQ(merged[0], uint8_t{0x10});
  EXPECT_EQ(merged[1], uint8_t{0xAA});
  EXPECT_EQ(merged[2], uint8_t{0xBB});
  EXPECT_EQ(merged[3], uint8_t{0x40});
}

// ===========================================================================
// Coverage additions: every 1-D array element type for read and write, 2-D
// ByteString slicing, scalar String/ByteString write error paths, and the
// ErrorDetail content on the failure paths.
// ===========================================================================

// --- apply_read: dispatch over every supported array element type ---

TEST(IndexRangeUtilsReadElementTypes, Boolean)
{
  Array<bool> arr;
  arr.payload() = {true, false, true, false};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 2));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<bool>>();
  ASSERT_EQ(sliced.size(), 2u);
  EXPECT_FALSE(static_cast<bool>(sliced.payload()[0]));
  EXPECT_TRUE(static_cast<bool>(sliced.payload()[1]));
}

TEST(IndexRangeUtilsReadElementTypes, SByte)
{
  Array<int8_t> arr{int8_t{-1}, int8_t{-2}, int8_t{-3}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(0, 1));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<int8_t>>();
  ASSERT_EQ(sliced.size(), 2u);
  EXPECT_EQ(sliced[0], int8_t{-1});
  EXPECT_EQ(sliced[1], int8_t{-2});
}

TEST(IndexRangeUtilsReadElementTypes, Byte)
{
  Array<uint8_t> arr{uint8_t{1}, uint8_t{2}, uint8_t{3}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 2));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<uint8_t>>();
  ASSERT_EQ(sliced.size(), 2u);
  EXPECT_EQ(sliced[0], uint8_t{2});
}

TEST(IndexRangeUtilsReadElementTypes, Int16)
{
  Array<int16_t> arr{int16_t{10}, int16_t{20}, int16_t{30}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<int16_t>>()[0], int16_t{10});
}

TEST(IndexRangeUtilsReadElementTypes, UInt16)
{
  Array<uint16_t> arr{uint16_t{10}, uint16_t{20}, uint16_t{30}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 2));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<uint16_t>>().size(), 2u);
}

TEST(IndexRangeUtilsReadElementTypes, UInt32)
{
  Array<uint32_t> arr{uint32_t{10}, uint32_t{20}, uint32_t{30}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(0, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<uint32_t>>()[1], uint32_t{20});
}

TEST(IndexRangeUtilsReadElementTypes, Int64)
{
  Array<int64_t> arr{int64_t{100}, int64_t{200}, int64_t{300}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(2, 2));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<int64_t>>()[0], int64_t{300});
}

TEST(IndexRangeUtilsReadElementTypes, UInt64)
{
  Array<uint64_t> arr{uint64_t{100}, uint64_t{200}, uint64_t{300}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<uint64_t>>()[0], uint64_t{200});
}

TEST(IndexRangeUtilsReadElementTypes, Float)
{
  Array<float> arr{1.0f, 2.0f, 3.0f};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(0, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<float>>()[1], 2.0f);
}

TEST(IndexRangeUtilsReadElementTypes, Double)
{
  Array<double> arr{1.0, 2.0, 3.0};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 2));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<double>>().size(), 2u);
}

TEST(IndexRangeUtilsReadElementTypes, DateTime)
{
  Array<DateTime> arr{DateTime{2024, 1, 1, 0, 0, 0.0}, DateTime{2024, 1, 2, 0, 0, 0.0}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<DateTime>>().size(), 1u);
}

TEST(IndexRangeUtilsReadElementTypes, Guid)
{
  Array<Guid> arr{Guid::parse("550e8400-e29b-41d4-a716-446655440000"), Guid{}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<Guid>>().size(), 1u);
}

TEST(IndexRangeUtilsReadElementTypes, StringArray1D)
{
  Array<String> arr{String{"abc"}, String{"def"}, String{"ghi"}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(0, 1));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<String>>();
  ASSERT_EQ(sliced.size(), 2u);
  EXPECT_EQ(string_view{sliced[0]}, "abc");
}

TEST(IndexRangeUtilsReadElementTypes, ByteStringArray1D)
{
  Array<ByteString> arr{ByteString{uint8_t{1}, uint8_t{2}}, ByteString{uint8_t{3}, uint8_t{4}}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<ByteString>>().size(), 1u);
}

TEST(IndexRangeUtilsReadElementTypes, NodeIdArray1D)
{
  Array<NodeId> arr{NodeId{uint32_t{1}}, NodeId{uint32_t{2}}, NodeId{uint32_t{3}}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(0, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<NodeId>>()[1], NodeId{uint32_t{2}});
}

TEST(IndexRangeUtilsReadElementTypes, ExpandedNodeIdArray1D)
{
  Array<ExpandedNodeId> arr{ExpandedNodeId{NodeId{uint32_t{1}}}, ExpandedNodeId{NodeId{uint32_t{2}}}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<ExpandedNodeId>>().size(), 1u);
}

TEST(IndexRangeUtilsReadElementTypes, StatusCodeArray1D)
{
  Array<StatusCode> arr{StatusCode{Status::Good}, StatusCode{Status::BadTimeout}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<StatusCode>>()[0], StatusCode{Status::BadTimeout});
}

TEST(IndexRangeUtilsReadElementTypes, QualifiedNameArray1D)
{
  Array<QualifiedName> arr{QualifiedName{"a"}, QualifiedName{"b"}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<QualifiedName>>().size(), 1u);
}

TEST(IndexRangeUtilsReadElementTypes, LocalizedTextArray1D)
{
  Array<LocalizedText> arr{LocalizedText{String{"a"}}, LocalizedText{String{"b"}}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<LocalizedText>>().size(), 1u);
}

TEST(IndexRangeUtilsReadElementTypes, XmlElementArray1D)
{
  XmlElement first;
  first = string_view{"<a/>"};
  XmlElement second;
  second = string_view{"<b/>"};
  Array<XmlElement> arr;
  arr.payload() = {first, second};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<XmlElement>>().size(), 1u);
}

TEST(IndexRangeUtilsReadElementTypes, DataValueArray1D)
{
  DataValue first;
  first.value() = int32_t{1};
  DataValue second;
  second.value() = int32_t{2};
  Array<DataValue> arr;
  arr.payload() = {first, second};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<DataValue>>().size(), 1u);
}

TEST(IndexRangeUtilsReadElementTypes, VariantArray1D)
{
  Array<Variant> arr;
  arr.payload() = {Variant{int32_t{1}}, Variant{String{"x"}}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<Variant>>().size(), 1u);
}

TEST(IndexRangeUtilsReadElementTypes, ExtensionObjectArray1D)
{
  Array<RefStructure<Structure>> arr;
  arr.push_back(RefStructure<Structure>{});
  arr.push_back(RefStructure<Structure>{});
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<RefStructure<Structure>>>().size(), 1u);
}

// --- apply_read: 2-D ByteString array slicing ---

TEST(IndexRangeUtilsRead, ByteStringArray2D)
{
  Array<ByteString> arr{ByteString{uint8_t{0x10}, uint8_t{0x11}, uint8_t{0x12}},
    ByteString{uint8_t{0x20}, uint8_t{0x21}, uint8_t{0x22}}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_2d(0, 1, 1, 2));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<ByteString>>();
  ASSERT_EQ(sliced.size(), 2u);
  ASSERT_EQ(sliced[0].size(), 2u);
  EXPECT_EQ(sliced[0][0], uint8_t{0x11});
  EXPECT_EQ(sliced[0][1], uint8_t{0x12});
  EXPECT_EQ(sliced[1][0], uint8_t{0x21});
}

TEST(IndexRangeUtilsRead, ByteStringArray2DCharOutOfRangeYieldsEmpty)
{
  Array<ByteString> arr{ByteString{uint8_t{0x10}}, ByteString{uint8_t{0x20}}};
  Variant source{std::move(arr)};
  // Char dimension starts past the end of each (length-1) byte string.
  auto result = index_range_utils::apply_read(source, range_2d(0, 1, 5, 9));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<ByteString>>();
  ASSERT_EQ(sliced.size(), 2u);
  EXPECT_TRUE(sliced[0].empty());
  EXPECT_TRUE(sliced[1].empty());
}

TEST(IndexRangeUtilsRead, StringArray2DCharOutOfRangeYieldsEmptyString)
{
  Array<String> arr{String{"a"}, String{"b"}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_2d(0, 1, 5, 9));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<String>>();
  ASSERT_EQ(sliced.size(), 2u);
  EXPECT_TRUE(sliced[0].empty());
}

TEST(IndexRangeUtilsRead, ByteStringArray2DEmptyArrayNoData)
{
  Array<ByteString> arr;
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_2d(0, 0, 0, 0));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

// --- apply_read: error path detail content ---

TEST(IndexRangeUtilsRead, EmptyVariantWithRangeCarriesDetail)
{
  Variant source;
  auto result = index_range_utils::apply_read(source, range_1d(0, 0));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->source, "IndexRangeUtils");
}

TEST(IndexRangeUtilsRead, ThreeDimensionRangeNoData)
{
  Array<int32_t> arr{10, 20, 30};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, make_range({{0, 0}, {0, 0}, {0, 0}}));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

// --- apply_write: every supported 1-D array element type ---

TEST(IndexRangeUtilsWriteElementTypes, Boolean)
{
  Array<bool> existing;
  existing.payload() = {true, true, true};
  Variant existingV{std::move(existing)};
  Array<bool> partial;
  partial.payload() = {false};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  const auto& merged = result.value().as<Array<bool>>();
  ASSERT_EQ(merged.size(), 3u);
  EXPECT_FALSE(static_cast<bool>(merged.payload()[1]));
  EXPECT_TRUE(static_cast<bool>(merged.payload()[0]));
}

TEST(IndexRangeUtilsWriteElementTypes, Byte)
{
  Array<uint8_t> existing{uint8_t{1}, uint8_t{2}, uint8_t{3}};
  Variant existingV{std::move(existing)};
  Array<uint8_t> partial{uint8_t{9}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<uint8_t>>()[0], uint8_t{9});
}

TEST(IndexRangeUtilsWriteElementTypes, Int16)
{
  Array<int16_t> existing{int16_t{1}, int16_t{2}, int16_t{3}};
  Variant existingV{std::move(existing)};
  Array<int16_t> partial{int16_t{99}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(2, 2));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<int16_t>>()[2], int16_t{99});
}

TEST(IndexRangeUtilsWriteElementTypes, UInt16)
{
  Array<uint16_t> existing{uint16_t{1}, uint16_t{2}};
  Variant existingV{std::move(existing)};
  Array<uint16_t> partial{uint16_t{77}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<uint16_t>>()[0], uint16_t{77});
}

TEST(IndexRangeUtilsWriteElementTypes, UInt32)
{
  Array<uint32_t> existing{uint32_t{1}, uint32_t{2}};
  Variant existingV{std::move(existing)};
  Array<uint32_t> partial{uint32_t{55}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<uint32_t>>()[1], uint32_t{55});
}

TEST(IndexRangeUtilsWriteElementTypes, Int64)
{
  Array<int64_t> existing{int64_t{1}, int64_t{2}};
  Variant existingV{std::move(existing)};
  Array<int64_t> partial{int64_t{555}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<int64_t>>()[0], int64_t{555});
}

TEST(IndexRangeUtilsWriteElementTypes, UInt64)
{
  Array<uint64_t> existing{uint64_t{1}, uint64_t{2}};
  Variant existingV{std::move(existing)};
  Array<uint64_t> partial{uint64_t{999}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<uint64_t>>()[1], uint64_t{999});
}

TEST(IndexRangeUtilsWriteElementTypes, Float)
{
  Array<float> existing{1.0f, 2.0f};
  Variant existingV{std::move(existing)};
  Array<float> partial{9.5f};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<float>>()[0], 9.5f);
}

TEST(IndexRangeUtilsWriteElementTypes, Double)
{
  Array<double> existing{1.0, 2.0};
  Variant existingV{std::move(existing)};
  Array<double> partial{9.5};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<double>>()[1], 9.5);
}

TEST(IndexRangeUtilsWriteElementTypes, DateTime)
{
  Array<DateTime> existing{DateTime{2024, 1, 1, 0, 0, 0.0}, DateTime{2024, 1, 2, 0, 0, 0.0}};
  Variant existingV{std::move(existing)};
  Array<DateTime> partial{DateTime{2025, 5, 5, 0, 0, 0.0}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<DateTime>>().size(), 2u);
}

TEST(IndexRangeUtilsWriteElementTypes, Guid)
{
  Array<Guid> existing{Guid{}, Guid{}};
  Variant existingV{std::move(existing)};
  Array<Guid> partial{Guid::parse("550e8400-e29b-41d4-a716-446655440000")};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<Guid>>().size(), 2u);
}

TEST(IndexRangeUtilsWriteElementTypes, StringArray1D)
{
  Array<String> existing{String{"a"}, String{"b"}, String{"c"}};
  Variant existingV{std::move(existing)};
  Array<String> partial{String{"X"}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  const auto& merged = result.value().as<Array<String>>();
  EXPECT_EQ(string_view{merged[1]}, "X");
  EXPECT_EQ(string_view{merged[0]}, "a");
}

TEST(IndexRangeUtilsWriteElementTypes, ByteStringArray1D)
{
  Array<ByteString> existing{ByteString{uint8_t{1}}, ByteString{uint8_t{2}}};
  Variant existingV{std::move(existing)};
  Array<ByteString> partial{ByteString{uint8_t{9}}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<ByteString>>().size(), 2u);
}

TEST(IndexRangeUtilsWriteElementTypes, NodeIdArray1D)
{
  Array<NodeId> existing{NodeId{uint32_t{1}}, NodeId{uint32_t{2}}};
  Variant existingV{std::move(existing)};
  Array<NodeId> partial{NodeId{uint32_t{99}}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<NodeId>>()[1], NodeId{uint32_t{99}});
}

TEST(IndexRangeUtilsWriteElementTypes, ExpandedNodeIdArray1D)
{
  Array<ExpandedNodeId> existing{ExpandedNodeId{NodeId{uint32_t{1}}}, ExpandedNodeId{NodeId{uint32_t{2}}}};
  Variant existingV{std::move(existing)};
  Array<ExpandedNodeId> partial{ExpandedNodeId{NodeId{uint32_t{9}}}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<ExpandedNodeId>>().size(), 2u);
}

TEST(IndexRangeUtilsWriteElementTypes, StatusCodeArray1D)
{
  Array<StatusCode> existing{StatusCode{Status::Good}, StatusCode{Status::Good}};
  Variant existingV{std::move(existing)};
  Array<StatusCode> partial{StatusCode{Status::BadTimeout}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<StatusCode>>()[1], StatusCode{Status::BadTimeout});
}

TEST(IndexRangeUtilsWriteElementTypes, QualifiedNameArray1D)
{
  Array<QualifiedName> existing{QualifiedName{"a"}, QualifiedName{"b"}};
  Variant existingV{std::move(existing)};
  Array<QualifiedName> partial{QualifiedName{"Z"}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<QualifiedName>>().size(), 2u);
}

TEST(IndexRangeUtilsWriteElementTypes, LocalizedTextArray1D)
{
  Array<LocalizedText> existing{LocalizedText{String{"a"}}, LocalizedText{String{"b"}}};
  Variant existingV{std::move(existing)};
  Array<LocalizedText> partial{LocalizedText{String{"Z"}}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<LocalizedText>>().size(), 2u);
}

TEST(IndexRangeUtilsWriteElementTypes, XmlElementArray1D)
{
  XmlElement a;
  a = string_view{"<a/>"};
  XmlElement b;
  b = string_view{"<b/>"};
  XmlElement z;
  z = string_view{"<z/>"};
  Array<XmlElement> existing;
  existing.payload() = {a, b};
  Variant existingV{std::move(existing)};
  Array<XmlElement> partial;
  partial.payload() = {z};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<XmlElement>>().size(), 2u);
}

TEST(IndexRangeUtilsWriteElementTypes, DataValueArray1D)
{
  DataValue a;
  a.value() = int32_t{1};
  DataValue b;
  b.value() = int32_t{2};
  DataValue z;
  z.value() = int32_t{99};
  Array<DataValue> existing;
  existing.payload() = {a, b};
  Variant existingV{std::move(existing)};
  Array<DataValue> partial;
  partial.payload() = {z};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(1, 1));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<DataValue>>().size(), 2u);
}

TEST(IndexRangeUtilsWriteElementTypes, VariantArray1D)
{
  Array<Variant> existing;
  existing.payload() = {Variant{int32_t{1}}, Variant{int32_t{2}}};
  Variant existingV{std::move(existing)};
  Array<Variant> partial;
  partial.payload() = {Variant{int32_t{99}}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<Variant>>()[0].as<int32_t>(), 99);
}

TEST(IndexRangeUtilsWriteElementTypes, ExtensionObjectArray1D)
{
  Array<RefStructure<Structure>> existing;
  existing.push_back(RefStructure<Structure>{});
  existing.push_back(RefStructure<Structure>{});
  Variant existingV{std::move(existing)};
  Array<RefStructure<Structure>> partial;
  partial.push_back(RefStructure<Structure>{});
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_good());
  EXPECT_EQ(result.value().as<Array<RefStructure<Structure>>>().size(), 2u);
}

// --- apply_write: 2-D ByteString array ---

TEST(IndexRangeUtilsWrite, ByteStringArray2DReplace)
{
  Array<ByteString> existing{ByteString{uint8_t{0x10}, uint8_t{0x11}, uint8_t{0x12}},
    ByteString{uint8_t{0x20}, uint8_t{0x21}, uint8_t{0x22}}};
  Variant existingV{std::move(existing)};
  Array<ByteString> partial{
    ByteString{uint8_t{0xAA}, uint8_t{0xBB}}, ByteString{uint8_t{0xCC}, uint8_t{0xDD}}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_2d(0, 1, 1, 2));
  ASSERT_TRUE(result.is_good());
  const auto& merged = result.value().as<Array<ByteString>>();
  ASSERT_EQ(merged.size(), 2u);
  EXPECT_EQ(merged[0][0], uint8_t{0x10});
  EXPECT_EQ(merged[0][1], uint8_t{0xAA});
  EXPECT_EQ(merged[0][2], uint8_t{0xBB});
}

TEST(IndexRangeUtilsWrite, StringArray2DReplace)
{
  Array<String> existing{String{"abc"}, String{"def"}};
  Variant existingV{std::move(existing)};
  Array<String> partial{String{"XY"}, String{"ZW"}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_2d(0, 1, 1, 2));
  ASSERT_TRUE(result.is_good());
  const auto& merged = result.value().as<Array<String>>();
  ASSERT_EQ(merged.size(), 2u);
  EXPECT_EQ(string_view{merged[0]}, "aXY");
  EXPECT_EQ(string_view{merged[1]}, "dZW");
}

TEST(IndexRangeUtilsWrite, ByteStringArray2DCharOutOfRangeKeepsExisting)
{
  Array<ByteString> existing{ByteString{uint8_t{0x10}}, ByteString{uint8_t{0x20}}};
  Variant existingV{std::move(existing)};
  Array<ByteString> partial{ByteString{}, ByteString{}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_2d(0, 1, 5, 9));
  ASSERT_TRUE(result.is_good());
  const auto& merged = result.value().as<Array<ByteString>>();
  ASSERT_EQ(merged.size(), 2u);
  EXPECT_EQ(merged[0][0], uint8_t{0x10});
}

TEST(IndexRangeUtilsWrite, StringArray2DCharOutOfRangeKeepsExisting)
{
  Array<String> existing{String{"a"}, String{"b"}};
  Variant existingV{std::move(existing)};
  Array<String> partial{String{""}, String{""}};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_2d(0, 1, 5, 9));
  ASSERT_TRUE(result.is_good());
  const auto& merged = result.value().as<Array<String>>();
  ASSERT_EQ(merged.size(), 2u);
  EXPECT_EQ(string_view{merged[0]}, "a");
}

TEST(IndexRangeUtilsWrite, ByteStringArray2DUnsupportedElementNoData)
{
  Array<int32_t> existing{1, 2, 3};
  Variant existingV{std::move(existing)};
  Array<int32_t> partial{9, 9, 9};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, range_2d(0, 1, 0, 1));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

// --- apply_write: scalar error paths and ErrorDetail content ---

TEST(IndexRangeUtilsWrite, ScalarStringSizeMismatchInvalid)
{
  Variant existingV{String{"Hello"}};
  Variant partialV{String{"X"}};  // range is 2 chars but partial is 1
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 1));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeInvalid});
  ASSERT_NE(result.error_detail(), nullptr);
  EXPECT_EQ(result.error_detail()->code, "IndexRangeInvalid");
}

TEST(IndexRangeUtilsWrite, ScalarStringStartOutOfBoundsNoData)
{
  Variant existingV{String{"Hi"}};
  Variant partialV{String{"X"}};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(5, 5));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

TEST(IndexRangeUtilsWrite, ScalarStringWrongPartialTypeMismatch)
{
  Variant existingV{String{"Hello"}};
  Variant partialV{int32_t{1}};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 1));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTypeMismatch});
}

TEST(IndexRangeUtilsWrite, ScalarByteStringWrongPartialTypeMismatch)
{
  Variant existingV{ByteString{uint8_t{1}, uint8_t{2}, uint8_t{3}}};
  Variant partialV{int32_t{1}};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 1));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTypeMismatch});
}

TEST(IndexRangeUtilsWrite, ScalarByteStringSizeMismatchInvalid)
{
  Variant existingV{ByteString{uint8_t{1}, uint8_t{2}, uint8_t{3}}};
  Variant partialV{ByteString{uint8_t{9}}};  // range is 2 bytes but partial is 1
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 1));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeInvalid});
}

TEST(IndexRangeUtilsWrite, ScalarByteStringStartOutOfBoundsNoData)
{
  Variant existingV{ByteString{uint8_t{1}, uint8_t{2}}};
  Variant partialV{ByteString{uint8_t{9}}};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(5, 5));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

// --- apply_write: shape mismatches and unsupported scalar types ---

TEST(IndexRangeUtilsWrite, ArrayExistingScalarPartialTypeMismatch)
{
  Array<int32_t> existing{1, 2, 3};
  Variant existingV{std::move(existing)};
  Variant partialV{int32_t{9}};  // scalar partial against array existing
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadTypeMismatch});
}

TEST(IndexRangeUtilsWrite, ScalarInt32UnsupportedTypeNoData)
{
  Variant existingV{int32_t{1}};
  Variant partialV{int32_t{2}};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

TEST(IndexRangeUtilsWrite, ScalarMultiDimensionNoData)
{
  Variant existingV{String{"Hello"}};
  Variant partialV{String{"XY"}};
  auto result = index_range_utils::apply_write(existingV, partialV, range_2d(0, 1, 0, 1));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

TEST(IndexRangeUtilsWrite, ArrayThreeDimensionNoData)
{
  Array<int32_t> existing{1, 2, 3};
  Variant existingV{std::move(existing)};
  Array<int32_t> partial{9};
  Variant partialV{std::move(partial)};
  auto result = index_range_utils::apply_write(existingV, partialV, make_range({{0, 0}, {0, 0}, {0, 0}}));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

TEST(IndexRangeUtilsWrite, EmptyExistingNoData)
{
  Variant existingV;
  Variant partialV{int32_t{9}};
  auto result = index_range_utils::apply_write(existingV, partialV, range_1d(0, 0));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

// NOTE: there is intentionally no "unsupported array element type" test. A
// Variant cannot hold an Array<Decimal> (and similar non-Variant element types) -
// constructing/accessing one throws BadInvalidState - so the dispatch table's
// default branch is unreachable defensive code with a well-formed Variant.

// ===== Multi-dimensional (true N-D) array tests =====

namespace
{

// Build a row-major multi-dimensional Int32 array Variant with the given dimensions, valued 0..N-1.
Variant make_matrix_i32(Dimensions dims)
{
  size_t total = 1;
  for (auto d : dims)
    total *= static_cast<size_t>(d);
  std::vector<int32_t> payload(total);
  for (size_t i = 0; i < total; ++i)
    payload[i] = static_cast<int32_t>(i);
  return Variant{Array<int32_t>{dims, payload}};
}

ParsedNumericRange range_3d(uint32_t l0, uint32_t h0, uint32_t l1, uint32_t h1, uint32_t l2, uint32_t h2)
{
  return make_range({{l0, h0}, {l1, h1}, {l2, h2}});
}

}  // namespace

// A 3x4 matrix sliced [1:2, 1:2] yields a 2x2 sub-block with the correct row-major values and
// ArrayDimensions metadata.
TEST(IndexRangeUtilsNd, Read2DMiddleBlock)
{
  Variant source = make_matrix_i32({3, 4});  // payload row-major: row*4 + col
  auto result = index_range_utils::apply_read(source, range_2d(1, 2, 1, 2));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<int32_t>>();
  ASSERT_EQ(sliced.size(), 4u);
  EXPECT_EQ(sliced[0], 5);  // (1,1)
  EXPECT_EQ(sliced[1], 6);  // (1,2)
  EXPECT_EQ(sliced[2], 9);  // (2,1)
  EXPECT_EQ(sliced[3], 10);  // (2,2)
  ASSERT_TRUE(sliced.dimensions().has_value());
  EXPECT_EQ(*sliced.dimensions(), (Dimensions{2, 2}));
}

// A single-row slice [1:1, 0:3] yields a 1x4 block.
TEST(IndexRangeUtilsNd, Read2DSingleRow)
{
  Variant source = make_matrix_i32({3, 4});
  auto result = index_range_utils::apply_read(source, range_2d(1, 1, 0, 3));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<int32_t>>();
  ASSERT_EQ(sliced.size(), 4u);
  EXPECT_EQ(sliced[0], 4);
  EXPECT_EQ(sliced[3], 7);
  EXPECT_EQ(*sliced.dimensions(), (Dimensions{1, 4}));
}

// A high bound beyond the dimension extent is clamped to the last valid index.
TEST(IndexRangeUtilsNd, Read2DClampsHighBound)
{
  Variant source = make_matrix_i32({2, 3});
  auto result = index_range_utils::apply_read(source, range_2d(0, 9, 1, 9));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<int32_t>>();
  // rows 0..1, cols 1..2 -> 2x2: (0,1)=1,(0,2)=2,(1,1)=4,(1,2)=5
  ASSERT_EQ(sliced.size(), 4u);
  EXPECT_EQ(sliced[0], 1);
  EXPECT_EQ(sliced[1], 2);
  EXPECT_EQ(sliced[2], 4);
  EXPECT_EQ(sliced[3], 5);
  EXPECT_EQ(*sliced.dimensions(), (Dimensions{2, 2}));
}

// A start index past a dimension's size yields Bad_IndexRangeNoData.
TEST(IndexRangeUtilsNd, Read2DStartOutOfBoundsReturnsNoData)
{
  Variant source = make_matrix_i32({2, 3});
  auto result = index_range_utils::apply_read(source, range_2d(5, 5, 0, 0));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeNoData});
}

// Part 4 section 7.27: a range whose dimension count differs from the array's rank is valid syntax that is
// not valid for this Value, so a read answers Bad_IndexRangeNoData (NR-10 rule 9). Bad_IndexRangeInvalid is
// only for invalid syntax.
// @relation(AC-COMP-CORE-INDEX-RANGE-APPLY-TO-VALUE-02-APPLY-READ-DIMENSION-MISMATCH-NO-DATA, scope=function)
TEST(IndexRangeUtilsNd, Read2DDimensionCountMismatchIsNoData)
{
  Variant source = make_matrix_i32({2, 3});
  auto result = index_range_utils::apply_read(source, range_1d(0, 1));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code().as_status(), Status::BadIndexRangeNoData);
}

// 3-D slicing walks the flattened payload in row-major order.
TEST(IndexRangeUtilsNd, Read3DBlock)
{
  Variant source = make_matrix_i32({2, 2, 2});  // values 0..7
  auto result = index_range_utils::apply_read(source, range_3d(0, 1, 1, 1, 0, 1));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<int32_t>>();
  // rows 0..1, mid=1, cols 0..1 -> (0,1,0)=2,(0,1,1)=3,(1,1,0)=6,(1,1,1)=7
  ASSERT_EQ(sliced.size(), 4u);
  EXPECT_EQ(sliced[0], 2);
  EXPECT_EQ(sliced[1], 3);
  EXPECT_EQ(sliced[2], 6);
  EXPECT_EQ(sliced[3], 7);
  EXPECT_EQ(*sliced.dimensions(), (Dimensions{2, 1, 2}));
}

// A genuine 2-D String matrix slices element-wise (not as a char-range).
TEST(IndexRangeUtilsNd, Read2DStringMatrix)
{
  Array<String> arr{
    Dimensions{2, 2}, std::vector<String>{String{"a"}, String{"b"}, String{"c"}, String{"d"}}};
  Variant source{std::move(arr)};
  auto result = index_range_utils::apply_read(source, range_2d(0, 1, 1, 1));
  ASSERT_TRUE(result.is_good());
  const auto& sliced = result.value().as<Array<String>>();
  ASSERT_EQ(sliced.size(), 2u);
  EXPECT_EQ(string_view{sliced[0]}, "b");
  EXPECT_EQ(string_view{sliced[1]}, "d");
  EXPECT_EQ(*sliced.dimensions(), (Dimensions{2, 1}));
}

// Writing a 2x2 sub-block replaces exactly those elements and preserves the rest + dimensions.
TEST(IndexRangeUtilsNd, Write2DSubBlock)
{
  Variant existing = make_matrix_i32({3, 4});  // 0..11
  Array<int32_t> partial{Dimensions{2, 2}, std::vector<int32_t>{100, 101, 102, 103}};
  Variant partialV{std::move(partial)};

  auto result = index_range_utils::apply_write(existing, partialV, range_2d(1, 2, 1, 2));
  ASSERT_TRUE(result.is_good());
  const auto& merged = result.value().as<Array<int32_t>>();
  ASSERT_EQ(merged.size(), 12u);
  // Overwritten: (1,1)=idx5,(1,2)=idx6,(2,1)=idx9,(2,2)=idx10
  EXPECT_EQ(merged[5], 100);
  EXPECT_EQ(merged[6], 101);
  EXPECT_EQ(merged[9], 102);
  EXPECT_EQ(merged[10], 103);
  // Untouched neighbours
  EXPECT_EQ(merged[0], 0);
  EXPECT_EQ(merged[4], 4);
  EXPECT_EQ(merged[7], 7);
  EXPECT_EQ(merged[11], 11);
  ASSERT_TRUE(merged.dimensions().has_value());
  EXPECT_EQ(*merged.dimensions(), (Dimensions{3, 4}));
}

// A partial block whose element count differs from the range extent is Bad_IndexRangeInvalid.
TEST(IndexRangeUtilsNd, Write2DSizeMismatchIsInvalid)
{
  Variant existing = make_matrix_i32({3, 4});
  Array<int32_t> partial{Dimensions{2, 1}, std::vector<int32_t>{100, 101}};
  Variant partialV{std::move(partial)};

  auto result = index_range_utils::apply_write(existing, partialV, range_2d(1, 2, 1, 2));
  ASSERT_TRUE(result.is_bad());
  EXPECT_EQ(result.status_code(), StatusCode{Status::BadIndexRangeInvalid});
}

// NR-42 A-14: a write whose range has a different number of dimensions from the matrix keeps
// Bad_IndexRangeInvalid (Part 4 section 5.10.4.4, Table 61: "the passed IndexRange cannot be written by the
// Server"); only the read's code changes. The write-side twin of Read2DDimensionCountMismatchIsNoData, and a
// guard: it fails if the read's change reaches the write.
// @relation(AC-SVR-ATTR-WRITE-020-DIMENSION-COUNT-MISMATCH-STAYS-INVALID, scope=function)
TEST(IndexRangeUtilsNd, Write2DDimensionCountMismatchIsInvalid)
{
  Variant existing = make_matrix_i32({2, 3});
  Variant partial{Array<int32_t>{10, 11}};

  auto mismatched = index_range_utils::apply_write(existing, partial, range_1d(0, 1));
  ASSERT_TRUE(mismatched.is_bad());
  EXPECT_EQ(mismatched.status_code().as_status(), Status::BadIndexRangeInvalid);

  Array<int32_t> block{Dimensions{2, 2}, std::vector<int32_t>{20, 21, 22, 23}};
  auto matching = index_range_utils::apply_write(existing, Variant{std::move(block)}, range_2d(0, 1, 1, 2));
  ASSERT_TRUE(matching.is_good()) << "the two-dimension control was refused";
  const auto& merged = matching.value().as<Array<int32_t>>();
  EXPECT_EQ(merged.payload(), (std::vector<int32_t>{0, 20, 21, 3, 22, 23}));
}

// A read slice written straight back reproduces the original matrix (round-trip).
TEST(IndexRangeUtilsNd, ReadThenWriteRoundTrip)
{
  Variant original = make_matrix_i32({3, 4});
  auto range = range_2d(0, 2, 0, 3);  // whole matrix
  auto readBack = index_range_utils::apply_read(original, range);
  ASSERT_TRUE(readBack.is_good());

  auto written = index_range_utils::apply_write(original, readBack.value(), range);
  ASSERT_TRUE(written.is_good());
  const auto& merged = written.value().as<Array<int32_t>>();
  const auto& orig = original.as<Array<int32_t>>();
  ASSERT_EQ(merged.size(), orig.size());
  for (size_t i = 0; i < orig.size(); ++i)
    EXPECT_EQ(merged[i], orig[i]) << "element " << i;
}
