// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include <gtest/gtest.h>

#include "test_utilities.h"

#include "ua_binary_codec.h"
#include "ua_diagnostic_info.h"
#include "ua_encoding_limits.h"
#include "ua_memory_stream.h"
#include "ua_server_configuration.h"
#include "ua_server_encoding_limits.h"
#include "ua_structure_factory.h"
#include "ua_variant.h"

#include "ua_array.h"
#include "ua_data_type_registration.h"
#include "ua_decimal.h"
#include "ua_object_id.h"
#include "ua_request_header.h"

#include <limits>
#include <memory>
#include <functional>

namespace
{

class ObservedReadStream : public ua::MemoryStream<ua::memory_stream_device::ExternalReadOnly>
{
public:
  ObservedReadStream(
    ua::memory_stream_device::ExternalReadOnly& device, std::function<void(size_t)> beforeRead)
    : MemoryStream(device), mBeforeRead(std::move(beforeRead))
  {}

  void read_all(ua::span<ua::byte> destination) const override
  {
    mBeforeRead(get_position());
    MemoryStream::read_all(destination);
  }

private:
  std::function<void(size_t)> mBeforeRead;
};

void append_i32(std::vector<ua::byte>& out, int32_t value)
{
  // UA Binary uses little-endian encoding.
  const uint32_t u = static_cast<uint32_t>(value);
  out.push_back(static_cast<ua::byte>(u & 0xFFu));
  out.push_back(static_cast<ua::byte>((u >> 8u) & 0xFFu));
  out.push_back(static_cast<ua::byte>((u >> 16u) & 0xFFu));
  out.push_back(static_cast<ua::byte>((u >> 24u) & 0xFFu));
}

void append_bytes(std::vector<ua::byte>& out, size_t count, std::byte value)
{
  out.insert(out.end(), count, value);
}

static void expect_runtime_exception_status(const std::function<void()>& fn, ua::Status expected)
{
  try
  {
    fn();
    FAIL() << "Expected UaException";
  }
  catch (const ua::UaException& ex)
  {
    EXPECT_EQ(ex.status(), expected);
  }
}

// Builds the UA Binary wire form of `levels` nested DiagnosticInfo values. Each level sets ONLY the
// InnerDiagnosticInfo bit (bit 6 == 0x40), so decoding descends exactly one recursion level per byte;
// the innermost level has an empty mask (0x00 == no further nesting). A DiagnosticInfo can nest an
// InnerDiagnosticInfo without any wire-level bound, which is the lever for the decode-recursion DoS.
std::vector<ua::byte> make_nested_diagnostic_info(size_t levels)
{
  std::vector<ua::byte> out(levels, static_cast<ua::byte>(0x40));
  out.push_back(static_cast<ua::byte>(0x00));
  return out;
}

}  // namespace

TEST(UaBinaryEncodingLimitsTests, StringOverLimitIsRejected)
{
  auto appCfg = ua::test_utils::create_test_config();
  ua::server::ServerConfig serverCfg;
  serverCfg.server_capabilities().maxStringLength = 5;

  const auto limits = ua::server::make_server_encoding_limits(appCfg, serverCfg);

  std::vector<ua::byte> encoded;
  append_i32(encoded, 6);
  append_bytes(encoded, 6, std::byte{'a'});

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, limits};

  std::string out;
  expect_runtime_exception_status(
    [&]() { decoder.decode(limits.stack_depth(), out); }, ua::Status::BadEncodingLimitsExceeded);
}

TEST(UaBinaryEncodingLimitsTests, StringAtLimitIsAccepted)
{
  auto appCfg = ua::test_utils::create_test_config();
  ua::server::ServerConfig serverCfg;
  serverCfg.server_capabilities().maxStringLength = 5;

  const auto limits = ua::server::make_server_encoding_limits(appCfg, serverCfg);

  std::vector<ua::byte> encoded;
  append_i32(encoded, 5);
  append_bytes(encoded, 5, std::byte{'b'});

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, limits};

  std::string out;
  decoder.decode(limits.stack_depth(), out);
  EXPECT_EQ(out, std::string(5, 'b'));
}

TEST(UaBinaryEncodingLimitsTests, ByteStringOverLimitIsRejected)
{
  auto appCfg = ua::test_utils::create_test_config();
  ua::server::ServerConfig serverCfg;
  serverCfg.server_capabilities().maxByteStringLength = 3;

  const auto limits = ua::server::make_server_encoding_limits(appCfg, serverCfg);

  std::vector<ua::byte> encoded;
  append_i32(encoded, 4);
  append_bytes(encoded, 4, std::byte{0xCC});

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, limits};

  ua::ByteString out;
  expect_runtime_exception_status(
    [&]() { decoder.decode(limits.stack_depth(), out); }, ua::Status::BadEncodingLimitsExceeded);
}

TEST(UaBinaryEncodingLimitsTests, ArrayOverLimitIsRejected)
{
  auto appCfg = ua::test_utils::create_test_config();
  ua::server::ServerConfig serverCfg;
  serverCfg.server_capabilities().maxArrayLength = 2;

  const auto limits = ua::server::make_server_encoding_limits(appCfg, serverCfg);

  // UA Binary Array<T>: length (int32) then payload.
  std::vector<ua::byte> encoded;
  append_i32(encoded, 3);
  append_i32(encoded, 1);
  append_i32(encoded, 2);
  append_i32(encoded, 3);

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, limits};

  ua::Array<int32_t> out;
  expect_runtime_exception_status(
    [&]() { decoder.decode(limits.stack_depth(), out); }, ua::Status::BadEncodingLimitsExceeded);
}

TEST(UaBinaryEncodingLimitsTests, ArrayDimensionsCountOverLimitIsRejected)
{
  auto appCfg = ua::test_utils::create_test_config();
  ua::server::ServerConfig serverCfg;
  serverCfg.server_capabilities().maxArrayLength = 2;

  const auto limits = ua::server::make_server_encoding_limits(appCfg, serverCfg);

  // Variant encoding mask = ArrayOfValues (0x80) | ArrayDimensions (0x40) | Int32 (0x06).
  // The value array is empty (length 0); the dimensions array declares a count (3) over the cap (2).
  // The stream carries ONLY the dimensions length field, with nothing after it, so the cap must fire
  // before any allocation/read of the dimension entries (limit error, not a read-underflow).
  std::vector<ua::byte> encoded;
  encoded.push_back(static_cast<ua::byte>(0xC6));
  append_i32(encoded, 0);  // value array length: empty
  append_i32(encoded, 3);  // dimensions count: over the cap of 2

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, limits};

  ua::Variant out;
  expect_runtime_exception_status(
    [&]() { decoder.decode(limits.stack_depth(), out); }, ua::Status::BadEncodingLimitsExceeded);
}

TEST(UaBinaryEncodingLimitsTests, BoolArrayOverLimitIsRejected)
{
  auto appCfg = ua::test_utils::create_test_config();
  ua::server::ServerConfig serverCfg;
  serverCfg.server_capabilities().maxArrayLength = 2;

  const auto limits = ua::server::make_server_encoding_limits(appCfg, serverCfg);

  // Array<bool>: length (int32) then payload. The declared length (3) exceeds the cap (2); the stream
  // carries ONLY the length field, so the cap must fire before allocation (limit error, not underflow).
  std::vector<ua::byte> encoded;
  append_i32(encoded, 3);

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, limits};

  ua::Array<bool> out;
  expect_runtime_exception_status(
    [&]() { decoder.decode(limits.stack_depth(), out); }, ua::Status::BadEncodingLimitsExceeded);
}

// --- Bare-constructed EncodingLimits now carries a bounded floor (P0.2) ------------------------
// A decoder built from a default EncodingLimits{} (no server-derived caps) must be fail-closed
// against hostile remote wire input rather than an allocation bomb. These feed only the length
// field, so the cap fires before allocation (limit error, not read-underflow). RED before the
// floor change (default was SIZE_MAX -> no rejection).

TEST(UaBinaryEncodingLimitsTests, BareDecoderDefaultRejectsOversizedString)
{
  std::vector<ua::byte> encoded;
  append_i32(encoded, (1 * 1024 * 1024) + 1);  // 1 byte over the 1 MB floor

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, ua::EncodingLimits{}};

  std::string out;
  expect_runtime_exception_status([&]() { decoder.decode(ua::EncodingLimits{}.stack_depth(), out); },
    ua::Status::BadEncodingLimitsExceeded);
}

TEST(UaBinaryEncodingLimitsTests, BareDecoderDefaultRejectsOversizedByteString)
{
  std::vector<ua::byte> encoded;
  append_i32(encoded, (16 * 1024 * 1024) + 1);  // 1 byte over the 16 MB floor

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, ua::EncodingLimits{}};

  ua::ByteString out;
  expect_runtime_exception_status([&]() { decoder.decode(ua::EncodingLimits{}.stack_depth(), out); },
    ua::Status::BadEncodingLimitsExceeded);
}

TEST(UaBinaryEncodingLimitsTests, BareDecoderDefaultRejectsOversizedArray)
{
  std::vector<ua::byte> encoded;
  append_i32(encoded, 65535 + 1);  // 1 element over the 65535 floor

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, ua::EncodingLimits{}};

  ua::Array<int32_t> out;
  expect_runtime_exception_status([&]() { decoder.decode(ua::EncodingLimits{}.stack_depth(), out); },
    ua::Status::BadEncodingLimitsExceeded);
}

TEST(UaBinaryEncodingLimitsTests, TrustedLocalLimitsRaiseCapsAboveFloor)
{
  // The trusted-local factory lifts the size caps so a large-but-legitimate local document (e.g. the
  // built-in NS0 nodeset or an operator-supplied NodeSet) decodes successfully. An array of 70000
  // int32 elements is over the 65535 default floor but must decode under trusted-local limits.
  auto appCfg = ua::test_utils::create_test_config();
  const auto trusted = ua::make_trusted_local_encoding_limits(appCfg);
  const auto bounded = ua::make_encoding_limits(appCfg);

  constexpr int32_t count = 70000;
  std::vector<ua::byte> encoded;
  append_i32(encoded, count);
  for (int32_t i = 0; i < count; ++i)
  {
    append_i32(encoded, i);
  }

  // Bounded (default-floor) limits reject it.
  {
    ua::memory_stream_device::ExternalReadOnly device{encoded};
    ua::MemoryStream stream{device};
    ua::StructureFactory factory;
    ua::UaBinaryDecoder decoder{factory.resolver(), stream, bounded};
    ua::Array<int32_t> out;
    expect_runtime_exception_status(
      [&]() { decoder.decode(bounded.stack_depth(), out); }, ua::Status::BadEncodingLimitsExceeded);
  }

  // Trusted-local limits accept it.
  {
    ua::memory_stream_device::ExternalReadOnly device{encoded};
    ua::MemoryStream stream{device};
    ua::StructureFactory factory;
    ua::UaBinaryDecoder decoder{factory.resolver(), stream, trusted};
    ua::Array<int32_t> out;
    decoder.decode(trusted.stack_depth(), out);
    EXPECT_EQ(out.size(), static_cast<size_t>(count));
  }
}

// --- Recursion-depth guard (native-stack-overflow DoS) -----------------------------------------
// A DiagnosticInfo nests an InnerDiagnosticInfo with no wire-level bound, so a hostile peer can drive
// the decoder into unbounded native recursion (a PRE-AUTH DoS: DiagnosticInfo rides in service
// request/response/fault paths). The size-oriented work budget does not stop this - it permits
// ~maxWork^2 byte reads, astronomically more than the native stack survives. The StackDepth depth
// guard must reject the descent cleanly with BadEncodingLimitsExceeded once it passes the depth cap.

TEST(UaBinaryEncodingLimitsTests, DeeplyNestedDiagnosticInfoIsRejectedNotStackOverflow)
{
  // 5000 levels is well past kDefaultMaxDepth (100); the guard must fire long before the stack dies.
  const auto encoded = make_nested_diagnostic_info(5000);

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, ua::EncodingLimits{}};

  ua::DiagnosticInfo out;
  expect_runtime_exception_status([&]() { decoder.decode(ua::EncodingLimits{}.stack_depth(), out); },
    ua::Status::BadEncodingLimitsExceeded);
}

TEST(UaBinaryEncodingLimitsTests, ModestlyNestedDiagnosticInfoIsAccepted)
{
  // The guard must not regress legitimate nesting: a handful of InnerDiagnosticInfo levels (far under
  // the cap) decodes successfully. Without this, a too-tight cap would be a silent correctness bug.
  const auto encoded = make_nested_diagnostic_info(64);

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, ua::EncodingLimits{}};

  ua::DiagnosticInfo out;
  EXPECT_NO_THROW(decoder.decode(ua::EncodingLimits{}.stack_depth(), out));
}

// @verifies CL-ADDRSP-007
// @relation(CL-ADDRSP-007, scope=function)
TEST(UaBinaryEncodingLimitsTests, DefaultRecursionBoundaryAccepts100AndRejects101)
{
  const ua::EncodingLimits limits{};

  // make_nested_diagnostic_info(N) produces one outer value plus N inner descents. Ninety-nine inner
  // values therefore exercise exactly 100 live decoder frames, the mandatory supported floor.
  const auto acceptedEncoding = make_nested_diagnostic_info(99);
  ua::memory_stream_device::ExternalReadOnly acceptedDevice{acceptedEncoding};
  ua::MemoryStream acceptedStream{acceptedDevice};
  ua::StructureFactory acceptedFactory;
  ua::UaBinaryDecoder acceptedDecoder{acceptedFactory.resolver(), acceptedStream, limits};
  ua::DiagnosticInfo accepted;
  EXPECT_NO_THROW(acceptedDecoder.decode(limits.stack_depth(), accepted));

  // One further inner value reaches frame 101 and must fail through the shared recursion guard rather than
  // recursing into the native stack. Variant and ExtensionObject decoding use this same StackDepth budget.
  const auto rejectedEncoding = make_nested_diagnostic_info(100);
  ua::memory_stream_device::ExternalReadOnly rejectedDevice{rejectedEncoding};
  ua::MemoryStream rejectedStream{rejectedDevice};
  ua::StructureFactory rejectedFactory;
  ua::UaBinaryDecoder rejectedDecoder{rejectedFactory.resolver(), rejectedStream, limits};
  ua::DiagnosticInfo rejected;
  try
  {
    rejectedDecoder.decode(limits.stack_depth(), rejected);
    FAIL() << "frame 101 must exceed the default recursion-depth limit";
  }
  catch (const ua::UaException& exception)
  {
    EXPECT_EQ(exception.status(), ua::Status::BadEncodingLimitsExceeded);
    ASSERT_NE(exception.detail(), nullptr);
    EXPECT_EQ(exception.detail()->code, "RecursionDepthExceeded");
  }
}

// --- Configurable recursion-depth cap (decodeRecursionDepthLimit) ------------------------------
// Before this fix the codec's recursion-depth cap was hardcoded to StackDepth::defaultMaxDepth (100)
// and unreachable from configuration: EncodingLimits::stack_depth() allocated StackDepth{workLimit},
// silently dropping the depth argument so the second constructor parameter defaulted. These tests pin
// that the configured decodeRecursionDepthLimit now flows through to the live recursion guard,
// decoupled from the (deliberately large) work budget.

TEST(UaBinaryEncodingLimitsTests, ConfiguredRecursionDepthCapRejectsBeyondLimit)
{
  // Depth cap of 3 with a generous work budget. 50 nested DiagnosticInfo levels decode fine under the
  // default cap (100) but must now be rejected because the configured cap is honoured. This is the
  // falsifiable proof of the fix: the SAME message that passes at the default cap fails at the small
  // configured one, so the depth field is genuinely wired through (not the hardcoded 100).
  const ua::EncodingLimits limits{
    .execution = ua::ExecutionLimits{.decodeWorkLimit = 100000, .decodeRecursionDepthLimit = 3}};

  const auto encoded = make_nested_diagnostic_info(50);

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, limits};

  ua::DiagnosticInfo out;
  try
  {
    decoder.decode(limits.stack_depth(), out);
    FAIL() << "Expected UaException for exceeding the configured recursion-depth cap";
  }
  catch (const ua::UaException& ex)
  {
    EXPECT_EQ(ex.status(), ua::Status::BadEncodingLimitsExceeded);
    ASSERT_NE(ex.detail(), nullptr);
    EXPECT_EQ(ex.detail()->code, "RecursionDepthExceeded")
      << "the failure must come from the live recursion-depth guard, not the work budget";
  }
}

TEST(UaBinaryEncodingLimitsTests, ConfiguredRecursionDepthCapAcceptsWithinLimit)
{
  // Companion to the reject case with the same small cap (3): a message nested within the cap decodes
  // cleanly. make_nested_diagnostic_info(2) reaches a live depth of 3 (outer + 2 inner), exactly at the
  // cap, so it must be accepted - proving the small cap does not spuriously reject legitimate nesting.
  const ua::EncodingLimits limits{
    .execution = ua::ExecutionLimits{.decodeWorkLimit = 100000, .decodeRecursionDepthLimit = 3}};

  const auto encoded = make_nested_diagnostic_info(2);

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, limits};

  ua::DiagnosticInfo out;
  EXPECT_NO_THROW(decoder.decode(limits.stack_depth(), out));
}

// --- Typed ExtensionObject fields charge the configured recursion-depth cap ------------------------

namespace
{

/// `levels` RequestHeaders, each held in the AdditionalHeader field of the one above it.
std::unique_ptr<ua::RequestHeader> nested_request_headers(size_t levels)
{
  auto current = std::make_unique<ua::RequestHeader>();
  for (size_t level = 1; level < levels; ++level)
  {
    auto outer = std::make_unique<ua::RequestHeader>();
    outer->additional_header() = std::unique_ptr<ua::Structure>{std::move(current)};
    current = std::move(outer);
  }
  return current;
}

std::vector<ua::byte> encode_structure(const ua::Structure& structure, const ua::EncodingLimits& limits)
{
  ua::memory_stream_device::Dynamic device{4096, true};
  ua::MemoryStream stream{device};
  ua::UaBinaryEncoder encoder(ua::CodecNamespaceContext{}, stream);
  encoder.encode(limits.stack_depth(), structure);
  auto out = device.move_storage_out();
  out.resize(stream.get_position());
  return out;
}

}  // namespace

// @relation(AC-SVR-UASC-063-TYPED-FIELD-NESTING-CHARGES-RECURSION-DEPTH, scope=function)
TEST(UaBinaryEncodingLimitsTests, ConfiguredRecursionDepthCapAppliesToTypedExtensionObjectFields)
{
  // Six nested headers peak at depth 6 (one charge per structure held in a typed field, plus the
  // top-level structure); a cap of 5 refuses exactly that shape and a cap of 6 (control) admits it.
  const ua::EncodingLimits limits{
    .execution = ua::ExecutionLimits{.decodeWorkLimit = 100000, .decodeRecursionDepthLimit = 5}};
  const auto encoded = encode_structure(*nested_request_headers(6), limits);

  ua::StructureFactory factory;
  ua::register_ua_data_types_with_factory({}, &factory, nullptr);
  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, limits};

  ua::RequestHeader out;
  try
  {
    decoder.decode(limits.stack_depth(), out);
    FAIL() << "six levels must exceed a cap of five";
  }
  catch (const ua::UaException& exception)
  {
    EXPECT_EQ(exception.status(), ua::Status::BadEncodingLimitsExceeded);
    ASSERT_NE(exception.detail(), nullptr);
    EXPECT_EQ(exception.detail()->code, "RecursionDepthExceeded");
  }
}

// @relation(AC-SVR-UASC-063-TYPED-FIELD-NESTING-CHARGES-RECURSION-DEPTH, scope=function)  // control arm
TEST(UaBinaryEncodingLimitsTests, TypedExtensionObjectFieldsWithinTheRecursionDepthCapDecode)
{
  const ua::EncodingLimits limits{
    .execution = ua::ExecutionLimits{.decodeWorkLimit = 100000, .decodeRecursionDepthLimit = 6}};
  const auto encoded = encode_structure(*nested_request_headers(6), limits);

  ua::StructureFactory factory;
  ua::register_ua_data_types_with_factory({}, &factory, nullptr);
  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, limits};

  ua::RequestHeader out;
  EXPECT_NO_THROW(decoder.decode(limits.stack_depth(), out));
}

// Part 6 section 5.2.2.12: at least 100 nesting levels are supported; the 101st is refused.
// @relation(AC-SVR-UASC-063-TYPED-FIELD-NESTING-CHARGES-RECURSION-DEPTH, scope=function)
TEST(UaBinaryEncodingLimitsTests, DefaultRecursionDepthCapAdmits100TypedFieldLevelsAndRefuses101)
{
  const ua::EncodingLimits limits{};
  ua::StructureFactory factory;
  ua::register_ua_data_types_with_factory({}, &factory, nullptr);

  {
    const auto encoded = encode_structure(*nested_request_headers(100), limits);
    ua::memory_stream_device::ExternalReadOnly device{encoded};
    ua::MemoryStream stream{device};
    ua::UaBinaryDecoder decoder{factory.resolver(), stream, limits};
    ua::RequestHeader out;
    EXPECT_NO_THROW(decoder.decode(limits.stack_depth(), out)) << "100 levels are within the default cap";
  }
  {
    const auto encoded = encode_structure(*nested_request_headers(101), limits);
    ua::memory_stream_device::ExternalReadOnly device{encoded};
    ua::MemoryStream stream{device};
    ua::UaBinaryDecoder decoder{factory.resolver(), stream, limits};
    ua::RequestHeader out;
    try
    {
      decoder.decode(limits.stack_depth(), out);
      FAIL() << "101 levels must exceed the default cap of 100";
    }
    catch (const ua::UaException& exception)
    {
      EXPECT_EQ(exception.status(), ua::Status::BadEncodingLimitsExceeded);
      ASSERT_NE(exception.detail(), nullptr);
      EXPECT_EQ(exception.detail()->code, "RecursionDepthExceeded");
    }
  }
}

// --- A stream that ends before a value is complete is a decoding error ----------------------------

// @relation(AC-SVR-UASC-064-TRUNCATED-STREAM-IS-A-DECODING-ERROR, scope=function)
TEST(UaBinaryEncodingLimitsTests, ValueCutShortByTheEndOfTheStreamIsADecodingError)
{
  const std::vector<ua::byte> twoBytes{static_cast<ua::byte>(0x01), static_cast<ua::byte>(0x02)};
  ua::memory_stream_device::ExternalReadOnly device{twoBytes};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, ua::EncodingLimits{}};

  int32_t out = 0;
  expect_runtime_exception_status(
    [&]() { decoder.decode(ua::EncodingLimits{}.stack_depth(), out); }, ua::Status::BadDecodingError);
}

// --- A declared length is refused before anything is allocated for it ------------------------------

// Each nesting level below declares an Array of 65535 Variants (the configured maximum) and then holds
// only the first element, which opens the next level. Trusting each length allocated and constructed
// 65535 Variants per level, megabytes per level and hundreds of megabytes over the recursion limit,
// from a few hundred bytes. Every encoded value takes at least one byte, so a length the rest of the
// message cannot hold is refused at the outermost level, before its storage exists.
// @relation(AC-SVR-UASC-064-DECLARED-LENGTH-NEEDS-ITS-BYTES, scope=function)
// @relation(AC-SVR-UASC-064-NESTED-ARRAYS-ALLOCATE-ONLY-DECODED-ELEMENTS, scope=function)
TEST(UaBinaryEncodingLimitsTests, PaddedNestedArraysDoNotConstructUndecodedSiblings)
{
  std::vector<ua::byte> encoded;
  append_i32(encoded, 64);
  for (size_t level = 0; level < 3; ++level)
  {
    encoded.push_back(static_cast<ua::byte>(0x98));
    append_i32(encoded, 64);
  }
  append_bytes(encoded, 65, ua::byte{0});

  ua::Array<ua::Variant> decoded;
  size_t constructedAtFirstChild = std::numeric_limits<size_t>::max();
  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ObservedReadStream stream{device,
    [&](size_t position)
    {
      if (position == sizeof(int32_t))
        constructedAtFirstChild = decoded.size();
    }};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, ua::EncodingLimits{}};
  expect_runtime_exception_status(
    [&] { decoder.decode(ua::EncodingLimits{}.stack_depth(), decoded); }, ua::Status::BadDecodingError);
  EXPECT_EQ(constructedAtFirstChild, 1u)
    << "only the element being decoded may exist when its first byte is read; undecoded siblings were built";

  std::vector<ua::byte> valid;
  append_i32(valid, 2);
  valid.push_back(ua::byte{0x98});
  append_i32(valid, 2);
  append_bytes(valid, 2, ua::byte{0});
  valid.push_back(ua::byte{0x06});
  append_i32(valid, 17);
  ua::memory_stream_device::ExternalReadOnly validDevice{valid};
  ua::MemoryStream validStream{validDevice};
  ua::UaBinaryDecoder validDecoder{factory.resolver(), validStream, ua::EncodingLimits{}};
  ua::Array<ua::Variant> validDecoded;
  validDecoder.decode(ua::EncodingLimits{}.stack_depth(), validDecoded);
  ASSERT_EQ(validDecoded.size(), 2u);
  EXPECT_TRUE(validDecoded[0].is_array());
  EXPECT_EQ(validDecoded[1].as<int32_t>(), 17);

  std::vector<ua::byte> hostile;
  for (size_t level = 0; level < 60; ++level)
  {
    hostile.push_back(ua::byte{0x98});
    append_i32(hostile, 65535);
  }
  append_bytes(hostile, 65536, ua::byte{0});
  ua::memory_stream_device::ExternalReadOnly hostileDevice{hostile};
  ua::MemoryStream hostileStream{hostileDevice};
  ua::UaBinaryDecoder hostileDecoder{factory.resolver(), hostileStream, ua::EncodingLimits{}};
  ua::Variant hostileDecoded;
  expect_runtime_exception_status([&]
    { hostileDecoder.decode(ua::EncodingLimits{}.stack_depth(), hostileDecoded); },
    ua::Status::BadDecodingError);
}

// An ExtensionObject array decodes each body from the same stream before the next element, so its
// elements are constructed one at a time like any other aggregate array.
// @relation(AC-SVR-UASC-064-NESTED-ARRAYS-ALLOCATE-ONLY-DECODED-ELEMENTS, scope=function)
TEST(UaBinaryEncodingLimitsTests, AnExtensionObjectArrayConstructsOnlyItsDecodedElements)
{
  std::vector<ua::byte> encoded;
  append_i32(encoded, 64);
  append_bytes(encoded, 64, ua::byte{0});  // padding the length check accepts; no valid body follows

  ua::Array<ua::RefStructure<ua::Structure>> decoded;
  size_t constructedAtFirstChild = std::numeric_limits<size_t>::max();
  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ObservedReadStream stream{device,
    [&](size_t position)
    {
      if (position == sizeof(int32_t))
        constructedAtFirstChild = decoded.size();
    }};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, ua::EncodingLimits{}};
  try
  {
    decoder.decode(ua::EncodingLimits{}.stack_depth(), decoded);
  }
  catch (const ua::UaException&)
  {
    // The padding is not a valid sequence of ExtensionObjects; only the construction order matters.
  }
  EXPECT_EQ(constructedAtFirstChild, 1u)
    << "only the element being decoded may exist when its first byte is read; undecoded siblings were built";
}

// @relation(AC-SVR-UASC-064-DECLARED-LENGTH-NEEDS-ITS-BYTES, scope=function)
TEST(UaBinaryEncodingLimitsTests, ADeclaredArrayLengthTheMessageCannotHoldIsRefusedBeforeAllocating)
{
  std::vector<ua::byte> encoded;
  for (int level = 0; level < 60; ++level)
  {
    encoded.push_back(static_cast<ua::byte>(0x18 | 0x80));  // Variant of Variant, array
    append_i32(encoded, 65535);
  }
  encoded.push_back(static_cast<ua::byte>(0x00));  // the innermost element: an empty Variant

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, ua::EncodingLimits{}};

  ua::Variant out;
  try
  {
    decoder.decode(ua::EncodingLimits{}.stack_depth(), out);
    FAIL() << "Expected UaException";
  }
  catch (const ua::UaException& exception)
  {
    EXPECT_EQ(exception.status(), ua::Status::BadDecodingError);
    ASSERT_NE(exception.detail(), nullptr);
    EXPECT_EQ(
      exception.detail()->summary, "A declared length needs more bytes than remain in the encoded value")
      << "the length was trusted and the decode ran until the stream ended";
  }
  EXPECT_EQ(stream.get_position(), 5u) << "the refusal came after the first level's length, not deeper";

  // Control: a length the message does hold still decodes.
  std::vector<ua::byte> held;
  held.push_back(static_cast<ua::byte>(0x18 | 0x80));
  append_i32(held, 3);
  append_bytes(held, 3, static_cast<ua::byte>(0x00));
  ua::memory_stream_device::ExternalReadOnly heldDevice{held};
  ua::MemoryStream heldStream{heldDevice};
  ua::UaBinaryDecoder heldDecoder{factory.resolver(), heldStream, ua::EncodingLimits{}};
  ua::Variant decoded;
  heldDecoder.decode(ua::EncodingLimits{}.stack_depth(), decoded);
  EXPECT_TRUE(decoded.is_array());
}

// --- Array dimension products are checked for overflow ----------------------------------------------

// @relation(AC-SVR-UASC-064-ARRAY-DIMENSION-PRODUCT-OVERFLOW-IS-REFUSED, scope=function)
TEST(UaBinaryEncodingLimitsTests, ArrayDimensionProductThatOverflowsIsRefused)
{
  // Four dimensions of 65536 multiply to 2^64, which wraps to 0 in size_t and would match an empty
  // payload; the product must be refused instead.
  ua::Array<int32_t> empty;
  expect_runtime_exception_status([&]()
    { empty.add_and_validate_dimensions(ua::Dimensions{65536, 65536, 65536, 65536}); },
    ua::Status::BadInvalidArgument);
}

// The same product arrives on the wire as a Variant's ArrayDimensions (Part 6 section 5.2.2.16).
// @relation(AC-SVR-UASC-064-ARRAY-DIMENSION-PRODUCT-OVERFLOW-IS-REFUSED, scope=function)
TEST(UaBinaryEncodingLimitsTests, VariantArrayDimensionsWhoseProductOverflowsAreADecodingError)
{
  std::vector<ua::byte> encoded;
  encoded.push_back(static_cast<ua::byte>(0x06 | 0x80 | 0x40));  // Int32, array, dimensions present
  append_i32(encoded, 0);  // ArrayLength 0
  append_i32(encoded, 4);  // four dimensions
  for (int i = 0; i < 4; ++i)
  {
    append_i32(encoded, 65536);
  }

  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, ua::EncodingLimits{}};

  ua::Variant out;
  expect_runtime_exception_status(
    [&]() { decoder.decode(ua::EncodingLimits{}.stack_depth(), out); }, ua::Status::BadDecodingError);
}

// --- Decimal body length is bounded -----------------------------------------------------------------

namespace
{

std::vector<ua::byte> decimal_prefix_with_length(int32_t length)
{
  ua::memory_stream_device::Dynamic device{64, true};
  ua::MemoryStream stream{device};
  ua::UaBinaryEncoder encoder(ua::CodecNamespaceContext{}, stream);
  const ua::EncodingLimits limits{};
  encoder.encode(limits.stack_depth(), ua::NodeId{ua::ObjectId::DecimalDataType_Encoding_DefaultBinary});
  encoder.encode(limits.stack_depth(), uint8_t{1});
  encoder.encode(limits.stack_depth(), length);
  auto out = device.move_storage_out();
  out.resize(stream.get_position());
  return out;
}

}  // namespace

// @relation(AC-SVR-UASC-064-DECIMAL-BODY-LENGTH-IS-BOUNDED, scope=function)
TEST(UaBinaryEncodingLimitsTests, DecimalBodyLengthAboveTheByteStringCapIsRefused)
{
  const auto encoded = decimal_prefix_with_length(std::numeric_limits<int32_t>::max());
  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, ua::EncodingLimits{}};

  ua::Decimal out;
  expect_runtime_exception_status([&]() { decoder.decode(ua::EncodingLimits{}.stack_depth(), out); },
    ua::Status::BadEncodingLimitsExceeded);
}

// @relation(AC-SVR-UASC-064-DECIMAL-BODY-LENGTH-IS-BOUNDED, scope=function)
TEST(UaBinaryEncodingLimitsTests, NegativeDecimalBodyLengthIsADecodingError)
{
  const auto encoded = decimal_prefix_with_length(-5);
  ua::memory_stream_device::ExternalReadOnly device{encoded};
  ua::MemoryStream stream{device};
  ua::StructureFactory factory;
  ua::UaBinaryDecoder decoder{factory.resolver(), stream, ua::EncodingLimits{}};

  ua::Decimal out;
  expect_runtime_exception_status(
    [&]() { decoder.decode(ua::EncodingLimits{}.stack_depth(), out); }, ua::Status::BadDecodingError);
}
