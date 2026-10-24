// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_secure_memory.h"
#include "ua_secure_string.h"
#include "ua_security_token.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <string_view>

namespace ua
{
/// Reaches the owned buffer so the scrub can be observed while the storage is still owned; end-of-life
/// scrubbing cannot be observed in-process without undefined behaviour.
struct SecureStringTestAccess
{
  static void scrub(SecureString& s)
  {
    s.scrub();
  }

  static const char* buffer(const SecureString& s)
  {
    return s.mBuffer.get();
  }

  static bool owns_bytes(const SecureString& s)
  {
    return s.mBuffer != nullptr;
  }
};
}  // namespace ua

using namespace ua;
using namespace std::string_view_literals;

// @verifies AC-SVR-IDENT-021-DECRYPTED-CREDENTIALS-ARE-SCRUBBED
TEST(SecureStringTests, MovedFromInstanceOwnsNoBytes)
{
  SecureString source{"hunter2"};
  SecureString moved{std::move(source)};
  EXPECT_FALSE(SecureStringTestAccess::owns_bytes(source));  // NOLINT(bugprone-use-after-move)
  EXPECT_TRUE(source.empty());
  EXPECT_EQ(moved.view(), "hunter2"sv);
  EXPECT_STREQ(moved.c_str(), "hunter2");
}

// @verifies AC-SVR-IDENT-021-DECRYPTED-CREDENTIALS-ARE-SCRUBBED
TEST(SecureStringTests, PointerLengthConstructorPreservesEmbeddedNul)
{
  const char raw[] = {'a', 'b', '\0', 'c', 'd'};
  SecureString password{raw, sizeof raw};
  EXPECT_EQ(password.size(), 5u);
  EXPECT_EQ(password.view(), std::string_view(raw, sizeof raw));
  EXPECT_EQ(std::strlen(password.c_str()), 2u) << "c_str stops at the embedded NUL; view does not";
  EXPECT_EQ(password.c_str()[5], '\0') << "the buffer is NUL-terminated after the full length";
}

// @verifies AC-SVR-IDENT-021-DECRYPTED-CREDENTIALS-ARE-SCRUBBED
TEST(SecureStringTests, CopyAssignmentLeavesIndependentStorage)
{
  SecureString first{"first"};
  SecureString second{"second-longer"};
  first = second;
  EXPECT_EQ(first.view(), "second-longer"sv);
  EXPECT_NE(SecureStringTestAccess::buffer(first), SecureStringTestAccess::buffer(second));
  SecureString copy{first};
  EXPECT_NE(SecureStringTestAccess::buffer(copy), SecureStringTestAccess::buffer(first));
  EXPECT_EQ(copy.view(), first.view());
}

// @verifies AC-SVR-IDENT-021-DECRYPTED-CREDENTIALS-ARE-SCRUBBED
TEST(SecureStringTests, ScrubZeroesTheLiveBuffer)
{
  SecureString password{"correct horse battery staple"};
  const auto* buffer = SecureStringTestAccess::buffer(password);
  ASSERT_NE(buffer, nullptr);
  const size_t size = password.size();
  SecureStringTestAccess::scrub(password);
  EXPECT_TRUE(std::all_of(buffer, buffer + size + 1, [](char c) { return c == '\0'; }))
    << "every byte of the owned buffer, terminator included, is zero after the scrub";
}

// @verifies AC-SVR-IDENT-021-DECRYPTED-CREDENTIALS-ARE-SCRUBBED
TEST(SecureMemoryTests, SecureZeroZeroesALiveSpan)
{
  unsigned char bytes[16];
  std::memset(bytes, 0xAB, sizeof bytes);
  security::secure_zero(bytes, sizeof bytes);
  EXPECT_TRUE(std::all_of(std::begin(bytes), std::end(bytes), [](unsigned char b) { return b == 0; }));
  security::secure_zero(nullptr, 0);  // a no-op, not a fault
}

// @verifies AC-SVR-IDENT-021-DECRYPTED-CREDENTIALS-ARE-SCRUBBED
TEST(SecureMemoryTests, SecureClearZeroesThenEmptiesTheByteString)
{
  ByteString secret{std::vector<uint8_t>{1, 2, 3, 4, 5, 6, 7, 8}};
  const auto* storage = secret.data();
  security::secure_clear(secret);
  EXPECT_TRUE(secret.empty());
  // The storage is still reachable through the (now empty) container's allocation only if it was not
  // released; either way the bytes were zeroed before clear(). Observe through the pointer taken above
  // only when the capacity survived (implementation-defined), never dereferencing freed memory:
  if (secret.data() == storage)
    EXPECT_TRUE(std::all_of(storage, storage + 8, [](uint8_t b) { return b == 0; }));
}

// A token's symmetric keys are scrubbed when destroyed or overwritten, so their copy and move operations are
// written by hand; they must still carry the key material exactly, including a self-assignment.
// @relation(AC-COMP-SECURE-MEMORY-SYMMETRIC-KEYS-SCRUBBED, scope=function)
TEST(SecureMemoryTests, SymmetricKeysKeepTheirValueAcrossCopyMoveAndAssignment)
{
  SecurityToken::Keys original;
  original.signingKey = ByteString{1, 2, 3};
  original.encryptingKey = ByteString{4, 5, 6, 7};
  original.initializationVector = ByteString{8, 9};

  SecurityToken::Keys copied{original};
  EXPECT_EQ(copied.signingKey, original.signingKey);
  EXPECT_EQ(copied.encryptingKey, original.encryptingKey);
  EXPECT_EQ(copied.initializationVector, original.initializationVector);

  SecurityToken::Keys assigned;
  assigned.signingKey = ByteString{0xAA};
  assigned = copied;
  EXPECT_EQ(assigned.signingKey, original.signingKey);
  EXPECT_EQ(assigned.initializationVector, original.initializationVector);

  auto& self = assigned;
  assigned = self;
  EXPECT_EQ(assigned.encryptingKey, original.encryptingKey);

  SecurityToken::Keys moveAssigned;
  moveAssigned.encryptingKey = ByteString{0xBB, 0xCC};
  moveAssigned = std::move(assigned);
  EXPECT_EQ(moveAssigned.encryptingKey, original.encryptingKey);
  EXPECT_EQ(moveAssigned.signingKey, original.signingKey);

  SecurityToken::Keys moveConstructed{std::move(moveAssigned)};
  EXPECT_EQ(moveConstructed.initializationVector, original.initializationVector);
}

// The guard clears its secret on every exit - here a plain scope end and an exception unwinding through it -
// so a function holding a private key cannot leave it in freed memory on a path its author forgot.
// @verifies AC-COMP-SECURE-MEMORY-SCRUB-ON-EXIT
TEST(SecureMemoryTests, ScrubOnExitClearsTheSecretWhenTheScopeEnds)
{
  ByteString secret{0x11, 0x22, 0x33};
  {
    const ua::security::ScrubOnExit guard{secret};
    ASSERT_EQ(secret.size(), 3u) << "the guard must not touch the secret before the scope ends";
  }
  EXPECT_TRUE(secret.empty());

  ByteString thrownPast{0x44, 0x55};
  try
  {
    const ua::security::ScrubOnExit guard{thrownPast};
    throw std::runtime_error{"unwinding"};
  }
  catch (const std::runtime_error&)
  {}
  EXPECT_TRUE(thrownPast.empty()) << "an exception skipped the scrub";

  std::array<uint8_t, 4> raw{1, 2, 3, 4};
  {
    const ua::security::ScrubOnExit guard{raw.data(), raw.size()};
  }
  EXPECT_EQ(raw, (std::array<uint8_t, 4>{0, 0, 0, 0}));
}
