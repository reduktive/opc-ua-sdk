// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

/// @file
/// @brief The shared test key cache: every private key a test needs, generated once per machine and user.
///
/// Key generation dominates the cost of a certificate test (an RSA 8192 key takes seconds), and a test
/// asserts on what a certificate says, not on which random key it carries. A key is therefore identified by
/// its type and a slot (a distinct key of the same type), generated on first use, and kept:
///   - in process, so a second request costs a map lookup;
///   - on disk, in `${UASDK_TEST_KEY_CACHE}` when that is set, else in
///     `${XDG_CACHE_HOME:-$HOME/.cache}/reduktive-uasdk/test-keys/v1/<type>-<slot>.pem`, so a second test
///     process, a parallel shard or another clone does not generate it again.
/// The directory is owner-only (0700) and every file is 0600. A file is written to a unique temporary file
/// in the same directory and renamed into place, so a reader never sees a partial key. A process that
/// finds the file already in place adopts it and discards its own, and every process adopts what is on
/// disk after its rename, so processes racing on a first use converge on one key (a lost race costs at
/// most one extra generation). A file that does not parse as a key of its type is regenerated. The cache
/// holds test keys only and is safe to delete; it is never committed.

#ifndef UA_TEST_HELPERS_TEST_KEY_CACHE_H
#define UA_TEST_HELPERS_TEST_KEY_CACHE_H

#include <filesystem>
#include <memory>
#include <string>

#include <openssl/evp.h>

namespace ua
{
class AsymmetricKeyPair;
class Crypto;
}  // namespace ua

namespace ua::test_keys
{

/// A key family and size. Rsa<N> is an RSA key of N bits; P<N> a NIST curve; Bp<N> a Brainpool r1 curve.
enum class KeyType
{
  Rsa512,
  Rsa1024,
  Rsa1025,
  Rsa1500,
  Rsa2048,
  Rsa2049,
  Rsa3000,
  Rsa3072,
  Rsa4096,
  Rsa8192,
  P256,
  P384,
  P521,
  Bp256,
  Bp384,
  Bp512,
  Ed25519,
  Ed448,
};

/// The name of @p type in a cache file name, for example "rsa2048" or "bp256".
std::string type_name(KeyType type);

/// The on-disk cache directory as the environment names it now: `${UASDK_TEST_KEY_CACHE}` when set and
/// non-empty, else `${XDG_CACHE_HOME:-$HOME/.cache}/reduktive-uasdk/test-keys/v1`.
/// @throws std::runtime_error when neither UASDK_TEST_KEY_CACHE, XDG_CACHE_HOME nor HOME (USERPROFILE or
///         LOCALAPPDATA on Windows) is set.
std::filesystem::path cache_directory();

/// The unencrypted PKCS#8 PEM of the private key in @p slot of @p type, from the cache in
/// @ref cache_directory. The reference stays valid until @ref clear_in_process_cache.
/// @throws std::runtime_error when this platform's OpenSSL cannot create the type (the test fails)
///         or the cache directory cannot be created or written.
const std::string& private_key_pem(KeyType type, unsigned slot);

/// As @ref private_key_pem, with the on-disk cache in @p directory instead of @ref cache_directory.
const std::string& private_key_pem_in(const std::filesystem::path& directory, KeyType type, unsigned slot);

/// The private key in @p slot of @p type as a new EVP_PKEY. The caller frees it with EVP_PKEY_free.
/// @throws std::runtime_error as @ref private_key_pem.
EVP_PKEY* new_evp_pkey(KeyType type, unsigned slot);

/// The private key in @p slot of @p type loaded through @p crypto (Crypto::get_private_key_from_pem), so
/// the key pair is the SDK's own type. The key is never generated through @p crypto.
/// @throws std::runtime_error as @ref private_key_pem; UaException when @p crypto refuses the key.
std::shared_ptr<const AsymmetricKeyPair> key_pair(const Crypto& crypto, KeyType type, unsigned slot);

/// Test-only hook: forgets every key held in process, so the next request reads the on-disk cache as a
/// second process would. Invalidates every reference @ref private_key_pem returned.
void clear_in_process_cache();

}  // namespace ua::test_keys

#endif  // UA_TEST_HELPERS_TEST_KEY_CACHE_H
