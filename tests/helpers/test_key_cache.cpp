// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

// The OpenSSL 1.1 API, which OpenSSL 3 still provides at this compatibility level, so the key cache builds
// against both supported OpenSSL versions. It must precede every OpenSSL header, test_key_cache.h's included.
#define OPENSSL_API_COMPAT 10100

#include "test_key_cache.h"

#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <tuple>
#include <vector>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#if !defined(_WIN32)
#include <unistd.h>

#include <cstdio>
#endif

#include "ua_crypto.h"
#include "ua_crypto_types.h"
#include "ua_owner_only_directory.h"

namespace ua::test_keys
{
namespace
{

namespace fs = std::filesystem;

/// How OpenSSL identifies and sizes a key type.
struct KeySpec
{
  int keyType = EVP_PKEY_NONE;  ///< The OpenSSL key type (EVP_PKEY_RSA, EVP_PKEY_EC, ...).
  int rsaBits = 0;  ///< RSA modulus size; 0 for every other type.
  int curve = NID_undef;  ///< The EC curve; NID_undef for RSA and EdDSA.
  int ecBits = 0;  ///< The EC group's size in bits; 0 for RSA and EdDSA.
};

KeySpec spec_of(KeyType type)
{
  switch (type)
  {
  case KeyType::Rsa512:
    return KeySpec{EVP_PKEY_RSA, 512, NID_undef, 0};
  case KeyType::Rsa1024:
    return KeySpec{EVP_PKEY_RSA, 1024, NID_undef, 0};
  case KeyType::Rsa1025:
    return KeySpec{EVP_PKEY_RSA, 1025, NID_undef, 0};
  case KeyType::Rsa1500:
    return KeySpec{EVP_PKEY_RSA, 1500, NID_undef, 0};
  case KeyType::Rsa2048:
    return KeySpec{EVP_PKEY_RSA, 2048, NID_undef, 0};
  case KeyType::Rsa2049:
    return KeySpec{EVP_PKEY_RSA, 2049, NID_undef, 0};
  case KeyType::Rsa3000:
    return KeySpec{EVP_PKEY_RSA, 3000, NID_undef, 0};
  case KeyType::Rsa3072:
    return KeySpec{EVP_PKEY_RSA, 3072, NID_undef, 0};
  case KeyType::Rsa4096:
    return KeySpec{EVP_PKEY_RSA, 4096, NID_undef, 0};
  case KeyType::Rsa8192:
    return KeySpec{EVP_PKEY_RSA, 8192, NID_undef, 0};
  case KeyType::P256:
    return KeySpec{EVP_PKEY_EC, 0, NID_X9_62_prime256v1, 256};
  case KeyType::P384:
    return KeySpec{EVP_PKEY_EC, 0, NID_secp384r1, 384};
  case KeyType::P521:
    return KeySpec{EVP_PKEY_EC, 0, NID_secp521r1, 521};
  case KeyType::Bp256:
    return KeySpec{EVP_PKEY_EC, 0, NID_brainpoolP256r1, 256};
  case KeyType::Bp384:
    return KeySpec{EVP_PKEY_EC, 0, NID_brainpoolP384r1, 384};
  case KeyType::Bp512:
    return KeySpec{EVP_PKEY_EC, 0, NID_brainpoolP512r1, 512};
  case KeyType::Ed25519:
    return KeySpec{EVP_PKEY_ED25519, 0, NID_undef, 0};
  case KeyType::Ed448:
    return KeySpec{EVP_PKEY_ED448, 0, NID_undef, 0};
  }
  throw std::invalid_argument{"unknown test key type"};
}

CertificateKeyAlgorithm algorithm_of(KeyType type)
{
  switch (type)
  {
  case KeyType::Rsa512:
  case KeyType::Rsa1024:
  case KeyType::Rsa1025:
  case KeyType::Rsa1500:
  case KeyType::Rsa2048:
  case KeyType::Rsa2049:
  case KeyType::Rsa3000:
  case KeyType::Rsa3072:
  case KeyType::Rsa4096:
  case KeyType::Rsa8192:
    return CertificateKeyAlgorithm::Rsa;
  case KeyType::P256:
    return CertificateKeyAlgorithm::EccNistP256;
  case KeyType::P384:
    return CertificateKeyAlgorithm::EccNistP384;
  case KeyType::P521:
    return CertificateKeyAlgorithm::EccNistP521;
  case KeyType::Bp256:
    return CertificateKeyAlgorithm::EccBrainpoolP256r1;
  case KeyType::Bp384:
    return CertificateKeyAlgorithm::EccBrainpoolP384r1;
  case KeyType::Bp512:
    return CertificateKeyAlgorithm::EccBrainpoolP512r1;
  case KeyType::Ed25519:
    return CertificateKeyAlgorithm::EccCurve25519;
  case KeyType::Ed448:
    return CertificateKeyAlgorithm::EccCurve448;
  }
  throw std::invalid_argument{"unknown test key type"};
}

struct EvpPkeyFree
{
  void operator()(EVP_PKEY* key) const
  {
    EVP_PKEY_free(key);
  }
};

struct BioFree
{
  void operator()(BIO* bio) const
  {
    BIO_free(bio);
  }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyFree>;
using BioPtr = std::unique_ptr<BIO, BioFree>;

/// Refuses a passphrase prompt: a cached key is never encrypted, and an encrypted file is a corrupt one.
int no_passphrase(char* /*buffer*/, int /*size*/, int /*rwflag*/, void* /*userdata*/)
{
  return 0;
}

/// @p pem parsed as a private key of @p type, or nullptr when it is not one.
EvpPkeyPtr parse_key(const std::string& pem, KeyType type)
{
  if (pem.empty())
  {
    return nullptr;
  }
  const BioPtr bio{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))};
  if (!bio)
  {
    ERR_clear_error();
    return nullptr;
  }
  EvpPkeyPtr key{PEM_read_bio_PrivateKey(bio.get(), nullptr, &no_passphrase, nullptr)};
  ERR_clear_error();
  if (!key)
  {
    return nullptr;
  }
  const auto spec = spec_of(type);
  if (EVP_PKEY_base_id(key.get()) != spec.keyType)
  {
    return nullptr;
  }
  const int expectedBits = spec.rsaBits != 0 ? spec.rsaBits : spec.ecBits;
  if (expectedBits != 0 && EVP_PKEY_bits(key.get()) != expectedBits)
  {
    return nullptr;
  }
  return key;
}

[[noreturn]] void cannot_create(KeyType type, const std::string& why)
{
  ERR_clear_error();
  throw std::runtime_error{
    "this platform's OpenSSL cannot create a " + type_name(type) + " test key (" + why + ")"};
}

/// A new key of @p type, as unencrypted PKCS#8 PEM.
std::string generate_pem(KeyType type)
{
  const auto spec = spec_of(type);
  const std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context{
    EVP_PKEY_CTX_new_id(spec.keyType, nullptr), &EVP_PKEY_CTX_free};
  if (!context || EVP_PKEY_keygen_init(context.get()) <= 0)
  {
    cannot_create(type, "no key generation context");
  }
  if (spec.rsaBits != 0 && EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), spec.rsaBits) <= 0)
  {
    cannot_create(type, "modulus size refused");
  }
  // OpenSSL 3 generates a two-prime key of 2048 bits or more by SP 800-56B, which yields only even sizes;
  // an odd size is generated with three primes, whose modulus has exactly the requested length (the
  // length is what the policy tests measure).
  if (spec.rsaBits >= 2048 && spec.rsaBits % 2 == 1 &&
      EVP_PKEY_CTX_set_rsa_keygen_primes(context.get(), 3) <= 0)
  {
    cannot_create(type, "three-prime generation refused");
  }
  if (spec.curve != NID_undef && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), spec.curve) <= 0)
  {
    cannot_create(type, "curve refused");
  }
  // OpenSSL may return a modulus one bit short of an odd requested size (two primes of half the size
  // each), so an RSA key is generated again until it has exactly the requested size.
  EvpPkeyPtr key;
  for (int attempt = 0; attempt < 32 && !key; ++attempt)
  {
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(context.get(), &raw) <= 0 || raw == nullptr)
    {
      cannot_create(type, "generation failed");
    }
    key.reset(raw);
    if (spec.rsaBits != 0 && EVP_PKEY_bits(key.get()) != spec.rsaBits)
    {
      key.reset();
    }
  }
  if (!key)
  {
    cannot_create(type, "no key of exactly the requested size in 32 attempts");
  }
  const BioPtr bio{BIO_new(BIO_s_mem())};
  if (!bio || PEM_write_bio_PKCS8PrivateKey(bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) != 1)
  {
    cannot_create(type, "PKCS#8 encoding failed");
  }
  char* data = nullptr;
  const long length = BIO_get_mem_data(bio.get(), &data);
  if (length <= 0 || data == nullptr)
  {
    cannot_create(type, "PKCS#8 encoding is empty");
  }
  return std::string{data, static_cast<std::size_t>(length)};
}

/// The file's content when it is a valid key of @p type; std::nullopt when it is absent or corrupt.
std::optional<std::string> load_valid(const fs::path& file, KeyType type)
{
  std::ifstream in{file, std::ios::binary};
  if (!in)
  {
    return std::nullopt;
  }
  std::string pem{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
  if (!parse_key(pem, type))
  {
    return std::nullopt;
  }
  return pem;
}

/// Creates @p directory owner-only (0700), its missing parents as the environment's umask makes them.
void ensure_directory(const fs::path& directory)
{
  try
  {
    if (directory.has_parent_path())
    {
      fs::create_directories(directory.parent_path());
    }
    ua::security::ensure_owner_only_directory(directory, "TestKeyCache");
  }
  catch (const std::exception& error)
  {
    throw std::runtime_error{"the test key cache directory " + directory.string() +
                             " cannot be created or is not owner-only: " + error.what()};
  }
}

/// Writes @p pem to a new file in @p directory that only the owner can read (0600), and returns its path.
fs::path write_temporary(const fs::path& directory, const std::string& stem, const std::string& pem)
{
#if !defined(_WIN32)
  std::string pattern = (directory / (stem + ".tmp.XXXXXX")).string();
  std::vector<char> name(pattern.begin(), pattern.end());
  name.push_back('\0');
  const int descriptor = ::mkstemp(name.data());  // Created 0600, exclusively.
  if (descriptor < 0)
  {
    throw std::runtime_error{"cannot create a temporary key file in " + directory.string()};
  }
  std::size_t written = 0;
  while (written < pem.size())
  {
    const auto result = ::write(descriptor, pem.data() + written, pem.size() - written);
    if (result <= 0)
    {
      ::close(descriptor);
      std::remove(name.data());
      throw std::runtime_error{"cannot write a temporary key file in " + directory.string()};
    }
    written += static_cast<std::size_t>(result);
  }
  ::close(descriptor);
  return fs::path{name.data()};
#else
  std::random_device random;
  std::ostringstream suffix;
  suffix << std::hex << random() << random();
  const auto path = directory / (stem + ".tmp." + suffix.str());
  {
    std::ofstream out{path, std::ios::binary | std::ios::trunc};
    out.write(pem.data(), static_cast<std::streamsize>(pem.size()));
    if (!out)
    {
      throw std::runtime_error{"cannot write a temporary key file in " + directory.string()};
    }
  }
  std::error_code ignored;
  fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ignored);
  return path;
#endif
}

/// Generates the key into @p file, and returns the key now on disk (another process's when it won a race).
std::string generate_into(const fs::path& directory, const fs::path& file, KeyType type)
{
  const auto pem = generate_pem(type);
  ensure_directory(directory);
  const auto temporary = write_temporary(directory, file.filename().string(), pem);
  std::error_code error;
  if (load_valid(file, type))
  {
    fs::remove(temporary, error);  // Another process put a valid key in place first: adopt it.
  }
  else
  {
    fs::rename(temporary, file, error);
    if (error)
    {
      std::error_code ignored;
      fs::remove(temporary, ignored);
    }
  }
  if (auto onDisk = load_valid(file, type))
  {
    return *onDisk;
  }
  throw std::runtime_error{
    "cannot store the test key " + file.string() + (error ? ": " + error.message() : std::string{})};
}

std::mutex gMutex;

std::map<std::tuple<std::string, int, unsigned>, std::string>& in_process_cache()
{
  static std::map<std::tuple<std::string, int, unsigned>, std::string> cache;
  return cache;
}

std::string environment(const char* name)
{
  const char* value = std::getenv(name);
  return value != nullptr ? std::string{value} : std::string{};
}

}  // namespace

std::string type_name(KeyType type)
{
  switch (type)
  {
  case KeyType::Rsa512:
    return "rsa512";
  case KeyType::Rsa1024:
    return "rsa1024";
  case KeyType::Rsa1025:
    return "rsa1025";
  case KeyType::Rsa1500:
    return "rsa1500";
  case KeyType::Rsa2048:
    return "rsa2048";
  case KeyType::Rsa2049:
    return "rsa2049";
  case KeyType::Rsa3000:
    return "rsa3000";
  case KeyType::Rsa3072:
    return "rsa3072";
  case KeyType::Rsa4096:
    return "rsa4096";
  case KeyType::Rsa8192:
    return "rsa8192";
  case KeyType::P256:
    return "p256";
  case KeyType::P384:
    return "p384";
  case KeyType::P521:
    return "p521";
  case KeyType::Bp256:
    return "bp256";
  case KeyType::Bp384:
    return "bp384";
  case KeyType::Bp512:
    return "bp512";
  case KeyType::Ed25519:
    return "ed25519";
  case KeyType::Ed448:
    return "ed448";
  }
  return "unknown";
}

std::filesystem::path cache_directory()
{
  const auto explicitDirectory = environment("UASDK_TEST_KEY_CACHE");
  if (!explicitDirectory.empty())
  {
    return fs::path{explicitDirectory};
  }
  fs::path base;
  if (const auto xdg = environment("XDG_CACHE_HOME"); !xdg.empty())
  {
    base = fs::path{xdg};
  }
  else if (const auto home = environment("HOME"); !home.empty())
  {
    base = fs::path{home} / ".cache";
  }
#if defined(_WIN32)
  else if (const auto local = environment("LOCALAPPDATA"); !local.empty())
  {
    base = fs::path{local};
  }
  else if (const auto profile = environment("USERPROFILE"); !profile.empty())
  {
    base = fs::path{profile} / ".cache";
  }
#endif
  else
  {
    throw std::runtime_error{
      "the test key cache needs UASDK_TEST_KEY_CACHE, XDG_CACHE_HOME or HOME to be set"};
  }
  return base / "reduktive-uasdk" / "test-keys" / "v1";
}

const std::string& private_key_pem_in(const std::filesystem::path& directory, KeyType type, unsigned slot)
{
  const std::lock_guard<std::mutex> lock{gMutex};
  auto& cache = in_process_cache();
  const auto key = std::make_tuple(directory.string(), static_cast<int>(type), slot);
  if (const auto found = cache.find(key); found != cache.end())
  {
    return found->second;
  }
  const auto file = directory / (type_name(type) + "-" + std::to_string(slot) + ".pem");
  auto pem = load_valid(file, type);
  if (!pem)
  {
    pem = generate_into(directory, file, type);
  }
  return cache.emplace(key, std::move(*pem)).first->second;
}

const std::string& private_key_pem(KeyType type, unsigned slot)
{
  return private_key_pem_in(cache_directory(), type, slot);
}

EVP_PKEY* new_evp_pkey(KeyType type, unsigned slot)
{
  auto key = parse_key(private_key_pem(type, slot), type);
  if (!key)
  {
    throw std::runtime_error{"the cached " + type_name(type) + " test key does not parse"};
  }
  return key.release();
}

std::shared_ptr<const AsymmetricKeyPair> key_pair(const Crypto& crypto, KeyType type, unsigned slot)
{
  const auto& pem = private_key_pem(type, slot);
  std::vector<ua::byte> bytes;
  bytes.reserve(pem.size());
  for (const char c : pem)
  {
    bytes.push_back(static_cast<ua::byte>(c));
  }
  return crypto.get_private_key_from_pem(algorithm_of(type), span<ua::byte>{bytes.data(), bytes.size()});
}

void clear_in_process_cache()
{
  const std::lock_guard<std::mutex> lock{gMutex};
  in_process_cache().clear();
}

}  // namespace ua::test_keys
