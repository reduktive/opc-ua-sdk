// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Reduktive Limited.

#ifndef UASDK_EXAMPLE_PKI_H
#define UASDK_EXAMPLE_PKI_H

/// @file
/// @brief A development PKI shared by the example programs, so that each of them runs in one
///        command without a provisioning step.
///
/// **Not for production.** Every function here takes a shortcut a deployment must not take: the
/// certificates are self-signed, the private-key password is a constant, the store lives in the
/// system temporary directory, and the two halves are made to trust each other automatically
/// rather than by an operator who has checked a fingerprint. It exists so that an example about
/// subscriptions is about subscriptions.
///
/// `examples/quickstart/roundtrip` does the rest of this in the foreground, in one file, using only
/// development_crypto() from here. Read that to see what these functions actually do, and
/// `examples/reference_server` to see how a real application manages its PKI.

#include "ua_certificate_store.h"
#include "ua_crypto.h"

#include <boost/asio/any_io_executor.hpp>

#include <filesystem>
#include <memory>
#include <string_view>

namespace examples
{

/// Which half of the example pair is being provisioned.
enum class PkiRole
{
  Server,
  Client
};

/// One half's cryptographic identity.
struct DevelopmentPki
{
  std::shared_ptr<const ua::Crypto> crypto;
  std::shared_ptr<ua::CertificateStore> store;
  std::shared_ptr<const ua::X509Certificate> certificate;
};

/// The crypto provider every example and every book example uses: the SDK's default provider with
/// a constant private-key password, so the keys a store writes can be read back on the next run.
///
/// **Not for production.** A deployment supplies the password from a secret provider, never from
/// source, a command line, or a log.
[[nodiscard]] std::shared_ptr<const ua::Crypto> development_crypto();

/// Opens the shared example PKI and returns the identity for @p role.
///
/// Both identities are created on the first call, whichever program makes it, and each is given
/// the other's public certificate as a trust anchor. That is what lets an example server and an
/// example client each start with no arguments and still refuse an untrusted peer.
///
/// **Not for production.** A deployment provisions certificates from its own authority, keeps them
/// in a protected location, and imports a peer certificate only after verifying its fingerprint
/// over an independent channel.
///
/// @param executor The executor the certificate store posts its file work to.
/// @param role     Which half's identity to return.
/// @return The requested half's crypto provider, store, and own certificate.
DevelopmentPki open_development_pki(boost::asio::any_io_executor executor, PkiRole role);

/// The directory the development PKI lives in: `<temp>/uasdk-examples-pki-<uid>` on POSIX (the temp
/// directory is shared between users there), `<temp>/uasdk-examples-pki` on Windows (per-user).
[[nodiscard]] std::filesystem::path development_pki_root();

/// Creates @p root owner-only (0700) or, when it exists, checks that it is a real directory (not a
/// symlink) owned by this user with no group/other permission bits. Throws std::runtime_error
/// otherwise: a shared, predictable temporary path is where another local user plants a directory
/// to read or replace the example's keys.
void prepare_development_pki_root(const std::filesystem::path& root);

/// The ApplicationUri carried by @p role's development certificate. An application's URI must
/// match the one in its certificate, so a configuration built by hand must use this exact value.
[[nodiscard]] std::string_view development_application_uri(PkiRole role) noexcept;

}  // namespace examples

#endif  // UASDK_EXAMPLE_PKI_H
