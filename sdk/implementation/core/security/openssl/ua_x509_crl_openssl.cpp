// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#include "ua_x509_crl_openssl.h"
#include "ua_utilities.h"
#include "ua_crypto_openssl.h"
#include "ua_error_detail.h"
#include "ua_openssl_error_helpers.h"

namespace ua
{

X509CrlOpenSsl::X509CrlOpenSsl(X509_CRL& crl) : mCrl(crl)
{}

X509CrlOpenSsl::~X509CrlOpenSsl()
{
  X509_CRL_free(&mCrl);
}

ByteString X509CrlOpenSsl::der_encoding() const
{
  auto length = i2d_X509_CRL(&mCrl, NULL);
  if (length < 0)
  {
    throw UaException{Status::BadInternalError,
      detail::make_openssl_error_detail(
        "DerEncodingFailed", "Failed to compute DER encoding length for X509 CRL", "X509Crl")};
  }

  ByteString result;
  // length >= 0 proven by the guard above (i2d_X509_CRL returns a negative value on error).
  result.resize(static_cast<size_t>(length));
  auto* dest = result.data();
  length = i2d_X509_CRL(&mCrl, &dest);
  if (length == -1)
  {
    throw UaException{Status::BadInternalError,
      detail::make_openssl_error_detail("DerEncodingFailed", "Failed to DER-encode X509 CRL", "X509Crl")};
  }

  return result;
}

ByteString X509CrlOpenSsl::thumbprint() const
{
  auto crypto = CryptoOpenSsl::create();
  auto der = der_encoding();
  auto result = crypto->calculate_digest_sync(HashAlgorithm::Sha1, der);
  return result;
}

bool X509CrlOpenSsl::operator==(const X509Crl& obj) const
{
  return (obj.thumbprint() == thumbprint());
}

const X509_CRL& X509CrlOpenSsl::crl() const
{
  return mCrl;
}

}  // namespace ua
