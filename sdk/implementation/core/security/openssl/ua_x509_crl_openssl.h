// SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
// Copyright (c) 2026 Reduktive Limited. All rights reserved.

#ifndef UA_X509_CRL_OPENSSL_H
#define UA_X509_CRL_OPENSSL_H

#include "openssl/x509.h"
#include "ua_x509_crl.h"
#include "ua_built_in_types_fwd_decl.h"

namespace ua
{

class X509CrlOpenSsl : public X509Crl
{
public:
  explicit X509CrlOpenSsl(X509_CRL& crl);
  ~X509CrlOpenSsl();

  // mCrl is owned (freed with X509_CRL_free in the destructor) but held by reference, so the
  // compiler-generated copy/move would alias the same X509_CRL* and double-free it. Forbid
  // value semantics; the type is only ever held via shared_ptr.
  X509CrlOpenSsl(const X509CrlOpenSsl&) = delete;
  X509CrlOpenSsl& operator=(const X509CrlOpenSsl&) = delete;
  X509CrlOpenSsl(X509CrlOpenSsl&&) = delete;
  X509CrlOpenSsl& operator=(X509CrlOpenSsl&&) = delete;

  bool operator==(const X509Crl& obj) const override;

  ByteString der_encoding() const override;

  ByteString thumbprint() const override;

  const X509_CRL& crl() const;

private:
  X509_CRL& mCrl;
};

}  // namespace ua

#endif  //! UA_X509_CRL_OPENSSL_H
