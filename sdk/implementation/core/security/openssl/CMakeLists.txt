# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PRIVATE
        ua_crypto_openssl.h
        ua_x509_certificate_openssl.h
        ua_x509_crl_openssl.h
        ua_openssl_error_helpers.h
        ua_crypto_openssl.cpp
        ua_x509_certificate_openssl.cpp
        ua_x509_crl_openssl.cpp
)

uasdk_private_include_directory(uasdk-core)
