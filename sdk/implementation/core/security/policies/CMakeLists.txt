# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PRIVATE
        ua_certificate_key_rules.h
        ua_sec_pol_aes128_sha256_rsa_oaep.h
        ua_sec_pol_aes256_sha256_rsa_pss.h
        ua_sec_pol_asymmetric_encryption.h
        ua_sec_pol_basic128_rsa15.h
        ua_sec_pol_basic256.h
        ua_sec_pol_basic256_sha256.h
        ua_sec_pol_ephemeral_key.h
        ua_sec_pol_none.h
        ua_certificate_key_rules.cpp
        ua_sec_pol_basic256_sha256.cpp
        ua_sec_pol_none.cpp
        ua_sec_pol_asymmetric_encryption.cpp
        ua_sec_pol_ephemeral_key.cpp
        ua_sec_pol_ephemeral_key_rows.cpp
        ua_sec_pol_aes128_sha256_rsa_oaep.cpp
        ua_sec_pol_aes256_sha256_rsa_pss.cpp
        ua_sec_pol_basic128_rsa15.cpp
        ua_sec_pol_basic256.cpp
)

uasdk_private_include_directory(uasdk-core)
