# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(uasdk-core PRIVATE
        ua_channel_role.h
        ua_secure_channel_context.h
        ua_security_policy.h
        ua_security_token.h
        ua_certificate_store_files.cpp
        ua_certificate_store_files_detail.h
        ua_certificate_store_files_impl.h
        ua_certificate_thumbprint.h
        ua_certificate_hostname.h
        ua_certificate_hostname.cpp
        ua_channel_bound_signature_data.h
        ua_channel_bound_signature_data.cpp
        ua_default_crypto.cpp
        ua_owner_only_directory.h
        ua_owner_only_directory.cpp
        ua_ecc_encrypted_secret_decoder.h
        ua_ecc_encrypted_secret_decoder.cpp
        ua_ecc_encrypted_secret_encoder.h
        ua_ecc_encrypted_secret_encoder.cpp
        ua_rsa_encrypted_secret_decoder.h
        ua_rsa_encrypted_secret_decoder.cpp
        ua_rsa_encrypted_secret_encoder.h
        ua_rsa_encrypted_secret_encoder.cpp
        ua_secure_memory.h
        ua_secure_memory.cpp
        ua_secure_string.cpp
        ua_security_policy.cpp
        ua_security_policy_internal.h
        ua_security_policy_test_access.h
        ua_crypto.cpp
        ua_certificate_store.cpp
        ua_certificate_validation_paths.h
        ua_certificate_validation_paths.cpp
        ua_security_token.cpp
        ua_security_policy_compatibility.h
        ua_security_policy_compatibility.cpp
        ua_user_token_encryption.h
        ua_user_token_encryption.cpp
)

uasdk_private_include_directory(uasdk-core)
add_subdirectory(openssl)
add_subdirectory(policies)
