# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

target_sources(tests PRIVATE
        crypto_generic_tests.cpp
        ecc_channel_wire_tests.cpp
        deprecated_security_policy_tests.cpp
        security_policy_parameterized_tests.cpp
        ecc_encrypted_secret_tests.cpp
        rsa_encrypted_secret_decoder_tests.cpp
        rsa_encrypted_secret_encoder_tests.cpp
        user_token_encryption_tests.cpp
        x509_tests.cpp
        x509_accessor_tests.cpp
        certificate_store_files_tests.cpp
        certificate_store_generic_tests.cpp
        certificate_store_generic_negative_tests.cpp
        certificate_store_rejected_tests.cpp
        certificate_store_test_backends.h
        certificate_hostname_tests.cpp
        certificate_validation_matrix_tests.cpp
        certificate_policy_and_error_matrix_tests.cpp
        certificate_session_acceptance_tests.cpp
        certificate_completeness_tests.cpp
        certificate_suppressed_audit_tests.cpp
        certificate_presented_chain_path_tests.cpp
        certificate_policy_compliance_tests.cpp
        certificate_validation_path_wiring_tests.cpp
        test_key_cache_tests.cpp
        secure_string_tests.cpp
        owner_only_directory_tests.cpp
        uasc_asymmetric_security_header_tests.cpp
        uasc_authenticated_opn_tests.cpp
        uasc_security_policy_tests.cpp
        uasc_sequence_tests.cpp
        cert_selection_utility_tests.cpp
        x509_user_authenticator_tests.cpp
        simple_user_password_authenticator_tests.cpp
        sce_crypto_tests.cpp
        enhanced_channel_framing_tests.cpp
        channel_bound_signature_data_tests.cpp
        sce_vector_helpers.h
        sce_vectors.h
)
