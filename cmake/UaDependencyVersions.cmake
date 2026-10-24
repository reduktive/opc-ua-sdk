# SPDX-License-Identifier: LicenseRef-Reduktive-Source-Available-1.0
# Copyright (c) 2026 Reduktive Limited. All rights reserved.

# Record configured versions for release inventory without requiring a package manager.
# Unknown versions stay empty: a provider may build, but cannot earn a verified SBOM.
function(ua_write_dependency_versions output boost_version openssl_version fmt_version with_sqlite sqlite_version)
    set(_versions_boost "${boost_version}")
    set(_versions_openssl "${openssl_version}")
    set(_versions_fmt "${fmt_version}")
    set(_names boost openssl fmt)
    if (with_sqlite)
        set(_versions_sqlite3 "${sqlite_version}")
        list(APPEND _names sqlite3)
    endif ()
    set(_manifest "{\"schemaVersion\":1,\"dependencies\":{}}")
    foreach (_name IN LISTS _names)
        set(_version "${_versions_${_name}}")
        if (NOT _version MATCHES "^[0-9]+\\.[0-9]+[0-9A-Za-z.+_~#-]*$")
            set(_version "")
        endif ()
        string(JSON _manifest SET "${_manifest}" dependencies "${_name}" "\"${_version}\"")
    endforeach ()
    file(WRITE "${output}" "${_manifest}\n")
endfunction()
