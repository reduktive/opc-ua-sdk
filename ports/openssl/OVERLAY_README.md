# OpenSSL overlay port

This directory is the upstream vcpkg `openssl` port as of its 3.5.4 release (vcpkg git-tree
`737382595bac2a92c7f8f54f120b53d2637af521`), changed only in `vcpkg.json` (version 3.5.9) and in
`portfile.cmake` (the SHA512 of the `openssl-3.5.9` source archive).

Why: the SDK pins the OpenSSL 3.5 long-term-support series. Upstream vcpkg stops at 3.5.4 and moved
on to 3.6, and the releases after 3.5.4 fix issues in code the SDK uses (X.509, ASN.1 parsing, EC
scalar multiplication, AEAD tag verification). Owner decision 5 of the security review (2026-10-01).

Remove this overlay when upstream vcpkg carries a 3.5.x at or above the pinned version, or when the
pin moves to a series upstream vcpkg carries.

It lives in `ports/` beside the SDK's own `uasdk` port so that one overlay directory serves both the SDK's
build (`vcpkg.json` overlay-ports) and a downstream consumer that points vcpkg at `ports/`
(`VCPKG_OVERLAY_PORTS`), which needs the same OpenSSL to resolve the pinned 3.5.9.
