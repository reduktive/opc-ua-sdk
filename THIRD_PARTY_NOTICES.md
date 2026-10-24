# Third-Party Notices

The Reduktive OPC UA SDK is distributed with, links against, or derives generated code from the
third-party components below. Each retains its own license. Versions reflect the pinned
`builtin-baseline` and overrides in `vcpkg.json`.

Test-only dependencies (e.g. GoogleTest) are **not** part of any shipped artefact and are excluded.

## Linked / distributed dependencies

| Component | Version | License (SPDX) | Notes |
|---|---|---|---|
| Boost | 1.88.0 | BSL-1.0 | Header-only for the SDK except Boost.JSON (compiled). Components: asio, container-hash, endian, flyweight, json, range, uuid. |
| OpenSSL | 3.5.9 | Apache-2.0 | Crypto backend (libcrypto). |
| {fmt} | 10.2.1 | MIT | Formatting. |
| RapidXml | 1.13 | BSL-1.0 OR MIT | **Vendored** in `third_party/rapidxml/`; full license text in `third_party/rapidxml/LICENSE`. Build-only (the SDK's XML codec); not exposed to consumers. |
| SQLite | 3.50.4 | Public Domain | Only when the optional `uasdk::history-sqlite` component is used. |

## OPC Foundation UA-Nodeset

The SDK's NS0 (namespace 0) generated types, identifiers, and status codes are generated from the
**OPC Foundation UA-Nodeset** normative files (tag `UA-1.05.06-2025-11-08`,
<https://github.com/OPCFoundation/UA-Nodeset>), and the SDK embeds the `Opc.Ua.NodeSet2.xml` content
directly. Those files are released under the **OPC Foundation MIT License 1.00** (a permissive
MIT-style license that grants use, copy, modify, distribute, sublicense, and sell, provided the notice
below is included). Full license: <http://opcfoundation.org/License/MIT/1.00/>.

```
Copyright (c) 2005-2024 The OPC Foundation, Inc. All rights reserved.

OPC Foundation MIT License 1.00

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The complete license agreement can be found here: http://opcfoundation.org/License/MIT/1.00/
```

## Full license texts

- Boost Software License 1.0 — <https://www.boost.org/LICENSE_1_0.txt>
- Apache License 2.0 — <https://www.apache.org/licenses/LICENSE-2.0>
- MIT — <https://opensource.org/license/mit>
- RapidXml — `third_party/rapidxml/LICENSE` (shipped in-tree, as it is vendored)
- SQLite — public domain, <https://www.sqlite.org/copyright.html>
- OPC Foundation MIT License 1.00 — <http://opcfoundation.org/License/MIT/1.00/> (see the
  OPC Foundation UA-Nodeset section above for the verbatim notice)

The authoritative per-component copyright texts are emitted by vcpkg under
`share/<port>/copyright` in the dependency install tree.
