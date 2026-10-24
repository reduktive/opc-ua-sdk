# `type_generator` (Python)

OPC-UA type generator: NodeSet2 XML → C++ types, identifier enums,
status codes, NS0 byte array, instance handles.

## Input

A single **manifest** — JSON (with `//` and `/* */` comments) — names
every NodeSet in scope and gives each one its C++ metadata + emission
policy:

```json
{
  "nodesets": [
    {
      "uri":               "http://opcfoundation.org/UA/",
      "sources":           ["Opc.Ua.NodeSet2.xml", "Opc.Ua.NodeSet2.Services.xml"],
      "nodeids_csv":       "NodeIds.csv",
      "statuscode_csv":    "StatusCode.csv",
      "attribute_ids_csv": "AttributeIds.csv",
      "include_prefix":    "ua_",
      "cpp_namespace":     "ua",
      "target":            "sdk",
      "emit":              true,
      "instance_type_categories":  ["all"],
      "instance_type_browse_names": [],
      "emit_event_types":           true
    }
  ]
}
```

Source paths resolve relative to the manifest file. Exactly one entry
must have `uri = "http://opcfoundation.org/UA/"` (NS0 is required for
cross-spec lookup; downstream entries set `emit: true` and reference
NS0 types). Set `emit: false` on a NodeSet to use it for lookup only.

Per `emit: true` entry, three policy fields control what gets emitted:
- `instance_type_categories` — `["all"]` discovers every category;
  `["alarms","conditions"]` picks specific ones; `[]` skips
  auto-discovery.
- `instance_type_browse_names` — explicit BrowseNames added to the
  instance-type set (in addition to auto-discovery).
- `emit_event_types` — `true` to emit event-type headers + hierarchy.

Data types are always emitted for every `emit: true` entry.

## Running

```bash
./tooling/type_generator/run_type_generator.sh \
    --manifest <manifest.json> --output <out-dir>
```

`--list-datatypes` (instead of `--output`) dumps every `UADataType`
found across the manifest's nodesets and exits.

## Using from CMake (downstream consumers)

Include the helper and call `ua_generate_types()`:

```cmake
include(UAGenerateTypes)

ua_generate_types(
    TARGET         my_di_types
    NS0_SOURCES    ${NS0_XML} ${NS0_SERVICES_XML}
    EMIT_SOURCES   ${DI_XML}
    OUTPUT_DIR     ${CMAKE_CURRENT_BINARY_DIR}/gen/di
    CPP_NAMESPACE  ua::di
    INCLUDE_PREFIX ua_di_
    DEPENDS        sdk
    # Optional emission policy:
    # INSTANCE_TYPE_CATEGORIES   all
    # INSTANCE_TYPE_BROWSE_NAMES DeviceType TopologyElementType
    # EMIT_EVENT_TYPES
)
target_link_libraries(my_app PRIVATE my_di_types)
```

The helper synthesises the JSON manifest from the inline args (URI
auto-detected from the NodeSet XML), runs the generator at configure
time, creates the library target, attaches the generated subtrees, and
registers `<TARGET>_regenerate` for XML-change iteration.

Pass `MANIFEST <path>` instead of the inline args to use a hand-authored
manifest.

## Regenerating the SDK's checked-in NS0 types

```bash
cmake --build <build-dir> --target generate_types
```

NS0 itself uses `ua_generate_types(... REGEN_ONLY SYNC_TO sdk/ ...)` —
the helper handles the regen-and-sync workflow that keeps the
committed generated files current. See
`tooling/type_generator/CMakeLists.txt` for the invocation.
