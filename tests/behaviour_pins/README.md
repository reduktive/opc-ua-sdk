# Behaviour-pin tests

This directory holds the **durable behavioural specification** for the SDK
async surface — SHA-256 KATs, `ErrorDetail` propagation invariants, single-
flight gates, threading-affinity contracts, destructor-during-flight rules,
and wire-observable invariants. This is the permanent home for these
assertions.

## Layout

```
tests/behaviour_pins/
├── README.md                                # this file
├── _pin_test_template.cpp                   # canonical example + fixture
├── CMakeLists.txt                           # add_subdirectory(...) per phase
├── phase_4_1_crypto/
│   ├── CMakeLists.txt
│   └── crypto_pin_test.cpp
├── phase_4_3_security_policy/
│   ├── CMakeLists.txt
│   ├── decode_asymmetric_pin_test.cpp
│   ├── decode_symmetric_pin_test.cpp
│   ├── derive_symmetric_keys_pin_test.cpp
│   ├── encode_symmetric_pin_test.cpp
│   └── wire_roundtrip_pin_test.cpp
└── ...
```

Each test class is `<Flow>Pin` (e.g. `BrowseServicePin`) and each test
name encodes the property: `BrowseServicePin.PropagatesAuthorizerErrorDetailToResponse`,
`BrowseServicePin.SecondInvocationWhilePendingReturnsBadInvalidState`, etc.

The `Pin` suffix usefully signals "this asserts an externally-observable
contract; edit with care" — renaming to a more conventional `<Flow>Test` is
permitted but not required. The filter `--gtest_filter='*Pin*'` selects the
corpus.

## Build and run

Pin tests compile into the main `tests` binary. They run with every unit-
test invocation:

```
cmake --build cmake-build-debug-gcc
cmake -E chdir cmake-build-debug-gcc/tests ./tests --gtest_filter='*Pin*'
```

There is no separate `behaviour_pins_test` executable; the dissolve in
§9.5 of the migration ledger folded the per-phase `target_sources(...)`
into the `tests` target.

## What a pin asserts

A pin test asserts at least one of the following observable properties:

1. **Final `Status`** for a successful invocation.
2. **Final `Status` and `ErrorDetail` payload** for each documented failure
   mode of the flow. ErrorDetail content matters: status alone is
   insufficient.
3. **`ErrorDetail` propagation** — when an inner step fails with detail, the
   outer callback receives the same detail (no copy-by-value loss, no
   replacement with a fresh detail at the boundary).
4. **Single-flight rejection** — for single-instance flows, a second
   concurrent invocation receives `Status::BadInvalidState` and does not
   perturb the in-flight call.
5. **Threading affinity** — the user callback fires on the strand the design
   names. A pin captures the executing strand (via
   `boost::asio::system_executor::context()` comparison or a thread-id
   capture set on the strand at construction).
6. **Concurrent-on-strand semantics** — for service flows that kick off N
   operations and aggregate, a pin asserts that operations N and N+1 both
   reach their first await before the response is built — i.e. they
   interleave on the strand rather than serialising.
7. **Destructor-during-flight** — destroying the owning component while the
   flow is mid-flight either fires `onComplete` with a shutdown status or
   drops cleanly without UAF (per `async_design.md` §7.3).
8. **Wire-observable invariants** — for flows that produce wire output
   (services, secure-channel encode/decode), the byte sequence on the wire
   is identical before and after the implementation change.

## What a pin must NOT do

- **Pin internal types or method names.** A pin asserting "the flow has a
  `step` field on its struct" couples to implementation. Pins are about
  external observation — `Result<T>`, callback-firing, wire bytes, thread
  context.
- **Pin internal call ordering not visible at the boundary.** "Crypto's
  `sign_async` was called before `encrypt_async`" is fine if observable
  through a fake collaborator that records calls; it is not fine if it
  requires reaching into private state.
- **Sleep-based assertions.** A pin must use a deterministic signal
  (callback fired, future ready, fake collaborator's call counter
  incremented). `std::this_thread::sleep_for(...)` then
  `EXPECT_FALSE(eventOccurred)` is forbidden — see the repository test-quality
  rules.

## Adding a pin

1. Identify the externally-observable property you want to assert from the
   list above.
2. Add a `TEST_F` to the matching `phase_4_<sub-phase>_<flow>/<flow>_pin_test.cpp`,
   following the `<Flow>Pin` fixture convention. Use
   `_pin_test_template.cpp` as a starting point.
3. Run the pin and confirm it passes.

There is no longer a separate "pin authoring PR" / "flip PR" cycle —
amendments are ordinary code changes.

## Cross-references

- The repository engineering guide — test-failure policy, test-quality rules.
- `../../design_docs/async/async_design.md` — async surface.
