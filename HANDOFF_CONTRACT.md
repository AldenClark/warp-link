# Current Private handoff contract

This is the main-line successor to the historical `PRIVATE128_INTEGRATION.md`.
That document records an earlier integration, not the current handoff verdict.

The implementation at `344a0486a69764da2e52441618d481fdcb43fbcf` keeps the
healthy primary as the sole application-delivery owner while a candidate connects,
waits for WELCOME, and passes its guard. Continuous incoming traffic cannot starve
the existing bounded upgrade probe. Cancellation drops the owned candidate.

Private delivery completes only through its explicit delivery-ID ACK. A HELLO
maximum sequence is not evidence that all smaller sequences were persisted:
sequence numbers belong to a device/resume epoch and can have legitimate gaps.
The client clears this compatibility hint on every HELLO. The server must retain
unacknowledged deliveries; an ACK lost in transit may cause replay, handled by the
application's durable identity/deduplication. This is not exactly-once delivery.

An offered `wl_handoff=1` capability negotiates prepare, freeze/drain, activate,
or resume receipts in HELLO/WELCOME. The profile retains the legacy payload prefix
and wire version and encodes only four bounded handoff metadata keys in a trailing
extension (maximum 1,024 bytes). Peers without an offer receive the old encoding.
An old server without the capability remains usable for normal connection and
recovery, but is not used for an unconfirmed loss-safe hot cutover.

The prepared candidate has no business outbound ownership. The server stops new
old-owner sends and joins its outstanding preparation before emitting an ordered
drained receipt. The client persists and explicitly ACKs preceding old frames,
fences those ACKs, and requests activation. Only the matching candidate active
receipt commits the client swap. Device, old session, resume epoch and reservation
nonce are checked. Ambiguous activation failure reconnects instead of assuming the
old owner is still safe. Gateway reservations are ephemeral and bounded to 15
seconds; this is not a message or identity retention period.

Whole Private frames/WELCOME remain bounded to 128 KiB; this is separate from
the application-level 48 KiB whole-request contract. No old-client fallback or
transport copy was added. Already running arbitrary synchronous host callbacks
cannot be forcibly cancelled; cancellation must not manufacture a wire ACK.

## Reproduce the component checks

Using the repository-pinned Rust toolchain:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
```

The final macOS ARM64 component input had 115 passing methods, including 22
cutover methods (a subset), all-feature strict Clippy and individual transport/FFI
feature checks. Tests preserve held/absent WELCOME, guard failure/cancellation,
old 8 before candidate 9, save failure, legal gaps, duplicate frames, stale epochs,
late freeze/resume and a single application callback owner. Candidate fixture
release depends on observing the primary's actual wire ACK within the unchanged
500 ms bound, not a sleep/retry or a performance claim.

Gateway also carries a portable, test-only two-sided regression under
`tests/support/handoff_integration/`. Its real production-module callbacks and
SQLite assertions verify that unsaved delivery 8 remains pending with its body,
then that successful persistence/explicit ACK permits terminalization. The local
two-sided run passed two methods. This is plain loopback/module evidence, not a
normal installed Android/Windows application, production TLS connector, every
transport, power-loss, or entire outer reconnect-loop acceptance.

Consumers must pin the actual implementation commit, not depend on this library's
lockfile. Android, Windows and Gateway normal manifests/locks pin full revision
`344a0486a69764da2e52441618d481fdcb43fbcf`. Later documentation-only main commits
do not alter those implementation bytes. Publication of a main ref and a successful
clean-source resolution are separate from device, release, signing and deployment
acceptance. No release or deployment is implied here.
