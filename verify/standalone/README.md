# Independent verifier

`sift_verify.py` checks a Sift evidence pack (`vpmp/v1`) **without Sift**.

- Python standard library only. No `pip install`, no Go toolchain, no network.
- No import of Sift code. Every rule is re-implemented from the published format.
- If this script and `sift verify` disagree about a pack, that disagreement is
  the finding — one of the two implementations is wrong.

That is the point: "trust our verifier" is not a security claim. A signature is
only meaningful if an independent party can check it from the bytes alone.

## Run it

```sh
python3 sift_verify.py --bundle bundle.json
python3 sift_verify.py --bundle bundle.json --samples bundle.samples.jsonl
python3 sift_verify.py --bundle bundle.json --samples bundle.samples.jsonl \
    --trust-key a09aa5f4... --require-anchor
python3 sift_verify.py --self-test
```

Exit status: `0` valid, `1` invalid, `2` unreadable input.

## What it checks

| Check | Meaning |
| --- | --- |
| `format` | the document declares `vpmp/v1` |
| `bundle-digest` | SHA-256 over the canonical bundle without its signature |
| `bundle-signature` | Ed25519 over that digest, by the key the bundle names |
| `issuer-trust` | that key is one you pinned (`UNPINNED` is never reported as trusted) |
| `commit-signature[w]` | each worker's Ed25519 signature over its commit |
| `commit-count[w]` | sidecar line count equals `commit.sample_count` |
| `commit-root[w]` | the records reproduce the signed Merkle root |
| `worker-aggregate[w]` | count, sum, min, max and histogram reproduce |
| `aggregate` | run-wide count, sum, p50/p95/p99 reproduce |
| `aggregate-rate` | `aggregate.rps` equals the record count over the duration |
| `integrity` | `dropped_samples` and `schedule_accuracy_ppm` reproduce |

## What it does not check

`aggregate.co_ci95_ns` — the coordinated-omission bootstrap interval needs the
producer's exact pseudo-random sequence. The script reports it as `SKIP`, not as
a pass. Everything else in `vpmp/v1` is covered.

## Why the crypto is hand-written

The Ed25519 verifier is the RFC 8032 reference construction, not a new design.
It is deliberately slow (no precomputation) because a pack holds a handful of
signatures and being obviously correct matters more than being fast.
`--self-test` proves it against RFC 8032 §7.1 TEST 1 and against a single flipped
bit, so a broken build cannot report a passing pack.

## The cross-implementation test

`internal/attest/python_verify_test.go` runs this script against a bundle the Go
package produced, and fails if the two disagree — on a clean pack, on a pack with
one altered nanosecond, and on the issuer-trust check. The test skips (never
passes silently) when `python3` is absent.
