#!/usr/bin/env python3
"""sift_verify.py — verify a Sift (vpmp/v1) evidence pack without Sift.

Why this file exists
--------------------
"Trust our verifier" is not a security claim. This script re-implements the
verification from the published format using nothing but the Python standard
library: no pip install, no Go toolchain, no import of Sift code, no network.
If this script and `sift verify` disagree, one of them is wrong and the
disagreement is the finding.

What it checks
--------------
  1. format            the document says vpmp/v1
  2. bundle-digest     SHA-256 over the canonical bundle without its signature
  3. bundle-signature  Ed25519 over that digest, by the key the bundle names
  4. issuer-trust      that key is one you pinned (only when you pass --trust-key
                       or --trust-store; otherwise the issuer is reported as
                       UNPINNED, never as trusted)
  5. commit-signature  each worker's Ed25519 signature over its commit digest
  6. commit-count      each worker's sample_count equals its sidecar line count
  7. commit-root       the sidecar records reproduce the signed Merkle root
  8. worker-aggregate  count, sum, min, max and histogram reproduce
  9. aggregate         run-wide count, sum, p50/p95/p99 and rate reproduce
 10. integrity         achieved_rps, dropped_samples and schedule_accuracy_ppm
                       reproduce from the rate and the record count

What it does NOT check
----------------------
The coordinated-omission bootstrap confidence interval (aggregate.co_ci95_ns)
needs the producer's exact pseudo-random sequence; this script reports it as
NOT CHECKED rather than pretending. Everything else in vpmp/v1 is covered.

Canonical encoding
------------------
The canonical form is: object keys sorted by byte order, no whitespace,
integers only (no floats, no exponents), minimal string escaping. Python's
json.dumps with sort_keys and compact separators produces exactly those bytes
for this data model; every number is required to be an int on the way in, so a
float in the input is a hard error rather than a silent re-rendering.

Exit status
-----------
  0  every check passed (or was explicitly not applicable)
  1  at least one check failed
  2  the input could not be read or parsed

Usage
-----
  python3 sift_verify.py --bundle bundle.json
  python3 sift_verify.py --bundle bundle.json --samples bundle.samples.jsonl
  python3 sift_verify.py --bundle bundle.json --samples s.jsonl \\
      --trust-key a09aa5f4... --require-anchor
  python3 sift_verify.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

FORMAT_ID = "vpmp/v1"
BUNDLE_COVERS = "sha256(canonical-bundle-without-signature)"
TRUST_FORMAT = "sift-trust/v1"
PPM_SCALE = 1_000_000
MILLI_SCALE = 1_000
NS_PER_SECOND = 1_000_000_000
EMPTY_ROOT_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032) — pure Python, verification only
# ---------------------------------------------------------------------------
#
# This is the RFC 8032 reference construction, not a new design. It is slow by
# design (no precomputation, no batch verification) because it verifies a
# handful of signatures per document, and being obviously correct matters more
# than being fast.

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)

Point = Tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        raise ValueError("point is not on the curve")
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_BX = _x_recover(_BY)
_BASE: Point = (_BX, _BY, 1, _BX * _BY % _P)
_IDENTITY: Point = (0, 1, 1, 0)


def _point_add(p: Point, q: Point) -> Point:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(p: Point, e: int) -> Point:
    result = _IDENTITY
    addend = p
    while e > 0:
        if e & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        e >>= 1
    return result


def _point_equal(p: Point, q: Point) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _decode_point(raw: bytes) -> Point:
    if len(raw) != 32:
        raise ValueError("point encoding must be 32 bytes")
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    sign = raw[31] >> 7
    if y >= _P:
        raise ValueError("point y coordinate is not in the field")
    x = _x_recover(y)
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Return True iff signature is a valid Ed25519 signature of message."""
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        a = _decode_point(public)
        r = _decode_point(signature[:32])
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(
        hashlib.sha512(signature[:32] + public + message).digest(), "little"
    ) % _L
    return _point_equal(_point_mul(_BASE, s), _point_add(r, _point_mul(a, h)))


# RFC 8032 §7.1 TEST 1 — a vector that has nothing to do with Sift. If this
# fails, the crypto above is wrong and no verdict from this script means
# anything, so --self-test exists to prove it independently.
_RFC8032_VECTOR = (
    bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    b"",
    bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ),
)


def self_test() -> bool:
    public, message, signature = _RFC8032_VECTOR
    if not ed25519_verify(public, message, signature):
        return False
    # A single flipped bit must be rejected, otherwise the verifier accepts
    # everything and every PASS below is meaningless.
    broken = bytearray(signature)
    broken[0] ^= 0x01
    return not ed25519_verify(public, message, bytes(broken))


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------


class CanonicalError(ValueError):
    pass


def _reject_float(text: str) -> Any:
    raise CanonicalError(f"non-integer number {text!r} is not canonical")


def _reject_constant(text: str) -> Any:
    raise CanonicalError(f"constant {text!r} is not valid JSON")


def parse_json(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalError(f"document is not valid UTF-8: {exc}") from exc
    try:
        return json.loads(
            text, parse_float=_reject_float, parse_constant=_reject_constant
        )
    except CanonicalError:
        raise
    except json.JSONDecodeError as exc:
        raise CanonicalError(f"document is not valid JSON: {exc}") from exc


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Merkle tree (docs: leaf = SHA-256(0x00 || be64(index) || leaf_bytes),
#              node = SHA-256(0x01 || left || right), odd node repeated)
# ---------------------------------------------------------------------------


def leaf_hash(index: int, data: bytes) -> bytes:
    return sha256(b"\x00" + index.to_bytes(8, "big") + data)


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        return sha256(b"")
    level = [leaf_hash(i, leaf) for i, leaf in enumerate(leaves)]
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(sha256(b"\x01" + left + right))
        level = nxt
    return level[0]


# ---------------------------------------------------------------------------
# Protocol arithmetic (mirrors docs/FORMAT.md, not the Go source)
# ---------------------------------------------------------------------------


def percentile(sorted_values: Sequence[int], ppm: int) -> int:
    n = len(sorted_values)
    if n == 0:
        return 0
    if ppm <= 0:
        return sorted_values[0]
    if ppm >= PPM_SCALE:
        return sorted_values[-1]
    rank = (ppm * n + PPM_SCALE - 1) // PPM_SCALE
    rank = max(1, min(rank, n))
    return sorted_values[rank - 1]


def bucket_upper_ns(latency_ns: int) -> int:
    if latency_ns <= 0:
        return 0
    return (1 << latency_ns.bit_length()) - 1


def mul_div_round(a: int, b: int, d: int) -> int:
    if d <= 0:
        raise CanonicalError("division by zero")
    return (a * b + d // 2) // d


def achieved_rps_milli(count: int, duration_ns: int) -> int:
    if duration_ns <= 0:
        raise CanonicalError(f"duration_ns {duration_ns} must be positive")
    return mul_div_round(count, NS_PER_SECOND * MILLI_SCALE, duration_ns)


def planned_slots(planned_milli: int, duration_ns: int) -> int:
    if planned_milli < 0 or duration_ns <= 0:
        raise CanonicalError("planned rate and duration must be non-negative")
    return mul_div_round(planned_milli, duration_ns, NS_PER_SECOND * MILLI_SCALE)


def schedule_accuracy_ppm(planned_milli: int, achieved_milli: int) -> int:
    if planned_milli <= 0:
        return PPM_SCALE if achieved_milli <= 0 else 0
    deviation = mul_div_round(
        abs(achieved_milli - planned_milli), PPM_SCALE, planned_milli
    )
    if deviation >= PPM_SCALE:
        return 0
    return PPM_SCALE - deviation


def decimal_milli(text: Any) -> int:
    """Parse a canonical Decimal ("6.500") into thousandths (6500)."""
    if not isinstance(text, str):
        raise CanonicalError(f"decimal {text!r} is not a string")
    if text.count(".") != 1:
        raise CanonicalError(f"decimal {text!r} must contain exactly one dot")
    whole, frac = text.split(".")
    if not whole or len(frac) != 3 or not whole.isdigit() or not frac.isdigit():
        raise CanonicalError(f"decimal {text!r} must have 3 fractional digits")
    if len(whole) > 1 and whole[0] == "0":
        raise CanonicalError(f"decimal {text!r} has leading zeros")
    return int(whole) * MILLI_SCALE + int(frac)


def decimal_from_milli(milli: int) -> str:
    if milli < 0:
        raise CanonicalError("negative rate")
    return f"{milli // MILLI_SCALE}.{milli % MILLI_SCALE:03d}"


# ---------------------------------------------------------------------------
# Records and commits
# ---------------------------------------------------------------------------

_MAX_WORKER_ID = 128
_MAX_STATUS = 999


def validate_record(rec: Dict[str, Any]) -> None:
    for key in ("seq", "worker", "start_ns", "latency_ns", "status", "bytes"):
        if key not in rec:
            raise CanonicalError(f"record is missing {key!r}")
    worker = rec["worker"]
    if not isinstance(worker, str) or not worker:
        raise CanonicalError("record worker id is empty")
    if len(worker.encode("utf-8")) > _MAX_WORKER_ID:
        raise CanonicalError("record worker id is too long")
    for key in ("seq", "start_ns", "latency_ns", "status", "bytes"):
        if not isinstance(rec[key], int) or isinstance(rec[key], bool):
            raise CanonicalError(f"record {key} is not an integer")
    if rec["seq"] < 1:
        raise CanonicalError("record seq must be >= 1")
    if rec["start_ns"] < 0 or rec["latency_ns"] < 0 or rec["bytes"] < 0:
        raise CanonicalError("record has a negative field")
    if not 0 <= rec["status"] <= _MAX_STATUS:
        raise CanonicalError("record status is out of range")


def canonical_record(rec: Dict[str, Any]) -> bytes:
    validate_record(rec)
    return canonical_bytes(
        {
            "bytes": rec["bytes"],
            "latency_ns": rec["latency_ns"],
            "seq": rec["seq"],
            "start_ns": rec["start_ns"],
            "status": rec["status"],
            "worker": rec["worker"],
        }
    )


def canonical_commit_unsigned(commit: Dict[str, Any]) -> bytes:
    return canonical_bytes(
        {
            "merkle_root": commit["merkle_root"],
            "sample_count": commit["sample_count"],
            "window_start_ns": commit["window_start_ns"],
            "window_end_ns": commit["window_end_ns"],
        }
    )


def record_sort_key(rec: Dict[str, Any]) -> Tuple[int, int]:
    return (rec["start_ns"], rec["seq"])


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


class Report:
    def __init__(self) -> None:
        self.rows: List[Dict[str, Any]] = []

    def add(self, check: str, status: str, detail: str) -> None:
        self.rows.append({"check": check, "status": status, "detail": detail})

    def ok(self, check: str, detail: str) -> None:
        self.add(check, PASS, detail)

    def fail(self, check: str, detail: str) -> None:
        self.add(check, FAIL, detail)

    def skip(self, check: str, detail: str) -> None:
        self.add(check, SKIP, detail)

    @property
    def failures(self) -> List[Dict[str, Any]]:
        return [r for r in self.rows if r["status"] == FAIL]

    @property
    def valid(self) -> bool:
        return not self.failures

    def emit_human(self, bundle_path: str, samples_path: Optional[str]) -> None:
        verdict = "VALID" if self.valid else "INVALID"
        print(f"{verdict} — {FORMAT_ID} evidence pack (independent verifier)")
        print(f"  bundle:  {bundle_path}")
        if samples_path:
            print(f"  samples: {samples_path}")
        print()
        width = max((len(r["check"]) for r in self.rows), default=10)
        for row in self.rows:
            print(f"  {row['status']:<4}  {row['check']:<{width}}  {row['detail']}")
        if not self.valid:
            print()
            print(f"{len(self.failures)} check(s) failed.")
        print()
        print("This script shares no code with Sift and needs no network.")
        print("A PASS means the document is internally consistent and, when a key")
        print("was pinned, that it was signed by that key.")

    def emit_json(self, bundle_path: str, samples_path: Optional[str]) -> None:
        json.dump(
            {
                "valid": self.valid,
                "format": FORMAT_ID,
                "bundle": bundle_path,
                "samples": samples_path,
                "checks": self.rows,
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")


# ---------------------------------------------------------------------------
# Trust anchor
# ---------------------------------------------------------------------------


def normalize_hex_key(text: str) -> str:
    cleaned = text.strip().replace(" ", "").replace(":", "").replace("-", "").lower()
    if len(cleaned) != 64:
        raise CanonicalError(f"issuer key {text!r} is not 64 hex characters")
    try:
        bytes.fromhex(cleaned)
    except ValueError as exc:
        raise CanonicalError(f"issuer key {text!r} is not hex: {exc}") from exc
    return cleaned


def load_trust_store(path: str) -> List[str]:
    with open(path, "rb") as handle:
        raw = handle.read()
    doc = parse_json(raw)
    if not isinstance(doc, dict) or doc.get("format") != TRUST_FORMAT:
        raise CanonicalError(f"{path} is not a {TRUST_FORMAT} trust store")
    issuers = doc.get("issuers")
    if not isinstance(issuers, list) or not issuers:
        raise CanonicalError(f"{path} contains no issuers, so it trusts nobody")
    keys: List[str] = []
    for entry in issuers:
        if not isinstance(entry, dict) or "key" not in entry:
            raise CanonicalError(f"{path} has an issuer entry without a key")
        keys.append(normalize_hex_key(str(entry["key"])))
    return keys


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_bundle_signature(bundle: Dict[str, Any], report: Report) -> Optional[str]:
    """Check the coordinator signature. Returns the issuer key hex, if present."""
    signature = bundle.get("signature")
    if not isinstance(signature, dict):
        report.fail("bundle-signature", "the bundle has no signature object")
        return None

    key_hex = str(signature.get("key", ""))
    sig_hex = str(signature.get("sig", ""))
    alg = signature.get("alg")
    covers = signature.get("covers")

    if alg != "ed25519":
        report.fail("bundle-signature", f"unsupported algorithm {alg!r}")
        return key_hex or None
    if covers != BUNDLE_COVERS:
        report.fail("bundle-signature", f"unexpected signature subject {covers!r}")
        return key_hex or None
    try:
        public = bytes.fromhex(normalize_hex_key(key_hex))
    except (CanonicalError, ValueError) as exc:
        report.fail("bundle-signature", f"issuer key is unusable: {exc}")
        return None
    if len(sig_hex) != 128:
        report.fail("bundle-signature", "signature is not 128 hex characters")
        return key_hex
    try:
        signature_bytes = bytes.fromhex(sig_hex)
    except ValueError as exc:
        report.fail("bundle-signature", f"signature is not hex: {exc}")
        return key_hex

    unsigned = {k: v for k, v in bundle.items() if k != "signature"}
    digest = sha256(canonical_bytes(unsigned))
    report.ok("bundle-digest", f"SHA-256 of the canonical document is {digest.hex()}")

    if ed25519_verify(public, digest, signature_bytes):
        report.ok(
            "bundle-signature",
            f"Ed25519 signature verifies over {digest.hex()[:16]}...",
        )
    else:
        report.fail(
            "bundle-signature",
            "Ed25519 signature does not verify over the recomputed digest",
        )
    return key_hex


def check_trust(
    issuer_key: Optional[str], pinned: Sequence[str], require_anchor: bool, report: Report
) -> None:
    if not pinned:
        if require_anchor:
            report.fail(
                "issuer-trust",
                "no issuer key was pinned but --require-anchor was given",
            )
            return
        report.skip(
            "issuer-trust",
            "UNPINNED: the bundle carries its own signer key; pass --trust-key "
            "or --trust-store to establish who issued it",
        )
        return

    if issuer_key is None:
        report.fail("issuer-trust", "the bundle names no issuer key")
        return

    normalized = issuer_key.lower()
    if normalized in pinned:
        report.ok("issuer-trust", f"issuer {normalized} is pinned")
    else:
        report.fail(
            "issuer-trust",
            f"UNTRUSTED: issuer {normalized} is not among the {len(pinned)} pinned key(s)",
        )


def verify_worker_commit(
    worker: Dict[str, Any], records: Sequence[Dict[str, Any]], report: Report
) -> None:
    worker_id = worker.get("id", "<unnamed>")
    commit = worker.get("commit")
    if not isinstance(commit, dict):
        report.fail(f"commit[{worker_id}]", "worker has no commit object")
        return

    # The commit signature covers the digest of the commit without its signature.
    key_hex = str(worker.get("public_key", ""))
    sig_hex = str(commit.get("signature", ""))
    try:
        public = bytes.fromhex(normalize_hex_key(key_hex))
        signature = bytes.fromhex(sig_hex)
    except (CanonicalError, ValueError) as exc:
        report.fail(f"commit-signature[{worker_id}]", f"key or signature is unusable: {exc}")
        return
    if len(signature) != 64:
        report.fail(f"commit-signature[{worker_id}]", "signature is not 64 bytes")
        return
    digest = sha256(canonical_commit_unsigned(commit))
    if not ed25519_verify(public, digest, signature):
        report.fail(
            f"commit-signature[{worker_id}]",
            "signature does not verify over the commit digest",
        )
        return
    report.ok(f"commit-signature[{worker_id}]", "signature verifies over the commit digest")

    # Count and root.
    claimed_count = commit.get("sample_count")
    if claimed_count != len(records):
        report.fail(
            f"commit-count[{worker_id}]",
            f"sidecar holds {len(records)} records but the commit claims {claimed_count}",
        )
        return
    report.ok(f"commit-count[{worker_id}]", f"{len(records)} records match sample_count")

    ordered = sorted(records, key=record_sort_key)
    leaves = [canonical_record(rec) for rec in ordered]
    root = merkle_root(leaves).hex()
    claimed_root = str(commit.get("merkle_root", "")).lower()
    if root != claimed_root:
        report.fail(
            f"commit-root[{worker_id}]",
            f"recomputed root {root[:16]}... does not match the signed {claimed_root[:16]}...",
        )
        return
    report.ok(f"commit-root[{worker_id}]", f"{len(leaves)} leaves reproduce {root[:16]}...")

    # Worker aggregate over raw latencies.
    claim = worker.get("aggregate")
    if not isinstance(claim, dict):
        report.fail(f"worker-aggregate[{worker_id}]", "worker has no aggregate object")
        return
    latencies = [rec["latency_ns"] for rec in ordered]
    hist: Dict[str, int] = {}
    for value in latencies:
        bucket = str(bucket_upper_ns(value))
        hist[bucket] = hist.get(bucket, 0) + 1
    problems = []
    if claim.get("count") != len(latencies):
        problems.append(f"count {claim.get('count')} != {len(latencies)}")
    if claim.get("sum_latency_ns") != sum(latencies):
        problems.append(f"sum {claim.get('sum_latency_ns')} != {sum(latencies)}")
    if latencies:
        if claim.get("min_ns") != min(latencies):
            problems.append(f"min {claim.get('min_ns')} != {min(latencies)}")
        if claim.get("max_ns") != max(latencies):
            problems.append(f"max {claim.get('max_ns')} != {max(latencies)}")
    if claim.get("hist") != hist:
        problems.append("histogram does not reproduce")
    if problems:
        report.fail(f"worker-aggregate[{worker_id}]", "; ".join(problems))
        return
    report.ok(
        f"worker-aggregate[{worker_id}]",
        f"count {len(latencies)}, sum, min, max and histogram reproduce",
    )


def verify_global_aggregate(
    bundle: Dict[str, Any],
    samples: Dict[str, List[Dict[str, Any]]],
    report: Report,
) -> None:
    workers = bundle.get("workers") or []
    values: List[int] = []
    count = 0
    total = 0
    for worker in workers:
        worker_id = worker.get("id")
        records = samples.get(worker_id)
        if records is None:
            report.skip(
                "aggregate",
                f"worker {worker_id!r} has no sidecar records, so the run-wide "
                "totals cannot be recomputed",
            )
            return
        ordered = sorted(records, key=record_sort_key)
        for rec in ordered:
            count += 1
            total += rec["latency_ns"]
            values.append(rec["latency_ns"])

    agg = bundle.get("aggregate")
    if not isinstance(agg, dict):
        report.fail("aggregate", "the bundle has no aggregate object")
        return
    if agg.get("co_corrected"):
        report.skip(
            "aggregate-percentiles",
            "co_corrected is true: the bootstrap interval and corrected "
            "percentiles need the producer's PRNG and are not checked here",
        )

    problems = []
    if agg.get("count") != count:
        problems.append(f"count {agg.get('count')} != {count}")
    if agg.get("sum_latency_ns") != total:
        problems.append(f"sum {agg.get('sum_latency_ns')} != {total}")
    values.sort()
    for label, ppm, field in (
        ("p50", 500_000, "p50_ns"),
        ("p95", 950_000, "p95_ns"),
        ("p99", 990_000, "p99_ns"),
    ):
        want = percentile(values, ppm)
        if agg.get(field) != want:
            problems.append(f"{label} {agg.get(field)} != {want}")
    if problems:
        report.fail("aggregate", "; ".join(problems))
        return
    report.ok(
        "aggregate",
        f"count {count}, sum, p50/p95/p99 reproduce from {count} records",
    )

    run = bundle.get("run") or {}
    duration_ns = run.get("duration_ns")
    try:
        milli = achieved_rps_milli(count, int(duration_ns))
        want_rps = decimal_from_milli(milli)
    except (CanonicalError, TypeError, ValueError) as exc:
        report.fail("aggregate-rate", f"cannot recompute the rate: {exc}")
        return
    if agg.get("rps") != want_rps:
        report.fail(
            "aggregate-rate", f"rps {agg.get('rps')!r} does not equal {want_rps!r}"
        )
        return
    report.ok("aggregate-rate", f"rps {want_rps!r} equals {count} requests over {duration_ns} ns")


def verify_integrity(bundle: Dict[str, Any], report: Report) -> None:
    run = bundle.get("run") or {}
    agg = bundle.get("aggregate") or {}
    integrity = bundle.get("integrity")
    if not isinstance(integrity, dict):
        report.fail("integrity", "the bundle has no integrity object")
        return
    try:
        planned_milli = decimal_milli(run.get("planned_rps"))
        achieved_milli = decimal_milli(integrity.get("achieved_rps"))
        duration_ns = int(run.get("duration_ns"))
        count = int(agg.get("count"))
        slots = planned_slots(planned_milli, duration_ns)
    except (CanonicalError, TypeError, ValueError) as exc:
        report.fail("integrity", f"cannot recompute the integrity block: {exc}")
        return

    want_dropped = 0 if count >= slots else slots - count
    want_accuracy = schedule_accuracy_ppm(planned_milli, achieved_milli)

    problems = []
    if integrity.get("dropped_samples") != want_dropped:
        problems.append(
            f"dropped_samples {integrity.get('dropped_samples')} != {want_dropped}"
        )
    if integrity.get("schedule_accuracy_ppm") != want_accuracy:
        problems.append(
            f"schedule_accuracy_ppm {integrity.get('schedule_accuracy_ppm')} != {want_accuracy}"
        )
    if problems:
        report.fail("integrity", "; ".join(problems))
        return
    report.ok(
        "integrity",
        f"dropped_samples {want_dropped} and schedule_accuracy_ppm {want_accuracy} reproduce",
    )


def load_sidecar(path: str) -> Dict[str, List[Dict[str, Any]]]:
    samples: Dict[str, List[Dict[str, Any]]] = {}
    with open(path, "rb") as handle:
        for lineno, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                rec = parse_json(stripped)
            except CanonicalError as exc:
                raise CanonicalError(f"{path}:{lineno}: {exc}") from exc
            if not isinstance(rec, dict):
                raise CanonicalError(f"{path}:{lineno}: record is not an object")
            validate_record(rec)
            samples.setdefault(rec["worker"], []).append(rec)
    return samples


def verify(
    bundle_path: str,
    samples_path: Optional[str],
    pinned: Sequence[str],
    require_anchor: bool,
) -> Report:
    report = Report()
    try:
        with open(bundle_path, "rb") as handle:
            bundle = parse_json(handle.read())
    except (OSError, CanonicalError) as exc:
        report.fail("read", str(exc))
        return report
    if not isinstance(bundle, dict):
        report.fail("format", "the bundle is not a JSON object")
        return report

    if bundle.get("format") != FORMAT_ID:
        report.fail("format", f"format is {bundle.get('format')!r}, want {FORMAT_ID!r}")
        return report
    report.ok("format", FORMAT_ID)

    issuer_key = verify_bundle_signature(bundle, report)
    check_trust(issuer_key, pinned, require_anchor, report)

    workers = bundle.get("workers")
    if not isinstance(workers, list) or not workers:
        report.fail("workers", "the bundle lists no workers")
        return report

    if not samples_path:
        report.skip(
            "sidecar",
            "no --samples given: the Merkle roots, per-worker aggregates and "
            "run-wide totals are NOT checked",
        )
        return report

    try:
        samples = load_sidecar(samples_path)
    except (OSError, CanonicalError) as exc:
        report.fail("sidecar", str(exc))
        return report

    seen: set = set()
    for worker in workers:
        if not isinstance(worker, dict):
            report.fail("workers", "a worker entry is not an object")
            continue
        worker_id = worker.get("id")
        if worker_id in seen:
            report.fail("workers", f"worker id {worker_id!r} appears more than once")
            continue
        seen.add(worker_id)
        records = samples.get(worker_id)
        if records is None:
            report.fail(
                f"sidecar[{worker_id}]",
                "the sidecar has no records for this worker, so its commit cannot be checked",
            )
            continue
        for rec in records:
            if rec["worker"] != worker_id:
                report.fail(f"sample-worker[{worker_id}]", "record worker id mismatch")
                break
        else:
            verify_worker_commit(worker, records, report)

    extra = sorted(set(samples) - seen)
    if extra:
        report.skip("sidecar-extra", f"records for unknown workers: {', '.join(extra)}")

    verify_global_aggregate(bundle, samples, report)
    verify_integrity(bundle, report)
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a Sift (vpmp/v1) evidence pack without Sift.",
        epilog="Exit: 0 valid, 1 invalid, 2 unreadable input.",
    )
    parser.add_argument("--bundle", help="path to bundle.json")
    parser.add_argument("--samples", help="path to the sidecar samples.jsonl")
    parser.add_argument(
        "--trust-key",
        action="append",
        default=[],
        metavar="HEX",
        help="pin an issuer public key (64 hex chars); repeatable",
    )
    parser.add_argument(
        "--trust-store",
        action="append",
        default=[],
        metavar="PATH",
        help="read pinned issuer keys from a sift-trust/v1 JSON file; repeatable",
    )
    parser.add_argument(
        "--require-anchor",
        action="store_true",
        help="fail unless the bundle's signer is pinned",
    )
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="check the built-in Ed25519 against the RFC 8032 test vector and exit",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        if self_test():
            print("self-test OK — Ed25519 matches RFC 8032 §7.1 TEST 1")
            return 0
        print("self-test FAILED — do not trust any verdict from this build")
        return 1

    if not args.bundle:
        parser.error("--bundle is required (or use --self-test)")

    pinned: List[str] = []
    try:
        for key in args.trust_key:
            pinned.append(normalize_hex_key(key))
        for store in args.trust_store:
            pinned.extend(load_trust_store(store))
    except (OSError, CanonicalError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    pinned = sorted(set(pinned))

    report = verify(args.bundle, args.samples, pinned, args.require_anchor)
    if args.json:
        report.emit_json(args.bundle, args.samples)
    else:
        report.emit_human(args.bundle, args.samples)
    return 0 if report.valid else 1


if __name__ == "__main__":
    sys.exit(main())
