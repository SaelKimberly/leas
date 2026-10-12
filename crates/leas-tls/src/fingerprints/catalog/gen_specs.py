#!/usr/bin/env python3
"""Raw JA4-string parser + Python mirror of crypto/fingerprint/ja4.rs hashing.

Semantics (FoxIO JA4):

- A-part `{proto}13d{cipher_count:02}{ext_count:02}{alpn}`: counts exclude
  GREASE, include SNI (0000)/ALPN (0010)/padding (0015), clamped at 99.
- hash1: sha256[:12] of sorted non-GREASE cipher ids (lowercase 4-hex,
  comma-joined).
- hash2: sha256[:12] of sorted filtered extension ids + `_` + sig-alg ids
  in hello order (sig algs NOT GREASE-filtered, mirroring ja4.rs hash2);
  empty sig algs omit the `_` segment entirely.
- GREASE: `(v & 0x0f0f) == 0x0a0a`.

hash2 extension exclusions -- TWO rules exist in the wild:

- ja4db export (this catalog's data source, original FoxIO tooling):
  excludes SNI (0000) and ALPN (0010); padding (0015) stays in the hash.
  This is `ja4_hash()`'s DEFAULT because recomputed keys must join
  thirdparty/ja4db-export/csv/ja4_fingerprint.csv.
- crypto/fingerprint/ja4.rs (peet.ws semantics): additionally excludes
  padding (0015). Pass `exclude_padding=True` to reproduce the Rust file
  byte-for-byte (pinned by the tls.peet.ws known-vector selftest below).

Raw-string format (csv/ja4_fingerprint_string.csv):
    <ja4_a>[_<ciphers>[_<exts>[_<sigalgs>]]]
segments are comma-joined lowercase hex ids. Only `t13d` A-parts are
accepted (this crate's profiles all offer TLS 1.3); other prefixes in the
export (t12d/t13i/t12i/q13d) yield None.

Generator usage:

- `--manifest` — rebuild `specs_manifest.json` from the ja4db export
  (attribution/join/dedup; stats printed).
- `--emit` — render `profiles/generated/*.rs` from the manifest
  (byte-deterministic; `--selftest` verifies committed == fresh render).
  **Run `--manifest` first and commit both**: the manifest caches the
  synthesized wire bodies, so `--emit` alone re-renders the OLD bodies and
  silently reverts a body fix made here (it did exactly that on 2026-09-17).
- `--selftest` — parse/hash round-trip + emitter determinism checks.

Output: a 69-entry kept JA4-faithful roster (the deterministic
`select_roster` subset of the 1825-entry manifest: top-3 distinct JA4
clusters per browser/os/device triple, family-range filtered, PSK
excluded, 2 hand-upgraded slots removed). Only `kept` manifest entries
are emitted; `specs_manifest.json` carries the `kept` flags.
Fidelity contract: each emitted spec's built ClientHello must reproduce
its registered source JA4 — enforced offline by
`tests/generated_ja4_gate.rs` (69/69) and confirmed live by the
grader `--roster` sweep against tls.peet.ws (`docs/tls-fingerprint-roster.md`).

Self-test: `python3 gen_specs.py --selftest`

Corpus quirks (investigated; see UNMATCHED breakdown printed by the
self-test). The string export and the hash export are DIFFERENT
observation sets -- a 100% set-level round-trip is impossible by
construction, not by a hashing bug:

- 46 of 998 parsed t13d strings have an A-part entirely absent from the
  hash CSV; 9 more share the A-part but a different cipher list.
- 45 more share A-part AND cipher hash but the hash CSV holds other hello
  variants' hash2 values. Proven unrecoverable: exhaustive search over
  all extension subsets x sig-alg orders/separators for the largest
  missing family (t13d09xxht/f91f431d341e) matches none of its three
  target h2 values.
- 5 hashed keys are corrupt (binary garbage instead of hex digests).
- Some rows have an empty cipher segment (`t13dNNNNNN__ext,...`);
  treated as zero ciphers.

Best achievable rates (keep-padding rule): 898/998 = 90.0% of unique
parsed strings; 264440/267622 = 98.81% observation-weighted. The
self-test asserts those floors.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass

# --- parsing -----------------------------------------------------------------

JA4_A_RE = re.compile(r"^t13d\d{2}(?:99|\d{2})(?:h2|h1|00|[a-z0-9]{2})$")


@dataclass
class RawComponents:
    ja4_a: str
    ciphers: list[int]
    exts_sorted: list[int]
    sigalgs_ordered: list[int]
    alpn_first: str


def parse_raw(s: str) -> RawComponents | None:
    """Parse a raw fingerprint string; None if not a TLS 1.3 client shape."""
    parts = s.split("_")
    if len(parts) < 2:
        return None
    ja4_a = parts[0]
    if not s.startswith("t13d") or not JA4_A_RE.match(ja4_a):
        return None
    try:
        ciphers = [int(x, 16) for x in parts[1].split(",") if x]
        exts = [int(x, 16) for x in parts[2].split(",") if x] if len(parts) > 2 else []
        sigalgs = (
            [int(x, 16) for x in parts[3].split(",") if x] if len(parts) > 3 else []
        )
    except ValueError:
        return None
    return RawComponents(ja4_a, ciphers, exts, sigalgs, ja4_a[-2:])


# --- hashing (mirror of ja4.rs) -----------------------------------------------


def is_grease(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A


SNI, ALPN, PADDING = 0x0000, 0x0010, 0x0015


def format_ja4_a(cipher_count: int, ext_count: int, alpn: str = "00") -> str:
    """A-part with FoxIO 99-clamp (ja4.rs `ja4_a`)."""
    return f"t13d{min(cipher_count, 99):02}{min(ext_count, 99):02}{alpn}"


def _sha12(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()[:12]


def ja4_hash(rc: RawComponents, *, exclude_padding: bool = False) -> str:
    """Full FoxIO JA4: `{ja4_a}_{hash1}_{hash2}`.

    Default excludes {SNI, ALPN} from hash2 (ja4db/original-FoxIO rule).
    `exclude_padding=True` adds 0x0015, reproducing
    crypto/fingerprint/ja4.rs byte-for-byte.
    """
    excluded = {SNI, ALPN, PADDING} if exclude_padding else {SNI, ALPN}
    cs = sorted(f"{c:04x}" for c in rc.ciphers if not is_grease(c))
    es = sorted(
        f"{e:04x}" for e in rc.exts_sorted if not is_grease(e) and e not in excluded
    )
    # ja4.rs appends sig algs in hello order WITHOUT GREASE filtering.
    ss = ",".join(f"{a:04x}" for a in rc.sigalgs_ordered)
    payload = ",".join(es)
    if rc.sigalgs_ordered:
        payload += "_" + ss
    return f"{rc.ja4_a}_{_sha12(','.join(cs))}_{_sha12(payload)}"


def load_raw_rows(path: str) -> dict[str, RawComponents]:
    """Parse every row of the raw-string CSV, keyed by recomputed JA4."""
    out: dict[str, RawComponents] = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            s = (row.get("ja4_fingerprint_string") or "").strip()
            if not s:
                continue
            rc = parse_raw(s)
            if rc is not None:
                out[ja4_hash(rc)] = rc
    return out


# --- attribution (verbatim from gen.py) ---------------------------------------

from ua_parser import parse  # noqa: E402

BROWSER_FAMILIES = {
    "Edge": "edge", "Edge Mobile": "edge",
    "Samsung Internet": "samsung",
    "Mobile Safari": "safari",
    "Mobile Safari UI/WKWebView": "safari",
    "Safari": "safari",
    "Firefox": "firefox",
    "Opera": "opera",
    "OPR": "opera",
    "Brave": "brave",
}
OS_FAMILIES = {"mac os x": "macos", "windows": "windows", "linux": "linux",
               "android": "android", "ios": "ios"}
# Desktop Linux shows up in ua-parser as the distribution name.
LINUX_DISTROS = {"ubuntu", "debian", "fedora", "centos", "kubuntu", "gentoo",
                 "mint", "red hat", "suse", "opensuse", "arch"}
APPLICATION_RE = re.compile(r"^(Chrome|Firefox|Safari|Edge|Brave|Opera|Samsung Internet)"
                            r"(?: ([0-9]+)(?:\.[0-9]+)?)?\s*$")


def map_browser(family):
    if family is None:
        return None
    if family in BROWSER_FAMILIES:
        return BROWSER_FAMILIES[family]
    # Chrome + Mobile/CriOS/Webview variants; Firefox and Opera families too.
    if family.startswith("Chrome") or "CriOS" in family:
        return "chrome"
    if family.startswith("Firefox"):
        return "firefox"
    if family.startswith("Opera") or family == "OPR":
        return "opera"
    return None


def map_os(family):
    """family may be None or an unrecognized name -> drop the row."""
    if not family:
        return None
    key = family.lower()
    if key in OS_FAMILIES:
        return OS_FAMILIES[key]
    # ua-parser reports modern Windows as e.g. 'Windows 10'.
    if key.startswith("windows"):
        return "windows"
    if key in LINUX_DISTROS:
        return "linux"
    return None


def derive_device(ua, device_family):
    dev = device_family or ""
    if "iPhone" in dev or "iPhone" in ua or "Mobile" in dev:
        return "phone"
    if "iPad" in dev or "Tablet" in dev or "iPad" in ua:
        return "tablet"
    if "Android" in ua and "Mobile" not in ua:
        return "tablet"
    return "desktop"


def parse_ua(ua):
    """UA string -> (browser, browser_major, os, os_major, device); None when
    unidentifiable. Majors are 0 when unknown."""
    ua = ua.strip()
    if not ua:
        return None
    r = parse(ua)
    if r.user_agent is None or r.user_agent.family is None:
        return None
    browser = map_browser(r.user_agent.family)
    if browser is None:
        return None
    if r.os is None or r.os.family is None:
        return None
    os_name = map_os(r.os.family)
    if os_name is None:
        return None

    def major(v):
        return int(v) if v and v.isdigit() else 0

    return (browser, major(r.user_agent.major), os_name,
            major(r.os.major), derive_device(ua, r.device.family if r.device else ""))


def parse_application(application):
    """Direct application field, e.g. 'Chrome 94.0'; fallback for UA-less rows."""
    m = APPLICATION_RE.match(application.strip())
    if not m:
        return None
    name = {"Samsung Internet": "samsung"}.get(m.group(1), m.group(1).lower())
    return name, int(m.group(2)) if m.group(2) else 0, "", 0, ""


# --- family templates: wire synthesis -----------------------------------------
#
# Ground truth: the canonical wire shapes below, distilled from the
# pre-reduction hand-written specs (deleted in the roster reduction; see
# profiles/hand_selected.rs for the surviving 2 and git history for the
# originals). Each template records a family's canonical wire shape;
# per-entry synthesis
# filters the canonical sequences down to the observed id sets:
#   - ciphers: canonical order filtered to the row's set, leftovers ascending;
#   - extensions: canonical order filtered to the row's ids, unknown ids
#     appended ascending as `Raw {ty, data: []}` (entry flagged low-fidelity);
#   - signature algorithms: copied verbatim from the observation when the raw
#     string carried them, otherwise the family canonical list (low-fidelity);
#   - supported_versions: always [0x0304, 0x0303] (engine is TLS-1.3-only);
#   - key_share: family canonical groups; the X25519MLKEM768 hybrid entry
#     appears only where the family's canonical group list advertises 4588.
# The ja4db string export omits the SNI (0000) and ALPN (0010) extension ids
# and never carries GREASE values, so ServerName is always added and Alpn
# whenever the A-part letter is not `00`; a GREASE slot is emitted (at the
# family's canonical position) only if an observed id is GREASE-shaped.

GREASE_CIPHER_PLACEHOLDER = 0xCACA  # profiles' GREASE cipher slot


def _template(ciphers, ext_order, groups, key_share, sig_algos,
              compress_cert=(), session_id="random32"):
    return {
        "ciphers": ciphers, "ext_order": ext_order, "groups": groups,
        "key_share": key_share, "sig_algos": sig_algos,
        "compress_cert": list(compress_cert), "session_id": session_id,
    }


_CHROME_CIPHERS = [
    0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
    0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
]
_CHROME_SIG = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]
# Extension type constants (spec/mod.rs construction sites).
EMS = 0x0017           # extended_master_secret -> Raw (no dedicated variant)
PRE_SHARED_KEY = 0x0029  # pre_shared_key -> Raw; the corpus carries it from
                         # resumed captures, the engine has no ticket store
RENEG = 0xFF01
GROUPS = 0x000A
ECPF = 0x000B
TICKET = 0x0023
SIGALGS = 0x000D
SCT = 0x0012
SIGALGS_CERT = 0x0032   # signature_algorithms_cert; body synthesized from
                        # the sigalgs list (RFC 8446 §4.2.3 default) — the
                        # string export carries ids only, and an EMPTY body
                        # is malformed (rejected by real servers; see
                        # docs/tls-fingerprint-roster.md Task 8 finding)
KEYSHARE = 0x0033
PSK_MODES = 0x002D
VERSIONS = 0x002B
COMPRESS_CERT = 0x001B
ALPS_OLD = 0x4469      # ApplicationSettings draft form
ALPS_NEW = 0x44CD      # ALPS u8-length form (engine emits it via Raw)
ECH_GREASE = 0xFE0D    # encrypted_client_hello; the engine emits a GREASE
                       # ECHClientHello whose body is drawn per connection
                       # (spec/mod.rs `EchGrease`), so the emitter only has to
                       # name the variant — an empty Raw body here was
                       # unparseable (BoringSSL: alert 2 50, the 2026-09-17
                       # run's firefox/safari/ios failures)
DELEGATED_CREDENTIALS = 0x0022  # delegated_credentials -> Raw; body is a
                                # u16-prefixed SignatureScheme list (RFC 9345
                                # §3), synthesized from the sigalgs list
                                # (mirrors SIGALGS_CERT) — empty is malformed
# Ids whose body MAY legally be empty (RFC 8446 §4.2 / RFC 7366): the corpus
# string export carries ids only, so a bodyless `Raw` is CORRECT for these and
# an approximation anywhere else (it flags the entry low-fidelity).
EMPTY_BODY_OK = {
    0x0016,  # encrypt_then_mac
    0x0017,  # extended_master_secret
    0x0023,  # session_ticket
    0x0031,  # post_handshake_auth
}
# Ids whose body may NOT be empty: each has a length-prefixed vector (or more)
# as its whole body, so a bodyless emission is unparseable and a strict peer
# answers `decode_error` (BoringSSL — Cloudflare, Google: alert 2 50, the
# 2026-09-17 run). Every one is either synthesized here (SIGALGS_CERT,
# DELEGATED_CREDENTIALS), named to its own engine variant (ECH), or simply must
# not appear bodyless (pre_shared_key, whose body needs a ticket our client
# does not have). Unknown ids (0x3374-style drafts) are NOT here: a peer must
# ignore an extension it does not know, so an opaque empty body is legal.
EMPTY_BODY_ILLEGAL = {
    COMPRESS_CERT,            # 0x001b: algorithms<2..2^8-2>
    DELEGATED_CREDENTIALS,    # 0x0022: SignatureScheme ...<2..2^16-2>
    PRE_SHARED_KEY,           # 0x0029: OfferedPsks (needs a ticket)
    SIGALGS_CERT,             # 0x0032: SignatureScheme ...<2..2^16-2>
    ECH_GREASE,               # 0xfe0d: ECHClientHello, >= 38 bytes
}
RECORD_SIZE_LIMIT = 0x001C
STATUS_REQ = 0x0005

# chrome.rs order: GREASE first, sig algs ahead of SCT, ALPS/ECH near end,
# padding last. `"grease"` marks the standalone-GREASE slot position.
_CHROME_EXT_ORDER = [
    "grease", SNI, EMS, RENEG, GROUPS, ECPF, TICKET, ALPN, STATUS_REQ,
    SIGALGS, SCT, KEYSHARE, PSK_MODES, VERSIONS, COMPRESS_CERT, ALPS_OLD,
    ALPS_NEW, ECH_GREASE, PADDING,
]
_CHROME_ANDROID_EXT_ORDER = [
    "grease", SNI, EMS, RENEG, GROUPS, ECPF, TICKET, ALPN, STATUS_REQ,
    SCT, KEYSHARE, PSK_MODES, VERSIONS, SIGALGS,
]
_FIREFOX_EXT_ORDER = [
    SNI, EMS, RENEG, GROUPS, ECPF, TICKET, ALPN, STATUS_REQ, KEYSHARE,
    VERSIONS, SIGALGS, PSK_MODES, COMPRESS_CERT, PADDING,
]
_SAFARI_EXT_ORDER = [
    SNI, EMS, RENEG, GROUPS, ECPF, ALPN, STATUS_REQ, SCT, KEYSHARE,
    VERSIONS, PSK_MODES, SIGALGS,
]
_SAFARI_IOS_EXT_ORDER = [
    SNI, EMS, RENEG, GROUPS, ALPN, STATUS_REQ, KEYSHARE, VERSIONS,
    PSK_MODES, SIGALGS,
]
_OKHTTP_EXT_ORDER = [SNI, EMS, RENEG, GROUPS, ECPF, STATUS_REQ, SIGALGS]

FAMILY_TEMPLATES = {
    # chrome.rs: modern desktop Chromium (incl. Edge/Opera/Brave).
    "chrome_desktop": _template(
        _CHROME_CIPHERS, _CHROME_EXT_ORDER,
        [0x11EC, 0x001D, 0x0017, 0x0018],
        ["X25519Mlkem768", "X25519"], _CHROME_SIG, [0x0002, 0x0003]),
    # chrome_android.rs: no ALPS/compress_certificate/padding; SHA-1 sig.
    "chrome_android": _template(
        _CHROME_CIPHERS, _CHROME_ANDROID_EXT_ORDER,
        [0x001D, 0x0017, 0x0018], ["X25519"], _CHROME_SIG + [0x0201]),
    # firefox.rs: no GREASE, distinct ordering, zlib-only compress_certificate.
    "firefox": _template(
        [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9,
         0xCCA8, 0xC013, 0xC014, 0x002F, 0x0035],
        _FIREFOX_EXT_ORDER,
        [0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101],
        ["X25519"],
        [0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0804, 0x0805, 0x0806,
         0x0401, 0x0501, 0x0601, 0x0201, 0x0203],
        [0x0002]),
    # safari.rs: EMPTY session id, no session_ticket/compress_certificate.
    "safari": _template(
        [0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xC030, 0xC02F, 0xCCA9,
         0xCCA8, 0xC024, 0xC023, 0xC028, 0xC027, 0xC00A, 0xC009, 0xC014,
         0xC013, 0x009D, 0x009C, 0x003D, 0x003C, 0x0035, 0x002F, 0x000A],
        _SAFARI_EXT_ORDER, [0x001D, 0x0017, 0x0018, 0x0019],
        ["X25519"],
        [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501,
         0x0601, 0x0201, 0x0203],
        session_id="empty"),
    # safari_ios.rs: additionally no ec_point_formats/SCT/3DES/secp521r1.
    "safari_ios": _template(
        [0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xC030, 0xC02F, 0xCCA9,
         0xCCA8, 0xC024, 0xC023, 0xC028, 0xC027, 0xC00A, 0xC009, 0xC014,
         0xC013, 0x009D, 0x009C, 0x003D, 0x003C, 0x0035, 0x002F],
        _SAFARI_IOS_EXT_ORDER, [0x001D, 0x0017, 0x0018], ["X25519"],
        [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501,
         0x0601, 0x0201, 0x0203],
        session_id="empty"),
    # okhttp.rs: Chromium-derived minimal preset.
    "okhttp": _template(
        [0xC02B, 0xC02C, 0xCCA9, 0xC02F, 0xC030, 0xCCA8, 0xC013, 0xC014,
         0x009C, 0x009D, 0x002F, 0x0035],
        _OKHTTP_EXT_ORDER, [0x001D, 0x0017, 0x0018], ["X25519"], _CHROME_SIG),
}

# Fallback (`ascending`) template: minimal standard contents, everything in
# ascending id order. Used only when no family template applies.
_FALLBACK = _template(
    [], [], [0x001D, 0x0017, 0x0018], ["X25519"], _CHROME_SIG, [0x0002])



def template_for(entry):
    """Pick the family template. OS decides before browser where WebKit
    reality dictates shape: everything on iOS is Safari-shaped (WKWebView),
    Firefox keeps its own shape on Android (never trust `device`, which
    mislabels Android phones as desktop)."""
    browser, os_name = entry["family"], entry["os"]
    if os_name == "ios":
        return "safari_ios"
    if browser == "firefox":
        return "firefox"
    if os_name == "android" and browser != "safari":
        return "chrome_android"
    if browser == "safari":
        return "safari"
    if browser in ("chrome", "edge", "opera", "brave", "samsung"):
        return "chrome_desktop"
    return None


def _alpn_protocols(letter):
    """A-part ALPN letter -> offered protocol list."""
    if letter == "h2":
        return ["h2", "http/1.1"]
    if letter == "00":
        return []
    return ["http/1.1"]


def _alps_new_body(protocols):
    """uTLS new-codepoint ALPS body: u16 total len, then u8 len + bytes
    per protocol (chrome.rs `Raw { ty: 0x446D, .. }` shape)."""
    entries = [bytes([len(p)]) + p.encode() for p in protocols]
    body = b"".join(entries)
    return list(len(body).to_bytes(2, "big")) + list(body)


def build_extension(ty, tmpl, protocols, sig_algos):
    """One extension id -> its `{ty, kind, args}` manifest object."""
    if ty == SNI:
        return {"ty": ty, "kind": "ServerName"}
    if ty == STATUS_REQ:
        return {"ty": ty, "kind": "StatusRequest"}
    if ty == GROUPS:
        return {"ty": ty, "kind": "SupportedGroups",
                "args": [list(tmpl["groups"])]}
    if ty == ECPF:
        return {"ty": ty, "kind": "EcPointFormats"}
    if ty == SIGALGS:
        return {"ty": ty, "kind": "SignatureAlgorithms", "args": [sig_algos]}
    if ty == ALPN:
        return {"ty": ty, "kind": "Alpn", "args": [protocols]}
    if ty == PADDING:
        return {"ty": ty, "kind": "Padding"}
    if ty == TICKET:
        return {"ty": ty, "kind": "SessionTicket"}
    if ty == KEYSHARE:
        return {"ty": ty, "kind": "KeyShare", "args": [list(tmpl["key_share"])]}
    if ty == VERSIONS:
        return {"ty": ty, "kind": "SupportedVersions",
                "args": [[0x0304, 0x0303]]}
    if ty == PSK_MODES:
        return {"ty": ty, "kind": "PskKeyExchangeModes"}
    if ty == SCT:
        return {"ty": ty, "kind": "SignedCertificateTimestamp"}
    if ty == RENEG:
        return {"ty": ty, "kind": "RenegotiationInfo"}
    if ty == COMPRESS_CERT:
        # RFC 8879 §4: `algorithms<2..2^8-2>` — at least one algorithm, so a
        # template without one must still offer what the engine can
        # decompress (brotli, decision 17) rather than frame a 0-byte body
        # (BoringSSL: alert 2 50; the safari/safari_ios rows).
        algos = list(tmpl["compress_cert"]) or [0x0002]
        return {"ty": ty, "kind": "CompressCertificate", "args": [algos]}
    if ty == RECORD_SIZE_LIMIT:
        return {"ty": ty, "kind": "RecordSizeLimit", "args": [16385]}
    if ty == ALPS_OLD:
        return {"ty": ty, "kind": "ApplicationSettings", "args": [protocols]}
    if ty == ALPS_NEW:
        return {"ty": ty, "kind": "Raw", "args": [_alps_new_body(protocols)]}
    if ty == ECH_GREASE:
        # The engine draws the whole outer ECHClientHello per connection
        # (config_id, enc, payload) — a constant body would give every
        # connection of an identity identical bytes.
        return {"ty": ty, "kind": "EchGrease"}
    if ty == DELEGATED_CREDENTIALS:
        # RFC 9345 §3: `SignatureScheme ...<2..2^16-2>`. Same reasoning as
        # signature_algorithms_cert below: the corpus carries the id but no
        # body, and an empty one is malformed (the firefox/safari rows).
        payload = b"".join(a.to_bytes(2, "big") for a in sig_algos)
        return {"ty": ty, "kind": "Raw",
                "args": [list(len(payload).to_bytes(2, "big")) + list(payload)]}
    if ty == SIGALGS_CERT:
        # signature_algorithms_cert: u16 length + sig-alg ids. The corpus
        # string export carries the id but no body; RFC 8446 §4.2.3 makes
        # the extension default to signature_algorithms, so mirror that
        # list. An EMPTY body is malformed and real servers reject the
        # hello (Task 8 live-sweep finding). JA4-invisible (body only).
        payload = b"".join(a.to_bytes(2, "big") for a in sig_algos)
        return {"ty": ty, "kind": "Raw",
                "args": [list(len(payload).to_bytes(2, "big")) + list(payload)]}
    if ty == EMS:  # extended_master_secret
        return {"ty": ty, "kind": "Raw", "args": [[]]}
    # Anything else falls through with no body. That is an approximation the
    # manifest must be able to REPRESENT (the corpus carries ids like
    # pre_shared_key, whose body needs a ticket; `select_roster` drops those
    # rows), but it may never be EMITTED: `_render_extension` refuses it.
    return {"ty": ty, "kind": "Raw", "args": [[]]}


def synthesize_wire(entry):
    """`(wire, template_name, low_fidelity)` for one manifest entry."""
    rc = entry["raw"]
    tname = template_for(entry)
    tmpl = FAMILY_TEMPLATES.get(tname) if tname else None
    if tmpl is None:
        tname, tmpl = "ascending", _FALLBACK

    # Ciphers: canonical order filtered to the row's multiset (some corpus
    # rows carry a duplicated suite id), leftovers ascending.
    grease_ciphers = [c for c in rc.ciphers if is_grease(c)]
    row_counts = Counter(c for c in rc.ciphers if not is_grease(c))
    ordered: list[int] = []
    for c in tmpl["ciphers"]:
        if row_counts.get(c, 0):
            ordered.append(c)
            row_counts[c] -= 1
    cipher_order = ([GREASE_CIPHER_PLACEHOLDER] * bool(grease_ciphers) +
                    ordered + sorted(row_counts.elements()))
    # Extensions. The raw-string export omits SNI/ALPN ids; reconstruct the
    # real offered set before filtering against the canonical order.
    protocols = _alpn_protocols(rc.alpn_first)
    offered = set(rc.exts_sorted) | {SNI}
    if protocols:
        offered.add(ALPN)
    grease_ids = {t for t in offered if is_grease(t)}
    offered -= grease_ids
    sig_algos = list(rc.sigalgs_ordered) or list(tmpl["sig_algos"])
    low_fidelity = not rc.sigalgs_ordered

    extensions = []
    placed = set()
    for slot in tmpl["ext_order"]:
        if slot == "grease":
            if grease_ids:
                extensions.append({"kind": "Grease"})
            continue
        if slot in offered:
            ext = build_extension(slot, tmpl, protocols, sig_algos)
            extensions.append(ext)
            placed.add(slot)
            # An empty body outside EMPTY_BODY_OK is a wire approximation
            # even when it comes from the canonical order (ECH used to land
            # here; it now names its own variant).
            if ext["kind"] == "Raw" and not ext["args"][0] and (
                    slot not in EMPTY_BODY_OK):
                low_fidelity = True
    for ty in sorted(offered - placed):  # ids outside the canonical order
        ext = build_extension(ty, tmpl, protocols, sig_algos)
        extensions.append(ext)
        # A Raw form with a real body is deliberate (new-codepoint ALPS, the
        # synthesized signature_algorithms_cert / delegated_credentials
        # lists); an empty body outside EMPTY_BODY_OK is an approximation.
        if ext["kind"] == "Raw" and not ext["args"][0] and (
                ty not in EMPTY_BODY_OK):
            low_fidelity = True

    wire = {
        "cipher_order": cipher_order,
        "extensions": extensions,
        "session_id": tmpl["session_id"],
        "compression": [0],
    }
    return wire, tname, low_fidelity


def verify_wire(entry):
    """Reconstruct the JA4 inputs from a synthesized `wire` block and check
    them against the recorded fingerprint. Returns `(a_part_ok, full_ok)`
    where `full_ok` is None when the reconstruction cannot be expected to
    reproduce hash2 (row carried no signature-algorithm segment)."""
    rc, wire = entry["raw"], entry["wire"]
    ciphers = [c for c in wire["cipher_order"] if not is_grease(c)]
    ext_tys = [x["ty"] for x in wire["extensions"]
               if x.get("ty") is not None and not is_grease(x["ty"])]
    sig = next((a for x in wire["extensions"]
                if x["kind"] == "SignatureAlgorithms" for a in x["args"]), [])
    letter = "h2" if rc.alpn_first == "h2" else \
        ("00" if rc.alpn_first == "00" else "ht")
    a_ok = format_ja4_a(len(ciphers), len(ext_tys), letter) == rc.ja4_a
    if not entry["raw"].sigalgs_ordered:
        return a_ok, None
    recon = RawComponents(rc.ja4_a, ciphers,
                          sorted(set(ext_tys) - {SNI, ALPN}), sig, letter)
    return a_ok, ja4_hash(recon) == entry["ja4"]


# --- manifest build ------------------------------------------------------------

MANIFEST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "specs_manifest.json")


def _hexlist(ids):
    return ",".join(f"{v:04x}" for v in ids)


def build_manifest(csv_dir: str) -> dict:
    """Attributed, joined, deduplicated fingerprint manifest.

    Joins the raw-string export to the label export by recomputed JA4,
    attributes each joined fingerprint to a browser/OS/device identity,
    merges identical (ja4, identity) rows and resolves same-identity
    collisions across different JA4s deterministically.
    """
    # Raw side: recomputed JA4 -> (components, observation_count).
    raw: dict[str, tuple[RawComponents, int]] = {}
    rows_in = dropped_t12 = dropped_no_ua = 0
    with open(os.path.join(csv_dir, "ja4_fingerprint_string.csv"),
              newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows_in += 1
            s = (row.get("ja4_fingerprint_string") or "").strip()
            if not s.startswith("t13d"):
                continue  # non-TLS1.3 strings are out of scope entirely
            rc = parse_raw(s)
            if rc is None:
                continue
            try:
                n = int(row.get("observation_count") or 1)
            except ValueError:
                n = 1
            k = ja4_hash(rc)
            prev = raw.get(k)
            raw[k] = (rc, n + prev[1] if prev else n)

    # Label side: attribute + join.
    entries: dict[tuple, dict] = {}  # (ja4, identity) -> entry
    with open(os.path.join(csv_dir, "ja4_fingerprint.csv"),
              newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows_in += 1
            ja4 = (row.get("ja4_fingerprint") or "").strip()
            if not ja4.startswith("t13d"):
                dropped_t12 += 1
                continue
            ua_field = (row.get("user_agent_string") or "").strip()
            parsed = parse_ua(ua_field) if ua_field else \
                parse_application(row.get("application") or "")
            if parsed is None or not parsed[2] or not parsed[1] or not parsed[3]:
                # unattributable: no UA/OS evidence, or unknown browser/OS major
                dropped_no_ua += 1
                continue
            browser, bmaj, os_name, omaj, device = parsed
            try:
                n = int(row.get("observation_count") or 1)
            except ValueError:
                n = 1
            hit = raw.get(ja4)
            if hit is None:
                continue  # no raw components on the string side; cannot join
            rc, raw_n = hit
            verified = (row.get("verified") or "").strip() == "true"
            ident = (browser, bmaj, os_name, omaj, device)
            key = (ja4, ident)
            e = entries.get(key)
            if e is None:
                entries[key] = {
                    "name": None, "browser": browser, "browser_major": bmaj,
                    "os": os_name, "os_major": omaj, "device": device,
                    "ja4": ja4, "raw": rc, "family": browser,
                    "observation_count": n + raw_n, "verified": verified,
                    "fallback": False,
                }
            else:
                e["observation_count"] += n
                e["verified"] = e["verified"] or verified

    # Collision resolution: one winner per identity across differing JA4s.
    by_ident: dict[tuple, list[dict]] = {}
    for e in entries.values():
        by_ident.setdefault((e["browser"], e["browser_major"], e["os"],
                             e["os_major"], e["device"]), []).append(e)
    winners: list[dict] = []
    collisions_dropped = 0
    for group in by_ident.values():
        group.sort(key=lambda e: (-e["observation_count"], not e["verified"],
                                  e["ja4"]))
        winners.append(group[0])
        collisions_dropped += len(group) - 1

    # Names: {browser}_{major}[_{os}_{device}], snake_case; `_2`, `_3` ...
    # disambiguate entries sharing a base name (uniqueness asserted below).
    winners.sort(key=lambda e: e["ja4"])
    used: dict[str, int] = {}
    for e in winners:
        base = f"{e['browser']}_{e['browser_major']}"
        if e["os"]:
            base += f"_{e['os']}_{e['device']}"
        seen = used.get(base, 0)
        used[base] = seen + 1
        e["name"] = base if seen == 0 else f"{base}_{seen + 1}"

    # Wire synthesis: per-entry family template + low-fidelity flag.
    for e in winners:
        wire, tname, low_fi = synthesize_wire(e)
        e["wire"] = wire
        e["wire_template"] = tname
        e["low_fidelity"] = low_fi
        e["fallback"] = tname == "ascending"

    stats = {
        "rows_in": rows_in,
        "kept": len(winners),
        "dropped_no_ua": dropped_no_ua,
        "dropped_t12": dropped_t12,
        "collisions_dropped": collisions_dropped,
    }
    return {"entries": winners, "stats": stats}


def _manifest_entry_json(e: dict) -> dict:
    rc = e["raw"]
    return {
        "name": e["name"], "browser": e["browser"],
        "browser_major": e["browser_major"], "os": e["os"],
        "os_major": e["os_major"], "device": e["device"], "ja4": e["ja4"],
        "raw": {
            "ja4_a": rc.ja4_a, "ciphers": _hexlist(rc.ciphers),
            "exts_sorted": _hexlist(rc.exts_sorted),
            "sigalgs_ordered": _hexlist(rc.sigalgs_ordered),
            "alpn_first": rc.alpn_first,
        },
        "family": e["family"], "observation_count": e["observation_count"],
        "verified": e["verified"], "fallback": e["fallback"],
        "wire": e["wire"], "low_fidelity": e["low_fidelity"],
    }


def _write_manifest(csv_dir: str) -> int:
    """Build the manifest, mark the kept-roster subset and write
    specs_manifest.json (the `--emit` input). Every entry carries
    `"kept": name in select_roster(...)`; the emitter renders only those."""
    man = build_manifest(csv_dir)
    kept = select_roster(man["entries"])
    entries = []
    for e in man["entries"]:
        j = _manifest_entry_json(e)
        j["kept"] = j["name"] in kept
        entries.append(j)
    with open(MANIFEST_PATH, "w", encoding="utf-8") as fh:
        json.dump({"entries": entries, "stats": man["stats"]}, fh,
                  indent=1)
        fh.write("\n")
    n_kept = sum(1 for e in entries if e["kept"])
    print(f"wrote {len(entries)} entries to {MANIFEST_PATH} "
          f"({n_kept} kept)")
    return 0


# --- kept-roster selection -----------------------------------------------------
#
# Deterministic reduction of the generated roster: top-3 observed distinct
# JA4 clusters per (browser, os, device) triple, most-modern major rep,
# family range filtered, PSK excluded; the top-ranked slot whose A+hash2
# matches a hand profile's assigned triple is removed from the generated
# keep (the hand profile replaces it), one slot per hand profile. Later
# tasks consume the emitted kept `name`s.

# Family sanity ranges (spec §1). Keyed by manifest `browser`.
FAMILY_RANGES = {
    'chrome': (80, 155), 'edge': (80, 155), 'opera': (80, 155),
    'brave': (80, 155), 'firefox': (80, 155), 'samsung': (10, 40),
    'safari': (3, 30),
}
# Hand profiles that survive as wire-exact upgrades: assigned concrete
# triple -> (A-part, hash2). Their JA4s are absent from the corpus, so they
# can never win by count; they replace the top-ranked cluster slot whose
# A-part+hash2 they share. (Source: tests/fingerprints.rs captured JA4s.)
HAND_UPGRADES = {
    'chrome_130': (('chrome', 'windows', 'desktop'), 't13d1516h2', '8daaf6152771'),
    'edge_106':   (('edge', 'windows', 'desktop'),  't13d1516h2', '8daaf6152771'),
}


def is_psk(e):
    return any(x.get('ty') == 0x0029 for x in e['wire'].get('extensions', []))


def select_roster(entries):
    """Top-3 observed distinct JA4 clusters per triple, most-modern major
    rep, family range filtered, PSK excluded; the top-ranked slot matching
    a hand profile's A+hash2 is removed from the generated keep (the hand
    profile replaces it), one slot per hand profile. Returns the set of
    kept generated `name`s."""
    from collections import defaultdict
    triples = defaultdict(list)
    for e in entries:
        triples[(e['browser'], e['os'], e['device'])].append(e)
    kept = set()
    used_upgrades: set[str] = set()
    for t, es in triples.items():
        flo, cap = FAMILY_RANGES[t[0]]
        es = [e for e in es if flo <= e['browser_major'] <= cap and not is_psk(e)]
        if not es:
            continue
        clusters = defaultdict(list)
        for e in es:
            clusters[e['ja4']].append(e)
        ranked = sorted(clusters.items(),
                        key=lambda kv: (-sum(x['observation_count'] for x in kv[1]), kv[0]))
        for ja4, cl in ranked[:3]:
            rep = max(cl, key=lambda x: x['browser_major'])
            a, h2 = ja4.split('_')[0], ja4.split('_')[1]
            # wire-exact upgrade: first (top-ranked) cluster in this triple
            # whose A+hash2 matches an unused hand profile is replaced.
            upgraded = False
            for hname, (ht, ha, hh2) in HAND_UPGRADES.items():
                if hname not in used_upgrades and ht == t and (ha, hh2) == (a, h2):
                    used_upgrades.add(hname)
                    upgraded = True
                    break
            if not upgraded:
                kept.add(rep['name'])
    return kept
# Expected kept roster (69 generated names; the 2 hand-upgraded generated
# slots -- chrome_148_windows_desktop, edge_149_windows_desktop -- excluded).
# Asserted verbatim by --selftest.
KEPT_STATS = [
    'chrome_148_android_desktop', 'chrome_134_android_desktop',
    'chrome_141_android_desktop_3', 'chrome_147_android_tablet',
    'chrome_131_android_tablet', 'chrome_83_android_tablet',
    'chrome_144_ios_phone_2', 'chrome_143_ios_phone', 'chrome_133_ios_phone',
    'chrome_148_ios_tablet', 'chrome_146_ios_tablet', 'chrome_141_ios_tablet',
    'chrome_149_macos_desktop', 'chrome_122_macos_desktop',
    'chrome_115_macos_desktop', 'chrome_143_windows_desktop',
    'chrome_93_windows_desktop',
    'edge_146_android_desktop', 'edge_134_android_desktop',
    'edge_121_android_desktop', 'edge_144_android_tablet',
    'edge_143_ios_phone_3', 'edge_143_ios_phone_2', 'edge_121_ios_phone',
    'edge_131_ios_tablet', 'edge_148_macos_desktop', 'edge_132_macos_desktop',
    'edge_112_macos_desktop', 'edge_128_windows_desktop',
    'edge_121_windows_desktop',
    'firefox_150_android_desktop', 'firefox_149_android_desktop_2',
    'firefox_144_android_desktop_5', 'firefox_146_ios_phone_2',
    'firefox_138_ios_phone', 'firefox_137_ios_phone',
    'firefox_150_macos_desktop', 'firefox_149_macos_desktop',
    'firefox_148_macos_desktop', 'firefox_148_windows_desktop',
    'firefox_139_windows_desktop', 'firefox_125_windows_desktop',
    'opera_96_android_desktop', 'opera_88_android_desktop',
    'opera_80_android_desktop', 'opera_130_macos_desktop',
    'opera_119_macos_desktop', 'opera_98_macos_desktop',
    'opera_130_windows_desktop', 'opera_128_windows_desktop',
    'opera_97_windows_desktop', 'brave_90_macos_desktop',
    'brave_89_windows_desktop', 'brave_126_windows_desktop',
    'safari_26_ios_phone', 'safari_18_ios_phone', 'safari_9_ios_phone',
    'safari_18_ios_tablet', 'safari_17_ios_tablet', 'safari_6_ios_tablet',
    'safari_26_macos_desktop', 'safari_16_macos_desktop',
    'safari_12_macos_desktop', 'safari_12_windows_desktop',
    'safari_12_windows_desktop_2', 'safari_5_windows_desktop',
    'samsung_29_android_desktop', 'samsung_28_android_desktop',
    'samsung_17_android_desktop',
]


# --- Rust emitter: profiles/generated/<family>.rs ------------------------------
#
# Renders every manifest entry as a `spec!` declaration plus a `GenEntry`
# registry row (the resolver and the offline JA4 gate consume `GENERATED`).
# Rendering is byte-deterministic: --emit twice produces identical files,
# and --selftest asserts both double-render determinism and that the
# committed files equal a fresh render.

GENERATED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "..", "..", "profiles", "generated")

# Family modules, in file/module declaration order (task brief file list).
FAMILY_ORDER = ["chrome", "firefox", "safari", "chrome_android",
                "safari_ios", "okhttp", "fallback"]
FAMILY_DOC = {
    "chrome": "Chromium family desktop hellos (Chrome, Edge, Opera, Brave, "
              "Samsung Internet; the `chrome_desktop` wire template)",
    "firefox": "Firefox hellos (the `firefox` wire template)",
    "safari": "Safari hellos on macOS and desktop (the `safari` wire "
              "template)",
    "chrome_android": "Chromium family Android hellos (the `chrome_android` "
                      "wire template)",
    "safari_ios": "`WebKit` hellos on iOS (the `safari_ios` wire template; "
                  "`WKWebView` reality)",
    "okhttp": "Minimal Chromium derived `OkHttp` hellos (the `okhttp` wire "
              "template; no corpus entries yet)",
    "fallback": "Entries with no family template (the `ascending` fallback; "
                "no corpus entries yet)",
}

_BROWSER_VARIANT = {
    "chrome": "Chrome", "firefox": "Firefox", "safari": "Safari",
    "edge": "Edge", "brave": "Brave", "opera": "Opera",
    "samsung": "SamsungInternet", "okhttp": "Chrome",
}
_OS_VARIANT = {"windows": "Windows", "macos": "MacOs", "linux": "Linux",
               "android": "Android", "ios": "Ios"}
_DEVICE_VARIANT = {"desktop": "Desktop", "phone": "Phone", "tablet": "Tablet"}

_GROUP_NAMES = {0x001D: "x25519", 0x11EC: "mlkem768", 0x0017: "p256",
                0x0018: "p384", 0x0019: "p521"}
_COMPRESS_NAMES = {0x0001: "zlib", 0x0002: "brotli", 0x0003: "zstd"}
_KEYSHAKE_NAMES = {"Grease": "grease", "X25519": "x25519",
                   "X25519Mlkem768": "mlkem768"}
# Bare extension ids -> spec! tokens (extension variant names, spec/mod.rs).
_BARE_EXT_TOKENS = {
    "ServerName": "sni", "Grease": "grease", "StatusRequest": "status",
    "EcPointFormats": "ecpf", "SessionTicket": "ticket",
    "PskKeyExchangeModes": "psk", "SignedCertificateTimestamp": "sct",
    "RenegotiationInfo": "reneg", "Padding": "padding",
    "EchGrease": "ech",
}


def _family_module(entry):
    """Module name for a manifest entry: the same browser/OS rules as
    `template_for`, so one module == one wire template."""
    browser, os_name = entry["family"], entry["os"]
    if os_name == "ios":
        return "safari_ios"
    if browser == "firefox":
        return "firefox"
    if os_name == "android" and browser != "safari":
        return "chrome_android"
    if browser == "safari":
        return "safari"
    if browser in ("chrome", "edge", "opera", "brave", "samsung"):
        return "chrome"
    return "fallback"


def _u16_token(v):
    return "grease" if is_grease(v) else f"0x{v:04x}"


def _group_token(v):
    return "grease" if is_grease(v) else _GROUP_NAMES.get(v, f"0x{v:04x}")


def _compress_token(v):
    return _COMPRESS_NAMES.get(v, f"0x{v:04x}")


def _ext_token(ext):
    """One manifest extension object -> its spec! token (spec! grammar in
    profiles/mod.rs; kinds are ExtensionSpec variant names, spec/mod.rs)."""
    kind = ext["kind"]
    if kind in _BARE_EXT_TOKENS:
        return _BARE_EXT_TOKENS[kind]
    args = ext["args"]
    if kind == "SupportedGroups":
        return f"groups[{', '.join(_group_token(v) for v in args[0])}]"
    if kind == "KeyShare":
        try:
            groups = [_KEYSHAKE_NAMES[g] for g in args[0]]
        except KeyError as e:
            raise ValueError(
                f"keyshare group {e} has no spec! token (profiles/mod.rs "
                f"keyshare_token keyspace)") from None
        return f"keyshare[{', '.join(groups)}]"
    if kind == "SupportedVersions":
        return f"versions[{', '.join(_u16_token(v) for v in args[0])}]"
    if kind == "SignatureAlgorithms":
        return f"sigalgs[{', '.join(_u16_token(v) for v in args[0])}]"
    if kind == "CompressCertificate":
        return f"compress[{', '.join(_compress_token(v) for v in args[0])}]"
    if kind == "Alpn":
        return f"alpn[{', '.join(json.dumps(p) for p in args[0])}]"
    if kind == "ApplicationSettings":
        return f"appsettings[{', '.join(json.dumps(p) for p in args[0])}]"
    if kind == "RecordSizeLimit":
        return f"rslimit[{args[0]}]"
    if kind == "Raw":
        if not args[0] and ext["ty"] in EMPTY_BODY_ILLEGAL:
            raise ValueError(
                f"extension 0x{ext['ty']:04x} would be emitted with an empty "
                f"body, but its body is a length-prefixed vector "
                f"(EMPTY_BODY_ILLEGAL) — synthesize it (SIGALGS_CERT / "
                f"DELEGATED_CREDENTIALS) or give it an engine variant "
                f"(EchGrease)")
        return f"raw[0x{ext['ty']:04x}, \"{bytes(args[0]).hex()}\"]"
    raise ValueError(f"extension kind {kind!r} is not an ExtensionSpec "
                     f"variant (spec/mod.rs)")


def _wrap(prefix, tokens):
    """Tokens joined onto `prefix`, wrapped at ~100 columns; continuation
    lines align under the first token, and every line ends with a comma
    (the spec! grammar needs one after the last cipher — the section
    separator — and tolerates one after the last extension)."""
    lines = []
    line = prefix
    for tok in tokens:
        if line == prefix:
            line += " " + tok
        elif len(line) + len(tok) + 2 <= 100:
            line += ", " + tok
        else:
            lines.append(line + ",")
            line = " " * (len(prefix) + 1) + tok
    lines.append(line + ",")
    return lines


def _spec_text(entry):
    """The `spec!` declaration for one manifest entry."""
    wire = entry["wire"]
    ciphers = wire["cipher_order"]
    assert not any(is_grease(c) for c in ciphers[1:]), (
        f"{entry['name']}: GREASE cipher outside the first slot would not "
        f"parse (spec! matcher requires GREASE first)")
    cipher_tokens = ["GREASE" if is_grease(c) else f"0x{c:04x}"
                     for c in ciphers]
    ext_tokens = [_ext_token(x) for x in wire["extensions"]]
    lines = ["spec! {",
             f"    {entry['name']},"]
    lines += _wrap("    ciphers:", cipher_tokens)
    lines.append(f"    session: {wire['session_id']},")
    lines += _wrap("    exts:", ext_tokens)
    lines.append("}")
    return "\n".join(lines)


def _gen_entry_text(entry):
    """One `GenEntry { ... }` registry literal (generated/mod.rs struct)."""
    name = entry["name"]
    try:
        browser = _BROWSER_VARIANT[entry["browser"]]
        os_name = _OS_VARIANT[entry["os"]]
        device = _DEVICE_VARIANT[entry["device"]]
    except KeyError as e:
        raise ValueError(
            f"{name}: no Rust enum variant for {e} (fingerprints/query.rs)"
        ) from None
    return ("    GenEntry {\n"
            f"        name: {json.dumps(name)},\n"
            f"        browser: Browser::{browser},\n"
            f"        os: Some(Os::{os_name}),\n"
            f"        device: Device::{device},\n"
            f"        major: {entry['browser_major']},\n"
            f"        ja4: {json.dumps(entry['ja4'])},\n"
            f"        spec_fn: {name},\n"
            "    },")


def _render_family_module(module, entries):
    header = (
        f"//! {FAMILY_DOC[module]}\n"
        "//!\n"
        "//! Emitter output (`gen_specs.py --emit`); do not edit by hand.\n"
        "//! Regeneration is byte-deterministic (`--selftest` verifies the\n"
        "//! committed files match a fresh render).\n"
        "\n"
        "use super::GenEntry;\n"
    )
    if entries:
        header += "use crate::fingerprints::{Browser, Device, Os};\n"
    if not entries:
        return (header + "\n" +
                "// No corpus entries for this family yet; the registry\n"
                "// stays empty until the catalog grows one.\n"
                "pub const GENERATED: &[GenEntry] = &[];\n")
    out = [header, "#[rustfmt::skip]", "pub const GENERATED: &[GenEntry] = &["]
    out += [_gen_entry_text(e) for e in entries]
    out.append("];")
    for e in entries:
        out.append("")
        out.append(f"// ja4={e['ja4']} obs={e['observation_count']}")
        out.append("#[rustfmt::skip]")
        out.append(_spec_text(e))
    return "\n".join(out) + "\n"


def _render_mod(by_family):
    out = [
        "//! Generated JA4-faithful profile roster, one module per browser\n"
        "//! family.\n"
        "//!\n"
        "//! Each family module holds `spec!` declarations and a `GENERATED`\n"
        "//! registry; `GENERATED` here is the merged slice consumed by the\n"
        "//! resolver and the offline JA4 gate (later tasks).\n"
        "//!\n"
        "//! Emitter output (`gen_specs.py --emit`); do not edit by hand.\n"
        "\n"
        "pub mod chrome;\n"
        "pub mod chrome_android;\n"
        "pub mod fallback;\n"
        "pub mod firefox;\n"
        "pub mod okhttp;\n"
        "pub mod safari;\n"
        "pub mod safari_ios;\n"
        "\n"
        "use crate::fingerprints::{Browser, Device, Os};\n"
        "use crate::spec::ClientHelloSpec;\n"
        "\n"
        "/// One generated roster entry: identity, registered source JA4 and\n"
        "/// the spec builder. `name` doubles as the spec function id.\n"
        "#[derive(Debug, Clone, Copy)]\n"
        "pub struct GenEntry {\n"
        "    pub name: &'static str,\n"
        "    pub browser: Browser,\n"
        "    pub os: Option<Os>,\n"
        "    pub device: Device,\n"
        "    pub major: u16,\n"
        "    pub ja4: &'static str,\n"
        "    pub spec_fn: fn() -> ClientHelloSpec,\n"
        "}\n"
        "\n"
        "/// Every generated profile, family by family (module order).\n"
        "#[rustfmt::skip]\n"
        "pub const GENERATED: &[GenEntry] = &[",
    ]
    for module in FAMILY_ORDER:
        entries = by_family[module]
        if not entries:
            continue
        out.append(f"    // {module}: {len(entries)} entries")
        out += [f"    {module}::GENERATED[{i}]," for i in range(len(entries))]
    out.append("];")
    return "\n".join(out) + "\n"


def render_modules(entries):
    """Render every generated file from manifest entries (JSON shape).
    Returns {filename: text}; deterministic for the same input."""
    by_family = {m: [] for m in FAMILY_ORDER}
    for e in entries:
        by_family[_family_module(e)].append(e)
    texts = {f"{m}.rs": _render_family_module(m, by_family[m])
             for m in FAMILY_ORDER}
    texts["mod.rs"] = _render_mod(by_family)
    return texts


def _write_modules(entries: list) -> int:
    """Render and write every generated file; returns 0 on success."""
    texts = render_modules(entries)
    os.makedirs(GENERATED_DIR, exist_ok=True)
    for fname, text in sorted(texts.items()):
        with open(os.path.join(GENERATED_DIR, fname), "w",
                  encoding="utf-8") as fh:
            fh.write(text)
    counts = {m: len([e for e in entries if _family_module(e) == m])
              for m in FAMILY_ORDER}
    print(f"generated {len(texts)} files -> {counts} "
          f"({len(entries)} entries)")
    return 0


# --- self-test -----------------------------------------------------------------


def _selftest() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", "..", "..", "..", ".."))
    csv_dir = os.path.join(root, "thirdparty", "ja4db-export", "csv")
    raw_csv = os.path.join(csv_dir, "ja4_fingerprint_string.csv")
    key_csv = os.path.join(csv_dir, "ja4_fingerprint.csv")

    # Unit: GREASE pattern and sha12.
    assert is_grease(0x0A0A) and is_grease(0x1A1A) and is_grease(0x1A0A)
    assert not is_grease(0x1301) and not is_grease(0x0017) and not is_grease(0x1F1F)

    # Byte-exact mirror of ja4.rs: the tls.peet.ws curl known vector
    # (`t13d3113h2_e8f1e7e78f70_db572f7c111e`), lists verbatim from the
    # Rust test module.
    peet = RawComponents(
        "t13d3113h2",
        [int(x, 16) for x in (
            "002f 0033 0035 0039 003c 003d 0067 006b 009c 009d 009e 009f"
            " 00ff 1301 1302 1303 c009 c00a c013 c014 c023 c024 c027 c028"
            " c02b c02c c02f c030 cca8 cca9 ccaa"
        ).split()],
        [0x0000, 0x000B, 0x000A, 0x3374, 0x0010, 0x0016, 0x0017, 0x0031,
         0x000D, 0x002B, 0x002D, 0x0033, 0x0015],
        [0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080A, 0x080B,
         0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301,
         0x0302, 0x0402, 0x0502, 0x0602],
        "h2",
    )
    assert ja4_hash(peet, exclude_padding=True) == (
        "t13d3113h2_e8f1e7e78f70_db572f7c111e"
    )
    # Rust `no_sig_algs_drops_trailing_segment`: ext-only payload hash.
    no_sig = RawComponents(peet.ja4_a, peet.ciphers, peet.exts_sorted, [], "h2")
    assert ja4_hash(no_sig, exclude_padding=True).split("_")[2] == "619e7cdd0224"

    # Unit: exclusion effects per rule.
    base = RawComponents("t13d0101h2", [0x1301], [0x000B], [], "h2")
    sni_alpn_only = RawComponents("t13d0101h2", [0x0A0A, 0x1301],
                                  [SNI, ALPN, 0x000B], [], "h2")
    with_padding = RawComponents("t13d0101h2", [0x1301],
                                 [SNI, ALPN, PADDING, 0x000B], [], "h2")
    assert ja4_hash(base) == ja4_hash(sni_alpn_only) != ja4_hash(with_padding)
    assert ja4_hash(base, exclude_padding=True) == ja4_hash(
        with_padding, exclude_padding=True)

    # Clamp helper (ja4.rs counts_clamp_at_99).
    assert format_ja4_a(120, 150) == "t13d999900"

    # Corpus round-trip.
    keys: set[str] = set()
    with open(key_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            k = (row.get("ja4_fingerprint") or "").strip()
            if k:
                keys.add(k)

    rows_total = rows_hit = obs_total = obs_hit = 0
    distinct: dict[str, bool] = {}
    unparsed = []
    with open(raw_csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            s = (row.get("ja4_fingerprint_string") or "").strip()
            n = int(row.get("observation_count") or 1)
            if not s.startswith("t13d"):
                continue  # non-TLS1.3 rows are out of scope, not misses
            rc = parse_raw(s)
            if rc is None:
                unparsed.append(s)
                continue
            hit = ja4_hash(rc) in keys
            rows_total += 1
            obs_total += n
            rows_hit += hit
            obs_hit += n * hit
            distinct[s] = hit

    row_rate = rows_hit / rows_total
    obs_rate = obs_hit / obs_total
    d_hit = sum(distinct.values())
    d_rate = d_hit / len(distinct)
    print(f"parsed(t13d rows): {rows_total}  matched: {rows_hit}  "
          f"rate: {row_rate:.4%}")
    print(f"distinct strings: {len(distinct)}  matched: {d_hit}  "
          f"rate: {d_rate:.4%}")
    print(f"observation-weighted: {obs_hit}/{obs_total}  rate: {obs_rate:.4%}")
    print(f"hashed-csv unique keys: {len(keys)}  unparsed t13d rows: "
          f"{len(unparsed)}")
    if rows_hit < rows_total:
        print(f"unmatched remainder ({rows_total - rows_hit} rows / "
              f"{len(distinct) - d_hit} distinct): see module docstring "
              f"'Corpus quirks' -- export-set asymmetry, not a hash bug")

    # Floors: row-level >=99% per plan; observation-weighted and distinct
    # floors are the corpus ceilings (see docstring 'Corpus quirks').
    assert row_rate >= 0.99, f"row match rate {row_rate:.4%} < 99%"
    assert obs_rate >= 0.988, f"observation-weighted rate {obs_rate:.4%} < 98.8%"
    assert d_rate >= 0.899, f"distinct-string rate {d_rate:.4%} < 89.9%"
    # Task 3: family-template wire synthesis round-trip. Every entry's
    # synthesized wire must reproduce the A-part exactly and the full JA4
    # wherever the observation carried its signature algorithms.
    VALID_KINDS = {
        "ServerName", "SupportedGroups", "KeyShare", "SupportedVersions",
        "SignatureAlgorithms", "Alpn", "EcPointFormats", "SessionTicket",
        "PskKeyExchangeModes", "StatusRequest", "SignedCertificateTimestamp",
        "RenegotiationInfo", "CompressCertificate", "ApplicationSettings",
        "RecordSizeLimit", "Padding", "Grease", "Raw", "EchGrease",
    }
    man = build_manifest(csv_dir)
    tmpl_dist: dict[str, int] = {}
    a_bad = full_bad = full_skipped = n_fallback = n_lowfi = 0
    for e in man["entries"]:
        w = e["wire"]
        assert all(x["kind"] in VALID_KINDS for x in w["extensions"])
        assert w["compression"] == [0]
        assert w["session_id"] in ("random32", "empty")
        cs = [c for c in w["cipher_order"] if not is_grease(c)]
        assert sorted(cs) == sorted(c for c in e["raw"].ciphers
                                    if not is_grease(c)), e["name"]
        a_ok, full_ok = verify_wire(e)
        if not a_ok:
            a_bad += 1
            print(f"A-PART MISMATCH: {e['name']}")
        if full_ok is None:
            full_skipped += 1
        elif not full_ok:
            full_bad += 1
            print(f"JA4 MISMATCH: {e['name']}")
        tmpl_dist[e["wire_template"]] = tmpl_dist.get(e["wire_template"], 0) + 1
        n_fallback += e["fallback"]
        n_lowfi += e["low_fidelity"]
    print(f"wire templates: {len(man['entries'])} entries -> {tmpl_dist}")
    print(f"wire fallback: {n_fallback}  low-fidelity: {n_lowfi}  "
          f"full-hash unverifiable (no sig-alg segment): {full_skipped}")
    assert a_bad == 0, f"{a_bad} entries fail A-part reconstruction"
    assert full_bad == 0, f"{full_bad} entries fail full-JA4 reconstruction"

    # Task 2: the kept roster is what gets emitted. The 2 hand-upgraded
    # generated slots (chrome_148_windows_desktop, edge_149_windows_desktop)
    # are excluded; chrome_143_windows_desktop / edge_128_windows_desktop are
    # second-slot distinct-JA4 variants and MUST remain.
    kept = select_roster(man["entries"])
    assert sorted(kept) == sorted(KEPT_STATS), (
        f"kept roster mismatch: {sorted(kept - set(KEPT_STATS))} extra, "
        f"{sorted(set(KEPT_STATS) - kept)} missing")

    # Task 5: emitter determinism + regenerate == committed. Rendering the
    # manifest twice must be byte-identical, and the committed files must
    # equal a fresh render of the kept subset (--emit output is the
    # committed artifact; only `kept` entries are emitted).
    entries = [_manifest_entry_json(e) for e in man["entries"]]
    for e in entries:
        e["kept"] = e["name"] in kept
    # The committed manifest carries the same kept flags as the selection.
    with open(MANIFEST_PATH, encoding="utf-8") as fh:
        committed = json.load(fh)
    committed_kept = {e["name"] for e in committed["entries"]
                      if e.get("kept")}
    assert committed_kept == kept, (
        f"committed manifest kept flags drifted: "
        f"{sorted(committed_kept - kept)} extra, "
        f"{sorted(kept - committed_kept)} missing")
    kept_entries = [e for e in entries if e["kept"]]
    texts = render_modules(kept_entries)
    assert render_modules(kept_entries) == texts, \
        "emitter output not deterministic"
    for fname, text in sorted(texts.items()):
        path = os.path.join(GENERATED_DIR, fname)
        with open(path, encoding="utf-8") as fh:
            assert fh.read() == text, (
                f"{path} differs from a fresh render — run `--emit` and "
                f"commit the result")
    rendered_names = {e["name"] for e in kept_entries}
    assert len(rendered_names) == 69, \
        f"expected 69 kept entries, got {len(rendered_names)}"
    for excluded in ("chrome_148_windows_desktop",
                     "edge_149_windows_desktop"):
        assert excluded not in rendered_names, (
            f"excluded hand-upgraded slot {excluded} still emitted")
    print(f"selection: {len(kept)} kept generated names == expected "
          f"{len(KEPT_STATS)} (2 hand-upgraded slots excluded)")
    print(f"emit: {len(kept_entries)} entries -> {len(texts)} files, "
          f"excluded slots absent, manifest kept flags consistent")
    print("PASS")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--manifest", action="store_true",
                    help="build specs_manifest.json from the ja4db export")
    ap.add_argument("--emit", action="store_true",
                    help="write profiles/generated/*.rs from "
                         "specs_manifest.json")
    ap.add_argument("--select", action="store_true",
                    help="print the deterministic kept roster (names)")
    args = ap.parse_args()
    if args.selftest:
        sys.exit(_selftest())
    if args.select:
        here = os.path.dirname(os.path.abspath(__file__))
        csv_dir = os.path.join(here, "..", "..", "..", "..", "..",
                               "thirdparty", "ja4db-export", "csv")
        kept = select_roster(build_manifest(csv_dir)["entries"])
        for name in sorted(kept):
            print(name)
        sys.exit(0)
    if args.manifest:
        here = os.path.dirname(os.path.abspath(__file__))
        csv_dir = os.path.join(here, "..", "..", "..", "..", "..",
                               "thirdparty", "ja4db-export", "csv")
        sys.exit(_write_manifest(csv_dir))
    if args.emit:
        with open(MANIFEST_PATH, encoding="utf-8") as fh:
            manifest = json.load(fh)
        entries = manifest["entries"]
        # Kept roster: the `kept` flag written by --manifest is
        # authoritative; recomputing select_roster covers manifests that
        # predate the flag. Both routes are deterministic and agree.
        kept = select_roster(entries)
        entries = [e for e in entries if e.get("kept", e["name"] in kept)]
        sys.exit(_write_modules(entries))
    ap.error("nothing to do; pass --selftest, --manifest or --emit")
