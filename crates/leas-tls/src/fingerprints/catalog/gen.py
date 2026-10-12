#!/usr/bin/env python3
"""Generates catalog_data.rs from the frozen ja4db-export CSV snapshot.

Cleaning rules (per the design spec):
- keep rows whose ja4_fingerprint matches ^t1[0-3] AND have an identifiable
  application: a parseable user_agent_string (via ua-parser) or, only when
  the UA is absent, a direct `application` field like 'Chrome 94.0';
- parse UA -> (browser, major, os, os_major, device); unparseable rows dropped;
- dedupe on (ja4, browser, major, os, os_major, device); sum observation_count.

Majors come straight from ua-parser; 0 = unknown.

Requires: python3 + `pip install -r requirements.txt` (ua-parser[regex]).
"""
import csv
import re
import sys
from collections import OrderedDict

from ua_parser import parse

CSV_PATH = "thirdparty/ja4db-export/csv/all_records.csv"
OUT_PATH = "crates/leas-tls/src/fingerprints/catalog/catalog_data.rs"

JA4_RE = re.compile(r"^t1[0-3][a-z]")
# Rust-string-safe shape: lowercase alnum segments, 2 or 3 parts.
JA4_STRICT_RE = re.compile(r"^t1[0-3][a-z0-9]+(?:_[a-z0-9]+){1,2}$")

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
    """Direct application field, e.g. 'Chrome 94.0'; fallback for UA-less rows.

    Returns a 5-tuple matching parse_ua(); application-only rows carry no OS
    evidence (os empty, os_major 0); an unparseable version -> browser_major 0.
    """
    m = APPLICATION_RE.match(application.strip())
    if not m:
        return None
    name = {"Samsung Internet": "samsung"}.get(m.group(1), m.group(1).lower())
    return name, int(m.group(2)) if m.group(2) else 0, "", 0, ""


def main():
    rows = OrderedDict()  # key -> row dict
    dropped = kept = 0
    with open(CSV_PATH, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for r in reader:
            ja4 = (r.get("ja4_fingerprint") or "").strip()
            if not JA4_RE.match(ja4) or not JA4_STRICT_RE.match(ja4):
                continue
            ua_field = (r.get("user_agent_string") or "").strip()
            parsed = parse_ua(ua_field) if ua_field else parse_application(r.get("application") or "")
            if parsed is None:
                dropped += 1
                continue
            browser, browser_major, os_name, os_major, device = parsed
            try:
                count = int(r.get("observation_count") or "1")
            except ValueError:
                count = 1
            key = (ja4, browser, browser_major, os_name, os_major, device)
            if key in rows:
                rows[key]["observation_count"] += count
            else:
                rows[key] = {
                    "ja4": ja4, "application": browser, "browser_major": browser_major,
                    "library": (r.get("library") or "").strip(),
                    "device": device, "os": os_name, "os_major": os_major,
                    "user_agent": ua_field,
                    "verified": (r.get("verified") or "").strip() == "true",
                    "observation_count": count,
                }
            kept += 1

    def esc(s):
        # Drop anything a Rust string literal cannot carry verbatim
        # (stray control bytes / non-ASCII junk in the raw CSV).
        s = s.replace("\\", "\\\\").replace('"', '\\"')
        return "".join(c for c in s if 32 <= ord(c) < 127)

    lines = [
        "// GENERATED by catalog/gen.py from thirdparty/ja4db-export (frozen",
        "// snapshot 2026-05-15). Do not edit by hand; rerun the generator.",
        "#[rustfmt::skip]",
        "/// One cleaned real-world JA4 observation.",
        "#[derive(Debug, Clone)]",
        "pub struct CatalogEntry {",
        "    pub ja4: &'static str,",
        "    pub application: &'static str,",
        "    pub browser_major: u16,",
        "    pub library: &'static str,",
        "    pub device: &'static str,",
        "    pub os: &'static str,",
        "    pub os_major: u16,",
        "    pub user_agent: &'static str,",
        "    pub verified: bool,",
        "    pub observation_count: u64,",
        "}",
        "",
        "#[rustfmt::skip]",
        "/// The cleaned catalog.",
        "pub static CATALOG: &[CatalogEntry] = &[",
    ]
    for row in rows.values():
        lines.append(
            "    CatalogEntry {{ ja4: \"{ja4}\", application: \"{app}\", "
            "browser_major: {bmaj}, library: \"{lib}\", device: \"{dev}\", "
            "os: \"{os}\", os_major: {omaj}, user_agent: \"{ua}\", "
            "verified: {ver}, observation_count: {cnt} }},".format(
                ja4=esc(row["ja4"]), app=esc(row["application"]), bmaj=row["browser_major"],
                lib=esc(row["library"]), dev=esc(row["device"]), os=esc(row["os"]),
                omaj=row["os_major"], ua=esc(row["user_agent"][:200]),
                ver="true" if row["verified"] else "false",
                cnt=row["observation_count"],
            ))
    lines.append("];")
    with open(OUT_PATH, "w", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")
    print(f"kept {len(rows)} unique entries ({kept} rows merged, {dropped} dropped)", file=sys.stderr)


if __name__ == "__main__":
    main()
