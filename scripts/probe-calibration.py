#!/usr/bin/env python3
"""Oracle calibration: does our client agree with xray-core on the same links?

Reads a `leas` database, samples N links per `(error_stage, error_cause)`
stratum, rebuilds each link's xray-core client outbound from the stored
`protocols.config`, dials the probe target through it, and prints an agreement
matrix (our outcome vs the oracle's). This is the only external check on "our
client is faithful" (spec `2026-11-19-probe-truth-and-ingest-boundary` S9); it
is dev tooling, not a test.

Usage:
  scripts/probe-calibration.py --db ~/.config/leas/data.db --xray /path/to/xray \\
      --per-stratum 20 [--target https://www.gstatic.com/generate_204] [--json out.json]

Read the DB read-only through the turso CLI (production engine, not sqlite3);
point `--db` at a COPY if the app is running.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

TURSODB = os.path.expanduser("~/.turso/tursodb")


def tursodb(db: str, sql: str) -> str:
    """Run one statement, return the box-drawing table as text."""
    out = subprocess.run(
        [TURSODB, "--readonly", db, sql],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout


def rows(db: str, sql: str) -> list[list[str]]:
    """Parse the tursodb table into cells (header dropped)."""
    lines = [ln for ln in tursodb(db, sql).splitlines() if ln.startswith("│")]
    cells = [[c.strip() for c in ln.strip("│").split("│")] for ln in lines]
    return cells[1:] if cells else []


def sample_links(db: str, per_stratum: int) -> list[dict]:
    """N links per (stage, cause), from the typed columns when present."""
    probe = rows(db, "SELECT name FROM pragma_table_info('profile_stats') WHERE name = 'error_stage'")
    if probe:
        sql = f"""
            SELECT error_stage, error_cause, p.proto_kind, p.transport_type, p.security_type,
                   p.config, e.domain, e.sub_domain, e.port
            FROM profile_stats ps
            JOIN protocols p ON p.id = ps.protocol_id
            JOIN endpoints e ON e.id = ps.endpoint_id
            WHERE ps.error = 1 AND ps.error_stage IS NOT NULL
            ORDER BY random() LIMIT {per_stratum * 64}
        """
    else:
        # Pre-schema-22 database: one stratum, so the run still means something.
        sql = f"""
            SELECT 'unknown', 'unknown', p.proto_kind, p.transport_type, p.security_type,
                   p.config, e.domain, e.sub_domain, e.port
            FROM profile_stats ps
            JOIN protocols p ON p.id = ps.protocol_id
            JOIN endpoints e ON e.id = ps.endpoint_id
            WHERE ps.error = 1
            ORDER BY random() LIMIT {per_stratum * 16}
        """
    links: list[dict] = []
    seen: dict[tuple[str, str], int] = {}
    for stage, cause, kind, transport, security, config, domain, sub, port in rows(db, sql):
        key = (stage, cause)
        if seen.get(key, 0) >= per_stratum:
            continue
        seen[key] = seen.get(key, 0) + 1
        host = f"{sub}.{domain}" if domain and sub else (domain or "")
        if not host:
            continue  # IP-literal endpoints need the packed key; skip them here.
        links.append(
            {
                "stage": stage,
                "cause": cause,
                "kind": kind,
                "transport": transport,
                "security": security,
                "config": json.loads(config.replace('\\"', '"')),
                "host": host,
                "port": int(port),
            }
        )
    return links


def xray_outbound(link: dict) -> dict:
    """A best-effort xray client outbound for a stored VLESS/VMess/Trojan row."""
    cfg = link["config"]
    sec = cfg.get("security") or {}
    net = cfg.get("transport") or {}
    stream = {"network": net.get("type") or link["transport"]}
    security = link["security"] or sec.get("type") or "none"

    tls = {
        "serverName": sec.get("sni") or link["host"],
        "fingerprint": sec.get("fp") or "chrome",
        "allowInsecure": bool(sec.get("insecure")),
    }
    if security == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": tls["serverName"],
            "fingerprint": tls["fingerprint"],
            "publicKey": sec.get("pbk", ""),
            "shortId": sec.get("sid", ""),
            "spiderX": sec.get("spx", "/"),
        }

    t = stream["network"]
    if t == "ws":
        stream["wsSettings"] = {"path": net.get("path") or "/", "headers": {"Host": net.get("host") or link["host"]}}
    elif t == "grpc":
        stream["grpcSettings"] = {"serviceName": net.get("service_name") or net.get("authority") or ""}
    elif t in ("httpupgrade", "xhttp"):
        stream["network"] = "httpupgrade" if t == "httpupgrade" else "xhttp"
        stream["httpupgradeSettings"] = {"path": net.get("path") or "/", "host": net.get("host") or link["host"]}

    if link["kind"] == "vless":
        user = {"id": cfg.get("uuid"), "encryption": "none"}
        if cfg.get("flow"):
            user["flow"] = cfg["flow"]
        out = {"protocol": "vless", "settings": {"vnext": [{"address": link["host"], "port": link["port"], "users": [user]}]}}
    elif link["kind"] == "vmess":
        out = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": link["host"], "port": link["port"], "users": [{"id": cfg.get("uuid"), "alterId": int(cfg.get("alter_id") or 0), "security": "auto"}]}]},
        }
    else:
        return {}
    out["streamSettings"] = stream
    return out


def run_through(xray: str, outbound: dict, target: str, timeout: float) -> str:
    """One dial through a local xray SOCKS inbound; returns 'ok' or the class."""
    if not outbound:
        return "unsupported"
    sock_port = random.randint(20000, 40000)
    cfg = {
        "log": {"loglevel": "error"},
        "inbounds": [{"port": sock_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [outbound],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(cfg, fh)
        path = fh.name
    proc = subprocess.Popen([xray, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.6)
        res = subprocess.run(
            [
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", str(int(timeout)),
                "--socks5-hostname", f"127.0.0.1:{sock_port}", target,
            ],
            capture_output=True,
            text=True,
        )
        return "ok" if res.stdout.strip() in ("200", "204") else f"fail:{res.stdout.strip() or res.returncode}"
    finally:
        proc.kill()
        proc.wait()
        os.unlink(path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", required=True)
    ap.add_argument("--xray", required=True, help="xray-core binary")
    ap.add_argument("--per-stratum", type=int, default=20)
    ap.add_argument("--target", default="https://www.gstatic.com/generate_204")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--json", help="write the per-link results here")
    args = ap.parse_args()

    if not shutil.which("curl"):
        print("curl is required", file=sys.stderr)
        return 2

    links = sample_links(args.db, args.per_stratum)
    if not links:
        print("no links sampled; is the DB path right?", file=sys.stderr)
        return 2

    results = []
    for link in links:
        outcome = run_through(args.xray, xray_outbound(link), args.target, args.timeout)
        results.append({**{k: link[k] for k in ("stage", "cause", "kind", "host", "port")}, "xray": outcome})
        print(f"{link['stage']:>9}/{link['cause']:<10} {link['kind']:<8} {link['host']}:{link['port']} -> {outcome}")

    matrix: dict[tuple[str, str], list[int]] = {}
    for r in results:
        key = (r["stage"], r["cause"])
        cell = matrix.setdefault(key, [0, 0])
        cell[1] += 1
        if r["xray"] == "ok":
            cell[0] += 1
    print("\nstratum -> xray agreed (ok) / sampled")
    for key in sorted(matrix):
        ok, n = matrix[key]
        print(f"  {key[0]:>9}/{key[1]:<10} {ok:>4} / {n}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
