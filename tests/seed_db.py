#!/usr/bin/env python3
"""Seed the leas database with 36 groups of subscription profiles."""

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import time
from base64 import b64decode
from pathlib import Path
from urllib.parse import unquote

CONFIG_DIR = (
    Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "leas"
)
DB_PATH = CONFIG_DIR / "data.db"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
BINARY = Path(__file__).resolve().parent.parent / "target/release/leas"

CONFIG_TYPE = {
    "vmess": 1,
    "vless": 5,
    "trojan": 6,
    "ss": 3,
    "ssr": 0,
    "socks": 4,
    "http": 10,
    "hysteria2": 7,
    "hysteria": 0,
    "tuic": 8,
    "wireguard": 9,
    "naive+https": 12,
    "naive+quic": 12,
    "anytls": 11,
    "shadowtls": 0,
}


def sanitize(s):
    """Keep only ASCII printable chars, safe for byte-slicing."""
    if not s:
        return ""
    return re.sub(r"[^\x20-\x7E]", " ", s).strip()[:200]


def load_subscription_urls(yaml_path):
    urls = []
    with open(yaml_path) as f:
        for line in f:
            m = re.match(r"\s*-\s*(https?://\S+)", line)
            if m:
                urls.append(m.group(1))
    return urls


def ensure_schema():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if DB_PATH.exists():
        DB_PATH.unlink()
    proc = subprocess.Popen(
        [str(BINARY)],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ, "XDG_CONFIG_HOME": str(CONFIG_DIR.parent)},
    )
    time.sleep(0.5)
    proc.communicate(input=b"q", timeout=5)
    proc.wait(timeout=5)
    assert DB_PATH.exists(), f"DB not created at {DB_PATH}"


def detect_protocol(url):
    if "://" not in url:
        return "unknown"
    return url.split("://")[0].lower()


def parse_vmess(url):
    b64 = url[8:]
    if "#" in b64:
        b64 = b64.split("#")[0]
    try:
        padded = b64 + "=" * (4 - len(b64) % 4) if len(b64) % 4 else b64
        raw = b64decode(padded)
        data = json.loads(raw)
    except Exception:
        return {}
    remarks = sanitize(data.get("ps", ""))
    return {
        "remarks": remarks,
        "address": data.get("add", ""),
        "port": int(data.get("port", 0)),
        "user_id": data.get("id", ""),
    }


def parse_vless(url):
    return _parse_userpass_url(url[8:])


def parse_trojan(url):
    return _parse_userpass_url(url[9:])


def _parse_userpass_url(rest):
    remarks = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        remarks = sanitize(unquote(frag))
    user_id = ""
    hostport = rest
    if "@" in rest:
        userinfo, hostport = rest.split("@", 1)
        user_id = unquote(userinfo)
    query = ""
    if "?" in hostport:
        hostport, query = hostport.split("?", 1)
    address = hostport
    port = 0
    if ":" in hostport:
        if hostport.startswith("["):
            m = re.match(r"^\[([^\]]+)\]:(\d+)$", hostport)
            if m:
                address = m.group(1)
                port = int(m.group(2))
        else:
            address, port_str = hostport.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                pass
    if not remarks and query:
        for part in query.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k in ("remarks", "name", "peer"):
                    remarks = sanitize(unquote(v))
    return {"remarks": remarks, "address": address, "port": port, "user_id": user_id}


def parse_shadowsocks(url):
    rest = url[5:]
    remarks = ""
    if "#" in rest:
        rest, remarks = rest.split("#", 1)
        remarks = sanitize(unquote(remarks))
    hostport = ""
    password = ""
    if "@" in rest:
        b64part, hp = rest.split("@", 1)
        hostport = hp
        try:
            padded = (
                b64part + "=" * (4 - len(b64part) % 4) if len(b64part) % 4 else b64part
            )
            decoded = b64decode(padded).decode("utf-8", errors="replace")
            if ":" in decoded:
                _, password = decoded.split(":", 1)
        except Exception:
            pass
    address = hostport
    port = 0
    if ":" in hostport:
        if hostport.startswith("["):
            m = re.match(r"^\[([^\]]+)\]:(\d+)$", hostport)
            if m:
                address = m.group(1)
                port = int(m.group(2))
        else:
            address, port_str = hostport.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                pass
    return {"remarks": remarks, "address": address, "port": port, "user_id": password}


def parse_shadowsocksr(url):
    b64 = url[6:]
    try:
        padded = b64 + "=" * (4 - len(b64) % 4) if len(b64) % 4 else b64
        decoded = b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        return {}
    parts = decoded.split(":")
    if len(parts) < 6:
        return {}
    host = parts[0]
    port = int(parts[1]) if parts[1].isdigit() else 0
    remarks = ""
    if "/?" in decoded:
        qpart = decoded.split("/?", 1)[1]
        for p in qpart.split("&"):
            if "=" in p:
                k, v = p.split("=", 1)
                if k in ("remarks", "name"):
                    try:
                        r = b64decode(v + "=" * (4 - len(v) % 4)).decode(
                            "utf-8", errors="replace"
                        )
                        remarks = sanitize(r)
                    except Exception:
                        remarks = v
    return {"remarks": remarks, "address": host, "port": port}


def parse_socks(url):
    return _parse_userpass_url(url.split("://", 1)[1])


def parse_http(url):
    return _parse_userpass_url(url.split("://", 1)[1])


def parse_simple(url):
    rest = url.split("://", 1)[1]
    remarks = ""
    if "#" in rest:
        rest, remarks = rest.split("#", 1)
        remarks = sanitize(unquote(remarks))
    user_id = ""
    if "@" in rest:
        userinfo, rest = rest.split("@", 1)
        user_id = unquote(userinfo)
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    address = rest
    port = 0
    if ":" in rest:
        if rest.startswith("["):
            m = re.match(r"^\[([^\]]+)\]:(\d+)$", rest)
            if m:
                address = m.group(1)
                port = int(m.group(2))
        else:
            address, port_str = rest.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                pass
    if not remarks and query:
        for part in query.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k in ("remarks", "name", "peer"):
                    remarks = sanitize(unquote(v))
    return {"remarks": remarks, "address": address, "port": port, "user_id": user_id}


PARSERS = {
    "vmess": parse_vmess,
    "vless": parse_vless,
    "trojan": parse_trojan,
    "ss": parse_shadowsocks,
    "ssr": parse_shadowsocksr,
    "socks": parse_socks,
    "socks5": parse_socks,
    "http": parse_http,
    "https": parse_http,
    "hysteria2": parse_simple,
    "hy2": parse_simple,
    "hysteria": parse_simple,
    "hy": parse_simple,
    "tuic": parse_simple,
    "naive+https": parse_simple,
    "naive+quic": parse_simple,
    "anytls": parse_simple,
    "shadowtls": parse_simple,
    "wireguard": parse_simple,
}


def parse_url(url):
    scheme = detect_protocol(url)
    parser = PARSERS.get(scheme)
    if parser:
        return parser(url)
    return {}


def main():
    yaml_path = Path(__file__).resolve().parent.parent / "large.yaml"
    urls = load_subscription_urls(yaml_path)
    assert len(urls) == 36, f"Expected 36 URLs, got {len(urls)}"
    print(f"Loading {len(urls)} subscription URLs...")

    ensure_schema()
    print(f"Schema created at {DB_PATH}")

    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")

    try:
        conn.execute(
            "ALTER TABLE profiles ADD COLUMN group_id TEXT REFERENCES groups(id)"
        )
        print("Added group_id column")
    except sqlite3.OperationalError:
        print("group_id exists")

    for i, sub_url in enumerate(urls):
        name = f"Sub-{i + 1:02d}"
        gid = f"group-{i + 1:04d}-{hashlib.md5(sub_url.encode()).hexdigest()[:8]}"
        conn.execute(
            "INSERT OR IGNORE INTO groups (id, name, subscription_url, subscription_enabled) VALUES (?, ?, ?, 1)",
            (gid, name, sub_url),
        )
        sid = f"sub-{i + 1:04d}-{hashlib.md5(sub_url.encode()).hexdigest()[:8]}"
        conn.execute(
            "INSERT OR IGNORE INTO subscriptions (id, group_id, url, status) VALUES (?, ?, ?, 'idle')",
            (sid, gid, sub_url),
        )
    conn.commit()
    print(f"Inserted 36 groups")

    fixture_files = sorted(FIXTURES_DIR.glob("m1n1-5ub-*.txt"))
    assert len(fixture_files) == 36

    total_profiles = 0
    failed_lines = 0

    for fi, fixture_file in enumerate(fixture_files):
        gid = f"group-{fi + 1:04d}-{hashlib.md5(urls[fi].encode()).hexdigest()[:8]}"
        with open(fixture_file, "r", errors="replace") as f:
            lines = f.readlines()

        pi = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            result = parse_url(line)
            if not result or not result.get("address"):
                failed_lines += 1
                continue

            proto = detect_protocol(line)
            ct = CONFIG_TYPE.get(proto, 0)
            pid = hashlib.md5(line.encode()).hexdigest()
            remarks = sanitize(result.get("remarks") or f"P{total_profiles}")
            address = result.get("address", "?")
            port = result.get("port", 0)
            uid = (result.get("user_id") or "")[:500]
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            sub_uid = abs(hash((ct, address, port, uid))) & 0x7FFFFFFFFFFFFFFF

            conn.execute(
                """INSERT OR IGNORE INTO profiles
                   (id, config_type, core_type, remarks, address, port, user_id,
                    is_sub, sub_id, group_id, sub_uid, sort_order,
                    is_active, created_at, updated_at)
                   VALUES (?, ?, 'auto', ?, ?, ?, ?,
                           1, ?, ?, ?, ?,
                           0, ?, ?)""",
                (
                    f"prof-{pid[:32]}",
                    ct,
                    remarks,
                    address,
                    port,
                    uid,
                    fi,
                    gid,
                    sub_uid,
                    pi,
                    now,
                    now,
                ),
            )
            pi += 1
            total_profiles += 1

        if fi % 10 == 0:
            conn.commit()

    conn.commit()
    conn.close()
    print(f"Inserted {total_profiles} profiles, {failed_lines} failed")

    conn2 = sqlite3.connect(str(DB_PATH))
    pcount = conn2.execute("SELECT COUNT(*) FROM profiles").fetchone()[0]
    gcount = conn2.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
    conn2.close()
    print(f"  Profiles: {pcount}  Groups: {gcount}")


if __name__ == "__main__":
    main()
