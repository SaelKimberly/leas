#!/usr/bin/env python3
"""Drive a traced `leas` release build through a PTY and report its CPU time.

`just memtrace-app` wraps this; read `docs/guides/tracing.md` first.

The sandbox is a copy: the app resolves its data directory as
`dirs::config_dir().join("leas")`, so with `HOME` pointed at a scratch directory
it reads `$HOME/.config/leas`, not `$XDG_CONFIG_HOME`. Getting that wrong
measures a fresh install instead of the profile database.

Options (env):
  HOME_SRC   real config dir to copy from   (default ~/.config/leas)
  SANDBOX    scratch root                   (default target/mem-trace/sandbox)
  TRACE_DIR  artifact output                (default target/mem-trace)
  DELAY      seconds before the app is asked to quit (default 12; the exit
             artifact is written after shutdown, so the drain must be generous)
  MIN_BYTES, INTERVAL, FOLD  passed through to the tracer
"""

import fcntl
import os
import pty
import resource
import select
import shutil
import signal
import sqlite3
import struct
import sys
import termios
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "release", "leas")
SANDBOX = os.environ.get("SANDBOX", os.path.join(ROOT, "target", "mem-trace", "sandbox"))
TRACE_DIR = os.environ.get("TRACE_DIR", os.path.join(ROOT, "target", "mem-trace"))
DELAY = float(os.environ.get("DELAY", "12"))


def stage() -> str:
    """Copy the real config directory into the sandbox and return its path."""
    src = os.path.expanduser(os.environ.get("HOME_SRC", "~/.config/leas"))
    dst = os.path.join(SANDBOX, ".config", "leas")
    # The trim below DELETEs rows. Never let it near a real installation: the
    # sandbox must be the script's own directory, resolved, and never the source.
    real_dst, real_src = os.path.realpath(dst), os.path.realpath(src)
    if real_dst == real_src or real_src.startswith(real_dst + os.sep):
        print(f"trace-app: refusing to stage into the source directory {real_dst}",
              file=sys.stderr)
        return None
    if not real_dst.startswith(os.path.realpath(os.path.join(ROOT, "target")) + os.sep):
        print(f"trace-app: note: sandbox {real_dst} is outside target/; "
              "the trim still only touches that copy", file=sys.stderr)
    os.makedirs(dst, exist_ok=True)
    for entry in ("data.db", "data.db-wal", "config.json", "geoip.dat", "geosite.dat",
                  "GeoLite2-City.mmdb"):
        path = os.path.join(src, entry)
        if os.path.exists(path):
            shutil.copy2(path, os.path.join(dst, entry))
    whitelist = os.path.join(src, "whitelist")
    if os.path.isdir(whitelist):
        shutil.copytree(whitelist, os.path.join(dst, "whitelist"), dirs_exist_ok=True)
    db_path = os.path.join(dst, "data.db")
    try:
        db = sqlite3.connect(db_path)
        # Due subscriptions turn a boot measurement into an import benchmark.
        db.execute("update groups set last_refreshed = ?", (int(time.time()),))
        # A 64k-row profile database keeps the UI busy enough that a scripted
        # `q` is not reliably read; a 3 000-row copy boots and quits. Only the
        # sandbox copy is trimmed.
        kept = "select id from endpoints limit 3000"
        rows = db.execute("select count(*) from endpoints").fetchone()[0]
        db.commit()
        if rows > 5000:
            for table in ("endpoint_ip", "profile_stats", "endpoint_rank"):
                columns = [row[1] for row in db.execute(f"pragma table_info({table})")]
                if "endpoint_id" in columns:
                    db.execute(f"delete from {table} where endpoint_id not in ({kept})")
            db.execute(f"delete from endpoints where id not in ({kept})")
            db.commit()
            # VACUUM refuses to run inside a transaction.
            db.execute("vacuum")
            after = db.execute("select count(*) from endpoints").fetchone()[0]
            print(f"trace-app: sandbox db trimmed {rows} -> {after} endpoints "
                  "(copy only)", file=sys.stderr)
        db.close()
    except sqlite3.Error as error:
        # A database that cannot be prepared produces a wrong measurement: the
        # run would trace a due-subscription import or an app that will not
        # quit. Fail the recipe instead of tracing it anyway.
        print(f"trace-app: could not prepare the sandbox database: {error}", file=sys.stderr)
        return None
    if not os.path.exists(db_path):
        print("trace-app: no database copied; this run profiles a fresh install",
              file=sys.stderr)
    return dst


def main() -> int:
    if not os.path.exists(BIN):
        print(f"trace-app: {BIN} is missing; build it with "
              "`cargo build --release -p leas --features mem-trace`", file=sys.stderr)
        return 2
    config = stage()
    if config is None:
        return 2
    env = dict(os.environ)
    env.pop("XDG_CONFIG_HOME", None)
    env.update({"HOME": SANDBOX, "LEAS_MEM_TRACE_DIR": TRACE_DIR})
    for key in ("MIN_BYTES", "INTERVAL", "FOLD"):
        value = os.environ.get(key)
        if value:
            env[f"LEAS_MEM_TRACE_{key}"] = value
    os.makedirs(TRACE_DIR, exist_ok=True)
    print(f"trace-app: sandbox {config}", file=sys.stderr)

    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(BIN, [BIN], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 200, 0, 0))
    started = time.time()
    while time.time() - started < DELAY:
        readable, _, _ = select.select([fd], [], [], 0.2)
        if readable:
            try:
                os.read(fd, 65536)
            except OSError:
                break
    for _ in range(3):
        try:
            os.write(fd, b"q")
        except OSError:
            break
        time.sleep(0.5)
    deadline = time.time() + 90
    while time.time() < deadline:
        done, _ = os.waitpid(pid, os.WNOHANG)
        if done:
            break
        readable, _, _ = select.select([fd], [], [], 0.2)
        if readable:
            try:
                os.read(fd, 65536)
            except OSError:
                break
    else:
        os.kill(pid, signal.SIGTERM)
    try:
        _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        status = 0
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    print(f"trace-app: elapsed {time.time() - started:.1f}s "
          f"cpu {usage.ru_utime + usage.ru_stime:.2f}s status {status}")
    print(f"trace-app: artifacts in {TRACE_DIR}")
    return 0 if status == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
