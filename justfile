# ─── Quality gate ─────────────────────────────────────────────────
# Docs: https://github.com/casey/just
#
# `just quality-gate`            — every check, verbose report, all checks run even on failure
# `just quality-gate code`       — source checks only (fmt-check, clippy, nextest)
# `just quality-gate deps`       — dependency checks only (hakari-check, deny, machete, outdated, audit)
# `just quality-gate-ci`         — every check, minimal output, stops at first failure (exit 0/1, for CI)
# `just quality-gate-ci code|deps` — the same subsets in CI mode

# The gate recipes and the recipes below are bash scripts (`set -uo pipefail`,
# arrays, `case`). Pin the Windows interpreter so a Windows runner resolves it
# deterministically instead of falling back to whatever `sh` happens to be.
set windows-shell := ["bash", "-c"]

# ─── Fast local build (opt-in) ────────────────────────────────────
#
# The committed .cargo/config.toml is deliberately portable, so the host-tuned
# speedups live here, for LOCAL work only:
#
#   * sccache           — `RUSTC_WRAPPER` must resolve to a real binary.
#   * mold              — Linux only; the flag would break other linkers.
#   * target-cpu=native — a machine-specific CPU baseline. NEVER use that for an
#                         artifact meant to run elsewhere, and never in CI.
#
# Two consequences worth stating out loud:
#   1. perf numbers — `just bench` and the ignored perf labs — are comparable
#      only when the build went through this recipe; and
#   2. arguments are word-split, so quote-and-escape for anything exotic.
#
#   just fast cargo check -p leas-core
fast *args:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ "$(uname -s)" = "Linux" ]; then
        flags="-Clink-arg=-fuse-ld=mold -Ctarget-cpu=native"
    else
        flags=""
    fi
    export RUSTC_WRAPPER=sccache
    export RUSTFLAGS="${flags} ${RUSTFLAGS:-}"
    export LEAS_CORE_BIN_DIR="${LEAS_CORE_BIN_DIR:-/tmp/core-bin}"
    exec {{args}}

# Run the quality gate (verbose report). `target` selects the group:
# code | deps | all (default). Exit 0 = all passed, 1 = any failed.
quality-gate target='all':
    @just _gate report "{{target}}"

# Run the quality gate for CI (minimal output, stop at first failure). Exit 0/1.
quality-gate-ci target='all':
    @just _gate ci "{{target}}"

# ─── Individual checks ────────────────────────────────────────────

# Formatting check (rustfmt.toml pins edition/max_width/newline_style)
fmt-check mode='report':
    @cargo fmt --all --check

# cargo-hakari workspace-hack verification (.config/hakari.toml).
# Three distinct checks; `verify` alone does NOT catch staleness or a member
# missing the workspace-hack dep (why leas-route drifted):
#   generate --diff        workspace-hack Cargo.toml is up-to-date
#   manage-deps --dry-run  every workspace crate depends on the workspace-hack
#   verify                 each crate resolves to a single feature set
hakari-check mode='report':
    @cargo hakari generate --diff
    @cargo hakari manage-deps --dry-run
    @cargo hakari verify

# Clippy, all workspace targets and features, warnings denied
clippy mode='report':
    @cargo clippy --workspace --all-targets --all-features -- -D warnings

# Tests via cargo-nextest (.config/nextest.toml; `ci` mode uses the `ci` profile)
nextest mode='report':
    @cargo nextest run {{ if mode == "ci" { "--profile ci" } else { "" } }}

# cargo-deny: bans, licenses, sources (deny.toml); advisories are owned by `audit`
deny mode='report':
    @cargo deny check bans licenses sources

# Unused dependencies (ignores live in `[package/workspace.metadata.cargo-machete]`)
machete mode='report':
    @cargo machete --with-metadata --skip-target-dir

# Outdated direct dependencies. Informational by design (`--exit-code 0`):
# direct deps are kept at latest (the 2026-10-22 pass moved every direct dep to
# its latest stable release, semver-major included — zip 9, heed 0.23,
# parking_lot 0.13, lru 0.19, protox 0.10, uuid 1.28, hyper 1.12 and the rest
# — with the breakage fixed in `leas-core/src/log_heed.rs` for heed's new
# commit-scoped database API). The residual entries are transitive-only,
# graph-inherent dual-major pins in the generated leas-hakari, e.g. base64
# 0.22 via dns-stamp-parser/tantivy/tonic, compact_str 0.9 via ratatui-core
# 0.1.2, hashbrown 0.16 via lru 0.16 (NOT yaml-rust2, which moved to hashlink
# 0.12.2), nom 7 via cexpr/bindgen (turso_sdk_kit), itertools 0.14 via prost
# 0.14, lock_api 0.4 via dashmap 6, parking_lot 0.12 via arboard/crossterm/
# opaline, lru 0.18 via ratatui-core 0.1.2, constant_time_eq 0.4 via blake3,
# quinn-udp 0.5 via quinn 0.11, rand_core 0.6 via crypto-common 0.1 (turso's
# aes-gcm 0.10), tower-http 0.6 via reqwest 0.13, syn 2 vs 3, and the
# getrandom/windows-sys platform pins — only upstream bumps remove them, so a
# hard fail would keep the gate red indefinitely.
outdated mode='report':
    @cargo outdated --workspace --root-deps-only --exit-code 0 {{ if mode == "ci" { "--quiet" } else { "" } }}

# cargo-audit vulnerability scan (.cargo/audit.toml)
audit mode='report':
    @cargo audit {{ if mode == "ci" { "--quiet" } else { "" } }}

# ─── Gate runner (private) ────────────────────────────────────────

_gate mode target:
    #!/usr/bin/env bash
    set -uo pipefail
    mode="{{mode}}"
    target="{{target}}"
    case "$target" in
        code) tools=(fmt-check clippy nextest) ;;
        deps) tools=(hakari-check deny machete outdated audit) ;;
        all)  tools=(fmt-check clippy nextest hakari-check deny machete outdated audit) ;;
        *)
            echo "unknown gate target: $target (expected code | deps | all)" >&2
            exit 2
            ;;
    esac
    total=${#tools[@]}
    passed=0
    failed=()
    for tool in "${tools[@]}"; do
        echo
        echo "===== $tool ====="
        if just "$tool" "$mode" 2>&1; then
            echo "PASS: $tool"
            passed=$((passed + 1))
        else
            echo "FAIL: $tool"
            failed+=("$tool")
            if [ "$mode" = "ci" ]; then
                exit 1
            fi
        fi
    done
    echo
    echo "===== summary: $passed/$total passed ====="
    if [ "${#failed[@]}" -gt 0 ]; then
        printf 'failed: %s\n' "${failed[@]}"
        exit 1
    fi

# ─── Benchmarks ───────────────────────────────────────────────────
#
# `just bench`       — every criterion target (`throughput` needs real cores at
#                      $LEAS_CORE_BIN_DIR, see .cargo/config.toml)
# `just bench micro` — only the targets that need no external binaries
#
# Results land in ./.benchmarks (criterion.toml). `LEAS_BENCH_MB` sets the
# per-row transfer size (default 64) and is inherited from the environment.

# Run the criterion benchmarks. `target` selects the group: micro | all (default).
#
# LEAS_BENCH_MB defaults to 4 here, NOT to the harness default of 64:
# benches/baseline.md was captured at 4, and the recorded medians are only
# comparable at the same transfer size.
#
# LEAS_CORE_BIN_DIR is exported explicitly: `cargo criterion` launches the
# bench executable itself, so an unset variable makes the throughput rows print
# "SKIP ... is not set" while the run still exits 0. (The `[env]` default that
# used to cover this lived in .cargo/config.toml and is gone with the
# portability change.)
#
# Every criterion call goes through `just fast`, so the measured build carries
# the same rustflags as any other local measurement — without it the numbers are
# not comparable across time.
bench target='all':
    #!/usr/bin/env bash
    set -euo pipefail
    case "{{target}}" in
        micro|all) ;;
        *)
            echo "unknown bench target: {{target}} (expected micro | all)" >&2
            exit 2
            ;;
    esac
    : "${LEAS_BENCH_MB:=4}"
    : "${LEAS_CORE_BIN_DIR:=/tmp/core-bin}"
    export LEAS_BENCH_MB LEAS_CORE_BIN_DIR
    echo "LEAS_BENCH_MB=$LEAS_BENCH_MB LEAS_CORE_BIN_DIR=$LEAS_CORE_BIN_DIR"
    if [ "{{target}}" = all ] && { [ ! -x "$LEAS_CORE_BIN_DIR/xray" ] || [ ! -x "$LEAS_CORE_BIN_DIR/sing-box" ]; }; then
        echo "missing xray/sing-box in $LEAS_CORE_BIN_DIR — the throughput rows would skip silently" >&2
        echo "install the pinned versions or run 'just bench micro'" >&2
        exit 2
    fi
    just fast cargo criterion -p leas-tls    --bench record
    just fast cargo criterion -p leas-route  --bench decide
    just fast cargo criterion -p leas-native --bench dispatch
    # Hermetic Shadowsocks codec/KDF rows — no cores, no sockets, so micro-safe.
    just fast cargo criterion -p leas-native --bench ss_codec
    # Per-kind ProtocolId identity traversal — hermetic, micro-safe.
    just fast cargo criterion -p leas-proto  --bench identity
    just fast cargo criterion -p leas-native --features native-e2e --bench relay
    if [ "{{target}}" = all ]; then
        just fast cargo criterion -p leas-native --features native-e2e --bench throughput
    fi

# ─── Tier-3b test oracle: pinned SIP003 plugin binaries ────────────
#
# The Shadowsocks plugin rows (spec §9 tier 3b) need a real plugin, and
# neither core can host one: xray-core has no SIP003 support at all, and
# sing-box's SS *inbound* has no plugin field (only its outbound does, and
# in-process). So the server side is a real plugin binary.
#
#   $LEAS_PLUGIN_BIN_DIR   install target (default /tmp/plugin-bin)
#
# Two pins, both deliberate:
#   * v2ray-plugin — a PREBUILT release asset, sha256-verified. Its own
#     `-host` default is `cloudfront.com`, the fact spec §5.1 diverges from on
#     purpose (we follow sing-box, which uses the host only when the option is
#     present).
#   * obfs-local / obfs-server — simple-obfs v0.0.5, which is C (not the Go
#     port) and needs libev + autotools. Its published v0.0.5 asset is
#     Windows-only, so there is nothing to download. The binary speaks the env
#     contract shadowsocks-rust drives it with (SS_REMOTE_HOST /
#     SS_REMOTE_PORT / SS_LOCAL_HOST / SS_LOCAL_PORT / SS_PLUGIN_OPTIONS —
#     simple-obfs src/local.c:889-893). Name the **server** half:
#     `obfs-server` binds SS_REMOTE_PORT (src/server.c:1437-1438) and is what
#     `ssserver` must spawn; `obfs-local` is the client half and binds
#     SS_LOCAL_PORT (src/local.c:913) — the port ssserver already holds, so it
#     fails with EADDRINUSE on every fresh port.
#
# Never a CI requirement: tier 3b is opt-in, exactly like the core binaries.
PLUGIN_V2RAY_TAG := 'v1.3.2'
PLUGIN_V2RAY_SHA256 := 'b578514235b98b230f881aa2a01a7277205f85135bc09fc3832e5f3993ee541a'
PLUGIN_OBFS_TAG := 'v0.0.5'
PLUGIN_LIBEV_VERSION := '4.33'

# Install the pinned SIP003 plugin binaries the Shadowsocks plugin e2e rows need.
plugin-bins:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="${LEAS_PLUGIN_BIN_DIR:-/tmp/plugin-bin}"
    mkdir -p "$dir"

    # ── v2ray-plugin: prebuilt, checksum-verified ──
    # The release ASSET is named with hyphens, the binary INSIDE the tarball
    # with underscores — both are mapped here so neither guess reaches install.
    case "$(uname -m)" in
        x86_64|amd64) asset="linux-amd64"; inner="v2ray-plugin_linux_amd64" ;;
        aarch64|arm64) asset="linux-arm64"; inner="v2ray-plugin_linux_arm64" ;;
        *) echo "unsupported arch $(uname -m) for the pinned plugin assets" >&2; exit 2 ;;
    esac
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    url="https://github.com/shadowsocks/v2ray-plugin/releases/download/{{PLUGIN_V2RAY_TAG}}/v2ray-plugin-$asset-{{PLUGIN_V2RAY_TAG}}.tar.gz"
    echo "fetching $url"
    curl -fsSL -o "$tmp/vp.tar.gz" "$url"
    echo "{{PLUGIN_V2RAY_SHA256}}  $tmp/vp.tar.gz" | sha256sum -c -
    tar xzf "$tmp/vp.tar.gz" -C "$tmp"
    install -m 0755 "$tmp/$inner" "$dir/v2ray-plugin"

    # ── obfs: built from source. Two facts make this self-contained:
    #   * the published v0.0.5 asset is Windows-only, so there is nothing to
    #     download; and
    #   * libev (its only dependency) builds to a user prefix with no root, so
    #     the recipe needs neither sudo nor libev-dev. It goes into a TEMP
    #     prefix, and the binaries get an rpath, so nothing lands in $HOME and
    #     they run without LD_LIBRARY_PATH.
    prefix="$tmp/prefix"
    loader_path=""
    if [ ! -e /usr/include/ev.h ] && [ ! -e "$HOME/.local/include/ev.h" ] && ! pkg-config --exists libev 2>/dev/null; then
        echo "building libev into $prefix (no root needed)" >&2
        curl -fsSL -o "$tmp/libev.tar.gz" "https://dist.schmorp.de/libev/Attic/libev-{{PLUGIN_LIBEV_VERSION}}.tar.gz"
        tar xf "$tmp/libev.tar.gz" -C "$tmp"
        (
            cd "$tmp/libev-{{PLUGIN_LIBEV_VERSION}}"
            # static-only: see the LDFLAGS note below
            ./configure --prefix="$prefix" --disable-shared --enable-static >/dev/null
            make -j"$(nproc)" >/dev/null
            make install >/dev/null
        )
    elif [ -e "$HOME/.local/include/ev.h" ]; then
        prefix="$HOME/.local"
        loader_path="$prefix/lib"
        echo "using the user-local libev at $prefix" >&2
    else
        prefix=""
        echo "using the system libev" >&2
    fi
    shim="$tmp/shim"; mkdir -p "$shim"
    # configure hard-requires asciidoc + xmlto for the man pages; the binaries
    # do not use them, so stub rather than install two doc toolchains.
    for tool in asciidoc xmlto; do
        printf '#!/bin/sh\nexit 0\n' > "$shim/$tool"
        chmod +x "$shim/$tool"
    done
    git clone -q --depth 1 --recurse-submodules --branch {{PLUGIN_OBFS_TAG}} \
        https://github.com/shadowsocks/simple-obfs.git "$tmp/simple-obfs"
    (
        cd "$tmp/simple-obfs"
        # simple-obfs probes `-lev` and `ev.h` directly, so no pkg-config is
        # needed — only the include and library paths.
        if [ -n "$prefix" ]; then
            export CPPFLAGS="-I$prefix/include ${CPPFLAGS:-}"
            export LDFLAGS="-L$prefix/lib ${LDFLAGS:-}"
            # The obfs binaries link libev dynamically, and `$ORIGIN` does not
            # survive shell -> make -> ld intact (it arrives as the literal
            # `RIGIN`), so the loader path is reported below and the caller
            # passes it to the server that spawns `obfs-local`.
            loader_path="$prefix/lib"
        fi
        PATH="$shim:$PATH" ./autogen.sh >/dev/null 2>&1
        PATH="$shim:$PATH" ./configure >/dev/null
        PATH="$shim:$PATH" make -j"$(nproc)" >/dev/null
    )
    for bin in obfs-local obfs-server; do
        if [ ! -x "$tmp/simple-obfs/src/$bin" ]; then
            echo "build produced no $bin" >&2
            exit 2
        fi
        install -m 0755 "$tmp/simple-obfs/src/$bin" "$dir/$bin"
    done

    # ── verify both, loudly ──
    echo
    echo "installed in $dir:"
    if ! "$dir/v2ray-plugin" --help 2>&1 | grep -m1 -- '-host'; then
        echo "v2ray-plugin failed to run" >&2
        exit 2
    fi
    echo "  v2ray-plugin  {{PLUGIN_V2RAY_TAG}}  sha $(sha256sum "$dir/v2ray-plugin" | cut -c1-16)…"
    for bin in obfs-local obfs-server; do
        if ! "$dir/$bin" -v >/dev/null 2>&1 && ! "$dir/$bin" -h >/dev/null 2>&1; then
            echo "$bin failed to run" >&2
            exit 2
        fi
        echo "  $bin  simple-obfs {{PLUGIN_OBFS_TAG}}"
    done
    # The plugin's CHILD environment, written next to the binaries: a plugin-capable
    # ssserver spawns the plugin itself, so the plugin dir must be on PATH and libev
    # must be loadable by the child. `tests/plugin_sip003.rs` reads this file, so the
    # recipe is the single place that knows the loader path.
    {
        echo "export PATH=\"$dir\":\$PATH"
        [ -n "$loader_path" ] && echo "export LD_LIBRARY_PATH=\"$loader_path\":\$LD_LIBRARY_PATH"
    } > "$dir/plugin-env.sh"
    echo
    if [ -n "$loader_path" ]; then
        echo "wrote $dir/plugin-env.sh (PATH + the libev loader path); the obfs binaries"
        echo "need libev at runtime and the recipe has no say over a server that spawns them."
    else
        echo "wrote $dir/plugin-env.sh (system libev; no loader path needed)"
    fi
    echo
    echo "run the plugin rows with:"
    echo "  LEAS_PLUGIN_BIN_DIR=$dir \\"
    echo "    cargo test -p leas-native --features native-e2e --test plugin_sip003 -- --ignored"
    echo
    echo "(--ignored matters: the plugin rows live in an #[ignore]d test. Set"
    echo "LEAS_SSSERVER_BIN if the vendored thirdparty build is not present."
