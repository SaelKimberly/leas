//! SIP003 plugin options: the typed, **lossless** stored form of a
//! Shadowsocks plugin row.
//!
//! One `ss://` query carries the plugin in more shapes than the SIP003 text
//! suggests, and the captured feeds (`tests/fixtures/m1n1-5ub-*.txt`) exercise
//! all of them:
//!
//! | shape | example |
//! | --- | --- |
//! | name and options glued in one value | `?plugin=obfs-local;obfs=tls;obfs-host=x` |
//! | the same, percent-encoded | `?plugin=v2ray-plugin%3Bpath%3D%2F%E3%80%81%E3%80%81tls` |
//! | a query key named after the plugin, base64-JSON | `?v2ray-plugin=eyJwYXRoIjoi…` |
//! | obfs name with v2ray vocabulary | `?plugin=obfs-local;mode=websocket;mux=false` |
//! | `host:port` inside `obfs-host` | `?plugin=simple-obfs;obfs=tls;obfs-host=h:16569` |
//! | no options at all | `?plugin=obfs-local` |
//!
//! The parse here **never refuses** (spec §3's two-layer rule): every key lands
//! in a typed field or in [`PluginSpec::extra`], and every verdict is a
//! connect-time decision made by `capability::ss_reason`, so a row we cannot
//! serve stays importable, exportable, and correctly marked untestable. A
//! spelling that fell through to a *plugin-less* row would instead dial the bare
//! server — the one failure this whole change exists to remove.
//!
//! References: `thirdparty/sing-box/transport/sip003/{v2ray,obfs}.go` (the
//! option vocabulary and defaults), `thirdparty/sing-box/transport/simple-obfs/`
//! (the obfs wire), and the `args.go` bare-key-means-`1` rule.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::urlx::TinyText;

use super::{ProtoSpec, ProtocolConfig};

/// The option keys the v2ray-plugin family speaks.
pub const V2RAY_KEYS: &[&str] = &["mode", "host", "path", "tls", "mux"];

/// The option keys the obfs (simple-obfs) family speaks.
pub const OBFS_KEYS: &[&str] = &["obfs", "obfs-host"];

/// Which option **vocabulary** a row's keys speak.
///
/// This describes the keys present, not the name: a name-only row speaks no
/// vocabulary at all (its family comes from [`PluginFamily::for_name`] at
/// connect time), and a row that mixes both is [`Unknown`](Self::Unknown) with
/// every conflicting key preserved in [`PluginSpec::extra`] so the refusal can
/// name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginFamily {
    /// `obfs` / `obfs-host` — simple-obfs (`obfs-local`, `simple-obfs`).
    Obfs,
    /// `mode` / `host` / `path` / `tls` / `mux` — v2ray-plugin.
    V2Ray,
    /// A name with no known vocabulary (`kcptun`, a bare `obfs`, a mixed row).
    Unknown,
}

impl PluginFamily {
    /// The family a **name** implies, for a row that states no vocabulary.
    ///
    /// The name says which binary the operator installed; it is the fallback
    /// family, never a mode.
    #[must_use]
    pub fn for_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "obfs-local" | "simple-obfs" => Self::Obfs,
            "v2ray-plugin" => Self::V2Ray,
            _ => Self::Unknown,
        }
    }
}

/// The mode key's value. `Unset` is "the key was absent", which the wire has as
/// a real state distinct from any value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginMode {
    /// Absent — the family default applies at connect.
    Unset,
    /// obfs: the HTTP-request disguise.
    Http,
    /// obfs: the synthetic-TLS record writer (**not** a TLS handshake).
    Tls,
    /// v2ray-plugin: WebSocket (optionally inside TLS).
    Websocket,
    /// v2ray-plugin: QUIC transport (TLS forced by the plugin).
    Quic,
    /// A mode the row **states** that we do not implement, kept verbatim.
    ///
    /// Rewriting it to a default would be the silent misclassification this
    /// whole type exists to prevent: `obfs=websocket` (the legacy smux
    /// dialect) read as `http` would dial a server neither spelling describes.
    /// The connect-time refusal names the value.
    Invalid(String),
}

impl PluginMode {
    /// The default the family resolves `Unset` to.
    ///
    /// Applied at **parse** (see [`PluginSpec`]): the canonical export elides a
    /// default, so a row that stored "absent" would re-parse as a different
    /// stored form and a different uid (spec §3.1 rule 3).
    #[must_use]
    pub const fn default_for(family: PluginFamily) -> Self {
        match family {
            PluginFamily::Obfs => Self::Http,
            PluginFamily::V2Ray | PluginFamily::Unknown => Self::Websocket,
        }
    }

    /// Whether this mode is a **stream** shape.
    ///
    /// The mux predicate reads this (spec §5.2): a `mode=quic` row replaces
    /// dial + security + framing with the quinn dial, so there is no stream
    /// for a mux phase to wrap and `mux_active` must be false whatever the
    /// stored `mux` key says. An [`Self::Invalid`] mode is never a stream.
    #[must_use]
    pub const fn as_stream(&self) -> bool {
        matches!(self, Self::Unset | Self::Http | Self::Tls | Self::Websocket)
    }

    /// The wire name, as the option value spells it — `""` for `Unset`, and the
    /// operator's own text for an [`Self::Invalid`] value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Unset => "",
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Websocket => "websocket",
            Self::Quic => "quic",
            Self::Invalid(value) => value,
        }
    }

    /// The option value to write back out, or `None` when the stored mode IS the
    /// family default (the export elides defaults, which is what keeps an
    /// absent key and an explicit default on one row).
    ///
    /// An [`Self::Invalid`] value always renders: dropping it would export
    /// a row that no longer says what it refuses about.
    #[must_use]
    pub fn rendered_value(&self) -> Option<String> {
        if let Self::Invalid(value) = self {
            return Some(value.clone());
        }
        let rendered = self.as_str();
        (!rendered.is_empty()).then(|| rendered.to_string())
    }

    /// Parse a `mode` (v2ray) or `obfs` (obfs-family) value, keeping anything
    /// unrecognized as [`Self::Invalid`] rather than dropping it.
    #[must_use]
    pub fn parse(family: PluginFamily, value: &str) -> Self {
        match (family, value.to_ascii_lowercase().as_str()) {
            (PluginFamily::V2Ray, "websocket" | "ws") => Self::Websocket,
            (PluginFamily::V2Ray, "quic") => Self::Quic,
            (PluginFamily::Obfs, "http") => Self::Http,
            (PluginFamily::Obfs, "tls") => Self::Tls,
            // A cross-family value (`obfs=websocket`) is preserved verbatim.
            _ => Self::Invalid(value.to_string()),
        }
    }
}

/// A presence-only flag that still has to survive a garbage value.
///
/// `Invalid(v)` keeps the operator's own text verbatim so the connect-time
/// refusal can quote it instead of inventing a reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsSetting {
    /// Key absent.
    Unset,
    /// `tls`, `tls=1`, JSON `true`.
    On,
    /// `tls=0`, JSON `false`.
    Off,
    /// Present with a value we do not accept; refused at connect.
    Invalid(String),
}

impl TlsSetting {
    /// Parse a `tls` option value. A bare key arrives as `1` (`args.go`).
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Self::On,
            "0" | "false" | "no" | "off" => Self::Off,
            _ => Self::Invalid(value.to_string()),
        }
    }

    /// The value to write back out, or `None` when at its default/`Unset`.
    #[must_use]
    pub fn value(&self) -> Option<&str> {
        match self {
            Self::On => Some("1"),
            Self::Off => Some("0"),
            Self::Invalid(v) => Some(v),
            Self::Unset => None,
        }
    }
}

/// The `mux` option: concurrency cap, off, absent, or unparseable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MuxSetting {
    /// Key absent — resolves at connect (websocket: on, quic: off).
    Unset,
    /// `mux=0` / `mux=false`.
    Off,
    /// `mux=8`, `mux=true` → `On(1)`.
    On(u32),
    /// Present with a value we do not accept; refused at connect.
    Invalid(String),
}

impl MuxSetting {
    /// Parse a `mux` option value. A bare key arrives as `1` (`args.go`).
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Self::On(1),
            "0" | "false" | "no" | "off" => Self::Off,
            // `-1` (unlimited) and every other integer-shaped value: the
            // option is a cap, and a cap of -1 is not expressible as u32, so
            // keep the text and let the refusal name it.
            _ => value
                .trim()
                .parse::<u32>()
                .map_or_else(|_| Self::Invalid(value.to_string()), Self::On),
        }
    }

    /// The value to write back out, or `None` when at its default/`Unset`.
    #[must_use]
    pub fn value(&self) -> Option<String> {
        match self {
            Self::On(n) => Some(n.to_string()),
            Self::Off => Some("0".to_string()),
            Self::Invalid(v) => Some(v.clone()),
            Self::Unset => None,
        }
    }

    /// Whether mux is requested, at connect time.
    ///
    /// `Unset` resolves to the family/mode default: websocket multiplexes
    /// (upstream's `mux=1`), quic never does (`main.go` `case "quic"` leaves
    /// `connectionReuse` false, and both references agree). Only the **resolved**
    /// value is ever a predicate — the stored key is not (spec §5.2).
    #[must_use]
    pub const fn active_for(&self, mode: &PluginMode) -> bool {
        match self {
            Self::Unset => matches!(mode, PluginMode::Unset | PluginMode::Websocket),
            Self::On(_) => mode.as_stream(),
            Self::Off | Self::Invalid(_) => false,
        }
    }
}

/// A SIP003 plugin row's options — the total, lossless stored form.
///
/// The type is **total**: every combination the wire can produce is
/// representable, so parsing never has to panic, never has to drop a key, and
/// never has to invent a vocabulary. Invariant (pinned by a test): `family ==
/// Unknown` ⟺ `mode == Unset` — a name we know nothing about carries no mode,
/// and a row with a mode has a family.
///
/// `family` and `mode` are **normalized at parse**: an absent mode key stores
/// the family's default, and a row with no vocabulary keys takes the family its
/// name implies. That is what makes the export fixed point hold (spec §3.1 rule
/// 3) — the canonical export elides a default, so storing "absent" would
/// re-parse as a different stored form and a different uid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PluginSpec {
    /// The wire name, verbatim — an open string. Never normalized away and
    /// never validated away: `obfs-local`, `simple-obfs`, `obfs`, `kcptun` …
    /// An **empty** name means options arrived without one, which the
    /// connect-time refusal names (spec §3.2 rule 5).
    pub name: TinyText,
    /// The vocabulary this row speaks — from its keys, else from its name.
    pub family: PluginFamily,
    /// The mode: the key's value, else the family's default, else `Unset` for
    /// a name we know nothing about.
    pub mode: PluginMode,
    /// The host, verbatim. An unparseable `:port` suffix stays here rather than
    /// being dropped (see [`Self::port`]).
    pub host: Option<TinyText>,
    /// The `:port` suffix of `obfs-host`, when it parsed. It feeds the obfs
    /// `Host` header only — never the dial.
    pub port: Option<u16>,
    pub path: Option<TinyText>,
    /// The `tls` key (v2ray family; the obfs family's TLS is [`Self::mode`]).
    pub tls: TlsSetting,
    pub mux: MuxSetting,
    /// Every key the typed fields do not own, verbatim and sorted: `obfs-uri`,
    /// an unknown key, a future upstream option, and the keys of a mixed-
    /// vocabulary row (which must stay intact for the refusal to name them).
    pub extra: BTreeMap<String, String>,
}

impl Default for PluginSpec {
    fn default() -> Self {
        Self {
            name: TinyText::default(),
            family: PluginFamily::Unknown,
            mode: PluginMode::Unset,
            host: None,
            port: None,
            path: None,
            tls: TlsSetting::Unset,
            mux: MuxSetting::Unset,
            extra: BTreeMap::new(),
        }
    }
}

impl PluginSpec {
    /// Split a SIP003 option string into `(name, options)`, where the first
    /// token without `=` becomes the name.
    ///
    /// This is the one splitter both the URL and the form path use.
    #[must_use]
    pub fn split(value: &str) -> (Option<String>, BTreeMap<String, String>) {
        Self::split_with(value, true)
    }

    /// The splitter, told whether a bare first token may become the name.
    ///
    /// It may only when no name is known yet: `plugin=v2ray-plugin;…;tls` ends
    /// in a bare `tls`, and a splitter that always treats the first bare token
    /// as the name would consume the option and lose it — which is the
    /// difference between a wss row and a plaintext one.
    #[must_use]
    fn split_with(value: &str, take_name: bool) -> (Option<String>, BTreeMap<String, String>) {
        let mut name = None;
        let mut opts = BTreeMap::new();
        for token in value.split(';') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            match token.split_once('=') {
                Some((k, v)) => {
                    opts.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                }
                None => {
                    // A bare key means the value `1` (`args.go`), unless the
                    // slot is still open for the name.
                    if take_name && name.is_none() {
                        name = Some(token.to_string());
                    } else {
                        opts.insert(token.to_ascii_lowercase(), "1".to_string());
                    }
                }
            }
        }
        (name, opts)
    }

    /// Build a spec from a name and a `;`-joined option string — the **form**
    /// and **Clash** entry point, and the same splitter the URL path uses, so
    /// neither is a second dialect.
    #[must_use]
    pub fn from_parts(name: Option<&str>, opts: &str) -> Self {
        // A supplied name closes the name slot, so a bare option key stays an
        // option instead of stealing it.
        let (glued_name, map) = Self::split_with(opts, name.is_none());
        let name = name.map(str::to_string).or(glued_name).unwrap_or_default();
        Self::assemble(name, map)
    }

    /// Build a spec from a parsed URL query — the single constructor
    /// [`crate::proto_spec::SsConfig::try_parse_proto`] calls.
    ///
    /// Handles, in order: the `plugin` value (glued name + options), a separate
    /// `plugin_opts` value (merged **over** the glued options, so a feed that
    /// sets both is deterministic), and the base64-JSON spelling where a query
    /// key *named* after a known plugin carries a JSON object.
    #[must_use]
    pub fn from_query(params: &[(String, String)]) -> Option<Self> {
        // The `plugin` value, when present, contributes BOTH the name and the
        // first option set; a separate `plugin_opts` then merges over it.
        let (glued_name, glued) =
            query_value(params, "plugin").map_or_else(|| (None, BTreeMap::new()), Self::split);
        let mut name: Option<String> = glued_name;
        let mut map: BTreeMap<String, String> = glued;
        if let Some(raw) = query_value(params, "plugin_opts") {
            let (_, explicit) = Self::split_with(raw, false);
            // Explicit wins over inline: the same key set from two places has one
            // answer, and the one a reader would expect is the dedicated key.
            map.extend(explicit);
        }
        if name.is_none() {
            // The base64-JSON spelling: a query key named after a known plugin,
            // whose value decodes to a flat JSON object. Today this imports as a
            // plugin-LESS row and dials the bare server.
            for (key, value) in params {
                if PluginFamily::for_name(key) == PluginFamily::Unknown {
                    continue;
                }
                name = Some(key.clone());
                match Self::decode_flat_json(value) {
                    Some(fields) => {
                        map.extend(fields);
                    }
                    None => {
                        // Not a flat object of scalars: preserved, not rejected.
                        // The refusal names this key at connect.
                        map.insert(key.to_ascii_lowercase(), value.clone());
                    }
                }
                break;
            }
        }

        if name.is_none() && map.is_empty() {
            return None;
        }
        let spec = Self::assemble(name.unwrap_or_default(), map);
        Some(spec)
    }

    /// The canonical `;`-joined option string: every non-default typed field,
    /// then every `extra` entry, sorted by key.
    ///
    /// The one renderer, shared by `reconstruct_proto`, `to_clash` and
    /// `inject_singbox` — the three export paths that must not disagree.
    #[must_use]
    pub fn render_opts(&self) -> String {
        let mut out: BTreeMap<String, String> = self.extra.clone();
        // The keys are chosen by the row's EFFECTIVE family — the observed
        // vocabulary, else the one its name implies. Hashing or writing the
        // stored `family` field instead would break the fixed point: a
        // name-only `plugin=v2ray-plugin` row stores `Unknown` (no keys to
        // observe) but resolves to V2Ray, and a `mode=` written for a
        // V2Ray row must come back as a V2Ray row.
        let family = self.effective_family();
        // An explicit default is ELIDED (identity rule (c), and the export
        // fixed point depends on it). An `Invalid` value is never a default, so
        // it always writes — dropping it would export a row that no longer says
        // what it refuses about.
        if let Some(value) = self.mode.rendered_value()
            && !(self.name_agrees()
                && self.mode == PluginMode::default_for(family)
                && !matches!(self.mode, PluginMode::Invalid(_)))
        {
            if let Some(key) = Self::key_for(family, "mode", "obfs") {
                out.insert(key.to_string(), value);
            } else {
                // No vocabulary at all: keep the value under the v2ray key so
                // the row stays lossless (it re-parses as a V2Ray row, which
                // is what the effective family already claims).
                out.insert("mode".to_string(), value);
            }
        }
        if let Some(host) = &self.host {
            let mut value = host.to_string();
            if let Some(port) = self.port {
                value.push(':');
                value.push_str(&port.to_string());
            }
            let key = Self::key_for(family, "host", "obfs-host").unwrap_or("host");
            out.insert(key.to_string(), value);
        }
        if let Some(path) = &self.path {
            out.insert("path".to_string(), path.to_string());
        }
        if let Some(value) = self.tls.value() {
            out.insert("tls".to_string(), value.to_string());
        }
        if let Some(value) = self.mux.value() {
            out.insert("mux".to_string(), value);
        }
        out.into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(";")
    }

    /// The option key a family spells for one concept: `v2ray_key` for the
    /// v2ray-plugin family, `obfs_key` for simple-obfs, `None` for a row with
    /// no vocabulary.
    ///
    /// ONE mapping, used by every family-specific key (`mode`/`obfs` and
    /// `host`/`obfs-host`). The two were spelled separately at first, and the
    /// obfs row's host was written under the v2ray `host` key — which re-parsed
    /// as a *v2ray* row. A third family key can now only be added here.
    const fn key_for(
        family: PluginFamily,
        v2ray_key: &'static str,
        obfs_key: &'static str,
    ) -> Option<&'static str> {
        match family {
            PluginFamily::V2Ray => Some(v2ray_key),
            PluginFamily::Obfs => Some(obfs_key),
            PluginFamily::Unknown => None,
        }
    }

    /// The family this row resolves to at connect time: the observed
    /// vocabulary, else the one its name implies.
    #[must_use]
    pub fn effective_family(&self) -> PluginFamily {
        match self.family {
            PluginFamily::Unknown => PluginFamily::for_name(&self.name),
            known => known,
        }
    }

    /// Whether the row's NAME implies the same family its keys were read as.
    ///
    /// This is the condition for eliding a default, in BOTH the renderer and
    /// the identity writer — and it is why those two agree. A row whose name
    /// contradicts its keys (`obfs-local;mode=websocket`, corpus 24:7251)
    /// cannot drop the key that carries the disagreement: the name alone
    /// re-derives the OTHER family, so the export would come back as a
    /// different row. One rule, two call sites.
    #[must_use]
    pub fn name_agrees(&self) -> bool {
        self.family == PluginFamily::for_name(&self.name)
    }

    /// The mode this row resolves to — the stored mode, or the family default
    /// for a name we only know the family of. Borrowed, because the default is a
    /// temporary for a family-only row.
    #[must_use]
    pub fn resolved_mode(&self) -> PluginMode {
        if matches!(self.mode, PluginMode::Unset) {
            PluginMode::default_for(self.effective_family())
        } else {
            self.mode.clone()
        }
    }

    /// Whether this row wants TLS on its session — `tls` set, or a QUIC
    /// transport, which forces it (`main.go` `case "quic"` sets `*tlsEnabled`).
    ///
    /// One predicate, read by `LinkContext::is_tls` and by the mux predicate, so
    /// the two cannot disagree (spec §5.2).
    #[must_use]
    pub fn needs_tls(&self) -> bool {
        self.tls == TlsSetting::On || self.resolved_mode() == PluginMode::Quic
    }

    /// Whether the production path must use the mux protocol phase.
    ///
    /// `mux_active(link) == resolved_mode.is_stream() && resolved_mux > 0` — the
    /// **resolved** value, never the stored key: a `mode=quic` row may store
    /// `mux=1` while resolving to off, and routing it to `connect_mux` would
    /// have no stream to wrap (the quinn dial replaces dial + framing).
    #[must_use]
    pub fn mux_active(&self) -> bool {
        let mode = self.resolved_mode();
        mode.as_stream() && self.mux.active_for(&mode)
    }

    /// Whether a TCP fast probe says ANYTHING about this row (§8.1 item 4).
    ///
    /// `FastPingManager` picks its adapter from `ProtocolKind` alone, so an SS
    /// row always takes `TcpPingAdapter` and the plugin mode is not an input. For
    /// a datagram-mode row the server port is UDP, so the probe's TCP connect is
    /// refused and the row is recorded as a hard fast failure — the UI would be
    /// advertising a TCP measurement of a server that does not speak TCP.
    ///
    /// Read the row's own **resolved** mode, never the stored key: a row that
    /// merely mentions `mode=quic` in an unusable spelling still resolves to a
    /// stream mode and IS fast-probeable.
    #[must_use]
    pub fn tcp_fast_probe_is_meaningful(&self) -> bool {
        self.resolved_mode().as_stream()
    }

    /// The SNI for a TLS plugin row: the stated `security.tls.sni`, else the
    /// plugin's `host` **when it states one**, else the endpoint host — sing-box's
    /// rule (`transport/sip003/v2ray.go:48-51` sets `ServerName` only when the
    /// key is present; `:59` falls back to the server address). `cloudfront.com`
    /// is the ws `Host` default and is never an SNI.
    ///
    /// Returns `None` for every non-TLS row: `obfs=http` and `obfs=tls` have no
    /// TLS session, and inventing a name from the obfs `Host` would make the
    /// whitelist verdict a false statement about the row.
    #[must_use]
    pub fn sni(&self, stated: Option<&str>, endpoint_host: &str) -> Option<String> {
        if let Some(sni) = stated {
            return Some(sni.to_string());
        }
        if !self.needs_tls() {
            return None;
        }
        Some(
            self.host
                .as_ref()
                .map_or_else(|| endpoint_host.to_string(), TinyText::to_string),
        )
    }

    /// Assemble the typed form from a name and the raw option map.
    fn assemble(name: String, mut map: BTreeMap<String, String>) -> Self {
        let has_v2ray = V2RAY_KEYS.iter().any(|k| map.contains_key(*k));
        let has_obfs = OBFS_KEYS.iter().any(|k| map.contains_key(*k));

        // A mixed row is stored with BOTH vocabularies intact and refused at
        // connect naming the two conflicting keys — guessing would dial a server
        // neither spelling describes.
        if has_v2ray && has_obfs {
            return Self {
                name: TinyText::from(name),
                family: PluginFamily::Unknown,
                mode: PluginMode::Unset,
                extra: map,
                ..Self::default()
            };
        }

        // No vocabulary keys: the NAME says which family this is, and the mode
        // normalizes to that family's default. Normalizing here — rather than
        // storing "absent" and resolving at connect — is what keeps the export
        // fixed point (spec §3.1 rule 3): the canonical export elides a
        // default, so a row that stored "absent" would re-parse as a *different*
        // stored form and therefore a different uid. `Unknown` stays `Unset`: a
        // name we know nothing about gets no guessed mode.
        let family = match (has_v2ray, has_obfs) {
            (true, _) => PluginFamily::V2Ray,
            (_, true) => PluginFamily::Obfs,
            _ => PluginFamily::for_name(&name),
        };

        let mode_key = if has_obfs { "obfs" } else { "mode" };
        let mode = match map.remove(mode_key) {
            Some(value) => PluginMode::parse(family, &value),
            None if family == PluginFamily::Unknown => PluginMode::Unset,
            None => PluginMode::default_for(family),
        };
        let tls = map
            .remove("tls")
            .map_or(TlsSetting::Unset, |value| TlsSetting::parse(&value));
        let mux = map
            .remove("mux")
            .map_or(MuxSetting::Unset, |value| MuxSetting::parse(&value));
        let path = map.remove("path").map(TinyText::from);

        // `obfs-host=host:port`: the port reaches the obfs `Host` header only.
        // An unparseable suffix keeps the whole raw value in `host`, so the
        // refusal can quote it instead of the row losing it.
        let (host, port) = map.remove("obfs-host").map_or_else(
            || (map.remove("host").map(TinyText::from), None),
            |value| {
                let (host, port) = value.rsplit_once(':').map_or_else(
                    || (value.clone(), None),
                    |(h, p)| {
                        if h.is_empty() {
                            return (value.clone(), None);
                        }
                        p.trim().parse::<u16>().map_or_else(
                            |_| (value.clone(), None),
                            |port| (h.to_string(), Some(port)),
                        )
                    },
                );
                (Some(TinyText::from(host)), port)
            },
        );

        Self {
            name: TinyText::from(name),
            family,
            mode,
            host,
            port,
            path,
            tls,
            mux,
            extra: map,
        }
    }

    /// Decode the base64-JSON spelling into `(key, value)` pairs.
    ///
    /// Only a **flat object of string/boolean scalars** is accepted; JSON
    /// booleans become `1`/`0` so they meet the same `args.go` bare-key rule the
    /// `;`-joined form does. Anything else is `None`, and the caller preserves
    /// the raw value instead of rejecting the row.
    fn decode_flat_json(value: &str) -> Option<BTreeMap<String, String>> {
        let bytes = decode_base64_lenient(value)?;
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        let object = parsed.as_object()?;
        let mut out = BTreeMap::new();
        for (key, value) in object {
            let text = match value {
                serde_json::Value::String(text) => text.clone(),
                serde_json::Value::Bool(flag) => if *flag { "1" } else { "0" }.to_string(),
                _ => return None,
            };
            out.insert(key.to_ascii_lowercase(), text);
        }
        Some(out)
    }
}

/// The SNI a link actually puts on the wire — **one** owner for the whole tree.
///
/// sing-box's rule (`transport/sip003/v2ray.go:48-51` sets `ServerName` only when the `host`
/// key is present; `:59` falls back to the server address), with `cloudfront.com` the ws
/// `Host` header default and never an SNI:
///
/// 1. an explicitly stated `security.tls.sni`;
/// 2. else the plugin's `host`, **when it states one**;
/// 3. else the endpoint host;
/// 4. else `None` — and `None` for every row with no TLS session (`obfs=http`,
///    `obfs=tls`, a plain ws row), because there is no name to verify and inventing
///    one from the obfs `Host` would make a whitelist verdict a false statement.
///
/// Two callers, one answer: the engine (`LinkContext::server_name`, which falls back to
/// the endpoint host when this is `None`) and the enrichment path (`extract_sni`, which
/// needs the `None`).
#[must_use]
pub fn link_sni(config: &ProtocolConfig, endpoint_host: &str) -> Option<String> {
    let stated = config.security().and_then(|security| security.sni());
    let endpoint = || Some(stated.unwrap_or(endpoint_host).to_string());
    match config {
        // A plugin row answers from the spec (which knows whether the row has a
        // TLS session at all); every other row — including a plugin-less
        // Shadowsocks row — is `security`'s SNI or the endpoint host.
        ProtocolConfig::Ss(ss) => ss
            .plugin
            .as_ref()
            .map_or_else(endpoint, |plugin| plugin.sni(stated, endpoint_host)),
        _ => endpoint(),
    }
}

/// First value for `key`, case-insensitively (the feeds mix cases freely).
fn query_value<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

/// Base64 in either alphabet, padded or not.
fn decode_base64_lenient(value: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let value = value.trim();
    for engine in [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(value) {
            return Some(bytes);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn spec(name: &str, opts: &str) -> PluginSpec {
        PluginSpec::from_parts(Some(name), opts)
    }

    #[test]
    fn glued_name_and_options_split_on_semicolon() {
        let s = spec(
            "v2ray-plugin",
            "path=/kpnzyxsj;host=fn600mlines021.svcline.com;tls",
        );
        assert_eq!(s.name.as_str(), "v2ray-plugin");
        assert_eq!(s.family, PluginFamily::V2Ray);
        assert_eq!(
            s.mode,
            PluginMode::Websocket,
            "no mode key → the family default"
        );
        assert_eq!(s.resolved_mode(), PluginMode::Websocket);
        assert_eq!(s.path.as_deref(), Some("/kpnzyxsj"));
        assert_eq!(s.host.as_deref(), Some("fn600mlines021.svcline.com"));
        assert_eq!(s.tls, TlsSetting::On);
        assert!(s.extra.is_empty(), "every key is owned: {:?}", s.extra);
    }

    /// Corpus m1n1-5ub-1.txt:4264 — obfs=tls with an `obfs-uri` the reference
    /// ignores. Refusing it would make a WORKING row untestable.
    #[test]
    fn obfs_uri_is_preserved_and_not_owned() {
        let s = spec("obfs-local", "obfs-uri=/;obfs=tls;obfs-host=IsiBugSendiri");
        assert_eq!(s.family, PluginFamily::Obfs);
        assert_eq!(s.mode, PluginMode::Tls);
        assert_eq!(s.host.as_deref(), Some("IsiBugSendiri"));
        assert_eq!(s.extra.get("obfs-uri").map(String::as_str), Some("/"));
    }

    /// Corpus m1n1-5ub-21.txt:3563 — `obfs-host=host:port`; the port feeds the
    /// obfs `Host` header and nothing else.
    #[test]
    fn obfs_host_splits_its_port() {
        let s = spec(
            "simple-obfs",
            "obfs=tls;obfs-host=df1fab2.dl.nintendo.net:16569",
        );
        assert_eq!(s.host.as_deref(), Some("df1fab2.dl.nintendo.net"));
        assert_eq!(s.port, Some(16569));
    }

    /// An unparseable suffix must not cost the row its host.
    #[test]
    fn unparseable_port_suffix_stays_in_host() {
        let s = spec("obfs-local", "obfs=http;obfs-host=example.com:notaport");
        assert_eq!(s.host.as_deref(), Some("example.com:notaport"));
        assert_eq!(s.port, None);
    }

    /// Corpus m1n1-5ub-24.txt:7251 — an obfs NAME with the v2ray vocabulary.
    /// The vocabulary wins, or the row would dial a server no such spelling
    /// describes.
    #[test]
    fn vocabulary_beats_the_name() {
        let s = spec("obfs-local", "mode=websocket;mux=false");
        assert_eq!(s.family, PluginFamily::V2Ray);
        assert_eq!(s.mode, PluginMode::Websocket);
        assert_eq!(s.mux, MuxSetting::Off);
        assert!(!s.mux_active(), "mux=false is not mux");
    }

    /// A mixed row keeps BOTH vocabularies intact for the refusal to name.
    #[test]
    fn mixed_vocabulary_is_preserved_not_guessed() {
        let s = spec("obfs-local", "obfs=http;mode=websocket");
        assert_eq!(s.family, PluginFamily::Unknown);
        assert_eq!(s.mode, PluginMode::Unset);
        assert_eq!(s.extra.get("obfs").map(String::as_str), Some("http"));
        assert_eq!(s.extra.get("mode").map(String::as_str), Some("websocket"));
        assert!(s.host.is_none() && s.path.is_none());
    }

    /// The total-type invariant: a name we have no vocabulary for.
    #[test]
    fn unknown_name_stores_as_unknown_and_unset() {
        let s = spec("kcptun", "key=abc");
        assert_eq!(s.family, PluginFamily::Unknown);
        assert_eq!(s.mode, PluginMode::Unset);
        assert_eq!(s.extra.get("key").map(String::as_str), Some("abc"));
        assert_eq!(s.effective_family(), PluginFamily::Unknown);
    }

    /// Options without a name (the form's independent optionals, a Clash YAML
    /// with only `plugin-opts`) must not become a plugin-LESS row.
    #[test]
    fn options_without_a_name_are_stored_not_dropped() {
        let s = PluginSpec::from_parts(None, "obfs=http;obfs-host=example.com");
        assert_eq!(s.name.as_str(), "");
        assert_eq!(s.family, PluginFamily::Obfs);
        assert_eq!(s.mode, PluginMode::Http);
        assert_eq!(s.host.as_deref(), Some("example.com"));
    }

    /// `VlessConfig` has no mux field; here the plugin's `mux` must be
    /// boolean-tolerant because v2rayN emits `mux=false` (corpus 24:7251) while
    /// upstream spells it as an integer.
    #[test]
    fn mux_accepts_bools_and_integers() {
        assert_eq!(spec("v2ray-plugin", "mux=true").mux, MuxSetting::On(1));
        assert_eq!(spec("v2ray-plugin", "mux=8").mux, MuxSetting::On(8));
        assert_eq!(spec("v2ray-plugin", "mux=0").mux, MuxSetting::Off);
        assert_eq!(spec("v2ray-plugin", "mux").mux, MuxSetting::On(1));
        assert!(matches!(
            spec("v2ray-plugin", "mux=many").mux,
            MuxSetting::Invalid(_)
        ));
        assert!(
            matches!(spec("v2ray-plugin", "mux=-1").mux, MuxSetting::Invalid(_)),
            "-1 is a cap we cannot hold in u32; the refusal quotes it"
        );
    }

    /// `tls` carries a real boolean in the base64-JSON spelling, so presence-only
    /// reading would turn `"tls":false` into a handshake against a plaintext
    /// port.
    #[test]
    fn tls_distinguishes_presence_from_false() {
        assert_eq!(spec("v2ray-plugin", "tls").tls, TlsSetting::On);
        assert_eq!(spec("v2ray-plugin", "tls=1").tls, TlsSetting::On);
        assert_eq!(spec("v2ray-plugin", "tls=0").tls, TlsSetting::Off);
        assert_eq!(spec("v2ray-plugin", "tls=false").tls, TlsSetting::Off);
        assert!(matches!(
            spec("v2ray-plugin", "tls=maybe").tls,
            TlsSetting::Invalid(_)
        ));
    }

    /// An absent mode key normalizes to the family default at parse, so an
    /// absent key and an explicit default are literally the same stored row —
    /// which is what the export fixed point needs. `needs_tls` follows from it.
    #[test]
    fn defaults_normalize_at_parse_so_the_row_is_one() {
        let obfs = spec("obfs-local", "obfs-host=x");
        assert_eq!(
            obfs.mode,
            PluginMode::Http,
            "an absent key stores the default"
        );
        assert_eq!(
            obfs,
            spec("obfs-local", "obfs=http;obfs-host=x"),
            "one row, one uid"
        );
        assert!(!obfs.needs_tls(), "obfs http is a plain head");

        let tls_obfs = spec("obfs-local", "obfs=tls");
        assert_eq!(tls_obfs.resolved_mode(), PluginMode::Tls);
        assert!(
            !tls_obfs.needs_tls(),
            "obfs tls is a synthetic record writer, not a session"
        );

        let ws = spec("v2ray-plugin", "host=x");
        assert_eq!(ws.resolved_mode(), PluginMode::Websocket);
        assert_eq!(
            ws,
            spec("v2ray-plugin", "mode=websocket;host=x"),
            "one row, one uid"
        );
        assert!(!ws.needs_tls(), "a plain ws row must not get a handshake");

        let wss = spec("v2ray-plugin", "host=x;tls");
        assert!(wss.needs_tls());

        let quic = spec("v2ray-plugin", "mode=quic");
        assert!(quic.needs_tls(), "the plugin forces TLS for quic");
    }

    /// The stored-vs-resolved distinction that decides the production dispatch:
    /// a quic row may STORE `mux=1` while resolving off, and must never reach
    /// the mux phase — the quinn dial leaves it no stream to wrap.
    #[test]
    fn stored_mux_never_dispatches_a_quic_row_to_mux() {
        let quic = spec("v2ray-plugin", "mode=quic;mux=1");
        assert_eq!(quic.mux, MuxSetting::On(1));
        assert_eq!(quic.resolved_mode(), PluginMode::Quic);
        assert!(!quic.mux_active(), "no stream exists to wrap");

        let ws = spec("v2ray-plugin", "mode=websocket");
        assert!(ws.mux_active(), "websocket defaults to mux on");

        let ws_off = spec("v2ray-plugin", "mode=websocket;mux=0");
        assert!(!ws_off.mux_active());
    }

    /// sing-box's rule: the plugin `host` is the SNI only when the key is
    /// present, else the endpoint host; `cloudfront.com` is never an SNI.
    #[test]
    fn sni_follows_sing_box_presence_gating() {
        // The SNI only exists on a TLS session, so the first case must ask
        // about a `tls` row — a `host` with no `tls` is a plaintext ws row and
        // has no name to verify.
        let stated = spec("v2ray-plugin", "host=cdn.example;tls");
        assert_eq!(
            stated.sni(None, "server.example").as_deref(),
            Some("cdn.example")
        );
        assert_eq!(
            stated
                .sni(Some("explicit.example"), "server.example")
                .as_deref(),
            Some("explicit.example")
        );

        let host_less = spec("v2ray-plugin", "tls");
        assert_eq!(
            host_less.sni(None, "server.example").as_deref(),
            Some("server.example")
        );
        assert_ne!(
            host_less.sni(None, "a.example").as_deref(),
            Some("cloudfront.com")
        );

        assert_eq!(
            spec("obfs-local", "obfs=http").sni(None, "x").as_deref(),
            None
        );
        assert_eq!(
            spec("obfs-local", "obfs=tls").sni(None, "x").as_deref(),
            None
        );
        assert_eq!(
            spec("v2ray-plugin", "host=x").sni(None, "y").as_deref(),
            None,
            "no `tls` key means no TLS session, so no SNI at all"
        );
    }

    /// Every raw key lands in exactly one place — typed or `extra`, never both
    /// and never dropped.
    #[test]
    fn no_key_is_ever_owned_twice_or_dropped() {
        let s = spec(
            "v2ray-plugin",
            "mode=websocket;host=h;path=/p;tls=1;mux=4;obfs-uri=/;zz=1",
        );
        let mut owned: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        if s.mode != PluginMode::Unset {
            owned.insert("mode".to_string());
        }
        if s.host.is_some() {
            owned.insert("host".to_string());
        }
        if s.path.is_some() {
            owned.insert("path".to_string());
        }
        if s.tls != TlsSetting::Unset {
            owned.insert("tls".to_string());
        }
        if s.mux != MuxSetting::Unset {
            owned.insert("mux".to_string());
        }
        for key in s.extra.keys() {
            assert!(!owned.contains(key), "{key} is owned twice");
            owned.insert(key.clone());
        }
        let expected: std::collections::BTreeSet<String> =
            ["mode", "host", "path", "tls", "mux", "obfs-uri", "zz"]
                .iter()
                .map(|k| (*k).to_string())
                .collect();
        assert_eq!(owned, expected);
    }

    /// The export fixed point: `render_opts` → re-parse is **behaviourally**
    /// the same spec, which is what makes
    /// `uid(parse(u)) == uid(parse(export(parse(u))))` hold.
    ///
    /// Structural equality is deliberately NOT asserted: an explicit default
    /// (`mode=websocket`) is elided on export by design, so the re-parsed spec
    /// stores `Unset` where the first stored the value. Asserting equality here
    /// would assert the opposite of identity rule (c).
    #[test]
    fn render_then_reparse_is_behaviourally_identical() {
        for (name, opts) in [
            (
                "v2ray-plugin",
                "mode=websocket;host=h;path=/p;tls=1;mux=4;obfs-uri=/;zz=1",
            ),
            ("obfs-local", "obfs=http;obfs-host=example.com:8080"),
            ("v2ray-plugin", "host=cdn.example;tls=1"),
            ("v2ray-plugin", "mux=8"),
            ("obfs-local", "obfs=tls"),
            ("v2ray-plugin", "mode=quic;mux=1"),
        ] {
            let first = spec(name, opts);
            let rendered = first.render_opts();
            let (name_again, map_again) = PluginSpec::split(&rendered);
            let second =
                PluginSpec::assemble(name_again.unwrap_or_else(|| name.to_string()), map_again);
            assert_eq!(first.name, second.name, "{opts} rendered as {rendered}");
            assert_eq!(first.family, second.family, "{opts} rendered as {rendered}");
            assert_eq!(
                first.resolved_mode(),
                second.resolved_mode(),
                "{opts} rendered as {rendered}"
            );
            assert_eq!(
                first.needs_tls(),
                second.needs_tls(),
                "{opts} rendered as {rendered}"
            );
            assert_eq!(
                first.mux_active(),
                second.mux_active(),
                "{opts} rendered as {rendered}"
            );
            assert_eq!(first.host, second.host, "{opts} rendered as {rendered}");
            assert_eq!(first.port, second.port, "{opts} rendered as {rendered}");
            assert_eq!(first.path, second.path, "{opts} rendered as {rendered}");
            assert_eq!(first.tls, second.tls, "{opts} rendered as {rendered}");
            assert_eq!(first.mux, second.mux, "{opts} rendered as {rendered}");
            assert_eq!(first.extra, second.extra, "{opts} rendered as {rendered}");
        }
    }

    /// An explicit default renders as nothing, an absent key stays absent: the
    /// two forms share one `Protocol` row (identity elision, spec §4).
    #[test]
    fn defaults_elide_and_non_defaults_survive() {
        assert_eq!(spec("obfs-local", "obfs=http").render_opts(), "");
        assert_eq!(spec("obfs-local", "obfs=tls").render_opts(), "obfs=tls");
        assert_eq!(spec("v2ray-plugin", "mode=websocket").render_opts(), "");
        assert_eq!(spec("v2ray-plugin", "mode=quic").render_opts(), "mode=quic");
        assert_eq!(spec("v2ray-plugin", "tls=0").render_opts(), "tls=0");
        assert_eq!(spec("v2ray-plugin", "mux=8").render_opts(), "mux=8");
    }

    /// The corpus's own payload (m1n1-5ub-20.txt:8014, decoded): path, a
    /// **boolean** `mux`, host, mode and a boolean `tls` — the shape that makes
    /// presence-only reading wrong for both keys at once.
    #[test]
    fn base64_json_spelling_flattens_booleans() {
        let raw = base64::engine::general_purpose::STANDARD.encode(
            br#"{"path":"\/kpnzyxsj","mux":true,"host":"fn600mlines021.svcline.com","mode":"websocket","tls":true}"#,
        );
        let params = vec![("v2ray-plugin".to_string(), raw)];
        let s = PluginSpec::from_query(&params).expect("the base64-JSON spelling parses");
        assert_eq!(s.name.as_str(), "v2ray-plugin");
        assert_eq!(s.family, PluginFamily::V2Ray);
        assert_eq!(s.mode, PluginMode::Websocket);
        assert_eq!(
            s.mux,
            MuxSetting::On(1),
            "a JSON boolean meets the bare-key rule"
        );
        assert_eq!(s.tls, TlsSetting::On);
        assert_eq!(s.path.as_deref(), Some("/kpnzyxsj"));
        assert_eq!(s.host.as_deref(), Some("fn600mlines021.svcline.com"));
        assert!(s.extra.is_empty());
        assert!(
            s.mux_active(),
            "websocket defaults to mux on, and it is active"
        );
    }

    /// Not a flat object of scalars → the **raw wire value** is preserved under
    /// its query key: never rejected, never a plugin-less row.
    #[test]
    fn base64_json_non_object_is_preserved() {
        let raw = base64::engine::general_purpose::STANDARD.encode(br#"{"nested":{"a":1}}"#);
        let params = vec![("v2ray-plugin".to_string(), raw.clone())];
        let s = PluginSpec::from_query(&params).expect("stored, not rejected");
        assert_eq!(s.name.as_str(), "v2ray-plugin");
        assert_eq!(
            s.extra.get("v2ray-plugin").map(String::as_str),
            Some(raw.as_str()),
            "the operator's own text, so the refusal can quote it"
        );
        assert_eq!(
            s.family,
            PluginFamily::V2Ray,
            "the name still says which family this is"
        );
        assert_eq!(
            s.mode,
            PluginMode::Websocket,
            "normalized, not guessed from the payload"
        );
    }

    /// `plugin_opts` merged over the glued options: the dedicated key wins, so a
    /// feed that sets both is deterministic.
    #[test]
    fn plugin_opts_wins_over_the_glued_value() {
        let params = vec![
            (
                "plugin".to_string(),
                "v2ray-plugin;path=/glued;host=a".to_string(),
            ),
            ("plugin_opts".to_string(), "path=/explicit".to_string()),
        ];
        let s = PluginSpec::from_query(&params).expect("parses");
        assert_eq!(s.path.as_deref(), Some("/explicit"));
        assert_eq!(
            s.host.as_deref(),
            Some("a"),
            "the non-conflicting key survives"
        );
    }

    #[test]
    fn no_plugin_query_is_no_spec() {
        assert!(PluginSpec::from_query(&[]).is_none());
        assert!(
            PluginSpec::from_query(&[("insecure".to_string(), "1".to_string())]).is_none(),
            "an unrelated query key is not a plugin"
        );
    }

    /// The Clash path must normalize values exactly like the query path. Its
    /// `plugin_opts` is a bare string, so `mux=true` arrives at `from_parts`
    /// **unnormalized** — and the corpus has no such row, so only a test
    /// catches a divergence here. It matters: the identical
    /// `?plugin=v2ray-plugin;mux=true` row connects, and a Clash one that
    /// landed in `Invalid("true")` would be refused for a spelling difference.
    #[test]
    fn the_clash_path_normalizes_booleans_like_the_query_path() {
        for opts in ["mux=true", "mux=false", "tls=true", "tls=0"] {
            let via_clash = PluginSpec::from_parts(Some("v2ray-plugin"), opts);
            let (_, pairs) = PluginSpec::split(opts);
            let via_query = PluginSpec::assemble("v2ray-plugin".to_string(), pairs);
            assert_eq!(
                via_clash, via_query,
                "{opts} must parse identically either way"
            );
        }
        assert_eq!(
            PluginSpec::from_parts(Some("v2ray-plugin"), "mux=true").mux,
            MuxSetting::On(1),
            "a Clash boolean must not land in Invalid"
        );
        assert_eq!(
            PluginSpec::from_parts(Some("v2ray-plugin"), "tls=false").tls,
            TlsSetting::Off,
            "a Clash `tls=false` must not be read as TLS on"
        );
    }

    /// An unrecognized mode keeps the operator's text. Without this the value
    /// would land in neither a typed field nor `extra`, and the row would
    /// silently connect with the family's default framing instead of returning
    /// the named refusal (spec §3.1 rule 1).
    #[test]
    fn an_unrecognized_mode_keeps_its_text() {
        let s = spec("obfs-local", "obfs=websocket");
        assert_eq!(
            s.family,
            PluginFamily::Obfs,
            "the name is a known obfs family"
        );
        assert_eq!(
            s.mode,
            PluginMode::Invalid("websocket".to_string()),
            "the value is preserved, not rewritten to a default"
        );
        assert!(
            !s.mode.as_stream(),
            "and it is not a stream shape we can serve"
        );
        assert_eq!(
            s.render_opts(),
            "obfs=websocket",
            "so the export still says what the refusal is about"
        );
    }

    /// The two spellings the corpus mixes: an obfs NAME carrying the v2ray
    /// vocabulary, and the reverse. Each must keep the key that carries the
    /// disagreement, or the name alone re-derives the other family on re-import.
    #[test]
    fn a_name_that_contradicts_its_keys_keeps_them() {
        let obfs_name = spec("obfs-local", "mode=websocket");
        assert_eq!(obfs_name.effective_family(), PluginFamily::V2Ray);
        assert!(!obfs_name.name_agrees());
        assert_eq!(
            obfs_name.render_opts(),
            "mode=websocket",
            "the mode is the family's default but it is the ONLY thing that says v2ray"
        );

        let v2ray_name = spec("v2ray-plugin", "obfs=tls");
        assert_eq!(v2ray_name.effective_family(), PluginFamily::Obfs);
        assert!(!v2ray_name.name_agrees());
        assert_eq!(v2ray_name.render_opts(), "obfs=tls");
    }
}
