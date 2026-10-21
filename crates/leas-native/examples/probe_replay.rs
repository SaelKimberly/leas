//! Diagnostic harness: re-run the real-ping probe over a recorded failure set.
//!
//! Input is JSONL, one row per link, with the fields the probe needs plus the
//! in-batch outcome for comparison. Produce it from the live database with:
//!
//! ```text
//! sqlite3 -readonly ~/.config/leas/data.db "select json_object(
//!   'delay', s.latency_delay, 'host', e.host, 'port', e.port,
//!   'config', p.config, 'err', coalesce(s.error_text,''), 'grp', 'X')
//!   from profile_stats s
//!   join endpoints e on e.id = s.endpoint_id
//!   join protocols p on p.id = s.protocol_id
//!   where s.error_kind = 'real' limit 60;"
//! ```
//!
//! Usage: `cargo run --release -p leas-native --example probe_replay <file.jsonl> [concurrency] [timeout_secs]`
//!
//! The probe itself mirrors `leas::ops::ping_native` (HEAD to the ping URL
//! over one engine tunnel, per-attempt deadline) — the same policy the batch
//! runs, minus the retry fan-out, so a replayed result is comparable.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use leas_native::addr::TargetAddr;
use leas_native::context::NativeConnectParams;
use leas_native::probe::{self, ProbeMethod, ProbeRequest};
use leas_proto::proto_spec::{EndpointEssentials, ProtocolConfig};

/// The default `ping_url` (`app_config.rs`, default config).
const PING_HOST: &str = "www.gstatic.com";
const PING_PATH: &str = "/generate_204";
const PING_PORT: u16 = 443;

/// One recorded link: the endpoint address, its config JSON, the batch's own
/// fast delay and real-ping error text.
struct Row {
    delay: i64,
    host: String,
    port: u16,
    config: String,
    err: String,
    grp: String,
}

impl Row {
    fn from_json(value: &serde_json::Value) -> Option<Self> {
        let str_field = |key: &str| {
            value
                .get(key)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        Some(Self {
            delay: value
                .get("delay")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(-1),
            host: str_field("host"),
            port: u16::try_from(value.get("port").and_then(serde_json::Value::as_i64)?).ok()?,
            config: str_field("config"),
            err: str_field("err"),
            grp: str_field("grp"),
        })
    }
}

async fn run(row: Row, timeout: Duration) -> String {
    let fail = |stage: &str, detail: String| {
        format!(
            "{}\t{}:{}\tdelay={}\tFAIL[{stage}]\t{detail}\tin-batch: {}",
            row.grp, row.host, row.port, row.delay, row.err
        )
    };
    let Ok(config) = serde_json::from_str::<ProtocolConfig>(&row.config) else {
        return fail("parse", row.config.chars().take(80).collect());
    };
    let params = NativeConnectParams::new(
        config,
        EndpointEssentials::new(row.host.clone(), row.port),
        TargetAddr::new(PING_HOST, PING_PORT),
    );
    let request = ProbeRequest {
        host: PING_HOST,
        port: PING_PORT,
        https: true,
        method: ProbeMethod::Head,
        path: PING_PATH,
        timeout,
        transport_timeout: timeout,
    };
    let started = Instant::now();
    match probe::fetch(params, &request).await {
        Ok(response) => format!(
            "{}\t{}:{}\tdelay={}\tOK\tstatus={} probe={}ms wall={}ms\tin-batch: {}",
            row.grp,
            row.host,
            row.port,
            row.delay,
            response.status,
            response.elapsed.as_millis(),
            started.elapsed().as_millis(),
            row.err
        ),
        Err(e) => fail(
            "probe",
            format!("{:.1}s {e}", started.elapsed().as_secs_f64()),
        ),
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: <file.jsonl> [conc] [timeout]");
    let concurrency: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(20);
    let timeout = Duration::from_secs(args.next().and_then(|s| s.parse().ok()).unwrap_or(5));

    let text = std::fs::read_to_string(&path).expect("read jsonl");
    let rows: Vec<Row> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| Row::from_json(&serde_json::from_str(line).expect("jsonl row")))
        .collect();
    eprintln!(
        "{} rows, concurrency {concurrency}, timeout {timeout:?}",
        rows.len()
    );

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut set = tokio::task::JoinSet::new();
    for row in rows {
        let semaphore = semaphore.clone();
        set.spawn(async move {
            let _permit = semaphore.acquire_owned().await.expect("semaphore");
            run(row, timeout).await
        });
    }
    let mut lines = Vec::new();
    while let Some(joined) = set.join_next().await {
        lines.push(joined.expect("task"));
    }
    lines.sort();
    let ok = lines.iter().filter(|l| l.contains("\tOK\t")).count();
    for line in &lines {
        println!("{line}");
    }
    println!("=== {ok} ok / {} failed", lines.len() - ok);
}
