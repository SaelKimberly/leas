//! Telegram public-channel source.
//!
//! A channel page is a second [`UrlSource`], so the decoder, feed ceilings,
//! write-behind persistence and in-run dedup are the SAME code as an HTTP
//! subscription. `t.me/s/<channel>` is the public web preview: an HTML page of
//! the latest messages, paginated backwards with `?before=<message id>`.
//!
//! The page is parsed with `scraper` (Servo's `html5ever` + `selectors`): the
//! message list is `div.tgme_widget_message` and each message's text is its
//! LAST `div.tgme_widget_message_text` (a reply quote carries its own text
//! block above the message's). Text nodes are concatenated with `<br>` as a
//! line break and inline markup contributing no separator, so a share URL that
//! `t.me` split across an `<a>` or a `tg-emoji` is rejoined.
//!
//! Only text nodes carry share URLs. A URL in an `href` attribute is not read,
//! matching the reference implementation
//! (`thirdparty/sub-healer/src/mining/telegram.rs`).

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::Bytes;
use leas_config::app_config::ImportConfig;
use leas_config::import_export::ValidationSettings;
use leas_db::Database;
use scraper::{ElementRef, Html, Node, Selector};

use crate::ops::stream_import::{self, ImportOutcome, SourceBatch, UrlSource};
use crate::ops::subscriptions::PERSIST_CHUNK;
use crate::state::ProxyEndpoint;

/// Public web-preview origin. Tests point the crawl elsewhere.
const TG_ORIGIN: &str = "https://t.me";
/// Between two page fetches. `t.me` answers 429 to a burst, and a whole crawl
/// is one user-visible refresh.
const PAGE_DELAY: Duration = Duration::from_millis(50);
/// Deadline for one page (request + body). A preview page is a few hundred
/// KiB, so the shared 60 s read timeout (tuned for a 26 MB feed) is too slow a
/// failure for five pages of a user-visible refresh.
const PAGE_TIMEOUT: Duration = Duration::from_secs(30);
/// Pages one refresh may read. A settled channel stops on its watermark after
/// one page, so this only bounds a deep backlog: the run records the LOWEST id
/// it read, and the next refresh continues from there.
const MAX_PAGES: usize = 5;
/// `app_meta` key prefix for a group's lowest imported message id.
const WATERMARK_PREFIX: &str = "tg_watermark:";
/// One message container; its `data-post` attribute carries the message id.
static MESSAGE: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("div.tgme_widget_message").expect("valid message selector"));
/// One message's text block.
static MESSAGE_TEXT: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("div.tgme_widget_message_text").expect("valid text selector"));

/// Which fetch a group URL asks for. Derived from the URL: `groups.url` stores
/// both kinds and no schema change marks them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind {
    Http,
    /// Canonical channel page, `https://t.me/s/<name>`.
    Telegram(String),
}

/// Classify a group URL. `@name`, `t.me/name`, `t.me/s/name` and
/// `telegram.me/name` are channels; everything else is fetched as a
/// subscription.
#[must_use]
pub fn detect(url: &str) -> SourceKind {
    channel_name(url).map_or(SourceKind::Http, |name| {
        SourceKind::Telegram(format!("https://t.me/s/{name}"))
    })
}

/// The bare channel name in a channel URL or `@name`, `None` when the URL is
/// not a channel (a name holds only ASCII alphanumerics and `_`).
fn channel_name(url: &str) -> Option<&str> {
    let rest = url.trim();
    let rest = strip_prefix_ignore_case(rest, "https://")
        .or_else(|| strip_prefix_ignore_case(rest, "http://"))
        .unwrap_or(rest);
    let rest = strip_prefix_ignore_case(rest, "t.me/")
        .or_else(|| strip_prefix_ignore_case(rest, "telegram.me/"))
        .unwrap_or(rest);
    let rest = strip_prefix_ignore_case(rest, "s/").unwrap_or(rest);
    let name = rest.trim_start_matches('@');
    let name = name.split(['/', '?', '#']).next().unwrap_or_default();
    let is_channel = !name.is_empty()
        && name != "s"
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    is_channel.then_some(name)
}

/// `s` without `prefix`, compared ASCII-case-insensitively: a scheme and a host
/// are case-insensitive, while the channel name (the rest of the path) is not
/// and is returned exactly as typed.
fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// One channel message: its id (monotonic within a channel) and the share URLs
/// its text carries.
struct TgMessage {
    id: u32,
    urls: Vec<String>,
}

/// Every message on one preview page, newest first.
fn messages(html: &str) -> Vec<TgMessage> {
    let document = Html::parse_document(html);
    document
        .select(&MESSAGE)
        .filter_map(|message| {
            let id = message
                .attr("data-post")?
                .rsplit('/')
                .next()?
                .parse::<u32>()
                .ok()?;
            // A reply quote carries its own text block above the message's own
            // text, so the LAST one is this message's text.
            let urls = message
                .select(&MESSAGE_TEXT)
                .last()
                .map_or_else(Vec::new, |text| {
                    let mut plain = String::new();
                    text_of(text, &mut plain);
                    scan_urls(&plain)
                });
            Some(TgMessage { id, urls })
        })
        .collect()
}

/// Text of a subtree: text nodes concatenated, `<br>` a line break. Inline
/// markup contributes its text and no separator, so a share URL split across
/// nodes is rejoined.
fn text_of(element: ElementRef<'_>, out: &mut String) {
    for child in element.children() {
        if let Node::Text(text) = child.value() {
            out.push_str(text);
        } else if let Some(child) = ElementRef::wrap(child) {
            if child.value().name() == "br" {
                out.push('\n');
            } else {
                text_of(child, out);
            }
        }
    }
}

/// Share URLs in plain text, in order and with duplicates kept (the persist
/// path dedups by deterministic id).
fn scan_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut from = 0;
    while let Some(found) = text[from..].find("://") {
        let sep = from + found;
        let start = text[..sep]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '+'))
            .map_or(0, |i| i + 1);
        let end = text[sep + 3..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '`'))
            .map_or(text.len(), |i| sep + 3 + i);
        if is_share_scheme(&text[start..sep]) {
            let url = &text[start..end];
            // `t.me` cuts a long post with `…`; that URL is unrecoverable.
            if !url.contains('…') {
                urls.push(url.to_owned());
            }
        }
        from = end.max(sep + 3);
    }
    urls
}

/// Whether the importer can parse this scheme as a share URL: any known scheme
/// except the plain-URL, transport-not-a-proxy and unresolvable ones.
fn is_share_scheme(scheme: &str) -> bool {
    use leas_proto::SchemeX;
    use std::str::FromStr;
    SchemeX::from_str(scheme).is_ok_and(|scheme| {
        !matches!(
            scheme,
            SchemeX::Http
                | SchemeX::Https
                | SchemeX::Undefined
                | SchemeX::Unknown(_)
                | SchemeX::Socks
                | SchemeX::Naive
                | SchemeX::Tor
                | SchemeX::Ssh
                | SchemeX::Tailscale
        )
    })
}

/// The `app_meta` key holding a group's lowest imported message id.
///
/// The channel name is PART of the key: retargeting a group at another channel
/// must not inherit the old channel's ids, which are unrelated and would make
/// the crawl stop immediately. A superseded key is a few bytes of dead weight,
/// and `app_meta` has no delete door.
fn watermark_key(group_id: &str, name: &str) -> String {
    format!("{WATERMARK_PREFIX}{group_id}:{name}")
}

/// Backwards crawl of one channel's preview pages, one page per
/// [`UrlSource::next_chunk`].
///
/// Stops at the group's watermark (its lowest already-imported message id), at
/// an empty page, or after a page cap — whichever comes first. The watermark
/// always records the LOWEST id this crawl read, so a capped crawl continues
/// where it stopped on the next refresh and a re-read overlaps rather than
/// skips.
struct TelegramSource {
    client: reqwest::Client,
    /// First page (`…/s/<name>`), `?before=` is appended for the rest.
    page_url: String,
    /// Canonical channel URL for error text.
    label: String,
    /// Lowest message id already imported by an earlier run.
    watermark: Option<u32>,
    /// Id the next page ends before.
    before: Option<u32>,
    /// Lowest id this crawl read.
    lowest: Option<u32>,
    pages: usize,
    done: bool,
}

impl TelegramSource {
    fn new(client: reqwest::Client, name: &str, origin: &str, watermark: Option<u32>) -> Self {
        Self {
            client,
            page_url: format!("{origin}/s/{name}"),
            label: format!("https://t.me/s/{name}"),
            watermark,
            before: None,
            lowest: None,
            pages: 0,
            done: false,
        }
    }

    /// Lowest message id this crawl read, `None` when it read nothing.
    const fn lowest_processed(&self) -> Option<u32> {
        self.lowest
    }

    async fn next_page(&mut self) -> Option<SourceBatch> {
        // The cap is checked BEFORE the sleep and the request, so a capped
        // crawl neither waits nor asks for a page it will not read.
        if self.done || self.pages >= MAX_PAGES {
            return None;
        }
        if self.pages > 0 {
            tokio::time::sleep(PAGE_DELAY).await;
        }
        let url = self.before.map_or_else(
            || self.page_url.clone(),
            |before| format!("{}?before={before}", self.page_url),
        );
        let fetched = tokio::time::timeout(PAGE_TIMEOUT, async {
            let response = self.client.get(&url).send().await?;
            let status = response.status();
            let body = response.text().await?;
            Ok::<_, reqwest::Error>((status, body))
        })
        .await;
        let body = match fetched {
            Ok(Ok((status, body))) if status.is_success() => body,
            Ok(Ok((status, _))) => return Some(Err(format!("{url} answered {status}"))),
            Ok(Err(e)) => return Some(Err(format!("fetch of {url} failed: {e}"))),
            Err(_) => {
                return Some(Err(format!("{url} did not answer within {PAGE_TIMEOUT:?}")));
            }
        };
        let messages = messages(&body);
        if messages.is_empty() {
            self.done = true;
            if self.pages == 0 {
                return Some(Err(format!(
                    "{} has no public message preview (private or unknown channel)",
                    self.label
                )));
            }
            return None;
        }
        self.pages += 1;
        let mut chunk = String::new();
        for message in messages {
            if self
                .watermark
                .is_some_and(|watermark| message.id <= watermark)
            {
                self.done = true;
                break;
            }
            self.lowest = Some(self.lowest.map_or(message.id, |low| low.min(message.id)));
            for url in message.urls {
                chunk.push_str(&url);
                chunk.push('\n');
            }
        }
        if self.done {
            return (!chunk.is_empty()).then(|| Ok(Bytes::from(chunk)));
        }
        self.before = self.lowest;
        Some(Ok(Bytes::from(chunk)))
    }
}

impl UrlSource for TelegramSource {
    fn next_chunk(&mut self) -> Pin<Box<dyn Future<Output = Option<SourceBatch>> + Send + '_>> {
        Box::pin(self.next_page())
    }
}

/// Fetch a Telegram channel and import its share URLs.
///
/// Same outcome contract as [`stream_import::import_http_subscription`]:
/// partial-load semantics, and `ended_early` carries the reason when the
/// crawl died before its natural end.
pub async fn import_telegram_channel(
    channel: &str,
    user_agent: &str,
    db: &Arc<Database>,
    group_id: Option<&str>,
    validation: &ValidationSettings,
    budget: ImportConfig,
    proxy: Option<&ProxyEndpoint>,
) -> ImportOutcome {
    import_telegram_channel_at(
        TG_ORIGIN, channel, user_agent, db, group_id, validation, budget, proxy,
    )
    .await
}

/// [`import_telegram_channel`] with the origin injected — the crawl's test
/// seam, so the pagination runs against a local page server.
#[allow(
    clippy::too_many_arguments,
    reason = "mirrors import_http_subscription; `origin` is the test seam"
)]
pub(crate) async fn import_telegram_channel_at(
    origin: &str,
    channel: &str,
    user_agent: &str,
    db: &Arc<Database>,
    group_id: Option<&str>,
    validation: &ValidationSettings,
    budget: ImportConfig,
    proxy: Option<&ProxyEndpoint>,
) -> ImportOutcome {
    let Some(name) = channel_name(channel) else {
        return ImportOutcome {
            ended_early: Some(format!("`{channel}` is not a Telegram channel")),
            ..ImportOutcome::default()
        };
    };
    let client = match stream_import::http_client(user_agent, proxy) {
        Ok(client) => client,
        Err(reason) => {
            return ImportOutcome {
                ended_early: Some(reason),
                ..ImportOutcome::default()
            };
        }
    };
    let key = group_id.map(|group_id| watermark_key(group_id, name));
    let previous = match &key {
        Some(key) => match db.meta_get(key).await {
            Ok(value) => value.and_then(|value| value.parse::<u32>().ok()),
            Err(e) => {
                tracing::warn!(
                    target: "tui::ops::subscriptions",
                    "telegram watermark read failed: {e}"
                );
                None
            }
        },
        None => None,
    };
    let mut source = TelegramSource::new(client, name, origin, previous);
    let outcome = stream_import::run_streaming_import(
        &mut source,
        db,
        group_id,
        validation,
        PERSIST_CHUNK,
        None::<&fn(usize)>,
        budget,
    )
    .await;
    // A run that died mid-crawl must NOT move the watermark: the unread range
    // between the newest message and the failure point would be skipped.
    if outcome.ended_early.is_none()
        && let Some(key) = key
        && let Some(lowest) = source.lowest_processed()
    {
        let next = previous.map_or(lowest, |previous| previous.min(lowest));
        if Some(next) != previous
            && let Err(e) = db.meta_set(&key, &next.to_string()).await
        {
            tracing::warn!(
                target: "tui::ops::subscriptions",
                "telegram watermark write failed: {e}"
            );
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Markup structure captured from a live `t.me/s/<channel>` page, with every
    /// host and credential replaced by a test value: a `&amp;`-escaped config
    /// pair, a share URL split across an inline `<a>`, a post cut with `…`, and
    /// a post carrying only a plain link.
    const PAGE: &str = r#"<div class="tgme_widget_message js-widget_message" data-post="example_channel/900">
<div class="tgme_widget_message_text js-message_text" dir="auto"><blockquote expandable>vless://11111111-1111-4111-8111-111111111111@a.example.com:443?security=reality&amp;encryption=none&amp;type=tcp#Channel<br/>trojan://deadbeefdeadbeefdeadbeefdeadbeef@b.example.com:443?security=tls&amp;sni=example.com#Channel</blockquote></div>
<div class="tgme_widget_message_footer"><span class="tgme_widget_message_views">1.2K</span></div></div>
<div class="tgme_widget_message js-widget_message" data-post="example_channel/901">
<div class="tgme_widget_message_text js-message_text" dir="auto">ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0@<a href="http://c.example.com:43558/#tag" target="_blank" rel="noopener">c.example.com:43558#tag</a></div>
<div class="tgme_widget_message_footer"><span class="tgme_widget_message_views">2K</span></div></div>
<div class="tgme_widget_message js-widget_message" data-post="example_channel/902">
<div class="tgme_widget_message_text js-message_text" dir="auto">vless://22222222-2222-4222-8222-222222222222@d.example.com:443?security=reality&amp;sni=sni.example.com…</div>
<div class="tgme_widget_message_footer"><span class="tgme_widget_message_views">3K</span></div></div>
<div class="tgme_widget_message js-widget_message" data-post="example_channel/903">
<a class="tgme_widget_message_reply" href="https://t.me/other/1"><div class="tgme_widget_message_text js-message_reply_text" dir="auto">vless://33333333-3333-4333-8333-333333333333@reply.example.com:443#reply</div></a>
<div class="tgme_widget_message_text js-message_text" dir="auto">WG Tunnel update https://github.com/wgtunnel/android/releases/tag/5.8.2 👇</div>
<div class="tgme_widget_message_footer"><span class="tgme_widget_message_views">4K</span></div></div>"#;

    #[rstest]
    #[case::short_at("@ConfigV2rayNG", "ConfigV2rayNG")]
    #[case::bare_host("t.me/ConfigV2rayNG", "ConfigV2rayNG")]
    #[case::https("https://t.me/ConfigV2rayNG", "ConfigV2rayNG")]
    #[case::preview("https://t.me/s/ConfigV2rayNG", "ConfigV2rayNG")]
    #[case::telegram_me("https://telegram.me/ConfigV2rayNG", "ConfigV2rayNG")]
    #[case::query("https://t.me/ConfigV2rayNG?single=1", "ConfigV2rayNG")]
    #[case::uppercase_scheme_and_host("HTTPS://T.ME/ConfigV2rayNG", "ConfigV2rayNG")]
    fn channel_urls_resolve_to_the_bare_name(#[case] input: &str, #[case] name: &str) {
        assert_eq!(
            detect(input),
            SourceKind::Telegram(format!("https://t.me/s/{name}"))
        );
    }

    #[rstest]
    #[case::subscription("https://raw.githubusercontent.com/a/b/main/sub.txt")]
    #[case::localhost("http://127.0.0.1:8080/sub")]
    #[case::empty("")]
    #[case::no_channel("https://t.me/s/")]
    fn non_channel_urls_stay_http(#[case] input: &str) {
        assert_eq!(detect(input), SourceKind::Http);
    }

    #[test]
    fn extraction_keeps_share_urls_and_drops_broken_ones() {
        let parsed = messages(PAGE);
        assert_eq!(
            parsed.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![900, 901, 902, 903]
        );

        // `&amp;` decoded; the two configs stay separate lines.
        assert_eq!(
            parsed[0].urls,
            vec![
                "vless://11111111-1111-4111-8111-111111111111@a.example.com:443?security=reality&encryption=none&type=tcp#Channel",
                "trojan://deadbeefdeadbeefdeadbeefdeadbeef@b.example.com:443?security=tls&sni=example.com#Channel",
            ]
        );
        // The URL `t.me` split across the inline `<a>` is rejoined; the `href`
        // target is not read.
        assert_eq!(
            parsed[1].urls,
            vec!["ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0@c.example.com:43558#tag"]
        );
        // Cut by `…`: unrecoverable, dropped rather than stored truncated.
        assert!(parsed[2].urls.is_empty(), "{:?}", parsed[2].urls);
        // The reply quote holds its OWN text block carrying a share URL: only
        // the LAST text block is this message's, so the quoted URL is skipped.
        // Plain links are not proxies.
        assert!(
            !parsed[3]
                .urls
                .iter()
                .any(|url| url.contains("reply.example.com")),
            "the reply quote's URL must not be read as this message's: {:?}",
            parsed[3].urls
        );
        assert!(parsed[3].urls.is_empty(), "{:?}", parsed[3].urls);
    }

    /// How long the page server waits for the next request before it stops.
    const ACCEPT_IDLE: Duration = Duration::from_secs(5);

    /// Serve one page per connection and report the request lines in order.
    async fn serve_pages(pages: Vec<String>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            let mut requested = Vec::new();
            for page in pages {
                // A crawl that stops early (the page cap, a watermark) leaves
                // later pages unrequested; idle out instead of waiting forever.
                // The FIRST request is waited for without a deadline: the
                // caller is still opening its database. Idling only applies
                // between pages, where an absent request means the crawl
                // stopped early (the page cap, a watermark).
                let accepted = if requested.is_empty() {
                    listener.accept().await.ok()
                } else {
                    tokio::time::timeout(ACCEPT_IDLE, listener.accept())
                        .await
                        .ok()
                        .and_then(Result::ok)
                };
                let Some((mut stream, _)) = accepted else {
                    break;
                };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        break;
                    }
                    head.push(byte[0]);
                    assert!(head.len() < 8192, "request head too large");
                }
                requested.push(String::from_utf8_lossy(&head).into_owned());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
                    page.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
            requested
        });
        (format!("http://{addr}"), handle)
    }

    /// One message carrying a share URL unique to its id: the host is derived
    /// from the id, because the persist path dedups by `uid` and two messages
    /// with the same host would store as ONE link.
    fn message(id: u32) -> String {
        format!(
            r#"<div class="tgme_widget_message" data-post="chan/{id}"><div class="tgme_widget_message_text js-message_text">vless://6202b230-417c-4d8e-b624-0f71afa9c75d@m{id}.example.com:443?security=tls&amp;type=tcp#m{id}</div><div class="tgme_widget_message_footer"></div></div>"#
        )
    }

    fn page(ids: &[u32]) -> String {
        ids.iter().map(|id| message(*id)).collect()
    }

    #[tokio::test]
    async fn first_import_crawls_to_an_empty_page_and_records_the_lowest_id() {
        leas_core::ensure_tls_provider();
        let (origin, server) =
            serve_pages(vec![page(&[110, 109]), page(&[108, 107]), String::new()]).await;
        let db = Arc::new(Database::in_memory().await.expect("db"));
        let outcome = import_telegram_channel_at(
            &origin,
            "https://t.me/s/chan",
            "leas/0.1",
            &db,
            Some("g1"),
            &ValidationSettings::default(),
            ImportConfig::default(),
            None,
        )
        .await;

        assert!(outcome.ended_early.is_none(), "{outcome:?}");
        assert_eq!(outcome.links, 4);
        assert_eq!(
            db.meta_get(&watermark_key("g1", "chan"))
                .await
                .expect("read"),
            Some("107".to_owned())
        );
        let requested = server.await.expect("server");
        assert_eq!(requested.len(), 3);
        assert!(requested[0].starts_with("GET /s/chan "));
        assert!(requested[1].starts_with("GET /s/chan?before=109 "));
        assert!(requested[2].starts_with("GET /s/chan?before=107 "));
    }

    #[tokio::test]
    async fn watermark_stops_the_crawl_within_the_first_page() {
        leas_core::ensure_tls_provider();
        let (origin, server) = serve_pages(vec![page(&[110, 109, 107])]).await;
        let db = Arc::new(Database::in_memory().await.expect("db"));
        db.meta_set(&watermark_key("g1", "chan"), "107")
            .await
            .expect("seed watermark");
        let outcome = import_telegram_channel_at(
            &origin,
            "https://t.me/s/chan",
            "leas/0.1",
            &db,
            Some("g1"),
            &ValidationSettings::default(),
            ImportConfig::default(),
            None,
        )
        .await;

        assert!(outcome.ended_early.is_none(), "{outcome:?}");
        // 107 is at the watermark, so it is excluded along with everything older.
        assert_eq!(outcome.links, 2);
        assert_eq!(
            db.meta_get(&watermark_key("g1", "chan"))
                .await
                .expect("read"),
            Some("107".to_owned())
        );
        let requested = tokio::time::timeout(Duration::from_secs(15), server)
            .await
            .expect("server finished")
            .expect("server");
        assert_eq!(requested.len(), 1, "{requested:?}");
    }

    #[tokio::test]
    async fn a_failed_run_does_not_move_the_watermark() {
        leas_core::ensure_tls_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read_exact(&mut byte).await.is_err() {
                    break;
                }
                head.push(byte[0]);
            }
            let _ = stream
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
        });
        let db = Arc::new(Database::in_memory().await.expect("db"));
        let outcome = import_telegram_channel_at(
            &format!("http://{addr}"),
            "https://t.me/s/chan",
            "leas/0.1",
            &db,
            Some("g1"),
            &ValidationSettings::default(),
            ImportConfig::default(),
            None,
        )
        .await;

        // The REASON is pinned: a 500 on the first page must surface as the
        // HTTP failure, not as the no-preview or watermark path.
        let reason = outcome
            .ended_early
            .as_deref()
            .expect("failed run reports why");
        assert!(
            reason.ends_with("answered 500 Internal Server Error"),
            "{reason}"
        );
        assert_eq!(
            db.meta_get(&watermark_key("g1", "chan"))
                .await
                .expect("read"),
            None
        );
        handle.await.expect("server");
    }

    /// Retargeting a group at another channel must not inherit the old
    /// channel's ids: they are unrelated, and a stale watermark above them
    /// would stop the crawl on its first page and import nothing.
    #[tokio::test]
    async fn another_channels_watermark_does_not_bound_this_crawl() {
        leas_core::ensure_tls_provider();
        let (origin, server) = serve_pages(vec![page(&[100, 99]), String::new()]).await;
        let db = Arc::new(Database::in_memory().await.expect("db"));
        db.meta_set(&watermark_key("g1", "old_channel"), "107")
            .await
            .expect("seed the other channel's watermark");
        let outcome = import_telegram_channel_at(
            &origin,
            "https://t.me/s/chan",
            "leas/0.1",
            &db,
            Some("g1"),
            &ValidationSettings::default(),
            ImportConfig::default(),
            None,
        )
        .await;

        assert!(outcome.ended_early.is_none(), "{outcome:?}");
        assert_eq!(outcome.links, 2);
        assert_eq!(
            db.meta_get(&watermark_key("g1", "chan"))
                .await
                .expect("read"),
            Some("99".to_owned())
        );
        let requested = tokio::time::timeout(Duration::from_secs(15), server)
            .await
            .expect("server finished")
            .expect("server");
        assert_eq!(requested.len(), 2, "{requested:?}");
    }

    /// The cap bounds a channel with a deep backlog: one refresh reads
    /// `MAX_PAGES` pages and records only what it read, so the next refresh
    /// continues backwards instead of walking the whole history at once.
    #[tokio::test]
    async fn the_page_cap_bounds_a_backlog_and_the_watermark_keeps_place() {
        leas_core::ensure_tls_provider();
        let pages: Vec<String> = (0..=MAX_PAGES)
            .map(|index| {
                let high = 120 - u32::try_from(index * 2).expect("fits");
                page(&[high, high - 1])
            })
            .collect();
        let (origin, server) = serve_pages(pages).await;
        let db = Arc::new(Database::in_memory().await.expect("db"));
        let outcome = import_telegram_channel_at(
            &origin,
            "https://t.me/s/chan",
            "leas/0.1",
            &db,
            Some("g1"),
            &ValidationSettings::default(),
            ImportConfig::default(),
            None,
        )
        .await;

        assert!(outcome.ended_early.is_none(), "{outcome:?}");
        assert_eq!(outcome.links, MAX_PAGES * 2);
        // The lowest id of the LAST page read (page index MAX_PAGES - 1).
        let lowest = 120 - u32::try_from((MAX_PAGES - 1) * 2).expect("fits") - 1;
        assert_eq!(
            db.meta_get(&watermark_key("g1", "chan"))
                .await
                .expect("read"),
            Some(lowest.to_string())
        );
        let requested = tokio::time::timeout(Duration::from_secs(15), server)
            .await
            .expect("server finished")
            .expect("server");
        assert_eq!(requested.len(), MAX_PAGES, "{requested:?}");
    }

    /// A channel fetch is a source fetch: with a live tunnel it dials through
    /// that tunnel's `SOCKS5h` endpoint, exactly like an HTTP subscription. The
    /// proxy refuses the CONNECT, so no test ever reaches the real `t.me`.
    #[tokio::test]
    async fn a_channel_fetch_rides_the_live_tunnel() {
        leas_core::ensure_tls_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy bind");
        let proxy = ProxyEndpoint::from_inbound(
            "127.0.0.1",
            listener.local_addr().expect("proxy addr").port(),
        );
        let dial = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("proxy accept");
            let mut greeting = [0u8; 2];
            stream.read_exact(&mut greeting).await.expect("greeting");
            let mut methods = vec![0u8; usize::from(greeting[1])];
            stream.read_exact(&mut methods).await.expect("methods");
            stream.write_all(&[5, 0]).await.expect("auth reply");

            let mut head = [0u8; 4];
            stream.read_exact(&mut head).await.expect("request head");
            assert_eq!(head, [5, 1, 0, 3], "CONNECT by domain name");
            let mut domain_len = [0u8; 1];
            stream
                .read_exact(&mut domain_len)
                .await
                .expect("domain length");
            let mut domain = vec![0u8; usize::from(domain_len[0])];
            stream.read_exact(&mut domain).await.expect("domain");
            let mut target_port = [0u8; 2];
            stream.read_exact(&mut target_port).await.expect("port");
            // Host unreachable: the dial is proven, the network is not touched.
            stream
                .write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .expect("connect reply");
            (
                String::from_utf8(domain).expect("utf8 domain"),
                u16::from_be_bytes(target_port),
            )
        });
        let db = Arc::new(Database::in_memory().await.expect("db"));
        let outcome = import_telegram_channel(
            "https://t.me/s/chan",
            "leas/0.1",
            &db,
            Some("g1"),
            &ValidationSettings::default(),
            ImportConfig::default(),
            Some(&proxy),
        )
        .await;

        assert!(outcome.ended_early.is_some(), "{outcome:?}");
        assert_eq!(dial.await.expect("proxy"), ("t.me".to_owned(), 443));
    }
}
