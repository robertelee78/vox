//! A link card (ADR-028 F-10): what a message carrying a URL says about the page, fetched once by
//! the **sender's** node and placed in the encrypted message, so a reader's node never contacts
//! the linked site.
//!
//! **Only public addresses are fetched.** An agent can be talked into posting a URL, and a card
//! puts what it found into the room: so a host that resolves to a loopback, link-local,
//! unspecified, private (10/8, 172.16/12, 192.168/16, fc00::/7) or shared (100.64/10) address is
//! never fetched, and the message goes without a card. The address checked is the one connected
//! to, pinned for the request, and every redirect is checked again.
//!
//! **Bounded**: one page and one image, at most [`DEADLINE`] in all, [`MAX_REDIRECTS`] redirects,
//! [`MAX_PAGE`] bytes of the page read; an image larger than [`MAX_IMAGE`] is left out. Anything
//! that fails leaves the message without a card. Nothing is sent but a plain GET: no cookies.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use std::time::{Duration, Instant};

/// The most a card may take, from the first lookup to the image's last byte.
pub const DEADLINE: Duration = Duration::from_secs(3);
/// How many redirects a card follows.
pub const MAX_REDIRECTS: usize = 3;
/// How much of the page is read for its title and description.
pub const MAX_PAGE: usize = 256 * 1024;
/// The largest image a card carries (F-10).
pub const MAX_IMAGE: usize = 16 * 1024;
/// The longest title a card keeps, in characters.
const MAX_TITLE: usize = 200;
/// The longest description a card keeps, in characters.
const MAX_DESCRIPTION: usize = 300;

/// The first `http://` or `https://` URL in `text`, without the punctuation that ends a sentence.
#[must_use]
pub fn first_url(text: &str) -> Option<String> {
    text.split(|c: char| c.is_whitespace() || c == '<' || c == '>' || c == '"')
        .find(|w| w.starts_with("http://") || w.starts_with("https://"))
        .map(|w| {
            w.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '\''])
                .to_owned()
        })
        .filter(|w| w.len() > "https://".len())
}

/// Whether `ip` is an address a card may be fetched from: public, and nothing else.
#[must_use]
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (18..20).contains(&o[1]))
                || o[0] >= 240)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xffc0) == 0xfec0
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x64 && s[1] == 0xff9b)
                || (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0))
        }
    }
}

/// Whether a card may be fetched from `at`: a public address, or, in a build made for proofs
/// only, the one address `VOX_TEST_CARD_ALLOW` names (the proof's own server).
fn allowed(at: SocketAddr) -> bool {
    #[cfg(feature = "test-knobs")]
    if std::env::var("VOX_TEST_CARD_ALLOW")
        .ok()
        .and_then(|v| v.parse::<SocketAddr>().ok())
        == Some(at)
    {
        return true;
    }
    public(at.ip())
}

/// Fetch the card for `url`, or `None`: the host is not public, the page did not answer within
/// the bounds, or it says nothing a card could show. Blocking: run it off the async threads.
#[must_use]
pub fn fetch(url: &str) -> Option<serde_json::Value> {
    let start = Instant::now();
    let left = || DEADLINE.checked_sub(start.elapsed());
    let (page_url, page) = get(url, MAX_PAGE, "text/html", &left)?;
    let html = String::from_utf8_lossy(&page);
    let meta = Meta::read(&html);
    let title = meta
        .property("og:title")
        .or_else(|| meta.title.clone())
        .map(|t| clean(&t, MAX_TITLE))
        .filter(|t| !t.is_empty());
    let description = meta
        .property("og:description")
        .or_else(|| meta.name("description"))
        .map(|d| clean(&d, MAX_DESCRIPTION))
        .filter(|d| !d.is_empty());
    if title.is_none() && description.is_none() {
        return None;
    }
    let mut card = serde_json::json!({ "url": url });
    if let Some(t) = title {
        card["title"] = t.into();
    }
    if let Some(d) = description {
        card["description"] = d.into();
    }
    // The image, only if it is small enough to travel in the message as it is.
    let image = meta
        .property("og:image")
        .and_then(|src| page_url.join(src.trim()).ok())
        .and_then(|img| get(img.as_str(), MAX_IMAGE, "image/", &left));
    if let Some((_, bytes)) = image {
        use base64::Engine as _;
        card["image"] = base64::engine::general_purpose::STANDARD
            .encode(&bytes)
            .into();
    }
    Some(card)
}

/// GET `url`, following at most [`MAX_REDIRECTS`] redirects, each to an allowed address only,
/// within what `left` says remains: the final URL and at most `most` bytes of a body whose type
/// starts with `kind`. `None` for anything else, a body longer than `most` among it.
fn get(
    url: &str,
    most: usize,
    kind: &str,
    left: &dyn Fn() -> Option<Duration>,
) -> Option<(reqwest::Url, Vec<u8>)> {
    use std::io::Read as _;
    let mut at = reqwest::Url::parse(url).ok()?;
    for _ in 0..=MAX_REDIRECTS {
        if !matches!(at.scheme(), "http" | "https") {
            return None;
        }
        let host = at.host_str()?.to_owned();
        let port = at.port_or_known_default()?;
        let addr = (host.trim_matches(['[', ']']), port)
            .to_socket_addrs()
            .ok()?
            .find(|a| allowed(*a))?;
        // **Every address the host has must be allowed**: pinning the first allowed one keeps a
        // later lookup from swapping in another, and a host that also names a private address is
        // not one a card is fetched from.
        let all_allowed = (host.trim_matches(['[', ']']), port)
            .to_socket_addrs()
            .ok()?
            .all(allowed);
        if !all_allowed {
            return None;
        }
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(left()?)
            .resolve(&host, addr)
            .user_agent("vox (link card)")
            .build()
            .ok()?;
        let resp = client.get(at.clone()).send().ok()?;
        if resp.status().is_redirection() {
            let to = resp
                .headers()
                .get(reqwest::header::LOCATION)?
                .to_str()
                .ok()?;
            at = at.join(to).ok()?;
            continue;
        }
        if !resp.status().is_success() {
            return None;
        }
        let ty = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !ty.starts_with(kind) {
            return None;
        }
        let mut body = Vec::new();
        resp.take(most as u64 + 1).read_to_end(&mut body).ok()?;
        if body.len() > most {
            // A page is read only as far as `most`; an image that large is not carried.
            if kind.starts_with("image/") {
                return None;
            }
            body.truncate(most);
        }
        return Some((at, body));
    }
    None
}

/// A text as a card keeps it: whitespace runs as one space, no control characters, at most `max`
/// characters.
fn clean(text: &str, max: usize) -> String {
    let words: Vec<&str> = text.split_whitespace().collect();
    words
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect()
}

/// What a page says of itself: its `<title>` and its `<meta>` tags.
struct Meta {
    title: Option<String>,
    /// `(property or name, content)`, lowercase keys, in page order.
    tags: Vec<(String, String)>,
}

impl Meta {
    fn read(html: &str) -> Self {
        let lower = html.to_ascii_lowercase();
        let title = lower.find("<title").and_then(|i| {
            let open = i + lower[i..].find('>')? + 1;
            let close = open + lower[open..].find("</title")?;
            Some(unescape(&html[open..close]))
        });
        let mut tags = Vec::new();
        let mut from = 0;
        while let Some(i) = lower[from..].find("<meta") {
            let start = from + i;
            let Some(end) = lower[start..].find('>').map(|e| start + e) else {
                break;
            };
            let tag = &html[start..end];
            let key = attr(tag, "property").or_else(|| attr(tag, "name"));
            if let (Some(k), Some(v)) = (key, attr(tag, "content")) {
                tags.push((k.to_ascii_lowercase(), unescape(&v)));
            }
            from = end;
        }
        Self { title, tags }
    }

    fn property(&self, key: &str) -> Option<String> {
        self.tags
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    }

    fn name(&self, key: &str) -> Option<String> {
        self.property(key)
    }
}

/// The value of attribute `name` in the tag text `tag`, quoted with `"` or `'`.
fn attr(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find(name) {
        let at = from + i;
        from = at + name.len();
        // A whole attribute name: preceded by a space, followed by `=`.
        if !lower[..at].ends_with(char::is_whitespace) {
            continue;
        }
        let rest = lower[from..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start();
        let quote = rest.chars().next()?;
        if quote != '"' && quote != '\'' {
            continue;
        }
        let value_at = tag.len() - rest.len() + 1;
        let len = tag[value_at..].find(quote)?;
        return Some(tag[value_at..value_at + len].to_owned());
    }
    None
}

/// The few character references a title or description commonly carries.
fn unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}

/// `text` (a message) with a card for its first URL in its envelope's `data.card`, or `text` as
/// it is: no URL, a card already there, or none could be fetched. Waits at most [`DEADLINE`].
pub async fn attach(text: &str) -> String {
    let Ok(mut env) = vox_agentcomms::envelope::Envelope::parse(text) else {
        return text.to_owned();
    };
    if env.data.get("card").is_some() {
        return text.to_owned();
    }
    let Some(url) = first_url(&env.body) else {
        return text.to_owned();
    };
    let fetched = tokio::time::timeout(
        DEADLINE + Duration::from_millis(250),
        tokio::task::spawn_blocking(move || fetch(&url)),
    )
    .await;
    let Ok(Ok(Some(card))) = fetched else {
        return text.to_owned();
    };
    if !env.data.is_object() {
        env.data = serde_json::Value::Object(serde_json::Map::new());
    }
    env.data["card"] = card;
    let with = env.to_text();
    if with.len() > crate::node::content::MAX_TEXT_LEN {
        return text.to_owned();
    }
    with
}
