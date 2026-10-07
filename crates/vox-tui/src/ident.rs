//! How a member is named on screen.
//!
//! A member is its fingerprint, and every surface used to show a short prefix of it: 8 hex
//! characters in the TUI (32 bits), 8 base32 in the agent drain (40 bits), 12 base32 in the
//! CLI and the work board (60 bits). A prefix that short can be matched by grinding keys: 2^40
//! attempts is an afternoon, so a member could post under a name that reads as another's (#198).
//!
//! Where the keyring's petnames are at hand (the TUI holds the node's view), a trusted member is
//! shown by the name the operator gave it, and anyone else by [`AUTHOR_CHARS`] of its fingerprint,
//! marked as not in the keyring. Surfaces that speak to a node over its control socket read the
//! same names from it ([`load_names`], V210-162) and show a member by [`name_of`]: the reader's own
//! name for it, or its fingerprint at [`AUTHOR_CHARS`] when it has none.

use std::sync::OnceLock;

use vox_core::hash::Digest32;
use vox_core::node::ipc::{Frame, IpcClient};
use vox_core::node::link::b32_encode;

/// Base32 characters of a fingerprint shown wherever a member is named without a keyring name:
/// 26, i.e. 130 bits, past the reach of anyone grinding keys for a lookalike.
pub const AUTHOR_CHARS: usize = 26;

/// What marks a member that is not in this node's trust keyring, where the keyring is known.
/// Short enough that 26 characters, a space and this fit the TUI's members pane (46 columns):
/// the longer "(not in your keyring)" was cut off there, which the proof caught.
pub const NOT_IN_KEYRING: &str = "(not in keyring)";

/// What a person is told wherever a node is made (ADR-028 K-8): a node has no backup, so a lost
/// machine means a new node, which the people who trusted the old one untrust.
pub const NO_BACKUP: &str = "there is no backup of a node: if this machine is lost, so is this \
     node; make a new one, and ask everyone who trusts this one to untrust it and trust the new one";

/// A member's fingerprint as shown on screen: its first [`AUTHOR_CHARS`] base32 characters.
#[must_use]
pub fn author_id(fp: &Digest32) -> String {
    b32_encode(fp).chars().take(AUTHOR_CHARS).collect()
}

/// What a person is told about a member this node holds back for equivocating (V210-63):
/// `name` signed two different messages at one position, `seq`, in the room being read. The
/// wording is the decider's (2026-09-28).
#[must_use]
pub fn equivocation_notice(name: &str, seq: u64) -> String {
    format!(
        "{name} signed two different messages at the same place in this room (their message \
         {seq}). Their later messages are held back."
    )
}

/// The TUI's one trust action, as offered beside a node not in the keyring (ADR-028 K-5):
/// `:trust` and the start of its fingerprint, enough to name it.
#[must_use]
pub fn trust_hint(fp: &Digest32) -> String {
    format!(":trust {}", &author_id(fp)[..MIN_PREFIX])
}

/// A fingerprint as a person pasted or typed it, compared as the node writes it: spaces, dashes
/// and case do not count, so `M4OL SURT …` in groups is `m4olsurt…`.
#[must_use]
pub fn typed_fingerprint(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// How many fingerprint characters follow an alias that another node's alias equals but for case.
pub const CLASH_SUFFIX: usize = 6;

/// `fp`'s alias as a person reads it (ADR-028 K-4): the alias, and, when another node in the
/// keyring has the same alias but for case ("Ann" and "ann"), `#` and the first [`CLASH_SUFFIX`]
/// characters of the fingerprint, so the two are never taken for one. `None` when `fp` has no
/// alias.
#[must_use]
pub fn alias_of(trusted: &[(Digest32, String)], fp: &Digest32) -> Option<String> {
    let (_, alias) = trusted.iter().find(|(id, _)| id == fp)?;
    let alias = alias.trim();
    if alias.is_empty() {
        return None;
    }
    let clash = trusted
        .iter()
        .any(|(id, other)| id != fp && other.trim().to_lowercase() == alias.to_lowercase());
    Some(if clash {
        let mut suffix = b32_encode(fp);
        suffix.truncate(CLASH_SUFFIX);
        format!("{alias}#{suffix}")
    } else {
        alias.to_owned()
    })
}

/// A member's name where the keyring is known: its alias ([`alias_of`]), or its fingerprint at
/// [`AUTHOR_CHARS`] followed by [`NOT_IN_KEYRING`].
#[must_use]
pub fn member_name(trusted: &[(Digest32, String)], fp: &Digest32) -> String {
    alias_of(trusted, fp).unwrap_or_else(|| format!("{} {NOT_IN_KEYRING}", author_id(fp)))
}

/// This process's copy of the node's names for its members: `(fingerprint, name)`.
static NAMES: OnceLock<Vec<(Digest32, String)>> = OnceLock::new();

/// This node's own fingerprint, as the node reported it, for [`name_of`].
static ME: OnceLock<Digest32> = OnceLock::new();

/// How every surface names the reader's own node: as the TUI does, and as a message addressed
/// to it says "to you".
pub const YOU: &str = "you";

/// Read the node's names for its members once, for [`name_of`] (V210-162).
///
/// Best effort: a node that does not answer leaves every member shown by fingerprint, as every
/// surface showed them before.
pub async fn load_names(client: &mut IpcClient) {
    if let Some(me) = client.me() {
        let _ = ME.set(me);
    }
    if NAMES.get().is_some() {
        return;
    }
    if let Ok(Frame::Trusted { entries }) = client.trusted("").await {
        let _ = NAMES.set(entries);
    }
}

/// This node, as [`load_names`] read it, or `None` before it has.
#[must_use]
pub fn me() -> Option<&'static Digest32> {
    ME.get()
}

/// The names [`load_names`] read, or none.
#[must_use]
pub fn names() -> &'static [(Digest32, String)] {
    NAMES.get().map_or(&[], Vec::as_slice)
}

/// A member as the reader knows it (V210-162): [`YOU`] for this node itself, the name this node
/// gave it, on one line, or its fingerprint at [`AUTHOR_CHARS`] when it gave none.
#[must_use]
pub fn name_of(fp: &Digest32) -> String {
    if ME.get() == Some(fp) {
        return YOU.to_owned();
    }
    name_in(names(), fp)
}

/// [`member_name`], but [`YOU`] for `me`: how the daemon names an author to its own agents.
#[must_use]
pub fn author_for(trusted: &[(Digest32, String)], me: Option<&Digest32>, fp: &Digest32) -> String {
    if me == Some(fp) {
        return YOU.to_owned();
    }
    member_name(trusted, fp)
}

/// [`name_of`] against `trusted`.
#[must_use]
pub fn name_in(trusted: &[(Digest32, String)], fp: &Digest32) -> String {
    match alias_of(trusted, fp) {
        Some(n) => vox_agentcomms::envelope::shown(&n, vox_agentcomms::envelope::SHOWN_NAME),
        None => author_id(fp),
    }
}

/// Whether `name` may be this node's name for `target` (V210-162): on one line, and not already
/// its name for another member, since a name is how a person addresses a member.
///
/// # Errors
/// Saying which rule `name` breaks.
pub fn check_new_name(
    trusted: &[(Digest32, String)],
    target: &Digest32,
    name: &str,
) -> Result<(), crate::app::AppError> {
    let name = name.trim();
    if !vox_agentcomms::envelope::is_valid_name(name, vox_agentcomms::envelope::MAX_NAME) {
        return Err(crate::app::AppError::Usage(format!(
            "a name must be 1–{} bytes on one line",
            vox_agentcomms::envelope::MAX_NAME
        )));
    }
    match trusted
        .iter()
        .find(|(fp, n)| fp != target && n.trim() == name)
    {
        Some((fp, _)) => Err(crate::app::AppError::Usage(format!(
            "{name:?} is already your name for {}; give this one another",
            author_id(fp)
        ))),
        None => Ok(()),
    }
}

/// The fewest fingerprint characters a member may be named by: fewer is too easily a mistyped
/// name that happens to begin a fingerprint.
pub const MIN_PREFIX: usize = 8;

/// The member of `members` that `word` names (V210-161): the reader's own name for it, or its
/// fingerprint, whole or a unique prefix of at least [`MIN_PREFIX`] characters.
///
/// # Errors
/// A sentence saying why `word` names no one, or more than one, in this room.
pub fn resolve_member(
    word: &str,
    members: &[Digest32],
    trusted: &[(Digest32, String)],
) -> Result<Digest32, String> {
    let w = word.trim();
    let named: Vec<Digest32> = trusted
        .iter()
        .filter(|(_, n)| n.trim() == w)
        .map(|(fp, _)| *fp)
        .collect();
    match named.as_slice() {
        [fp] if members.contains(fp) => return Ok(*fp),
        [_] => return Err(format!("{w:?} is not a member of this room")),
        [] => {}
        many => {
            return Err(format!(
                "{w:?} is your name for {} members; name one by fingerprint",
                many.len()
            ))
        }
    }
    let needle = w.to_ascii_lowercase();
    let hits: Vec<Digest32> = members
        .iter()
        .copied()
        .filter(|m| needle.len() >= MIN_PREFIX && b32_encode(m).starts_with(&needle))
        .collect();
    match hits.as_slice() {
        [fp] => Ok(*fp),
        [] => Err(format!(
            "no member of this room is called {w:?}. Name one by your name for it (`vox trust \
             list`) or by its fingerprint, at least {MIN_PREFIX} characters (`vox room roster`)"
        )),
        many => Err(format!(
            "{w:?} begins {} members' fingerprints; use more characters",
            many.len()
        )),
    }
}

/// Who `text`, typed in the TUI's composer, addresses (ADR-028 K-4): each `@alias` resolved to
/// the whole fingerprint of the room member it names, as `to` carries it. An alias is matched
/// exactly first, then without regard to case; `@alias#abc123` picks among nodes whose aliases
/// differ only by case, by the start of the fingerprint, as their names are shown. Punctuation
/// after the alias (`@ann,`) is not part of it.
///
/// # Errors
/// A sentence saying which `@alias` names no member of the room, or more than one.
pub fn addressed_in(
    text: &str,
    members: &[Digest32],
    trusted: &[(Digest32, String)],
) -> Result<Vec<String>, String> {
    let mut to: Vec<String> = Vec::new();
    for word in text.split_whitespace() {
        let Some(at) = word.strip_prefix('@') else {
            continue;
        };
        let at = at.trim_end_matches(|c: char| ",.;:!?)".contains(c));
        if at.is_empty() {
            continue;
        }
        let (alias, prefix) = match at.split_once('#') {
            Some((a, p)) => (a, Some(p.to_ascii_lowercase())),
            None => (at, None),
        };
        let fits = |fp: &Digest32| {
            prefix
                .as_ref()
                .is_none_or(|p| b32_encode(fp).starts_with(p))
        };
        let exact: Vec<Digest32> = trusted
            .iter()
            .filter(|(fp, n)| n.trim() == alias && fits(fp))
            .map(|(fp, _)| *fp)
            .collect();
        let named = if exact.len() == 1 {
            exact
        } else {
            trusted
                .iter()
                .filter(|(fp, n)| n.trim().to_lowercase() == alias.to_lowercase() && fits(fp))
                .map(|(fp, _)| *fp)
                .collect()
        };
        let fp = match named.as_slice() {
            [fp] => *fp,
            [] => return Err(format!("no node in your keyring is called @{at}")),
            many => {
                let said: Vec<String> = many
                    .iter()
                    .map(|fp| format!("@{}", alias_of(trusted, fp).unwrap_or_default()))
                    .collect();
                return Err(format!(
                    "@{at} could be {}: write the one you mean",
                    said.join(" or ")
                ));
            }
        };
        if !members.contains(&fp) {
            return Err(format!("@{at} is not a member of this room"));
        }
        let fp = b32_encode(&fp);
        if !to.contains(&fp) {
            to.push(fp);
        }
    }
    Ok(to)
}

/// The node one entry of an envelope's `to` names: a whole fingerprint, written exactly as
/// [`b32_encode`] writes it.
///
/// **Only that form** (V210-161): the wake and `vox room post`'s unread list compare `to` with
/// this node's fingerprint as written, so an address in any other spelling (upper case, padded)
/// would read as "to you" here and wake no one there. Such an entry names no node.
#[must_use]
pub fn recipient(t: &str) -> Option<Digest32> {
    vox_core::node::link::b32_decode(t, "recipient")
        .ok()
        .filter(|fp| b32_encode(fp) == t)
}

/// Who a message is addressed to, as the reader knows them (V210-161): each recipient by
/// [`name_in`], the reader itself as `you`, and one session of a node as the node's name and the
/// session's short id (ADR-029 TA-1, SE-3). A recipient that is not a fingerprint (an older build
/// addressed sessions by name) is shown as written, on one line.
#[must_use]
pub fn recipients(to: &[String], me: Option<&Digest32>, trusted: &[(Digest32, String)]) -> String {
    to.iter()
        .map(|t| {
            let (node, session) = vox_agentcomms::envelope::addressee(t);
            let node = match recipient(node) {
                Some(fp) if Some(&fp) == me => YOU.to_owned(),
                Some(fp) => name_in(trusted, &fp),
                None => {
                    return vox_agentcomms::envelope::shown(t, vox_agentcomms::envelope::SHOWN_NAME)
                }
            };
            match session {
                Some(s) => format!(
                    "{node}/{}",
                    vox_agentcomms::envelope::shown(
                        &s.chars().take(8).collect::<String>(),
                        vox_agentcomms::envelope::SHOWN_NAME
                    )
                ),
                None => node,
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// **Who reads whom between this node and one other member** (ADR-028 R-5, #481): whether the
/// member is in this node's keyring, and whether its trust in this node has reached it. The three
/// states every client says on joining, with what each person still has to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reading {
    /// Each trusts the other: they read each other.
    BothWays,
    /// This node trusts the member, whose trust in this node has not reached it (yet): neither
    /// reads the other until it does. Whether the member has trusted it is not known here.
    Waiting,
    /// The member is not in this node's keyring; `trusts_you` when it already trusts this node.
    NotInKeyring {
        /// The member's trust in this node has reached it.
        trusts_you: bool,
    },
}

impl Reading {
    /// The state from the keyring (`in_keyring`) and the room's log (`trusts_you`).
    #[must_use]
    pub fn of(in_keyring: bool, trusts_you: bool) -> Self {
        match (in_keyring, trusts_you) {
            (true, true) => Reading::BothWays,
            (true, false) => Reading::Waiting,
            (false, trusts_you) => Reading::NotInKeyring { trusts_you },
        }
    }

    /// The state's glyph (ADR-028 L-4): `⇄`, `→`, or `·`.
    #[must_use]
    pub fn glyph(self) -> &'static str {
        match self {
            Reading::BothWays => "⇄",
            Reading::Waiting => "→",
            Reading::NotInKeyring { .. } => "·",
        }
    }

    /// The state in words, and what is still to do: `name` is how this node names the member,
    /// `fp` and `me` the member's and this node's whole fingerprints, as `vox trust add` takes
    /// them.
    #[must_use]
    pub fn say(self, name: &str, fp: &str, me: &str) -> String {
        match self {
            Reading::BothWays => "trusted both ways: you read each other".to_owned(),
            Reading::Waiting => format!(
                "waiting for the other side: you trust {name}; {name}'s trust in you has not \
                 reached this node yet. Until it does neither reads the other; if they have not \
                 trusted you, they run `vox trust add {me}`"
            ),
            // Their trust in this node, when it has reached it, is said; when it has not, only what
            // each still runs, never that they have or have not given it.
            Reading::NotInKeyring { trusts_you: true } => format!(
                "not in keyring, trusts you: to read each other, you run `vox trust add {fp} \
                 --name NAME`"
            ),
            Reading::NotInKeyring { trusts_you: false } => format!(
                "not in keyring: to read each other, you run `vox trust add {fp} --name NAME`; \
                 if they have not trusted you, they run `vox trust add {me}`"
            ),
        }
    }
}
