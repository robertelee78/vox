//! Stateless governance pages on the existing room-page transport.
use super::*;
use crate::node::api::{GovernancePage as Page, GovernanceQuery as Query};

fn invalid() -> Error {
    Error::MalformedIpc("ipc governance page")
}
fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?.try_into().map_err(|_| invalid())
}
fn put_hash(e: &mut Encoder, v: Option<Digest32>) {
    e.bytes(v.as_ref().map_or(&[][..], |v| &v[..]));
}
fn hash(d: &mut Decoder<'_>) -> Result<Option<Digest32>> {
    let b = d.bytes()?;
    if b.is_empty() {
        Ok(None)
    } else {
        Ok(Some(b.try_into().map_err(|_| invalid())?))
    }
}
fn put_num(e: &mut Encoder, v: Option<u64>) {
    e.array(usize::from(v.is_some()));
    if let Some(v) = v {
        e.uint(v);
    }
}
fn num(d: &mut Decoder<'_>) -> Result<Option<u64>> {
    match d.array()? {
        0 => Ok(None),
        1 => Ok(Some(d.uint()?)),
        _ => Err(invalid()),
    }
}
fn put_order(e: &mut Encoder, v: Option<(u64, Digest32)>) {
    e.array(usize::from(v.is_some()) * 2);
    if let Some((n, h)) = v {
        e.uint(n).bytes(&h);
    }
}
fn order(d: &mut Decoder<'_>) -> Result<Option<(u64, Digest32)>> {
    match d.array()? {
        0 => Ok(None),
        2 => Ok(Some((d.uint()?, digest(d)?))),
        _ => Err(invalid()),
    }
}
pub(super) fn put_pair(e: &mut Encoder, v: Option<(Digest32, Digest32)>) {
    e.array(usize::from(v.is_some()) * 2);
    if let Some((a, b)) = v {
        e.bytes(&a).bytes(&b);
    }
}
pub(super) fn pair(d: &mut Decoder<'_>) -> Result<Option<(Digest32, Digest32)>> {
    match d.array()? {
        0 => Ok(None),
        2 => Ok(Some((digest(d)?, digest(d)?))),
        _ => Err(invalid()),
    }
}
fn count(d: &mut Decoder<'_>) -> Result<usize> {
    let n = d.array()?;
    if n > 64 {
        Err(invalid())
    } else {
        Ok(n)
    }
}
pub(super) fn put_query(e: &mut Encoder, q: &Query) {
    match q {
        Query::Admin { target } => {
            e.array(2).uint(6).bytes(target);
        }
        Query::Service { host, selector } => {
            e.array(3).uint(4).bytes(host).text(selector);
        }
        Query::NoticesAfter {
            entry,
            after,
            revision,
        } => {
            e.array(4).uint(5);
            put_hash(e, *entry);
            put_order(e, *after);
            put_num(e, *revision);
        }
        Query::Notices { before, revision } => {
            e.array(3).uint(0);
            put_order(e, *before);
            put_num(e, *revision);
        }
        Query::Shares { after, revision } => {
            e.array(3).uint(1);
            put_pair(e, *after);
            put_num(e, *revision);
        }
        Query::Admins { after, revision } => {
            e.array(3).uint(2);
            put_hash(e, *after);
            put_num(e, *revision);
        }
        Query::Consent {
            author,
            after,
            revision,
        } => {
            e.array(4).uint(3);
            put_hash(e, *author);
            put_hash(e, *after);
            put_num(e, *revision);
        }
    }
}
pub(super) fn query(d: &mut Decoder<'_>) -> Result<Query> {
    let n = d.array()?;
    Ok(match (d.uint()?, n) {
        (6, 2) => Query::Admin { target: digest(d)? },
        (4, 3) => Query::Service {
            host: digest(d)?,
            selector: d.text()?.to_owned(),
        },
        (5, 4) => Query::NoticesAfter {
            entry: hash(d)?,
            after: order(d)?,
            revision: num(d)?,
        },
        (0, 3) => Query::Notices {
            before: order(d)?,
            revision: num(d)?,
        },
        (1, 3) => Query::Shares {
            after: pair(d)?,
            revision: num(d)?,
        },
        (2, 3) => Query::Admins {
            after: hash(d)?,
            revision: num(d)?,
        },
        (3, 4) => Query::Consent {
            author: hash(d)?,
            after: hash(d)?,
            revision: num(d)?,
        },
        _ => return Err(invalid()),
    })
}
pub(super) fn put_page(e: &mut Encoder, p: &Page) {
    match p {
        Page::Admin {
            target,
            admin,
            revision,
        } => {
            e.array(4)
                .uint(6)
                .bytes(target)
                .uint(u64::from(*admin))
                .uint(*revision);
        }
        Page::Service { share, revision } => {
            e.array(3).uint(4).array(usize::from(share.is_some()));
            if let Some(s) = share {
                put_share(e, s);
            }
            e.uint(*revision);
        }
        Page::NoticesAfter {
            rows,
            next,
            revision,
        } => {
            e.array(4).uint(5).array(rows.len());
            for n in rows {
                e.array(5)
                    .bytes(&n.entry_hash)
                    .bytes(&n.author)
                    .uint(n.created_millis)
                    .text(&n.what);
                put_hash(e, n.after);
            }
            put_order(e, *next);
            e.uint(*revision);
        }
        Page::Notices {
            rows,
            before,
            revision,
        } => {
            e.array(4).uint(0).array(rows.len());
            for n in rows {
                e.array(5)
                    .bytes(&n.entry_hash)
                    .bytes(&n.author)
                    .uint(n.created_millis)
                    .text(&n.what);
                put_hash(e, n.after);
            }
            put_order(e, *before);
            e.uint(*revision);
        }
        Page::Shares {
            rows,
            next,
            revision,
        } => {
            e.array(4).uint(1).array(rows.len());
            for s in rows {
                e.array(4)
                    .bytes(&s.host)
                    .text(&s.name)
                    .uint(u64::from(s.udp))
                    .text(s.kind.as_str());
            }
            put_pair(e, *next);
            e.uint(*revision);
        }
        Page::Admins {
            creator,
            members,
            next,
            revision,
        } => {
            e.array(5).uint(2).bytes(creator).array(members.len());
            for h in members {
                e.bytes(h);
            }
            put_hash(e, *next);
            e.uint(*revision);
        }
        Page::Consent {
            author,
            targets,
            next,
            revision,
        } => {
            e.array(5).uint(3).bytes(author).array(targets.len());
            for h in targets {
                e.bytes(h);
            }
            put_hash(e, *next);
            e.uint(*revision);
        }
    }
}
pub(super) fn page(d: &mut Decoder<'_>) -> Result<Page> {
    let arity = d.array()?;
    Ok(match (d.uint()?, arity) {
        (6, 4) => {
            let target = digest(d)?;
            let admin = match d.uint()? {
                0 => false,
                1 => true,
                _ => return Err(invalid()),
            };
            Page::Admin {
                target,
                admin,
                revision: d.uint()?,
            }
        }
        (4, 3) => {
            let share = match d.array()? {
                0 => None,
                1 => Some(share(d)?),
                _ => return Err(invalid()),
            };
            Page::Service {
                share,
                revision: d.uint()?,
            }
        }
        (kind @ (0 | 5), 4) => {
            let mut rows = Vec::new();
            for _ in 0..count(d)? {
                if d.array()? != 5 {
                    return Err(invalid());
                }
                rows.push(crate::node::channel::RoomNotice {
                    entry_hash: digest(d)?,
                    author: digest(d)?,
                    created_millis: d.uint()?,
                    what: d.text()?.to_owned(),
                    after: hash(d)?,
                });
            }
            let next = order(d)?;
            let revision = d.uint()?;
            if kind == 0 {
                Page::Notices {
                    rows,
                    before: next,
                    revision,
                }
            } else {
                Page::NoticesAfter {
                    rows,
                    next,
                    revision,
                }
            }
        }
        (1, 4) => {
            let mut rows = Vec::new();
            for _ in 0..count(d)? {
                if d.array()? != 4 {
                    return Err(invalid());
                }
                let host = digest(d)?;
                let name = d.text()?.to_owned();
                let udp = match d.uint()? {
                    0 => false,
                    1 => true,
                    _ => return Err(invalid()),
                };
                let kind = crate::governance::share::ServiceKind::from_word(d.text()?)
                    .ok_or_else(invalid)?;
                rows.push(crate::node::channel::Share {
                    host,
                    name,
                    udp,
                    kind,
                });
            }
            Page::Shares {
                rows,
                next: pair(d)?,
                revision: d.uint()?,
            }
        }
        (kind @ (2 | 3), 5) => {
            let who = digest(d)?;
            let mut rows = Vec::new();
            for _ in 0..count(d)? {
                rows.push(digest(d)?);
            }
            let next = hash(d)?;
            let revision = d.uint()?;
            if kind == 2 {
                Page::Admins {
                    creator: who,
                    members: rows,
                    next,
                    revision,
                }
            } else {
                Page::Consent {
                    author: who,
                    targets: rows,
                    next,
                    revision,
                }
            }
        }
        _ => return Err(invalid()),
    })
}

fn put_share(e: &mut Encoder, s: &crate::node::channel::Share) {
    e.array(4)
        .bytes(&s.host)
        .text(&s.name)
        .uint(u64::from(s.udp))
        .text(s.kind.as_str());
}
fn share(d: &mut Decoder<'_>) -> Result<crate::node::channel::Share> {
    if d.array()? != 4 {
        return Err(invalid());
    }
    let host = digest(d)?;
    let name = d.text()?.to_owned();
    let udp = match d.uint()? {
        0 => false,
        1 => true,
        _ => return Err(invalid()),
    };
    let kind = crate::governance::share::ServiceKind::from_word(d.text()?).ok_or_else(invalid)?;
    Ok(crate::node::channel::Share {
        host,
        name,
        udp,
        kind,
    })
}
