//! Completed-fetch facts, read one bounded disk page at a time. The original book is retained.
use super::*;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};

#[derive(Debug)]
pub(super) struct PulledBook {
    root: PathBuf,
    ready: std::result::Result<(), String>,
}
impl PulledBook {
    // A background import or exact disk page may briefly outlive node detach. A private
    // advisory file lock serializes it with a replacement instance, without holding a Store
    // transaction or blocking the async reactor during the potentially long import.
    fn disk_lock(root: &std::path::Path) -> std::result::Result<std::fs::File, String> {
        use std::os::unix::fs::OpenOptionsExt;
        Self::private_dir(root)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(root.join("receipt.lock"))
            .map_err(|error| error.to_string())?;
        file.lock().map_err(|error| error.to_string())?;
        Ok(file)
    }
    fn small_file(path: &std::path::Path, max: u64) -> std::io::Result<Vec<u8>> {
        let file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.take(max + 1).read_to_end(&mut bytes)?;
        Ok(bytes)
    }
    fn private_dir(dir: &std::path::Path) -> std::result::Result<(), String> {
        crate::node::paths::create_private_dir(dir).map_err(|e| e.to_string())?;
        crate::node::paths::sync_dir(dir).map_err(|e| e.to_string())?;
        if let Some(parent) = dir.parent() {
            crate::node::paths::sync_dir(parent).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
    fn verify_position(
        dir: &std::path::Path,
        member: &Digest32,
        at: u64,
    ) -> std::result::Result<(), String> {
        use std::os::unix::fs::FileExt;
        if !at.is_multiple_of(32) {
            return Err("invalid completed-pull recipient position".into());
        }
        let file = std::fs::File::open(dir.join("recipients")).map_err(|e| e.to_string())?;
        let mut saved = [0; 32];
        file.read_exact_at(&mut saved, at)
            .map_err(|e| e.to_string())?;
        if saved != *member {
            return Err("completed-pull recipient pointer differs from its receipt".into());
        }
        Ok(())
    }
    pub(super) fn new(root: PathBuf) -> Self {
        Self {
            root,
            ready: Err("completed-pull receipts are loading; retry".into()),
        }
    }
    pub(super) fn root(&self) -> PathBuf {
        self.root.clone()
    }
    pub(super) fn set_ready(&mut self, ready: std::result::Result<(), String>) {
        self.ready = ready;
    }
    pub(super) fn check(&self) -> std::result::Result<(), String> {
        self.ready.clone()
    }
    fn dir(root: &std::path::Path, tag: &str) -> PathBuf {
        use sha2::{Digest, Sha256};
        root.join("by-tag")
            .join(hex(&Sha256::digest(tag.as_bytes())))
    }
    fn metadata(
        dir: &std::path::Path,
    ) -> std::result::Result<Option<(Digest32, Digest32)>, String> {
        match Self::small_file(&dir.join("identity"), 64) {
            Ok(bytes) if bytes.len() == 64 => Ok(Some((
                bytes[..32]
                    .try_into()
                    .map_err(|_| "invalid completed-pull receipt identity")?,
                bytes[32..]
                    .try_into()
                    .map_err(|_| "invalid completed-pull receipt identity")?,
            ))),
            Ok(_) => Err("invalid completed-pull receipt identity".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    fn identify(
        dir: &std::path::Path,
        room: Digest32,
        entry: Digest32,
    ) -> std::result::Result<(), String> {
        let prior = Self::metadata(dir)?;
        if prior.is_some_and(|(r, e)| r != room || (e != [0; 32] && entry != [0; 32] && e != entry))
        {
            return Err("completed-pull receipt belongs to another announcement".into());
        }
        let entry = prior
            .filter(|(_, e)| *e != [0; 32])
            .map_or(entry, |(_, e)| e);
        Self::private_dir(dir)?;
        crate::node::paths::write_private_file(
            &dir.join("identity"),
            &[room.as_slice(), entry.as_slice()].concat(),
        )
        .map_err(|e| e.to_string())
    }
    fn marker(dir: &std::path::Path, member: &Digest32) -> PathBuf {
        dir.join("members").join(hex(member))
    }
    fn position(
        dir: &std::path::Path,
        member: &Digest32,
    ) -> std::result::Result<Option<u64>, String> {
        match Self::small_file(&Self::marker(dir, member), 8) {
            Ok(bytes) if bytes.len() == 8 => {
                Ok(Some(u64::from_be_bytes(bytes.try_into().map_err(
                    |_| "invalid completed-pull recipient position",
                )?)))
            }
            Ok(_) => Err("invalid completed-pull recipient position".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    fn mark(dir: &std::path::Path, member: &Digest32, at: u64) -> std::result::Result<(), String> {
        Self::private_dir(&dir.join("members"))?;
        crate::node::paths::write_private_file(&Self::marker(dir, member), &at.to_be_bytes())
            .map_err(|e| e.to_string())
    }
    // An immutable 32-byte receipt is durable before its dedup pointer. A crash between the
    // two leaves a recoverable receipt, never a pointer to bytes that were not made durable.
    fn member(dir: &std::path::Path, member: Digest32) -> std::result::Result<(), String> {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(at) = Self::position(dir, &member)? {
            return Self::verify_position(dir, &member, at);
        }
        Self::private_dir(dir)?;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(dir.join("recipients"))
            .map_err(|e| e.to_string())?;
        let at = file.metadata().map_err(|e| e.to_string())?.len();
        if at % 32 != 0 {
            return Err("incomplete completed-pull receipt; saved bytes retained".into());
        }
        file.write_all(&member)
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        crate::node::paths::sync_dir(dir).map_err(|e| e.to_string())?;
        Self::mark(dir, &member, at)
    }
    pub(super) fn pulled(
        &self,
        tag: &str,
        room: Digest32,
        member: Digest32,
    ) -> std::result::Result<(), String> {
        self.check()?;
        let _lock = Self::disk_lock(&self.root)?;
        let dir = Self::dir(&self.root, tag);
        Self::identify(&dir, room, [0; 32])?;
        Self::member(&dir, member)
    }
    pub(super) fn announced(
        &self,
        tag: &str,
        room: Digest32,
        entry: &str,
    ) -> std::result::Result<(), String> {
        self.check()?;
        let _lock = Self::disk_lock(&self.root)?;
        Self::identify(
            &Self::dir(&self.root, tag),
            room,
            b32_decode(entry, "announcement").map_err(|e| e.to_string())?,
        )
    }
    pub(super) fn page(
        &self,
        tag: &str,
        room: Digest32,
        entry: Digest32,
        after: Option<u64>,
        limit: usize,
    ) -> std::result::Result<(Vec<Digest32>, Option<u64>), String> {
        self.check()?;
        let _lock = Self::disk_lock(&self.root)?;
        let dir = Self::dir(&self.root, tag);
        match Self::metadata(&dir)? {
            None => return Ok((Vec::new(), None)),
            Some((r, e)) if r == room && e == entry => {}
            Some((r, e)) if r == room && e == [0; 32] => Self::identify(&dir, room, entry)?,
            Some(_) => return Err("completed-pull receipt does not match this message".into()),
        }
        let mut file = match std::fs::File::open(dir.join("recipients")) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), None)),
            Err(e) => return Err(e.to_string()),
        };
        let end = file.metadata().map_err(|e| e.to_string())?.len();
        let mut at = after.unwrap_or(0);
        if !end.is_multiple_of(32) || !at.is_multiple_of(32) || at > end {
            return Err("invalid completed-pull page; saved bytes retained".into());
        }
        file.seek(SeekFrom::Start(at)).map_err(|e| e.to_string())?;
        let mut members = Vec::new();
        for _ in 0..limit.min(64) {
            if at == end {
                break;
            }
            let mut member = [0; 32];
            file.read_exact(&mut member).map_err(|e| e.to_string())?;
            match Self::position(&dir, &member)? {
                None => {
                    Self::mark(&dir, &member, at)?;
                    members.push(member);
                }
                Some(canonical) if canonical == at => members.push(member),
                Some(canonical) if canonical < end && canonical % 32 == 0 => {
                    Self::verify_position(&dir, &member, canonical)?;
                }
                Some(_) => return Err("invalid completed-pull recipient pointer".into()),
            }
            at += 32;
        }
        Ok((members, (at < end).then_some(at)))
    }
    pub(super) fn initialize(root: &std::path::Path) -> std::result::Result<(), String> {
        let _lock = Self::disk_lock(root)?;
        let marker = root.join("split-complete");
        match Self::small_file(&marker, 2) {
            Ok(bytes) if bytes == b"1\n" => return Ok(()),
            Ok(_) => return Err("invalid completed-pull import marker".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        match std::fs::File::open(root.join("book.json")) {
            Ok(file) => {
                let mut de = serde_json::Deserializer::from_reader(BufReader::new(file));
                BookSeed(root)
                    .deserialize(&mut de)
                    .map_err(|e| format!("cannot import completed-pull receipts: {e}"))?;
                de.end().map_err(|e| e.to_string())?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        Self::private_dir(root)?;
        crate::node::paths::write_private_file(&marker, b"1\n").map_err(|e| e.to_string())
    }
}
struct BookSeed<'a>(&'a std::path::Path);
impl<'de> DeserializeSeed<'de> for BookSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for BookSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("the completed-pull book")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        while let Some(tag) = map.next_key::<String>()? {
            if tag.len() > 512 {
                return Err(serde::de::Error::custom("invalid share tag"));
            }
            map.next_value_seed(ReceiptSeed(PulledBook::dir(self.0, &tag)))?;
        }
        Ok(())
    }
}
struct ReceiptSeed(PathBuf);
impl<'de> DeserializeSeed<'de> for ReceiptSeed {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for ReceiptSeed {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("one completed-pull receipt")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        let (mut room, mut entry) = (None, None);
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "room" => {
                    let s: String = map.next_value()?;
                    room = Some(b32_decode(&s, "receipt room").map_err(serde::de::Error::custom)?);
                }
                "entry" => {
                    let s: String = map.next_value()?;
                    entry = Some(if s.is_empty() {
                        [0; 32]
                    } else {
                        b32_decode(&s, "receipt entry").map_err(serde::de::Error::custom)?
                    });
                }
                "who" => map.next_value_seed(MembersSeed(&self.0))?,
                _ => {
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }
        PulledBook::identify(
            &self.0,
            room.ok_or_else(|| serde::de::Error::custom("receipt room missing"))?,
            entry.ok_or_else(|| serde::de::Error::custom("receipt entry missing"))?,
        )
        .map_err(serde::de::Error::custom)
    }
}
struct MembersSeed<'a>(&'a std::path::Path);
impl<'de> DeserializeSeed<'de> for MembersSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for MembersSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("completed recipients")
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<(), S::Error> {
        while let Some(s) = seq.next_element::<String>()? {
            let member = b32_decode(&s, "receipt member").map_err(serde::de::Error::custom)?;
            PulledBook::member(self.0, member).map_err(serde::de::Error::custom)?;
        }
        Ok(())
    }
}
