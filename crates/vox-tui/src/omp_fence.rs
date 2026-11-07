//! Private, process-lifetime ownership for OMP registration writes.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use rustix::fs::{flock, mkdirat, open, openat, FlockOperation, Mode, OFlags};
use vox_core::node::paths::Account;
use crate::wake::AttentionRoute;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OmpFenceRef {
    pub instance_id: String,
    pub generation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceError { Busy, Invalid }

#[derive(serde::Serialize, serde::Deserialize)]
struct Binding { generation: String, node: String, session: String, route: AttentionRoute }

fn opaque(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn random_id() -> Result<String, FenceError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| FenceError::Invalid)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn checked(file: File, dir: bool, private: bool) -> Result<File, FenceError> {
    let m = file.metadata().map_err(|_| FenceError::Invalid)?;
    if m.uid() != rustix::process::geteuid().as_raw()
        || (dir && !m.is_dir()) || (!dir && (!m.is_file() || m.nlink() != 1))
        || (private && m.permissions().mode() & 0o7777 != if dir { 0o700 } else { 0o600 }) {
        return Err(FenceError::Invalid);
    }
    Ok(file)
}
fn flags(dir: bool) -> OFlags {
    OFlags::CLOEXEC | OFlags::NOFOLLOW | if dir { OFlags::RDONLY | OFlags::DIRECTORY } else { OFlags::RDWR | OFlags::NONBLOCK }
}
fn directory(parent: &File, name: &str, create: bool) -> Result<File, FenceError> {
    if create {
        match mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => (),
            Err(_) => return Err(FenceError::Invalid),
        }
    }
    let fd = openat(parent, name, flags(true), Mode::empty()).map_err(|_| FenceError::Invalid)?;
    checked(File::from(fd), true, true)
}
fn private_file(parent: &File, name: &str, create: bool) -> Result<File, FenceError> {
    let f = flags(false) | if create { OFlags::CREATE | OFlags::EXCL } else { OFlags::empty() };
    let fd = openat(parent, name, f, Mode::from_raw_mode(0o600)).map_err(|_| FenceError::Invalid)?;
    checked(File::from(fd), false, true)
}
fn root(account: &Account, create: bool) -> Result<File, FenceError> {
    let fd = open(&account.data_root, flags(true), Mode::empty()).map_err(|_| FenceError::Invalid)?;
    let root = checked(File::from(fd), true, false)?;
    let daemon = directory(&root, ".daemon", create)?;
    directory(&daemon, "omp-instances", create)
}
fn lock(file: &File, nonblocking: bool) -> Result<(), FenceError> {
    let op = if nonblocking { FlockOperation::NonBlockingLockExclusive } else { FlockOperation::LockExclusive };
    flock(file, op).map_err(|e| if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::WOULDBLOCK { FenceError::Busy } else { FenceError::Invalid })
}
fn read_binding(dir: &File) -> Result<Option<Binding>, FenceError> {
    let mut file = private_file(dir, "binding", false)?;
    let mut bytes = Vec::new();
    (&mut file).take(65537).read_to_end(&mut bytes).map_err(|_| FenceError::Invalid)?;
    if bytes.len() > 65536 { return Err(FenceError::Invalid); }
    if bytes.is_empty() { return Ok(None); }
    serde_json::from_slice(&bytes).map(Some).map_err(|_| FenceError::Invalid)
}
fn write_binding(dir: &File, binding: Option<&Binding>) -> Result<(), FenceError> {
    let mut file = private_file(dir, "binding", false)?;
    let bytes = binding.map(serde_json::to_vec).transpose().map_err(|_| FenceError::Invalid)?.unwrap_or_default();
    if bytes.len() > 65536 { return Err(FenceError::Invalid); }
    file.set_len(0).map_err(|_| FenceError::Invalid)?;
    file.seek(SeekFrom::Start(0)).map_err(|_| FenceError::Invalid)?;
    file.write_all(&bytes).map_err(|_| FenceError::Invalid)?;
    file.sync_data().map_err(|_| FenceError::Invalid)
}

/// Holds the stable mutation inode locked until the registration write finishes.
pub struct MutationGuard { _lock: File }

pub fn validate(account: &Account, reference: &OmpFenceRef, node: &str, session: &str, route: &AttentionRoute) -> Result<MutationGuard, FenceError> {
    if !opaque(&reference.instance_id) || !opaque(&reference.generation) { return Err(FenceError::Invalid); }
    let dir = directory(&root(account, false)?, &reference.instance_id, false)?;
    let mutation = private_file(&dir, "mutation", false)?;
    lock(&mutation, true)?;
    let lifetime = private_file(&dir, "lifetime", false)?;
    match lock(&lifetime, true) {
        Err(FenceError::Busy) => (),
        _ => return Err(FenceError::Invalid),
    }
    let mut compatibility = private_file(&dir, "compatibility", false)?;
    let mut enabled = [0u8; 1];
    if compatibility.read_exact(&mut enabled).is_err() || enabled != [1] {
        return Err(FenceError::Invalid);
    }
    let binding = read_binding(&dir)?.ok_or(FenceError::Invalid)?;
    if binding.generation != reference.generation || binding.node != node || binding.session != session || binding.route != *route {
        return Err(FenceError::Invalid);
    }
    Ok(MutationGuard { _lock: mutation })
}

/// Lifetime owner; lock files are never unlinked, even after owner death.
pub(crate) struct Owner { pub instance_id: String, dir: File, _lifetime: File }
impl Owner {
    pub(crate) fn acquire(account: &Account, previous: Option<&str>) -> Result<Self, FenceError> {
        let root = root(account, true)?;
        let (instance_id, dir) = if let Some(id) = previous {
            if !opaque(id) { return Err(FenceError::Invalid); }
            (id.to_owned(), directory(&root, id, false)?)
        } else {
            let id = random_id()?;
            mkdirat(&root, id.as_str(), Mode::from_raw_mode(0o700)).map_err(|_| FenceError::Invalid)?;
            let dir = directory(&root, &id, false)?;
            for name in ["mutation", "lifetime", "binding", "identity", "generations", "compatibility"] { private_file(&dir, name, true)?; }
            (id, dir)
        };
        let mutation = private_file(&dir, "mutation", false)?;
        lock(&mutation, true)?;
        let lifetime = private_file(&dir, "lifetime", false)?;
        lock(&lifetime, true)?;
        let mut compatibility = private_file(&dir, "compatibility", false)?;
        compatibility.set_len(0).map_err(|_| FenceError::Invalid)?;
        write_binding(&dir, None)?;
        drop(mutation);
        Ok(Self { instance_id, dir, _lifetime: lifetime })
    }
    pub(crate) fn set_compatible(&self, compatible: bool) -> Result<(), FenceError> {
        let mutation = private_file(&self.dir, "mutation", false)?;
        lock(&mutation, true)?;
        let mut file = private_file(&self.dir, "compatibility", false)?;
        file.set_len(0).map_err(|_| FenceError::Invalid)?;
        file.write_all(&[u8::from(compatible)]).map_err(|_| FenceError::Invalid)?;
        Ok(())
    }
    pub(crate) fn pin(&self, identity: &str) -> Result<(), FenceError> {
        let mutation = private_file(&self.dir, "mutation", false)?;
        lock(&mutation, true)?;
        let mut file = private_file(&self.dir, "identity", false)?;
        let mut saved = String::new();
        (&mut file).take(128).read_to_string(&mut saved).map_err(|_| FenceError::Invalid)?;
        if saved.is_empty() {
            file.write_all(identity.as_bytes()).map_err(|_| FenceError::Invalid)?;
            file.sync_data().map_err(|_| FenceError::Invalid)?;
        } else if saved != identity {
            return Err(FenceError::Invalid);
        }
        Ok(())
    }
    pub(crate) fn revoke(&self) -> Result<(), FenceError> {
        let mutation = private_file(&self.dir, "mutation", false)?;
        lock(&mutation, true)?;
        write_binding(&self.dir, None)
    }
    pub(crate) fn install(&self, generation: String, node: String, session: String, route: AttentionRoute) -> Result<(), FenceError> {
        if !opaque(&generation) || node.is_empty() || session.is_empty() || session.len() > 4096 || route.endpoint.is_empty() || route.token.is_empty() { return Err(FenceError::Invalid); }
        let mutation = private_file(&self.dir, "mutation", false)?;
        lock(&mutation, true)?;
        if read_binding(&self.dir)?.is_some() { return Err(FenceError::Invalid); }
        // Retain bounded used references across helper succession; even a late command cannot
        // reactivate one whose lifetime owner died.
        let mut history = private_file(&self.dir, "generations", false)?;
        let mut used = String::new();
        (&mut history).take(65 * 4096 + 1).read_to_string(&mut used).map_err(|_| FenceError::Invalid)?;
        if used.len() >= 65 * 4096 || used.lines().any(|old| old == generation) {
            return Err(FenceError::Invalid);
        }
        history.write_all(generation.as_bytes()).map_err(|_| FenceError::Invalid)?;
        history.write_all(b"\n").map_err(|_| FenceError::Invalid)?;
        history.sync_data().map_err(|_| FenceError::Invalid)?;
        write_binding(&self.dir, Some(&Binding { generation, node, session, route }))
    }
}
