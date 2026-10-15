//! Private selected attention reads. No public roster/count and no adapter side effect.
use super::*;
use vox_core::node::attention::{Operation, OwnRequest, Query, Reply, LABEL, MAX_BYTES};

impl Router {
    pub(super) fn serve_attention(&self, handle: &NodeHandle, mut detached: watch::Receiver<bool>) {
        let hub = Arc::clone(handle.app());
        let mut listener = match hub.listen(None, LABEL) {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("vox daemon: private attention listener unavailable: {error}");
                return;
            }
        };
        let handle = handle.clone();
        tokio::spawn(async move {
            let slots = Arc::new(tokio::sync::Semaphore::new(8));
            loop {
                let permit = tokio::select! {
                    _ = detached.wait_for(|d| *d) => return,
                    permit = slots.clone().acquire_owned() => match permit { Ok(permit) => permit, Err(_) => return },
                };
                let incoming = tokio::select! {
                    _ = detached.wait_for(|d| *d) => return,
                    incoming = listener.next() => match incoming { Some(incoming) => incoming, None => return },
                };
                let (hub, handle, mut detached) = (hub.clone(), handle.clone(), detached.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    tokio::select! {
                        _ = detached.wait_for(|d| *d) => {},
                        _ = tokio::time::timeout(Duration::from_secs(15), async {
                            let Ok(stream) = hub.accept(incoming.id).await else { return; };
                            let info = stream.info().clone();
                            let mut bytes = Vec::new();
                            let mut chunk = [0; 4096];
                            while bytes.len() <= MAX_BYTES && !bytes.contains(&b'\n') {
                                match stream.read(&mut chunk).await {
                                    Ok(Some(n)) if n > 0 => bytes.extend_from_slice(&chunk[..n]),
                                    _ => return,
                                }
                            }
                            if bytes.len() > MAX_BYTES || bytes.last() != Some(&b'\n') { return; }
                            let result = match serde_json::from_slice::<Query>(&bytes) {
                                Err(error) => Err(format!("invalid attention query: {error}")),
                                Ok(query) => match handle.attention(info.channel_id, info.peer, None, Operation::Page(query)).await {
                                    Ok(Reply::Page(page)) => Ok(page),
                                    Ok(_) => Err("unexpected attention query answer".into()),
                                    Err(error) => Err(error),
                                },
                            };
                            if let Ok(mut bytes) = serde_json::to_vec(&result) {
                                bytes.push(b'\n');
                                if bytes.len() <= MAX_BYTES {
                                    let mut authority = handle.watch();
                                    let withdrawn = async {
                                        loop {
                                            let allowed = {
                                                let current = authority.borrow();
                                                let own = current.identity.as_ref().is_some_and(|id| id.fingerprint == info.peer);
                                                !current.locked && !current.locking && (own || current.drive.contains(&info.peer)) && current.open_channels.iter().any(|room| room.channel_id == info.channel_id && (own || room.members.contains(&info.peer)) && result.as_ref().map_or(true, |page| page.instance == room.history_instance))
                                            };
                                            if !allowed || authority.changed().await.is_err() { return; }
                                        }
                                    };
                                    tokio::select! { biased; () = withdrawn => {}, _ = stream.write_all(&bytes) => {} }
                                }
                            }
                            stream.finish().await;
                        }) => {},
                    }
                });
            }
        });
    }
    pub(super) async fn attention_own(
        &self,
        handle: &NodeHandle,
        request: OwnRequest,
        mut stream: tokio::net::UnixStream,
    ) {
        let result = match handle.view().identity {
            Some(identity) => {
                handle
                    .attention(
                        request.room,
                        identity.fingerprint,
                        request.instance,
                        request.operation,
                    )
                    .await
            }
            None => Err("this node is locked".into()),
        };
        if let Ok(bytes) = OwnRequest::answer(&result) {
            let _ = vox_core::node::ipc::write_frame(&mut stream, &bytes).await;
        }
    }
}
