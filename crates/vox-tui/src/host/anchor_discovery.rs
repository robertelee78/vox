//! A daemon answers only for its currently attached headless anchor roles.
use super::*;
use vox_core::nat::bootstrap::{BootstrapNode, MAX_BOOTSTRAP_NODES};
use vox_core::nat::multiaddr::EndpointList;
use vox_core::node::nearby::anchors::Responder;

impl Router {
    pub(super) fn answer_anchor_searches(&self) {
        let weak = Arc::downgrade(&self.inner);
        self.inner.rt.spawn(async move {
            let responder = match Responder::open() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("vox daemon: cannot answer local anchor searches: {e}");
                    return;
                }
            };
            let mut last_answer = None;
            loop {
                let question =
                    tokio::time::timeout(Duration::from_secs(1), responder.question()).await;
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                if inner.stopping.load(Ordering::SeqCst) {
                    return;
                }
                let (to, nonce) = match question {
                    Ok(Ok(Some(q))) => q,
                    Ok(Err(e)) => {
                        eprintln!("vox daemon: local anchor search listener stopped: {e}");
                        return;
                    }
                    _ => {
                        drop(inner);
                        tokio::task::yield_now().await;
                        continue;
                    }
                };
                let now = tokio::time::Instant::now();
                if last_answer
                    .is_some_and(|last| now.duration_since(last) < Duration::from_millis(250))
                {
                    drop(inner);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                last_answer = Some(now);
                // No room-bearing node view is cloned: select the headless roles first.
                let anchors: Vec<_> = lock(&inner.slots)
                    .values()
                    .filter_map(|slot| match slot {
                        Slot::Attached(a) if a.anchor && !*a.ended.borrow() => {
                            a.fingerprint.map(|fp| (fp, a.handle.clone()))
                        }
                        _ => None,
                    })
                    .take(MAX_BOOTSTRAP_NODES + 1)
                    .collect();
                for (id, handle) in anchors {
                    let addresses = handle
                        .view()
                        .listening
                        .iter()
                        .filter_map(|text| vox_core::nat::multiaddr::Multiaddr::parse(text).ok())
                        .collect();
                    let Ok(endpoints) = EndpointList::new(addresses) else {
                        continue;
                    };
                    if let Ok(anchor) = BootstrapNode::new(id, endpoints) {
                        responder.answer(to, &nonce, &anchor);
                    }
                }
            }
        });
    }
}
