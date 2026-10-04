//! PRD-001 R36 (#406) — what the embedded node reports to an app is a sentence. `on_notice` reaches
//! the macOS app's user as text, and it carried each event's debug form
//! (`ChannelOpened { channel_id: [12, 200, …] }`). Driven through the library's public API exactly
//! as an app calls it: `VoxNode::start`, `subscribe`, `create_room`.
//!
//! The claim: once a room is created, the app hears that the room is open, in words, and no notice
//! is an event's debug form. Mutant: `on_notice(format!("{other:?}"))` restored in `subscribe`, red
//! as `PRODUCT: a notice is an event's debug form`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vox_ffi::{EventListener, Message, VoxNode};

#[derive(Default)]
struct Heard(Mutex<Vec<String>>);

impl EventListener for Heard {
    fn on_message(&self, _room: String, _message: Message) {}
    fn on_notice(&self, text: String) {
        self.0.lock().unwrap().push(text);
    }
}

/// Whether `text` is a Rust debug form: a variant name alone, or one followed by its fields.
fn debug_form(text: &str) -> bool {
    let name: String = text
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    let rest = &text[name.len()..];
    let variant = name.chars().next().is_some_and(char::is_uppercase)
        && name.chars().skip(1).any(char::is_uppercase);
    (variant && (rest.is_empty() || rest.starts_with(" {") || rest.starts_with('(')))
        || text.contains("channel_id:")
        || text.contains("peer:")
}

#[test]
#[ignore = "a real embedded node with production Argon2id; run on demand in release"]
fn an_apps_notices_are_sentences() {
    let dir = std::env::temp_dir().join(format!("vox-ffi-notices-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("APPARATUS: temp dir");
    let heard = Arc::new(Heard::default());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: a runtime to call the library from");
    let node = rt
        .block_on(VoxNode::start(
            dir.to_string_lossy().into_owned(),
            "the app's passphrase".into(),
            "127.0.0.1:0".into(),
        ))
        .expect("PRODUCT (staging): the embedded node did not start");
    node.subscribe(heard.clone());
    let room = rt
        .block_on(node.create_room("r".into(), "the room's passphrase".into()))
        .expect("PRODUCT (staging): the room was not created");
    let short: String = room.chars().take(12).collect();
    let opened = format!("room {short} is open");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline && !heard.0.lock().unwrap().iter().any(|t| t == &opened) {
        std::thread::sleep(Duration::from_millis(100));
    }
    // Whatever else the node reports as it settles.
    std::thread::sleep(Duration::from_secs(2));
    rt.block_on(node.stop());
    drop(node);
    drop(rt);
    let _ = std::fs::remove_dir_all(&dir);

    let notices = heard.0.lock().unwrap().clone();
    println!(
        "[proof] the app heard {} notices: {notices:?}",
        notices.len()
    );
    let dumps: Vec<&String> = notices.iter().filter(|t| debug_form(t)).collect();
    assert!(
        dumps.is_empty(),
        "PRODUCT: a notice is an event's debug form: {dumps:?}"
    );
    assert!(
        notices.contains(&opened),
        "PRODUCT: the app never heard {opened:?} in words: {notices:?}"
    );
}
