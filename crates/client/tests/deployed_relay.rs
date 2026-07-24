//! Smoke test for a DEPLOYED relay (a container, cp1, anything reachable).
//!
//! Skipped unless `ENCLAVE_RELAY_URL` is set, so it never runs in CI -- the rest
//! of the suite covers the protocol against an in-process relay. Point it at a
//! deployment to prove the real thing works end to end:
//!
//! ```sh
//! ENCLAVE_RELAY_URL=ws://127.0.0.1:8443 cargo test -p enclave-client \
//!     --test deployed_relay -- --nocapture
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use enclave_client::Client;

async fn pump_until<F: Fn(&Client) -> bool>(client: &mut Client, pred: F) -> bool {
    for _ in 0..400 {
        if pred(client) {
            return true;
        }
        let _ = tokio::time::timeout(Duration::from_millis(50), client.next_event()).await;
    }
    pred(client)
}

/// A fresh account name per run: a deployed relay keeps its account store, so
/// reusing a name across runs would collide.
fn unique(prefix: &str) -> String {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{prefix}{}", n % 1_000_000_000)
}

async fn account(url: &str, name: &str) -> Client {
    let mut c = Client::connect(url).await.expect("connect to the relay");
    c.set_keystore_dir(std::env::temp_dir());
    c.create_account(name, "", "deploy-smoke-password-1234")
        .await
        .expect("create account");
    c
}

/// Two real clients, a workspace, a text channel, a message and a FILE -- the
/// full path a deployment has to serve.
#[tokio::test]
async fn a_deployed_relay_carries_a_workspace_channel_file() {
    let Ok(url) = std::env::var("ENCLAVE_RELAY_URL") else {
        eprintln!("ENCLAVE_RELAY_URL not set; skipping the deployed-relay smoke test");
        return;
    };
    eprintln!("testing deployed relay at {url}");

    let mut owner = account(&url, &unique("owner")).await;
    let mut bob = account(&url, &unique("bob")).await;
    let owner_h = owner.name().to_string();
    let bob_h = bob.name().to_string();

    let ws = owner.create_workspace("Deploy Check").unwrap();
    assert!(
        pump_until(&mut owner, |c| c.workspace(&ws).is_some()).await,
        "workspace never materialized through the deployed relay"
    );

    owner.workspace_add_member(&ws, &bob_h).await.unwrap();
    assert!(
        pump_until(&mut bob, |c| c
            .workspace(&ws)
            .is_some_and(|s| s.members.len() == 2))
        .await,
        "the invited member never joined through the deployed relay"
    );
    assert!(
        pump_until(&mut owner, |c| c
            .workspace(&ws)
            .is_some_and(|s| s.members.len() == 2))
        .await
    );

    let chan = owner.create_channel(&ws, "general", None).unwrap();
    assert!(
        pump_until(&mut bob, |c| c
            .workspace(&ws)
            .is_some_and(|s| !s.channels.is_empty()))
        .await,
        "the channel never reached the other member"
    );

    // Text.
    owner.send_channel_post(&ws, &chan, "deploy check").unwrap();
    assert!(
        pump_until(&mut bob, |c| c
            .channel_history(&ws, &chan)
            .iter()
            .any(|m| m.text == "deploy check"))
        .await,
        "a channel message did not cross the deployed relay"
    );

    // File: written, posted, and byte-identical on the far side.
    let contents = b"deployed relay file check\x00\x01\xfe\xff".to_vec();
    let src = std::env::temp_dir().join(format!("enclave-deploy-{}.bin", std::process::id()));
    std::fs::write(&src, &contents).unwrap();
    owner
        .send_channel_file(&ws, &chan, &src.to_string_lossy())
        .unwrap();
    assert!(
        pump_until(&mut bob, |c| c
            .channel_history(&ws, &chan)
            .iter()
            .any(|m| m.file.is_some()))
        .await,
        "a channel file did not cross the deployed relay"
    );
    let hist = bob.channel_history(&ws, &chan);
    let line = hist.iter().find(|m| m.file.is_some()).unwrap();
    assert_eq!(line.user, owner_h, "file attributed to its signer");
    let f = line.file.as_ref().unwrap();
    assert_eq!(f.size, contents.len() as u64);
    assert_eq!(
        std::fs::read(&f.path).expect("stored file"),
        contents,
        "file bytes survived the deployed relay intact"
    );
    let _ = std::fs::remove_file(&src);

    eprintln!("deployed relay OK: workspace, channel, message and file all round-tripped");
}
