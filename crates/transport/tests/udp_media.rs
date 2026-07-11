//! Phase 3 glue: the low-latency UDP media carrier. Two clients open UDP media
//! sockets to the relay and stream sealed frames; the relay fans them out
//! seeing only ciphertext, and the far end opens them.

mod common;

use std::time::Duration;

use common::{establish, GROUP};
use enclave_crypto::{MediaOpener, MediaSealer};
use enclave_protocol::{DeviceId, MediaKind};
use enclave_transport::MediaSocket;

#[tokio::test]
async fn media_streams_over_udp_and_far_end_opens_it() {
    let e = establish().await;

    let root_alice = e.alice_group.media_root_secret(&e.alice).unwrap();
    let root_bob = e.bob_group.media_root_secret(&e.bob).unwrap();
    let mut sealer = MediaSealer::new(
        &root_alice,
        GROUP,
        DeviceId("alice-1".into()),
        &e.alice.identity_key(),
        1,
    )
    .unwrap();
    let mut opener = MediaOpener::new(&root_bob, &GROUP, &e.alice.identity_key(), 1).unwrap();

    let alice_media = MediaSocket::connect(e.media_addr, DeviceId("alice-1".into()), GROUP)
        .await
        .unwrap();
    let bob_media = MediaSocket::connect(e.media_addr, DeviceId("bob-1".into()), GROUP)
        .await
        .unwrap();

    // Let both Hello packets register the endpoints before streaming.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let plaintexts: Vec<Vec<u8>> = (0..5).map(|i| vec![(i * 41) as u8; 100]).collect();
    for pt in &plaintexts {
        let frame = sealer.seal(MediaKind::Audio, pt).unwrap();
        alice_media.send_frame(&frame).await.unwrap();
    }

    // Collect the frames (UDP may reorder, so compare as a set).
    let mut opened = Vec::new();
    for _ in 0..plaintexts.len() {
        let relayed = tokio::time::timeout(Duration::from_secs(5), bob_media.recv_frame())
            .await
            .expect("timed out waiting for a UDP frame")
            .expect("recv frame");

        // The relay forwarded ciphertext, not the plaintext.
        assert!(
            !relayed
                .payload
                .0
                .windows(100)
                .any(|w| plaintexts.iter().any(|p| w == p.as_slice())),
            "relayed UDP payload must be opaque"
        );
        opened.push(opener.open(&relayed).unwrap());
    }

    for expected in &plaintexts {
        assert!(
            opened.iter().any(|o| o == expected),
            "far end did not recover frame {expected:?}"
        );
    }
}
