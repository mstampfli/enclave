//! Phase 3 end-to-end: two clients stream sealed media frames through the relay.
//! The server fans out the frames but sees only ciphertext; the far end derives
//! the sender's media key and opens them. This is the whole product premise on
//! the real transport, minus the codec (synthetic "encoded" frames stand in for
//! Opus output, which is what the sealing layer operates on either way).

mod common;

use common::{establish, recv_media, GROUP};
use enclave_crypto::{MediaOpener, MediaSealer};
use enclave_protocol::{ClientMsg, DeviceId, MediaKind};

#[tokio::test]
async fn two_clients_stream_sealed_audio_through_the_server() {
    let mut e = establish().await;

    // Both sides derive the shared media root secret; Bob keys an opener to
    // Alice's identity, as a real client would from the group roster.
    let root_alice = e.alice_group.media_root_secret(&e.alice).unwrap();
    let root_bob = e.bob_group.media_root_secret(&e.bob).unwrap();
    assert_eq!(root_alice, root_bob);

    let mut sealer = MediaSealer::new(
        &root_alice,
        GROUP,
        DeviceId("alice".into()),
        &e.alice.identity_key(),
        1,
        e.alice.media_signer().unwrap(),
    )
    .unwrap();
    let mut opener = MediaOpener::new(&root_bob, &GROUP, &e.alice.identity_key(), 1).unwrap();

    // Stream several synthetic "encoded audio" frames through the server.
    let frames: Vec<Vec<u8>> = (0..8).map(|i| vec![(i * 17) as u8; 120]).collect();
    for frame in &frames {
        let sealed = sealer.seal(MediaKind::Audio, frame).unwrap();
        e.alice_conn.send(ClientMsg::Media(sealed));
    }

    for expected in &frames {
        let relayed = recv_media(&mut e.bob_conn).await;
        // What crossed the server is ciphertext, not the frame.
        assert!(
            !relayed
                .payload
                .0
                .windows(expected.len())
                .any(|w| w == expected.as_slice()),
            "relayed media payload must be opaque"
        );
        let opened = opener.open(&relayed).unwrap();
        assert_eq!(&opened, expected, "far end recovers the clear frame");
    }
}
