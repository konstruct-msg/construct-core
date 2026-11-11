//! A delayed message of a previous state still reads after a delayed message of the current one
//! (TODO 298). Found while measuring TODO 296: the current state answered such a message with
//! `MESSAGE_KEY_CONSUMED` — a duplicate verdict — because its PQ chain had passed the same
//! `(epoch, index)`, and a duplicate ends the search, so the state that could read it was never
//! tried. The message was lost without a trace.

#[path = "../examples/support/allocation_fixture.rs"]
#[allow(dead_code)]
mod fixture;

use fixture::{Pair, delayed_sequence};

/// Two states, one delayed message in each, read newest state first.
#[test]
fn a_delayed_message_of_the_previous_state_reads_after_one_of_the_current() {
    let pair = Pair::with_history(1, 1);
    delayed_sequence(&pair).unwrap();
}

/// The common case after a renewal: one message of the old state is late, and the new state has
/// meanwhile read its own messages in order past the same PQ position — nothing skipped in it.
#[test]
fn a_late_message_of_the_old_state_reads_after_the_new_one_moved_on() {
    let mut pair = Pair::new();
    let late = pair.alice.encrypt_bytes_for(&pair.bob_id, b"late").unwrap();
    let on_time = pair
        .alice
        .encrypt_bytes_for(&pair.bob_id, b"on time")
        .unwrap();
    assert_eq!(
        pair.bob
            .decrypt_bytes_for(&pair.alice_id, &on_time)
            .unwrap(),
        b"on time"
    );

    pair.reopen();
    for i in 0..4 {
        let text = format!("new state {i}");
        let wire = pair
            .alice
            .encrypt_bytes_for(&pair.bob_id, text.as_bytes())
            .unwrap();
        assert_eq!(
            pair.bob.decrypt_bytes_for(&pair.alice_id, &wire).unwrap(),
            text.as_bytes()
        );
    }

    assert_eq!(
        pair.bob.decrypt_bytes_for(&pair.alice_id, &late).unwrap(),
        b"late"
    );
}

/// The shape the measurement found it in: many skipped keys, three previous states.
#[test]
fn every_held_state_reads_its_delayed_message_in_turn() {
    let pair = Pair::with_history(50, 3);
    delayed_sequence(&pair).unwrap();
}
