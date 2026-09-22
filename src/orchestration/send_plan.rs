//! Who gets a copy of an outgoing message.
//!
//! # Why this is here and not in a client
//!
//! "Which sessions does this message go into" is a plan, and a plan is protocol. It answers three
//! questions that the iOS client used to answer in two places each, differently: which devices are
//! targets, whether our own sending device is one of them, and whose device each copy is. The
//! recipient-fan-out path and the own-replica path had drifted from each other, and the drift was
//! invisible — a device simply never received a message, which looks exactly like a peer who has
//! not written.
//!
//! The client keeps what this crate cannot have: it fetches the bundles, knows which account it is
//! writing to, and knows whether that account is its own — all account-space facts, and
//! `ServerUserId` does not exist here. What it hands over is the device id sets; what it gets back
//! is who to send to and as what.
//!
//! See `construct-docs/decisions/a-peer-is-a-set-of-devices.md`.

/// Whose device a copy is for. The two differ in which account the envelope is addressed to and in
/// whether it may travel unsealed — a copy to our own device is the pair (me, me), which the relay
/// already knows; a copy to a peer's device is not, and must be sealed to that device's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryAudience {
    /// A device of the person we are writing to.
    Recipient,
    /// Another of our own devices, so the message appears in its transcript too.
    OwnReplica,
}

/// One device that must receive its own ciphertext of an outgoing message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryTarget {
    pub device_id: String,
    pub audience: DeliveryAudience,
}

/// Every device that must receive a copy.
///
/// * `recipient_device_ids` — the devices of the person we are writing to. Empty when writing to
///   ourselves; see `recipient_is_self`.
/// * `own_device_ids` — our account's devices, **including this one**. Filtered here rather than by
///   each caller, because forgetting to is invisible: delivery hands us our own copy back anyway,
///   so the symptom is a device trying to open a message it wrote.
/// * `our_device_id` — this device; empty means unknown. Then no own-replica copies are planned at
///   all: we cannot tell ourselves apart from our replicas, and sending to all of them would
///   include a copy addressed to this device.
/// * `recipient_is_self` — a note to self. Then the recipient's devices *are* our devices, and
///   planning both audiences would send every replica two copies of one message. This is an
///   account-space comparison, which is why it is an argument and not a derivation.
///
/// There was a sixth argument, `primary_send_covered`: the one recipient device that an ordinary
/// send had already reached, to be skipped here. It existed because a message went out twice — an
/// account-addressed send to one device, then a fan-out to the rest — and the two paths had to
/// agree on which device not to collide over. Both clients stopped sending that way
/// (`construct-messenger@4a74c013`, `construct-android@5850ce8`), so there is no longer a copy
/// that could already be covered, and a parameter whose only correct value is "none" is a way for
/// a future caller to be wrong. §B item 1 of `a-peer-is-a-set-of-devices`.
///
/// Recipient devices first, then own replicas — the caller's order preserved within each group. A
/// plan whose order changes between runs makes a failure reproduce on one launch and not the next.
///
/// A device id appears at most once. Empty ids are dropped: an empty id names nobody, and it is
/// what an unresolved translation produces on the client side.
pub fn plan_send(
    recipient_device_ids: &[String],
    own_device_ids: &[String],
    our_device_id: &str,
    recipient_is_self: bool,
) -> Vec<DeliveryTarget> {
    let mut out: Vec<DeliveryTarget> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    let mut push = |id: &String, audience: DeliveryAudience, out: &mut Vec<DeliveryTarget>| {
        if id.is_empty() || seen.iter().any(|s| s == id) {
            return;
        }
        seen.push(id.clone());
        out.push(DeliveryTarget {
            device_id: id.clone(),
            audience,
        });
    };

    if !recipient_is_self {
        for id in recipient_device_ids {
            push(id, DeliveryAudience::Recipient, &mut out);
        }
    }

    if !our_device_id.is_empty() {
        for id in own_device_ids {
            if id == our_device_id {
                continue;
            }
            push(id, DeliveryAudience::OwnReplica, &mut out);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn plan(t: &[DeliveryTarget]) -> Vec<(&str, DeliveryAudience)> {
        t.iter()
            .map(|x| (x.device_id.as_str(), x.audience))
            .collect()
    }

    /// The ordinary case: a peer with two devices and one replica of ours. Asserted as a full
    /// sequence — the grouping and the order are both part of what this function decides.
    ///
    /// Both of the peer's devices are here. Until 2026-09-22 one of them would have been missing,
    /// because an account-addressed send had already reached it and `primary_send_covered` named
    /// it; that send no longer exists on either client.
    #[test]
    fn recipients_first_then_replicas() {
        let targets = plan_send(
            &ids(&["them1", "them2"]),
            &ids(&["me", "mine2"]),
            "me",
            false,
        );
        assert_eq!(
            plan(&targets),
            vec![
                ("them1", DeliveryAudience::Recipient),
                ("them2", DeliveryAudience::Recipient),
                ("mine2", DeliveryAudience::OwnReplica),
            ]
        );
    }

    /// This device is never its own target. Delivery hands us our own copy back regardless, so the
    /// symptom of getting this wrong is a device trying to open a message it wrote — which looks
    /// like a decryption failure, not like a planning mistake.
    #[test]
    fn our_own_device_is_never_a_target() {
        let targets = plan_send(&[], &ids(&["me", "mine2"]), "me", true);
        assert_eq!(
            plan(&targets),
            vec![("mine2", DeliveryAudience::OwnReplica)]
        );
    }

    /// Without knowing which device we are, no replica copy can be planned: sending to every own
    /// device would include one addressed to this one. Refusing beats guessing.
    #[test]
    fn an_unknown_own_device_plans_no_replicas() {
        let targets = plan_send(&ids(&["them1"]), &ids(&["a", "b"]), "", false);
        assert_eq!(plan(&targets), vec![("them1", DeliveryAudience::Recipient)]);
    }

    /// A note to self: the recipient's devices *are* our devices. Planning both audiences would
    /// send every replica two copies of one message.
    #[test]
    fn a_note_to_self_plans_replicas_only() {
        let targets = plan_send(&ids(&["me", "mine2"]), &ids(&["me", "mine2"]), "me", true);
        assert_eq!(
            plan(&targets),
            vec![("mine2", DeliveryAudience::OwnReplica)]
        );
    }

    /// A device appears once even if the caller's two lists overlap. Asserted with the overlap on
    /// the *recipient* side so the surviving entry proves which audience won.
    #[test]
    fn a_device_is_planned_once() {
        let targets = plan_send(&ids(&["x"]), &ids(&["x", "me"]), "me", false);
        assert_eq!(plan(&targets), vec![("x", DeliveryAudience::Recipient)]);
    }

    /// Empty ids name nobody and must not become targets.
    #[test]
    fn empty_ids_are_dropped() {
        let targets = plan_send(
            &ids(&["", "them1"]),
            &ids(&["", "mine2", "me"]),
            "me",
            false,
        );
        assert_eq!(
            plan(&targets),
            vec![
                ("them1", DeliveryAudience::Recipient),
                ("mine2", DeliveryAudience::OwnReplica),
            ]
        );
    }

    /// Nothing to send to is an empty plan, not an error — a contact whose devices we do not know
    /// yet, and no replicas of ours.
    #[test]
    fn nothing_to_copy_is_an_empty_plan() {
        assert!(plan_send(&[], &ids(&["me"]), "me", false).is_empty());
    }
}
