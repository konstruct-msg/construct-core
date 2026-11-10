//! The name a person is shown by, the same on every client.
//!
//! A person who chose no name is called by one generated from their account id: an adjective and
//! an animal, or one time in five an IT noun, picked by the SHA-256 of the id ("silent dolphin").
//! Which name is shown when there are several — the one we gave them, the one they shared, their
//! username, the generated one — is the second rule here. Both were written three times (iOS
//! `DisplayNameGenerator` / `ContactName.resolved`, Android `DisplayNameGenerator` /
//! `resolvedName`, construct-client `names.rs`) and had already diverged once: until 2026-10-07 a
//! username won over the shared name on Android ("@ALICE" there, "ALICE" on iOS). The copies left
//! differed in whitespace and in an empty alias (construct-docs `decisions/client-rules-shared-in-rust.md`).
//!
//! The word lists are iOS's, in order, repeats included: the index is taken modulo their length,
//! so a list changes every name after the change. SHA-256 here only picks words; nothing is secret.

use sha2::{Digest, Sha256};

/// The generated name of `user_id`, lower case ("silent dolphin").
pub fn generated(user_id: &str) -> String {
    let hash = Sha256::digest(user_id.as_bytes());
    let index = |at: usize, len: usize| {
        let value = u32::from_be_bytes([hash[at], hash[at + 1], hash[at + 2], hash[at + 3]]);
        value as usize % len
    };
    let adjective = ADJECTIVES[index(0, ADJECTIVES.len())];
    let noun = if hash[8] % 5 == 0 {
        IT_NOUNS[index(4, IT_NOUNS.len())]
    } else {
        ANIMALS[index(4, ANIMALS.len())]
    };
    format!("{adjective} {noun}")
}

/// Whether `name` is only `user_id`'s generated name — something any client computes for itself,
/// so it says nothing about what the person chose to be called. Case and surrounding whitespace
/// are ignored: earlier iOS builds capitalised it.
pub fn is_generated(name: &str, user_id: &str) -> bool {
    name.trim().eq_ignore_ascii_case(&generated(user_id))
}

/// The name `user_id` is shown by: the name we gave them ourselves, then the name they shared
/// unless it is only their generated one, then their username, then the generated name. Each is
/// trimmed, and an empty one is none.
pub fn shown(alias: Option<&str>, display_name: &str, username: &str, user_id: &str) -> String {
    if let Some(alias) = alias.map(str::trim).filter(|a| !a.is_empty()) {
        return alias.to_owned();
    }
    let display_name = display_name.trim();
    if !display_name.is_empty() && !is_generated(display_name, user_id) {
        return display_name.to_owned();
    }
    let username = username.trim();
    if !username.is_empty() {
        return username.to_owned();
    }
    generated(user_id)
}

const ADJECTIVES: [&str; 102] = [
    "silent",
    "happy",
    "swift",
    "brave",
    "gentle",
    "calm",
    "bright",
    "bold",
    "quick",
    "quiet",
    "wise",
    "noble",
    "free",
    "kind",
    "pure",
    "jolly",
    "witty",
    "fierce",
    "proud",
    "sly",
    "lucky",
    "cheerful",
    "jovial",
    "merry",
    "clever",
    "cunning",
    "valiant",
    "humble",
    "clear",
    "cool",
    "warm",
    "soft",
    "strong",
    "wild",
    "misty",
    "sunny",
    "cloudy",
    "starry",
    "frosty",
    "stormy",
    "ember",
    "blazing",
    "frozen",
    "mountain",
    "ocean",
    "river",
    "forest",
    "desert",
    "volcanic",
    "thunder",
    "solar",
    "lunar",
    "celestial",
    "crystal",
    "golden",
    "silver",
    "copper",
    "obsidian",
    "amber",
    "crimson",
    "azure",
    "verdant",
    "sleek",
    "sharp",
    "smooth",
    "tall",
    "deep",
    "light",
    "dark",
    "ancient",
    "agile",
    "majestic",
    "elegant",
    "graceful",
    "giant",
    "tiny",
    "nimble",
    "radiant",
    "gleaming",
    "shadowy",
    "whispering",
    "echoing",
    "vivid",
    "mystic",
    "hidden",
    "lonely",
    "weathered",
    "deprecated",
    "recursive",
    "async",
    "frozen",
    "nested",
    "compiled",
    "broken",
    "pending",
    "idle",
    "verbose",
    "headless",
    "orphaned",
    "forked",
    "stale",
    "cursed",
];

const ANIMALS: [&str; 101] = [
    "fox",
    "wolf",
    "bear",
    "lion",
    "tiger",
    "panda",
    "jaguar",
    "panther",
    "leopard",
    "cheetah",
    "lynx",
    "cougar",
    "hyena",
    "jackal",
    "dingo",
    "wolverine",
    "otter",
    "seal",
    "orca",
    "dolphin",
    "whale",
    "shark",
    "ferret",
    "mongoose",
    "badger",
    "deer",
    "moose",
    "elk",
    "bison",
    "hare",
    "rabbit",
    "squirrel",
    "beaver",
    "hedgehog",
    "bat",
    "boar",
    "ox",
    "ram",
    "stag",
    "marten",
    "meerkat",
    "eagle",
    "hawk",
    "owl",
    "raven",
    "falcon",
    "swan",
    "dove",
    "crane",
    "heron",
    "sparrow",
    "robin",
    "finch",
    "wren",
    "phoenix",
    "crow",
    "vulture",
    "albatross",
    "kingfisher",
    "kestrel",
    "harrier",
    "gull",
    "penguin",
    "peacock",
    "parrot",
    "hornbill",
    "nightjar",
    "dragon",
    "griffin",
    "unicorn",
    "pegasus",
    "basilisk",
    "chimera",
    "kraken",
    "hydra",
    "manticore",
    "gryphon",
    "yeti",
    "kitsune",
    "sphinx",
    "serpent",
    "cobra",
    "viper",
    "python",
    "rattler",
    "gecko",
    "iguana",
    "scorpion",
    "spider",
    "mantis",
    "beetle",
    "butterfly",
    "moth",
    "dragonfly",
    "mammoth",
    "saber",
    "raptor",
    "tricera",
    "rex",
    "titan",
    "direwolf",
];

const IT_NOUNS: [&str; 58] = [
    "printer",
    "keyboard",
    "monitor",
    "server",
    "router",
    "modem",
    "firewall",
    "switch",
    "hub",
    "rack",
    "cable",
    "dongle",
    "cursor",
    "terminal",
    "daemon",
    "kernel",
    "process",
    "thread",
    "socket",
    "buffer",
    "pointer",
    "callback",
    "semaphore",
    "mutex",
    "cron",
    "webhook",
    "pipeline",
    "protocol",
    "endpoint",
    "payload",
    "namespace",
    "instance",
    "container",
    "cluster",
    "registry",
    "proxy",
    "gateway",
    "runtime",
    "compiler",
    "debugger",
    "spreadsheet",
    "invoice",
    "deadline",
    "standup",
    "backlog",
    "ticket",
    "milestone",
    "stakeholder",
    "deployment",
    "outage",
    "rollback",
    "hotfix",
    "sprint",
    "retro",
    "roadmap",
    "handover",
    "escalation",
    "pivot",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The golden vectors iOS, Android and construct-client checked against each other: a
    /// person is called the same on every client. Mutation that reddens it: any change to the
    /// index (byte order, offset, the 1-in-5 test) or to a list.
    #[test]
    fn names_match_the_clients_vectors() {
        for (id, name) in [
            ("550e8400-e29b-41d4-a716-446655440000", "cool cobra"),
            ("14f28d31-0000-0000-0000-000000000000", "silver raven"),
            ("test", "ancient sphinx"),
            ("construct", "idle deer"),
            ("6f5e37ac9b2d4e1f8a0c5d6e7f80911a", "gleaming serpent"),
        ] {
            assert_eq!(generated(id), name, "{id}");
        }
    }

    /// One in five names takes an IT noun: the vectors above are all animals, so this pins the
    /// other branch. Mutation that reddens it: drop the `hash[8] % 5` branch.
    #[test]
    fn some_names_take_an_it_noun() {
        let with_noun = (0..200)
            .map(|i| generated(&format!("user-{i}")))
            .filter(|n| IT_NOUNS.contains(&n.split(' ').nth(1).unwrap()))
            .count();
        assert!((20..=60).contains(&with_noun), "{with_noun} of 200");
    }

    #[test]
    fn the_lists_are_the_clients_lengths() {
        assert_eq!(
            (ADJECTIVES.len(), ANIMALS.len(), IT_NOUNS.len()),
            (102, 101, 58)
        );
    }

    /// Mutation that reddens it: compare with case, or untrimmed.
    #[test]
    fn a_generated_name_is_known_in_any_case() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        assert!(is_generated("Cool Cobra", id));
        assert!(is_generated("  cool cobra ", id));
        assert!(!is_generated("cool cobras", id));
    }

    /// The order, and what each step skips. Mutations that redden it: let a generated shared name
    /// through; put the username before the shared name; keep a blank alias; return untrimmed.
    #[test]
    fn the_shown_name_follows_the_order() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(shown(None, "Анна", "anna_k", id), "Анна");
        assert_eq!(
            shown(None, "Cool Cobra", "anna_k", id),
            "anna_k",
            "a generated name is no name"
        );
        assert_eq!(shown(None, "", "", id), "cool cobra");
        assert_eq!(
            shown(Some(" Аня "), "Анна", "anna_k", id),
            "Аня",
            "ours wins"
        );
        assert_eq!(
            shown(Some("  "), "Анна", "anna_k", id),
            "Анна",
            "a blank alias is none"
        );
        assert_eq!(
            shown(Some(""), "Анна", "anna_k", id),
            "Анна",
            "an empty alias is none"
        );
        assert_eq!(shown(None, " Анна ", "anna_k", id), "Анна", "trimmed");
        assert_eq!(
            shown(None, "  ", " anna_k ", id),
            "anna_k",
            "a blank shared name is none"
        );
    }
}
