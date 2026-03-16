//! IAT (Inter-Arrival Time) obfuscation mode.
//!
//! Controls timing between network writes to resist traffic analysis.
//! Matches the Go obfs4 reference implementation's `iat-mode` parameter.
//!
//! Three modes (as in Go `iatNone`/`iatEnabled`/`iatParanoid`):
//! - `None (0)`:     no delay, maximum throughput (default)
//! - `Enabled (1)`:  MTU-sized chunks with 0–10ms random delays between them
//! - `Paranoid (2)`: random chunk sizes + random delays, maximum obfuscation

use std::time::Duration;

use bytes::Bytes;
use rand::Rng;

/// Maximum IAT delay (10 milliseconds).
pub const MAX_IAT_DELAY: Duration = Duration::from_millis(10);

/// Segment length used to split data in `Enabled` mode.
/// Matches Go `framing.MaximumSegmentLength = 1448`.
pub const MAX_SEGMENT_LENGTH: usize = 1448;

/// IAT (Inter-Arrival Time) obfuscation mode.
///
/// Controls how writes are timed to resist traffic-fingerprinting attacks.
/// Corresponds to the `iat-mode=N` field in obfs4 bridge lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum IatMode {
    /// No IAT obfuscation. All frames are sent as a single burst. (`iat-mode=0`)
    #[default]
    None = 0,
    /// Standard IAT. Frames split into ≤MTU chunks, random 0–10ms delay between chunks.
    /// Good balance of obfuscation and throughput. (`iat-mode=1`)
    Enabled = 1,
    /// Paranoid IAT. Random chunk sizes and random delays per chunk.
    /// Maximum obfuscation at the cost of throughput. (`iat-mode=2`)
    Paranoid = 2,
}

impl IatMode {
    /// Parse from the numeric value used in bridge lines (`iat-mode=N`).
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::None),
            1 => Some(Self::Enabled),
            2 => Some(Self::Paranoid),
            _ => None,
        }
    }

    /// Numeric value for use in bridge lines.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for IatMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_u8())
    }
}

impl std::str::FromStr for IatMode {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n: u8 = s
            .trim()
            .parse()
            .map_err(|_| crate::Error::InvalidBridgeLine(format!("invalid iat-mode '{s}'")))?;
        IatMode::from_u8(n)
            .ok_or_else(|| crate::Error::InvalidBridgeLine(format!("invalid iat-mode '{n}'")))
    }
}

/// Split pre-encoded, framed bytes into IAT transmit chunks.
///
/// - `None`:     returns a single chunk containing all data (no-op)
/// - `Enabled`:  splits at `MAX_SEGMENT_LENGTH` boundaries
/// - `Paranoid`: splits at random lengths (1 ..= `MAX_SEGMENT_LENGTH`)
pub fn split_for_iat(framed: &[u8], mode: IatMode, rng: &mut impl Rng) -> Vec<Bytes> {
    if mode == IatMode::None || framed.is_empty() {
        return vec![Bytes::copy_from_slice(framed)];
    }
    let mut chunks = Vec::new();
    let mut pos = 0;
    while pos < framed.len() {
        let chunk_size = match mode {
            IatMode::None => framed.len() - pos,
            IatMode::Enabled => MAX_SEGMENT_LENGTH.min(framed.len() - pos),
            IatMode::Paranoid => {
                let target: usize = rng.gen_range(1..=MAX_SEGMENT_LENGTH);
                target.min(framed.len() - pos)
            }
        };
        chunks.push(Bytes::copy_from_slice(&framed[pos..pos + chunk_size]));
        pos += chunk_size;
    }
    chunks
}

/// Sample a random IAT delay (0 – 10 ms in 100 µs steps).
///
/// Matches the Go formula: `iatDelta = iatDist.Sample() * 100` µs,
/// with `iatDist` uniform over [0, maxIATDelay].
pub fn sample_delay(rng: &mut impl Rng) -> Duration {
    sample_delay_with_max(rng, MAX_IAT_DELAY)
}

/// Sample a random IAT delay up to the given maximum.
///
/// Uses a log-normal-approximated distribution when `max > 10ms`:
/// most delays are short, but occasional long pauses mimic real
/// application think-time (e.g. user reading a message).
pub fn sample_delay_with_max(rng: &mut impl Rng, max: Duration) -> Duration {
    let max_us = max.as_micros() as u64;
    if max_us <= 10_000 {
        // Classic obfs4: uniform in 100µs steps
        let units = max_us / 100;
        if units == 0 {
            return Duration::ZERO;
        }
        let u: u64 = rng.gen_range(0..=units);
        Duration::from_micros(u * 100)
    } else {
        // Extended mode: log-normal-ish via squaring a uniform sample.
        // This concentrates most delays near 0 with a heavy tail up to max,
        // which resembles real web traffic inter-arrival times.
        let u: f64 = rng.gen_range(0.0..1.0);
        let delay_us = (u * u * max_us as f64) as u64;
        Duration::from_micros(delay_us)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn seeded_rng() -> rand::rngs::SmallRng {
        rand::rngs::SmallRng::seed_from_u64(0xdeadbeef)
    }

    #[test]
    fn iat_mode_roundtrip() {
        for &n in &[0u8, 1, 2] {
            let mode = IatMode::from_u8(n).unwrap();
            assert_eq!(mode.as_u8(), n);
        }
        assert!(IatMode::from_u8(3).is_none());
    }

    #[test]
    fn iat_mode_from_str() {
        use std::str::FromStr;
        assert_eq!(IatMode::from_str("0").unwrap(), IatMode::None);
        assert_eq!(IatMode::from_str("1").unwrap(), IatMode::Enabled);
        assert_eq!(IatMode::from_str("2").unwrap(), IatMode::Paranoid);
        assert!(IatMode::from_str("3").is_err());
        assert!(IatMode::from_str("xyz").is_err());
    }

    #[test]
    fn split_none_is_single_chunk() {
        let data = vec![42u8; 3000];
        let mut rng = seeded_rng();
        let chunks = split_for_iat(&data, IatMode::None, &mut rng);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 3000);
    }

    #[test]
    fn split_enabled_at_mtu_boundaries() {
        let data = vec![1u8; 4000];
        let mut rng = seeded_rng();
        let chunks = split_for_iat(&data, IatMode::Enabled, &mut rng);
        // 4000 / 1448 = 2 full + 1 partial = 3 chunks
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), MAX_SEGMENT_LENGTH);
        assert_eq!(chunks[1].len(), MAX_SEGMENT_LENGTH);
        assert_eq!(chunks[2].len(), 4000 - 2 * MAX_SEGMENT_LENGTH);
        // All bytes preserved
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, 4000);
    }

    #[test]
    fn split_paranoid_random_sizes() {
        let data = vec![7u8; 5000];
        let mut rng = seeded_rng();
        let chunks = split_for_iat(&data, IatMode::Paranoid, &mut rng);
        assert!(chunks.len() >= 4); // should split into several chunks
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        assert_eq!(total, 5000);
        for chunk in &chunks {
            assert!(chunk.len() <= MAX_SEGMENT_LENGTH);
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn sample_delay_within_range() {
        let mut rng = seeded_rng();
        for _ in 0..1000 {
            let d = sample_delay(&mut rng);
            assert!(d <= MAX_IAT_DELAY, "delay {d:?} exceeds max");
        }
    }

    #[test]
    fn split_empty_data_is_one_empty_chunk() {
        let mut rng = seeded_rng();
        for mode in [IatMode::None, IatMode::Enabled, IatMode::Paranoid] {
            let chunks = split_for_iat(&[], mode, &mut rng);
            assert_eq!(chunks.len(), 1);
            assert!(chunks[0].is_empty());
        }
    }
}
