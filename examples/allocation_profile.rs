//! TODO 296 allocation counts. Timing benchmarks use System without this wrapper.
#[path = "support/allocation_fixture.rs"]
mod fixture;

use construct_core::cfe::{self, CfeMessageType};
use construct_core::orchestration::IncomingEvent;
use fixture::*;
use serde_json::json;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

struct CountingAllocator;
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
static ACTIVE: AtomicBool = AtomicBool::new(false);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static REALLOCS: AtomicUsize = AtomicUsize::new(0);
static REALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);
static SHRINK_MOVED: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn malloc_size(pointer: *const std::ffi::c_void) -> usize;
}

fn allocated(size: usize, is_realloc: bool) {
    let live = LIVE.fetch_add(size, Relaxed) + size;
    if ACTIVE.load(Relaxed) {
        PEAK.fetch_max(live, Relaxed);
        if is_realloc {
            REALLOCS.fetch_add(1, Relaxed);
            REALLOC_BYTES.fetch_add(size, Relaxed);
        } else {
            ALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(size, Relaxed);
        }
    }
}

// SAFETY: Every call forwards the original pointer/layout to System. Counters allocate no
// memory and track successful operations only. The executable is single-threaded during phases.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            allocated(layout.size(), false);
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            allocated(layout.size(), false);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            System.dealloc(ptr, layout);
        }
        LIVE.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, size) };
        if !new.is_null() {
            if ACTIVE.load(Relaxed) && size < layout.size() && new != ptr {
                SHRINK_MOVED.fetch_add(1, Relaxed);
            }
            LIVE.fetch_sub(layout.size(), Relaxed);
            allocated(size, true);
        }
        new
    }
}

fn start_measurement() -> usize {
    let baseline = LIVE.load(Relaxed);
    ALLOCS.store(0, Relaxed);
    BYTES.store(0, Relaxed);
    REALLOCS.store(0, Relaxed);
    REALLOC_BYTES.store(0, Relaxed);
    SHRINK_MOVED.store(0, Relaxed);
    PEAK.store(baseline, Relaxed);
    ACTIVE.store(true, Relaxed);
    baseline
}

fn measure(name: &str, metadata: &serde_json::Value, f: impl FnOnce()) -> serde_json::Value {
    let baseline = start_measurement();
    f();
    ACTIVE.store(false, Relaxed);
    let allocations = ALLOCS.load(Relaxed);
    let bytes = BYTES.load(Relaxed);
    let reallocations = REALLOCS.load(Relaxed);
    let realloc_bytes = REALLOC_BYTES.load(Relaxed);
    let peak = PEAK.load(Relaxed).saturating_sub(baseline);
    let retained = LIVE.load(Relaxed) as i64 - baseline as i64;
    json!({"case": name, "metadata": metadata, "allocations": allocations,
        "allocated_bytes": bytes, "reallocations": reallocations,
        "realloc_requested_bytes": realloc_bytes, "additional_peak_bytes": peak,
        "live_delta_after_drop": retained})
}

fn measure_held(
    name: &str,
    metadata: &serde_json::Value,
    f: impl FnOnce() -> Vec<u8>,
) -> serde_json::Value {
    let baseline = start_measurement();
    let output = black_box(f());
    ACTIVE.store(false, Relaxed);
    let allocations = ALLOCS.load(Relaxed);
    let bytes = BYTES.load(Relaxed);
    let reallocations = REALLOCS.load(Relaxed);
    let realloc_bytes = REALLOC_BYTES.load(Relaxed);
    let peak = PEAK.load(Relaxed).saturating_sub(baseline);
    let held = LIVE.load(Relaxed) as i64 - baseline as i64;
    let shrink_moved = SHRINK_MOVED.load(Relaxed);
    let len = output.len();
    let capacity = output.capacity();
    // SAFETY: a nonempty Vec<u8> allocated by System starts at its malloc allocation base.
    #[cfg(target_os = "macos")]
    let backend_bytes = Some(unsafe { malloc_size(output.as_ptr().cast()) });
    #[cfg(not(target_os = "macos"))]
    let backend_bytes: Option<usize> = None;
    drop(output);
    let after_drop = LIVE.load(Relaxed) as i64 - baseline as i64;
    assert_eq!(
        held, capacity as i64,
        "only the returned output should remain live"
    );
    assert_eq!(after_drop, 0);
    json!({"case":name,"metadata":metadata,"allocations":allocations,"allocated_bytes":bytes,
        "reallocations":reallocations,"realloc_requested_bytes":realloc_bytes,
        "additional_peak_bytes":peak,"live_bytes_with_output":held,"live_delta_after_drop":after_drop,
        "output_len":len,"output_capacity":capacity,"backend_output_bytes":backend_bytes,
        "shrink_relocations":shrink_moved})
}

fn main() {
    if std::env::args().any(|a| a == "--held-outputs") {
        for &(skipped, previous) in CASES {
            let pair = Pair::with_history(skipped, previous);
            let mut current = decode_session(&pair.bob, &pair.alice_id);
            current.previous.clear();
            let metadata = json!({"skipped":skipped,"previous":previous});
            let stage = measure_held(
                &format!("held/S4/k{skipped}_p{previous}"),
                &metadata,
                || cfe::encode(CfeMessageType::SessionState, &current).unwrap(),
            );
            let full = measure_held(
                &format!("held/SF/k{skipped}_p{previous}"),
                &metadata,
                || pair.bob.export_session_cfe(&pair.alice_id).unwrap(),
            );
            println!("{stage}");
            println!("{full}");
        }
        return;
    }
    let empty = json!({});
    let noop = measure("calibration/noop", &empty, || {
        black_box(0usize);
    });
    assert_eq!(noop["allocations"], 0);
    assert_eq!(noop["allocated_bytes"], 0);
    assert_eq!(noop["additional_peak_bytes"], 0);
    let one = measure("calibration/vec128", &empty, || {
        let mut bytes = Vec::with_capacity(128);
        bytes.resize(128, black_box(7u8));
        drop(black_box(bytes));
    });
    assert_eq!(one["allocations"], 1);
    assert_eq!(one["allocated_bytes"], 128);
    assert_eq!(one["additional_peak_bytes"], 128);
    assert_eq!(one["live_delta_after_drop"], 0);
    let grow = measure("calibration/realloc16to32", &empty, || {
        let mut bytes = Vec::with_capacity(16);
        bytes.resize(16, black_box(7u8));
        black_box(&mut bytes).reserve_exact(16);
        drop(black_box(bytes));
    });
    assert_eq!(grow["allocations"], 1);
    assert_eq!(grow["allocated_bytes"], 16);
    assert_eq!(grow["reallocations"], 1);
    assert_eq!(grow["realloc_requested_bytes"], 32);
    assert_eq!(grow["additional_peak_bytes"], 32);
    assert_eq!(grow["live_delta_after_drop"], 0);
    if std::env::args().any(|a| a == "--reproduce-delayed-sequence") {
        let pair = Pair::with_history(500, 3);
        match delayed_sequence(&pair) {
            Ok(()) => println!("delayed sequence succeeded"),
            Err(error) => {
                eprintln!("BASELINE REPRODUCTION: {error}");
                std::process::exit(1);
            }
        }
        return;
    }
    let verify_only = std::env::args().any(|a| a == "--verify");
    for len in [50, 512, 4096, 65536] {
        let mut pair = Pair::new();
        let plaintext = vec![b'a'; len];
        let message_id = format!("measured-{len}");
        let event = pair.event(&plaintext, &message_id);
        let IncomingEvent::MessageReceived { data: wire, .. } = &event else {
            unreachable!()
        };
        let d = construct_core::wire_payload::unpack(wire).unwrap();
        let metadata = json!({"plaintext":len,"wire":wire.len(),"sealed":d.sealed_box.len(),"suite":d.suite_id,"epoch":d.pq_message_epoch,"pq_field":d.pq_ratchet_field.is_some(),"handshake":d.pqxdh_v2});
        let mut rows = Vec::new();
        for (name, passes, split) in [("P1", 1, false), ("P3", 3, false), ("P4", 3, true)] {
            rows.push(measure(&format!("payload/{name}/{len}"), &metadata, || {
                parse_stage(wire, passes, split)
            }));
        }
        // Independent invariant: a changed loop must change these exact allocation counts.
        assert_eq!(
            rows[1]["allocations"].as_u64().unwrap(),
            rows[0]["allocations"].as_u64().unwrap() * 3
        );
        assert_eq!(
            rows[1]["allocated_bytes"].as_u64().unwrap(),
            rows[0]["allocated_bytes"].as_u64().unwrap() * 3
        );
        assert_eq!(
            rows[2]["allocations"].as_u64().unwrap(),
            rows[1]["allocations"].as_u64().unwrap() + 2
        );
        assert!(rows.iter().all(|r| r["live_delta_after_drop"] == 0));
        let mut prepared_event = Some(event);
        let row = measure(&format!("payload/PE/{len}"), &metadata, || {
            let actions = pair.bob.handle_event(prepared_event.take().unwrap());
            validate_actions(&actions, &plaintext, &message_id);
            drop(black_box(actions));
        });
        rows.push(row);
        // PE consumes the pre-existing event: retained delta may be negative, not a leak.
        if !verify_only {
            for row in rows {
                println!("{row}");
            }
        }
    }
    for &(skipped, previous) in CASES {
        let pair = Pair::with_history(skipped, previous);
        verify_restore(&pair);
        let cfe = decode_session(&pair.bob, &pair.alice_id);
        let metadata = json!({"skipped":skipped,"pq_skipped":cfe.pqr.as_ref().unwrap().skipped.len(),"previous":previous,"each_previous_skipped":skipped,"cfe":pair.bob.export_session_cfe(&pair.alice_id).unwrap().len(),"epoch":cfe.pqr.as_ref().unwrap().current_epoch});
        let ratchet = ratchet_from(cfe.clone());
        let serial = ratchet.to_serializable();
        let mut current = cfe.clone();
        current.previous.clear();
        let label = format!("k{skipped}_p{previous}");
        let rows = [
            measure(&format!("save/S1/{label}"), &metadata, || {
                drop(black_box(ratchet.to_serializable()))
            }),
            measure(&format!("save/S2/{label}"), &metadata, || {
                drop(black_box(serial.to_cfe_v1().unwrap()))
            }),
            measure(&format!("save/S3/{label}"), &metadata, || {
                drop(black_box(rmp_serde::to_vec_named(&current).unwrap()))
            }),
            measure(&format!("save/S4/{label}"), &metadata, || {
                drop(black_box(
                    cfe::encode(CfeMessageType::SessionState, &current).unwrap(),
                ))
            }),
            measure(&format!("save/SF/{label}"), &metadata, || {
                drop(black_box(
                    pair.bob.export_session_cfe(&pair.alice_id).unwrap(),
                ))
            }),
        ];
        assert!(rows.iter().all(|r| r["live_delta_after_drop"] == 0));
        if !verify_only {
            for row in rows {
                println!("{row}");
            }
        }
    }
    eprintln!(
        "Verified PQ fixtures, parse allocation counts, previous-state restore, delayed decrypt, and bidirectional continuation."
    );
}
