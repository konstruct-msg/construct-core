//! Observe only this test thread's requested heap; neither malloc rounding nor RSS is measured.
use construct_core::cfe::{CfeError, CfeMessageType, encode};
use serde::Serialize;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

#[derive(Clone, Copy, Default)]
struct Usage {
    enabled: bool,
    live: isize,
    peak: usize,
    fail_after: usize,
}

thread_local! {
    static USAGE: Cell<Usage> = const { Cell::new(Usage { enabled: false, live: 0, peak: 0, fail_after: 0 }) };
}

fn fail_this_request() -> bool {
    USAGE
        .try_with(|slot| {
            let mut usage = slot.get();
            if !usage.enabled || usage.fail_after == 0 {
                return false;
            }
            usage.fail_after -= 1;
            slot.set(usage);
            usage.fail_after == 0
        })
        .unwrap_or(false)
}

fn account(delta: isize) {
    // Const-initialized, non-dropping TLS allocates nothing. Ignore shutdown of unrelated threads.
    let _ = USAGE.try_with(|slot| {
        let mut usage = slot.get();
        if usage.enabled {
            usage.live += delta;
            usage.peak = usage.peak.max(usage.live.max(0) as usize);
            slot.set(usage);
        }
    });
}

struct TestAllocator;
#[global_allocator]
static ALLOCATOR: TestAllocator = TestAllocator;

// SAFETY: The allocator forwards every original pointer and layout to System, tracks successful
// requests only, and performs no allocation or panicking operation in the accounting callback.
unsafe impl GlobalAlloc for TestAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if fail_this_request() {
            return std::ptr::null_mut();
        }
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            account(layout.size() as isize);
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if fail_this_request() {
            return std::ptr::null_mut();
        }
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            account(layout.size() as isize);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe {
            System.dealloc(pointer, layout);
        }
        account(-(layout.size() as isize));
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if fail_this_request() {
            return std::ptr::null_mut();
        }
        let new = unsafe { System.realloc(pointer, layout, new_size) };
        if !new.is_null() {
            account(new_size as isize - layout.size() as isize);
        }
        new
    }
}

fn tracked<T>(operation: impl FnOnce() -> T) -> (T, Usage) {
    USAGE.with(|slot| {
        slot.set(Usage {
            enabled: true,
            ..Usage::default()
        })
    });
    let result = operation();
    let usage = USAGE.with(|slot| {
        let usage = slot.get();
        slot.set(Usage::default());
        usage
    });
    (result, usage)
}

/// The old payload Vec plus final envelope exceed this bound. Returning an untrimmed growing
/// Vec instead passes the peak bound but fails the retained-capacity assertion.
#[test]
fn cfe_encoding_has_one_growing_buffer_and_keeps_no_spare_output_capacity() {
    let (calibration, usage) = tracked(|| vec![black_box(7u8); 128]);
    assert_eq!(usage.live, 128);
    assert_eq!(usage.peak, 128);
    drop(calibration);

    #[derive(Serialize)]
    struct Counters<'a> {
        numbers: &'a [u32],
    }
    // Both the initial reservation and payload growth must propagate allocation failure.
    for fail_after in [1, 2] {
        let (result, _) = tracked(|| {
            USAGE.with(|slot| {
                let mut u = slot.get();
                u.fail_after = fail_after;
                slot.set(u);
            });
            encode(
                CfeMessageType::SessionState,
                &Counters {
                    numbers: &[0x1234; 16],
                },
            )
        });
        assert!(matches!(result, Err(CfeError::SerializeFailed(_))));
    }
    for count in [16, 2048, 25_000] {
        let numbers = vec![0x1234u32; count];
        let value = Counters { numbers: &numbers };
        let (encoded, usage) =
            tracked(|| encode(CfeMessageType::SessionState, black_box(&value)).unwrap());
        assert_eq!(
            usage.live as usize,
            encoded.capacity(),
            "only the returned envelope may remain allocated"
        );
        assert_eq!(
            encoded.capacity(),
            encoded.len(),
            "queued state saves must not retain growth capacity"
        );
        assert!(
            usage.peak < 2 * encoded.len(),
            "encoding retains a second payload buffer: peak {} B, output {} B",
            usage.peak,
            encoded.len()
        );
        black_box(encoded);
    }
}
