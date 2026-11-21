//! The lib test binary's allocator: `System`, plus a scan of freed blocks for a secret's bytes.
//!
//! `Zeroize` is a promise about memory that has been given back, which no assertion on a live
//! value can check: a secret copied into a plain `Vec<u8>` behaves exactly like one in
//! `SecretBytes` until it is dropped. This allocator looks at that moment. A thread that arms it
//! with a set of secrets (`freed_blocks_holding`) has every block it frees searched for those
//! bytes before the block goes back to `System`; a block still holding one is a copy that was
//! freed without being wiped.
//!
//! Only the arming thread is scanned (const-initialized thread-local, which allocates nothing),
//! so the rest of the test binary runs on plain `System`. `realloc` is not scanned: a block that
//! grows in place is still live, and telling the two cases apart is not this tool's job — build
//! secrets at their final size (`SecretBytes` module docs).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

#[derive(Clone, Copy)]
struct Armed {
    /// The secrets, concatenated; null when this thread is not armed.
    needles: *const u8,
    count: usize,
    len: usize,
    hits: usize,
}

const DISARMED: Armed = Armed {
    needles: std::ptr::null(),
    count: 0,
    len: 0,
    hits: 0,
};

thread_local! {
    static ARMED: Cell<Armed> = const { Cell::new(DISARMED) };
}

pub(crate) struct ScanOnFree;

#[global_allocator]
static ALLOCATOR: ScanOnFree = ScanOnFree;

// SAFETY: every call forwards the caller's pointer and layout to `System` unchanged. `dealloc`
// reads the block only before handing it back, while it is still the caller's live allocation of
// `layout.size()` bytes, and reads the needles only while `freed_blocks_holding` keeps them alive
// (its guard disarms before they are freed, on unwind too). The scan allocates nothing and does
// not panic.
unsafe impl GlobalAlloc for ScanOnFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe { System.realloc(pointer, layout, new_size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = ARMED.try_with(|slot| {
            let mut armed = slot.get();
            if armed.needles.is_null() || layout.size() < armed.len {
                return;
            }
            let block = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
            let needles =
                unsafe { std::slice::from_raw_parts(armed.needles, armed.count * armed.len) };
            let holds_one = needles
                .chunks_exact(armed.len)
                .any(|needle| block.windows(armed.len).any(|window| window == needle));
            if holds_one {
                armed.hits += 1;
                slot.set(armed);
            }
        });
        unsafe { System.dealloc(pointer, layout) }
    }
}

struct Disarm;

impl Drop for Disarm {
    fn drop(&mut self) {
        let _ = ARMED.try_with(|slot| slot.set(DISARMED));
    }
}

/// Run `f` and count the blocks this thread freed meanwhile that still held one of `secrets`.
///
/// Secrets must be non-empty and of one length; a short one would match by chance.
pub(crate) fn freed_blocks_holding(secrets: &[Vec<u8>], f: impl FnOnce()) -> usize {
    let len = secrets.first().map_or(0, Vec::len);
    assert!(len >= 16, "secrets this short would match by chance");
    assert!(
        secrets.iter().all(|s| s.len() == len),
        "secrets of one length"
    );
    let flat = secrets.concat();
    // Declared after `flat`, so dropped before it: the needles are never read once freed.
    let _disarm = Disarm;
    ARMED.with(|slot| {
        slot.set(Armed {
            needles: flat.as_ptr(),
            count: secrets.len(),
            len,
            hits: 0,
        })
    });
    f();
    ARMED.with(|slot| slot.get().hits)
}
