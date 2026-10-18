// INPUT handle – injecting input events from a service (usbd).
// Design: ARCHITECTURE.md, "USB", "Input – `input_inject`".
//
// * Only the kernel creates the handle, for init (slot 5); init gives a copy to each usbd.
//   INPUT is effectively the system keyboard (it can type into the shell), so only
//   system code gets it.
// * Each COPY of the handle is a separate source (Clone creates a new one): the kernel
//   remembers which keys (HID usage) this source has pressed.  When a copy disappears
//   (usbd exit, kill, close) all its keys are released – after a crash no Shift or Ctrl
//   stays stuck.  The release is done by the kernel's input-repeat task under the BKL
//   (Drop may run in any context – only atomics here).

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub struct InputEnd {
    pub id: u64,
    /// Pressed keys (bit = HID usage 0..255).
    pressed: [AtomicU64; 4],
}

impl InputEnd {
    pub fn new() -> InputEnd {
        InputEnd { id: NEXT_ID.fetch_add(1, Ordering::Relaxed), pressed: [const { AtomicU64::new(0) }; 4] }
    }

    pub fn mark(&self, usage: u8, pressed: bool) {
        let (w, b) = ((usage / 64) as usize, usage % 64);
        if pressed {
            self.pressed[w].fetch_or(1 << b, Ordering::Relaxed);
        } else {
            self.pressed[w].fetch_and(!(1 << b), Ordering::Relaxed);
        }
    }

    pub fn is_pressed(&self, usage: u8) -> bool {
        self.pressed[(usage / 64) as usize].load(Ordering::Relaxed) & (1 << (usage % 64)) != 0
    }
}

/// A copy of the handle (dup, spawn_ex) = a new source with no keys pressed.
impl Clone for InputEnd {
    fn clone(&self) -> InputEnd {
        InputEnd::new()
    }
}

impl Drop for InputEnd {
    fn drop(&mut self) {
        let bits = [0, 1, 2, 3].map(|i| self.pressed[i].swap(0, Ordering::Relaxed));
        crate::input::usb_release_all(bits, self.id);
    }
}
