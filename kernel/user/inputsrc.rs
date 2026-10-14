// M20.e: uchwyt INPUT – wstrzykiwanie zdarzeń wejścia z usługi (usbd).
// Projekt: ARCHITEKTURA.md, „USB”, „Wejście – input_inject (49)”.
//
// * Uchwyt tworzy tylko jądro dla init (slot 5); init daje kopię każdemu usbd.
//   INPUT to w praktyce klawiatura systemu (może pisać do shella), więc ma go
//   tylko kod systemu.
// * Każda KOPIA uchwytu to osobne źródło (Clone tworzy nowe): jądro pamięta,
//   które klawisze (HID usage) wcisnęło to źródło.  Zniknięcie kopii (koniec
//   usbd, kill, close) = puszczenie wszystkich jej klawiszy – po awarii nie
//   zostaje wciśnięty Shift ani Ctrl.  Puszczenie wykonuje zadanie jądra
//   input-repeat pod BKL (Drop może biec w dowolnym kontekście – tu tylko atomiki).

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub struct InputEnd {
    pub id: u64,
    /// Wciśnięte klawisze (bit = HID usage 0..255).
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

/// Kopia uchwytu (dup, spawn_ex) = nowe źródło bez wciśniętych klawiszy.
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
