// M20.c: test parsera deskryptorów USB bez sprzętu (USB TEST 1/3).
// Deskryptory przychodzą z urządzenia – parser musi odrzucić złośliwe dane, nie
// czytać poza buforem, nie zapętlić się i nie spanikować (panika = koniec
// procesu = test nie przechodzi).
//   1. poprawne próbki: klawiatura HID, pamięć masowa, kamera z 20 ustawieniami
//      alternatywnymi, 9 interfejsów (limit 8 -> pominięte, nie błąd), urządzenie,
//   2. tabela złośliwych przypadków z oczekiwanym błędem,
//   3. 10 000 losowych mutacji próbek (ustalone ziarno): każdy wynik to błąd
//      albo poprawna struktura w limitach.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../lib/usb_desc.rs"]
mod usb_desc;

use desoos::*;
use usb_desc::*;

entry!(main);

macro_rules! check {
    ($n:ident, $cond:expr, $($msg:tt)*) => {
        $n += 1;
        if !$cond {
            println!("usbparse: FAIL check {}: {}", $n, format_args!($($msg)*));
            return 1;
        }
    };
}

const KBD: [u8; 34] = [
    9, 2, 34, 0, 1, 1, 0, 0xA0, 50, // konfiguracja
    9, 4, 0, 0, 1, 3, 1, 1, 0, // interfejs HID, boot, klawiatura
    9, 0x21, 0x11, 0x01, 0, 1, 0x22, 63, 0, // HID, raport 63 B
    7, 5, 0x81, 3, 8, 0, 10, // endpoint IN 1, przerwania, 8 B
];

const STORAGE: [u8; 32] = [
    9, 2, 32, 0, 1, 1, 0, 0x80, 50, //
    9, 4, 0, 0, 2, 8, 6, 0x50, 0, // pamięć masowa, SCSI, bulk-only
    7, 5, 0x81, 2, 0, 2, 0, // bulk IN 512
    7, 5, 0x02, 2, 0, 2, 0, // bulk OUT 512
];

const DEVICE: [u8; 18] = [18, 1, 0x00, 0x02, 0, 0, 0, 64, 0x27, 0x06, 0x01, 0x00, 0x00, 0x01, 1, 2, 3, 1];

/// Kamera: IAD, interfejs sterujący z deskryptorem klasy, interfejs strumienia
/// z 20 ustawieniami alternatywnymi (endpoint izochroniczny w każdym).
fn webcam(b: &mut [u8; 4096]) -> usize {
    let mut n = 0;
    let mut put = |d: &[u8], b: &mut [u8; 4096]| {
        b[n..n + d.len()].copy_from_slice(d);
        n += d.len();
    };
    put(&[9, 2, 0, 0, 2, 1, 0, 0x80, 250], b);
    put(&[8, 0x0B, 0, 2, 0x0E, 3, 0, 0], b);
    put(&[9, 4, 0, 0, 1, 0x0E, 1, 0, 0], b);
    put(&[5, 0x24, 1, 0, 1], b);
    put(&[7, 5, 0x83, 3, 16, 0, 6], b);
    put(&[9, 4, 1, 0, 0, 0x0E, 2, 0, 0], b);
    for alt in 1..=20u8 {
        put(&[9, 4, 1, alt, 1, 0x0E, 2, 0, 0], b);
        put(&[7, 5, 0x81, 5, 0x00, 0x0C, 1], b);
    }
    let total = n;
    b[2] = total as u8;
    b[3] = (total >> 8) as u8;
    total
}

/// 9 interfejsów bez endpointów (limit zapamiętanych: 8).
fn nine_ifaces(b: &mut [u8; 4096]) -> usize {
    b[..9].copy_from_slice(&[9, 2, 0, 0, 9, 1, 0, 0x80, 50]);
    let mut n = 9;
    for i in 0..9u8 {
        b[n..n + 9].copy_from_slice(&[9, 4, i, 0, 0, 0xFF, 0, 0, 0]);
        n += 9;
    }
    b[2] = n as u8;
    n
}

/// xorshift64 – powtarzalne „losowe” mutacje.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Struktura w limitach (gdy parser powiedział Ok).
fn sane(c: &Config, len: usize) -> bool {
    c.n_ifaces <= IFACES_MAX
        && c.total as usize <= len
        && c.total as usize <= CONFIG_MAX
        && c.iface_descs <= IFACE_DESCS_MAX
        && c.ifaces[..c.n_ifaces].iter().all(|f| {
            f.n_eps <= EPS_MAX
                && f.n_eps <= f.declared_eps as usize
                && f.eps[..f.n_eps].iter().all(|e| !matches!(e.kind(), 2 | 3) || e.max_packet & 0x7FF != 0)
        })
}

fn with(base: &[u8], at: usize, v: u8) -> ([u8; 64], usize) {
    let mut b = [0u8; 64];
    b[..base.len()].copy_from_slice(base);
    b[at] = v;
    (b, base.len())
}

fn main(_args: Args) -> i32 {
    let mut n = 0;

    // 1. Poprawne próbki.
    let k = parse_config(&KBD);
    check!(n, k.is_ok(), "keyboard config: {:?}", k.err());
    let k = k.unwrap();
    let f = &k.ifaces[0];
    check!(n, k.n_ifaces == 1 && (f.class, f.subclass, f.protocol) == (3, 1, 1), "keyboard interface 03/01/01");
    check!(n, f.n_eps == 1 && f.eps[0].address == 0x81 && f.eps[0].kind() == 3 && f.eps[0].max_packet == 8, "keyboard interrupt IN endpoint");
    check!(n, f.hid_report_len == 63 && k.value == 1, "HID report length / config value");
    let s = parse_config(&STORAGE).unwrap_or_default();
    check!(n, s.n_ifaces == 1 && s.ifaces[0].n_eps == 2 && s.ifaces[0].class == 8, "mass storage: 2 bulk endpoints");
    let mut buf = [0u8; 4096];
    let len = webcam(&mut buf);
    let w = parse_config(&buf[..len]);
    check!(n, matches!(w, Ok(c) if c.n_ifaces == 2 && c.iface_descs == 22 && c.ifaces[1].n_eps == 0 && !c.truncated), "webcam with 20 alternate settings: {:?}", w.map(|c| (c.n_ifaces, c.iface_descs)));
    let len = nine_ifaces(&mut buf);
    let c = parse_config(&buf[..len]);
    check!(n, matches!(c, Ok(c) if c.n_ifaces == 8 && c.truncated), "9 interfaces -> 8 kept, truncated");
    let d = parse_device(&DEVICE, false);
    check!(n, matches!(d, Ok(d) if d.vendor == 0x0627 && d.product == 1 && d.mps0 == 64 && d.usb == 0x200 && d.i_product == 2), "device descriptor: {:?}", d);
    let mut sd = [0u8; 12];
    sd[..2].copy_from_slice(&[12, 3]);
    for (i, ch) in b"QEMU ".iter().enumerate() {
        sd[2 + 2 * i] = *ch;
    }
    let mut out = [0u8; 32];
    let m = string_ascii(&sd, &mut out);
    check!(n, &out[..m] == b"QEMU", "string descriptor -> {:?}", &out[..m]);
    check!(n, first_langid(&[4, 3, 0x09, 0x04]) == Some(0x0409) && first_langid(&[2, 3]).is_none(), "language list");

    // 2. Złośliwe przypadki z oczekiwanym błędem.
    use DescError::*;
    let cases: [(&str, ([u8; 64], usize), DescError); 13] = [
        ("bLength 0 (endless loop without the check)", with(&KBD, 18, 0), BadLength),
        ("bLength past wTotalLength", with(&KBD, 27, 20), Overrun),
        ("wTotalLength larger than the buffer", with(&KBD, 2, 200), BadTotal),
        ("wTotalLength above 4 KiB", with(&with(&KBD, 2, 0x88).0[..34], 3, 0x13), BadTotal),
        ("wTotalLength below the header", with(&KBD, 2, 5), BadTotal),
        ("more endpoints than bNumEndpoints", with(&STORAGE, 13, 1), TooManyEndpoints),
        ("bulk endpoint with wMaxPacketSize 0", with(&with(&STORAGE, 22, 0).0[..32], 23, 0), BadMaxPacket),
        ("interface turned into an endpoint (before any interface)", with(&KBD, 10, 5), OrphanEndpoint),
        ("interface descriptor too short", with(&KBD, 9, 5), BadLength),
        ("wrong configuration type", with(&KBD, 1, 4), WrongType),
        ("configuration header too short", with(&KBD, 0, 8), BadLength),
        ("header longer than wTotalLength", with(&with(&KBD, 0, 40).0[..34], 2, 34), Overrun),
        ("one byte left at the end", with(&with(&KBD, 2, 35).0[..34], 34, 0), Truncated),
    ];
    for (name, (b, len), want) in cases {
        let len = if want == Truncated { len + 1 } else { len };
        let r = parse_config(&b[..len]);
        check!(n, r.err() == Some(want), "{}: got {:?}, want {:?}", name, r.err(), want);
    }
    // Endpoint przed interfejsem (poprawne długości).
    let mut orphan = [0u8; 16];
    orphan[..9].copy_from_slice(&[9, 2, 16, 0, 1, 1, 0, 0x80, 50]);
    orphan[9..16].copy_from_slice(&[7, 5, 0x81, 3, 8, 0, 10]);
    check!(n, parse_config(&orphan).err() == Some(OrphanEndpoint), "orphan endpoint");
    // 65 deskryptorów interfejsu.
    let mut big = [0u8; 4096];
    big[..9].copy_from_slice(&[9, 2, 0, 0, 1, 1, 0, 0x80, 50]);
    let mut len = 9;
    for alt in 0..65u8 {
        big[len..len + 9].copy_from_slice(&[9, 4, 0, alt, 0, 0xFF, 0, 0, 0]);
        len += 9;
    }
    big[2] = len as u8;
    big[3] = (len >> 8) as u8;
    check!(n, parse_config(&big[..len]).err() == Some(TooManyInterfaces), "65 interface descriptors");
    // Urządzenie.
    check!(n, parse_device(&DEVICE[..17], false).err() == Some(Truncated), "device descriptor 17 B");
    check!(n, parse_device(&with(&DEVICE, 0, 10).0[..18], false).err() == Some(BadLength), "device bLength 10");
    check!(n, parse_device(&with(&DEVICE, 7, 7).0[..18], false).err() == Some(BadMaxPacket0), "bMaxPacketSize0 7");
    check!(n, parse_device(&DEVICE, true).err() == Some(BadMaxPacket0), "USB 3 with bMaxPacketSize0 64");
    check!(n, parse_device(&with(&DEVICE, 1, 2).0[..18], false).err() == Some(WrongType), "device type 2");
    check!(n, string_ascii(&[255, 3, b'A', 0], &mut out) == 1, "string with bLength past the buffer is clipped");

    // 3. Mutacje.
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let (mut ok, mut rejected) = (0u64, 0u64);
    for _ in 0..10_000 {
        let mut len = match rng.below(4) {
            0 => {
                buf[..34].copy_from_slice(&KBD);
                34
            }
            1 => {
                buf[..32].copy_from_slice(&STORAGE);
                32
            }
            2 => webcam(&mut buf),
            _ => nine_ifaces(&mut buf),
        };
        for _ in 0..1 + rng.below(4) {
            match rng.below(5) {
                0 | 1 => {
                    let i = rng.below(len);
                    buf[i] = rng.next() as u8;
                }
                2 => {
                    let i = rng.below(len);
                    buf[i] = if rng.below(2) == 0 { 0 } else { 0xFF };
                }
                3 => len = rng.below(len + 1),
                _ => {
                    let extra = rng.below(64);
                    for j in 0..extra {
                        if len + j < buf.len() {
                            buf[len + j] = rng.next() as u8;
                        }
                    }
                    len = (len + extra).min(buf.len());
                }
            }
        }
        let b = &buf[..len];
        match parse_config(b) {
            Ok(c) => {
                if !sane(&c, len) {
                    println!("usbparse: FAIL mutation accepted outside limits: {:?}", (c.n_ifaces, c.total, c.iface_descs));
                    return 1;
                }
                ok += 1;
            }
            Err(_) => rejected += 1,
        }
        let _ = config_total(b);
        let _ = parse_device(b, rng.below(2) == 0);
        let _ = max_packet0(b, false);
        let _ = first_langid(b);
        let _ = string_ascii(b, &mut out);
    }
    check!(n, ok > 0 && rejected > 0, "mutations: {} accepted, {} rejected", ok, rejected);
    println!("usbparse: {} checks OK, 10000 mutations ({} accepted within limits, {} rejected), no panic", n, ok, rejected);
    0
}
