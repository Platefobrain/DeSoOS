// USB descriptor parser – pure code (no MMIO, no allocation, no
// panics).  The data comes from the device, so it is untrusted: every error ends in
// Err, never in a read past the buffer, an endless loop or an overflow.
// Malicious-data tests without hardware: /bin/usbparse (USB TEST 1/3).
//
// Limits (ARCHITECTURE.md, "Enumeration"): configuration descriptor ≤ 4 KiB,
// remembered interfaces (alternate setting 0) ≤ 8, endpoints per
// interface ≤ 16, all interface descriptors (including alternate
// settings – cameras have dozens of them) ≤ 64.  Interfaces and endpoints
// beyond the limit – skipped (the `truncated` flag), not an error.
#![allow(dead_code)]

pub const DESC_DEVICE: u8 = 1;
pub const DESC_CONFIG: u8 = 2;
pub const DESC_STRING: u8 = 3;
pub const DESC_INTERFACE: u8 = 4;
pub const DESC_ENDPOINT: u8 = 5;
pub const DESC_HID: u8 = 0x21;

pub const CONFIG_MAX: usize = 4096;
pub const IFACES_MAX: usize = 8;
pub const EPS_MAX: usize = 16;
pub const IFACE_DESCS_MAX: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DescError {
    /// Buffer shorter than the descriptor / than the header.
    Truncated,
    /// Wrong descriptor type.
    WrongType,
    /// bLength too small for the type (including 0 – without the check it would loop forever).
    BadLength,
    /// Descriptor extends past wTotalLength.
    Overrun,
    /// wTotalLength smaller than the header or larger than 4 KiB / than the buffer.
    BadTotal,
    /// bMaxPacketSize0 not in 8/16/32/64 (USB 3: 9 = 512 B).
    BadMaxPacket0,
    /// Interrupt / bulk endpoint with wMaxPacketSize 0.
    BadMaxPacket,
    /// Endpoint before the first interface.
    OrphanEndpoint,
    /// More endpoints than the interface's bNumEndpoints.
    TooManyEndpoints,
    /// More than 64 interface descriptors.
    TooManyInterfaces,
}

impl DescError {
    pub fn name(self) -> &'static str {
        match self {
            DescError::Truncated => "truncated",
            DescError::WrongType => "wrong descriptor type",
            DescError::BadLength => "bad bLength",
            DescError::Overrun => "descriptor past wTotalLength",
            DescError::BadTotal => "bad wTotalLength",
            DescError::BadMaxPacket0 => "bad bMaxPacketSize0",
            DescError::BadMaxPacket => "endpoint with wMaxPacketSize 0",
            DescError::OrphanEndpoint => "endpoint before any interface",
            DescError::TooManyEndpoints => "more endpoints than bNumEndpoints",
            DescError::TooManyInterfaces => "too many interface descriptors",
        }
    }
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    b[i] as u16 | (b[i + 1] as u16) << 8
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DeviceDesc {
    pub usb: u16,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    /// EP0 packet size in bytes (USB 3: 512).
    pub mps0: u16,
    pub vendor: u16,
    pub product: u16,
    pub release: u16,
    pub i_manufacturer: u8,
    pub i_product: u8,
    pub i_serial: u8,
    pub configs: u8,
}

/// First 8 bytes of the device descriptor: bMaxPacketSize0 (to set up EP0
/// before reading the whole descriptor).  `usb3` – device on a USB 3 port (exponent).
pub fn max_packet0(b: &[u8], usb3: bool) -> Result<u16, DescError> {
    if b.len() < 8 {
        return Err(DescError::Truncated);
    }
    if b[1] != DESC_DEVICE {
        return Err(DescError::WrongType);
    }
    if (b[0] as usize) < 8 {
        return Err(DescError::BadLength);
    }
    match (usb3, b[7]) {
        (true, 9) => Ok(512),
        (false, 8 | 16 | 32 | 64) => Ok(b[7] as u16),
        _ => Err(DescError::BadMaxPacket0),
    }
}

pub fn parse_device(b: &[u8], usb3: bool) -> Result<DeviceDesc, DescError> {
    if b.len() < 18 {
        return Err(DescError::Truncated);
    }
    if b[1] != DESC_DEVICE {
        return Err(DescError::WrongType);
    }
    if (b[0] as usize) < 18 {
        return Err(DescError::BadLength);
    }
    let mps0 = max_packet0(b, usb3)?;
    Ok(DeviceDesc {
        usb: u16_at(b, 2),
        class: b[4],
        subclass: b[5],
        protocol: b[6],
        mps0,
        vendor: u16_at(b, 8),
        product: u16_at(b, 10),
        release: u16_at(b, 12),
        i_manufacturer: b[14],
        i_product: b[15],
        i_serial: b[16],
        configs: b[17],
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Endpoint {
    pub address: u8,
    pub attributes: u8,
    pub max_packet: u16,
    pub interval: u8,
}

impl Endpoint {
    pub fn is_in(&self) -> bool {
        self.address & 0x80 != 0
    }
    /// 0 control, 1 isochronous, 2 bulk, 3 interrupt.
    pub fn kind(&self) -> u8 {
        self.attributes & 3
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Interface {
    pub number: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub declared_eps: u8,
    pub eps: [Endpoint; EPS_MAX],
    pub n_eps: usize,
    /// HID report length (0 – no HID descriptor).
    pub hid_report_len: u16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Config {
    pub total: u16,
    pub value: u8,
    pub attributes: u8,
    pub max_power: u8,
    pub ifaces: [Interface; IFACES_MAX],
    pub n_ifaces: usize,
    /// All interface descriptors (including alternate settings).
    pub iface_descs: usize,
    /// Some interfaces / endpoints were skipped (limit), not an error.
    pub truncated: bool,
}

/// First 9 bytes of the configuration descriptor: wTotalLength (≤ 4 KiB).
pub fn config_total(b: &[u8]) -> Result<u16, DescError> {
    if b.len() < 9 {
        return Err(DescError::Truncated);
    }
    if b[1] != DESC_CONFIG {
        return Err(DescError::WrongType);
    }
    if (b[0] as usize) < 9 {
        return Err(DescError::BadLength);
    }
    let total = u16_at(b, 2);
    if (total as usize) < 9 || total as usize > CONFIG_MAX {
        return Err(DescError::BadTotal);
    }
    Ok(total)
}

/// Whole configuration (buffer = exactly what came from the device).
pub fn parse_config(b: &[u8]) -> Result<Config, DescError> {
    let total = config_total(b)? as usize;
    if total > b.len() {
        return Err(DescError::BadTotal);
    }
    let mut c = Config { total: total as u16, value: b[5], attributes: b[7], max_power: b[8], ..Config::default() };
    // Current interface: Some(index in the array) or None (alternate / over the limit).
    let mut cur: Option<usize> = None;
    let mut cur_seen = 0usize;
    let mut cur_declared = 0usize;
    let mut any_iface = false;
    let mut off = b[0] as usize;
    if off > total {
        return Err(DescError::Overrun);
    }
    while off < total {
        if total - off < 2 {
            return Err(DescError::Truncated);
        }
        let len = b[off] as usize;
        let ty = b[off + 1];
        if len < 2 {
            return Err(DescError::BadLength);
        }
        if len > total - off {
            return Err(DescError::Overrun);
        }
        let d = &b[off..off + len];
        match ty {
            DESC_INTERFACE => {
                if len < 9 {
                    return Err(DescError::BadLength);
                }
                c.iface_descs += 1;
                if c.iface_descs > IFACE_DESCS_MAX {
                    return Err(DescError::TooManyInterfaces);
                }
                any_iface = true;
                cur_seen = 0;
                cur_declared = d[4] as usize;
                cur = None;
                if d[3] == 0 {
                    if c.n_ifaces < IFACES_MAX {
                        c.ifaces[c.n_ifaces] = Interface {
                            number: d[2],
                            class: d[5],
                            subclass: d[6],
                            protocol: d[7],
                            declared_eps: d[4],
                            ..Interface::default()
                        };
                        cur = Some(c.n_ifaces);
                        c.n_ifaces += 1;
                    } else {
                        c.truncated = true;
                    }
                }
            }
            DESC_ENDPOINT => {
                if len < 7 {
                    return Err(DescError::BadLength);
                }
                if !any_iface {
                    return Err(DescError::OrphanEndpoint);
                }
                cur_seen += 1;
                if cur_seen > cur_declared {
                    return Err(DescError::TooManyEndpoints);
                }
                let ep = Endpoint { address: d[2], attributes: d[3], max_packet: u16_at(d, 4), interval: d[6] };
                if matches!(ep.kind(), 2 | 3) && ep.max_packet & 0x7FF == 0 {
                    return Err(DescError::BadMaxPacket);
                }
                if let Some(i) = cur {
                    let f = &mut c.ifaces[i];
                    if f.n_eps < EPS_MAX {
                        f.eps[f.n_eps] = ep;
                        f.n_eps += 1;
                    } else {
                        c.truncated = true;
                    }
                }
            }
            DESC_HID => {
                if len >= 9 {
                    if let Some(i) = cur {
                        c.ifaces[i].hid_report_len = u16_at(d, 7);
                    }
                }
            }
            _ => {} // IAD, class-specific, SS companion – skipped
        }
        off += len;
    }
    Ok(c)
}

/// Language list (string descriptor 0): the first language ID.
pub fn first_langid(b: &[u8]) -> Option<u16> {
    if b.len() < 4 || b[1] != DESC_STRING || (b[0] as usize) < 4 {
        return None;
    }
    Some(u16_at(b, 2))
}

/// UTF-16LE string -> ASCII (other characters as '?', control characters skipped);
/// returns the number of bytes in `out`.
pub fn string_ascii(b: &[u8], out: &mut [u8]) -> usize {
    if b.len() < 2 || b[1] != DESC_STRING {
        return 0;
    }
    let len = (b[0] as usize).min(b.len());
    let mut n = 0;
    let mut i = 2;
    while i + 1 < len && n < out.len() {
        let ch = u16_at(b, i);
        i += 2;
        let c = match ch {
            0x20..=0x7E => ch as u8,
            0..=0x1F | 0x7F => continue,
            _ => b'?',
        };
        out[n] = c;
        n += 1;
    }
    // No trailing spaces (some devices pad with spaces).
    while n > 0 && out[n - 1] == b' ' {
        n -= 1;
    }
    n
}
