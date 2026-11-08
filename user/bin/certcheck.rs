// certcheck <file> [host] [--time SECONDS] [--anchor FILE] – checks a server certificate
// chain offline, with the same code TLS will use (common/desotls).
//
//   <file>          the chain: PEM (one or more "BEGIN CERTIFICATE" blocks, the server's own
//                   first) or one DER certificate
//   [host]          the name to check; without it, the first DNS name of the certificate
//   --time SECONDS  check at this Unix time instead of now (the clock need not be plausible)
//   --anchor FILE   trust only this CA certificate (PEM or DER) instead of /etc/certs/roots
//
// Output: one line per certificate (subject, issuer, validity), then
//   "certcheck: OK - <host>: <n> certificates up to <CA>"         exit 0
//   "certcheck: REFUSED - <reason>"                               exit 1
// and exit 2 for wrong usage, a file that cannot be read or a clock that is not plausible
// (without --time: TLS would refuse to connect then too).
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;
#[path = "../../common/desocrypto/mod.rs"]
mod desocrypto;
#[path = "../../common/desotls/mod.rs"]
mod desotls;

use alloc::vec::Vec;
use desoos::*;
use desotls::roots::{AnchorList, Anchors, Roots};
use desotls::{name, pem, verify, x509};

entry!(main);

const ROOTS: &str = "/etc/certs/roots";
const USAGE: &str = "usage: certcheck <chain.pem|cert.der> [host] [--time SECONDS] [--anchor ca.pem]";

fn read_file(path: &str) -> Result<Vec<u8>, i64> {
    let fd = open(path, O_READ);
    if fd < 0 {
        return Err(fd);
    }
    let mut v = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = read(fd as u64, &mut buf);
        if n < 0 {
            close(fd as u64);
            return Err(n);
        }
        if n == 0 {
            break;
        }
        v.extend_from_slice(&buf[..n as usize]);
        if v.len() > 4 * 1024 * 1024 {
            close(fd as u64);
            return Err(ERROR_NO_SPACE);
        }
    }
    close(fd as u64);
    Ok(v)
}

/// PEM or DER file -> DER certificates (positions in `out`).
fn certificates(data: &[u8], out: &mut Vec<u8>, spans: &mut [(usize, usize)]) -> Result<usize, desotls::Error> {
    if data.starts_with(&[0x30]) {
        out.extend_from_slice(data);
        spans[0] = (0, data.len());
        return Ok(1);
    }
    out.resize(data.len(), 0);
    let n = pem::certificates(data, out, spans)?;
    if n == 0 {
        return Err(desotls::Error::Empty);
    }
    Ok(n)
}

fn main(args: Args) -> i32 {
    let mut file = None;
    let mut host: Option<&str> = None;
    let mut at: Option<i64> = None;
    let mut anchor_file = None;
    let mut i = 1;
    while let Some(a) = args.get(i) {
        match a {
            "--time" => {
                i += 1;
                match args.get(i).and_then(|t| t.parse::<i64>().ok()) {
                    Some(t) => at = Some(t),
                    None => {
                        eprintln!("{}", USAGE);
                        return 2;
                    }
                }
            }
            "--anchor" => {
                i += 1;
                anchor_file = args.get(i);
                if anchor_file.is_none() {
                    eprintln!("{}", USAGE);
                    return 2;
                }
            }
            _ if file.is_none() => file = Some(a),
            _ if host.is_none() => host = Some(a),
            _ => {
                eprintln!("{}", USAGE);
                return 2;
            }
        }
        i += 1;
    }
    let Some(file) = file else {
        eprintln!("{}", USAGE);
        return 2;
    };
    let data = match read_file(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("certcheck: {}: {}", file, strerror(e));
            return 2;
        }
    };
    let mut ders = Vec::new();
    let mut spans = [(0usize, 0usize); verify::MAX_CHAIN + 1];
    let n = match certificates(&data, &mut ders, &mut spans) {
        Ok(n) => n,
        Err(e) => {
            println!("certcheck: REFUSED - {}", e.as_str());
            return 1;
        }
    };
    let chain: Vec<&[u8]> = spans[..n].iter().map(|&(s, l)| &ders[s..s + l]).collect();

    // What the certificates say (whatever the verdict).
    let mut first_dns: Option<Vec<u8>> = None;
    for (k, der) in chain.iter().enumerate() {
        match x509::Cert::parse(der, false) {
            Ok(c) => {
                let (mut a, mut b) = ([0u8; 19], [0u8; 19]);
                println!(
                    "  [{}] {} <- {}, valid {} .. {} UTC",
                    k,
                    c.subject_cn().unwrap_or("(no CN)"),
                    x509::name_cn(c.issuer).unwrap_or("(no CN)"),
                    format_utc(c.not_before.max(0) as u64, &mut a),
                    format_utc(c.not_after.max(0) as u64, &mut b)
                );
                if k == 0 {
                    if let Some(san) = c.san {
                        let _ = name::for_each_dns(san, |d| {
                            if first_dns.is_none() {
                                first_dns = Some(d.to_vec());
                            }
                            Ok(())
                        });
                    }
                }
            }
            Err(e) => println!("  [{}] cannot be read: {}", k, e.as_str()),
        }
    }
    let derived;
    let host = match host {
        Some(h) => h,
        None => match first_dns.as_deref().and_then(|d| core::str::from_utf8(d).ok()) {
            Some(d) => {
                derived = d.replace_star();
                println!("  (no host given - checking {})", derived.as_str());
                derived.as_str()
            }
            None => {
                println!("certcheck: REFUSED - {}", desotls::Error::NoSubjectAltName.as_str());
                return 1;
            }
        },
    };

    // The time.
    let now = match at {
        Some(t) => t,
        None => match time_unix() {
            Ok(c) if c.plausible() => c.secs as i64,
            Ok(c) => {
                eprintln!("certcheck: clock not plausible: {} - TLS would refuse too; use --time to check offline", clock_reason(c.status));
                return 2;
            }
            Err(e) => {
                eprintln!("certcheck: no clock: {}", strerror(e));
                return 2;
            }
        },
    };

    // The anchors and the verdict.
    let store_data;
    let anchor_der;
    let mut anchor_spans = [(0usize, 0usize); 1];
    let list: [&[u8]; 1];
    let anchors: &dyn Anchors;
    let store;
    let source: &str;
    let list_holder;
    match anchor_file {
        Some(f) => {
            let d = match read_file(f) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("certcheck: {}: {}", f, strerror(e));
                    return 2;
                }
            };
            let mut out = Vec::new();
            if certificates(&d, &mut out, &mut anchor_spans).is_err() {
                eprintln!("certcheck: {}: no certificate", f);
                return 2;
            }
            anchor_der = out;
            list = [&anchor_der[anchor_spans[0].0..anchor_spans[0].0 + anchor_spans[0].1]];
            list_holder = AnchorList(&list);
            anchors = &list_holder;
            source = "the given anchor";
        }
        None => {
            store_data = match read_file(ROOTS) {
                Ok(d) => d,
                Err(e) => {
                    println!("certcheck: REFUSED - {} ({}: {})", desotls::Error::BadRootStore.as_str(), ROOTS, strerror(e));
                    return 1;
                }
            };
            store = match Roots::parse(&store_data) {
                Ok(r) => r,
                Err(e) => {
                    println!("certcheck: REFUSED - {}", e.as_str());
                    return 1;
                }
            };
            anchors = &store;
            source = store.nss_tag;
        }
    }
    match verify::server(&chain, anchors, host, now) {
        Ok(v) => {
            let mut ca = None;
            let mut k = 0;
            anchors.each(&mut |der, _| {
                if k == v.anchor_index {
                    ca = x509::Cert::parse(der, true).ok().and_then(|c| c.subject_cn()).map(|s| s.as_bytes().to_vec());
                    return false;
                }
                k += 1;
                true
            });
            let ca = ca.as_deref().and_then(|c| core::str::from_utf8(c).ok()).unwrap_or("(no CN)");
            println!("certcheck: OK - {}: {} certificates up to {} ({})", host, v.certs, ca, source);
            0
        }
        Err(e) => {
            println!("certcheck: REFUSED - {}", e.as_str());
            1
        }
    }
}

/// "*.example.com" -> "www.example.com" (to check a wildcard certificate without a host).
trait ReplaceStar {
    fn replace_star(&self) -> alloc::string::String;
}

impl ReplaceStar for str {
    fn replace_star(&self) -> alloc::string::String {
        match self.strip_prefix("*.") {
            Some(rest) => alloc::format!("www.{}", rest),
            None => alloc::string::String::from(self),
        }
    }
}
