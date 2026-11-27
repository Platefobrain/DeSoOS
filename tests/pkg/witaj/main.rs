// witaj – the test package of PKG TEST (tests/pkg-test.sh) and the first real package
// of the DecodeSoft repository.  An ordinary SDK program (sdk/deso-build.sh): it prints its version, its argv[0]
// (the shell gives a package program its full path) and the line from its data file
// ../share/witaj/hello.txt next to its bin/ directory.
//
// tests/pkg-test.sh builds it once per version, replacing VERSION below.
#![no_std]
#![no_main]

#[macro_use]
extern crate libdeso;
use libdeso as deso;

entry!(main);

const VERSION: &str = "0.0.0";

fn main(args: deso::Args) -> i32 {
    let argv0 = args.get(0).unwrap_or("?");
    println!("witaj {} argv0={}", VERSION, argv0);
    // <dir>/bin/witaj -> <dir>/share/witaj/hello.txt
    let Some(dir) = argv0.strip_suffix("/bin/witaj") else {
        println!("witaj: started without a full path - no data");
        return 1;
    };
    let mut path = [0u8; 256];
    let tail = b"/share/witaj/hello.txt";
    if dir.len() + tail.len() > path.len() {
        return 1;
    }
    path[..dir.len()].copy_from_slice(dir.as_bytes());
    path[dir.len()..dir.len() + tail.len()].copy_from_slice(tail);
    let p = core::str::from_utf8(&path[..dir.len() + tail.len()]).unwrap_or("");
    let fd = deso::open(p, deso::O_READ);
    if fd < 0 {
        println!("witaj: {}: {}", p, deso::strerror(fd));
        return 1;
    }
    let mut buf = [0u8; 256];
    let n = deso::read(fd as u64, &mut buf);
    deso::close(fd as u64);
    if n <= 0 {
        return 1;
    }
    println!("witaj data: {}", core::str::from_utf8(&buf[..n as usize]).unwrap_or("?").trim_end());
    0
}
