// IPC demo to run manually in the shell (`ipcdemo`).
// The parent creates a channel and shared memory, starts a child via
// spawn_ex (channel, console, memory – nothing else), sends it text over the channel,
// the child replies in uppercase; then the child writes to the shared memory,
// and the parent reads it after the "doorbell".  Everything is printed on the screen.
#![no_std]
#![no_main]

#[path = "../lib/desoos.rs"]
#[macro_use]
mod desoos;

use desoos::*;

entry!(main);

fn child() -> i32 {
    let me = getpid();
    let mut buf = [0u8; 64];
    let mut info = RecvInfo::default();
    let n = chan_recv(0, &mut buf, 0, &mut info);
    if n < 0 {
        return 1;
    }
    let n = n as usize;
    println!("  [child {}] received from {}: \"{}\"", me, info.sender, core::str::from_utf8(&buf[..n]).unwrap_or("?"));
    for b in buf[..n].iter_mut() {
        b.make_ascii_uppercase();
    }
    chan_send(0, &buf[..n], 0);
    let Ok(a) = shm_map(2, PROT_READ | PROT_WRITE) else { return 2 };
    let text = b"tekst zapisany przez dziecko we wspolnej pamieci";
    unsafe { core::ptr::copy_nonoverlapping(text.as_ptr(), a as *mut u8, text.len()) };
    println!("  [child {}] wrote {} bytes to shared memory, ringing", me, text.len());
    chan_send(0, &(text.len() as u64).to_le_bytes(), 0);
    0
}

fn main(args: Args) -> i32 {
    if args.get(1) == Some("child") {
        return child();
    }
    let Ok((p, c)) = channel_create() else {
        println!("ipcdemo: channel_create failed");
        return 1;
    };
    let shm = shm_create(4096);
    if shm < 0 {
        println!("ipcdemo: shm_create failed");
        return 1;
    }
    let shm = shm as u64;
    println!("[parent {}] channel: handles {} and {}, shared memory: handle {} ({} B)", getpid(), p, c, shm, shm_size(shm));
    // Child: 0 = channel, 1 = console (println), 2 = memory – nothing else.
    let pid = spawn_ex("/bin/ipcdemo", &["ipcdemo", "child"], &[(c, 0), (1, 1), (shm, 2)], 0);
    if pid < 0 {
        println!("ipcdemo: spawn_ex: {}", strerror(pid));
        return 1;
    }
    close(c);
    println!("[parent] started child {} with 3 handles (channel, memory, console)", pid);
    chan_send(p, b"czesc z DeSoOS", 0);
    let mut buf = [0u8; 64];
    let mut info = RecvInfo::default();
    let n = chan_recv(p, &mut buf, 0, &mut info);
    if n > 0 {
        println!("[parent] reply from {}: \"{}\"", info.sender, core::str::from_utf8(&buf[..n as usize]).unwrap_or("?"));
    }
    let n = chan_recv(p, &mut buf, 0, &mut info);
    if n == 8 {
        let len = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]) as usize;
        if let Ok(a) = shm_map(shm, PROT_READ) {
            let s = unsafe { core::slice::from_raw_parts(a as *const u8, len.min(4096)) };
            println!("[parent] doorbell – in shared memory: \"{}\"", core::str::from_utf8(s).unwrap_or("?"));
        }
    }
    let st = wait(pid as u64, 0);
    println!("[parent] child finished: {:?}", st);
    0
}
