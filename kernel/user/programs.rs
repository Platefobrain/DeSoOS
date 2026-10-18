// Test programs for ring 3 (assembly, position-independent code).
//
// The earliest programs ended with `int3` (the kernel saves registers, rax = result);
// newer programs use syscalls (write, read, open, exit... – numbers
// in user/syscalls.rs).  The code lives in
// the kernel's .rodata (it is never executed there) and is copied into the
// process pages at USER_CODE.  The process data page (USER_DATA) holds at startup
// the argument given at launch in its first qword.

use core::arch::global_asm;

global_asm!(r#"
    .pushsection .rodata.user_programs, "a"

    .global up_sum
    .global up_sum_end
    // sum of 1..100 through the stack (push/pop), rbx = CS (ring 3 -> 0x23)
    up_sum:
        xor eax, eax
        mov ecx, 100
    1:  add rax, rcx
        push rax
        pop rax
        dec rcx
        jnz 1b
        mov bx, cs
        movzx ebx, bx
        int3
    up_sum_end:

    // ---------------- programs using syscalls ----------------

    .global up_hello
    .global up_hello_end
    up_hello:
        mov eax, 1                      // write(1, msg, len)
        mov edi, 1
        lea rsi, [rip + up_hello_msg]
        lea rdx, [rip + up_hello_msg_end]
        sub rdx, rsi
        syscall
        xor edi, edi                    // exit(0)
        xor eax, eax
        syscall
    up_hello_msg:
        .ascii "Hello from ring 3! (syscall write)\n"
    up_hello_msg_end:
    up_hello_end:

    .global up_cat
    .global up_cat_end
    // asks for a line (read from fd 0) and prints it back
    up_cat:
        mov eax, 1
        mov edi, 1
        lea rsi, [rip + up_cat_q]
        lea rdx, [rip + up_cat_q_end]
        sub rdx, rsi
        syscall
        sub rsp, 128
        mov eax, 2                      // read(0, rsp, 128)
        xor edi, edi
        mov rsi, rsp
        mov edx, 128
        syscall
        test rax, rax
        js 1f
        mov r12, rax
        mov eax, 1
        mov edi, 1
        lea rsi, [rip + up_cat_a]
        lea rdx, [rip + up_cat_a_end]
        sub rdx, rsi
        syscall
        mov eax, 1                      // write(1, rsp, n)
        mov edi, 1
        mov rsi, rsp
        mov rdx, r12
        syscall
        xor edi, edi
        xor eax, eax
        syscall
    1:  mov rdi, rax                    // exit(error)
        xor eax, eax
        syscall
    up_cat_q:
        .ascii "Type something: "
    up_cat_q_end:
    up_cat_a:
        .ascii "You typed: "
    up_cat_a_end:
    up_cat_end:

    .global up_files
    .global up_files_end
    // open/write/close/open/read/close on a VFS file, then prints the contents
    up_files:
        mov eax, 3                      // open(path, len, WRITE|CREATE|TRUNC)
        lea rdi, [rip + up_files_path]
        lea rsi, [rip + up_files_path_end]
        sub rsi, rdi
        mov edx, 14
        syscall
        test rax, rax
        js 1f
        mov r12, rax
        mov eax, 1                      // write(fd, text, len)
        mov rdi, r12
        lea rsi, [rip + up_files_text]
        lea rdx, [rip + up_files_text_end]
        sub rdx, rsi
        syscall
        test rax, rax
        js 1f
        mov eax, 4                      // close(fd)
        mov rdi, r12
        syscall
        mov eax, 3                      // open(path, len, READ)
        lea rdi, [rip + up_files_path]
        lea rsi, [rip + up_files_path_end]
        sub rsi, rdi
        mov edx, 1
        syscall
        test rax, rax
        js 1f
        mov r12, rax
        sub rsp, 128
        mov eax, 2                      // read(fd, rsp, 128)
        mov rdi, r12
        mov rsi, rsp
        mov edx, 128
        syscall
        test rax, rax
        js 1f
        mov r13, rax
        mov eax, 4
        mov rdi, r12
        syscall
        mov eax, 1                      // write(1, rsp, n)
        mov edi, 1
        mov rsi, rsp
        mov rdx, r13
        syscall
        xor edi, edi
        xor eax, eax
        syscall
    1:  mov rdi, rax
        xor eax, eax
        syscall
    up_files_path:
        .ascii "/tmp/ring3.txt"
    up_files_path_end:
    up_files_text:
        .ascii "written by a ring 3 process\n"
    up_files_text_end:
    up_files_end:

    .global up_badptr
    .global up_badptr_end
    // write with a kernel address -> -EFAULT (-14) as the exit code
    up_badptr:
        mov eax, 1
        mov edi, 1
        mov rsi, 0xffffffff80000000
        mov edx, 16
        syscall
        mov rdi, rax
        xor eax, eax
        syscall
    up_badptr_end:

    .global up_badsys
    .global up_badsys_end
    // unknown syscall -> -ENOSYS (-38) as the exit code
    up_badsys:
        mov eax, 999
        syscall
        mov rdi, rax
        xor eax, eax
        syscall
    up_badsys_end:

    .global up_pid
    .global up_pid_end
    // exit(getpid())
    up_pid:
        mov eax, 5
        syscall
        mov rdi, rax
        xor eax, eax
        syscall
    up_pid_end:

    .global up_sleeper
    .global up_sleeper_end
    // exit(how many ms sleep(100) really took)
    up_sleeper:
        mov eax, 8                      // uptime
        syscall
        mov r12, rax
        mov eax, 6                      // sleep(100)
        mov edi, 100
        syscall
        mov eax, 8
        syscall
        sub rax, r12
        mov rdi, rax
        xor eax, eax
        syscall
    up_sleeper_end:

    .global up_regs
    .global up_regs_end
    // 100 000 x getpid; registers other than rax/rcx/r11 must not change
    up_regs:
        mov rbx, 0x1111111111111111
        mov rbp, 0x2222222222222222
        mov rdi, 0x3333333333333333
        mov rsi, 0x4444444444444444
        mov rdx, 0x5555555555555555
        mov r8,  0x6666666666666666
        mov r9,  0x7777777777777777
        mov r10, 0x0888888888888888
        mov r12, 0x0999999999999999
        mov r13, 0x0aaaaaaaaaaaaaaa
        mov r14, 0x0bbbbbbbbbbbbbbb
        mov r15, 100000
    1:  mov eax, 5
        syscall
        mov rax, 0x1111111111111111
        cmp rbx, rax
        jne 2f
        mov rax, 0x2222222222222222
        cmp rbp, rax
        jne 2f
        mov rax, 0x3333333333333333
        cmp rdi, rax
        jne 2f
        mov rax, 0x4444444444444444
        cmp rsi, rax
        jne 2f
        mov rax, 0x5555555555555555
        cmp rdx, rax
        jne 2f
        mov rax, 0x6666666666666666
        cmp r8, rax
        jne 2f
        mov rax, 0x7777777777777777
        cmp r9, rax
        jne 2f
        mov rax, 0x0888888888888888
        cmp r10, rax
        jne 2f
        mov rax, 0x0999999999999999
        cmp r12, rax
        jne 2f
        mov rax, 0x0aaaaaaaaaaaaaaa
        cmp r13, rax
        jne 2f
        mov rax, 0x0bbbbbbbbbbbbbbb
        cmp r14, rax
        jne 2f
        dec r15
        jnz 1b
        xor edi, edi                    // exit(0)
        xor eax, eax
        syscall
    2:  mov edi, 1                      // exit(1) – a register changed
        xor eax, eax
        syscall
    up_regs_end:

    .global up_ticker
    .global up_ticker_end
    // 5 x ("tick" + sleep 1 s) – runs in the background without using the CPU
    up_ticker:
        mov r12, 5
    1:  mov eax, 1
        mov edi, 1
        lea rsi, [rip + up_ticker_msg]
        lea rdx, [rip + up_ticker_msg_end]
        sub rdx, rsi
        syscall
        mov eax, 6
        mov edi, 1000
        syscall
        dec r12
        jnz 1b
        xor edi, edi
        xor eax, eax
        syscall
    up_ticker_msg:
        .ascii "tick (sleep syscall, 1 s)\n"
    up_ticker_msg_end:
    up_ticker_end:

    .global up_counter
    .global up_counter_end
    // 3 000 000 x (read [USER_DATA], +1, write) – isolation and preemption
    up_counter:
        mov rdx, 0x600000
        mov ecx, 3000000
    1:  mov rbx, [rdx]
        inc rbx
        mov [rdx], rbx
        dec ecx
        jnz 1b
        mov rax, [rdx]
        int3
    up_counter_end:

    .global up_loop
    .global up_loop_end
    up_loop:
    1:  inc rax
        jmp 1b
    up_loop_end:

    .global up_pf_null
    .global up_pf_null_end
    up_pf_null:
        xor edx, edx
        mov rax, [rdx]
    up_pf_null_end:

    .global up_pf_kernel
    .global up_pf_kernel_end
    up_pf_kernel:
        mov rdx, 0xffffffff80000000
        mov rax, [rdx]
    up_pf_kernel_end:

    .global up_write_code
    .global up_write_code_end
    up_write_code:
        lea rdx, [rip]
        mov byte ptr [rdx], 0x90
    up_write_code_end:

    .global up_nx
    .global up_nx_end
    // jump onto its own stack (an NX page)
    up_nx:
        mov rdx, rsp
        sub rdx, 64
        jmp rdx
    up_nx_end:

    .global up_gp
    .global up_gp_end
    up_gp:
        hlt
    up_gp_end:

    .global up_ud
    .global up_ud_end
    up_ud:
        ud2
    up_ud_end:

    .global up_sse
    .global up_sse_end
    // SSE/x87 code as raw bytes – the kernel is soft-float, so we do not
    // rely on the assembler accepting these instructions.  The source is
    // in the comments.
    // mov eax, 21; movq xmm0, rax; paddq xmm0, xmm0; movq rax, xmm0; int3
    up_sse:
        .byte 0xb8, 0x15, 0x00, 0x00, 0x00, 0x66, 0x48, 0x0f, 0x6e, 0xc0, 0x66, 0x0f, 0xd4, 0xc0, 0x66, 0x48
        .byte 0x0f, 0x7e, 0xc0, 0xcc
    up_sse_end:

    .global up_x87
    .global up_x87_end
    // fld1; fld1; faddp; fld1; faddp; push 0; fistp qword [rsp]; pop rax; int3
    up_x87:
        .byte 0xd9, 0xe8, 0xd9, 0xe8, 0xde, 0xc1, 0xd9, 0xe8, 0xde, 0xc1, 0x6a, 0x00, 0xdf, 0x3c, 0x24, 0x58
        .byte 0xcc
    up_x87_end:

    .global up_xmm
    .global up_xmm_end
    // xmm0..xmm15 = seed+0..seed+15 (seed = [USER_DATA]), st0 = seed;
    // checks 2 000 000 times that the registers did not change (processes
    // switch meanwhile).  rax = 1 OK, 0xbad = XMM changed, 0xbad1 = x87.
    up_xmm:
        .byte 0x48, 0xc7, 0xc2, 0x00, 0x00, 0x60, 0x00, 0x48, 0x8b, 0x02, 0x66, 0x48, 0x0f, 0x6e, 0xc0, 0x48
        .byte 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x6e, 0xc8, 0x48, 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x6e, 0xd0, 0x48
        .byte 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x6e, 0xd8, 0x48, 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x6e, 0xe0, 0x48
        .byte 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x6e, 0xe8, 0x48, 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x6e, 0xf0, 0x48
        .byte 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x6e, 0xf8, 0x48, 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x6e, 0xc0, 0x48
        .byte 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x6e, 0xc8, 0x48, 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x6e, 0xd0, 0x48
        .byte 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x6e, 0xd8, 0x48, 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x6e, 0xe0, 0x48
        .byte 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x6e, 0xe8, 0x48, 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x6e, 0xf0, 0x48
        .byte 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x6e, 0xf8, 0xdf, 0x2a, 0x49, 0xc7, 0xc0, 0x80, 0x84, 0x1e, 0x00
        .byte 0x48, 0x8b, 0x02, 0x66, 0x48, 0x0f, 0x7e, 0xc1, 0x48, 0x39, 0xc1, 0x0f, 0x85, 0xfb, 0x00, 0x00
        .byte 0x00, 0x48, 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x7e, 0xc9, 0x48, 0x39, 0xc1, 0x0f, 0x85, 0xea, 0x00
        .byte 0x00, 0x00, 0x48, 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x7e, 0xd1, 0x48, 0x39, 0xc1, 0x0f, 0x85, 0xd9
        .byte 0x00, 0x00, 0x00, 0x48, 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x7e, 0xd9, 0x48, 0x39, 0xc1, 0x0f, 0x85
        .byte 0xc8, 0x00, 0x00, 0x00, 0x48, 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x7e, 0xe1, 0x48, 0x39, 0xc1, 0x0f
        .byte 0x85, 0xb7, 0x00, 0x00, 0x00, 0x48, 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x7e, 0xe9, 0x48, 0x39, 0xc1
        .byte 0x0f, 0x85, 0xa6, 0x00, 0x00, 0x00, 0x48, 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x7e, 0xf1, 0x48, 0x39
        .byte 0xc1, 0x0f, 0x85, 0x95, 0x00, 0x00, 0x00, 0x48, 0xff, 0xc0, 0x66, 0x48, 0x0f, 0x7e, 0xf9, 0x48
        .byte 0x39, 0xc1, 0x0f, 0x85, 0x84, 0x00, 0x00, 0x00, 0x48, 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x7e, 0xc1
        .byte 0x48, 0x39, 0xc1, 0x75, 0x77, 0x48, 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x7e, 0xc9, 0x48, 0x39, 0xc1
        .byte 0x75, 0x6a, 0x48, 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x7e, 0xd1, 0x48, 0x39, 0xc1, 0x75, 0x5d, 0x48
        .byte 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x7e, 0xd9, 0x48, 0x39, 0xc1, 0x75, 0x50, 0x48, 0xff, 0xc0, 0x66
        .byte 0x4c, 0x0f, 0x7e, 0xe1, 0x48, 0x39, 0xc1, 0x75, 0x43, 0x48, 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x7e
        .byte 0xe9, 0x48, 0x39, 0xc1, 0x75, 0x36, 0x48, 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x7e, 0xf1, 0x48, 0x39
        .byte 0xc1, 0x75, 0x29, 0x48, 0xff, 0xc0, 0x66, 0x4c, 0x0f, 0x7e, 0xf9, 0x48, 0x39, 0xc1, 0x75, 0x1c
        .byte 0x49, 0xff, 0xc8, 0x0f, 0x85, 0x07, 0xff, 0xff, 0xff, 0x48, 0x83, 0xec, 0x08, 0xdf, 0x3c, 0x24
        .byte 0x59, 0x48, 0x3b, 0x0a, 0x75, 0x0c, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xcc, 0xb8, 0xad, 0x0b, 0x00
        .byte 0x00, 0xcc, 0xb8, 0xd1, 0xba, 0x00, 0x00, 0xcc
    up_xmm_end:

    .global up_fpuclean
    .global up_fpuclean_end
    // New process: xmm0..15 = 0, FCW = 0x37f, MXCSR = 0x1f80 -> rax = 1
    // (0xbad2 = XMM not zero, 0xbad3 = FCW, 0xbad4 = MXCSR).
    up_fpuclean:
        .byte 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0x66, 0x0f, 0xeb, 0xc1, 0x66, 0x0f, 0xeb, 0xc2, 0x66, 0x0f, 0xeb
        .byte 0xc3, 0x66, 0x0f, 0xeb, 0xc4, 0x66, 0x0f, 0xeb, 0xc5, 0x66, 0x0f, 0xeb, 0xc6, 0x66, 0x0f, 0xeb
        .byte 0xc7, 0x66, 0x41, 0x0f, 0xeb, 0xc0, 0x66, 0x41, 0x0f, 0xeb, 0xc1, 0x66, 0x41, 0x0f, 0xeb, 0xc2
        .byte 0x66, 0x41, 0x0f, 0xeb, 0xc3, 0x66, 0x41, 0x0f, 0xeb, 0xc4, 0x66, 0x41, 0x0f, 0xeb, 0xc5, 0x66
        .byte 0x41, 0x0f, 0xeb, 0xc6, 0x66, 0x41, 0x0f, 0xeb, 0xc7, 0x66, 0x48, 0x0f, 0x7e, 0xc0, 0x66, 0x0f
        .byte 0x73, 0xd8, 0x08, 0x66, 0x48, 0x0f, 0x7e, 0xc1, 0x48, 0x09, 0xc8, 0x75, 0x28, 0x48, 0x83, 0xec
        .byte 0x08, 0xd9, 0x3c, 0x24, 0x0f, 0xb7, 0x0c, 0x24, 0x81, 0xf9, 0x7f, 0x03, 0x00, 0x00, 0x75, 0x1b
        .byte 0x0f, 0xae, 0x1c, 0x24, 0x8b, 0x0c, 0x24, 0x81, 0xf9, 0x80, 0x1f, 0x00, 0x00, 0x75, 0x12, 0xb8
        .byte 0x01, 0x00, 0x00, 0x00, 0xcc, 0xb8, 0xd2, 0xba, 0x00, 0x00, 0xcc, 0xb8, 0xd3, 0xba, 0x00, 0x00
        .byte 0xcc, 0xb8, 0xd4, 0xba, 0x00, 0x00, 0xcc
    up_fpuclean_end:

    .global up_simdexc
    .global up_simdexc_end
    // divide-by-zero unmasked in MXCSR, divsd x/0 -> #XM (vector 19)
    up_simdexc:
        .byte 0x48, 0x83, 0xec, 0x08, 0x0f, 0xae, 0x1c, 0x24, 0x81, 0x24, 0x24, 0xff, 0xfd, 0xff, 0xff, 0x0f
        .byte 0xae, 0x14, 0x24, 0x66, 0x0f, 0x57, 0xc9, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xf2, 0x48, 0x0f, 0x2a
        .byte 0xc0, 0xf2, 0x0f, 0x5e, 0xc1, 0xcc
    up_simdexc_end:

    .global up_ret
    .global up_ret_end
    up_ret:
        ret
    up_ret_end:

    // ---------------- syscalls without the BKL ----------------

    .global up_lines
    .global up_lines_end
    // 2000 x write(1, 51-byte line), exit(0) – every line must arrive whole
    up_lines:
        mov r12d, 2000
    1:  mov eax, 1
        mov edi, 1
        lea rsi, [rip + up_lines_msg]
        mov edx, 51
        syscall
        cmp rax, 51
        jne 2f
        dec r12d
        jnz 1b
        xor edi, edi
        xor eax, eax
        syscall
    2:  mov rdi, rax
        xor eax, eax
        syscall
    up_lines_msg:
        .ascii "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN\n"
    up_lines_end:

    .global up_pidloop
    .global up_pidloop_end
    // getpid forever (killed in the middle of BKL-free syscalls)
    up_pidloop:
    1:  mov eax, 5
        syscall
        jmp 1b
    up_pidloop_end:

    .popsection
"#);

macro_rules! programs {
    ($( $name:literal => $start:ident, $end:ident, $about:literal; )*) => {
        unsafe extern "C" {
            $( static $start: u8; static $end: u8; )*
        }

        /// (name, description)
        pub const LIST: &[(&str, &str)] = &[ $( ($name, $about), )* ];

        /// Program code.
        pub fn code(name: &str) -> Option<&'static [u8]> {
            $(
                if name == $name {
                    let start = core::ptr::addr_of!($start);
                    let end = core::ptr::addr_of!($end) as usize;
                    return Some(unsafe { core::slice::from_raw_parts(start, end - start as usize) });
                }
            )*
            None
        }
    };
}

programs! {
    "hello"     => up_hello, up_hello_end, "prints a line with the write syscall, exit(0)";
    "cat"       => up_cat, up_cat_end, "asks for a line (read from the keyboard) and prints it";
    "files"     => up_files, up_files_end, "open/write/read/close /tmp/ring3.txt, prints it";
    "ticker"    => up_ticker, up_ticker_end, "prints 'tick' 5 times, sleeping 1 s (try 'run ticker &')";
    "pid"       => up_pid, up_pid_end, "exit(getpid())";
    "sleeper"   => up_sleeper, up_sleeper_end, "sleep(100) -> exit code = measured ms";
    "regs"      => up_regs, up_regs_end, "100k syscalls, checks registers survive (exit 0)";
    "badptr"    => up_badptr, up_badptr_end, "write() with a kernel address -> exit(-14 EFAULT)";
    "badsys"    => up_badsys, up_badsys_end, "unknown syscall -> exit(-38 ENOSYS)";
    "sum"       => up_sum, up_sum_end, "sum 1..100 via the stack, ends with int3 (rax = 5050)";
    "counter"   => up_counter, up_counter_end, "3M increments of its own data page (isolation)";
    "loop"      => up_loop, up_loop_end, "infinite loop (preemption; stop with Ctrl+C / kill)";
    "pf"        => up_pf_null, up_pf_null_end, "read address 0 -> #PF";
    "pfkernel"  => up_pf_kernel, up_pf_kernel_end, "read kernel memory -> #PF (protection)";
    "writecode" => up_write_code, up_write_code_end, "write to its own code page -> #PF";
    "nx"        => up_nx, up_nx_end, "jump to its stack -> #PF (NX)";
    "gp"        => up_gp, up_gp_end, "hlt in ring 3 -> #GP";
    "ud"        => up_ud, up_ud_end, "ud2 -> #UD";
    "sse"       => up_sse, up_sse_end, "SSE: 21 + 21 in xmm0 (rax = 42)";
    "x87"       => up_x87, up_x87_end, "x87: 1 + 1 + 1 (rax = 3)";
    "xmm"       => up_xmm, up_xmm_end, "xmm0-15 + st0 checked 2M times (run several: 'run xmm &')";
    "fpuclean"  => up_fpuclean, up_fpuclean_end, "new process starts with clean FPU/SSE state (rax = 1)";
    "simdexc"   => up_simdexc, up_simdexc_end, "unmasked SSE divide by zero -> #XM";
    "ret"       => up_ret, up_ret_end, "single ret (kernel SMEP test)";
    "lines"     => up_lines, up_lines_end, "2000 lines with write (syscall without BKL), exit(0)";
    "pidloop"   => up_pidloop, up_pidloop_end, "getpid forever (stop with Ctrl+C / kill)";
}
