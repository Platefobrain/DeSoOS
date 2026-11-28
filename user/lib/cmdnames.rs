// The names the system keeps for itself – one list for the shell (/bin/sh) and the package
// manager (/bin/desopkg).
//
// A name on these lists, or the name of any file in /bin, is a *system name*: the shell runs
// the built-in, the information command or the /bin program and never looks further – not in
// /disk/bin, not among installed packages.  So desopkg refuses a package, or a program in a
// package, with such a name: it would install, but typing its name would never run it.
//
// Comparison is plain byte equality: no case folding, no normalisation (package and program
// names are lower-case ASCII, digits and '-' only – anything else is refused by the name
// grammar before it gets here).  /bin is not written out: `system_name` asks the caller whether
// /bin/<name> exists (the shell and desopkg: `stat` on the running system; tools/desopkg.py on
// the host: the programs build.sh put into build/user/).
//
// tools/desopkg.py reads the four lists below from this file (the `const NAME: … = &[` lines up
// to the closing `];`), so keep each list in this shape.

/// Built-in commands of the shell (name, the line `help` prints).
pub const BUILTINS: &[(&str, &str)] = &[
    ("cd", "cd [dir]           change directory (no argument: /)"),
    ("pwd", "pwd                print the current directory"),
    ("echo", "echo [text...]     print text"),
    ("exit", "exit [code]        leave the shell (init starts a new one)"),
    ("help", "help               this list"),
    ("history", "history            command history"),
    ("clear", "clear              clear the screen (also Ctrl+L)"),
    ("wait", "wait               wait for background programs"),
    ("kill", "kill <pid|service>  end a program started here, or a service (init restarts it)"),
    ("sync", "sync               flush file system buffers to disk"),
    ("reboot", "reboot             restart the computer"),
    ("halt", "halt               stop the computer"),
    ("stress", "stress [s]         SMP stress test in the kernel (1..600 s, default 10)"),
    ("desofs", "desofs <cmd> <disk> DeSoFS: info, format [yes], mount (0 at /disk, others at /desofs), unmount, check, repair [yes],\n                   snapshot create|mount <disk> <name>, snapshot list <disk>, snapshot delete|restore <disk> <name> [yes]"),
];

/// System actions (sysctl syscall) – only with the SYSCTL handle from init.
pub const SYSCTL_BUILTINS: &[&str] = &["sync", "reboot", "halt", "stress", "desofs"];

/// Information from the kernel (sysinfo syscall, read-only).
pub const INFO_COMMANDS: &[&str] = &["ver", "uptime", "date", "mem", "counters", "irq", "cpus", "lspci", "acpi", "disk", "mount", "df", "dcp"];

/// Commands that remain only in the kernel's emergency shell.
pub const KERNEL_ONLY: &[&str] = &["run", "hexdump", "write", "spawn", "colors", "keys", "k"];

/// A name on one of the lists above (without /bin).
pub fn listed(name: &str) -> bool {
    BUILTINS.iter().any(|(n, _)| *n == name) || SYSCTL_BUILTINS.contains(&name) || INFO_COMMANDS.contains(&name) || KERNEL_ONLY.contains(&name)
}

/// A name the system already uses: on a list above, or a file /bin/<name> (`in_bin` – asked
/// live, so every program that ever lands in /bin is covered without changing this file).
pub fn system_name(name: &str, in_bin: &dyn Fn(&str) -> bool) -> bool {
    listed(name) || in_bin(name)
}
