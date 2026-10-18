// Embeds the kernel into the DSB (include_bytes! in boot/dsb.rs).
// The kernel is an ELF (build/kernel.boot.elf = build/kernel.elf without symbols),
// not a flat kernel.bin.
fn main() {
    let kernel = std::path::Path::new("build/kernel.boot.elf");
    println!("cargo:rerun-if-changed={}", kernel.display());
    if !kernel.exists() {
        panic!("build/kernel.boot.elf missing — build the kernel first (./build.sh)");
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out = std::path::Path::new(&out_dir);
    std::fs::copy(kernel, out.join("kernel.elf")).expect("copy kernel ELF into OUT_DIR");
}
