//! Build settings that only the linker can make.
//!
//! Windows gives a program's main thread 1 MiB of stack, against 8 MiB on Linux and macOS.
//! Building opv's command-line definition (clap, every subcommand and flag) uses more than
//! that in debug builds, so `opv` overflowed its stack on Windows before printing anything
//! once the 0.6.0 commands were added. Reserve 8 MiB there too, as on every other platform.

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os == "windows" && env == "msvc" {
        println!("cargo:rustc-link-arg-bins=/STACK:8388608");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
