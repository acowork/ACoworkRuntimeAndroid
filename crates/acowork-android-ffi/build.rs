//! Link liblog so `src/logcat.rs` can reach `__android_log_write`.
//!
//! The NDK clang driver does not add it for Rust (rustc drives the link
//! itself), and without it the cdylib loads with an unresolved symbol — which
//! surfaces as a `dlopen` failure in `System.loadLibrary`, i.e. as "native
//! library not ready" in the app rather than as a link error.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-lib=log");
    }
}
