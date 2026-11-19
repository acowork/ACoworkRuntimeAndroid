//! `acowork-android version`

pub fn run() {
    println!(
        "acowork-android {} (independent Android node+runtime; Gateway enroll wired)",
        env!("CARGO_PKG_VERSION")
    );
}
