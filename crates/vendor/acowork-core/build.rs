fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use vendored protoc so contributors and CI don't need to install protoc manually.
    // This works on Windows, macOS, and Linux without any extra setup.
    let protoc_path = protoc_bin_vendored::protoc_bin_path()
        .expect("protoc-bin-vendored: failed to locate bundled protoc binary");
    // SAFETY: build scripts are single-threaded; setting PROTOC here is safe.
    unsafe { std::env::set_var("PROTOC", protoc_path) };

    // ADR-033: Compile MQTT payload protos (prost-only — no gRPC bindings).
    // `mqtt_payload.proto` carries the wire format for every PUBLISH payload
    // that flows over the local MQTT bus between Gateway, Runtime, Desktop, and
    // sidecars.
    prost_build::Config::new()
        .compile_protos(&["proto/mqtt_payload.proto"], &["proto"])?;

    Ok(())
}
