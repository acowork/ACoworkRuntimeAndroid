fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Vendored protoc so CI / developer machines do not need a system install.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    prost_build::Config::new()
        .protoc_executable(protoc)
        .btree_map(["."])
        .compile_protos(&["proto/node_control.proto"], &["proto/"])?;
    println!("cargo:rerun-if-changed=proto/node_control.proto");
    Ok(())
}
