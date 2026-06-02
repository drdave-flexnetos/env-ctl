//! Compile the VENDORED control-plane proto with no system `protoc`: `protox` (pure Rust) parses
//! the .proto into a FileDescriptorSet, which tonic-build turns into client+server code. The proto
//! lives inside this crate (CARGO_MANIFEST_DIR/proto) so the crate drops into envctl verbatim.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR")?;
    let proto_dir = std::path::Path::new(&manifest).join("proto");
    let proto = proto_dir.join("control.proto");

    let fds = protox::compile([&proto], [&proto_dir])?;

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_fds(fds)?;

    println!("cargo:rerun-if-changed={}", proto.display());
    Ok(())
}
