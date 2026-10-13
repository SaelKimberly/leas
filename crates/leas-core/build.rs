fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `protox` parses the .proto in-process, so `protoc` is no longer a build
    // prerequisite of this crate (or of anyone building it from crates.io):
    // `tonic_prost_build::compile_protos` used to shell out to an external
    // binary that neither a clean machine nor a CI image necessarily has.
    //
    // `compile_fds` consumes the builder, so the configuration must be applied
    // first. The emitted code is byte-identical to the protoc path — a change in
    // it means the descriptor set differs, not that the formatting moved.
    let fds = protox::compile(["proto/stats.proto"], ["proto"])?;
    tonic_prost_build::configure()
        .build_server(false)
        .compile_fds(fds)?;
    Ok(())
}
