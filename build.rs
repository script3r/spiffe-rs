fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_server(false)
        .compile_well_known_types(true)
        .compile(&["proto/spiffe/workload/workload.proto"], &["proto"])?;
    Ok(())
}
