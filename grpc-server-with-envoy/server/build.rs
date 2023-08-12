const PROTO_ROOT_DIR: &str = "./proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .file_descriptor_set_path(out_dir.join("auth_service_descriptor.bin"))
        .build_client(false)
        .compile(
            &[format!("{}/auth/v1/auth_service.proto", PROTO_ROOT_DIR)],
            &[PROTO_ROOT_DIR],
        )?;
    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .file_descriptor_set_path(out_dir.join("misc_service_descriptor.bin"))
        .build_client(false)
        .compile(
            &[format!("{}/misc/v1/misc_service.proto", PROTO_ROOT_DIR)],
            &[PROTO_ROOT_DIR],
        )?;
    Ok(())
}
