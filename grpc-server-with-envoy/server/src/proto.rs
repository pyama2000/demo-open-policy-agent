pub mod auth {
    pub mod v1 {
        tonic::include_proto!("auth.v1");
        pub const FILE_DESCRIPTOR: &[u8] =
            tonic::include_file_descriptor_set!("auth_service_descriptor");
    }
}

pub mod misc {
    pub mod v1 {
        tonic::include_proto!("misc.v1");
        pub const FILE_DESCRIPTOR: &[u8] =
            tonic::include_file_descriptor_set!("misc_service_descriptor");
    }
}
