//! Public V2 application entry. No V1 IPC fallback.
fn main()->std::process::ExitCode { rbad::v2_tls::candidate::entry() }
