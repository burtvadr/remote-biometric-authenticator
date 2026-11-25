#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() <= 35 { rbad::v2_store::fuzz_state_trace(data); }
});
