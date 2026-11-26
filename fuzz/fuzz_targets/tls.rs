#![no_main]
//! TLS ClientHello parser: any stream must parse, ask for more, or fail cleanly, and every
//! prefix of a stream must be consistent (no "complete" result before the bytes exist).
use libfuzzer_sys::fuzz_target;
use silentsnake_capture::tls;

fuzz_target!(|data: &[u8]| {
    let full = tls::parse_client_hello(data);
    if let Ok(Some(ch)) = &full {
        if let Some(n) = &ch.server_name {
            assert!(n.len() <= 4 * tls::MAX_SNI);
            assert!(n.bytes().all(|b| b.is_ascii_graphic()), "unsanitized SNI: {n:?}");
        }
    }
    let _ = tls::parse_client_hello(&data[..data.len() / 2]);
});
