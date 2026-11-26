#![no_main]
//! DNS parser: any bytes must parse or fail cleanly; names stay sanitized and bounded.
use libfuzzer_sys::fuzz_target;
use silentsnake_capture::dns;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = dns::parse(data) {
        assert!(m.questions.len() <= dns::MAX_QUESTIONS);
        assert!(m.answers.len() <= dns::MAX_ANSWERS);
        for name in m.questions.iter().map(|q| &q.name).chain(m.answers.iter().map(|a| &a.name)) {
            // 255 wire bytes, each escaped to at most 4 characters.
            assert!(name.len() <= 4 * dns::MAX_NAME_WIRE_LEN);
            assert!(name.bytes().all(|b| b.is_ascii_graphic()), "unsanitized name: {name:?}");
        }
    }
});
