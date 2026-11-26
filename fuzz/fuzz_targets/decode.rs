#![no_main]
//! Link-layer and header decoding on every supported link type.
use libfuzzer_sys::fuzz_target;
use silentsnake_capture::decode::{self, LinkType};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, pkt)) = data.split_first() else { return };
    let link = match sel % 6 {
        0 => LinkType::Ethernet,
        1 => LinkType::LinuxSll,
        2 => LinkType::LinuxSll2,
        3 => LinkType::Raw,
        4 => LinkType::Null,
        _ => LinkType::Unsupported(i32::from(sel)),
    };
    let _ = decode::decode(link, pkt, sel & 0x80 != 0);
});
