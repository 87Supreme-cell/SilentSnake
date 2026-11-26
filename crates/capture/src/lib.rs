//! SilentSnake capture engine, stage A (`dependencies.json` > `capture_integration_roadmap`):
//! libpcap capture; flows, DNS and TLS SNI; plain-English summaries.
//!
//! Design and rationale: `docs/decisions/0001-stage-a-libpcap-capture.md`.
//! Output schema: `docs/api/capture-events.md`.

#![forbid(unsafe_code)]

pub mod decode;
pub mod dns;
pub mod engine;
pub mod event;
pub mod privilege;
pub mod sanitize;
pub mod source;
pub mod summary;
pub mod time;
pub mod tls;

#[cfg(test)]
mod robustness;
