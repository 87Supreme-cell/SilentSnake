//! Packet timestamps and RFC 3339 formatting (UTC, microseconds), without extra crates.

use serde::{Serialize, Serializer};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// A UTC timestamp with microsecond precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ts {
    secs: i64,
    micros: u32,
}

impl Ts {
    /// Builds a timestamp from seconds and microseconds; out-of-range microseconds are normalized.
    pub fn new(secs: i64, micros: i64) -> Self {
        let carry = micros.div_euclid(1_000_000);
        let rem = micros.rem_euclid(1_000_000);
        Ts {
            secs: secs.saturating_add(carry),
            micros: u32::try_from(rem).unwrap_or(0),
        }
    }

    /// Current wall-clock time (falls back to the epoch if the clock is before 1970).
    pub fn now() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => Ts {
                secs: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                micros: d.subsec_micros(),
            },
            Err(_) => Ts::default(),
        }
    }

    pub fn secs(&self) -> i64 {
        self.secs
    }

    /// `self + secs`, saturating.
    pub fn plus_secs(&self, secs: i64) -> Self {
        Ts {
            secs: self.secs.saturating_add(secs),
            micros: self.micros,
        }
    }

    /// Milliseconds from `earlier` to `self` (negative if `earlier` is later), saturating.
    pub fn millis_since(&self, earlier: Ts) -> i64 {
        let s = self.secs.saturating_sub(earlier.secs).saturating_mul(1000);
        let us = i64::from(self.micros) - i64::from(earlier.micros);
        s.saturating_add(us / 1000)
    }

    /// RFC 3339 / ISO 8601 in UTC, e.g. `2026-11-25T19:35:02.123456Z`.
    pub fn rfc3339(&self) -> String {
        let days = self.secs.div_euclid(86_400);
        let sod = self.secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:06}Z",
            sod / 3600,
            (sod % 3600) / 60,
            sod % 60,
            self.micros
        )
    }
}

impl fmt::Display for Ts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.rfc3339())
    }
}

impl Serialize for Ts {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.rfc3339())
    }
}

/// Days since 1970-01-01 to (year, month, day) in the proleptic Gregorian calendar
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(Ts::new(0, 0).rfc3339(), "1970-01-01T00:00:00.000000Z");
        assert_eq!(
            Ts::new(951_782_400, 5).rfc3339(),
            "2000-02-29T00:00:00.000005Z"
        );
        assert_eq!(
            Ts::new(1_795_628_102, 123_456).rfc3339(),
            "2026-11-25T17:35:02.123456Z"
        );
        assert_eq!(Ts::new(-1, 0).rfc3339(), "1969-12-31T23:59:59.000000Z");
    }

    #[test]
    fn normalizes_and_diffs() {
        assert_eq!(Ts::new(10, 1_500_000), Ts::new(11, 500_000));
        assert_eq!(Ts::new(10, 0).millis_since(Ts::new(8, 500_000)), 1500);
        assert_eq!(Ts::new(8, 0).millis_since(Ts::new(10, 0)), -2000);
    }
}
