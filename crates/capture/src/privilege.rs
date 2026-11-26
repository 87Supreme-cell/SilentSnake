//! Least-privilege guard (CLAUDE.md section 4): never run as root, and hold no capability
//! other than CAP_NET_RAW. Read from `/proc/self/status`, so no `unsafe` is needed.
//!
//! Every identity and capability set is checked, not just the effective ones (ADV-0001): a
//! process whose saved uid is 0, or which holds extra *permitted* capabilities, can regain
//! that privilege at any moment, so it is refused just like an effective root.

pub const CAP_NET_RAW: u32 = 13;
const ALLOWED: u64 = 1u64 << CAP_NET_RAW;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    /// Real, effective, saved and filesystem uid.
    pub uids: [u32; 4],
    /// Real, effective, saved and filesystem gid.
    pub gids: [u32; 4],
    /// Group 0 is among the supplementary groups (ADV-0022).
    pub root_group: bool,
    pub cap_inh: u64,
    pub cap_prm: u64,
    pub cap_eff: u64,
    pub cap_amb: u64,
}

impl Identity {
    pub fn euid(&self) -> u32 {
        self.uids[1]
    }

    pub fn has_cap_net_raw(&self) -> bool {
        self.cap_eff & ALLOWED != 0
    }

    /// An ordinary unprivileged identity (uid/gid `id`, no capabilities). For tests and tools.
    pub fn unprivileged(id: u32) -> Self {
        Identity {
            uids: [id; 4],
            gids: [id; 4],
            root_group: false,
            cap_inh: 0,
            cap_prm: 0,
            cap_eff: 0,
            cap_amb: 0,
        }
    }
}

fn ids(rest: &str) -> Option<[u32; 4]> {
    let v: Vec<u32> = rest
        .split_whitespace()
        .map(|s| s.parse().ok())
        .collect::<Option<_>>()?;
    <[u32; 4]>::try_from(v).ok()
}

fn mask(rest: &str) -> Option<u64> {
    u64::from_str_radix(rest.trim(), 16).ok()
}

/// Parses `Uid:`, `Gid:`, `Groups:`, `CapInh:`, `CapPrm:`, `CapEff:` and `CapAmb:`. Any missing or
/// malformed line yields `None` (and the caller refuses to start).
pub fn parse_status(status: &str) -> Option<Identity> {
    let (mut uids, mut gids) = (None, None);
    let mut groups: Option<Vec<u32>> = None;
    let (mut inh, mut prm, mut eff, mut amb) = (None, None, None, None);
    for line in status.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        match key {
            "Uid" => uids = ids(rest),
            "Gid" => gids = ids(rest),
            "CapInh" => inh = mask(rest),
            "CapPrm" => prm = mask(rest),
            "CapEff" => eff = mask(rest),
            "CapAmb" => amb = mask(rest),
            "Groups" => {
                groups = rest.split_whitespace().map(|g| g.parse().ok()).collect();
            }
            _ => {}
        }
    }
    Some(Identity {
        uids: uids?,
        gids: gids?,
        root_group: groups?.contains(&0),
        cap_inh: inh?,
        cap_prm: prm?,
        cap_eff: eff?,
        cap_amb: amb?,
    })
}

pub fn current() -> Result<Identity, String> {
    let s = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("cannot read /proc/self/status: {e}"))?;
    parse_status(&s).ok_or_else(|| "cannot parse /proc/self/status".to_string())
}

/// Fails closed: refuses uid or gid 0 in any slot (real, effective, saved, filesystem) or
/// among the supplementary groups, and
/// any inheritable, permitted, effective or ambient capability other than CAP_NET_RAW.
pub fn check(id: &Identity) -> Result<(), String> {
    if id.uids.contains(&0) || id.gids.contains(&0) || id.root_group {
        return Err(format!(
            "refusing to run with root identity (uids {:?}, gids {:?}). Grant CAP_NET_RAW to \
             this binary instead: sudo setcap cap_net_raw=ep <path-to-silentsnake-capture>",
            id.uids, id.gids
        ));
    }
    for (name, set) in [
        ("inheritable", id.cap_inh),
        ("permitted", id.cap_prm),
        ("effective", id.cap_eff),
        ("ambient", id.cap_amb),
    ] {
        let extra = set & !ALLOWED;
        if extra != 0 {
            return Err(format!(
                "refusing to run with capabilities beyond CAP_NET_RAW ({name} set {set:#x}, extra {extra:#x})"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(uid: &str, gid: &str, inh: &str, prm: &str, eff: &str, amb: &str) -> String {
        format!(
            "Name:\tx\nUid:\t{uid}\nGid:\t{gid}\nGroups:\t10 1000 \nCapInh:\t{inh}\nCapPrm:\t{prm}\nCapEff:\t{eff}\nCapAmb:\t{amb}\n"
        )
    }
    const U: &str = "1000\t1000\t1000\t1000";
    const Z: &str = "0000000000000000";
    const RAW: &str = "0000000000002000";
    const RAW_ADMIN: &str = "0000000000003000";
    const SYS_ADMIN_P: &str = "0000000000202000";

    #[test]
    fn accepts_plain_user_and_net_raw() {
        let u = parse_status(&status(U, U, Z, Z, Z, Z)).unwrap();
        assert!(check(&u).is_ok() && !u.has_cap_net_raw());
        let n = parse_status(&status(U, U, Z, RAW, RAW, Z)).unwrap();
        assert!(check(&n).is_ok() && n.has_cap_net_raw());
        assert_eq!(n.euid(), 1000);
    }

    #[test]
    fn refuses_root_in_any_uid_or_gid_slot() {
        for s in [
            "0\t1000\t1000\t1000",
            "1000\t0\t0\t0",
            "1000\t1000\t0\t1000",
            "1000\t1000\t1000\t0",
        ] {
            assert!(
                check(&parse_status(&status(s, U, Z, Z, Z, Z)).unwrap())
                    .unwrap_err()
                    .contains("root"),
                "uids {s}"
            );
            assert!(
                check(&parse_status(&status(U, s, Z, Z, Z, Z)).unwrap())
                    .unwrap_err()
                    .contains("root"),
                "gids {s}"
            );
        }
    }

    #[test]
    fn refuses_extra_caps_in_any_set() {
        // ADV-0001: `setcap 'cap_net_raw=ep cap_sys_admin=p'` gives an extra *permitted* cap.
        let e = check(&parse_status(&status(U, U, Z, SYS_ADMIN_P, RAW, Z)).unwrap()).unwrap_err();
        assert!(e.contains("permitted"), "{e}");
        assert!(
            check(&parse_status(&status(U, U, Z, RAW, RAW_ADMIN, Z)).unwrap())
                .unwrap_err()
                .contains("effective")
        );
        assert!(
            check(&parse_status(&status(U, U, RAW_ADMIN, RAW, RAW, Z)).unwrap())
                .unwrap_err()
                .contains("inheritable")
        );
        assert!(
            check(&parse_status(&status(U, U, Z, RAW, RAW, RAW_ADMIN)).unwrap())
                .unwrap_err()
                .contains("ambient")
        );
    }

    #[test]
    fn refuses_supplementary_root_group() {
        let with_root =
            status(U, U, Z, Z, Z, Z).replace("Groups:\t10 1000 ", "Groups:\t0 10 1000 ");
        assert!(
            check(&parse_status(&with_root).unwrap())
                .unwrap_err()
                .contains("root")
        );
        let no_groups = status(U, U, Z, Z, Z, Z).replace("Groups:\t10 1000 ", "Groups:\t");
        assert!(check(&parse_status(&no_groups).unwrap()).is_ok());
        let missing = status(U, U, Z, Z, Z, Z).replace("Groups:\t10 1000 \n", "");
        assert_eq!(parse_status(&missing), None);
    }

    #[test]
    fn missing_or_malformed_lines_fail_closed() {
        assert_eq!(
            parse_status("Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0\n"),
            None
        );
        assert_eq!(
            parse_status(&status("1000\t1000\t1000", U, Z, Z, Z, Z)),
            None
        );
        assert_eq!(parse_status(&status(U, U, Z, "zz", Z, Z)), None);
    }
}
