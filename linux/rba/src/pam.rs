//! PAM integration helpers.
//!
//! Edits `/etc/pam.d` files directly so `rba` is self-contained: no shell
//! scripts, no "installer not found" errors. All changes are scoped, backed up
//! and reversible.

use std::fs;
use std::path::Path;

const MODULE_PATH: &str = "/usr/lib/security/pam_rba.so";

#[derive(Clone, Copy)]
pub struct Backend {
    pub name: &'static str,
    pub target: &'static str,
    pub vendor: Option<&'static str>,
    pub purpose: &'static str,
    /// Line to insert before (matched as a substring of a trimmed line).
    pub anchor: &'static str,
    pub timeout_ms: u32,
}

pub const BACKENDS: &[Backend] = &[
    Backend {
        name: "gdm",
        target: "/etc/pam.d/gdm-password",
        vendor: Some("/usr/lib/pam.d/gdm-password"),
        purpose: "gdm",
        anchor: "auth       include                     system-local-login",
        timeout_ms: 5000,
    },
    Backend {
        name: "polkit",
        target: "/etc/pam.d/polkit-1",
        vendor: Some("/usr/lib/pam.d/polkit-1"),
        purpose: "polkit",
        anchor: "auth       include      system-auth",
        timeout_ms: 5000,
    },
    Backend {
        name: "sudo",
        target: "/etc/pam.d/sudo",
        vendor: None,
        purpose: "sudo",
        anchor: "auth\t\tinclude\t\tsystem-auth",
        timeout_ms: 5000,
    },
];

pub fn find_backend(name: &str) -> Option<&'static Backend> {
    BACKENDS.iter().find(|b| b.name == name)
}

fn pam_line(b: &Backend, timeout_ms: u32) -> String {
    format!(
        "auth        sufficient    pam_rba.so purpose={} timeout_ms={}",
        b.purpose, timeout_ms
    )
}

fn rollback_record_path(b: &Backend) -> String {
    format!("{}.rba.rollback", b.target)
}

pub fn is_enabled(b: &Backend) -> bool {
    fs::read_to_string(b.target)
        .map(|s| s.contains("pam_rba.so"))
        .unwrap_or(false)
}

/// Show what would change. Returns (old_content, new_content).
pub fn plan_enable(b: &Backend, timeout_ms: u32) -> Result<(String, String), String> {
    let module = Path::new(MODULE_PATH);
    if !module.exists() {
        return Err(format!("{MODULE_PATH} not found; install rba first"));
    }
    let line = pam_line(b, timeout_ms);

    let base = if Path::new(b.target).exists() {
        fs::read_to_string(b.target).map_err(|e| e.to_string())?
    } else if let Some(v) = b.vendor {
        if Path::new(v).exists() {
            fs::read_to_string(v).map_err(|e| e.to_string())?
        } else {
            return Err(format!("vendor file {v} missing"));
        }
    } else {
        return Err(format!("target file {} missing", b.target));
    };

    // Already enabled: update in place
    if base.contains("pam_rba.so") {
        let new = base
            .lines()
            .map(|l| {
                if l.contains("pam_rba.so") {
                    line.clone()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        // preserve trailing newline
        let new = if base.ends_with('\n') && !new.ends_with('\n') {
            new + "\n"
        } else {
            new
        };
        if new == base {
            return Err("already up to date".into());
        }
        return Ok((base, new));
    }

    // Find anchor
    let mut lines: Vec<String> = base.lines().map(|s| s.to_string()).collect();
    let mut inserted = false;
    for l in lines.iter_mut() {
        if l.trim() == b.anchor.trim() && !inserted {
            // insert before this line
            *l = format!("{line}\n{l}");
            inserted = true;
        }
    }
    if !inserted {
        // try looser match: line contains anchor keywords
        let anchor_key = b.anchor.split_whitespace().last().unwrap_or("");
        let mut found = false;
        for l in lines.iter_mut() {
            if l.trim().starts_with("auth") && l.contains(anchor_key) && !found {
                *l = format!("{line}\n{l}");
                found = true;
            }
        }
        if !found {
            return Err(format!("anchor '{}' not found in {}", b.anchor, b.target));
        }
    }

    let new = lines.join("\n");
    let new = if base.ends_with('\n') && !new.ends_with('\n') {
        new + "\n"
    } else {
        new
    };
    Ok((base, new))
}

pub fn apply_enable(b: &Backend, base: &str, new: &str) -> Result<(), String> {
    let backup = format!("{}.bak.{}", b.target, chrono_stamp());
    fs::write(&backup, base).map_err(|e| e.to_string())?;

    fs::write(b.target, new).map_err(|e| e.to_string())?;

    // Create rollback record
    let record = rollback_record_path(b);
    let content = format!("RBA_BACKUP={}\n", backup);
    fs::write(&record, &content).map_err(|e| e.to_string())?;
    let _ = std::process::Command::new("chmod")
        .arg("600")
        .arg(&record)
        .status();

    Ok(())
}

pub fn apply_rollback(b: &Backend) -> Result<(), String> {
    let record = rollback_record_path(b);
    let rec = fs::read_to_string(&record).map_err(|e| format!("no rollback record: {e}"))?;
    // Parse RBA_BACKUP
    let backup = rec
        .lines()
        .find(|l| l.starts_with("RBA_BACKUP="))
        .and_then(|l| l.strip_prefix("RBA_BACKUP="))
        .unwrap_or("absent");

    if backup == "absent" {
        // Remove the target file
        let _ = fs::remove_file(b.target);
    } else {
        let content = fs::read_to_string(backup).map_err(|e| format!("backup not found: {e}"))?;
        fs::write(b.target, content).map_err(|e| e.to_string())?;
    }
    let _ = fs::remove_file(&record);
    Ok(())
}

fn chrono_stamp() -> String {
    // Simple timestamp without chrono dependency
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Format as YYYYMMDD-HHMMSS (approximate, good enough for backup names)
    format!("{}", secs)
}

pub fn diff(b: &Backend, old: &str, new: &str) -> String {
    // Simple unified diff
    let mut out = String::new();
    out.push_str(&format!("--- {}\n", b.target));
    out.push_str("+++ (proposed)\n");
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    // Simple line-by-line diff
    let mut i = 0;
    let mut j = 0;
    while i < old_lines.len() || j < new_lines.len() {
        if i < old_lines.len() && j < new_lines.len() && old_lines[i] == new_lines[j] {
            out.push_str(&format!(" {}\n", old_lines[i]));
            i += 1;
            j += 1;
        } else if j < new_lines.len()
            && (i >= old_lines.len() || !old_lines[i..].contains(&new_lines[j]))
        {
            out.push_str(&format!("+{}\n", new_lines[j]));
            j += 1;
        } else if i < old_lines.len() {
            out.push_str(&format!("-{}\n", old_lines[i]));
            i += 1;
        } else {
            out.push_str(&format!("+{}\n", new_lines[j]));
            j += 1;
        }
    }
    out
}
