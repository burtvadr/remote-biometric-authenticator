//! Audit logging (`PROTOCOL.md` §15).
//!
//! The design rule is that a reader of the logs must not be able to reconstruct
//! a credential. So this module records *identifiers and outcomes* only, and it
//! deliberately has no API that could emit a secret: challenges, signatures,
//! pairing codes and MACs have no path to the writer.
//!
//! A companion invariant worth keeping: `challenge` values are single-use, so
//! logging them adds risk without adding value. `request_id` is enough to
//! correlate a decision with a device.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The outcome of one authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Denied,
    Error,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Denied => "denied",
            Outcome::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub kind: &'static str,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub username: Option<String>,
    pub purpose: Option<String>,
    pub service: Option<String>,
    pub operation: Option<String>,
    pub request_id: Option<String>,
    pub transport: Option<String>,
    pub local_uid: Option<u32>,
    pub result: Outcome,
    pub code: Option<String>,
    pub detail: Option<String>,
}

impl Event {
    pub fn new(kind: &'static str) -> Event {
        Event {
            kind,
            device_id: None,
            device_name: None,
            username: None,
            purpose: None,
            service: None,
            operation: None,
            request_id: None,
            transport: None,
            local_uid: None,
            result: Outcome::Error,
            code: None,
            detail: None,
        }
    }

    pub fn device_id(mut self, v: impl Into<String>) -> Event {
        self.device_id = Some(v.into());
        self
    }

    pub fn device_name(mut self, v: impl Into<String>) -> Event {
        self.device_name = Some(v.into());
        self
    }

    pub fn username(mut self, v: impl Into<String>) -> Event {
        self.username = Some(v.into());
        self
    }

    pub fn purpose(mut self, v: impl Into<String>) -> Event {
        self.purpose = Some(v.into());
        self
    }

    pub fn service(mut self, v: impl Into<String>) -> Event {
        self.service = Some(v.into());
        self
    }

    pub fn operation(mut self, v: impl Into<String>) -> Event {
        self.operation = Some(v.into());
        self
    }

    pub fn request_id(mut self, v: impl Into<String>) -> Event {
        self.request_id = Some(v.into());
        self
    }

    pub fn transport(mut self, v: impl Into<String>) -> Event {
        self.transport = Some(v.into());
        self
    }

    pub fn local_uid(mut self, v: u32) -> Event {
        self.local_uid = Some(v);
        self
    }

    pub fn detail(mut self, v: impl Into<String>) -> Event {
        self.detail = Some(v.into());
        self
    }

    pub fn denied(mut self, code: &str) -> Event {
        self.result = Outcome::Denied;
        self.code = Some(code.to_owned());
        self
    }

    pub fn success(mut self) -> Event {
        self.result = Outcome::Success;
        self
    }

    /// Renders one log line as a JSON object with fixed key order.
    ///
    /// `None` fields are omitted so a log line stays readable, but key order is
    /// fixed so that lines diff cleanly.
    pub fn to_line(&self, now: u64) -> String {
        let mut out = String::with_capacity(256);
        out.push_str("{\"ts\":");
        out.push_str(&now.to_string());
        out.push_str(",\"kind\":\"");
        out.push_str(self.kind);
        out.push('"');
        // `kind` has already been written, so this is no longer the first field.
        let mut first = false;
        let kv = |k: &str, v: &str, out: &mut String, first: &mut bool| {
            if v.is_empty() {
                return;
            }
            if *first {
                *first = false;
            } else {
                out.push(',');
            }
            out.push('"');
            out.push_str(k);
            out.push_str("\":\"");
            push_escaped(v, out);
            out.push('"');
        };
        kv(
            "device_id",
            self.device_id.as_deref().unwrap_or(""),
            &mut out,
            &mut first,
        );
        kv(
            "device_name",
            self.device_name.as_deref().unwrap_or(""),
            &mut out,
            &mut first,
        );
        kv(
            "user",
            self.username.as_deref().unwrap_or(""),
            &mut out,
            &mut first,
        );
        kv(
            "purpose",
            self.purpose.as_deref().unwrap_or(""),
            &mut out,
            &mut first,
        );
        kv(
            "service",
            self.service.as_deref().unwrap_or(""),
            &mut out,
            &mut first,
        );
        kv(
            "operation",
            self.operation.as_deref().unwrap_or(""),
            &mut out,
            &mut first,
        );
        kv(
            "request_id",
            self.request_id.as_deref().unwrap_or(""),
            &mut out,
            &mut first,
        );
        kv(
            "transport",
            self.transport.as_deref().unwrap_or(""),
            &mut out,
            &mut first,
        );
        if let Some(uid) = self.local_uid {
            if !first {
                out.push(',');
            }
            out.push_str("\"local_uid\":");
            out.push_str(&uid.to_string());
        }
        let _ = first;
        out.push_str(",\"result\":\"");
        out.push_str(self.result.as_str());
        out.push('"');
        if let Some(c) = &self.code {
            out.push_str(",\"code\":\"");
            push_escaped(c, &mut out);
            out.push('"');
        }
        if let Some(d) = &self.detail {
            out.push_str(",\"detail\":\"");
            push_escaped(d, &mut out);
            out.push('"');
        }
        out.push('}');
        out
    }
}

fn push_escaped(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

pub struct AuditLog {
    inner: Mutex<Option<std::fs::File>>,
    #[allow(dead_code)]
    path: PathBuf,
    echo: bool,
}

impl AuditLog {
    pub fn to_file(path: &Path) -> std::io::Result<AuditLog> {
        if let Some(parent) = path.parent() {
            crate::config::ensure_private_dir(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(AuditLog {
            inner: Mutex::new(Some(file)),
            path: path.to_path_buf(),
            echo: false,
        })
    }

    /// Discards everything. Used by tests.
    pub fn null() -> AuditLog {
        AuditLog {
            inner: Mutex::new(None),
            path: PathBuf::new(),
            echo: false,
        }
    }

    pub fn with_echo(mut self, on: bool) -> Self {
        self.echo = on;
        self
    }

    pub fn write(&self, event: &Event) {
        let line = event.to_line(rba_protocol::unix_now());
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(f) = guard.as_mut() {
                let _ = writeln!(f, "{line}");
                let _ = f.flush();
            }
        }
        if self.echo {
            eprintln!("{line}");
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("path", &self.path)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_contains_metadata_but_no_secrets() {
        let e = Event {
            kind: "auth",
            device_id: Some("aa".repeat(16)),
            device_name: Some("Pixel 9".into()),
            username: Some("alice".into()),
            purpose: Some("sudo".into()),
            service: Some("sudo".into()),
            operation: Some("authenticate".into()),
            request_id: Some("bb".repeat(16)),
            transport: Some("wifi".into()),
            local_uid: Some(1000),
            result: Outcome::Success,
            code: None,
            detail: None,
        };
        let line = e.to_line(1_700_000_000);
        assert!(line.contains("\"user\":\"alice\""));
        assert!(line.contains("\"purpose\":\"sudo\""));
        assert!(line.contains("\"result\":\"success\""));
        assert!(line.contains("\"local_uid\":1000"));
        // Field order is fixed.
        let k1 = line.find("\"user\"").unwrap();
        let k2 = line.find("\"purpose\"").unwrap();
        assert!(k1 < k2);
    }

    #[test]
    fn every_rendered_line_is_valid_json() {
        // A malformed log line is both unauditable and forgeable, so assert the
        // shape directly rather than by inspection.
        let full = Event {
            kind: "auth",
            device_id: Some("aa".into()),
            device_name: Some("Pixel 9".into()),
            username: Some("alice".into()),
            purpose: Some("sudo".into()),
            service: Some("sudo".into()),
            operation: Some("authenticate".into()),
            request_id: Some("bb".into()),
            transport: Some("wifi".into()),
            local_uid: Some(1000),
            result: Outcome::Success,
            code: None,
            detail: None,
        };
        let v: serde_json::Value =
            serde_json::from_str(&full.to_line(1_700_000_000)).expect("valid JSON");
        assert_eq!(v["kind"], "auth");
        assert_eq!(v["user"], "alice");
        assert_eq!(v["local_uid"], 1000);
        assert_eq!(v["result"], "success");

        // Also with only a kind, and with an error code and detail.
        let minimal = Event::new("startup").success();
        let v2: serde_json::Value = serde_json::from_str(&minimal.to_line(1)).expect("valid JSON");
        assert_eq!(v2["kind"], "startup");

        let denied = Event::new("auth")
            .denied("REPLAY")
            .detail("no such request");
        let v3: serde_json::Value = serde_json::from_str(&denied.to_line(1)).expect("valid JSON");
        assert_eq!(v3["code"], "REPLAY");
        assert_eq!(v3["result"], "denied");
    }

    #[test]
    fn strings_are_escaped_so_lines_cannot_be_forged() {
        let e = Event {
            device_name: Some("evil\",\"result\":\"success".into()),
            ..Event::new("auth")
        };
        let line = e.to_line(1);
        // The injected quote is escaped, so the real result field still governs.
        assert!(line.contains("evil\\\",\\\"result\\\":\\\"success"));
        let result_pos = line.rfind("\"result\"").unwrap();
        assert!(line[result_pos..].contains("\"error\""));
    }

    #[test]
    fn newlines_cannot_inject_extra_log_records() {
        let e = Event {
            kind: "auth",
            detail: Some("line1\nline2".into()),
            ..Event::new("auth")
        };
        let line = e.to_line(1);
        assert_eq!(line.matches('\n').count(), 0);
        assert!(line.contains("\\n"));
    }

    #[test]
    fn writes_append_one_record_per_event() {
        let path = std::env::temp_dir().join(format!("rba-audit-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let log = AuditLog::to_file(&path).unwrap();
        log.write(&Event::new("startup").success());
        log.write(&Event::new("auth").denied("REPLAY"));
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 2);
        assert!(body.contains("\"kind\":\"startup\""));
        assert!(body.contains("\"code\":\"REPLAY\""));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn null_logger_is_safe() {
        AuditLog::null().write(&Event::new("test"));
    }
}
