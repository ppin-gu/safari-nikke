//! The checks. Every check only opens files and registry keys for reading.

pub mod exposure;
pub mod hosts;
pub mod install;
pub mod launcher_data;
pub mod profile;
pub mod system;

use crate::model::{Event, Finding, Kind, Severity};
use crate::util::{cut, MAX_EVIDENCE};

#[derive(Default)]
pub struct Collector {
    pub findings: Vec<Finding>,
    pub timeline: Vec<Event>,
    pub last_activity: Option<u64>,
    pub notes: Vec<String>,
}

impl Collector {
    pub fn add(&mut self, severity: Severity, kind: Kind, title: &str, location: impl Into<String>, evidence: Vec<String>) {
        let location = location.into();
        // One finding per kind and location; extra evidence is merged into it.
        // `C:\a/b` and `C:\a\b` are the same place on Windows.
        let same = |a: &str| a.to_lowercase().replace('\\', "/") == location.to_lowercase().replace('\\', "/");
        if let Some(f) = self.findings.iter_mut().find(|f| f.kind == kind && same(&f.location)) {
            for e in evidence {
                if f.evidence.len() < MAX_EVIDENCE && !f.evidence.contains(&e) {
                    f.evidence.push(e);
                }
            }
            if severity > f.severity {
                f.severity = severity;
            }
            return;
        }
        let evidence = evidence.into_iter().map(|e| cut(&e)).take(MAX_EVIDENCE).collect();
        self.findings.push(Finding {
            severity,
            kind,
            title: title.to_string(),
            location,
            evidence,
        });
    }

    pub fn event(&mut self, time: String, what: impl Into<String>) {
        let what = what.into();
        if !self.timeline.iter().any(|e| e.time == time && e.what == what) {
            self.timeline.push(Event { time, what });
        }
    }

    pub fn activity(&mut self, t: Option<u64>) {
        if let Some(t) = t {
            self.last_activity = Some(self.last_activity.map_or(t, |c| c.max(t)));
        }
    }
}
