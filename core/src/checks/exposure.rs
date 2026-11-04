//! What the agent's commands could read: saved logins, wallet extensions and
//! secret files. Existence checks only; none of these files is opened.

use std::fs;
use std::path::Path;

use crate::iocs;
use crate::model::Exposure;
use crate::util::{name_of, path_ci};

pub fn collect(profiles: &[impl AsRef<Path>]) -> Exposure {
    let mut e = Exposure::default();
    for p in profiles {
        let p = p.as_ref();
        for (browser, rel) in iocs::CHROMIUM {
            let Some(root) = path_ci(p, rel).filter(|r| r.is_dir()) else {
                continue;
            };
            // Opera keeps one profile in the folder itself.
            let mut dirs = vec![root.clone()];
            if let Ok(rd) = fs::read_dir(&root) {
                dirs.extend(rd.flatten().map(|d| d.path()).filter(|d| d.is_dir()));
            }
            for d in dirs {
                let profile = if d == root { name_of(&root) } else { name_of(&d) };
                if path_ci(&d, "Login Data").is_some() || path_ci(&d, "Login Data For Account").is_some() {
                    push(&mut e.logins, (browser.to_string(), profile.clone()));
                }
                if let Some(ext) = path_ci(&d, "Extensions") {
                    for (id, wallet) in iocs::WALLETS {
                        if ext.join(id).is_dir() {
                            push(&mut e.wallets, (wallet.to_string(), browser.to_string()));
                        }
                    }
                }
            }
        }
        if let Some(ff) = path_ci(p, iocs::FIREFOX) {
            if let Ok(rd) = fs::read_dir(ff) {
                for d in rd.flatten().map(|d| d.path()).filter(|d| d.is_dir()) {
                    if path_ci(&d, "logins.json").is_some() || path_ci(&d, "key4.db").is_some() {
                        push(&mut e.logins, ("Firefox".into(), name_of(&d)));
                    }
                }
            }
        }
        for (what, rel) in iocs::SECRETS {
            if let Some(f) = path_ci(p, rel) {
                push(&mut e.secrets, (what.to_string(), f.display().to_string()));
            }
        }
        if let Some(ssh) = path_ci(p, ".ssh") {
            if let Ok(rd) = fs::read_dir(ssh) {
                let mut keys: Vec<_> = rd
                    .flatten()
                    .map(|d| d.path())
                    .filter(|k| {
                        let n = name_of(k);
                        k.is_file() && n.starts_with("id_") && !n.ends_with(".pub")
                    })
                    .collect();
                keys.sort();
                for k in keys {
                    push(&mut e.secrets, ("SSH 개인 키".into(), k.display().to_string()));
                }
            }
        }
    }
    e
}

fn push(v: &mut Vec<(String, String)>, item: (String, String)) {
    if !v.contains(&item) {
        v.push(item);
    }
}
