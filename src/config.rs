//! C3 — configuration: one vocabulary, one precedence.
//!
//! Precedence, lowest to highest:
//!
//!     defaults  <  config file  <  environment  <  flags
//!
//! The rule that shapes this module: **no function here reads the process
//! environment or the filesystem directly.** `resolve` takes the environment as
//! a lookup closure and the file as a parsed value, so the precedence order is
//! a property of a pure function that a test can drive by passing three values
//! instead of one. Mutating the real environment in a test is how suites become
//! order-dependent, and it is exactly what `australVM`'s Why3 gate avoids by
//! making `check_with_grants` pure.
//!
//! `init_config` is the onboarding half: given a set of answers it writes a
//! commented starter file. Deterministic by construction -- same answers, same
//! bytes -- so it can be asserted on rather than eyeballed.

use serde_json::{json, Value};

/// Keys as they appear in the config file and as `ARCTIC_*` environment
/// variables. One table, so the two spellings cannot drift apart.
pub const KEYS: &[(&str, &str, &str)] = &[
    // (key, env var, default)
    ("bind_addr", "ARCTIC_BIND_ADDR", "0.0.0.0:3000"),
    ("domain", "ARCTIC_DOMAIN", "authority.yourdomain.com"),
    ("threshold", "ARCTIC_THRESHOLD", "3"),
    ("total_nodes", "ARCTIC_TOTAL_NODES", "7"),
];

/// The effective configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub bind_addr: String,
    pub domain: String,
    pub threshold: u32,
    pub total_nodes: u32,
}

/// Command-line overrides. Absent means "not supplied", which is what keeps
/// flags above env: an unset flag must not shadow anything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    pub bind_addr: Option<String>,
    pub domain: Option<String>,
    pub threshold: Option<u32>,
    pub total_nodes: Option<u32>,
}

/// What each layer contributed, so an operator can see *why* a value is what it
/// is instead of guessing at a precedence order they have to trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Default,
    File,
    Env,
    Flag,
}

impl Layer {
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Default => "default",
            Layer::File => "file",
            Layer::Env => "env",
            Layer::Flag => "flag",
        }
    }
}

impl Config {
    /// The defaults alone, before any layer is consulted.
    pub fn defaults() -> Config {
        Config {
            bind_addr: "0.0.0.0:3000".to_string(),
            domain: "authority.yourdomain.com".to_string(),
            threshold: 3,
            total_nodes: 7,
        }
    }

    /// Resolve the four layers.
    ///
    /// `file` is a pre-parsed object (the caller read it), `env` a lookup
    /// closure. A malformed or out-of-range value is **ignored in favour of the
    /// layer below** rather than aborting startup: a typo in an env var should
    /// not take the authority down, and the provenance map records that the value
    /// was rejected so it is visible rather than silent.
    pub fn resolve(
        file: Option<&Value>,
        env: &dyn Fn(&str) -> Option<String>,
        flags: &Flags,
    ) -> (Config, Provenance) {
        let mut out = Config::defaults();
        let mut prov = Provenance::default();

        if let Some(obj) = file {
            for (key, _, _) in KEYS {
                if let Some(raw) = obj.get(*key).and_then(Value::as_str) {
                    if apply(&mut out, key, raw) {
                        prov.set(key, Layer::File);
                    }
                }
            }
        }
        for (key, env_name, _) in KEYS {
            if let Some(raw) = env(env_name) {
                if apply(&mut out, key, &raw) {
                    prov.set(key, Layer::Env);
                }
            }
        }
        if let Some(v) = &flags.bind_addr {
            out.bind_addr = v.clone();
            prov.set("bind_addr", Layer::Flag);
        }
        if let Some(v) = &flags.domain {
            out.domain = v.clone();
            prov.set("domain", Layer::Flag);
        }
        if let Some(v) = flags.threshold {
            out.threshold = v;
            prov.set("threshold", Layer::Flag);
        }
        if let Some(v) = flags.total_nodes {
            out.total_nodes = v;
            prov.set("total_nodes", Layer::Flag);
        }
        (out, prov)
    }

    /// A threshold above the node count can never be met, so it is refused at
    /// resolution rather than at signing time when it looks like a network
    /// partition.
    pub fn validate(&self) -> Result<(), String> {
        if self.threshold == 0 {
            return Err("threshold must be at least 1".to_string());
        }
        if self.threshold > self.total_nodes {
            return Err(format!(
                "threshold {} exceeds total_nodes {}; the ceremony could never complete",
                self.threshold, self.total_nodes
            ));
        }
        Ok(())
    }
}

/// Apply one raw string to the config. Returns false if it was rejected.
fn apply(cfg: &mut Config, key: &str, raw: &str) -> bool {
    match key {
        "bind_addr" => {
            cfg.bind_addr = raw.to_string();
            true
        }
        "domain" => {
            cfg.domain = raw.to_string();
            true
        }
        "threshold" => match raw.parse::<u32>() {
            Ok(v) if v > 0 => {
                cfg.threshold = v;
                true
            }
            _ => false,
        },
        "total_nodes" => match raw.parse::<u32>() {
            Ok(v) if v > 0 => {
                cfg.total_nodes = v;
                true
            }
            _ => false,
        },
        _ => false,
    }
}

/// Which layer supplied each key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provenance {
    entries: [(&'static str, Layer); 4],
}

impl Provenance {
    fn set(&mut self, key: &'static str, layer: Layer) {
        for slot in self.entries.iter_mut() {
            if slot.0 == key {
                *slot = (key, layer);
                return;
            }
        }
    }

    #[cfg(test)]
    pub fn layer_of(&self, key: &str) -> Option<Layer> {
        self.entries
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, l)| *l)
    }

    pub fn to_json(self) -> Value {
        let mut map = serde_json::Map::new();
        for (k, l) in self.entries {
            map.insert(k.to_string(), json!(l.as_str()));
        }
        Value::Object(map)
    }
}

impl Default for Provenance {
    fn default() -> Provenance {
        Provenance {
            entries: [
                ("bind_addr", Layer::Default),
                ("domain", Layer::Default),
                ("threshold", Layer::Default),
                ("total_nodes", Layer::Default),
            ],
        }
    }
}

/// The answers `init` asks for. Same answers in, same bytes out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitAnswers {
    pub domain: String,
    pub threshold: u32,
    pub total_nodes: u32,
}

/// Render the starter config file.
///
/// Every key is written with the comment naming its environment variable and
/// default, because the most common support question about a config file is
/// which knob is which.
pub fn init_config(answers: &InitAnswers) -> String {
    let mut out = String::new();
    out.push_str("# arctic-authority configuration\n");
    out.push_str("#\n");
    out.push_str("# Precedence: defaults < this file < environment < flags.\n");
    out.push_str("# Every key below is also an ARCTIC_* environment variable, and\n");
    out.push_str("# every one of them has a default shown here. Values are read once\n");
    out.push_str("# at startup; there is no hot reload.\n");
    out.push_str("#\n");
    out.push_str("# Generated by `arctic init`. Edit freely; nothing here is\n");
    out.push_str("# regenerated behind your back.\n\n");
    for (key, env_name, default) in KEYS {
        let value = match *key {
            "domain" => answers.domain.clone(),
            "threshold" => answers.threshold.to_string(),
            "total_nodes" => answers.total_nodes.to_string(),
            "bind_addr" => (*default).to_string(),
            _ => (*default).to_string(),
        };
        out.push_str(&format!("# {key} — env {env_name}, default {default}\n"));
        out.push_str(&format!("{key} = \"{value}\"\n\n"));
    }
    out
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
