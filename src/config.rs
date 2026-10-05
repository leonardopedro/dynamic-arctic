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

/// What the command line asked for.
#[derive(Debug, Clone, PartialEq)]
pub enum Invocation {
    /// `arctic init` -- write a starter config. Needs no config file.
    Init,
    /// `arctic [--config FILE] [--key value ...]` -- run the authority.
    Serve {
        file: Option<std::path::PathBuf>,
        flags: Flags,
    },
}

impl Flags {
    /// Record a raw override, rejecting anything unparseable.
    ///
    /// The error names the flag, so an operator does not have to work out which
    /// of four numbers was wrong.
    fn set_raw(&mut self, key: &str, raw: &str) -> Result<(), String> {
        let bad = |what: &str| format!("--{key} expects {what}, got {raw:?}");
        match key {
            "bind-addr" | "bind_addr" => self.bind_addr = Some(raw.to_string()),
            "domain" => self.domain = Some(raw.to_string()),
            "threshold" => self.threshold = Some(raw.parse().map_err(|_| bad("an integer"))?),
            "total-nodes" | "total_nodes" => {
                self.total_nodes = Some(raw.parse().map_err(|_| bad("an integer"))?)
            }
            other => return Err(format!("unknown flag --{other}")),
        }
        Ok(())
    }
}

/// Parse the command line.
///
/// Hand-rolled rather than pulling in an argument parser: this is four options and
/// a subcommand, and the crate has no CLI dependency. More to the point it is a
/// pure function, so precedence is testable directly instead of by running the
/// binary.
///
/// Both `--flag value` and `--flag=value` are accepted, because an operator who
/// types one of them should not get an error from the other.
pub fn parse_args(args: &[String]) -> Result<Invocation, String> {
    let mut it = args.iter().skip(1).peekable();
    let mut file = None;
    let mut flags = Flags::default();

    while let Some(arg) = it.next() {
        if arg == "init" {
            return Ok(Invocation::Init);
        }
        let Some(rest) = arg.strip_prefix("--") else {
            return Err(format!("unexpected argument {arg:?}"));
        };
        let (key, inline) = match rest.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (rest, None),
        };
        if key == "config" {
            file = Some(match inline {
                Some(v) => std::path::PathBuf::from(v),
                None => std::path::PathBuf::from(
                    it.next()
                        .ok_or_else(|| "--config expects a file path".to_string())?,
                ),
            });
            continue;
        }
        if key == "help" || key == "h" {
            return Err(usage());
        }
        let value = match inline {
            Some(v) => v,
            None => it
                .next()
                .ok_or_else(|| format!("--{key} expects a value"))?
                .to_string(),
        };
        flags.set_raw(key, &value)?;
    }

    Ok(Invocation::Serve { file, flags })
}

/// Turn a parsed invocation into the effective configuration.
///
/// `Ok(None)` means "this was `init`", which needs no configuration.
///
/// This exists so the whole chain -- argv, file, environment, flags -- is one
/// testable function. Wiring it inside `main` instead meant every layer had its
/// own test and the line connecting them had none: I reverted the call in `main`
/// to pass `Flags::default()` again and the entire suite still passed. `main` is a
/// tokio entry point that calls `process::exit`, so it cannot be the thing under
/// test; this can.
pub fn resolve_invocation(
    inv: &Invocation,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<(Config, Provenance)>, String> {
    let Invocation::Serve { file, flags } = inv else {
        return Ok(None);
    };
    let file = load_file(file.as_deref())?;
    Ok(Some(Config::resolve(file.as_ref(), env, flags)))
}

/// Usage text. Returned as `Err` so a bare `--help` produces the text plus a
/// non-zero exit, which is what `main` does with it.
pub fn usage() -> String {
    "usage: arctic init\n       arctic [--config FILE] [--bind-addr ADDR] [--domain D]\n               [--threshold N] [--total-nodes N]".to_string()
}

/// Read a config file, treating "no path given" as "no file layer".
pub fn load_file(path: Option<&std::path::Path>) -> Result<Option<Value>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|e| format!("config {} is not valid JSON: {e}", path.display()))
}

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
                // Accept a JSON number or bool as well as a string. Reading only
                // `as_str()` meant a config written the obvious way --
                // `{"threshold": 2}` -- was silently ignored in favour of the
                // default, with no error and no provenance entry. A file layer
                // that quietly discards what you wrote is worse than no file
                // layer: it looks like it is working.
                if let Some(raw) = obj.get(*key).and_then(scalar_to_string) {
                    if apply(&mut out, key, &raw) {
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
/// Render a JSON scalar as the string `apply` expects.
///
/// Numbers and bools are accepted so a config file can be written naturally.
/// A float is rendered as its JSON form, so `2.0` reaches `apply` as `"2.0"`
/// and is rejected by the integer parse -- a fractional threshold is not a
/// valid value, and saying so beats rounding it to something plausible.
fn scalar_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

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

/// One line per key: `threshold=5 (flag)`. An operator staring at "why is the
/// threshold 5" should not have to guess which of four layers won.
impl std::fmt::Display for Provenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self
            .entries
            .iter()
            .map(|(k, l)| format!("{k} ({})", l.as_str()))
            .collect();
        write!(f, "{}", parts.join(", "))
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
