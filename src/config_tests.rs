use std::collections::HashMap;

use super::*;
use serde_json::json;

/// Build an env lookup from a table, so no test touches the real environment.
fn env_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |k: &str| map.get(k).cloned()
}

fn no_env(_: &str) -> Option<String> {
    None
}

#[test]
fn defaults_match_the_parameters_the_server_actually_used() {
    // This binary always ran t=3, n=7 for native robustness. If a default here
    // drifts, configuration silently changes the security parameters on the
    // first environment variable anybody sets.
    let cfg = Config::defaults();
    assert_eq!(3, cfg.threshold);
    assert_eq!(7, cfg.total_nodes);
    assert_eq!("0.0.0.0:3000", cfg.bind_addr);
}

#[test]
fn precedence_is_defaults_then_file_then_env_then_flags() {
    let file = json!({
        "domain": "from-file",
        "threshold": "5",
        "total_nodes": "9",
    });
    let env = env_from(&[("ARCTIC_DOMAIN", "from-env")]);
    let flags = Flags {
        domain: Some("from-flag".into()),
        ..Flags::default()
    };

    let (cfg, prov) = Config::resolve(Some(&file), &env, &flags);

    // flag beats env beats file beats default, each on its own key
    assert_eq!("from-flag", cfg.domain);
    assert_eq!(5, cfg.threshold, "env did not set threshold, so file wins");
    assert_eq!(9, cfg.total_nodes);
    assert_eq!("0.0.0.0:3000", cfg.bind_addr, "untouched keys stay default");

    assert_eq!(Some(Layer::Flag), prov.layer_of("domain"));
    assert_eq!(Some(Layer::File), prov.layer_of("threshold"));
    assert_eq!(Some(Layer::Default), prov.layer_of("bind_addr"));
}

#[test]
fn each_layer_wins_only_when_the_one_above_is_absent() {
    let file = json!({ "threshold": "5" });
    let flags = Flags {
        threshold: Some(9),
        ..Flags::default()
    };

    let (cfg, _) = Config::resolve(Some(&file), &env_from(&[("ARCTIC_THRESHOLD", "7")]), &flags);
    assert_eq!(9, cfg.threshold, "the flag is the top layer");

    let (cfg, _) = Config::resolve(
        Some(&file),
        &env_from(&[("ARCTIC_THRESHOLD", "7")]),
        &Flags::default(),
    );
    assert_eq!(7, cfg.threshold, "with no flag, env beats file");

    let (cfg, _) = Config::resolve(Some(&file), &no_env, &Flags::default());
    assert_eq!(5, cfg.threshold, "with no env, file beats default");

    let (cfg, _) = Config::resolve(None, &no_env, &Flags::default());
    assert_eq!(3, cfg.threshold, "with nothing set, the default stands");
}

#[test]
fn an_unset_flag_does_not_shadow_anything() {
    // Flags::default() is all-None. If absent meant "zero" rather than "unset",
    // the top layer would erase every lower one.
    let file = json!({ "domain": "from-file" });
    let (cfg, _) = Config::resolve(Some(&file), &no_env, &Flags::default());
    assert_eq!("from-file", cfg.domain);
}

#[test]
fn a_malformed_value_falls_through_instead_of_aborting_startup() {
    // A typo in an env var should not take the authority down, and the value it
    // rejected must not be used.
    let (cfg, prov) = Config::resolve(
        None,
        &env_from(&[("ARCTIC_THRESHOLD", "not-a-number")]),
        &Flags::default(),
    );
    assert_eq!(3, cfg.threshold, "fell back to the default");
    assert_eq!(
        Some(Layer::Default),
        prov.layer_of("threshold"),
        "provenance must not credit a layer whose value was rejected"
    );
}

#[test]
fn a_zero_threshold_is_rejected_rather_than_silently_defaulting() {
    // Zero is parseable but meaningless, so it is refused rather than accepted
    // as a number and then rejected at signing time.
    let (cfg, prov) = Config::resolve(
        None,
        &env_from(&[("ARCTIC_THRESHOLD", "0")]),
        &Flags::default(),
    );
    assert_eq!(3, cfg.threshold, "zero is rejected, default stands");
    assert_eq!(Some(Layer::Default), prov.layer_of("threshold"));
}

#[test]
fn validation_catches_a_threshold_no_node_set_can_meet() {
    // Better at startup than looking like a network partition mid-ceremony.
    let bad = Config {
        threshold: 5,
        total_nodes: 3,
        ..Config::defaults()
    };
    assert!(bad.validate().is_err());
    let zero = Config {
        threshold: 0,
        ..Config::defaults()
    };
    assert!(zero.validate().is_err());
    assert!(Config::defaults().validate().is_ok());
}

#[test]
fn init_output_is_deterministic_for_the_same_answers() {
    let a = InitAnswers {
        domain: "d.example".into(),
        threshold: 3,
        total_nodes: 7,
    };
    let b = a.clone();
    assert_eq!(
        init_config(&a),
        init_config(&b),
        "same answers must produce the same bytes or the output is untestable"
    );
}

#[test]
fn init_output_documents_every_key_with_its_env_var_and_default() {
    // The most common support question about a config file is which knob is
    // which; the generated file should answer it without a manual.
    let text = init_config(&InitAnswers {
        domain: "d.example".into(),
        threshold: 3,
        total_nodes: 7,
    });
    for (key, env_name, default) in KEYS {
        assert!(
            text.contains(&format!("{key} = ")),
            "generated file omits {key}"
        );
        assert!(
            text.contains(&format!("env {env_name}, default {default}")),
            "generated file does not document {key}'s env var and default"
        );
    }
}

#[test]
fn init_answers_agree_with_the_resolver_defaults() {
    // The regression that motivated this: `init` wrote `threshold = "2"` while
    // the server ran 3, because the two derived their defaults separately.
    let base = Config::defaults();
    let text = init_config(&InitAnswers {
        domain: base.domain.clone(),
        threshold: base.threshold,
        total_nodes: base.total_nodes,
    });
    assert!(text.contains(&format!("threshold = \"{}\"", base.threshold)));
    assert!(text.contains(&format!("total_nodes = \"{}\"", base.total_nodes)));
}

#[test]
fn every_key_has_a_distinct_env_var() {
    // One table drives both spellings, so a duplicate would make precedence
    // ambiguous for that key.
    let mut names: Vec<&str> = KEYS.iter().map(|(_, e, _)| *e).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "duplicate ARCTIC_* variable in KEYS");
}

// ── C3: the command line actually reaches the resolver ──────────────────────
//
// `resolve` gained a file layer and a flag layer, and `main` passed `None` and
// `Flags::default()` to both. The API was tested; the binary used neither. These
// cover the wiring, because an untested precedence order is a claim in a README.

fn args(list: &[&str]) -> Vec<String> {
    std::iter::once("arctic".to_string())
        .chain(list.iter().map(|s| s.to_string()))
        .collect()
}

#[test]
fn no_arguments_means_serve_with_defaults() {
    match parse_args(&args(&[])).expect("bare invocation is valid") {
        Invocation::Serve { file, flags } => {
            assert!(file.is_none(), "no --config means no file layer");
            assert_eq!(flags, Flags::default());
        }
        other => panic!("expected Serve, got {other:?}"),
    }
}

#[test]
fn init_is_recognised_and_needs_no_file() {
    assert_eq!(parse_args(&args(&["init"])).unwrap(), Invocation::Init);
}

#[test]
fn flags_accept_both_spellings_and_reach_the_resolver() {
    for spelling in [vec!["--threshold", "5"], vec!["--threshold=5"]] {
        let inv = parse_args(&args(&spelling)).expect("valid");
        let Invocation::Serve { flags, .. } = inv else {
            panic!("expected Serve for {spelling:?}");
        };
        assert_eq!(flags.threshold, Some(5), "{spelling:?}");

        let (cfg, prov) = Config::resolve(None, &|_| None, &flags);
        assert_eq!(cfg.threshold, 5, "{spelling:?} must reach the resolver");
        assert_eq!(
            prov.layer_of("threshold"),
            Some(Layer::Flag),
            "{spelling:?}"
        );
    }
}

#[test]
fn a_flag_beats_the_environment_which_beats_the_file() {
    let dir = std::env::temp_dir().join(format!("arctic-prec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("c.json");
    std::fs::write(&file, br#"{"threshold": 2, "domain": "file.example"}"#).unwrap();

    let parsed = load_file(Some(&file)).expect("file parses");
    assert!(parsed.is_some(), "the file layer is actually read");

    let (cfg, prov) = Config::resolve(
        parsed.as_ref(),
        &env_from(&[("ARCTIC_THRESHOLD", "4")]),
        &Flags::default(),
    );
    assert_eq!(cfg.threshold, 4, "environment beats the file");
    assert_eq!(prov.layer_of("threshold"), Some(Layer::Env));

    let flags = Flags {
        threshold: Some(6),
        ..Flags::default()
    };
    let (cfg, prov) = Config::resolve(
        parsed.as_ref(),
        &env_from(&[("ARCTIC_THRESHOLD", "4")]),
        &flags,
    );
    assert_eq!(cfg.threshold, 6, "a flag beats the environment");
    assert_eq!(prov.layer_of("threshold"), Some(Layer::Flag));

    // And the file still supplies what nothing overrode.
    assert_eq!(
        cfg.domain, "file.example",
        "unoverridden keys still come from the file"
    );
    assert_eq!(prov.layer_of("domain"), Some(Layer::File));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_or_malformed_config_file_is_reported_not_ignored() {
    let dir = std::env::temp_dir().join(format!("arctic-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let missing = dir.join("nope.json");
    assert!(
        load_file(Some(&missing)).is_err(),
        "a --config path that does not exist must not silently become 'no file'"
    );

    let bad = dir.join("bad.json");
    std::fs::write(&bad, b"{not json").unwrap();
    assert!(
        load_file(Some(&bad)).is_err(),
        "malformed JSON must be reported"
    );

    // No path at all is the one case that is genuinely "no file layer".
    assert!(load_file(None).unwrap().is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_bad_flag_value_names_the_flag() {
    let err = parse_args(&args(&["--threshold", "many"])).unwrap_err();
    assert!(
        err.contains("--threshold"),
        "error should name the flag: {err}"
    );
    assert!(parse_args(&args(&["--nonsense", "1"])).is_err());
    assert!(parse_args(&args(&["stray"])).is_err());
    assert!(
        parse_args(&args(&["--config"])).is_err(),
        "a value is required"
    );
}

#[test]
fn the_whole_chain_argv_file_env_flags_is_one_testable_call() {
    // Added after a negative control showed that reverting `main` to ignore flags
    // broke no test at all: every layer was covered and the connection was not.
    let dir = std::env::temp_dir().join(format!("arctic-chain-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("c.json");
    std::fs::write(&file, br#"{"threshold": 2, "total_nodes": 9}"#).unwrap();

    let inv = parse_args(&args(&[
        "--config",
        file.to_str().unwrap(),
        "--threshold",
        "5",
    ]))
    .expect("argv parses");

    let env = env_from(&[("ARCTIC_THRESHOLD", "4"), ("ARCTIC_DOMAIN", "env.example")]);
    let (cfg, prov) = resolve_invocation(&inv, &env)
        .expect("chain resolves")
        .expect("Serve resolves to a configuration");

    assert_eq!(cfg.threshold, 5, "the flag from argv wins");
    assert_eq!(cfg.total_nodes, 9, "the file supplies what argv omitted");
    assert_eq!(cfg.domain, "env.example", "the environment still applies");
    assert_eq!(prov.layer_of("threshold"), Some(Layer::Flag));
    assert_eq!(prov.layer_of("total_nodes"), Some(Layer::File));
    assert_eq!(prov.layer_of("domain"), Some(Layer::Env));

    // And `init` short-circuits rather than demanding a file.
    assert_eq!(
        resolve_invocation(&Invocation::Init, &|_| None).unwrap(),
        None,
        "init resolves to no configuration"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_config_file_may_write_numbers_as_numbers() {
    // Found by the chain test above, which asserted `total_nodes` came from a file
    // containing `"total_nodes": 9` and got the default 7. The file layer read only
    // `Value::as_str()`, so a JSON number was silently discarded: no error, no
    // provenance entry, just a config file that looks like it is working.
    let dir = std::env::temp_dir().join(format!("arctic-num-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("c.json");
    std::fs::write(&file, br#"{"threshold": 2, "total_nodes": 9}"#).unwrap();

    let parsed = load_file(Some(&file)).unwrap();
    let (cfg, prov) = Config::resolve(parsed.as_ref(), &|_| None, &Flags::default());

    assert_eq!(cfg.threshold, 2, "a numeric threshold must be honoured");
    assert_eq!(cfg.total_nodes, 9, "a numeric node count must be honoured");
    assert_eq!(prov.layer_of("threshold"), Some(Layer::File));
    assert_eq!(prov.layer_of("total_nodes"), Some(Layer::File));

    // Strings still work, so nothing regressed for the existing spelling.
    let sfile = dir.join("s.json");
    std::fs::write(&sfile, br#"{"threshold": "4"}"#).unwrap();
    let sp = load_file(Some(&sfile)).unwrap();
    let (cfg, _) = Config::resolve(sp.as_ref(), &|_| None, &Flags::default());
    assert_eq!(cfg.threshold, 4, "the string spelling must keep working");

    // A fractional value is rejected rather than rounded into something plausible.
    let ffile = dir.join("f.json");
    std::fs::write(&ffile, br#"{"threshold": 2.5}"#).unwrap();
    let fp = load_file(Some(&ffile)).unwrap();
    let (cfg, prov) = Config::resolve(fp.as_ref(), &|_| None, &Flags::default());
    assert_ne!(cfg.threshold, 2, "2.5 must not become 2");
    assert_ne!(
        prov.layer_of("threshold"),
        Some(Layer::File),
        "and must not be recorded as applied"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
