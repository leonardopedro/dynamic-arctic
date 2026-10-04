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
