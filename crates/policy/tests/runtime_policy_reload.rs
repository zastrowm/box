//! `PolicyEngine::reload` installs a new authored policy on a live engine, in-process.
//!
//! This is the durable reload surface: a caller that already holds the engine (the box's
//! trusted half, or a harness that embeds it) calls `reload` directly. No signal, no socket,
//! no separate process. The test opens one engine, denies a write under policy A, reloads to
//! policy B, and shows the same request now permitted on the same engine — with no restart.

use std::path::{Path, PathBuf};

use policy::{
    ApprovedPath, Decision, FsOperation, GovernedBox, PathResolver, Policy, PolicyEngine,
    Principal, Request,
};

fn source(name: &str, text: &str) -> Policy {
    Policy {
        origin: PathBuf::from(name),
        text: text.to_string(),
    }
}

/// Mint the `ApprovedPath` a `Request::Fs` demands, in the virtual namespace (touches no disk).
fn approved(path: &str) -> ApprovedPath {
    PathResolver::over([PathBuf::from("/home")])
        .expect("the root is absolute")
        .approve_virtual(Path::new(path))
        .unwrap_or_else(|refusal| panic!("a fixture path must resolve: {refusal}"))
}

fn write_allowed(engine: &PolicyEngine, path: &ApprovedPath) -> bool {
    matches!(
        engine.decide(
            &GovernedBox::assigned("test-box"),
            &Principal::agent(),
            &Request::Fs {
                path,
                operation: FsOperation::WriteContent,
            },
        ),
        Decision::Allow { .. }
    )
}

/// A write denied under policy A is permitted after a reload to policy B, on one live engine.
#[test]
fn reload_installs_a_new_authored_policy_on_a_live_engine() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let operator = policy::Operator::unanchored();

    let policy_a = vec![source(
        "a.dw",
        r#"permit(principal, action == Box::Action::"fs:read", resource);"#,
    )];
    let policy_b = vec![source(
        "b.dw",
        r#"permit(principal, action == Box::Action::"fs:read", resource);
           permit(principal, action == Box::Action::"fs:write", resource);"#,
    )];

    let engine = PolicyEngine::open_staged(&operator, policy_a, &path).expect("policy A opens");
    let target = approved("/home/project/README.md");

    assert!(
        !write_allowed(&engine, &target),
        "policy A names no fs:write rule, so the write is denied"
    );

    engine
        .reload(&policy_b)
        .expect("policy B reloads onto the live engine");

    assert!(
        write_allowed(&engine, &target),
        "after the reload, policy B permits the write on the same engine, with no restart"
    );
}

/// A reload that does not validate is refused in full, and the previous policy stays live.
#[test]
fn a_reload_that_does_not_validate_leaves_the_previous_policy_in_force() {
    let history = tempfile::tempdir().expect("history directory");
    let path = history.path().join("dogwood.redb");
    let operator = policy::Operator::unanchored();

    let working = vec![source(
        "working.dw",
        r#"permit(principal, action == Box::Action::"fs:write", resource);"#,
    )];
    let engine = PolicyEngine::open_staged(&operator, working, &path).expect("the policy opens");
    let target = approved("/home/project/README.md");
    assert!(
        write_allowed(&engine, &target),
        "the working policy permits the write"
    );

    let broken = vec![source("broken.dw", "this is not a policy {{{")];
    engine
        .reload(&broken)
        .expect_err("a policy that does not parse is refused");

    assert!(
        write_allowed(&engine, &target),
        "the refused reload validated before taking the live lock, so the previous policy still serves"
    );
}
