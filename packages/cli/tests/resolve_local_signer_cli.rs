//! Local `treeship resolve` attributes the card and its actions by the keys
//! whose signatures verified, never by the keyid a signature names. A card
//! signed by another pinned party with a garbage first signature naming the
//! victim's key used to resolve as "verified".

use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

struct Ship {
    home: tempfile::TempDir,
}

impl Ship {
    fn init(name: &str) -> Self {
        let ship = Self {
            home: tempfile::tempdir().unwrap(),
        };
        let out = ship.run(&["init", "--name", name]);
        assert!(out.status.success(), "{}", text(&out));
        ship
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(cli_path())
            .current_dir(self.home.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .arg("--config")
            .arg(self.home.path().join(".treeship/config.json"))
            .output()
            .expect("run treeship")
    }
    fn json(&self, args: &[&str]) -> serde_json::Value {
        let out = self.run(&[args, &["--format", "json"]].concat());
        assert!(out.status.success(), "{}", text(&out));
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&out)))
    }
    fn artifacts(&self) -> std::path::PathBuf {
        self.home.path().join(".treeship/artifacts")
    }
    /// (key id, "ed25519:<b64url>") of the default key.
    fn default_key(&self) -> (String, String) {
        let k = self.json(&["keys", "export"]);
        (
            k["key_id"].as_str().unwrap().to_string(),
            k["public_key"].as_str().unwrap().to_string(),
        )
    }
}

/// Copy an artifact (file + index entry) from one store into another.
fn copy_artifact(from: &Ship, to: &Ship, id: &str, mutate: impl Fn(&mut serde_json::Value)) {
    let mut art: serde_json::Value = serde_json::from_slice(
        &std::fs::read(from.artifacts().join(format!("{id}.json"))).unwrap(),
    )
    .unwrap();
    mutate(&mut art);
    std::fs::write(
        to.artifacts().join(format!("{id}.json")),
        serde_json::to_vec_pretty(&art).unwrap(),
    )
    .unwrap();
    let src: serde_json::Value =
        serde_json::from_slice(&std::fs::read(from.artifacts().join("index.json")).unwrap())
            .unwrap();
    let entry = src["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == id)
        .cloned()
        .unwrap();
    std::fs::create_dir_all(to.artifacts()).unwrap();
    let mut dst: serde_json::Value = std::fs::read(to.artifacts().join("index.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({ "entries": [] }));
    dst["entries"].as_array_mut().unwrap().push(entry);
    std::fs::write(
        to.artifacts().join("index.json"),
        serde_json::to_vec_pretty(&dst).unwrap(),
    )
    .unwrap();
}

#[test]
fn a_forged_card_from_another_pinned_ship_does_not_resolve_as_the_victim() {
    let victim = Ship::init("victim");
    let attacker = Ship::init("attacker");
    let (victim_key, victim_pk) = victim.default_key();
    let (attacker_key, attacker_pk) = attacker.default_key();
    // The victim's own honest card, and both keys pinned under agent_cert
    // (a partner whose key you pin is exactly who this must hold against).
    let honest = victim.json(&[
        "attest",
        "card",
        "--agent",
        "agent://victim",
        "--tools",
        "git",
    ]);
    assert!(victim
        .run(&[
            "trust",
            "add",
            &victim_key,
            &victim_pk,
            "--kind",
            "agent_cert",
            "--agent",
            "agent://victim",
            "--yes"
        ])
        .status
        .success());
    assert!(victim
        .run(&[
            "trust",
            "add",
            &attacker_key,
            &attacker_pk,
            "--kind",
            "agent_cert",
            "--agent",
            "agent://attacker",
            "--yes"
        ])
        .status
        .success());
    let before = victim.json(&["resolve", "agent://victim"]);
    assert_eq!(before["current_card"], honest["id"], "{before}");

    // The attacker mints a card for the victim, signed by the attacker's
    // key, with a garbage first signature naming the victim's key.
    let forged = attacker.json(&[
        "attest",
        "card",
        "--agent",
        "agent://victim",
        "--tools",
        "db.drop",
        "--keyid",
        &victim_key,
    ]);
    let forged_id = forged["id"].as_str().unwrap().to_string();
    copy_artifact(&attacker, &victim, &forged_id, |art| {
        let sigs = art["envelope"]["signatures"].as_array_mut().unwrap();
        sigs.insert(
            0,
            serde_json::json!({ "keyid": victim_key, "sig": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc" }),
        );
    });

    // The honest card resolved key-bound. The forged one is newer, but the
    // current card is chosen among KEY-BOUND cards, so the agent's own card
    // stays current and the forged one is never the victim's.
    assert_eq!(
        before["capabilities"], "checked (0/0 captured actions in scope)",
        "{before}"
    );
    let after = victim.json(&["resolve", "agent://victim"]);
    assert_eq!(
        after["current_card"], honest["id"],
        "the forged card displaced the agent's own:\n{after}"
    );
    assert_eq!(
        after["capabilities"], "checked (0/0 captured actions in scope)",
        "{after}"
    );

    // With no honest card at all, the forged card is all there is: it
    // resolves asserted, never verified.
    let lone = Ship::init("lone");
    assert!(lone
        .run(&[
            "trust",
            "add",
            &victim_key,
            &victim_pk,
            "--kind",
            "agent_cert",
            "--agent",
            "agent://victim",
            "--yes"
        ])
        .status
        .success());
    assert!(lone
        .run(&[
            "trust",
            "add",
            &attacker_key,
            &attacker_pk,
            "--kind",
            "agent_cert",
            "--agent",
            "agent://attacker",
            "--yes"
        ])
        .status
        .success());
    let vk = victim_key.clone();
    copy_artifact(&attacker, &lone, &forged_id, move |art| {
        *art = forge_first_sig(art.clone(), &vk);
    });
    let out = lone.run(&["resolve", "agent://victim", "--format", "json"]);
    let all = text(&out);
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {all}"));
    assert_eq!(doc["current_card"], forged_id, "{doc}");
    assert_eq!(
        doc["capabilities"], "asserted (card not key-bound)",
        "a forged first signature made the attacker's card the victim's:\n{doc}"
    );
    assert!(!all.contains("resolved (verified)"), "{all}");
}

use std::io::{Read, Write};

/// Serve one JSON body for every request.
fn serve_json(body: String) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        }
    });
    format!("http://{addr}")
}

fn read_artifact(ship: &Ship, id: &str) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(ship.artifacts().join(format!("{id}.json"))).unwrap())
        .unwrap()
}

fn forge_first_sig(mut art: serde_json::Value, claimed: &str) -> serde_json::Value {
    let sigs = art["envelope"]["signatures"].as_array_mut().unwrap();
    sigs.insert(0, serde_json::json!({ "keyid": claimed, "sig": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc" }));
    art
}

/// Honest card, the victim's own revocation of it, and an attacker card for
/// the victim that a trusted key verifies: the revocation must be seen
/// whether the forged card is newer or older.
struct Scene {
    victim: Ship,
    attacker: Ship,
    honest_id: String,
    forged_id: String,
    victim_key: String,
}

fn scene(forged_newer: bool) -> Scene {
    let victim = Ship::init("victim");
    let attacker = Ship::init("attacker");
    let (victim_key, victim_pk) = victim.default_key();
    let (attacker_key, attacker_pk) = attacker.default_key();
    assert!(victim
        .run(&[
            "trust",
            "add",
            &victim_key,
            &victim_pk,
            "--kind",
            "agent_cert",
            "--agent",
            "agent://victim",
            "--yes"
        ])
        .status
        .success());
    assert!(victim
        .run(&[
            "trust",
            "add",
            &attacker_key,
            &attacker_pk,
            "--kind",
            "agent_cert",
            "--agent",
            "agent://attacker",
            "--yes"
        ])
        .status
        .success());
    let mint_forged = || {
        attacker.json(&[
            "attest",
            "card",
            "--agent",
            "agent://victim",
            "--tools",
            "db.drop",
            "--keyid",
            &victim_key,
        ])["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let forged_id_older = if forged_newer {
        None
    } else {
        Some(mint_forged())
    };
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let honest_id = victim.json(&[
        "attest",
        "card",
        "--agent",
        "agent://victim",
        "--tools",
        "git",
    ])["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(victim
        .run(&["revoke-capability", &honest_id, "--reason", "rotated"])
        .status
        .success());
    let forged_id = match forged_id_older {
        Some(id) => id,
        None => {
            std::thread::sleep(std::time::Duration::from_millis(1100));
            mint_forged()
        }
    };
    let vk = victim_key.clone();
    copy_artifact(&attacker, &victim, &forged_id, move |art| {
        *art = forge_first_sig(art.clone(), &vk);
    });
    Scene {
        victim,
        attacker,
        honest_id,
        forged_id,
        victim_key,
    }
}

fn assert_revoked_locally(s: &Scene) {
    let out = s
        .victim
        .run(&["resolve", "agent://victim", "--format", "json"]);
    let all = text(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a revoked agent must exit 1:\n{all}"
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {all}"));
    assert_eq!(
        doc["current_card"], s.honest_id,
        "the forged card {} displaced the agent's own:\n{doc}",
        s.forged_id
    );
    assert_eq!(doc["ok"], false, "{doc}");
    assert!(doc["revocation"]["reason"] == "rotated", "{doc}");
    let out = s.victim.run(&["resolve", "agent://victim"]);
    assert!(text(&out).contains("REVOKED"), "{}", text(&out));
}

#[test]
fn a_newer_forged_card_does_not_hide_the_agents_own_revocation() {
    let s = scene(true);
    assert_revoked_locally(&s);
}

#[test]
fn an_older_forged_card_does_not_hide_the_agents_own_revocation() {
    let s = scene(false);
    assert_revoked_locally(&s);
}

/// The hub serves the same three; its `current_card` hint is the forged
/// newer card. The client picks the agent's key-bound card and sees the
/// revocation.
#[test]
fn a_hub_bundle_with_a_forged_newer_card_still_reports_revoked() {
    let s = scene(true);
    let honest = read_artifact(&s.victim, &s.honest_id);
    let forged = read_artifact(&s.victim, &s.forged_id); // already forged in the victim's store
    let revocation_id = {
        let idx: serde_json::Value = serde_json::from_slice(
            &std::fs::read(s.victim.artifacts().join("index.json")).unwrap(),
        )
        .unwrap();
        idx["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["payload_type"].as_str().unwrap_or("").contains("receipt"))
            .map(|e| e["id"].as_str().unwrap().to_string())
            .find(|id| {
                let a = read_artifact(&s.victim, id);
                let payload = a["envelope"]["payload"].as_str().unwrap();
                let bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    payload,
                )
                .unwrap();
                String::from_utf8_lossy(&bytes).contains("agent_card_revocation.v1")
            })
            .expect("the victim's revocation is in the store")
    };
    let revocation = read_artifact(&s.victim, &revocation_id);
    let entry = |a: &serde_json::Value, signed_at: i64| {
        serde_json::json!({
            "artifact_id": a["artifact_id"],
            "envelope_json": serde_json::to_string(&a["envelope"]).unwrap(),
            "signer": a["key_id"],
            "signed_at": signed_at,
        })
    };
    let bundle = serde_json::json!({
        "agent": "agent://victim",
        "current_card": entry(&forged, 3000),
        "cards": [entry(&forged, 3000), entry(&honest, 1000)],
        "certs": [],
        "revocations": [entry(&revocation, 2000)],
        "transparency": null,
    });
    let hub = serve_json(bundle.to_string());
    let out = s.victim.run(&[
        "resolve",
        "agent://victim",
        "--hub",
        &hub,
        "--format",
        "json",
    ]);
    let all = text(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a revoked agent must exit 1:\n{all}"
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {all}"));
    assert_eq!(
        doc["current_card"], s.honest_id,
        "the hub's hint was trusted over the agent's own card:\n{doc}"
    );
    assert!(all.to_lowercase().contains("revoked"), "{all}");
    let _ = &s.attacker;
    let _ = &s.victim_key;
}

/// No forgery at all: the attacker's own pinned key signs a card claiming the
/// victim's name. Pinned as agent://attacker, it binds no card for
/// agent://victim, and resolve says which pin it found.
#[test]
fn a_pinned_key_signing_another_agents_card_resolves_asserted_with_the_reason() {
    let victim = Ship::init("victim");
    let attacker = Ship::init("attacker");
    let (attacker_key, attacker_pk) = attacker.default_key();
    assert!(victim
        .run(&[
            "trust",
            "add",
            &attacker_key,
            &attacker_pk,
            "--kind",
            "agent_cert",
            "--agent",
            "agent://attacker",
            "--yes"
        ])
        .status
        .success());
    let claim = attacker.json(&[
        "attest",
        "card",
        "--agent",
        "agent://victim",
        "--tools",
        "db.drop",
    ]);
    let claim_id = claim["id"].as_str().unwrap().to_string();
    copy_artifact(&attacker, &victim, &claim_id, |_| {});
    let out = victim.run(&["resolve", "agent://victim"]);
    let all = text(&out);
    assert!(all.contains("resolved (asserted)"), "{all}");
    assert!(!all.contains("resolved (verified)"), "{all}");
    assert!(
        all.contains("pinned under agent_cert as agent://attacker, not as agent://victim"),
        "{all}"
    );
}

/// A pin from before --agent, with a label that is not an agent name, binds
/// nothing and names the re-pin that would.
#[test]
fn a_legacy_unscoped_pin_does_not_bind_and_says_how_to_fix_it() {
    let victim = Ship::init("victim");
    let (victim_key, victim_pk) = victim.default_key();
    assert!(victim
        .run(&[
            "trust",
            "add",
            &victim_key,
            &victim_pk,
            "--kind",
            "agent_cert",
            "--label",
            "the counterparty",
            "--yes"
        ])
        .status
        .success());
    let card = victim.json(&[
        "attest",
        "card",
        "--agent",
        "agent://victim",
        "--tools",
        "git",
    ]);
    assert_eq!(card["key-bound"], "no (asserted)", "{card}");
    let out = victim.run(&["verify-capability", card["id"].as_str().unwrap()]);
    let all = text(&out);
    assert!(
        all.contains("self-asserted") && all.contains("--agent agent://victim --replace"),
        "{all}"
    );
    // Re-pinned with the scope, the same card is key-bound.
    assert!(victim
        .run(&[
            "trust",
            "add",
            &victim_key,
            &victim_pk,
            "--kind",
            "agent_cert",
            "--agent",
            "agent://victim",
            "--replace",
            "--yes"
        ])
        .status
        .success());
    let out = victim.run(&["verify-capability", card["id"].as_str().unwrap()]);
    assert!(
        text(&out).contains("key-bound:         yes"),
        "{}",
        text(&out)
    );
}

/// `treeship verify` actor proof through a self-signed certificate: a key
/// pinned as agent://attacker certifying itself as agent://victim proves
/// nothing about agent://victim.
#[test]
fn a_self_signed_certificate_from_a_key_pinned_as_another_agent_proves_nothing() {
    let victim = Ship::init("victim");
    let attacker = Ship::init("attacker");
    let (attacker_key, attacker_pk) = attacker.default_key();
    assert!(victim
        .run(&[
            "trust",
            "add",
            &attacker_key,
            &attacker_pk,
            "--kind",
            "agent_cert",
            "--agent",
            "agent://attacker",
            "--yes"
        ])
        .status
        .success());
    let cert_payload = format!(
        r#"{{"agent":"agent://victim","subject_key_id":"{attacker_key}","subject_public_key":"{}","issuer":"ship://attacker","issued_at":"2026-01-01T00:00:00Z","valid_until":"2030-01-01T00:00:00Z"}}"#,
        attacker_pk.trim_start_matches("ed25519:")
    );
    let cert = attacker.json(&[
        "attest",
        "receipt",
        "--system",
        "ship://attacker",
        "--kind",
        "agent_cert.v1",
        "--payload",
        &cert_payload,
    ]);
    let action = attacker.json(&[
        "attest",
        "action",
        "--actor",
        "agent://victim",
        "--action",
        "deploy",
    ]);
    let cert_id = cert["id"].as_str().unwrap().to_string();
    let action_id = action["id"].as_str().unwrap().to_string();
    copy_artifact(&attacker, &victim, &cert_id, |_| {});
    copy_artifact(&attacker, &victim, &action_id, |_| {});
    let out = victim.run(&["verify", &action_id]);
    let all = text(&out);
    assert!(
        !all.contains("proven (key-bound)"),
        "a self-signed cert from a key pinned as another agent proved the actor:\n{all}"
    );
    assert!(all.contains("asserted"), "{all}");

    // Pinned as agent://victim instead, the same certificate does prove it.
    assert!(victim
        .run(&[
            "trust",
            "add",
            &attacker_key,
            &attacker_pk,
            "--kind",
            "agent_cert",
            "--agent",
            "agent://victim",
            "--replace",
            "--yes"
        ])
        .status
        .success());
    let out = victim.run(&["verify", &action_id]);
    assert!(text(&out).contains("proven (key-bound)"), "{}", text(&out));
}
