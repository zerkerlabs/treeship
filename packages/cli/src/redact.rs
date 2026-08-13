//! Redaction for anything that reaches a signed receipt.
//!
//! # Why this is not just a bigger denylist
//!
//! The previous implementation split a command on whitespace and checked each
//! token for a substring like `TOKEN=` or `--password=`. Every pattern ended
//! in `=`, so the single most common way to pass a secret on a command line
//! survived untouched:
//!
//! ```text
//! curl --token secret123      -> ["curl", "--token", "secret123"]
//! ```
//!
//! Neither token matches, because `--token` is not `--token=` and `secret123`
//! looks like any other word. Same for `-H "Authorization: Bearer sk_live_.."`,
//! `curl -u user:password`, and `https://host/x?signature=SECRET`.
//!
//! So this module does two different jobs, and it is important not to confuse
//! them:
//!
//! * [`redact_command`] understands argv *structure* -- it knows that the token
//!   after `--token` is a value, that `-H` takes a header, that a URL can carry
//!   userinfo and query credentials. Structure is what makes it able to redact
//!   a secret it has never seen and cannot recognise.
//!
//! * [`redact_text`] gets arbitrary program output, where there is no structure
//!   to lean on. It can only match shapes it already knows -- known credential
//!   prefixes and `key: value` pairs. **It will miss novel secrets**, and that
//!   is not a bug that can be fixed by adding patterns.
//!
//! Which is why the real defence is structural and lives at the call sites:
//! program output is recorded as a digest, and the raw text is opt-in. A
//! denylist decides what to hide and is wrong by default; a digest decides what
//! to reveal and is safe by default. Treat everything here as defence in depth
//! behind that choice, never as the thing keeping credentials out of receipts.

/// Flags whose *following* argument is a credential.
///
/// Matched case-insensitively, and also in `--flag=value` form.
const VALUE_FLAGS: &[&str] = &[
    "--token",
    "--api-key",
    "--api_key",
    "--apikey",
    "--secret",
    "--password",
    "--passwd",
    "--pass",
    "--auth",
    "--authorization",
    "--credential",
    "--credentials",
    "--private-key",
    "--access-key",
    "--secret-key",
    "--session-token",
    "--bearer",
    "--key",
    "-p",
    "-u",
    "--user",
    "--header",
    "-H",
    "--data-urlencode",
];

/// Environment-variable name fragments that mark an inline `NAME=value`
/// assignment as sensitive.
const SENSITIVE_ENV_FRAGMENTS: &[&str] = &[
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "AUTH",
    "CREDENTIAL",
    "SESSION",
    "COOKIE",
    "SIGNATURE",
    "PASSPHRASE",
];

/// Query-string parameter names that carry credentials in signed URLs.
const SENSITIVE_QUERY_KEYS: &[&str] = &[
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "key",
    "api_key",
    "apikey",
    "secret",
    "password",
    "passwd",
    "auth",
    "signature",
    "sig",
    "x-amz-signature",
    "sas",
    "code",
];

/// Literal prefixes that identify a credential wherever it appears, including
/// in unstructured output. Deliberately narrow: every entry here is a shape a
/// vendor documents as always-secret.
const CREDENTIAL_PREFIXES: &[&str] = &[
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "pk_live_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxs-",
    "AKIA",
    "ASIA",
    "AIza",
    "ya29.",
    "sk-ant-",
    "sk-proj-",
    "hf_",
    "npm_",
    "dop_v1_",
    "shpat_",
    "SG.",
    "-----BEGIN",
];

/// Header names whose value is a credential.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-amz-security-token",
    "x-goog-api-key",
    "api-key",
];

pub const REDACTED: &str = "[REDACTED]";

fn strip_leading_dashes(s: &str) -> &str {
    s.trim_start_matches('-')
}

/// Does this token name a flag whose next argument is a credential?
fn is_value_flag(token: &str) -> bool {
    // Must actually look like a flag. Comparing dash-stripped names on both
    // sides made bare words match: `gh auth login` treated `auth` as `--auth`
    // and redacted `login`, and `git config user.name` lost `.name` to
    // `--user`. Over-redaction destroys the evidence a receipt exists to
    // carry, so the leading dash is required.
    if !token.starts_with('-') {
        return false;
    }
    let bare = strip_leading_dashes(token);
    VALUE_FLAGS.iter().any(|f| {
        token.eq_ignore_ascii_case(f) || bare.eq_ignore_ascii_case(strip_leading_dashes(f))
    })
}

/// `NAME=value` where NAME looks sensitive, or `--flag=value` where the flag is
/// a credential flag. Returns the redacted form.
fn redact_assignment(token: &str) -> Option<String> {
    let (name, _) = token.split_once('=')?;
    // A URL's first `=` belongs to a query parameter, not an assignment.
    // Treating `https://h/f?signature=X&y=1` as `name=value` would match
    // "SIGNATURE" in the name and redact everything after the first `=`,
    // destroying the rest of the query. URLs are handled by `redact_url`.
    if name.contains("://") || name.contains('?') {
        return None;
    }
    if is_value_flag(name) {
        return Some(format!("{name}={REDACTED}"));
    }
    let upper = name.to_ascii_uppercase();
    if SENSITIVE_ENV_FRAGMENTS.iter().any(|f| upper.contains(f)) {
        return Some(format!("{name}={REDACTED}"));
    }
    None
}

/// Redact credentials carried inside a URL: `scheme://user:pass@host` userinfo,
/// and sensitive query parameters.
fn redact_url(token: &str) -> Option<String> {
    let scheme_end = token.find("://")?;
    let (scheme, rest) = token.split_at(scheme_end + 3);
    let mut out = String::from(scheme);

    // userinfo -- everything before the last '@' in the authority component.
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(authority_end);
    match authority.rsplit_once('@') {
        Some((userinfo, host)) => {
            // Keep the username, drop the password: `user:pass@` -> `user:[REDACTED]@`
            match userinfo.split_once(':') {
                Some((user, _)) => out.push_str(&format!("{user}:{REDACTED}@{host}")),
                None => out.push_str(&format!("{userinfo}@{host}")),
            }
        }
        None => out.push_str(authority),
    }

    // query parameters
    match tail.split_once('?') {
        Some((path, query)) => {
            out.push_str(path);
            out.push('?');
            let redacted: Vec<String> = query
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    Some((k, _))
                        if SENSITIVE_QUERY_KEYS
                            .iter()
                            .any(|s| k.eq_ignore_ascii_case(s)) =>
                    {
                        format!("{k}={REDACTED}")
                    }
                    _ => pair.to_string(),
                })
                .collect();
            out.push_str(&redacted.join("&"));
        }
        None => out.push_str(tail),
    }

    if out == token {
        None
    } else {
        Some(out)
    }
}

/// Does this token contain a literal credential prefix?
fn has_credential_prefix(token: &str) -> bool {
    CREDENTIAL_PREFIXES.iter().any(|p| token.contains(p))
}

/// A `user:password` pair passed positionally, as `curl -u` takes.
fn looks_like_userinfo_pair(token: &str) -> bool {
    match token.split_once(':') {
        // Not a URL, not a time, not a Windows path, both halves non-empty.
        Some((user, pass)) => {
            !user.is_empty()
                && !pass.is_empty()
                && !token.contains("://")
                && !token.contains('/')
                && !pass.chars().all(|c| c.is_ascii_digit())
                && user.chars().all(|c| !c.is_whitespace())
        }
        None => false,
    }
}

/// Redact a command line, using argv structure.
///
/// Handles inline `NAME=value` assignments, `--flag=value`, **space-separated
/// `--flag value`**, header arguments, `user:pass` pairs, URL userinfo and
/// query credentials, and known credential prefixes.
pub fn redact_command(cmd: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    // Set when the previous token was a flag that takes a credential value.
    let mut redact_next = false;

    for token in cmd.split_whitespace() {
        if redact_next {
            redact_next = false;
            // A following token that is itself a flag is not the value -- the
            // value was omitted. Redacting it would corrupt the record and
            // hide nothing.
            if token.starts_with('-') && token.len() > 1 {
                out.push(token.to_string());
                continue;
            }
            out.push(REDACTED.to_string());
            continue;
        }

        if token.contains('=') {
            if let Some(r) = redact_assignment(token) {
                out.push(r);
                continue;
            }
        }

        if is_value_flag(token) {
            redact_next = true;
            out.push(token.to_string());
            continue;
        }

        if has_credential_prefix(token) {
            out.push(REDACTED.to_string());
            continue;
        }

        if token.contains("://") {
            if let Some(r) = redact_url(token) {
                out.push(r);
                continue;
            }
        }

        if looks_like_userinfo_pair(token) {
            out.push(REDACTED.to_string());
            continue;
        }

        out.push(token.to_string());
    }

    out.join(" ")
}

/// Redact argv that is already split into arguments.
///
/// Preferred over [`redact_command`] wherever the real argv is available:
/// joining on spaces and re-splitting loses the argument boundaries, so a
/// quoted `-H "Authorization: Bearer x"` becomes three tokens and the
/// structural rules no longer see one header argument.
pub fn redact_argv(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut redact_next = false;

    for arg in argv {
        if redact_next {
            redact_next = false;
            if arg.starts_with('-') && arg.len() > 1 {
                out.push(arg.clone());
                continue;
            }
            out.push(REDACTED.to_string());
            continue;
        }

        if arg.contains('=') {
            if let Some(r) = redact_assignment(arg) {
                out.push(r);
                continue;
            }
        }

        if is_value_flag(arg) {
            redact_next = true;
            out.push(arg.clone());
            continue;
        }

        // A whole header passed as one argument: "Authorization: Bearer x".
        if let Some((name, _)) = arg.split_once(':') {
            if SENSITIVE_HEADERS
                .iter()
                .any(|h| name.trim().eq_ignore_ascii_case(h))
            {
                out.push(format!("{}: {REDACTED}", name.trim()));
                continue;
            }
        }

        if has_credential_prefix(arg) {
            out.push(REDACTED.to_string());
            continue;
        }

        if arg.contains("://") {
            if let Some(r) = redact_url(arg) {
                out.push(r);
                continue;
            }
        }

        if looks_like_userinfo_pair(arg) {
            out.push(REDACTED.to_string());
            continue;
        }

        out.push(arg.clone());
    }

    out
}

/// Redact unstructured text -- program output, error messages.
///
/// **This is best-effort and will miss secrets it has no pattern for.** There
/// is no argv structure here to reason from, so it can only catch known
/// credential prefixes and `sensitive-name: value` pairs. Callers must not
/// treat a redacted string as safe to publish; record a digest instead and
/// make the raw text opt-in.
pub fn redact_text(text: &str) -> String {
    let mut out: Vec<String> = Vec::new();

    for line in text.lines() {
        // `Authorization: Bearer ...` and friends, anywhere in the line.
        let lowered = line.to_ascii_lowercase();
        if let Some(h) = SENSITIVE_HEADERS
            .iter()
            .find(|h| lowered.contains(&format!("{h}:")))
        {
            let idx = lowered.find(&format!("{h}:")).unwrap_or(0);
            out.push(format!("{}{}: {REDACTED}", &line[..idx], h));
            continue;
        }

        let redacted: Vec<String> = line
            .split_whitespace()
            .map(|tok| {
                if has_credential_prefix(tok) {
                    REDACTED.to_string()
                } else if tok.contains('=') {
                    redact_assignment(tok).unwrap_or_else(|| tok.to_string())
                } else if tok.contains("://") {
                    redact_url(tok).unwrap_or_else(|| tok.to_string())
                } else {
                    tok.to_string()
                }
            })
            .collect();
        out.push(redacted.join(" "));
    }

    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every form the 2026-08 audit listed as bypassing the old sanitizer.
    /// These are the regression vectors; each one leaked before this module.
    #[test]
    fn audit_bypass_vectors_are_redacted() {
        let cases = [
            "curl --token secret123 https://api.example.com",
            "mytool --password hunter2",
            "psql --user admin --pass s3cr3t",
            "aws --secret-key AKIAIOSFODNN7EXAMPLE",
            "curl -u user:password https://example.com",
            "deploy --api-key abcdef123456",
        ];
        for case in cases {
            let got = redact_command(case);
            assert!(
                got.contains(REDACTED),
                "nothing redacted in {case:?} -> {got:?}"
            );
        }
    }

    #[test]
    fn space_separated_flag_value_is_redacted() {
        // The exact case the old sanitizer missed: no `=`, so no pattern hit.
        assert_eq!(
            redact_command("curl --token secret123 https://api.example.com"),
            "curl --token [REDACTED] https://api.example.com"
        );
    }

    #[test]
    fn secret_value_never_survives_verbatim() {
        let got = redact_command("curl --token secret123 --password hunter2");
        assert!(!got.contains("secret123"), "{got}");
        assert!(!got.contains("hunter2"), "{got}");
    }

    #[test]
    fn bearer_header_as_single_argv_entry_is_redacted() {
        let argv = vec![
            "curl".to_string(),
            "-H".to_string(),
            "Authorization: Bearer sk_live_abc123".to_string(),
        ];
        let got = redact_argv(&argv);
        assert!(!got.join(" ").contains("sk_live_abc123"), "{got:?}");
    }

    #[test]
    fn signed_url_query_credentials_are_redacted() {
        let got = redact_command("curl https://example.com/f?signature=SECRETVALUE&x=1");
        assert!(!got.contains("SECRETVALUE"), "{got}");
        // Non-sensitive params survive -- redaction should not destroy context.
        assert!(got.contains("x=1"), "{got}");
    }

    #[test]
    fn url_userinfo_password_is_redacted_but_user_kept() {
        let got = redact_command("git clone https://alice:hunter2@github.com/o/r.git");
        assert!(!got.contains("hunter2"), "{got}");
        assert!(got.contains("alice"), "{got}");
    }

    #[test]
    fn inline_env_assignment_still_redacted() {
        // The old sanitizer's one real capability must not regress.
        for case in [
            "AWS_SECRET_ACCESS_KEY=abc123 aws s3 ls",
            "TOKEN=xyz ./deploy",
            "STRIPE_KEY=sk_live_1 node app.js",
        ] {
            let got = redact_command(case);
            assert!(got.contains(REDACTED), "{case} -> {got}");
        }
    }

    #[test]
    fn credential_prefixes_are_caught_anywhere() {
        for tok in [
            "ghp_abc123",
            "AKIAIOSFODNN7",
            "xoxb-1-2-3",
            "sk-ant-api03-x",
        ] {
            let got = redact_command(&format!("echo {tok}"));
            assert!(got.contains(REDACTED), "{tok} -> {got}");
        }
    }

    #[test]
    fn output_text_redacts_known_shapes() {
        let got = redact_text("error: bad credential ghp_abcdef123456 rejected");
        assert!(!got.contains("ghp_abcdef123456"), "{got}");
    }

    #[test]
    fn benign_commands_are_untouched() {
        // Over-redaction destroys the evidence value of a receipt. A command
        // with nothing sensitive must come back byte-identical.
        for case in [
            "cargo build --release",
            "git commit -m fix",
            "ls -la /tmp",
            "npm run test",
        ] {
            assert_eq!(redact_command(case), case, "over-redacted {case}");
        }
    }

    #[test]
    fn flag_without_value_does_not_eat_the_next_flag() {
        // `--token` immediately followed by another flag means the value was
        // omitted; redacting `--verbose` would corrupt the record for nothing.
        let got = redact_command("tool --token --verbose run");
        assert_eq!(got, "tool --token --verbose run");
    }

    #[test]
    fn timestamps_are_not_mistaken_for_userinfo() {
        let got = redact_command("echo 12:30");
        assert_eq!(got, "echo 12:30");
    }

    #[test]
    fn redact_argv_preserves_argument_boundaries() {
        // Joining and re-splitting would turn this into 4 tokens and lose the
        // header structure. redact_argv sees one argument.
        let argv = vec!["-H".to_string(), "Cookie: session=abc123secret".to_string()];
        let got = redact_argv(&argv);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(!got[1].contains("abc123secret"), "{got:?}");
    }
}
