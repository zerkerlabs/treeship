//! Exit codes, typed.
//!
//! The docs promise a small set of exit codes (cli/overview, "Exit codes").
//! Through 0.31.9 `main` chose the code by searching the error text, so an
//! agent named `required-bot` in a `resolve` error exited 4 ("usage") and
//! a message that happened to mention `treeship init` exited 3. A command
//! that means a specific code now returns an [`ExitError`] carrying it, and
//! `main` reads the code, never the words. Everything else is 1.

use std::fmt;

/// Something went wrong; the default.
pub const ERROR: i32 = 1;
/// No workspace here: run `treeship init`.
pub const NOT_INITIALIZED: i32 = 3;
/// The command was called wrong (a missing value, an impossible
/// combination). The argument parser's own usage errors exit 2.
pub const USAGE: i32 = 4;
/// The command exists but its implementation is not compiled into this
/// binary (`prove` without `--features zk`, `otel` without `otel`).
// Only the feature-gated stubs raise it, so a build with every feature
// on has no caller; the code is still part of the contract.
#[allow(dead_code)]
pub const NOT_IN_BUILD: i32 = 5;

/// An error that names its exit code.
#[derive(Debug)]
pub struct ExitError {
    pub code: i32,
    pub message: String,
}

impl fmt::Display for ExitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ExitError {}

fn boxed(code: i32, message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(ExitError {
        code,
        message: message.into(),
    })
}

/// A usage error raised by the command itself (exit 4).
pub fn usage(message: impl Into<String>) -> Box<dyn std::error::Error> {
    boxed(USAGE, message)
}

/// The feature is not compiled into this binary (exit 5).
#[allow(dead_code)]
pub fn not_in_build(message: impl Into<String>) -> Box<dyn std::error::Error> {
    boxed(NOT_IN_BUILD, message)
}

/// The exit code for an error that reached `main`.
pub fn code_for(e: &(dyn std::error::Error + 'static)) -> i32 {
    if let Some(x) = e.downcast_ref::<ExitError>() {
        return x.code;
    }
    if let Some(crate::ctx::CtxError::Config(crate::config::ConfigError::NotFound(_))) =
        e.downcast_ref::<crate::ctx::CtxError>()
    {
        return NOT_INITIALIZED;
    }
    if let Some(crate::config::ConfigError::NotFound(_)) =
        e.downcast_ref::<crate::config::ConfigError>()
    {
        return NOT_INITIALIZED;
    }
    ERROR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_errors_carry_their_code() {
        assert_eq!(code_for(usage("x").as_ref()), USAGE);
        assert_eq!(code_for(not_in_build("x").as_ref()), NOT_IN_BUILD);
        let plain: Box<dyn std::error::Error> = "required-bot is not required".into();
        assert_eq!(code_for(plain.as_ref()), ERROR);
    }

    #[test]
    fn words_in_a_message_do_not_pick_the_code() {
        let e: Box<dyn std::error::Error> =
            "no capability card for agent://required-bot, run treeship init".into();
        assert_eq!(code_for(e.as_ref()), ERROR);
    }
}
