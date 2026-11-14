// SPDX-License-Identifier: CC0-1.0

//! The ONE bounded compile of a regular expression that came off the wire.
//!
//! Two things this service does rest on compiling a caller's pattern:
//! `CreateCustomDataIdentifier` refuses a `regex` it could never run before it
//! stores an identifier, and an allow list's status reports whether "Amazon
//! Macie can compile the expression" its criteria specify. Both decide it here,
//! so the bound cannot drift between them; each caller words its own answer,
//! because the message and the status code belong to the operation and the
//! bound does not.
//!
//! The syntax is decided by the `regex` crate rather than by a hand-written
//! reader of the pattern language: it parses the whole expression, refuses what
//! it cannot represent, and matches in time linear in the subject, so no pattern
//! a caller sends can make matching blow up later.

/// The byte budget one compiled pattern may occupy. Compiling a pattern that
/// came off the wire is caller-driven work, so it is bounded twice: by the
/// documented length of the member it arrived in (512 characters for both of the
/// members above), and by this limit on the program built from it, past which
/// `regex` answers an error instead of growing the heap.
const PATTERN_PROGRAM_BYTES: usize = 1 << 20;

/// Whether `pattern` is a regular expression this service can run: it parses,
/// and the program built from it stays inside [`PATTERN_PROGRAM_BYTES`].
///
/// COMPILES the expression and nothing more — no caller data is ever matched
/// with it here.
#[must_use]
pub fn pattern_compiles(pattern: &str) -> bool {
    ::regex::RegexBuilder::new(pattern)
        .size_limit(PATTERN_PROGRAM_BYTES)
        .dfa_size_limit(PATTERN_PROGRAM_BYTES)
        .build()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::pattern_compiles;

    /// A pattern the service can run is accepted and one it cannot is refused,
    /// over the forms each takes.
    #[test]
    fn only_a_pattern_the_service_can_run_compiles() {
        for pattern in ["a", "[0-9]{3}-[0-9]{2}-[0-9]{4}", "^(foo|bar)+$", "\\d+\\s*"] {
            assert!(
                pattern_compiles(pattern),
                "case {pattern:?}: expected a pattern this service can run"
            );
        }
        for pattern in ["[0-9", "(unclosed", "a{3,1}", "*"] {
            assert!(
                !pattern_compiles(pattern),
                "case {pattern:?}: expected a pattern this service cannot run"
            );
        }
    }
}
