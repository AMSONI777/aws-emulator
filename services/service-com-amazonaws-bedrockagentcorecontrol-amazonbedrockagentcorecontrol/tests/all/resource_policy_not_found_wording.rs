// SPDX-License-Identifier: CC0-1.0

//! Intentionally empty: this module holds no suite.
//!
//! The resource-policy plane's refusal-wording cases it first held — the
//! unresolvable-`resourceArn` sentence asserted over the partition, account, Region,
//! resource type and label length the rule generalises over, and the `resourceArn` label's
//! published length bounds — live in `tests/all/resource_policy_lifecycle.rs`, beside the
//! rest of that surface's harness and its existing refusal table, so the one rule is
//! asserted in one place. The declaration in `tests/all.rs` stays because this crate's
//! build script refuses a file under `tests/all/` that no declaration names.
