// SPDX-License-Identifier: CC0-1.0

//! The CLOCK this service decides a span it owes against.
//!
//! A span the emulator owes — the one a credential-report generation takes before the
//! report exists ([`CREDENTIAL_REPORT_GENERATION_SECONDS`]) — is recorded as the instant it
//! falls due and materialised by the next call that finds that instant passed. Both halves
//! have to read ONE clock, and that clock is the emulator's own
//! ([`service_common::clock`]) rather than the process clock: an emulator whose clock stands
//! still keeps every span it owes open, and an emulator whose clock is moved on crosses
//! them, so both sides of a span are observable without any call having to wait for real
//! time to pass.
//!
//! By default that clock follows the process clock, so a span passes for a caller of a
//! served emulator exactly as it did before this module existed; nothing a REQUEST carries
//! can move it.

#[allow(unused_imports)]
use super::*;

/// The wall-clock instant this process anchors the emulator's monotonic clock to, beside the
/// reading of that monotonic clock taken with it.
///
/// Read once and then kept, so [`clock_now`] is a pure function of the emulator's own clock:
/// an emulator clock standing still reads the same timestamp every time, down to the
/// millisecond, rather than one that wobbles by however far the two system clocks happen to
/// be read apart.
static ANCHOR: ::std::sync::OnceLock<(::std::time::SystemTime, ::std::time::Instant)> =
    ::std::sync::OnceLock::new();

/// The instant the emulator's clock reads, in the modelled timestamp type — the one instant
/// a due instant is recorded from and compared against.
///
/// The emulator's clock is monotonic, so what it reads is projected onto the wall clock by
/// the span it stands from the anchor above: a running clock answers the wall clock as it
/// advances, and a clock standing still answers the wall-clock instant it stands at, however
/// long the process has been running since.
pub fn clock_now<Eng: ::std::marker::Send + ::std::marker::Sync + 'static>(
    engine: &Eng,
) -> ::aws_smithy_types::DateTime {
    let (anchored_at, anchor) =
        *ANCHOR.get_or_init(|| (::std::time::SystemTime::now(), ::std::time::Instant::now()));
    let standing = ::service_common::clock::now(engine);
    let reads = if standing >= anchor {
        anchored_at.checked_add(standing.duration_since(anchor))
    } else {
        anchored_at.checked_sub(anchor.duration_since(standing))
    }
    // A span past the end of the wall clock's range, which no span a service records comes
    // near, leaves the reading at the anchor rather than failing.
    .unwrap_or(anchored_at);
    let since_epoch = reads
        .duration_since(::std::time::UNIX_EPOCH)
        .unwrap_or_default();
    ::aws_smithy_types::DateTime::from_millis(since_epoch.as_millis() as i64)
}
