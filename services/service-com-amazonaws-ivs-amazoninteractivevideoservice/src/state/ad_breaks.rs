// SPDX-License-Identifier: CC0-1.0

//! The ad marker a broadcasting channel's playlist carries: what `InsertAdBreak`
//! writes, and the one rule it writes by, kept beside the rest of this service's
//! state so every operation that touches an ad break agrees on the record's form.
//!
//! An ad break is a marker placed in the playlist of the stream a channel is
//! currently ingesting ("Inserts an ad marker in the playlist for the specified
//! channel and duration using the ad configuration associated with the channel",
//! `smithy_query(query="doc",shape="InsertAdBreak")`), so the record belongs to the
//! BROADCAST rather than to the channel: it is written only while the channel has a
//! live stream and goes when that stream does ([`super::end_stream`]). That is also
//! what bounds this map — one entry per broadcasting channel.

use super::*;

/// How many characters an `AdBreakId` carries: the modelled shape is `@length 12..12`
/// over `^[a-zA-Z0-9]+$` (`smithy_query(query="shape",shape="AdBreakId")`).
const AD_BREAK_ID_LEN: usize = 12;

/// One ad break a caller has inserted into a channel's playlist.
#[derive(Debug, Clone)]
pub struct AdBreakRecord {
    /// The `adBreakId` the insert reported, "unique identifier for the ad break that
    /// was inserted into the playlist" — minted once, here, so the id a caller holds
    /// is the id this store carries.
    pub ad_break_id: String,
    /// How long the break runs, as the caller asked (`durationSeconds`, modelled
    /// `@range 1..300`).
    pub duration_seconds: i32,
    /// The ad configuration the break was inserted with: the channel's own
    /// `adConfigurationArn`, which is what the operation documents it uses, or `None`
    /// for a channel that has none associated.
    pub ad_configuration_arn: Option<String>,
    /// The stream whose playlist took the marker, so a record is never read as
    /// belonging to a later broadcast of the same channel.
    pub stream_id: Option<String>,
    /// When the marker was inserted.
    pub inserted_at: SystemTime,
}

/// Insert an ad break of `duration_seconds` into the playlist of the stream
/// `channel_arn` is ingesting, persist it as that channel's current marker and return
/// it.
///
/// The caller has already established that the channel exists and is broadcasting —
/// which is what the operation's `ResourceNotFoundException` and
/// `ChannelNotBroadcasting` answers separate — so this records the marker the live
/// playlist took. A later insert on the same channel replaces it: the playlist carries
/// the break most recently marked in it, and each insert mints its own id, so no two
/// breaks are ever reported under one identifier.
pub fn insert_ad_break(
    state: &mut ComAmazonawsIvsAmazoninteractivevideoserviceState,
    channel_arn: &str,
    duration_seconds: i32,
) -> AdBreakRecord {
    let ad_configuration_arn = state
        .channels
        .get(channel_arn)
        .and_then(|channel| channel.ad_configuration_arn.clone())
        .filter(|arn| !arn.is_empty());
    let stream_id = live_stream(state, channel_arn).and_then(|stream| stream.stream_id);
    // Hex is a subset of the `[a-zA-Z0-9]` alphabet the modelled id admits and
    // `mint_hex` never repeats a value, so one byte per two characters of the
    // modelled width gives an id that satisfies the shape and is unique per call.
    let ad_break_id = state.mint_hex("ad-break", AD_BREAK_ID_LEN / 2);
    let record = AdBreakRecord {
        ad_break_id,
        duration_seconds,
        ad_configuration_arn,
        stream_id,
        inserted_at: SystemTime::now(),
    };
    state
        .ad_breaks
        .insert(channel_arn.to_string(), record.clone());
    record
}
