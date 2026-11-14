// SPDX-License-Identifier: CC0-1.0

//! The sprite sheet a map resource serves, end to end over the wire.
//!
//! Every call goes through the shared harness (`crate::harness`), so each one is a
//! separate HTTP request against one shared engine: a sheet a sprite read answers
//! with came from the map resource the create call PERSISTED, not from the sprite
//! request itself.
//!
//! The rule these suites assert: a sprite read of a stored map answers with the
//! published file its `FileName` names, derived from that map's own stored style —
//! the PNG sheet, or the offsets document describing exactly the rectangles that
//! sheet draws, at the pixel ratio the name asks for — refusing a `FileName`
//! outside the published set as a bad field and a map name nothing is stored under
//! as not found. The tables span that class: all four published file names, both
//! pixel ratios, the shapes a name outside the set can take, and map styles drawn
//! from every data provider the catalog carries.
//!
//! A `FileName` the published set does not hold is refused at the request boundary
//! by the pattern its member declares, so the last suite here asserts the sentence
//! this service words for a value outside a declared pattern across the operations
//! and member kinds that carry one, not only this one.

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

use crate::harness::{call, call_bytes, emulator, millis_of, RawAnswer, REGION};

/// The sprite files a map resource publishes, with the media type and pixel ratio
/// each one is served at.
///
/// Source: the `GetMapSpritesRequest$FileName` member doc, which lists the sheet
/// names ("sprites.png sprites@2x.png for high pixel density displays") and the
/// offsets-document names ("sprites.json sprites@2x.json for high pixel density
/// displays"), and the `GetMapSpritesResponse$ContentType` doc, which states the
/// two media types ("the sprite sheet content type is image/png, and the sprite
/// offset JSON document is application/json").
const PUBLISHED_FILES: [(&str, &str, u64); 4] = [
    ("sprites.png", "image/png", 1),
    ("sprites@2x.png", "image/png", 2),
    ("sprites.json", "application/json", 1),
    ("sprites@2x.json", "application/json", 2),
];

/// Map styles spanning every data provider the `MapConfiguration$Style` member doc
/// groups its catalog by, plus a second style of one provider so a sheet that
/// followed the style NAME rather than the provider its tiles come from fails here.
const STYLES: [(&str, &str); 5] = [
    ("VectorEsriStreets", "Esri"),
    ("VectorEsriNavigation", "Esri"),
    ("VectorHereExplore", "Here"),
    ("VectorGrabStandardLight", "Grab"),
    ("VectorOpenDataStandardLight", "Open Data"),
];

/// A `FileName` the published set does not hold. `GetMapSprites` serves exactly
/// four names, so every other spelling — another extension, another pixel ratio,
/// another case, a bare stem, a doubled suffix — is one request to refuse.
const UNPUBLISHED_FILE_NAMES: [(&str, &str); 7] = [
    ("another image format", "sprites.svg"),
    ("an unpublished pixel ratio", "sprites@3x.png"),
    ("an unpublished stem", "sprite.png"),
    ("a bare stem", "sprites"),
    ("upper case", "SPRITES.PNG"),
    ("a doubled suffix", "sprites.png.json"),
    ("the style descriptor's name", "style-descriptor.json"),
];

/// The pattern the model puts on `GetMapSpritesRequest$FileName`
/// (`smithy_query(query="operation",operation="GetMapSprites")`), which admits
/// exactly the four published names and nothing else.
const FILE_NAME_PATTERN: &str = r"^sprites(@2x)?\.(png|json)$";

/// The sentence a `FileName` outside the published set is refused with: the
/// member as the model spells it in single quotes, the fixed phrase, then the
/// pattern the model declares — the sentence this service states for a value
/// outside a member's declared pattern, with the rejected value never echoed.
fn file_name_refusal() -> String {
    format!("'FileName' must match regex {FILE_NAME_PATTERN}")
}

async fn create_map(router: &MultiServiceRouter, name: &str, style: &str) {
    let created = call(
        router,
        "POST",
        "/maps/v0/maps",
        Some(json!({ "MapName": name, "Configuration": { "Style": style } })),
    )
    .await;
    assert_eq!(
        created.status, 200,
        "case {name:?}/{style:?}: the map must be created, got {} {:?}",
        created.status, created.body
    );
}

async fn get_sprites(router: &MultiServiceRouter, map: &str, file: &str) -> RawAnswer {
    call_bytes(
        router,
        "GET",
        &format!("/maps/v0/maps/{map}/sprites/{file}"),
    )
    .await
}

/// Decode a PNG into `(width, height, rgba)`, failing the case if the body is not
/// an 8-bit RGBA PNG.
fn decode_png(case: &str, bytes: &[u8]) -> (u32, u32, Vec<u8>) {
    let decoder = png::Decoder::new(bytes);
    let mut reader = decoder
        .read_info()
        .unwrap_or_else(|error| panic!("case {case:?}: body must be a PNG, got {error}"));
    let mut buffer = vec![0; reader.output_buffer_size()];
    let info = reader
        .next_frame(&mut buffer)
        .unwrap_or_else(|error| panic!("case {case:?}: PNG frame must decode, got {error}"));
    buffer.truncate(info.buffer_size());
    assert_eq!(
        info.color_type,
        png::ColorType::Rgba,
        "case {case:?}: expected an RGBA PNG, got {:?}",
        info.color_type
    );
    assert_eq!(
        info.bit_depth,
        png::BitDepth::Eight,
        "case {case:?}: expected an 8-bit PNG, got {:?}",
        info.bit_depth
    );
    (info.width, info.height, buffer)
}

/// The alpha channel of one pixel of a decoded RGBA raster.
fn alpha_at(width: u32, rgba: &[u8], x: u32, y: u32) -> u8 {
    let offset = (y as usize * width as usize + x as usize) * 4;
    rgba[offset + 3]
}

/// One icon's rectangle, as the offsets document reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rect {
    x: u64,
    y: u64,
    width: u64,
    height: u64,
    pixel_ratio: u64,
}

/// The offsets document's entries, keyed by icon name.
fn offsets(case: &str, bytes: &[u8]) -> Vec<(String, Rect)> {
    let document: Value = serde_json::from_slice(bytes).unwrap_or_else(|error| {
        panic!(
            "case {case:?}: body must be JSON, got {error}: {:?}",
            String::from_utf8_lossy(bytes)
        )
    });
    let object = document
        .as_object()
        .unwrap_or_else(|| panic!("case {case:?}: the offsets document must be an object, got {document}"));
    assert!(
        !object.is_empty(),
        "case {case:?}: the offsets document must describe at least one icon, got {document}"
    );
    let member = |entry: &Value, name: &str| -> u64 {
        entry
            .get(name)
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("case {case:?}: every entry must carry {name}, got {entry}"))
    };
    let mut entries: Vec<(String, Rect)> = object
        .iter()
        .map(|(icon, entry)| {
            (
                icon.clone(),
                Rect {
                    x: member(entry, "x"),
                    y: member(entry, "y"),
                    width: member(entry, "width"),
                    height: member(entry, "height"),
                    pixel_ratio: member(entry, "pixelRatio"),
                },
            )
        })
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

#[tokio::test]
async fn every_published_sprite_file_is_served_with_its_own_media_type() {
    let router = emulator();
    create_map(&router, "SpriteSheetMap", "VectorEsriStreets").await;

    for (file, content_type, ratio) in PUBLISHED_FILES {
        let case = format!("{file} at ratio {ratio}");
        let served = get_sprites(&router, "SpriteSheetMap", file).await;
        assert_eq!(
            served.status, 200,
            "case {case:?}: expected 200, got {} {:?}",
            served.status,
            String::from_utf8_lossy(&served.body)
        );
        assert_eq!(
            served.header("content-type").as_deref(),
            Some(content_type),
            "case {case:?}: expected Content-Type {content_type:?}, got {:?}",
            served.header("content-type")
        );
        let cache_control = served.header("cache-control");
        assert!(
            cache_control
                .as_deref()
                .is_some_and(|value| value.contains("max-age=")),
            "case {case:?}: expected a Cache-Control directive with a freshness window, got \
             {cache_control:?}"
        );
        assert!(
            !served.body.is_empty(),
            "case {case:?}: the served file must carry a body"
        );

        // The body really is the format its media type claims, and the file names
        // of one pixel ratio describe that same ratio.
        if content_type == "image/png" {
            let (width, height, _) = decode_png(&case, &served.body);
            assert!(
                width > 0 && height > 0,
                "case {case:?}: the sheet must have a non-zero size, got {width}x{height}"
            );
        } else {
            for (icon, rect) in offsets(&case, &served.body) {
                assert_eq!(
                    rect.pixel_ratio, ratio,
                    "case {case:?}: icon {icon:?} must report pixelRatio {ratio}, got {rect:?}"
                );
            }
        }

        // A read is a function of stored state alone, so asking twice answers the
        // same bytes.
        let again = get_sprites(&router, "SpriteSheetMap", file).await;
        assert_eq!(
            again.body, served.body,
            "case {case:?}: a repeat read must answer the same bytes"
        );
    }
}

#[tokio::test]
async fn the_offsets_document_describes_the_sheet_it_is_paired_with() {
    let router = emulator();
    create_map(&router, "PairedFilesMap", "VectorHereExplore").await;

    let mut by_ratio = Vec::new();
    for (sheet_file, index_file, ratio) in [
        ("sprites.png", "sprites.json", 1_u64),
        ("sprites@2x.png", "sprites@2x.json", 2),
    ] {
        let case = format!("ratio {ratio}");
        let sheet = get_sprites(&router, "PairedFilesMap", sheet_file).await;
        let index = get_sprites(&router, "PairedFilesMap", index_file).await;
        let (width, height, rgba) = decode_png(&case, &sheet.body);
        let entries = offsets(&case, &index.body);

        for (icon, rect) in &entries {
            assert!(
                rect.x + rect.width <= u64::from(width) && rect.y + rect.height <= u64::from(height),
                "case {case:?}: icon {icon:?} rectangle {rect:?} must lie inside the {width}x\
                 {height} sheet"
            );
            // The offsets describe icons the paired sheet really DRAWS: the
            // centre column of the rectangle carries at least one opaque pixel.
            let column = (rect.x + rect.width / 2) as u32;
            let drawn = (rect.y..rect.y + rect.height)
                .any(|row| alpha_at(width, &rgba, column, row as u32) == u8::MAX);
            assert!(
                drawn,
                "case {case:?}: icon {icon:?} rectangle {rect:?} must hold drawn pixels in the \
                 paired sheet"
            );
        }
        by_ratio.push((ratio, width, height, entries));
    }

    let (_, base_width, base_height, base_entries) = &by_ratio[0];
    let (_, wide_width, wide_height, wide_entries) = &by_ratio[1];
    assert_eq!(
        (*wide_width, *wide_height),
        (base_width * 2, base_height * 2),
        "the @2x sheet must be the same layout at twice the size, got {wide_width}x{wide_height} \
         against {base_width}x{base_height}"
    );
    assert_eq!(
        base_entries
            .iter()
            .map(|(icon, _)| icon.clone())
            .collect::<Vec<_>>(),
        wide_entries
            .iter()
            .map(|(icon, _)| icon.clone())
            .collect::<Vec<_>>(),
        "both pixel ratios must describe the same icons"
    );
    for ((icon, base), (_, wide)) in base_entries.iter().zip(wide_entries) {
        assert_eq!(
            (wide.x, wide.y, wide.width, wide.height),
            (base.x * 2, base.y * 2, base.width * 2, base.height * 2),
            "icon {icon:?}: the @2x rectangle must be exactly twice the 1x rectangle {base:?}, \
             got {wide:?}"
        );
    }
}

#[tokio::test]
async fn the_sheet_a_map_serves_follows_its_stored_style() {
    let router = emulator();
    let mut served: Vec<(&str, &str, Vec<u8>, Vec<String>)> = Vec::new();
    for (style, provider) in STYLES {
        let map = format!("Map{style}");
        create_map(&router, &map, style).await;
        let sheet = get_sprites(&router, &map, "sprites.png").await;
        assert_eq!(
            sheet.status, 200,
            "case {style:?}: expected 200, got {} {:?}",
            sheet.status,
            String::from_utf8_lossy(&sheet.body)
        );
        let index = get_sprites(&router, &map, "sprites.json").await;
        let icons = offsets(style, &index.body)
            .into_iter()
            .map(|(icon, _)| icon)
            .collect();
        served.push((style, provider, sheet.body, icons));
    }

    for (style, provider, sheet, icons) in &served {
        for (other_style, other_provider, other_sheet, other_icons) in &served {
            if style == other_style {
                continue;
            }
            let case = format!("{style} against {other_style}");
            assert_eq!(
                icons, other_icons,
                "case {case:?}: every style publishes the same iconography, got {icons:?} against \
                 {other_icons:?}"
            );
            if provider == other_provider {
                assert_eq!(
                    sheet, other_sheet,
                    "case {case:?}: two styles sourced from {provider} must serve the same sheet"
                );
            } else {
                assert_ne!(
                    sheet, other_sheet,
                    "case {case:?}: a sheet sourced from {provider} must differ from one sourced \
                     from {other_provider}"
                );
            }
        }
    }
}

/// One row of the pattern-refusal table: the request to send, the member whose
/// pattern it violates, and that member's pattern.
#[derive(Debug)]
struct PatternRow {
    case: &'static str,
    method: &'static str,
    path: &'static str,
    body: Option<Value>,
    member: &'static str,
    pattern: &'static str,
}

/// A value outside a member's declared pattern is refused in this service's own
/// wording, whichever operation and member kind carries it.
///
/// The rows span that class: the sprite file name this issue is about, the map
/// name beside it, another map-asset operation's label, and a body member of
/// another resource plane. Each pattern is the one its member declares in the
/// model (`smithy_query(query="operation",operation="<Op>")`).
#[tokio::test]
async fn a_value_outside_a_declared_pattern_is_refused_in_this_services_wording() {
    let router = emulator();
    create_map(&router, "PatternMap", "VectorEsriStreets").await;

    /// `ResourceName`, the shape every named resource of this API uses.
    const RESOURCE_NAME_PATTERN: &str = r"^[-._\w]+$";

    let rows = [
        PatternRow {
            case: "the sprite file label",
            method: "GET",
            path: "/maps/v0/maps/PatternMap/sprites/unknown.png",
            body: None,
            member: "FileName",
            pattern: FILE_NAME_PATTERN,
        },
        PatternRow {
            case: "the map name label beside it",
            method: "GET",
            path: "/maps/v0/maps/not!a!name/sprites/sprites.png",
            body: None,
            member: "MapName",
            pattern: RESOURCE_NAME_PATTERN,
        },
        PatternRow {
            case: "another map asset operation's label",
            method: "GET",
            path: "/maps/v0/maps/PatternMap/glyphs/fonts/not-a-range.pbf",
            body: None,
            member: "FontUnicodeRange",
            pattern: r"^[0-9]+-[0-9]+\.pbf$",
        },
        PatternRow {
            case: "a body member of another resource plane",
            method: "POST",
            path: "/tracking/v0/trackers",
            body: Some(json!({ "TrackerName": "not a name" })),
            member: "TrackerName",
            pattern: RESOURCE_NAME_PATTERN,
        },
    ];

    for row in rows {
        let case = row.case;
        let refused = call(&router, row.method, row.path, row.body).await;
        let sentence = format!("'{}' must match regex {}", row.member, row.pattern);
        assert_eq!(
            refused.status, 400,
            "case {case:?}: expected a 400 refusal, got {} {:?}",
            refused.status, refused.body
        );
        assert_eq!(
            refused.error_code(),
            "ValidationException",
            "case {case:?}: expected error code ValidationException, got {:?} ({:?})",
            refused.error_code(),
            refused.body
        );
        assert_eq!(
            refused.message(),
            sentence,
            "case {case:?}: expected message {sentence:?}, got {:?}",
            refused.message()
        );
    }
}

/// A `FileName` outside the published set is refused, and refused BEFORE the map
/// resource is resolved: the four names the member's pattern admits are the only
/// sprite files there are, so another spelling is a bad request whether or not a
/// map is stored under the name beside it.
#[tokio::test]
async fn a_file_name_outside_the_published_set_is_refused() {
    let router = emulator();
    create_map(&router, "RefusingMap", "VectorEsriStreets").await;

    for (case, file) in UNPUBLISHED_FILE_NAMES {
        let sentence = file_name_refusal();
        let refused = call(
            &router,
            "GET",
            &format!("/maps/v0/maps/RefusingMap/sprites/{file}"),
            None,
        )
        .await;
        assert_eq!(
            refused.status, 400,
            "case {case:?} ({file:?}): expected a 400 refusal, got {} {:?}",
            refused.status, refused.body
        );
        assert_eq!(
            refused.error_code(),
            "ValidationException",
            "case {case:?} ({file:?}): expected error code ValidationException, got {:?} ({:?})",
            refused.error_code(),
            refused.body
        );
        assert_eq!(
            refused.message(),
            sentence,
            "case {case:?} ({file:?}): expected message {sentence:?}, got {:?}",
            refused.message()
        );

        // The member check precedes the lookup: the same name is refused the same
        // way when no map is stored under the name beside it.
        let absent = call(
            &router,
            "GET",
            &format!("/maps/v0/maps/AbsentMap/sprites/{file}"),
            None,
        )
        .await;
        assert_eq!(
            absent.status, 400,
            "case {case:?} ({file:?}): a bad file name must be refused before the map is \
             resolved, got {} {:?}",
            absent.status, absent.body
        );
    }
}

#[tokio::test]
async fn a_map_name_no_map_is_stored_under_is_not_found() {
    let router = emulator();
    create_map(&router, "StoredMap", "VectorEsriStreets").await;

    for (case, map) in [
        ("a name no map holds", "AbsentMap"),
        ("a stored name in another case", "storedmap"),
        ("a stored name with a suffix", "StoredMap2"),
    ] {
        for (file, _, _) in PUBLISHED_FILES {
            let refused = call(
                &router,
                "GET",
                &format!("/maps/v0/maps/{map}/sprites/{file}"),
                None,
            )
            .await;
            assert_eq!(
                refused.status, 404,
                "case {case:?} ({map:?}, {file:?}): expected a 404, got {} {:?}",
                refused.status, refused.body
            );
            assert_eq!(
                refused.error_code(),
                "ResourceNotFoundException",
                "case {case:?} ({map:?}, {file:?}): expected ResourceNotFoundException, got {:?}",
                refused.error_code()
            );
            assert_eq!(
                refused.message(),
                format!("Map not found: {map}."),
                "case {case:?} ({map:?}, {file:?}): expected the map-not-found sentence, got {:?}",
                refused.message()
            );
        }
    }
}

#[tokio::test]
async fn a_sprite_read_changes_nothing_a_later_caller_sees() {
    let router = emulator();
    create_map(&router, "UntouchedMap", "VectorGrabStandardLight").await;

    let before = call(&router, "GET", "/maps/v0/maps/UntouchedMap", None).await;
    for (file, _, _) in PUBLISHED_FILES {
        let served = get_sprites(&router, "UntouchedMap", file).await;
        assert_eq!(
            served.status, 200,
            "case {file:?}: expected 200, got {}",
            served.status
        );
    }
    // A name no map is stored under, and a file name outside the set, must not
    // leave anything behind either.
    let _ = get_sprites(&router, "UntouchedMap", "sprites.svg").await;
    let _ = get_sprites(&router, "AbsentMap", "sprites.png").await;
    let after = call(&router, "GET", "/maps/v0/maps/UntouchedMap", None).await;

    assert_eq!(
        before.json(),
        after.json(),
        "a sprite read must leave the map resource exactly as it was"
    );
    // The timestamps are the part a mutating read would move, so they are pinned
    // by value as well as by the whole-body comparison above.
    assert_eq!(
        millis_of(&before.json(), "UpdateTime"),
        millis_of(&after.json(), "UpdateTime"),
        "a sprite read must not move the map's UpdateTime"
    );
    let listed = call(&router, "GET", "/maps/v0/maps/UntouchedMap", None).await;
    assert_eq!(
        listed.status, 200,
        "the map must still be readable after a sprite read, got {} {:?}",
        listed.status, listed.body
    );
    assert_eq!(
        before
            .json()
            .get("MapArn")
            .and_then(Value::as_str)
            .map(str::to_string),
        Some(format!(
            "arn:aws:geo:{REGION}:{}:map/UntouchedMap",
            crate::harness::ACCOUNT
        )),
        "the map read back after a sprite read must still carry its own ARN"
    );
}
