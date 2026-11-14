// SPDX-License-Identifier: CC0-1.0

//! Every `tests/all.rs` keeps its inner doc comments ahead of its first item.
//!
//! An inner doc comment (`//!`, `/*!`) documents the module it is written in, so the
//! language accepts it only before that module's first item: one written lower down is
//! `error[E0753]: expected outer doc comment` and the whole integration-test target
//! fails to compile, taking every suite in it down with it. These declaration roots are
//! appended to by every landing suite, each adding its own explanatory comment block
//! above its `#[path]`/`mod` pair, so a block typed with `//!` instead of `//` in the
//! middle of the list is the break this suite pins.
//!
//! It reads files only; it starts no router and reaches no network.

use std::fs;

// The roots this rule holds for are the ones the sibling layout suite already enumerates —
// this crate's `tests/all.rs` plus every service crate's — so that enumerator is shared
// rather than copied. The rule belongs to the single-target layout rather than to any one
// crate, and the crate that breaks it cannot pin it itself: a misplaced inner doc comment
// makes that crate's own `all` target fail to compile, so no suite inside it ever runs to
// report the break. This target is the one that links every service crate.
use crate::all_rs_declares_each_suite_once::{declaration_roots, workspace_root};

/// The 1-based line the first item of `source` starts on, if it has one.
///
/// An item starts at the first line that is neither blank, nor a comment of either style,
/// nor an inner attribute (`#![...]`, which may itself only precede the first item). An
/// outer attribute (`#[path = "..."]`) opens the item it decorates, so it counts as that
/// item's start: an inner doc comment between an outer attribute and its `mod` is the same
/// error as one after the `mod`.
fn first_item_line(source: &str) -> Option<usize> {
    source.lines().enumerate().find_map(|(index, line)| {
        let line = line.trim_start();
        let opens_an_item = !(line.is_empty()
            || line.starts_with("//")
            || line.starts_with("/*")
            || line.starts_with("#!["));
        opens_an_item.then_some(index + 1)
    })
}

/// One report per inner doc comment in `source` that sits after the first item, each
/// naming the line it is on and the line the item starts at.
///
/// The rule read here is the declaration root's: no `//!` anywhere after the first item.
/// It is deliberately the conservative reading — one of those lines is `E0753` where it
/// stands at a module's top level, and a declaration root holds nothing else — so a note
/// indented inside a later item is reported too rather than argued about.
fn misplaced_inner_doc_comments(source: &str) -> Vec<String> {
    let Some(item_line) = first_item_line(source) else {
        return Vec::new();
    };
    source
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim_start();
            let is_inner_doc = line.starts_with("//!") || line.starts_with("/*!");
            (is_inner_doc && index + 1 > item_line).then(|| {
                format!(
                    "line {}: expected a plain comment (`//`), got the inner doc comment \
                     {line:?} after the item starting on line {item_line}",
                    index + 1
                )
            })
        })
        .collect()
}

#[test]
fn every_declaration_root_keeps_its_inner_doc_comments_ahead_of_its_first_item() {
    let root = workspace_root();
    let roots = declaration_roots();
    assert!(
        roots.len() > 100,
        "expected one tests/all.rs per service crate under {}, read {} of them",
        root.display(),
        roots.len()
    );

    let mut reports = Vec::new();
    for declaration_root in &roots {
        let crate_root = declaration_root
            .strip_prefix(&root)
            .unwrap_or(declaration_root)
            .display()
            .to_string();
        let source = fs::read_to_string(declaration_root)
            .unwrap_or_else(|error| panic!("read {}: {error}", declaration_root.display()));
        for report in misplaced_inner_doc_comments(&source) {
            reports.push(format!("case {crate_root}: {report}"));
        }
    }

    assert!(
        reports.is_empty(),
        "expected each of the {} declaration roots to carry no inner doc comment after its \
         first item, got {} report(s), each of which fails that target with E0753: \
         {reports:#?}",
        roots.len(),
        reports.len()
    );
}

#[test]
fn the_reader_reports_an_inner_doc_comment_the_target_cannot_compile() {
    // One synthetic declaration root per way a comment block can land, with how many
    // reports the reader owes it. The forms differ in comment style, in where the block
    // sits relative to the first item, and in how the item is opened.
    let declaration = "#[path = \"all/boot_serve.rs\"]\nmod boot_serve;\n";
    let cases: [(&str, String, usize); 10] = [
        ("an empty root", String::new(), 0),
        (
            "a head inner doc comment only",
            format!("//! Single integration-test target.\n{declaration}"),
            0,
        ),
        (
            "a head inner doc comment under a license line",
            format!("// SPDX-License-Identifier: CC0-1.0\n\n//! The target.\n{declaration}"),
            0,
        ),
        (
            "a head inner attribute beside the doc comment",
            format!("#![allow(dead_code)]\n//! The target.\n{declaration}"),
            0,
        ),
        (
            // The shape this suite exists for: a landing suite appended its explanatory
            // block to the tail of the list and typed it `//!`.
            "an appended block typed as an inner doc comment",
            format!("//! The target.\n{declaration}//! Declared here, in the appended tail.\n{declaration}"),
            1,
        ),
        (
            "a four-line appended block typed as an inner doc comment",
            format!(
                "//! The target.\n{declaration}//! A suite left at the top level of `tests/`\n\
                 //! fails the build. Declare each suite exactly\n//! ONCE: a second `mod` for\n\
                 //! the same name is `E0428`.\n{declaration}"
            ),
            4,
        ),
        (
            "the same appended block typed as a plain comment",
            format!("//! The target.\n{declaration}// Declared here, in the appended tail.\n{declaration}"),
            0,
        ),
        (
            "an inner block doc comment after the first item",
            format!("//! The target.\n{declaration}/*! Declared here. */\n{declaration}"),
            1,
        ),
        (
            "an inner doc comment between an outer attribute and its mod",
            "//! The target.\n#[path = \"all/boot_serve.rs\"]\n//! Declared here.\nmod boot_serve;\n"
                .to_string(),
            1,
        ),
        (
            // Reported under the conservative reading above: a declaration root carries
            // only `#[path]`/`mod` pairs and comments, so nothing legitimate looks like
            // this.
            "an indented inner doc comment inside a later item",
            format!("//! The target.\n{declaration}fn helper() {{\n    //! Inside.\n}}\n"),
            1,
        ),
    ];

    for case in &cases {
        let (name, source, expected) = case;
        let reports = misplaced_inner_doc_comments(source);
        assert_eq!(
            reports.len(),
            *expected,
            "case {name:?}: expected {expected} report(s), got {reports:#?}"
        );
    }
}

#[test]
fn the_reader_finds_the_line_the_first_item_opens_on() {
    // Each form a declaration root opens with, and the line its first item starts on.
    let cases: [(&str, &str, Option<usize>); 6] = [
        ("nothing", "", None),
        ("comments only", "// SPDX\n\n//! The target.\n", None),
        ("a bare mod", "mod boot_serve;\n", Some(1)),
        (
            "an outer attribute above its mod",
            "#[path = \"all/boot_serve.rs\"]\nmod boot_serve;\n",
            Some(1),
        ),
        (
            "a head comment block above the first item",
            "// SPDX\n\n//! The target.\n// A note.\n#[path = \"all/boot_serve.rs\"]\nmod boot_serve;\n",
            Some(5),
        ),
        (
            "an inner attribute above the first item",
            "#![allow(dead_code)]\n//! The target.\nmod boot_serve;\n",
            Some(3),
        ),
    ];
    for (name, source, expected) in cases {
        let actual = first_item_line(source);
        assert_eq!(
            actual, expected,
            "case {name:?}: expected the first item on line {expected:?}, got {actual:?}"
        );
    }
}
