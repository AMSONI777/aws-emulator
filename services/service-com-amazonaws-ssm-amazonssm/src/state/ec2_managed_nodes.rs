// SPDX-License-Identifier: CC0-1.0

//! Where this service's EC2-FACING work lives, so neither half is looked for twice.
//!
//! An Amazon EC2 instance reaches this service in two places, and they are deliberately
//! separate:
//!
//! * [`super::node_registration`] — WHICH instances are managed nodes: the registration
//!   derived from the instance Amazon EC2 holds, the instance profile it runs as and what
//!   that profile's role may do, materialised by the node reports.
//! * [`super::guest_execution`] — what a command SENT to such a node does: the document's
//!   script performed in that instance's guest, through the seam the service that owns the
//!   instance exposes for it.
//!
//! Nothing else of this crate derives a node from an instance or reaches into a guest, so a
//! change to either rule has exactly one place to be made.
