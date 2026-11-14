// SPDX-License-Identifier: CC0-1.0

//! The Amazon ECS wire the `AWS::ECS::*` types a stack declares are created over lives with
//! the arms that use it: `state/provisioner/application_services.rs` for the cluster and
//! `state/provisioner/ecs_services.rs` for the service, and
//! `state/provisioning/ecs_task_definition.rs` for the revision.
//!
//! This module is deliberately empty, and is not declared, for the reason
//! [`super::ecs_service`]'s own note records: it held the shared wire of an earlier revision
//! of the ALB + Fargate convergence fix, whose per-type arm that catalogue now carries.
