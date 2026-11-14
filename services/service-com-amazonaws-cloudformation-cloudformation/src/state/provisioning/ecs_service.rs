// SPDX-License-Identifier: CC0-1.0

//! `AWS::ECS::Service` is provisioned by `state/provisioner/ecs_services.rs`, beside the
//! cluster arms of the same service, and the Amazon ECS wire its calls ride on is that
//! catalogue's own.
//!
//! This module is deliberately empty, and is not declared: an earlier revision of the
//! ALB + Fargate convergence fix carried its own `AWS::ECS::Service` provider here, through
//! `provisioning::Owner`, before that catalogue arm landed — and one resource type has ONE
//! provider, so the arm a stack reaches is that one.
