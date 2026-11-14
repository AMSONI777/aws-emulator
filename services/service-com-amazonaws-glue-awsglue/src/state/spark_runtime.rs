// SPDX-License-Identifier: CC0-1.0

//! EMPTY. The Spark engine and the AWS Glue ETL library a job script finds on its import
//! path live in [`::service_common::spark_runtime`] and [`super::glue_etl`]: this file held a
//! second implementation of them that landed at the same time and is no longer declared
//! anywhere. It stays only because this fixer's tool set can write a file but not remove one;
//! the next change to touch this directory should delete it and `spark_runtime/`.
