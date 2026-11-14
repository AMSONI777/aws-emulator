// SPDX-License-Identifier: CC0-1.0

//! The LISTING of one data source's ingestion jobs: which of the stored
//! [`IngestionJobRecord`] entries `ListIngestionJobs` reports, the order it
//! reports them in, the page it hands out and the cursor a page resumes from.
//!
//! An ingestion job ran for one data source of one knowledge base — the record
//! names both, and every modelled ingestion-job operation addresses the triple —
//! so one data source's listing never reports another's job. The default order
//! is the one every other listing of this service pages over: when the resource
//! came into being, ties broken by its minted id, both of which never change,
//! which is what lets a page resume exactly after the one before it. A request
//! that names `sortBy` orders the same set by the field it names instead, and
//! one that names `filters` reports only the jobs every filter admits.
//!
//! The reports here never change a record: the listing is a projection of what
//! the store already holds.

use super::*;

use crate::ops::types::{IngestionJobFilter, IngestionJobSortBy, IngestionJobSummary};

/// The most ingestion jobs one `ListIngestionJobs` page reports when the request
/// names no `maxResults`.
///
/// The modelled `IngestionJobSummaries` carries no `@length` bound and
/// `maxResults` is `range 1..1000`
/// (`smithy_query(query="operation",operation="ListIngestionJobs")`), so no
/// bound is published for the page: the default is the whole of what one data
/// source can hold ([`INGESTION_JOB_QUOTA`]), which is what a listing of every
/// job of a data source reports in one page.
pub const MAX_INGESTION_JOBS_PER_PAGE: usize = INGESTION_JOB_QUOTA;

/// The only member the modelled `IngestionJobFilterAttribute` enum declares: a
/// filter selects jobs on their status and on nothing else.
///
/// Source: the `IngestionJobFilterAttribute` enum of this service's Smithy model
/// (`smithy_query(query="shape",shape="IngestionJobFilterAttribute")`).
const FILTER_ATTRIBUTE_STATUS: &str = "STATUS";

/// The only member the modelled `IngestionJobFilterOperator` enum declares: a
/// filter admits a job whose field EQUALS one of the values it carries.
///
/// Source: the `IngestionJobFilterOperator` enum of this service's Smithy model
/// (`smithy_query(query="shape",shape="IngestionJobFilterOperator")`).
const FILTER_OPERATOR_EQUALS: &str = "EQ";

/// The `IngestionJobSortByAttribute` member that orders jobs by their status.
///
/// Source: the `IngestionJobSortByAttribute` enum of this service's Smithy model
/// (`smithy_query(query="shape",shape="IngestionJobSortByAttribute")`), whose
/// other member — `STARTED_AT` — names the order the listing uses by default.
const SORT_BY_STATUS: &str = "STATUS";

/// The `SortOrder` member that reverses the order the sort attribute puts the
/// jobs in.
///
/// Source: the `SortOrder` enum of this service's Smithy model
/// (`smithy_query(query="shape",shape="SortOrder")`), whose other member —
/// `ASCENDING` — is the direction the listing uses by default.
const SORT_ORDER_DESCENDING: &str = "DESCENDING";

impl IngestionJobRecord {
    /// This record as the modelled `IngestionJobSummary` shape, which is what
    /// `ListIngestionJobs` reports: every member comes from the same stored
    /// value the full projection ([`IngestionJobRecord::to_ingestion_job`])
    /// reports it from.
    pub fn to_summary(&self) -> IngestionJobSummary {
        IngestionJobSummary {
            knowledge_base_id: self.knowledge_base_id.clone(),
            data_source_id: self.data_source_id.clone(),
            ingestion_job_id: self.ingestion_job_id.clone(),
            description: self.description.clone(),
            status: self.status.as_wire().to_string(),
            started_at: to_date_time(self.started_at),
            updated_at: to_date_time(self.updated_at),
            text_ready_at: self.text_ready_at.map(to_date_time),
            statistics: Some(self.statistics.clone()),
        }
    }

    /// The total order the listing pages over by default: when the job started,
    /// ties broken by its minted id.
    fn started_at_key(&self) -> (u128, &str) {
        (
            epoch_nanos(self.started_at),
            self.ingestion_job_id.as_str(),
        )
    }

    /// The total order the listing pages over when the request sorts on the
    /// status field: the status as the modelled enum spells it, ties broken by
    /// the default order, so jobs sharing a status keep a stable position.
    ///
    /// CHOSEN, not documented: AWS publishes no order over the
    /// `IngestionJobStatus` values, so the values are ordered as their member
    /// names compare. It is NOT the job lifecycle's order, and nothing here
    /// claims it is — what the sort member asks for is a total order over the
    /// field it names, and this is one.
    fn status_key(&self) -> (&str, u128, &str) {
        let (started_at_nanos, ingestion_job_id) = self.started_at_key();
        (self.status.as_wire(), started_at_nanos, ingestion_job_id)
    }

    /// Whether this job is one `filter` admits.
    ///
    /// The modelled `IngestionJobFilter` names a field, an operator and the
    /// values to compare against; the model declares exactly one of each — the
    /// status field and equality — and the boundary validator refuses any other
    /// member value before a handler runs, so a filter admits a job whose status
    /// is one of the values it carries. A filter carrying no value admits
    /// nothing: no status equals a value that is not there.
    fn admitted_by(&self, filter: &IngestionJobFilter) -> bool {
        if filter.attribute != FILTER_ATTRIBUTE_STATUS
            || filter.operator != FILTER_OPERATOR_EQUALS
        {
            return false;
        }
        filter
            .values
            .iter()
            .any(|value| value == self.status.as_wire())
    }
}

/// A `ListIngestionJobs` resume cursor: how many of one data source's jobs the
/// listing has already reported, in the order the request asked for.
///
/// The token names a POSITION in that order rather than a job, which is what
/// lets one cursor resume whichever order the request sorted by — and a page
/// resumes even if the job it stopped at has since left the store with its data
/// source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngestionJobPageCursor {
    reported: usize,
}

impl IngestionJobPageCursor {
    /// Decode a `nextToken` a previous page handed out. `None` when the token is
    /// not one [`Self::token`] renders: a position is a plain decimal count of
    /// the jobs already reported, so nothing else names a position in this
    /// listing.
    pub fn parse(token: &str) -> Option<Self> {
        if !is_counted_token_position(token) {
            return None;
        }
        token.parse().ok().map(|reported| Self { reported })
    }

    /// The cursor that resumes after `reported` jobs, or `None` when none has
    /// been reported yet — the position an absent `nextToken` already names.
    fn after(reported: usize) -> Option<Self> {
        (reported > 0).then_some(Self { reported })
    }

    /// This position as the opaque `nextToken` a page hands out.
    pub fn token(self) -> String {
        self.reported.to_string()
    }
}

impl ComAmazonawsBedrockagentAmazonbedrockagentbuildtimelambdaState {
    /// One `ListIngestionJobs` page: the jobs of this knowledge base's data
    /// source that every filter admits, in the order `sort_by` names and from
    /// the position `cursor` names, at most `page_size` of them, plus the token
    /// to resume from when more remain.
    ///
    /// Only the addressed data source's jobs are reported, whatever their
    /// status: a data source that has run none reports an empty listing, and a
    /// data source the store does not hold has nothing to enumerate — which the
    /// caller refuses as a missing resource before asking.
    ///
    /// `page_size` is a page the caller has already bounded (the modelled
    /// `maxResults` clamped into `1..=`[`MAX_INGESTION_JOBS_PER_PAGE`]); a page
    /// of nothing is still one job, so no caller can ask for a page that
    /// reports nothing and hands out a token for the same position.
    pub fn page_of_ingestion_jobs(
        &self,
        knowledge_base_id: &str,
        data_source_id: &str,
        filters: &[IngestionJobFilter],
        sort_by: Option<&IngestionJobSortBy>,
        cursor: Option<IngestionJobPageCursor>,
        page_size: usize,
    ) -> (Vec<IngestionJobSummary>, Option<String>) {
        let mut ordered: Vec<&IngestionJobRecord> = self
            .ingestion_jobs
            .values()
            .filter(|record| {
                record.knowledge_base_id == knowledge_base_id
                    && record.data_source_id == data_source_id
            })
            .filter(|record| {
                filters
                    .iter()
                    .all(|filter| record.admitted_by(filter))
            })
            .collect();

        let sort_on_status =
            sort_by.is_some_and(|sort_by| sort_by.attribute == SORT_BY_STATUS);
        if sort_on_status {
            ordered.sort_by(|left, right| left.status_key().cmp(&right.status_key()));
        } else {
            ordered.sort_by(|left, right| left.started_at_key().cmp(&right.started_at_key()));
        }
        if sort_by.is_some_and(|sort_by| sort_by.order == SORT_ORDER_DESCENDING) {
            ordered.reverse();
        }

        let reported = cursor.map_or(0, |cursor| cursor.reported);
        let remaining = ordered.len().saturating_sub(reported);
        let page: Vec<&IngestionJobRecord> = ordered
            .into_iter()
            .skip(reported)
            .take(page_size.max(1))
            .collect();
        let next_token = (remaining > page.len())
            .then(|| {
                IngestionJobPageCursor::after(reported + page.len())
                    .map(IngestionJobPageCursor::token)
            })
            .flatten();
        (
            page.iter().map(|record| record.to_summary()).collect(),
            next_token,
        )
    }
}
