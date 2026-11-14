// SPDX-License-Identifier: CC0-1.0

//! The DELIVERY LEG of a vended-log pipeline: which deliveries carry the logs one sending
//! resource produces into a log group, and how each of them writes one record.
//!
//! The three control-plane calls a client makes — `PutDeliverySource` ("a logical object that
//! represents the resource that is actually sending the logs"), `PutDeliveryDestination` ("a
//! logical object that represents the actual delivery destination") and `CreateDelivery` ("a
//! delivery [...] pairing exactly one delivery source and one delivery destination") — wire up
//! a pipeline this service holds but another service FEEDS: the records travel from the
//! resource the source names. So the sending service needs one question answered, and this
//! module is where it is answered: for the resource it just produced a log record about, which
//! deliveries carry that record, into which log group, and under which record layout.
//!
//! The answer is read from this service's OWN store — the delivery sources, destinations and
//! deliveries the three calls above wrote — so a client that built the pipeline through the
//! API gets records, and a client that built nothing gets none. Nothing here writes: the
//! sender puts the record in the group through the one vended-logs write
//! ([`service_common::cloudwatch_logs::delivered`]), which is the same path every other
//! vended-logs record in this tree takes and the one `FilterLogEvents` reads back.
//!
//! # Which pipeline a resource's records travel
//!
//! A delivery source, a delivery destination and a delivery are REGIONAL resources
//! ([`super::RegionalKey`]), so the pipeline of one resource lives in one Region's endpoint:
//! the Region a source for it can be created in at all ([`super::delivery_source_required_region`]
//! pins it for a global sender), and otherwise the Region the resource's own ARN names. A
//! source matches when it REPRESENTS the resource — its `resourceArns` holds that ARN and its
//! `logType` is the type being sent — which is the same reading `PutDeliverySource` refuses a
//! duplicate by ([`super::ComAmazonawsCloudwatchlogsLogs20140328State::delivery_source_representing`]).
//! Each delivery naming such a source is one pipeline, and a delivery whose destination is a
//! log group ([`CWL_DELIVERY_DESTINATION_TYPE`]) is one THIS module resolves; a delivery to a
//! bucket, a delivery stream or a trace destination is left to the service that owns it.
//!
//! # What one record looks like
//!
//! A delivery carries "the list of record fields to be delivered to the destination, in order"
//! and, for the text formats, "the field delimiter [...] used between record fields" — both
//! already resolved to what the delivery will deliver under, defaults included
//! ([`super::DeliveryRecord::resolve_configuration`]). So a record is the delivery's own field
//! list, in its own order, rendered in its destination's `outputFormat`: the structured format
//! ([`STRUCTURED_OUTPUT_FORMAT`]) as one JSON object of field name to value, and the text
//! formats ([`DELIMITED_OUTPUT_FORMATS`]) as the values joined by the delivery's delimiter.
//! The VALUES are the sending service's: this module asks it for one field at a time and
//! renders what it answers, so nothing about the request a record describes is invented here.

use super::*;

/// One delivery that carries a sending resource's vended logs into a CloudWatch Logs log
/// group: where its records go, and the configuration they are written under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogGroupDelivery {
    /// `Delivery$id` — which delivery wrote the record, for the sender's own tracing.
    pub delivery_id: String,
    /// `DeliverySource$name` — the source this delivery is paired with.
    pub delivery_source_name: String,
    /// The name of the log group the destination's `destinationResourceArn` names.
    pub log_group: String,
    /// The Region that log group's ARN names, which is the endpoint the write is made on.
    pub region: String,
    /// `DeliveryDestination$outputFormat` — "the format of the logs that are sent to this
    /// delivery destination", defaulted to the structured format for a destination that
    /// states none, which is the one format a log-group destination receives.
    pub output_format: String,
    /// `Delivery$recordFields`, as the delivery will deliver them: in order, defaults
    /// included.
    pub record_fields: Vec<String>,
    /// `Delivery$fieldDelimiter`, as the delivery will deliver under it.
    pub field_delimiter: String,
}

impl LogGroupDelivery {
    /// The record this delivery writes for one thing the sender logged, with `value` asked for
    /// each of its record fields in turn.
    ///
    /// The field list and its order are the delivery's ([`Self::record_fields`]); the
    /// encoding is its destination's `outputFormat`. A field the sender has no value for is
    /// whatever the sender answers for it — the placeholder its own records carry — never a
    /// value composed here.
    #[must_use]
    pub fn record(&self, value: impl Fn(&str) -> String) -> String {
        if self.output_format == STRUCTURED_OUTPUT_FORMAT {
            let mut record = String::from("{");
            for (position, field) in self.record_fields.iter().enumerate() {
                if position > 0 {
                    record.push(',');
                }
                record.push_str(&json_string(field));
                record.push(':');
                record.push_str(&json_string(&value(field)));
            }
            record.push('}');
            return record;
        }
        self.record_fields
            .iter()
            .map(|field| value(field))
            .collect::<Vec<String>>()
            .join(&self.field_delimiter)
    }
}

/// One JSON string literal, escaped as JSON escapes one, so a field name or a value carrying a
/// quote, a backslash or a control character cannot break the record that holds it.
fn json_string(value: &str) -> String {
    ::serde_json::Value::String(value.to_string()).to_string()
}

/// Every delivery that carries `log_type` logs of the resource `resource_arn` names into a log
/// group.
///
/// The pipeline is read from this service's own store in the shared engine, so what a sender
/// gets back is what the account really created through `PutDeliverySource`,
/// `PutDeliveryDestination` and `CreateDelivery`. The answer is EMPTY — nothing is delivered —
/// for each of: an emulator with no CloudWatch Logs mounted, an account that wired no source
/// for this resource and log type, a source no delivery pairs, a delivery whose destination is
/// not a log group, a destination whose `destinationResourceArn` names no log group of a Region,
/// and a delivery that carries no record field (there being no record to write for it).
///
/// Takes no lock of the CALLER's service: it locks this service's store for the read and
/// releases it before answering, so a sender resolves its pipeline with its own store free and
/// then makes the write.
#[must_use]
pub fn log_group_deliveries<Eng: Send + Sync + 'static>(
    engine: &Eng,
    resource_arn: &str,
    log_type: &str,
) -> Vec<LogGroupDelivery> {
    let Some(region) = delivery_pipeline_region(resource_arn) else {
        return Vec::new();
    };
    let Some(state) = super::service_state(engine) else {
        return Vec::new();
    };
    let store = state.lock();
    // Which SOURCES represent this resource for this log type: a source's `resourceArns`
    // "contains the ARN of the Amazon Web Services resource that sends logs and is represented
    // by this delivery source", and its `logType` is "the type of log that the source is
    // sending".
    let sources: Vec<&str> = store
        .delivery_sources_in(&region)
        .filter(|source| {
            source.log_type == log_type
                && source
                    .resource_arns
                    .iter()
                    .any(|named| named == resource_arn)
        })
        .map(|source| source.name.as_str())
        .collect();
    if sources.is_empty() {
        return Vec::new();
    }
    store
        .deliveries_in(&region)
        .filter(|delivery| {
            sources
                .iter()
                .any(|name| *name == delivery.delivery_source_name)
        })
        .filter_map(|delivery| {
            let destination =
                store.delivery_destination_by_arn(&region, &delivery.delivery_destination_arn)?;
            if destination.delivery_destination_type.as_deref()
                != Some(CWL_DELIVERY_DESTINATION_TYPE)
            {
                return None;
            }
            let destination_arn = destination.destination_resource_arn.as_deref()?;
            let log_group =
                ::service_common::cloudwatch_logs::log_group_of_arn(destination_arn)?;
            // The group lives where its OWN ARN says, which is the endpoint the records are
            // written on — not the Region the pipeline's logical resources are held in. The
            // label is held to the grammar a Region is written in before it addresses an
            // endpoint ([`service_common::arn::region_of`]), so an ARN naming no log group of
            // a Region addresses no group and nothing is written for it.
            let destination_region = ::service_common::arn::region_of(
                destination_arn,
                CLOUDWATCH_LOGS_VENDOR,
            )?;
            let record_fields = delivery.record_fields.clone().unwrap_or_default();
            if record_fields.is_empty() {
                return None;
            }
            Some(LogGroupDelivery {
                delivery_id: delivery.id.clone(),
                delivery_source_name: delivery.delivery_source_name.clone(),
                log_group: log_group.to_string(),
                region: destination_region.to_string(),
                output_format: destination
                    .output_format
                    .clone()
                    .unwrap_or_else(|| STRUCTURED_OUTPUT_FORMAT.to_string()),
                record_fields,
                field_delimiter: delivery.field_delimiter.clone().unwrap_or_default(),
            })
        })
        .collect()
}

/// The Region whose endpoint holds the delivery pipeline of `resource_arn`: the one Region a
/// delivery source for it can be created in at all where the resource pins one
/// ([`super::delivery_source_required_region`]), and the Region the resource's own ARN names
/// otherwise.
///
/// `None` for a value that is no ARN, and for a regional resource whose ARN names no Region:
/// neither addresses an endpoint a pipeline could have been created through.
fn delivery_pipeline_region(resource_arn: &str) -> Option<String> {
    if let Some(pinned) = delivery_source_required_region(resource_arn) {
        return Some(pinned.to_string());
    }
    ::service_common::arn::parse(resource_arn)
        .map(|arn| arn.region)
        .filter(|region| !region.is_empty())
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A delivery whose records are JSON objects of the fields it carries, in its own order.
    fn structured(fields: &[&str]) -> LogGroupDelivery {
        LogGroupDelivery {
            delivery_id: "0000000000000001".to_string(),
            delivery_source_name: "sender".to_string(),
            log_group: "/vended/one".to_string(),
            region: "us-east-1".to_string(),
            output_format: STRUCTURED_OUTPUT_FORMAT.to_string(),
            record_fields: fields.iter().map(|field| (*field).to_string()).collect(),
            field_delimiter: String::new(),
        }
    }

    #[test]
    fn a_structured_record_is_one_json_object_of_the_fields_in_order() {
        let delivery = structured(&["time", "status", "path"]);
        let record = delivery.record(|field| match field {
            "time" => "01:42:39".to_string(),
            "status" => "200".to_string(),
            _ => "/probe.txt".to_string(),
        });
        let expected = r#"{"time":"01:42:39","status":"200","path":"/probe.txt"}"#;
        assert_eq!(
            record, expected,
            "case the three fields in order: expected {expected}, got {record}"
        );
        let parsed: ::serde_json::Value = ::serde_json::from_str(&record)
            .unwrap_or_else(|error| panic!("the record is JSON ({error}): {record}"));
        assert_eq!(
            parsed["status"], "200",
            "case reading the record back: expected the status field, got {parsed}"
        );
    }

    #[test]
    fn a_value_carrying_the_framing_of_the_format_is_escaped_rather_than_breaking_the_record() {
        let delivery = structured(&["agent"]);
        let record = delivery.record(|_field| "a \"quoted\"\nagent".to_string());
        let parsed: ::serde_json::Value = ::serde_json::from_str(&record)
            .unwrap_or_else(|error| panic!("the record is JSON ({error}): {record}"));
        assert_eq!(
            parsed["agent"], "a \"quoted\"\nagent",
            "case a value carrying a quote and a line break: expected it read back whole, got \
             {parsed}"
        );
    }

    #[test]
    fn a_text_record_joins_the_values_with_the_deliverys_own_delimiter() {
        for (case, format, delimiter, expected) in [
            ("plain, tab delimited", "plain", "\t", "01:42:39\t200"),
            ("w3c, space delimited", "w3c", " ", "01:42:39 200"),
            ("raw, comma delimited", "raw", ",", "01:42:39,200"),
            ("no delimiter at all", "plain", "", "01:42:39200"),
        ] {
            let delivery = LogGroupDelivery {
                output_format: format.to_string(),
                field_delimiter: delimiter.to_string(),
                ..structured(&["time", "status"])
            };
            let record = delivery.record(|field| match field {
                "time" => "01:42:39".to_string(),
                _ => "200".to_string(),
            });
            assert_eq!(
                record, expected,
                "case {case}: expected {expected:?}, got {record:?}"
            );
        }
    }

    #[test]
    fn a_pipeline_is_looked_for_where_the_sending_resource_pins_it() {
        for (case, resource_arn, expected) in [
            (
                "a global sender, pinned to the partition's one endpoint",
                "arn:aws:cloudfront::000000000000:distribution/E1EXAMPLE",
                Some("us-east-1"),
            ),
            (
                "a regional sender, in its own Region",
                "arn:aws:elasticloadbalancing:eu-west-2:000000000000:loadbalancer/app/one/abc",
                Some("eu-west-2"),
            ),
            (
                "a resource whose ARN names no Region and whose service pins none",
                "arn:aws:s3:::vended-logs",
                None,
            ),
            ("not an ARN at all", "E1EXAMPLE", None),
        ] {
            let got = delivery_pipeline_region(resource_arn);
            assert_eq!(
                got.as_deref(),
                expected,
                "case {case}: expected {expected:?} for {resource_arn:?}, got {got:?}"
            );
        }
    }
}
