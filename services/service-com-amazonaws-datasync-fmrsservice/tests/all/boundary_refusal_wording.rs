// SPDX-License-Identifier: CC0-1.0

//! How this service words a request its own modelled constraints refuse, before any handler
//! runs.
//!
//! RULE: a refusal decided at the boundary is still answered the way DataSync answers one.
//! Four parts of that wording are this service's own, and each is checked over a table that
//! spans what it generalises over:
//!
//! * a value that is not a well-formed ARN of one of THIS service's resources is the one
//!   boundary refusal that is a modelled client error: `InvalidRequestException` with the
//!   parameter class in `errorCode` and a sentence naming the value, and never the raw
//!   expression the value had to match. An ARN belonging to ANOTHER service is not that
//!   refusal and keeps the validation layer's own clause;
//! * a `@required` member carrying a nested configuration STRUCTURE that the request omitted
//!   is named by a sentence of its own, while a required member holding a value keeps the
//!   clause about that value's absence;
//! * an enumerated type's admissible values are listed in the order the table holding them
//!   is walked — a property of the TYPE, so one enum is listed alike in every operation that
//!   carries it, and not in the order the model declares it; and
//! * a clause about a bounded LIST quotes the elements the request submitted, not a count of
//!   them.
//!
//! Every case goes through the same front door a client uses: `POST /` with
//! `X-Amz-Target: FmrsService.<Operation>` and an `awsJson1_1` body, dispatched by the
//! multi-service router. Nothing reaches into the state struct.

use std::sync::Arc;

use serde_json::{json, Value};
use smithy_server_runtime::MultiServiceRouter;

/// The region every request in this suite signs for.
const SIGNED_REGION: &str = "us-west-2";

/// The class a refusal of a parameter value this service will not take carries.
const INVALID_PARAMETER: &str = "InvalidParameter";

/// The code the validation layer in front of this service answers a constraint refusal
/// with — not one of the shapes this service's model declares, because the refusal is that
/// layer's rather than one of the service's own modelled failures.
const VALIDATION_EXCEPTION: &str = "ValidationException";

/// A router with just this service mounted on a fresh engine.
fn service() -> MultiServiceRouter {
    let engine: Arc<engine::InMemoryEngine> = Arc::new(engine::InMemoryEngine::new());
    let mut router = MultiServiceRouter::new();
    router.set_request_authentication(false);
    router.register_service(
        service_com_amazonaws_datasync_fmrsservice::EmulatedService::new(engine),
    );
    router
}

/// One `awsJson1_1` call, returning the HTTP status and the parsed response body.
async fn call(router: &MultiServiceRouter, operation: &str, body: Value) -> (u16, Value) {
    let request = http::Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amz-target", format!("FmrsService.{operation}"))
        .header(
            "authorization",
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIDDATASYNCTEST/20260101/{SIGNED_REGION}\
                 /datasync/aws4_request, SignedHeaders=host;x-amz-target, Signature=00"
            ),
        )
        .body(bytes::Bytes::from(
            serde_json::to_vec(&body).expect("the request body serializes"),
        ))
        .expect("a well-formed request");

    let response = router.dispatch(request).await;
    let status = response.status().as_u16();
    let payload = response.into_body();
    let parsed = if payload.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&payload)
            .unwrap_or_else(|_| json!({ "__unparsed": String::from_utf8_lossy(&payload) }))
    };
    (status, parsed)
}

/// A refused call's error shape and message: the `__type` reduced to the shape's own name,
/// and the text the body carries.
async fn refusal(router: &MultiServiceRouter, operation: &str, body: Value) -> (Value, String) {
    let (status, parsed) = call(router, operation, body).await;
    assert_eq!(
        status, 400,
        "expected {operation} to answer 400, got {status} with {parsed}"
    );
    let message = parsed["message"].as_str().unwrap_or_default().to_string();
    (parsed, message)
}

/// The shape name a refusal body names itself by, with any namespace dropped.
fn shape_of(parsed: &Value) -> String {
    parsed["__type"]
        .as_str()
        .unwrap_or_default()
        .rsplit('#')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// A well-formed ARN of one of this service's resources, from the account the emulator
/// answers for: `resource` is the ARN's resource part (`location/loc-…`, `task/task-…`).
fn datasync_arn(resource: &str) -> String {
    format!(
        "arn:aws:datasync:{SIGNED_REGION}:{account}:{resource}",
        account = engine::emulator_account_id()
    )
}

/// RULE: a value that is not a well-formed ARN of one of this service's resources is refused
/// as the one modelled client error, with the parameter class in `errorCode` and a sentence
/// naming the value the request sent — never the expression the value had to match.
///
/// The rows differ along what the rule generalises over: which operation was called, which
/// KIND of resource ARN the member carries (location, task, agent, execution, and the
/// ARN that may name any of them), and how the value fails — a resource id of the wrong
/// length, one holding characters the id cannot, the wrong resource kind, a partition that
/// is not a partition, and a value that is no ARN at all.
#[tokio::test]
async fn a_malformed_resource_arn_is_refused_as_an_invalid_parameter() {
    let router = service();
    // (case, operation, member, the value that is not an ARN of this service)
    let rows: [(&str, &str, &str, String); 8] = [
        (
            "a location id too short",
            "DescribeLocationS3",
            "LocationArn",
            datasync_arn("location/loc-zzz"),
        ),
        (
            "a location id holding characters it cannot",
            "DeleteLocation",
            "LocationArn",
            datasync_arn("location/loc-ABCDEFGHIJKLMNOPQ"),
        ),
        (
            "a task id too short",
            "DescribeTask",
            "TaskArn",
            datasync_arn("task/task-0abcdef"),
        ),
        (
            "a task id holding characters a hexadecimal id cannot",
            "DeleteTask",
            "TaskArn",
            datasync_arn("task/task-zzzzzzzzzzzzzzzzz"),
        ),
        (
            "an agent ARN naming a location instead",
            "DescribeAgent",
            "AgentArn",
            datasync_arn("location/loc-0abcdef1234567890"),
        ),
        (
            "an execution ARN with no execution part",
            "DescribeTaskExecution",
            "TaskExecutionArn",
            datasync_arn("task/task-0abcdef1234567890"),
        ),
        (
            "a taggable ARN in a partition that is not one",
            "ListTagsForResource",
            "ResourceArn",
            format!(
                "arn:amazon:datasync:{SIGNED_REGION}:{account}:task/task-0abcdef1234567890",
                account = engine::emulator_account_id()
            ),
        ),
        (
            "a value that is no ARN at all",
            "DescribeLocationS3",
            "LocationArn",
            "loc-0abcdef1234567890".to_string(),
        ),
    ];

    for (case, operation, member, value) in rows {
        let (parsed, message) = refusal(&router, operation, json!({ member: value })).await;
        assert_eq!(
            shape_of(&parsed),
            "InvalidRequestException",
            "case {case:?}: expected the modelled client error from {operation}, got {parsed}"
        );
        assert_eq!(
            parsed["errorCode"].as_str(),
            Some(INVALID_PARAMETER),
            "case {case:?}: expected errorCode {INVALID_PARAMETER:?}, got {parsed}"
        );
        // The shape of an ARN is read ahead of the layer that resolves a DataSync resource,
        // which is the layer that sets the second code member, so this class carries one.
        assert!(
            parsed.get("datasyncErrorCode").is_none(),
            "case {case:?}: this class carries errorCode alone, got {parsed}"
        );
        assert_eq!(
            message,
            format!("Invalid parameter: DataSync ARN ({value}) must match datasync resource regex."),
            "case {case:?}: wrong refusal wording from {operation}"
        );
        assert!(
            !message.contains("^arn:") && !message.contains("satisfy"),
            "case {case:?}: the expression the value had to match is not disclosed, got \
             {message:?}"
        );
    }
}

/// RULE: a value outside the `@pattern` of an ARN belonging to ANOTHER service is not this
/// service's ARN refusal: it keeps the validation layer's own clause, under that layer's
/// code.
///
/// The rows differ along which other service's ARN namespace the member names — IAM, Amazon
/// S3, Amazon EFS and Amazon FSx — so the refusal is keyed on the namespace the broken
/// expression declares rather than on the member being an ARN at all.
#[tokio::test]
async fn an_arn_of_another_service_keeps_the_validation_layers_clause() {
    let router = service();
    // (case, operation, the request, the member path the clause names)
    let rows: [(&str, &str, Value, &str); 4] = [
        (
            "an IAM role ARN",
            "CreateLocationS3",
            json!({
                "S3BucketArn": "arn:aws:s3:::refusal-wording",
                "S3Config": { "BucketAccessRoleArn": "not-a-role-arn" },
            }),
            "s3Config.bucketAccessRoleArn",
        ),
        (
            "an Amazon S3 bucket ARN",
            "CreateLocationS3",
            json!({
                "S3BucketArn": "arn:aws:ec2:::refusal-wording",
                "S3Config": {
                    "BucketAccessRoleArn": format!(
                        "arn:aws:iam::{account}:role/datasync-bucket-access",
                        account = engine::emulator_account_id()
                    ),
                },
            }),
            "s3BucketArn",
        ),
        (
            "an Amazon EFS file system ARN",
            "CreateLocationEfs",
            json!({
                "EfsFilesystemArn": "arn:aws:elasticfilesystem:us-west-2:000000000000:file-system/zzz",
                "Ec2Config": {
                    "SubnetArn": format!(
                        "arn:aws:ec2:{SIGNED_REGION}:{account}:subnet/subnet-0abcdef1234567890",
                        account = engine::emulator_account_id()
                    ),
                    "SecurityGroupArns": [format!(
                        "arn:aws:ec2:{SIGNED_REGION}:{account}:security-group/sg-0abcdef1234567890",
                        account = engine::emulator_account_id()
                    )],
                },
            }),
            "efsFilesystemArn",
        ),
        (
            "an Amazon FSx storage virtual machine ARN",
            "CreateLocationFsxOntap",
            json!({
                "StorageVirtualMachineArn": "arn:aws:fsx:us-west-2:000000000000:storage-virtual-machine/zzz",
                "SecurityGroupArns": [format!(
                    "arn:aws:ec2:{SIGNED_REGION}:{account}:security-group/sg-0abcdef1234567890",
                    account = engine::emulator_account_id()
                )],
                "Protocol": { "Nfs": { "MountOptions": { "Version": "NFS3" } } },
            }),
            "storageVirtualMachineArn",
        ),
    ];

    for (case, operation, body, member_path) in rows {
        let (parsed, message) = refusal(&router, operation, body).await;
        assert_eq!(
            shape_of(&parsed),
            VALIDATION_EXCEPTION,
            "case {case:?}: expected the validation layer's own refusal from {operation}, got \
             {parsed}"
        );
        assert!(
            message.starts_with("1 validation error detected: ")
                && message.contains(&format!("at '{member_path}' failed to satisfy constraint")),
            "case {case:?}: expected the constraint clause for {member_path}, got {message:?}"
        );
        assert!(
            !message.contains("DataSync ARN"),
            "case {case:?}: an ARN of another service is not this service's ARN refusal, got \
             {message:?}"
        );
    }
}

/// RULE: a `@required` member whose target is a nested configuration STRUCTURE is reported by
/// the sentence naming that member, spelled as the model declares it; a required member that
/// holds a value of its own keeps the clause about that value's absence. Both are the
/// validation layer's refusal, under that layer's code.
///
/// The rows differ along what the rule generalises over: three operations whose model
/// declares a required structure member, beside required members of the other kinds — a
/// string and a list — in two of the same operations.
#[tokio::test]
async fn an_omitted_required_configuration_structure_is_named_rather_than_quoted() {
    let router = service();
    /// What the refusal of one omitted member must say.
    enum Expected {
        /// The sentence naming the member the model declares, with no clause at all.
        Names(&'static str),
        /// The validation layer's clause about the absent value, at this member path.
        Clause(&'static str),
    }

    let role_arn = format!(
        "arn:aws:iam::{account}:role/datasync-bucket-access",
        account = engine::emulator_account_id()
    );
    let subnet_arn = format!(
        "arn:aws:ec2:{SIGNED_REGION}:{account}:subnet/subnet-0abcdef1234567890",
        account = engine::emulator_account_id()
    );
    let security_group_arn = format!(
        "arn:aws:ec2:{SIGNED_REGION}:{account}:security-group/sg-0abcdef1234567890",
        account = engine::emulator_account_id()
    );
    let svm_arn = format!(
        "arn:aws:fsx:{SIGNED_REGION}:{account}:storage-virtual-machine/fs-0abcdef1/svm-0abcdef1234567890",
        account = engine::emulator_account_id()
    );

    // (case, operation, the request omitting exactly one required member, what it must say)
    let rows: [(&str, &str, Value, Expected); 6] = [
        (
            "an omitted S3 configuration",
            "CreateLocationS3",
            json!({ "S3BucketArn": "arn:aws:s3:::refusal-wording" }),
            Expected::Names("Must specify S3Config"),
        ),
        (
            "an omitted EC2 configuration",
            "CreateLocationEfs",
            json!({
                "EfsFilesystemArn": format!(
                    "arn:aws:elasticfilesystem:{SIGNED_REGION}:{account}:file-system/fs-0abcdef1",
                    account = engine::emulator_account_id()
                ),
            }),
            Expected::Names("Must specify Ec2Config"),
        ),
        (
            "an omitted file-access protocol",
            "CreateLocationFsxOntap",
            json!({
                "StorageVirtualMachineArn": svm_arn,
                "SecurityGroupArns": [security_group_arn.clone()],
            }),
            Expected::Names("Must specify Protocol"),
        ),
        (
            "an omitted destination location, a required string",
            "CreateTask",
            json!({ "SourceLocationArn": datasync_arn("location/loc-0abcdef1234567890") }),
            Expected::Clause("destinationLocationArn"),
        ),
        (
            "an omitted file system, a required string",
            "CreateLocationEfs",
            json!({
                "Ec2Config": {
                    "SubnetArn": subnet_arn,
                    "SecurityGroupArns": [security_group_arn.clone()],
                },
            }),
            Expected::Clause("efsFilesystemArn"),
        ),
        (
            "an omitted bucket, a required string",
            "CreateLocationS3",
            json!({ "S3Config": { "BucketAccessRoleArn": role_arn } }),
            Expected::Clause("s3BucketArn"),
        ),
    ];

    for (case, operation, body, expected) in rows {
        let (parsed, message) = refusal(&router, operation, body).await;
        assert_eq!(
            shape_of(&parsed),
            VALIDATION_EXCEPTION,
            "case {case:?}: expected the validation layer's own refusal from {operation}, got \
             {parsed}"
        );
        match expected {
            Expected::Names(sentence) => assert_eq!(
                message, sentence,
                "case {case:?}: wrong refusal wording from {operation}"
            ),
            Expected::Clause(member_path) => assert_eq!(
                message,
                format!(
                    "1 validation error detected: Value null at '{member_path}' failed to \
                     satisfy constraint: Member must not be null"
                ),
                "case {case:?}: wrong refusal wording from {operation}"
            ),
        }
    }
}

/// The admissible values of `com.amazonaws.datasync#Operator`, in the order this service
/// lists them.
///
/// The values are the enum's own
/// (`smithy_query(query="shape", shape="Operator")` lists them `Equals`, `NotEquals`, `In`,
/// `LessThanOrEqual`, `LessThan`, `GreaterThanOrEqual`, `GreaterThan`, `Contains`,
/// `NotContains`, `BeginsWith`); the ORDER is the one the table holding them is walked in,
/// which is not the model's declaration order.
const OPERATOR_VALUE_SET: &str = "[In, BeginsWith, NotContains, NotEquals, \
                                  GreaterThanOrEqual, LessThanOrEqual, LessThan, \
                                  GreaterThan, Contains, Equals]";

/// The admissible values of `com.amazonaws.datasync#TaskFilterName`
/// (`smithy_query(query="shape", shape="TaskFilter")`: `LocationId`, `CreationTime`), in the
/// same order — a second type, listed by the same rule and not in declaration order either.
const TASK_FILTER_NAME_VALUE_SET: &str = "[CreationTime, LocationId]";

/// RULE: a value outside an enumerated type is refused with that type's admissible values
/// listed in the order the table holding them is walked, whatever order the model declares
/// them in. The order belongs to the TYPE, so one enum is listed alike wherever it is
/// carried.
///
/// The rows differ along what the rule generalises over: the same enumerated type carried by
/// two different operations and at two different filter positions, and a second enumerated
/// type whose declaration order is likewise not the order it is listed in.
#[tokio::test]
async fn an_enumerated_value_set_is_listed_in_the_services_own_order() {
    let router = service();
    // (case, operation, the request, the member path the clause names, the value it carried,
    //  the value set it must list)
    let rows: [(&str, &str, Value, &str, &str, &str); 4] = [
        (
            "an operator no task filter takes",
            "ListTasks",
            json!({
                "Filters": [
                    { "Name": "LocationId", "Operator": "EQ", "Values": ["loc-0abcdef1234567890"] },
                ],
            }),
            "filters.1.member.operator",
            "EQ",
            OPERATOR_VALUE_SET,
        ),
        (
            "an operator no location filter takes",
            "ListLocations",
            json!({
                "Filters": [
                    { "Name": "LocationType", "Operator": "IS", "Values": ["S3"] },
                ],
            }),
            "filters.1.member.operator",
            "IS",
            OPERATOR_VALUE_SET,
        ),
        (
            "an operator in the second filter of a request",
            "ListTasks",
            json!({
                "Filters": [
                    { "Name": "LocationId", "Operator": "Equals", "Values": ["loc-0abcdef1234567890"] },
                    { "Name": "CreationTime", "Operator": "AFTER", "Values": ["0"] },
                ],
            }),
            "filters.2.member.operator",
            "AFTER",
            OPERATOR_VALUE_SET,
        ),
        (
            "a filter name no task filter takes",
            "ListTasks",
            json!({
                "Filters": [
                    { "Name": "TaskId", "Operator": "Equals", "Values": ["task-0abcdef1234567890"] },
                ],
            }),
            "filters.1.member.name",
            "TaskId",
            TASK_FILTER_NAME_VALUE_SET,
        ),
    ];

    for (case, operation, body, member_path, submitted, value_set) in rows {
        let (parsed, message) = refusal(&router, operation, body).await;
        assert_eq!(
            shape_of(&parsed),
            VALIDATION_EXCEPTION,
            "case {case:?}: expected the validation layer's own refusal from {operation}, got \
             {parsed}"
        );
        assert_eq!(
            message,
            format!(
                "1 validation error detected: Value '{submitted}' at '{member_path}' failed to \
                 satisfy constraint: Member must satisfy enum value set: {value_set}"
            ),
            "case {case:?}: wrong refusal wording from {operation}"
        );
    }
}

/// RULE: a clause about a bounded LIST quotes the elements the request submitted — each
/// structure as its shape's name over the members it carried — rather than a count of them.
///
/// The rows differ along what the rule generalises over: which bounded list member carried
/// the elements, how many it carried, and what each element held.
#[tokio::test]
async fn a_clause_about_a_bounded_list_quotes_the_elements_submitted() {
    let router = service();
    /// One filter rule, as a request writes it.
    fn rule(value: &str) -> Value {
        json!({ "FilterType": "SIMPLE_PATTERN", "Value": value })
    }
    /// The same rule as a clause quotes it.
    fn quoted(value: &str) -> String {
        format!("FilterRule(filterType=SIMPLE_PATTERN, value={value})")
    }

    // (case, the member carrying the list, the values its elements held)
    let rows: [(&str, &str, &[&str]); 4] = [
        ("two exclude rules", "Excludes", &["/a", "/b"]),
        ("three exclude rules", "Excludes", &["/a", "/b", "/c"]),
        ("two include rules", "Includes", &["/in", "/out"]),
        (
            "two exclude rules holding several patterns each",
            "Excludes",
            &["/one|/two", "/three"],
        ),
    ];

    for (case, member, values) in rows {
        let body = json!({
            "SourceLocationArn": datasync_arn("location/loc-0abcdef1234567890"),
            "DestinationLocationArn": datasync_arn("location/loc-1abcdef1234567890"),
            member: values.iter().map(|value| rule(value)).collect::<Vec<Value>>(),
        });
        let (parsed, message) = refusal(&router, "CreateTask", body).await;
        assert_eq!(
            shape_of(&parsed),
            VALIDATION_EXCEPTION,
            "case {case:?}: expected the validation layer's own refusal, got {parsed}"
        );
        let elements: Vec<String> = values.iter().map(|value| quoted(value)).collect();
        assert_eq!(
            message,
            format!(
                "1 validation error detected: Value '[{}]' at '{}' failed to satisfy \
                 constraint: Member must have length less than or equal to 1",
                elements.join(", "),
                member.to_lowercase(),
            ),
            "case {case:?}: wrong refusal wording for {member}"
        );
    }
}
