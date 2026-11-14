// SPDX-License-Identifier: CC0-1.0

//! The AWS X-Ray GROUP a stack declares: `AWS::XRay::Group`, created in X-Ray itself
//! through that service's own `CreateGroup`, read back through `GetGroup` and removed by
//! `DeleteGroup`.
//!
//! One file of [`super`]'s concern, beside the sampling-rule arms the same service owns
//! ([`super::platform_services`]): the two types are provisioned through different calls,
//! and a group's identity is an ARN that service draws per group rather than a name any
//! rule could compute, so the group's arms live together here.

use super::*;

/// The URI bindings of the three X-Ray calls a group deployment makes — `POST /CreateGroup`,
/// `POST /GetGroup` and `POST /DeleteGroup`
/// (`smithy_query(operation="CreateGroup,GetGroup,DeleteGroup")`).
pub(super) const XRAY_CREATE_GROUP_URI: &str = "/CreateGroup";
pub(super) const XRAY_GET_GROUP_URI: &str = "/GetGroup";
pub(super) const XRAY_DELETE_GROUP_URI: &str = "/DeleteGroup";

/// The member of a group that NAMES it: "the case-sensitive name of the group"
/// (`CreateGroup$GroupName`, `@length(min: 1, max: 32)`), which is also the property the
/// type declares it under.
pub(super) const XRAY_GROUP_NAME: &str = "GroupName";

/// The member that carries the ARN X-Ray MINTED for the group (`Group$GroupARN`), which is
/// this type's identity and its one published `Fn::GetAtt` attribute.
pub(super) const XRAY_GROUP_ARN: &str = "GroupARN";

/// The member a `CreateGroup`, a `GetGroup` and a `DeleteGroup` answer carries the group in.
pub(super) const XRAY_GROUP_MEMBER: &str = "Group";

/// The `AWS::XRay::Group` properties beside the name and the tags that are members of
/// `CreateGroup`, as (property, member).
///
/// Source: `CreateGroup`'s input members in X-Ray's own model (`GroupName`,
/// `FilterExpression`, `InsightsConfiguration`, `Tags`) against the property names a
/// CloudFormation template spells — which that service spells identically, so nothing is
/// re-cased here. The name is not here because it is the one member CloudFormation decides
/// ([`group_request`]), and the tags because they are a set the declaration and the stack
/// both contribute to ([`create_xray_group`]).
pub(super) const XRAY_GROUP_MEMBERS: &[(&str, &str)] = &[
    ("FilterExpression", "FilterExpression"),
    ("InsightsConfiguration", "InsightsConfiguration"),
];

/// Every property the type publishes, which is what a declaration may state: a property no
/// arm here maps onto `CreateGroup`'s request is refused rather than dropped silently.
pub(super) const XRAY_GROUP_PROPERTIES: &[&str] = &[
    XRAY_GROUP_NAME,
    "FilterExpression",
    "InsightsConfiguration",
    "Tags",
];

/// Create the group an `AWS::XRay::Group` declares, and report the `GroupARN` X-Ray MINTED
/// for it — so a client that deployed the stack and then calls `GetGroup`, or filters
/// `GetTraceSummaries` by the group, reaches the group the template described rather than
/// one that was never created.
///
/// The group is created under the name CloudFormation decided ([`declared_name`] — the
/// declared `GroupName`, or the `<stack>-<logical id>-<unique id>` name it generated,
/// fitted to that member's own 32-character bound by the naming rules), carrying the
/// filter expression and the insights configuration the declaration states under the member
/// names `CreateGroup` takes them as. X-Ray's own validation is what judges those values —
/// a filter expression it refuses leaves the stack `CREATE_FAILED` rather than a group
/// filtering differently from the template.
///
/// The group carries the tags the declaration asks for beside the ones CloudFormation gives
/// the resource ([`tags_of`]), as the `{Key, Value}` list `CreateGroup`'s own `Tags` member
/// takes.
///
/// What comes back is the ARN that service minted, which no naming rule could compute: it
/// is this resource's physical id ([`super::template::identity_is_service_assigned`] names
/// the type) and its one published `Fn::GetAtt` attribute, so both are reported off the
/// create's answer.
pub(super) async fn create_xray_group(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    resource: &StoredResource,
    propagated: &[(String, String)],
) -> Result<Created, Refusal> {
    refuse_unmapped_properties(resource, XRAY_GROUP_PROPERTIES)?;
    let mut request = group_request(&declared_name(resource), &resource.properties);
    let tags = tags_of(&resource.properties, propagated);
    if !tags.is_empty() {
        request.insert("Tags".to_string(), tags_as_list(&tags, UPPER_CASED_TAG));
    }
    let reported = call_xray_group(ctx, region, XRAY_CREATE_GROUP_URI, &Value::Object(request))
        .await?;
    let created = reported.get(XRAY_GROUP_MEMBER).cloned().unwrap_or(Value::Null);
    let Some(group_arn) = reported_text(&created, XRAY_GROUP_ARN) else {
        // The create answered 2xx without the ARN its output models. Nothing addresses a
        // group by an identity nothing minted, so this is reported as a failure rather than
        // recorded as a resource with a physical id this module invented.
        return Err(Refusal {
            code: UNIDENTIFIED_FAILURE.to_string(),
            message: format!("CreateGroup answered no {XRAY_GROUP_ARN}"),
        });
    };
    let mut attributes = BTreeMap::new();
    attributes.insert(XRAY_GROUP_ARN.to_string(), group_arn.clone());
    Ok(Created {
        physical_resource_id: Some(group_arn),
        attributes,
    })
}

/// Delete the group a stack created, addressed the way X-Ray addresses one
/// ([`xray_group_handle`]).
///
/// A group X-Ray no longer holds is already in the state the delete asks for. That service
/// answers every client rejection of this call under ONE class, so the code alone does not
/// say WHICH rejection it was: a refusal is confirmed by reading the group back
/// ([`held_xray_group`]), exactly as [`super::platform_services::delete_sampling_rule`]
/// confirms one, and only a group that read no longer holds is treated as already deleted.
pub(super) async fn delete_xray_group(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    resource: &StoredResource,
) -> Result<(), Refusal> {
    let refusal = match call_xray_group(
        ctx,
        region,
        XRAY_DELETE_GROUP_URI,
        &Value::Object(group_handle_request(resource)),
    )
    .await
    {
        Ok(_) => return Ok(()),
        Err(refusal) => refusal,
    };
    if refusal.code != XRAY_INVALID_REQUEST {
        return Err(refusal);
    }
    match held_xray_group(ctx, region, resource).await? {
        // The group is still there, so the delete really was refused.
        Some(_) => Err(refusal),
        None => Ok(()),
    }
}

/// The group's configuration as X-Ray reports it, for drift detection, under the property
/// names the type declares — so a declared member is compared against the member of the
/// same name that service answers with.
///
/// A group that read no longer holds was deleted, which for a READ is what
/// [`Provisioner::actual_configuration`] reports as `DELETED`.
///
/// `Tags` is not reported: the type publishes them as a `[{Key, Value}]` list, `GetGroup`
/// carries none, and a property the actual document does not carry is not evidence of
/// anything ([`super::drift`]) — so a group's tags are never read as drift rather than
/// compared against a set this read cannot see.
pub(super) async fn describe_xray_group(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    resource: &StoredResource,
) -> Result<Option<Value>, Refusal> {
    let Some(group) = held_xray_group(ctx, region, resource).await? else {
        return Ok(None);
    };
    let mut members = vec![(XRAY_GROUP_NAME, XRAY_GROUP_NAME)];
    members.extend_from_slice(XRAY_GROUP_MEMBERS);
    Ok(Some(reported_as_properties(&group, &members)))
}

/// The group this resource names, as X-Ray's own `GetGroup` reports it, or `None` for a
/// group that service does not hold.
///
/// X-Ray answers every client rejection of the read under one class
/// ([`XRAY_INVALID_REQUEST`]), which is what it answers for a group it does not hold, so
/// that refusal is read as "no such group" and every other refusal is reported.
pub(super) async fn held_xray_group(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    resource: &StoredResource,
) -> Result<Option<Value>, Refusal> {
    match call_xray_group(
        ctx,
        region,
        XRAY_GET_GROUP_URI,
        &Value::Object(group_handle_request(resource)),
    )
    .await
    {
        Ok(answered) => Ok(answered.get(XRAY_GROUP_MEMBER).cloned()),
        Err(refusal) if refusal.code == XRAY_INVALID_REQUEST => Ok(None),
        Err(refusal) => Err(refusal),
    }
}

/// One `CreateGroup` request: the `GroupName` CloudFormation decided, plus the members
/// `properties` declares ([`XRAY_GROUP_MEMBERS`]).
pub(super) fn group_request(name: &str, properties: &Value) -> Map<String, Value> {
    let mut request = Map::new();
    request.insert(
        XRAY_GROUP_NAME.to_string(),
        Value::String(name.to_string()),
    );
    if let Some(declared) = properties.as_object() {
        copy_members(declared, XRAY_GROUP_MEMBERS, &mut request);
    }
    request
}

/// The request a call on this resource's group is addressed by: the one member
/// [`xray_group_handle`] names, carrying that handle.
pub(super) fn group_handle_request(resource: &StoredResource) -> Map<String, Value> {
    let (member, selector) = xray_group_handle(resource);
    let mut request = Map::new();
    request.insert(member.to_string(), Value::String(selector.to_string()));
    request
}

/// The member a call on this resource's group addresses it by, and the value to address it
/// with: the `GroupARN` X-Ray minted, which is this type's physical id once its create went
/// through, and otherwise the `GroupName` the resource carries — `GetGroup` and
/// `DeleteGroup` each take one or the other.
pub(super) fn xray_group_handle(resource: &StoredResource) -> (&'static str, &str) {
    let identity = resource.physical_resource_id.as_str();
    if identity.starts_with("arn:") {
        return (XRAY_GROUP_ARN, identity);
    }
    (XRAY_GROUP_NAME, identity)
}

/// Call one group operation of AWS X-Ray on the `restJson1` wire its model declares: a POST
/// to the operation's own URI, carrying the request document.
pub(super) async fn call_xray_group(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    uri: &str,
    request: &Value,
) -> Result<Value, Refusal> {
    call_rest_json(ctx, XRAY_SIGNING_NAME, region, "POST", uri, Some(request)).await
}
