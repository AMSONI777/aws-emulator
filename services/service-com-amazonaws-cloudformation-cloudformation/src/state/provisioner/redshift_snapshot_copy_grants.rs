// SPDX-License-Identifier: CC0-1.0

//! The per-type provisioning arm of Amazon Redshift's SNAPSHOT COPY GRANT: the grant an
//! `AWS::Redshift::SnapshotCopyGrant` declares. One file of [`super`]'s per-type arms,
//! dispatched to by its `Provisioner`.
//!
//! "Ref returns the snapshot copy grant name", and the type states that name itself
//! (`SnapshotCopyGrantName`, which the conventional `<last segment>Name` reading of
//! `super::template::physical_name` finds), so the resource's physical id is the name the
//! template asked for and the grant is created in Amazon Redshift under exactly it. That is
//! the handle every call of that service on a grant takes — `DescribeSnapshotCopyGrants` and
//! `DeleteSnapshotCopyGrant` both address one by its name — so the name a stack publishes
//! resolves in the service that owns the resource.
//!
//! The type's remaining properties are `CreateSnapshotCopyGrant`'s own members
//! ([`CREATE_SNAPSHOT_COPY_GRANT_MEMBERS`]): the `KmsKeyId` the grant permits Amazon Redshift
//! to encrypt copied snapshots with, and the tag list this arm merges with the tags
//! CloudFormation propagates. Neither of those can be changed on a grant that exists — that
//! service publishes no modify for one at all — so a declaration restating the key is refused
//! rather than silently dropped ([`update_snapshot_copy_grant`]).

use super::*;

/// `AWS::Redshift::SnapshotCopyGrant`: the grant that "permits Amazon Redshift to use an
/// encrypted symmetric key from Key Management Service (KMS) to encrypt copied snapshots in a
/// destination region", which `CreateSnapshotCopyGrant` creates under the name the
/// declaration states, `DescribeSnapshotCopyGrants` reports and `DeleteSnapshotCopyGrant`
/// removes.
pub(crate) const REDSHIFT_SNAPSHOT_COPY_GRANT: &str = "AWS::Redshift::SnapshotCopyGrant";

/// The error code Amazon Redshift answers for a snapshot copy grant it does not hold:
/// `SnapshotCopyGrantNotFoundFault`'s own `awsQueryError` code
/// (`smithy_query(query="operation", operation="DeleteSnapshotCopyGrant")`), which is what an
/// awsQuery client branches on.
const SNAPSHOT_COPY_GRANT_NOT_FOUND: &str = "SnapshotCopyGrantNotFoundFault";

/// The members `CreateSnapshotCopyGrant` takes, from Amazon Redshift's own model
/// (`smithy_query(query="operation", operation="CreateSnapshotCopyGrant")`), with the tag
/// list's element name from its list shape's member `@xmlName`
/// (`smithy_query(query="shape", shape="TagList")`).
///
/// This is the catalogue the declaration of the type is walked against: its `KmsKeyId` is
/// that member's own name, so a property the catalogue does not carry is refused rather than
/// dropped ([`query_members`]).
const CREATE_SNAPSHOT_COPY_GRANT_MEMBERS: &[(&str, QueryMember)] = &[
    ("KmsKeyId", QueryMember::Scalar),
    ("SnapshotCopyGrantName", QueryMember::Scalar),
    ("Tags", QueryMember::List("Tag")),
];

/// The properties of the type the walk over the declaration does NOT turn into a create
/// member: the name this arm pushes (it is the resource's physical id) and the tag list this
/// arm merges with the ones CloudFormation propagates.
const SNAPSHOT_COPY_GRANT_PROPERTIES_NOT_SENT: &[&str] = &["SnapshotCopyGrantName", "Tags"];

/// The property of the type Amazon Redshift fixes when it makes the grant: the key the grant
/// permits it to use. That service publishes no call that re-points an existing grant at
/// another key — a grant IS the permission over one key — so a declaration restating it asks
/// for a different grant.
const SNAPSHOT_COPY_GRANT_CREATE_ONLY_PROPERTIES: &[&str] = &["KmsKeyId"];

/// Create the snapshot copy grant an `AWS::Redshift::SnapshotCopyGrant` declares, under the
/// name the declaration states — this resource's physical id, which is what its `Ref`
/// returns.
///
/// The grant is created in the service that OWNS it, so the `KmsKeyId` the declaration names
/// is resolved by Amazon Redshift against Key Management Service exactly as it is for a
/// client's own call: a value that names no readable key is that service's refusal, which
/// fails the resource and rolls the stack back rather than publishing a grant nothing holds.
/// The type publishes no `Fn::GetAtt` attribute, so the grant's name is the whole of what the
/// stack publishes for it.
pub(crate) async fn create_snapshot_copy_grant(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    resource: &StoredResource,
    propagated: &[(String, String)],
) -> Result<Created, Refusal> {
    let mut parameters = query_members(
        &resource.properties,
        CREATE_SNAPSHOT_COPY_GRANT_MEMBERS,
        // Every property of this type is its member's own name.
        &[],
        SNAPSHOT_COPY_GRANT_PROPERTIES_NOT_SENT,
        REDSHIFT_SNAPSHOT_COPY_GRANT,
    )?;
    parameters.push((
        "SnapshotCopyGrantName".to_string(),
        resource.physical_resource_id.clone(),
    ));
    push_tag_list(
        &mut parameters,
        "Tags",
        "Tag",
        &tags_of(&resource.properties, propagated),
    );
    call_query(
        ctx,
        REDSHIFT_SIGNING_NAME,
        region,
        REDSHIFT_API_VERSION,
        "CreateSnapshotCopyGrant",
        &parameters,
    )
    .await?;
    Ok(Created::attributes(BTreeMap::new()))
}

/// Apply a CHANGED declaration of the type to the grant the stack already has.
///
/// A grant has nothing Amazon Redshift can change on it: the name is its identity and the key
/// is the permission itself, and that service publishes no modify for a grant at all. A
/// declaration that states the KEY differently is therefore REFUSED rather than quietly
/// dropped — AWS applies such a change by replacing the grant, and this emulator creates no
/// replacement, so the stack never reports a grant permitting a key other than the one its
/// declaration asks for. A declaration whose only change is its tags reaches this with
/// nothing to do: the tag set travels on its own ([`Provisioner::retag`]).
/// Nothing is asked of Amazon Redshift for a change it can make, so this arm takes neither a
/// context nor a Region: what it decides is whether the change is one a grant that exists can
/// take at all.
pub(crate) fn update_snapshot_copy_grant(
    resource: &StoredResource,
    declared: &Value,
) -> Result<Option<Created>, Refusal> {
    if let Some(replaced) = SNAPSHOT_COPY_GRANT_CREATE_ONLY_PROPERTIES
        .iter()
        .find(|property| resource.properties.get(**property) != declared.get(**property))
    {
        return Err(Refusal {
            code: NOT_IMPLEMENTED.to_string(),
            message: format!(
                "this emulator does not change the {replaced} property of an existing \
                 {REDSHIFT_SNAPSHOT_COPY_GRANT}, which Amazon Redshift answers by replacing \
                 the grant; the resource was left as it is."
            ),
        });
    }
    Ok(Some(Created::attributes(BTreeMap::new())))
}

/// Delete the snapshot copy grant a stack created, addressed by its name — this resource's
/// physical id. A grant Amazon Redshift no longer has (`SnapshotCopyGrantNotFoundFault`) is
/// already in the state the delete asks for.
pub(crate) async fn delete_snapshot_copy_grant(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    physical_resource_id: &str,
) -> Result<(), Refusal> {
    let parameters = vec![(
        "SnapshotCopyGrantName".to_string(),
        physical_resource_id.to_string(),
    )];
    match call_query(
        ctx,
        REDSHIFT_SIGNING_NAME,
        region,
        REDSHIFT_API_VERSION,
        "DeleteSnapshotCopyGrant",
        &parameters,
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(refusal) if refusal.code == SNAPSHOT_COPY_GRANT_NOT_FOUND => Ok(()),
        Err(refusal) => Err(refusal),
    }
}

/// The grant's configuration as Amazon Redshift reports it, for drift detection. A grant it
/// no longer has (`SnapshotCopyGrantNotFoundFault`) was deleted.
///
/// Its scalar members are read the way every other awsQuery record's are, which covers the
/// one property a declaration can drift in under the same name (`KmsKeyId`); `Tags` is
/// reported as a structure list rather than as a scalar, so it takes no part in the
/// comparison — the position every other arm whose tags are reconciled on their own is in,
/// and what [`super::drift`] documents.
pub(crate) async fn describe_snapshot_copy_grant(
    ctx: &smithy_server_runtime::OperationContext<'_>,
    region: &str,
    physical_resource_id: &str,
) -> Result<Option<Value>, Refusal> {
    let parameters = vec![(
        "SnapshotCopyGrantName".to_string(),
        physical_resource_id.to_string(),
    )];
    match call_query(
        ctx,
        REDSHIFT_SIGNING_NAME,
        region,
        REDSHIFT_API_VERSION,
        "DescribeSnapshotCopyGrants",
        &parameters,
    )
    .await
    {
        Ok(answered) => Ok(Some(Value::Object(xml_scalar_children(
            &answered,
            "SnapshotCopyGrant",
        )))),
        Err(refusal) if refusal.code == SNAPSHOT_COPY_GRANT_NOT_FOUND => Ok(None),
        Err(refusal) => Err(refusal),
    }
}
