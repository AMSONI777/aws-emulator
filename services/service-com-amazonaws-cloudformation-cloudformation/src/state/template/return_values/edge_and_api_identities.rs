// SPDX-License-Identifier: CC0-1.0

//! The Amazon CloudFront and Amazon API Gateway resource types a template declares, and the
//! identifiers those two services ASSIGN: a distribution's id and domain name, an origin
//! access control's and identity's ids, and the ids and endpoints API Gateway and API
//! Gateway v2 mint for an api and the resources inside one.
//!
//! One file of [`super`]'s own concern — the per-type return-value catalogue stays THERE, and
//! this holds the type names, the per-type id salts and the derived identifiers of these two
//! services — split out so neither file carries the other's.

use super::*;

/// The `AWS::CloudFront::Distribution` resource type: one CloudFront distribution.
pub const CLOUDFRONT_DISTRIBUTION: &str = "AWS::CloudFront::Distribution";

/// The `AWS::CloudFront::OriginAccessControl` resource type: the origin access control an
/// origin is read through.
pub const CLOUDFRONT_ORIGIN_ACCESS_CONTROL: &str = "AWS::CloudFront::OriginAccessControl";

/// The `AWS::CloudFront::CloudFrontOriginAccessIdentity` resource type: the legacy origin
/// access identity an Amazon S3 bucket policy names by canonical user id.
pub const CLOUDFRONT_ORIGIN_ACCESS_IDENTITY: &str =
    "AWS::CloudFront::CloudFrontOriginAccessIdentity";

/// CloudFront's three policy resource types, each identified by a UUID CloudFront mints.
pub const CLOUDFRONT_CACHE_POLICY: &str = "AWS::CloudFront::CachePolicy";
pub const CLOUDFRONT_ORIGIN_REQUEST_POLICY: &str = "AWS::CloudFront::OriginRequestPolicy";
pub const CLOUDFRONT_RESPONSE_HEADERS_POLICY: &str = "AWS::CloudFront::ResponseHeadersPolicy";

/// The Amazon API Gateway resource types whose published `Ref` is a SERVICE-ASSIGNED id
/// rather than a name a template states: a REST API, a resource of one, and a deployment
/// of one.
pub const APIGATEWAY_REST_API: &str = "AWS::ApiGateway::RestApi";
pub const APIGATEWAY_RESOURCE: &str = "AWS::ApiGateway::Resource";
pub const APIGATEWAY_DEPLOYMENT: &str = "AWS::ApiGateway::Deployment";

/// The Amazon API Gateway resource types that govern ACCESS to a REST API, whose published
/// `Ref` is a SERVICE-ASSIGNED id in the same position: `CreateApiKey`, `CreateAuthorizer`
/// and `CreateUsagePlan` each take no identifier and answer the `id` that service assigned —
/// "Ref returns the API key ID", "Ref returns the authorizer ID", "Ref returns the usage
/// plan ID" — and a `UsagePlanKey`'s own id is the id of the key its create put in the plan
/// ("Ref returns the usage plan key ID"). A template declares a key's or a plan's NAME and
/// an association's members, never any of those ids, and every call on one takes the minted
/// id (`GetApiKey$apiKey`, `GetAuthorizer$authorizerId`, `GetUsagePlan$usagePlanId`), which
/// is why [`identity_is_service_assigned`] names all four.
pub const APIGATEWAY_API_KEY: &str = "AWS::ApiGateway::ApiKey";
pub const APIGATEWAY_AUTHORIZER: &str = "AWS::ApiGateway::Authorizer";
pub const APIGATEWAY_USAGE_PLAN: &str = "AWS::ApiGateway::UsagePlan";
pub const APIGATEWAY_USAGE_PLAN_KEY: &str = "AWS::ApiGateway::UsagePlanKey";

/// `AWS::ApiGateway::VpcLink`: the VPC link a PRIVATE integration reaches a VPC through,
/// whose published `Ref` is a SERVICE-ASSIGNED id in the same position as the types above.
///
/// `CreateVpcLink` takes no identifier and answers the `id` API Gateway assigned — "Ref
/// returns the VPC link ID", which is also this type's one `Fn::GetAtt` attribute
/// (`VpcLinkId`) — and every call on a link takes that id (`GetVpcLink$vpcLinkId`,
/// `DeleteVpcLink$vpcLinkId`), as does the integration that reaches a VPC through it
/// (`Integration$connectionId`). A template declares the link's NAME, never its id, so
/// [`identity_is_service_assigned`] names this type: the identifier in force is the one that
/// service minted ([`crate::state::provisioning::apigateway_rest_api`]).
pub const APIGATEWAY_VPC_LINK: &str = "AWS::ApiGateway::VpcLink";

/// `AWS::ApiGateway::RequestValidator`: the validator a method names in its
/// `requestValidatorId`, which decides whether the request's parameters and its payload are
/// checked before the method's integration is reached — so a stack whose validator exists
/// nowhere deploys a method that validates nothing
/// ([`crate::state::provisioning::apigateway_rest_api`] creates it in API Gateway itself).
///
/// "Ref returns the request validator ID", which is also this type's one `Fn::GetAtt`
/// attribute (`RequestValidatorId`): `CreateRequestValidator`
/// (`POST /restapis/{restApiId}/requestvalidators`) takes no identifier and answers the `id`
/// it assigned, and every call on one takes that id
/// (`GetRequestValidator$requestValidatorId`, `Method$requestValidatorId`). A template
/// declares the validator's NAME and which halves it checks, never its id, which is why
/// [`identity_is_service_assigned`] names this type.
pub const APIGATEWAY_REQUEST_VALIDATOR: &str = "AWS::ApiGateway::RequestValidator";

/// `AWS::ApiGateway::Model`: the data schema a method maps a content type to in its
/// `requestModels`, which is what the validator above validates a payload against — so a
/// stack whose model exists nowhere deploys a method whose body check has no schema
/// ([`crate::state::provisioning::apigateway_rest_api`] creates it in API Gateway itself).
///
/// "Ref returns the model name", which is the `Name` the declaration states — API Gateway
/// keys a model by its name under the api that holds it, and `CreateModel$name` is the
/// identifier every call on one takes (`GetModel$modelName`, `Method$requestModels`) — so
/// neither [`identity_is_service_assigned`] names this type nor does [`return_values`] carry
/// an arm for it: the name the naming rules read off the declaration is the identity in
/// force, and the type publishes no `Fn::GetAtt` attribute.
pub const APIGATEWAY_MODEL: &str = "AWS::ApiGateway::Model";

/// `AWS::ApiGateway::Account`: the account-level settings of the REST control plane — the
/// CloudWatch Logs role API Gateway writes an account's logs under — which a stack really
/// sets in that service ([`crate::state::provisioning::apigateway_rest_api`]).
///
/// "Ref returns the ID for the account", and `Fn::GetAtt` reads the same value as `Id`. The
/// settings are a SINGLETON of the account and Region, so there is no identifier for a
/// caller to state and none for API Gateway to assign — `UpdateAccount` (`PATCH /account`)
/// takes and answers neither — which is why [`identity_is_service_assigned`] does not name
/// this type: the id CloudFormation minted for the resource is the one in force.
pub const APIGATEWAY_ACCOUNT: &str = "AWS::ApiGateway::Account";

/// `AWS::ApiGateway::DomainName`: a custom domain name of the REST control plane, which a
/// stack creates in API Gateway itself ([`super::provisioner`]).
///
/// "Ref returns the domain name" — the name the template states in its own `DomainName`
/// property, which is this type's identifier ([`declared_name_property`]) — while every
/// attribute the type publishes (the CloudFront distribution an edge-optimized domain is
/// served by, the host a regional one is served on, the ARN API Gateway names the domain
/// by) is a value only that service assigns, so each is read off the create's answer rather
/// than computed by the naming rules ([`return_values`] carries no arm for this type).
pub const APIGATEWAY_DOMAIN_NAME: &str = "AWS::ApiGateway::DomainName";

/// `AWS::ApiGateway::BasePathMapping`: the base path of such a custom domain name that one
/// stage of a REST API answers on, which a stack creates in API Gateway itself
/// ([`super::provisioner`]).
///
/// The mapping is addressed by the domain name that holds it and its own base path — the two
/// `@httpLabel`s of every operation on one — and both are properties the declaration states,
/// so every call the provider makes is built from the declaration rather than from an
/// identifier only API Gateway can assign. It gets no arm here either: with none, `Ref` of
/// the resource is the stand-in [`physical_name`] computes for a type that declares no name
/// property, which nothing reads — no call of this type's provider takes it, and the type
/// publishes no `Fn::GetAtt` attribute at all.
pub const APIGATEWAY_BASE_PATH_MAPPING: &str = "AWS::ApiGateway::BasePathMapping";

/// The Amazon API Gateway v2 resource types a stack creates in that service.
///
/// `AWS::ApiGatewayV2::Api`: "Ref returns the API ID", and `Fn::GetAtt` reads
/// `ApiEndpoint` — the API Gateway v2 service MINTS both (`CreateApi` takes no identifier
/// and answers the `ApiId` it assigned together with the endpoint it serves the api on),
/// which is why [`identity_is_service_assigned`] names this type.
///
/// `AWS::ApiGatewayV2::ApiMapping`: "Ref returns the API mapping ID", which
/// `CreateApiMapping` mints the same way, and which is also this type's one published
/// `Fn::GetAtt` attribute.
///
/// `AWS::ApiGatewayV2::DomainName`: "Ref returns the domain name" — the name the template
/// states, which is this type's own identifier — and `Fn::GetAtt` reads
/// `RegionalDomainName` and `RegionalHostedZoneId`, the two values that service resolves
/// for the regional endpoint it serves the domain on.
pub const APIGATEWAYV2_API: &str = "AWS::ApiGatewayV2::Api";
pub const APIGATEWAYV2_API_MAPPING: &str = "AWS::ApiGatewayV2::ApiMapping";
pub const APIGATEWAYV2_DOMAIN_NAME: &str = "AWS::ApiGatewayV2::DomainName";

/// The Amazon API Gateway v2 resource types whose resources live INSIDE an api — the ones a
/// stack declares to make the api it deployed serve anything at all.
///
/// `AWS::ApiGatewayV2::Integration`: "Ref returns the integration ID",
/// `AWS::ApiGatewayV2::Route`: "Ref returns the route ID",
/// `AWS::ApiGatewayV2::Deployment`: "Ref returns the deployment ID" and
/// `AWS::ApiGatewayV2::Authorizer`: "Ref returns the authorizer ID" — each of those ids is
/// MINTED by API Gateway v2 (its create takes no identifier and answers the one it
/// assigned), which is why [`identity_is_service_assigned`] names all four.
///
/// `AWS::ApiGatewayV2::Stage` is not one of them: "Ref returns the stage name", the name the
/// template states, which is this type's own identifier.
pub const APIGATEWAYV2_INTEGRATION: &str = "AWS::ApiGatewayV2::Integration";
pub const APIGATEWAYV2_ROUTE: &str = "AWS::ApiGatewayV2::Route";
pub const APIGATEWAYV2_STAGE: &str = "AWS::ApiGatewayV2::Stage";
pub const APIGATEWAYV2_DEPLOYMENT: &str = "AWS::ApiGatewayV2::Deployment";
pub const APIGATEWAYV2_AUTHORIZER: &str = "AWS::ApiGatewayV2::Authorizer";

/// How many characters follow the `E` of a CloudFront-assigned identifier.
///
/// CloudFront mints a distribution id, an origin access control id and an origin access
/// identity id in one shape: `E` and 13 more characters — the form
/// `CloudFrontOriginAccessIdentity$Id` documents by example ("for example,
/// E74FTE3AJFJ256A") and the one this emulator's own CloudFront service mints an id in.
pub(crate) const CLOUDFRONT_ID_BODY_LEN: usize = 13;

/// How many characters an API-Gateway-assigned identifier carries: ten, the width of the
/// `RestApi`, `Resource` and `Deployment` ids API Gateway mints (and the width this
/// emulator's own API Gateway service mints one in).
pub(crate) const APIGATEWAY_ID_LEN: usize = 10;

/// How many lowercase hexadecimal characters an Amazon S3 canonical user id carries: 64,
/// the width S3 writes one in (and the width this emulator's CloudFront service mints the
/// canonical user id of an origin access identity in).
pub(crate) const S3_CANONICAL_USER_ID_HEX_CHARS: usize = 64;

/// The salts the identifiers above are derived under — one per identifier, so two ids of
/// ONE resource are never the same digits (see [`derived_digits`]).
pub(crate) const CLOUDFRONT_DISTRIBUTION_ID_SALT: &str = "cloudfront/distribution-id";
pub(crate) const CLOUDFRONT_DISTRIBUTION_DOMAIN_SALT: &str = "cloudfront/distribution-domain-label";
pub(crate) const CLOUDFRONT_ORIGIN_ACCESS_CONTROL_ID_SALT: &str = "cloudfront/origin-access-control-id";
pub(crate) const CLOUDFRONT_ORIGIN_ACCESS_IDENTITY_ID_SALT: &str = "cloudfront/origin-access-identity-id";
pub(crate) const CLOUDFRONT_S3_CANONICAL_USER_ID_SALT: &str = "cloudfront/s3-canonical-user-id";
pub(crate) const APIGATEWAY_REST_API_ID_SALT: &str = "apigateway/rest-api-id";
pub(crate) const APIGATEWAY_ROOT_RESOURCE_ID_SALT: &str = "apigateway/root-resource-id";
pub(crate) const APIGATEWAY_RESOURCE_ID_SALT: &str = "apigateway/resource-id";
pub(crate) const APIGATEWAY_DEPLOYMENT_ID_SALT: &str = "apigateway/deployment-id";
pub(crate) const APIGATEWAY_API_KEY_ID_SALT: &str = "apigateway/api-key-id";
pub(crate) const APIGATEWAY_AUTHORIZER_ID_SALT: &str = "apigateway/authorizer-id";
pub(crate) const APIGATEWAY_REQUEST_VALIDATOR_ID_SALT: &str = "apigateway/request-validator-id";
pub(crate) const APIGATEWAY_USAGE_PLAN_ID_SALT: &str = "apigateway/usage-plan-id";
pub(crate) const APIGATEWAY_USAGE_PLAN_KEY_ID_SALT: &str = "apigateway/usage-plan-key-id";
pub(crate) const APIGATEWAY_VPC_LINK_ID_SALT: &str = "apigateway/vpc-link-id";
pub(crate) const APIGATEWAY_ACCOUNT_ID_SALT: &str = "apigateway/account-id";
pub(crate) const APIGATEWAYV2_API_ID_SALT: &str = "apigatewayv2/api-id";
pub(crate) const APIGATEWAYV2_API_MAPPING_ID_SALT: &str = "apigatewayv2/api-mapping-id";
pub(crate) const APIGATEWAYV2_DOMAIN_LABEL_SALT: &str = "apigatewayv2/regional-domain-label";

/// An identifier of the shape CloudFront ASSIGNS one in: `E` followed by
/// [`CLOUDFRONT_ID_BODY_LEN`] uppercase characters.
///
/// The characters are uppercase hexadecimal, a subset of the base-36 alphabet CloudFront
/// mints from — a stand-in of the right shape, stable across reads for the reason
/// [`derived_digits`] gives.
pub(crate) fn cloudfront_assigned_id(salt: &str, name: &str) -> String {
    format!(
        "E{}",
        derived_digits(salt, name, CLOUDFRONT_ID_BODY_LEN, Alphabet::Upper)
    )
}

/// The domain name CloudFront serves a distribution on: `d<label>.cloudfront.net`.
///
/// `Distribution$DomainName` is "The domain name that corresponds to the distribution …
/// such as d111111abcdef8.cloudfront.net" — a generated label under CloudFront's own
/// `cloudfront.net` zone, in the lowercase a DNS label takes. It is a DIFFERENT value from
/// the distribution's id, so it is derived under its own salt.
pub(crate) fn cloudfront_distribution_domain_name(name: &str) -> String {
    format!(
        "d{}.{CLOUDFRONT_DOMAIN_SUFFIX}",
        derived_digits(
            CLOUDFRONT_DISTRIBUTION_DOMAIN_SALT,
            name,
            CLOUDFRONT_ID_BODY_LEN,
            Alphabet::Lower,
        )
    )
}

/// The DNS zone CloudFront serves a distribution's own domain name under — not
/// [`URL_SUFFIX`], which is where the AWS service endpoints live.
pub(crate) const CLOUDFRONT_DOMAIN_SUFFIX: &str = "cloudfront.net";

/// An identifier of the shape API Gateway ASSIGNS one in: [`APIGATEWAY_ID_LEN`] lowercase
/// characters, drawn from the same derivation as every other identifier here.
pub(crate) fn api_gateway_assigned_id(salt: &str, name: &str) -> String {
    derived_digits(salt, name, APIGATEWAY_ID_LEN, Alphabet::Lower)
}

/// The URI an API Gateway v2 api is invoked on: "The URI of the API, of the form
/// `{api-id}.execute-api.{region}.amazonaws.com`" (`Api$ApiEndpoint`), under the scheme
/// the api's protocol speaks — a WEBSOCKET api is reached over `wss`, an HTTP api over
/// `https`.
///
/// The protocol comes from the resource's own declared `ProtocolType`, evaluated through
/// the template's intrinsics like any other property, and an api whose declaration names
/// none is an HTTP one, that being the only other value of the modelled enum.
pub(crate) fn apigatewayv2_api_endpoint(
    api_id: &str,
    region: &str,
    properties: &Value,
    scope: &Scope<'_>,
    budget: &mut Budget,
) -> String {
    let websocket = properties
        .get("ProtocolType")
        .and_then(|value| text(value, scope, 0, budget))
        .is_some_and(|protocol| protocol.eq_ignore_ascii_case(APIGATEWAYV2_WEBSOCKET_PROTOCOL));
    let scheme = if websocket { "wss" } else { "https" };
    format!("{scheme}://{api_id}.execute-api.{region}.{URL_SUFFIX}")
}

/// The `ProtocolType` whose apis are reached over the WebSocket scheme, out of the
/// `HTTP | WEBSOCKET` enum API Gateway v2's model declares.
pub(crate) const APIGATEWAYV2_WEBSOCKET_PROTOCOL: &str = "WEBSOCKET";

/// The ARN namespace API Gateway v2's resources live in, which is that model's own
/// `awsService.arnNamespace` (`apigateway`) rather than the `ApiGatewayV2` its resource
/// types are spelled with.
pub(crate) const APIGATEWAYV2_ARN_NAMESPACE: &str = "apigateway";
