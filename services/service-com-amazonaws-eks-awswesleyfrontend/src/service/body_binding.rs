// SPDX-License-Identifier: CC0-1.0

//! WHETHER a request's body can be bound to the operation's input SHAPES at all — the
//! question a layer that runs before the body is read has to answer, and the one the
//! authorization decision asks ([`super::authorization`]).
//!
//! Two failures a caller can cause while a body is read look alike from outside and are
//! not the same thing:
//!
//! * a VALUE this service read and then refused. A member whose modelled type is a scalar
//!   is read from whichever of JSON's scalar types the body carries there
//!   ([`super::lenient_scalars`]), so the body always states something at such a member,
//!   and a value that states nothing of the modelled type is a fact about that value — the
//!   request was bound, one of its values was not accepted.
//! * a body the walk could not ENTER. A list, map or structure member is read from the
//!   JSON array or object the model declares for it and from nothing else
//!   (`vendor/smithy-schema-server/src/json.rs`, whose `read_list`/`read_map`/`read_struct`
//!   accept only their own opening token), so a string or a number where one of those
//!   stands leaves everything inside it unread. Nothing the body carried was determined.
//!
//! [`binds_to_input_shapes`] answers the second question alone, by running the operation's
//! own generated input type over the request through [`ShapeOnlyReader`]: the codec this
//! service reads a body with, with every scalar leaf consumed and DISCARDED rather than
//! converted. What is left to fail is the structure — a container whose opening token is
//! not there — so the answer is about the body's shape and never about one of its values.
//! The one leaf not discarded is a `document` member, which holds whatever JSON the caller
//! likes: there is no value it could carry that the codec's read of it refuses, so that
//! read can only fail on a body that is not JSON at all, which is this question's own
//! class.
//!
//! An absent `@required` member is excluded too: it is found while reading, yet it names
//! the member it is about and is refused as the constrained leaf it is (see
//! [`super::parameter_contract`]), so a request missing one HAS a shape this service can
//! bind.
//!
//! The reader costs one stack frame per nesting level and nothing else: each leaf is read
//! through the codec's own `read_document`, which reads the ONE token that is there under
//! the codec's own depth guard, and the containers are the codec's own, whose
//! `read_struct`/`read_list`/`read_map` refuse a body nested past their own maximum.

use aws_smithy_runtime_api::http::Request as RtRequest;
use aws_smithy_schema::serde::{SerdeError, ShapeDeserializer};
use aws_smithy_schema::Schema;
use aws_smithy_types::{BigDecimal, BigInteger, Blob, DateTime, Document};
use smithy_server_runtime::{DeserializableStruct, ServerHttpProtocol};

// `InnerDeserializer` is the one forwarding pair this crate has, so a wrapper that
// discards a value and one that converts it wear the same two cases.
use super::lenient_json::InnerDeserializer;
use super::lenient_scalars::reads_from_the_request;

/// Whether this request's body binds to the input shapes of the operation whose generated
/// input type is `T`.
///
/// `true` for a body the walk can enter — whatever its values then fail — for a request
/// that omits a member the shape requires, and for a request whose body cannot be reached
/// at all, which is a transport-level failure the framework owns rather than a shape this
/// service judges.
///
/// The protocol and schema are the ones the dispatch sequence will read that same body
/// with, so a layer asking this cannot disagree with the walk that follows it (see
/// [`super::body_codec`] and [`super::read_input`]).
pub fn binds_to_input_shapes<T: DeserializableStruct>(
    protocol: &dyn ServerHttpProtocol,
    schema: &'static Schema,
    req: &RtRequest,
) -> bool {
    let Ok(inner) = protocol.deserialize_input(req, schema) else {
        return true;
    };
    match T::deserialize(&mut ShapeOnlyReader(inner)) {
        Ok(_) => true,
        Err(SerdeError::MissingMember { .. }) => true,
        Err(_) => false,
    }
}

/// A deserializer that reads a body's STRUCTURE and nothing else: every container is the
/// codec's own, and every scalar leaf is consumed and thrown away.
///
/// The values it hands back are placeholders and are never used: the only thing read off a
/// walk through this reader is WHETHER it completed (see the module header). That is why a
/// leaf cannot fail here — the body always carries some JSON value at a scalar member, and
/// what that value states is the next layer's question, not this one's.
struct ShapeOnlyReader<D>(D);

impl<D: InnerDeserializer> ShapeOnlyReader<D> {
    /// Consume the one token standing at a scalar leaf, discarding it.
    ///
    /// A member whose value does not come from the JSON body at all — a URI label, a query
    /// member, a header ([`reads_from_the_request`]) — carries text the request's own
    /// addressing states and no body token, so there is nothing here to consume and
    /// nothing about the body's shape it could decide.
    fn discard(&mut self, schema: &Schema) -> Result<(), SerdeError> {
        if reads_from_the_request(schema) {
            return Ok(());
        }
        self.0.get().read_document(schema).map(|_| ())
    }
}

impl<D: InnerDeserializer> ShapeDeserializer for ShapeOnlyReader<D> {
    fn read_struct(
        &mut self,
        schema: &Schema,
        consumer: &mut dyn FnMut(&Schema, &mut dyn ShapeDeserializer) -> Result<(), SerdeError>,
    ) -> Result<(), SerdeError> {
        self.0
            .get()
            .read_struct(schema, &mut |member, d| consumer(member, &mut ShapeOnlyReader(d)))
    }

    fn read_list(
        &mut self,
        schema: &Schema,
        consumer: &mut dyn FnMut(&mut dyn ShapeDeserializer) -> Result<(), SerdeError>,
    ) -> Result<(), SerdeError> {
        self.0
            .get()
            .read_list(schema, &mut |d| consumer(&mut ShapeOnlyReader(d)))
    }

    fn read_map(
        &mut self,
        schema: &Schema,
        consumer: &mut dyn FnMut(String, &mut dyn ShapeDeserializer) -> Result<(), SerdeError>,
    ) -> Result<(), SerdeError> {
        self.0
            .get()
            .read_map(schema, &mut |key, d| consumer(key, &mut ShapeOnlyReader(d)))
    }

    fn read_boolean(&mut self, schema: &Schema) -> Result<bool, SerdeError> {
        self.discard(schema).map(|()| false)
    }

    fn read_byte(&mut self, schema: &Schema) -> Result<i8, SerdeError> {
        self.discard(schema).map(|()| 0)
    }

    fn read_short(&mut self, schema: &Schema) -> Result<i16, SerdeError> {
        self.discard(schema).map(|()| 0)
    }

    fn read_integer(&mut self, schema: &Schema) -> Result<i32, SerdeError> {
        self.discard(schema).map(|()| 0)
    }

    fn read_long(&mut self, schema: &Schema) -> Result<i64, SerdeError> {
        self.discard(schema).map(|()| 0)
    }

    fn read_float(&mut self, schema: &Schema) -> Result<f32, SerdeError> {
        self.discard(schema).map(|()| 0.0)
    }

    fn read_double(&mut self, schema: &Schema) -> Result<f64, SerdeError> {
        self.discard(schema).map(|()| 0.0)
    }

    fn read_big_integer(&mut self, schema: &Schema) -> Result<BigInteger, SerdeError> {
        self.discard(schema).map(|()| BigInteger::default())
    }

    fn read_big_decimal(&mut self, schema: &Schema) -> Result<BigDecimal, SerdeError> {
        self.discard(schema).map(|()| BigDecimal::default())
    }

    fn read_string(&mut self, schema: &Schema) -> Result<String, SerdeError> {
        self.discard(schema).map(|()| String::new())
    }

    fn read_blob(&mut self, schema: &Schema) -> Result<Blob, SerdeError> {
        self.discard(schema).map(|()| Blob::new(Vec::new()))
    }

    fn read_timestamp(&mut self, schema: &Schema) -> Result<DateTime, SerdeError> {
        self.discard(schema).map(|()| DateTime::from_secs(0))
    }

    fn read_document(&mut self, schema: &Schema) -> Result<Document, SerdeError> {
        // A `document` member holds whatever JSON the caller likes, so no value it carries
        // is refused here and the codec's own read of it is the whole rule: it can fail
        // only on a body that is not JSON at all (see the module header).
        self.0.get().read_document(schema)
    }

    fn is_null(&self) -> bool {
        self.0.peek().is_null()
    }

    fn read_null(&mut self) -> Result<(), SerdeError> {
        self.0.get().read_null()
    }

    fn container_size(&self) -> Option<usize> {
        self.0.peek().container_size()
    }
}
