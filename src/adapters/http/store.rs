//! The HTTP target's store (design `http-target` §6): one application's own secret store,
//! read and written through its gRPC-Web API over the runner's HTTPS calls.
//!
//! Every name the ports speak is a runtime env name; the target's `names` table maps it to
//! the remote name the application knows. A list is one [`CommandRunner::https_read`], a
//! write one [`CommandRunner::https_write`] per name, both carrying the request body on
//! stdin (SR-3). A value never reaches argv, a log, an error or a file: the write is encoded
//! by [`super::grpc_encode::encode_request`] straight from the [`SecretValue`].
//!
//! Errors map the application's gRPC status to opv's causes (§6): a conflict is a
//! `target_changed` (exit 5), an authentication refusal a `deploy_credentials_failed`, an
//! invalid value an `update_refused` with the server's message as scrubbed evidence, and any
//! other non-zero status after the request was sent an `outcome_unknown`.

use std::cell::RefCell;
use std::collections::BTreeMap;

use prost::Message;
use prost_reflect::{
    DescriptorPool, DynamicMessage, FieldDescriptor, Kind, MessageDescriptor, Value,
};
use zeroize::Zeroizing;

use super::descriptor;
use super::grpc_decode::{self, DecodedReply, RoleKind, RoleValue};
use super::grpc_encode;
use super::model::HttpTarget;
use super::url::Destination;
use crate::cause::{
    Cause, CredentialProblem, CredentialRef, During, EnvName, ExitClass, ItemId, Observed,
    OutputProblem, Principal, Refusal, ResourceKind, ResourceName, ResourceRef, StoreObject,
    System, TargetName, Upstream, VaultId,
};
use crate::domain::secret::SecretValue;
use crate::domain::StoreEntry;
use crate::error::Error;
use crate::ports::{StagedRuntime, StagedStore, Store, VariableStore};
use crate::runner::{take_unusable_reply, Call, CommandRunner};
use crate::runner_https::{HttpsRequest, PROGRAM};

/// The shortest value the application accepts (design §6): fewer than 16 characters is
/// refused before any call.
const MIN_VALUE: usize = 16;
/// The longest value the application accepts.
const MAX_VALUE: usize = 65_536;
/// The most server text kept in an error, in characters.
const MAX_SERVER_TEXT: usize = 200;
/// The refusal of a value shorter than [`MIN_VALUE`].
const TOO_SHORT_RULE: &str = "http-value-too-short";
/// The refusal of a value longer than [`MAX_VALUE`].
const TOO_LONG_RULE: &str = "http-value-too-long";
/// The refusal of a value with a control character.
const CONTROL_RULE: &str = "http-value-control";
/// The gRPC status of a rejected credential.
const UNAUTHENTICATED: i32 = 16;
/// The gRPC status of a credential without the right.
const PERMISSION_DENIED: i32 = 7;
/// The gRPC status of an invalid request.
const INVALID_ARGUMENT: i32 = 3;

/// The gRPC status names, indexed by code, for matching the configuration's status lists.
const STATUS_NAMES: [&str; 17] = [
    "OK",
    "CANCELLED",
    "UNKNOWN",
    "INVALID_ARGUMENT",
    "DEADLINE_EXCEEDED",
    "NOT_FOUND",
    "ALREADY_EXISTS",
    "PERMISSION_DENIED",
    "RESOURCE_EXHAUSTED",
    "FAILED_PRECONDITION",
    "ABORTED",
    "OUT_OF_RANGE",
    "UNIMPLEMENTED",
    "INTERNAL",
    "UNAVAILABLE",
    "DATA_LOSS",
    "UNAUTHENTICATED",
];

/// The application's secret store for one environment target.
pub struct HttpStore<'a> {
    runner: &'a dyn CommandRunner,
    pool: DescriptorPool,
    target: HttpTarget,
    destination: Destination,
    /// Remote name → delivered env name (the reverse of `target.names`).
    env_of: BTreeMap<String, String>,
    /// Remote name → the version the last `list` reported (absent names included; a name
    /// never listed is version 0).
    versions: RefCell<BTreeMap<String, i64>>,
    /// Delivered env name → the status its `put` reply reported, for `check_written`.
    written: RefCell<BTreeMap<String, String>>,
}

impl<'a> HttpStore<'a> {
    /// The store of `target`, reached through `runner`, with the request URIs built from
    /// `destination` (host plus the item's path prefix).
    pub fn new(
        runner: &'a dyn CommandRunner,
        pool: DescriptorPool,
        target: HttpTarget,
        destination: Destination,
    ) -> Self {
        let env_of = target
            .names
            .iter()
            .map(|(env, remote)| (remote.clone(), env.clone()))
            .collect();
        Self {
            runner,
            pool,
            target,
            destination,
            env_of,
            versions: RefCell::new(BTreeMap::new()),
            written: RefCell::new(BTreeMap::new()),
        }
    }

    /// The request URI for the `"pkg.Service/Method"` call.
    fn uri(&self, call: &str) -> String {
        self.destination.uri(&format!("/{call}"))
    }

    /// The remote name of a delivered env name, or the name itself when it is unmapped.
    fn remote(&self, name: &str) -> String {
        self.target
            .names
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_string())
    }

    /// The catalog subject of one remote entry.
    fn subject(&self, remote: &str) -> ResourceRef {
        ResourceRef {
            kind: ResourceKind::ExternalStore,
            name: ResourceName::new(remote),
            scope: None,
        }
    }

    /// The environment and target the deploy credentials name, when a run is under them.
    fn deploy_names(&self) -> (VaultId, ItemId, EnvName, TargetName) {
        match crate::runner::deploy_principal() {
            Some(Principal::DeployCredentials {
                vault,
                item,
                env,
                target,
            }) => (vault, item, env, target),
            _ => (
                VaultId::new(""),
                ItemId::new(""),
                EnvName::new(""),
                TargetName::new(""),
            ),
        }
    }

    /// The runner's own observation of the HTTPS call that just answered, if any.
    fn seen(&self) -> Option<Observed> {
        take_unusable_reply(&Call::new(PROGRAM, &[]))
    }

    /// The configuration/plan invariant this call site assumed but the loader refused.
    fn bug(&self, site: &'static str) -> Error {
        Cause::Bug { site }.into()
    }

    /// The status name of `code`, or `""` when it is outside the gRPC table.
    fn status_name(&self, code: i32) -> &'static str {
        usize::try_from(code)
            .ok()
            .and_then(|code| STATUS_NAMES.get(code))
            .copied()
            .unwrap_or("")
    }

    /// The `UnexpectedOutput` cause of a reply whose envelope decoded but whose roles did
    /// not.
    fn bad_reply(&self, site: &'static str) -> Error {
        match self.seen() {
            Some(seen) => Cause::UnexpectedOutput {
                system: System::Https,
                at: None,
                problem: OutputProblem::Unparseable,
                during: During::Read,
                seen,
            }
            .into(),
            None => self.bug(site),
        }
    }

    /// The `deploy_credentials_failed` cause of an authentication or permission refusal.
    fn credential_rejected(&self, site: &'static str) -> Error {
        let Some(seen) = self.seen() else {
            return self.bug(site);
        };
        let (vault, item, env, target) = self.deploy_names();
        Cause::CredentialRejected {
            system: System::Https,
            credential: CredentialRef::DeployCredentials {
                vault,
                item,
                env,
                target,
            },
            problem: CredentialProblem::Rejected { needs: Vec::new() },
            seen,
        }
        .into()
    }

    /// The `update_refused` cause of an invalid value, with the server's message (already
    /// percent-decoded) as scrubbed, escape-stripped, truncated evidence.
    fn validation_refused(&self, remote: &str, reply: &DecodedReply) -> Error {
        let Some(seen) = self.seen() else {
            return self.bug("http: the refused put left no observation");
        };
        let (_, _, env, target) = self.deploy_names();
        let said: Vec<String> = reply
            .grpc_message
            .as_deref()
            .map(scrub_server_text)
            .filter(|message| !message.is_empty())
            .into_iter()
            .collect();
        Error::with_evidence(
            Cause::TargetRefused {
                system: System::Https,
                subject: self.subject(remote),
                why: Refusal::Validation,
                env: (!env.as_str().is_empty()).then_some(env),
                target: (!target.as_str().is_empty()).then_some(target),
                seen,
            },
            Upstream {
                source: System::Https,
                tool: PROGRAM.to_string(),
                version: None,
                exit: ExitClass::Code {
                    code: INVALID_ARGUMENT,
                },
                said,
                truncated: false,
                removed_advice: false,
                untrusted: true,
            },
        )
    }

    /// The `outcome_unknown` cause of a put whose effect opv could not read.
    fn write_unknown(&self, remote: &str) -> Error {
        let Some(seen) = self.seen() else {
            return self.bug("http: the unknown put left no observation");
        };
        Cause::WriteOutcomeUnknown {
            system: System::Https,
            subject: self.subject(remote),
            seen,
        }
        .into()
    }

    /// Encode the list request: the literal template against the pinned request message,
    /// framed as one gRPC-Web message.
    fn encode_list(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let method = descriptor::method(&self.pool, &self.target.list.call)
            .ok_or_else(|| self.bug("http: the list method is not in the pinned descriptor"))?;
        let request = method.input();
        let table = match &self.target.list.request {
            toml::Value::Table(table) => table,
            _ => return Err(self.bug("http: the list request template is not an object")),
        };
        let message = decode_template(&request, table, "", 0)
            .map_err(|_| self.bug("http: the list request template is not valid"))?;
        let mut body = Zeroizing::new(Vec::with_capacity(message.encoded_len()));
        message
            .encode(&mut *body)
            .map_err(|_| self.bug("http: the list request could not be encoded"))?;
        Ok(frame(body))
    }

    /// Read one role value, mapping a wrong path or type to `UnexpectedOutput`.
    fn role(&self, msg: &DynamicMessage, path: &str, kind: RoleKind) -> Result<RoleValue, Error> {
        grpc_decode::read_role(msg, path, kind)
            .map_err(|_| self.bad_reply("http: the reply's role field did not read"))
    }

    /// The remote name of one list entry.
    fn entry_name(&self, entry: &DynamicMessage) -> Result<String, Error> {
        self.role(entry, &self.target.list.name, RoleKind::String)?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| self.bad_reply("http: the list entry name is not a string"))
    }

    /// The version of one list entry.
    fn entry_version(&self, entry: &DynamicMessage) -> Result<i64, Error> {
        self.role(entry, &self.target.list.version, RoleKind::Int)?
            .as_int()
            .ok_or_else(|| self.bad_reply("http: the list entry version is not an integer"))
    }

    /// The status name of one list entry.
    fn entry_status(&self, entry: &DynamicMessage) -> Result<String, Error> {
        self.role(entry, &self.target.list.status, RoleKind::Enum)?
            .as_enum()
            .map(str::to_string)
            .ok_or_else(|| self.bad_reply("http: the list entry status is not an enum"))
    }

    /// The status name of the written entry in a `put` reply.
    fn written_status(&self, reply: &DecodedReply) -> Result<Option<String>, Error> {
        let Some(message) = reply.decoded_message() else {
            return Ok(None);
        };
        let RoleValue::Message(entry) =
            self.role(message, &self.target.put.reply, RoleKind::Message)?
        else {
            return Err(self.bad_reply("http: the put reply is not a message"));
        };
        self.entry_status(&entry).map(Some)
    }

    /// Refuse a list whose gRPC status is not zero.
    fn list_failed(&self, status: i32) -> Error {
        match status {
            UNAUTHENTICATED | PERMISSION_DENIED => {
                self.credential_rejected("http: the refused list left no observation")
            }
            _ => self.bad_reply("http: the list answered with an unexpected gRPC status"),
        }
    }
}

impl Store for HttpStore<'_> {
    fn list(&self) -> Result<Vec<StoreEntry>, Error> {
        self.versions.borrow_mut().clear();
        let request = HttpsRequest {
            method: "POST",
            uri: self.uri(&self.target.list.call),
            headers: Vec::new(),
            body: self.encode_list()?,
        };
        let reply = self.runner.https_read(&request)?;
        let decoded = grpc_decode::decode_reply(&self.pool, &self.target.list.call, &reply)
            .map_err(|_| self.bad_reply("http: the list reply did not decode"))?;
        if decoded.grpc_status() != 0 {
            return Err(self.list_failed(decoded.grpc_status()));
        }
        let Some(message) = decoded.decoded_message() else {
            return Ok(Vec::new());
        };
        let RoleValue::Messages(entries) =
            self.role(message, &self.target.list.items, RoleKind::Messages)?
        else {
            return Err(self.bad_reply("http: the list items field is not a repeated message"));
        };
        let mut listed = Vec::new();
        for entry in &entries {
            let remote = self.entry_name(entry)?;
            let version = self.entry_version(entry)?;
            let status = self.entry_status(entry)?;
            let Some(env) = self.env_of.get(&remote) else {
                continue;
            };
            self.versions.borrow_mut().insert(remote, version);
            if self.target.list.absent.iter().any(|absent| absent == &status) {
                continue;
            }
            listed.push(StoreEntry {
                name: env.clone(),
                version: Some(version.to_string()),
                pending: false,
                stamp: None,
            });
        }
        Ok(listed)
    }

    fn refusal(&self, _name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)> {
        let trimmed = value.expose().trim();
        let length = trimmed.chars().count();
        if length < MIN_VALUE {
            return Some((TOO_SHORT_RULE, "the value is shorter than 16 characters"));
        }
        if length > MAX_VALUE {
            return Some((TOO_LONG_RULE, "the value is longer than 65536 characters"));
        }
        if trimmed.chars().any(char::is_control) {
            return Some((
                CONTROL_RULE,
                "the value has a control character the application refuses",
            ));
        }
        None
    }
}

impl StagedStore for HttpStore<'_> {
    fn validate(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error> {
        if batch
            .iter()
            .any(|(name, value)| self.refusal(name, value).is_some())
        {
            return Err(self.bug("http: a value the plan passed breaks an HTTP store rule"));
        }
        Ok(())
    }

    fn write(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error> {
        let method = descriptor::method(&self.pool, &self.target.put.call)
            .ok_or_else(|| self.bug("http: the put method is not in the pinned descriptor"))?;
        for (name, value) in batch {
            let remote = self.remote(name);
            let version = self
                .versions
                .borrow()
                .get(&remote)
                .copied()
                .unwrap_or(0);
            let body = grpc_encode::encode_request(
                &self.pool,
                &method,
                &self.target.put.request,
                &remote,
                version,
                &self.target.put.value,
                value,
            )
            .map_err(|_| self.bug("http: the plan staged a value the put template refused"))?;
            let request = HttpsRequest {
                method: "POST",
                uri: self.uri(&self.target.put.call),
                headers: Vec::new(),
                body,
            };
            let reply = self.runner.https_write(&request)?;
            let decoded = grpc_decode::decode_reply(&self.pool, &self.target.put.call, &reply)
                .map_err(|_| self.bad_reply("http: the put reply did not decode"))?;
            let status = decoded.grpc_status();
            if status == 0 {
                if let Some(status) = self.written_status(&decoded)? {
                    self.written.borrow_mut().insert(name.clone(), status);
                }
                continue;
            }
            let named = self.status_name(status);
            if self.target.put.conflict.iter().any(|conflict| conflict == named) {
                return Err(Cause::ChangedBeforeWrite {
                    object: StoreObject::Resource {
                        resource: self.subject(&remote),
                        changed: Vec::new(),
                    },
                }
                .into());
            }
            return Err(match status {
                UNAUTHENTICATED | PERMISSION_DENIED => {
                    self.credential_rejected("http: the refused put left no observation")
                }
                INVALID_ARGUMENT => self.validation_refused(&remote, &decoded),
                _ => self.write_unknown(&remote),
            });
        }
        Ok(())
    }

    fn remove(&self, names: &[String]) -> Result<(), Error> {
        // Removing a name is a person's action in the application; opv refuses before any
        // call and never touches the store.
        let remote = names
            .first()
            .map(|name| self.remote(name))
            .unwrap_or_default();
        let Some(seen) = self.seen() else {
            return Err(self.bug("http: the remove refusal left no observation"));
        };
        let (_, _, env, target) = self.deploy_names();
        Err(Cause::TargetRefused {
            system: System::Https,
            subject: self.subject(&remote),
            why: Refusal::Validation,
            env: (!env.as_str().is_empty()).then_some(env),
            target: (!target.as_str().is_empty()).then_some(target),
            seen,
        }
        .into())
    }

    fn check_written(&self, names: &[String]) -> Result<(), Error> {
        for name in names {
            let Some(status) = self.written.borrow().get(name).cloned() else {
                continue;
            };
            if !self.target.list.rejected.iter().any(|rejected| rejected == &status) {
                continue;
            }
            let remote = self.remote(name);
            let Some(seen) = self.seen() else {
                return Err(self.bug("http: the unhealthy entry left no observation"));
            };
            let (_, _, env, target) = self.deploy_names();
            return Err(Cause::TargetRefused {
                system: System::Https,
                subject: self.subject(&remote),
                why: Refusal::Unhealthy {
                    new_revision: remote.clone(),
                    serving: None,
                },
                env: (!env.as_str().is_empty()).then_some(env),
                target: (!target.as_str().is_empty()).then_some(target),
                seen,
            }
            .into());
        }
        Ok(())
    }

    fn variables(&self) -> Option<&dyn VariableStore> {
        None
    }
}

/// The HTTP target's runtime (design §6): every store write is live at once, so there is
/// nothing to deploy.
pub struct HttpRuntime;

impl StagedRuntime for HttpRuntime {
    fn deploy(&self) -> Result<(), Error> {
        Ok(())
    }

    fn live(&self) -> bool {
        true
    }
}

/// Scrub, strip escapes from and truncate one server message: never a value, never advice
/// that could be mistaken for opv's own steps.
fn scrub_server_text(message: &str) -> String {
    let scrubbed = crate::scrub::scrub(message);
    let stripped = crate::scrub::strip_escapes(&scrubbed);
    stripped.chars().take(MAX_SERVER_TEXT).collect()
}

// --- request encoding (the list template; the put template is `grpc_encode`'s) ------------

/// Decode the literal `table` against `request`, substituting `{name}`/`{version}`. Every
/// key must name a known field.
fn decode_template(
    request: &MessageDescriptor,
    table: &toml::Table,
    name: &str,
    version: i64,
) -> Result<DynamicMessage, String> {
    let mut message = DynamicMessage::new(request.clone());
    for (key, leaf) in table {
        let field = request
            .get_field_by_name(key)
            .ok_or_else(|| format!("the request template sets unknown field `{key}`"))?;
        let value = decode_leaf(&field, leaf, name, version)?;
        message.set_field(&field, value);
    }
    Ok(message)
}

/// Decode one leaf, an array for a repeated field and a single value otherwise.
fn decode_leaf(
    field: &FieldDescriptor,
    leaf: &toml::Value,
    name: &str,
    version: i64,
) -> Result<Value, String> {
    if field.is_list() {
        let items = match leaf {
            toml::Value::Array(items) => items,
            _ => return Err(wrong_type(field)),
        };
        let mut values = Vec::with_capacity(items.len());
        for item in items {
            values.push(decode_scalar(field, item, name, version)?);
        }
        return Ok(Value::List(values));
    }
    if field.is_map() {
        return Err(wrong_type(field));
    }
    decode_scalar(field, leaf, name, version)
}

/// Decode one scalar leaf: a placeholder or a literal of the field's own kind. A nested
/// message recurses into [`decode_template`].
fn decode_scalar(
    field: &FieldDescriptor,
    leaf: &toml::Value,
    name: &str,
    version: i64,
) -> Result<Value, String> {
    if let toml::Value::String(text) = leaf {
        if text == "{name}" {
            return match field.kind() {
                Kind::String => Ok(Value::String(name.to_owned())),
                Kind::Bytes => Ok(Value::Bytes(prost::bytes::Bytes::copy_from_slice(
                    name.as_bytes(),
                ))),
                _ => Err(placeholder_wrong_field(field, "{name}")),
            };
        }
        if text == "{version}" {
            return match field.kind() {
                Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => Ok(Value::I32(version as i32)),
                Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => Ok(Value::I64(version)),
                Kind::Uint32 | Kind::Fixed32 => Ok(Value::U32(version as u32)),
                Kind::Uint64 | Kind::Fixed64 => Ok(Value::U64(version as u64)),
                _ => Err(placeholder_wrong_field(field, "{version}")),
            };
        }
    }
    match (field.kind(), leaf) {
        (Kind::String, toml::Value::String(text)) => Ok(Value::String(text.clone())),
        (Kind::Bool, toml::Value::Boolean(flag)) => Ok(Value::Bool(*flag)),
        (Kind::Int32 | Kind::Sint32 | Kind::Sfixed32, toml::Value::Integer(i)) => {
            Ok(Value::I32(*i as i32))
        }
        (Kind::Int64 | Kind::Sint64 | Kind::Sfixed64, toml::Value::Integer(i)) => Ok(Value::I64(*i)),
        (Kind::Uint32 | Kind::Fixed32, toml::Value::Integer(i)) => Ok(Value::U32(*i as u32)),
        (Kind::Uint64 | Kind::Fixed64, toml::Value::Integer(i)) => Ok(Value::U64(*i as u64)),
        (Kind::Float, toml::Value::Float(f)) => Ok(Value::F32(*f as f32)),
        (Kind::Double, toml::Value::Float(f)) => Ok(Value::F64(*f)),
        (Kind::Bytes, toml::Value::String(text)) => Ok(Value::Bytes(
            prost::bytes::Bytes::copy_from_slice(text.as_bytes()),
        )),
        (Kind::Message(nested), toml::Value::Table(table)) => {
            Ok(Value::Message(decode_template(&nested, table, name, version)?))
        }
        (Kind::Enum(values), toml::Value::String(text)) => {
            let value = values.get_value_by_name(text).ok_or_else(|| {
                format!(
                    "the request template sets `{}` to an unknown enum value",
                    field.name()
                )
            })?;
            Ok(Value::EnumNumber(value.number()))
        }
        _ => Err(wrong_type(field)),
    }
}

/// A type error that names the field and never a value.
fn wrong_type(field: &FieldDescriptor) -> String {
    format!(
        "the request template field `{}` has the wrong type",
        field.name()
    )
}

/// A placeholder that cannot fill the field, naming both but never a value.
fn placeholder_wrong_field(field: &FieldDescriptor, placeholder: &str) -> String {
    format!(
        "the `{placeholder}` placeholder cannot fill the `{}` field",
        field.name()
    )
}

/// The gRPC-Web frame: `0x00` (uncompressed) plus the 4-byte big-endian message length.
fn frame(body: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    let mut framed = Zeroizing::new(Vec::with_capacity(body.len() + 5));
    framed.push(0x00);
    framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    framed.extend_from_slice(&body);
    framed
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
