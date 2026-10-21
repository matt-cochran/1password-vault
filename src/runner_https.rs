//! HTTPS as a runner effect (design `http-target` §5).
//!
//! opv's runner owns how every external call is made and observed, so an application's own
//! secret store is reached through it too. An HTTPS call is a program named [`PROGRAM`]
//! whose argv is the method and the host-plus-path URI, whose env carries the header pairs
//! and whose stdin carries the body; the reply is a fixed, length-prefixed envelope on
//! stdout ([`encode_reply`]/[`decode_reply`]), so the same read/write retry, run budget,
//! write tracking (`wrote()`) and observation (program `https`) apply.
//!
//! Contract (SR-3, SR-8): no secret value ever reaches argv, an error, a log line or a
//! `Debug`; header values travel in env pairs and the body on stdin, both zeroized on drop.
//!
//! The real attempt ([`real_attempt`]) is a stub: the `https-real` lane fills it in with
//! `ureq` 3 over rustls and the platform verifier. The fake attempt is the `https` program
//! spawned from `PATH` under the `fake` feature, selected only when `OPV_SIM_WORLD` is set
//! (see [`crate::runner_https_sim`]).

use std::io;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::domain::secret::SecretValue;
use crate::runner::{Attempt, Call, Stderr};

/// The program name the runner gives an HTTPS call: the observation, the verbose line and
/// the write tracking all key off it, exactly like a vendor CLI.
pub const PROGRAM: &str = "https";

/// One HTTPS call the runner makes. `uri` is host plus path only, never a value; header
/// values are [`SecretValue`] until [`HttpsRequest::call`] hands them to the runner's env.
pub struct HttpsRequest {
    pub method: &'static str,
    pub uri: String,
    pub headers: Vec<(String, SecretValue)>,
    pub body: Zeroizing<Vec<u8>>,
}

impl HttpsRequest {
    /// Runs `f` with the runner call for this request: [`PROGRAM`] with the method and URI
    /// in argv, the headers in env pairs and the body on stdin. A header value is never in
    /// argv. The argv and env slices live on this frame only; no value is copied (the
    /// strings and their zeroizing owners stay in `self`).
    pub fn with_call<R>(&self, f: impl FnOnce(&Call<'_>) -> R) -> R {
        let args: Vec<&str> = vec![self.method, self.uri.as_str()];
        let env: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.expose()))
            .collect();
        f(&Call {
            program: PROGRAM,
            args: &args,
            stdin: Some(self.body.as_slice()),
            env: &env,
            limit: None,
        })
    }
}

impl std::fmt::Debug for HttpsRequest {
    /// Names only: the method, the URI, the header names and the body's length. Never a
    /// header value or a body byte (SR-1, SR-3).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("HttpsRequest")
            .field("method", &self.method)
            .field("uri", &self.uri)
            .field("header_names", &names)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The reply to an HTTPS call: the HTTP status, the content type, the gRPC status and
/// message (a trailers-only reply, the usual error shape) and the body. `body` may hold
/// secret values, so it is zeroized on drop and never printed by `Debug`.
pub struct HttpsReply {
    pub status: u16,
    pub content_type: Option<String>,
    pub grpc_status: Option<i32>,
    pub grpc_message: Option<String>,
    pub body: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for HttpsReply {
    /// The status, the content type and the gRPC status/message, and the body's length;
    /// never a body byte.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsReply")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("grpc_status", &self.grpc_status)
            .field("grpc_message", &self.grpc_message)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Encode `reply` as the fixed stdout envelope the runner reads back (design §5): HTTP
/// status (`u16`), an optional content type, an optional gRPC status (`i32`), an optional
/// gRPC message and the body, all big-endian and length-prefixed. The bytes are zeroized
/// on drop like the body they carry.
pub fn encode_reply(reply: &HttpsReply) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(&reply.status.to_be_bytes());
    put_opt_str(&mut out, reply.content_type.as_deref());
    match reply.grpc_status {
        Some(status) => {
            out.push(1);
            out.extend_from_slice(&status.to_be_bytes());
        }
        None => out.push(0),
    }
    put_opt_str(&mut out, reply.grpc_message.as_deref());
    out.extend_from_slice(&(reply.body.len() as u32).to_be_bytes());
    out.extend_from_slice(&reply.body);
    out
}

/// A one-byte presence flag, then a `u32` length and the UTF-8 bytes when present.
fn put_opt_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(s) => {
            out.push(1);
            out.extend_from_slice(&(s.len() as u32).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        None => out.push(0),
    }
}

/// Decode the envelope [`encode_reply`] writes. Malformed input (a truncated field, an
/// unknown presence flag, invalid UTF-8 or trailing bytes) is an
/// [`io::ErrorKind::InvalidData`] error, never a panic.
pub fn decode_reply(bytes: &[u8]) -> io::Result<HttpsReply> {
    let mut r = Reader { bytes, at: 0 };
    let status = r.u16()?;
    let content_type = r.opt_str()?;
    let grpc_status = match r.u8()? {
        0 => None,
        1 => Some(r.i32()?),
        _ => return Err(malformed("the grpc-status flag")),
    };
    let grpc_message = r.opt_str()?;
    let body = Zeroizing::new(r.bytes_field()?.to_vec());
    if r.at != bytes.len() {
        return Err(malformed("trailing bytes"));
    }
    Ok(HttpsReply {
        status,
        content_type,
        grpc_status,
        grpc_message,
        body,
    })
}

/// A cursor that reads fixed-order fields and never reads past the end.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| malformed("a length"))?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| malformed("a truncated field"))?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> io::Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i32(&mut self) -> io::Result<i32> {
        Ok(self.u32()? as i32)
    }

    fn opt_str(&mut self) -> io::Result<Option<String>> {
        match self.u8()? {
            0 => Ok(None),
            1 => {
                let n = self.u32()? as usize;
                let b = self.take(n)?;
                let s = std::str::from_utf8(b).map_err(|_| malformed("invalid UTF-8"))?;
                Ok(Some(s.to_string()))
            }
            _ => Err(malformed("a presence flag")),
        }
    }

    fn bytes_field(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

fn malformed(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("malformed HTTPS reply: {what}"),
    )
}

/// The real HTTPS attempt: a stub. The `https-real` lane fills it in with `ureq` 3 over
/// rustls and the platform verifier. Until then every real call is refused before it starts
/// ([`io::ErrorKind::Unsupported`]), never a spawn of a program named `https`.
pub(crate) fn real_attempt(_call: &Call, _limit: Duration) -> io::Result<(Attempt, Stderr)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the real HTTPS attempt is not implemented yet",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> HttpsRequest {
        HttpsRequest {
            method: "POST",
            uri: "central.zonetico.com/portal.v1.PlatformConsoleService/List".to_string(),
            headers: vec![(
                "authorization".to_string(),
                SecretValue::new("Bearer sk-live-top-secret".to_string()),
            )],
            body: Zeroizing::new(vec![0, 1, 2, 3]),
        }
    }

    #[test]
    fn https_call_keeps_header_values_out_of_argv_and_the_body_on_stdin() {
        let req = request();
        assert!(!req.with_call(|call| call.args.iter().any(|a| a.contains("sk-live-top-secret"))));
    }

    #[test]
    fn https_call_sends_the_body_on_stdin() {
        let req = request();
        assert!(req.with_call(|call| call.stdin == Some(&[0u8, 1, 2, 3][..])));
    }

    #[test]
    fn encoded_reply_decodes_to_the_same_reply() {
        let reply = HttpsReply {
            status: 200,
            content_type: Some("application/grpc-web+proto".to_string()),
            grpc_status: Some(0),
            grpc_message: None,
            body: Zeroizing::new(vec![9, 8, 7]),
        };
        let back = decode_reply(&encode_reply(&reply)).expect("a round trip");
        assert_eq!(back.grpc_status, Some(0));
    }

    #[test]
    fn decode_reply_refuses_a_truncated_envelope() {
        let reply = HttpsReply {
            status: 200,
            content_type: None,
            grpc_status: None,
            grpc_message: None,
            body: Zeroizing::new(vec![1, 2, 3]),
        };
        let encoded = encode_reply(&reply);
        let truncated = &encoded[..encoded.len() - 1];
        assert!(decode_reply(truncated).is_err());
    }
}
