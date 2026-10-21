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
//! The real attempt ([`real_attempt`]) is `ureq` 3 over rustls with the operating system's
//! trust store; it runs in process, never as a spawned program. The fake attempt is the
//! `https` program spawned from `PATH` under the `fake` feature, selected only when
//! `OPV_SIM_WORLD` is set (see [`crate::runner_https_sim`]).

use std::io;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::domain::secret::SecretValue;
use crate::runner::{Attempt, Call, OUTPUT_CAP, Output, Stderr};

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

/// The content type every gRPC-Web request and reply carries (design §5.1).
const GRPC_WEB: &str = "application/grpc-web+proto";

/// The `User-Agent` opv sends: its own name and version, never ureq's default.
const USER_AGENT: &str = concat!("opv/", env!("CARGO_PKG_VERSION"));

/// The only env pairs the credentials may become headers (design §5): the item's token and
/// Cloudflare Access pair. Every other env pair is dropped, so a stray variable can never
/// travel to the target as a header. Lowercase keys here; matched case-insensitively.
const ALLOWED_HEADERS: [(&str, &str); 3] = [
    ("authorization", "Authorization"),
    ("cf-access-client-id", "CF-Access-Client-Id"),
    ("cf-access-client-secret", "CF-Access-Client-Secret"),
];

/// The real HTTPS attempt (design §4.3, §5): one in-process `ureq` 3 call over rustls with
/// the platform verifier, its redirects off and the runner's deadline as its global budget.
/// The reply is wrapped in the same length-prefixed envelope the fake attempt writes, so the
/// runner decodes one shape. A redirect is returned, never followed, so the caller refuses it
/// by status. A timeout is [`Attempt::TimedOut`]; a connect, TLS or IO failure is an
/// [`io::Error`] with a fixed, value-free message. No header value or body byte reaches an
/// error, a `Debug` or a log line (SR-3, SR-8).
pub(crate) fn real_attempt(call: &Call, limit: Duration) -> io::Result<(Attempt, Stderr)> {
    let url = target_url(call)?;
    let mut builder = ureq::http::Request::builder()
        .method(call.args[0])
        .uri(&url);
    for (name, value) in call.env {
        if let Some(header) = allowlisted(name) {
            builder = builder.header(header, *value);
        }
    }
    let request = builder
        .header("Content-Type", GRPC_WEB)
        .header("Accept", GRPC_WEB)
        .header("x-grpc-web", "1")
        .body(call.stdin.unwrap_or_default())
        .map_err(|_| invalid("the HTTPS request could not be built"))?;
    let mut response = match agent(limit).run(request) {
        Ok(response) => response,
        Err(ureq::Error::Timeout(_)) => return Ok((Attempt::TimedOut, Stderr::default())),
        Err(failure) => return Err(transport_error(&failure)),
    };
    let status = response.status().as_u16();
    let content_type = header_value(response.headers(), "content-type");
    let grpc_status =
        header_value(response.headers(), "grpc-status").and_then(|value| value.parse::<i32>().ok());
    let grpc_message = header_value(response.headers(), "grpc-message");
    let body = match response
        .body_mut()
        .with_config()
        .limit(OUTPUT_CAP as u64)
        .read_to_vec()
    {
        Ok(body) => Zeroizing::new(body),
        Err(ureq::Error::Timeout(_)) => return Ok((Attempt::TimedOut, Stderr::default())),
        Err(failure) => return Err(transport_error(&failure)),
    };
    let reply = HttpsReply {
        status,
        content_type,
        grpc_status,
        grpc_message,
        body,
    };
    Ok((
        Attempt::Exited(Output {
            status: 0,
            stdout: encode_reply(&reply),
        }),
        Stderr::default(),
    ))
}

/// The URL for `call`: argv is the method and the host-plus-path URI (design §5), so the URI
/// checked elsewhere is the host connected to. A call without both is a value-free refusal,
/// never an echo of any argv.
fn target_url(call: &Call) -> io::Result<String> {
    match call.args {
        [_, uri, ..] => Ok(format!("{}://{uri}", scheme(uri))),
        _ => Err(invalid("the HTTPS call needs a method and a URI")),
    }
}

/// The canonical name of an allowlisted header, `None` for every other env pair.
fn allowlisted(name: &str) -> Option<&'static str> {
    ALLOWED_HEADERS
        .iter()
        .find(|(lower, _)| name.eq_ignore_ascii_case(lower))
        .map(|(_, header)| *header)
}

/// The ureq agent for one attempt (design §4.3): no redirects (`max_redirects(0)`, so a 3xx
/// is a reply the caller refuses by status), the runner's deadline as the global budget,
/// `http_status_as_error(false)`, the operating system's trust store and the environment's
/// proxy (`HTTPS_PROXY`/`NO_PROXY`). No bundled roots enter the tree.
fn agent(limit: Duration) -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    ureq::Agent::config_builder()
        .max_redirects(0)
        .timeout_global(Some(limit))
        .http_status_as_error(false)
        .tls_config(tls)
        .proxy(ureq::Proxy::try_from_env())
        .user_agent(USER_AGENT)
        .build()
        .into()
}

/// One reply header as a `String`, `None` when absent or not UTF-8.
fn header_value(headers: &ureq::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// A connect, TLS or IO failure as an [`io::Error`] with a fixed, value-free message. An
/// empty operating-system trust store is its own fixed, non-retried refusal (design §4.3):
/// the platform verifier says so when it loads no roots, in its own words.
fn transport_error(failure: &ureq::Error) -> io::Error {
    let text = failure.to_string();
    if text.contains("No CA certificates were loaded from the system")
        || text.contains("no root trust anchors were provided")
    {
        return io::Error::new(
            io::ErrorKind::NotFound,
            "no trusted root certificates on this system",
        );
    }
    io::Error::other("the HTTPS call could not be completed")
}

/// A value-free refusal for a call opv cannot even build.
fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what)
}

/// The scheme for `uri`: HTTPS, except that a unit test may reach a plain-TCP listener on
/// the loopback interface (design §4.3). The exception is compiled only under `cfg(test)`,
/// so no shipped build can send a target's credentials over an unsecured connection.
#[cfg(test)]
fn scheme(uri: &str) -> &'static str {
    if is_loopback(uri) { "http" } else { "https" }
}

#[cfg(not(test))]
fn scheme(_uri: &str) -> &'static str {
    "https"
}

/// The test-only loopback hook: true for `localhost`, `127.0.0.0/8` and `::1`.
#[cfg(test)]
fn is_loopback(uri: &str) -> bool {
    let authority = uri
        .split_once("://")
        .map_or(uri, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = match host.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next().unwrap_or(bracketed),
        None => host.split(':').next().unwrap_or(host),
    };
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
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

    // The real attempt is exercised against a plain-TCP listener on 127.0.0.1. That is only
    // reachable through the test-only loopback hook in [`scheme`]; no shipped build can
    // downgrade a real target to http (design §4.3). Every value is an obvious canary.
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};

    const CANARY: &str = "CANARY-NOT-A-SECRET-0123456789";
    const OK_REPLY: &str = "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ngrpc-status: 7\r\ngrpc-message: permission%20denied\r\ncontent-length: 3\r\n\r\nabc";
    const REDIRECT_REPLY: &str =
        "HTTP/1.1 302 Found\r\nlocation: https://elsewhere.invalid/\r\ncontent-length: 0\r\n\r\n";

    fn call<'a>(args: &'a [&'a str], env: &'a [(&'a str, &'a str)], body: &'a [u8]) -> Call<'a> {
        Call {
            program: PROGRAM,
            args,
            stdin: Some(body),
            env,
            limit: None,
        }
    }

    /// Run one real attempt against the URI with `env` and `body`.
    fn attempt(
        uri: &str,
        env: &[(&str, &str)],
        body: &[u8],
        limit: Duration,
    ) -> io::Result<(Attempt, Stderr)> {
        let args = ["POST", uri];
        let call = call(&args, env, body);
        real_attempt(&call, limit)
    }

    /// The decoded reply of an exited attempt.
    fn reply_of(result: io::Result<(Attempt, Stderr)>) -> HttpsReply {
        match result.expect("an attempt") {
            (Attempt::Exited(o), _) => decode_reply(&o.stdout).expect("a reply envelope"),
            _ => panic!("expected an exited attempt"),
        }
    }

    /// One connection within `deadline`, so a broken attempt fails the test instead of
    /// hanging it on a listener that is never reached.
    fn accept_within(listener: &TcpListener, deadline: Duration) -> TcpStream {
        listener
            .set_nonblocking(true)
            .expect("a non-blocking listener");
        let stop = std::time::Instant::now() + deadline;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).expect("a blocking stream");
                    return stream;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < stop,
                        "the attempt never connected"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("accept failed: {e}"),
            }
        }
    }

    /// A listener that answers `reply` and hands back the request bytes it saw.
    fn answering(reply: &'static str) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let port = listener.local_addr().expect("an address").port();
        let uri = format!("127.0.0.1:{port}/portal.v1.PlatformConsoleService/List");
        let handle = std::thread::spawn(move || {
            let mut stream = accept_within(&listener, Duration::from_secs(10));
            let request = read_request(&mut stream);
            stream.write_all(reply.as_bytes()).expect("the reply");
            let _ = stream.flush();
            request
        });
        (uri, handle)
    }

    /// A listener that accepts and never answers: the caller must time out.
    fn stalling() -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let port = listener.local_addr().expect("an address").port();
        let uri = format!("127.0.0.1:{port}/portal.v1.PlatformConsoleService/List");
        let handle = std::thread::spawn(move || {
            let mut stream = accept_within(&listener, Duration::from_secs(10));
            let mut chunk = [0u8; 4096];
            while matches!(stream.read(&mut chunk), Ok(n) if n > 0) {}
        });
        (uri, handle)
    }

    /// The whole request: headers and, when `content-length` says so, the body.
    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(end) = request
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|at| at + 4)
                && request.len() >= end + content_length(&request[..end])
            {
                break;
            }
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => request.extend_from_slice(&chunk[..n]),
            }
        }
        request
    }

    fn content_length(head: &[u8]) -> usize {
        for line in String::from_utf8_lossy(head).lines() {
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                return value.trim().parse().unwrap_or(0);
            }
        }
        0
    }

    /// True when `request` carries `name: value`, matched by name without regard to case.
    fn has_header(request: &str, name: &str, value: &str) -> bool {
        request.lines().any(|line| match line.split_once(':') {
            Some((header, rest)) => header.eq_ignore_ascii_case(name) && rest.trim() == value,
            None => false,
        })
    }

    /// A loopback port nothing is listening on.
    fn unused_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        listener.local_addr().expect("an address").port()
    }

    #[test]
    fn https_attempt_sends_an_allowlisted_environment_pair_as_a_header() {
        let (uri, server) = answering(OK_REPLY);
        let _ = attempt(
            &uri,
            &[("Authorization", CANARY)],
            b"",
            Duration::from_secs(5),
        );
        let sent = String::from_utf8_lossy(&server.join().expect("the listener")).to_string();
        assert!(sent.lines().any(|line| match line.split_once(':') {
            Some((name, value)) =>
                name.eq_ignore_ascii_case("authorization") && value.trim() == CANARY,
            None => false,
        }));
    }

    #[test]
    fn https_attempt_drops_an_environment_pair_outside_the_allowlist() {
        let (uri, server) = answering(OK_REPLY);
        let _ = attempt(
            &uri,
            &[("X-Not-A-Header", CANARY)],
            b"",
            Duration::from_secs(5),
        );
        let sent = String::from_utf8_lossy(&server.join().expect("the listener")).to_string();
        assert!(!sent.contains(CANARY));
    }

    #[test]
    fn https_attempt_keeps_a_header_value_out_of_the_request_line() {
        let (uri, server) = answering(OK_REPLY);
        let _ = attempt(
            &uri,
            &[("Authorization", CANARY)],
            b"",
            Duration::from_secs(5),
        );
        let sent = String::from_utf8_lossy(&server.join().expect("the listener")).to_string();
        assert!(!sent.lines().next().unwrap_or("").contains(CANARY));
    }

    #[test]
    fn https_attempt_sends_the_stdin_body_as_the_request_body() {
        let (uri, server) = answering(OK_REPLY);
        let body = b"CANARY-NOT-A-SECRET-BODY";
        let _ = attempt(&uri, &[], body, Duration::from_secs(5));
        let sent = server.join().expect("the listener");
        assert!(sent.windows(body.len()).any(|w| w == body));
    }

    #[test]
    fn https_attempt_returns_a_redirect_status_without_following_it() {
        let (uri, server) = answering(REDIRECT_REPLY);
        let reply = reply_of(attempt(&uri, &[], b"", Duration::from_secs(5)));
        let _ = server.join();
        assert_eq!(reply.status, 302);
    }

    #[test]
    fn https_attempt_fills_the_grpc_status_from_the_reply_headers() {
        let (uri, server) = answering(OK_REPLY);
        let reply = reply_of(attempt(&uri, &[], b"", Duration::from_secs(5)));
        let _ = server.join();
        assert_eq!(reply.grpc_status, Some(7));
    }

    #[test]
    fn https_attempt_fills_the_body_from_the_reply() {
        let (uri, server) = answering(OK_REPLY);
        let reply = reply_of(attempt(&uri, &[], b"", Duration::from_secs(5)));
        let _ = server.join();
        assert_eq!(&reply.body[..], b"abc");
    }

    #[test]
    fn https_attempt_fills_the_content_type_from_the_reply_headers() {
        let (uri, server) = answering(OK_REPLY);
        let reply = reply_of(attempt(&uri, &[], b"", Duration::from_secs(5)));
        let _ = server.join();
        assert_eq!(reply.content_type.as_deref(), Some(GRPC_WEB));
    }

    #[test]
    fn https_attempt_fills_the_grpc_message_from_the_reply_headers() {
        let (uri, server) = answering(OK_REPLY);
        let reply = reply_of(attempt(&uri, &[], b"", Duration::from_secs(5)));
        let _ = server.join();
        assert_eq!(reply.grpc_message.as_deref(), Some("permission%20denied"));
    }

    #[test]
    fn https_attempt_sends_the_grpc_web_content_type() {
        let (uri, server) = answering(OK_REPLY);
        let _ = attempt(&uri, &[], b"", Duration::from_secs(5));
        let sent = String::from_utf8_lossy(&server.join().expect("the listener")).to_string();
        assert!(has_header(&sent, "content-type", GRPC_WEB));
    }

    #[test]
    fn https_attempt_marks_the_call_as_grpc_web() {
        let (uri, server) = answering(OK_REPLY);
        let _ = attempt(&uri, &[], b"", Duration::from_secs(5));
        let sent = String::from_utf8_lossy(&server.join().expect("the listener")).to_string();
        assert!(has_header(&sent, "x-grpc-web", "1"));
    }

    #[test]
    fn https_attempt_identifies_itself_as_opv() {
        let (uri, server) = answering(OK_REPLY);
        let _ = attempt(&uri, &[], b"", Duration::from_secs(5));
        let sent = String::from_utf8_lossy(&server.join().expect("the listener")).to_string();
        assert!(has_header(&sent, "user-agent", USER_AGENT));
    }

    #[test]
    fn https_attempt_reports_a_stalled_reply_as_a_timeout() {
        let (uri, server) = stalling();
        let result = attempt(&uri, &[], b"", Duration::from_millis(300));
        let _ = server.join();
        assert!(matches!(result, Ok((Attempt::TimedOut, _))));
    }

    #[test]
    fn https_attempt_reports_a_connect_failure_as_an_error() {
        let uri = format!(
            "127.0.0.1:{}/portal.v1.PlatformConsoleService/List",
            unused_port()
        );
        assert!(attempt(&uri, &[], b"", Duration::from_secs(5)).is_err());
    }
}
