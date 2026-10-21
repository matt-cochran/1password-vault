# Zonetico gRPC-Web wire recordings

Recorded replies from Zonetico's real gRPC-Web stack, for testing opv's HTTPS target decoder
against what the server actually sends.

## How they were produced

- Zonetico commit `d54f92eb45e40433290f64459765b778c7c8727b` (read-only; recorded from a
  throwaway worktree that was deleted afterwards).
- A throwaway crate added to the Zonetico workspace, so it builds against Zonetico's own
  `Cargo.lock`: tonic 0.14.6, tonic-web 0.14.6, tonic-prost 0.14.6, prost 0.14.4, axum 0.8.9,
  hyper 1.11.1, tower 0.5.3. The service code comes from the workspace's own `zonetico-proto`
  crate (tonic-prost-build 0.14.6).
- The server is `portal.v1.PlatformConsoleService` with a stub implementation (no database, no
  auth) that returns canned values. It is wrapped the way `services/api` does it:
  `tonic_web::GrpcWebLayer` on the service, then `tonic::service::Routes` ->
  `into_axum_router()`, then Zonetico's `fix_grpc_web_trailers_only` middleware (copied verbatim
  from `services/api/src/rpc/mod.rs`), then `no_store` (`cache-control: no-store`), then the
  `ops::harden` layers (trace, `x-request-id` set and propagate, catch-panic). The outer
  host-routing, canonical-portal and session-gateway middlewares were left out: they pass POSTs
  without a cookie through unchanged.
- The client sent raw HTTP/1.1 over 127.0.0.1: `POST /portal.v1.PlatformConsoleService/<Method>`,
  `content-type: application/grpc-web+proto`, `x-grpc-web: 1`, `accept: application/grpc-web+proto`,
  `x-request-id: 00000000-0000-4000-8000-00000000c0de` (so the echoed id is fixed),
  `connection: close`.
- `status` and `headers` are exactly as received: names lowercased, in the order received. The
  `.body` files are the payload bytes. Where the reply was `transfer-encoding: chunked`, the
  chunk framing has been removed; the header is kept as it was received.
- `request-save.bin` is the request body the client sent for `SavePlatformConnection`
  (`0x00`, 4-byte big-endian length, then the encoded `SavePlatformConnectionRequest` with
  operator_id `00000000-0000-4000-8000-000000000000`, provider `openrouter`, secret_value
  `CANARY-NOT-A-SECRET-0123456789`, expected_version 4).
- `platform_console.binpb` was built with
  `protoc -I <zonetico>/proto --include_imports --descriptor_set_out=platform_console.binpb <zonetico>/proto/portal/v1/platform_console.proto`
  (libprotoc 33.1). Its sha256 is
  `ec5b6933b89fc49c1ebeaaa31afc666e9090036c53301648cc657cd18f8a7445`.

Every value is a canary. Masked keys are `••••CANA`, ids are all-zero UUIDs, and the secret is
`CANARY-NOT-A-SECRET-0123456789`. There are no real keys, tokens, emails or account ids.

## Cases

Every reply is HTTP 200 with `content-type: application/grpc-web+proto`.

| Case | RPC | Where grpc-status arrived | Body |
|---|---|---|---|
| `list-ok` | ListPlatformConnections | 0x80 body trailer frame (`grpc-status:0`) | data frame with 3 connections (openrouter VERIFIED v4, tavily NOT_CONFIGURED v0, stripe REVOKED v7), then the trailer frame |
| `save-ok-verified` | SavePlatformConnection | 0x80 body trailer frame (`grpc-status:0`) | data frame (openrouter, VERIFIED, v5), then the trailer frame |
| `save-ok-rejected` | SavePlatformConnection | 0x80 body trailer frame (`grpc-status:0`) | data frame (openrouter, REJECTED, v6), then the trailer frame |
| `err-already-exists` | SavePlatformConnection | 0x80 body trailer frame (`grpc-status:6`) | trailer frame only |
| `err-unauthenticated` | SavePlatformConnection | 0x80 body trailer frame (`grpc-status:16`) | trailer frame only |
| `err-invalid-argument` | SavePlatformConnection | 0x80 body trailer frame (`grpc-status:3`) | trailer frame only |
| `err-permission-denied` | SavePlatformConnection | 0x80 body trailer frame (`grpc-status:7`) | trailer frame only |

Zonetico maps HTTP 409 CONFLICT to `ALREADY_EXISTS` (6) in `services/api/src/rpc/mod.rs`
`status()`, so that is the conflict code used here.

Trailer frames are `0x80`, a 4-byte big-endian length, then `name:value\r\n` lines with no
space after the colon. `grpc-message` is percent-encoded as tonic sends it (for example
`This%20connection%20changed;%20reload%20before%20saving`). OK trailers carry only
`grpc-status:0`, with no `grpc-message`. Successful replies are chunked; error replies have a
`content-length`.

## `tonic-web-only/`: the same server without Zonetico's middleware

tonic_web 0.14.6 on its own sends an error as **trailers-only**. `grpc-status` and
`grpc-message` arrive in the HTTP response headers, the body is empty, and the reply has
`content-length: 0`. Zonetico's `fix_grpc_web_trailers_only` then moves them into a 0x80 body
frame, so production Zonetico never sends status in headers. That fix applies only to replies
the router produces through that middleware. These recordings were made with the same stub and
request but only `GrpcWebLayer` + `Routes`, so a decoder can be tested against both shapes. In
that directory, `list-ok` has the same body bytes as the top-level one; only the headers differ
(no `cache-control` or `x-request-id`).
