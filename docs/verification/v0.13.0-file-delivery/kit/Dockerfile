# The §12.1 kit image: pinned debian-slim, the consumer binary, USER 10001, nothing else
# (no op, no opv, no token). Build context: a directory holding this Dockerfile and the
# release build of kit/opv-verify-136 (A4-V2).
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
COPY opv-verify-136 /usr/local/bin/opv-verify-136
USER 10001
ENTRYPOINT ["/usr/local/bin/opv-verify-136"]
CMD ["loop", "serve", "30"]
