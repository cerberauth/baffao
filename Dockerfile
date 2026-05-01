FROM rust:1 AS builder

WORKDIR /app

COPY . ./

RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian12 AS runner

COPY --from=builder /app/target/release/baffao-proxy /
COPY --from=builder /app/baffao-proxy/config /config

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/baffao-server"]
CMD []
