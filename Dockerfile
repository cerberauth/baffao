FROM rust:1 AS builder

WORKDIR /app

COPY . ./

RUN cargo build --locked --release

FROM gcr.io/distroless/cc-debian12 AS runner

COPY --from=builder /app/target/release/baffao-proxy /
COPY --from=builder /app/baffao-proxy/config /config

EXPOSE 3000

ENTRYPOINT ["./baffao-proxy"]
CMD ["./baffao-proxy"]
