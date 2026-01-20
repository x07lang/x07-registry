# syntax=docker/dockerfile:1

FROM rust:1.91.0-slim-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY openapi ./openapi
COPY migrations ./migrations

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/x07-registry /usr/local/bin/x07-registry

ENV X07_REGISTRY_BIND=0.0.0.0:8080
EXPOSE 8080

ENTRYPOINT ["x07-registry"]
