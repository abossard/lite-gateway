# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS build
WORKDIR /src

COPY src/LiteGateway.Proxy.Rust/Cargo.toml src/LiteGateway.Proxy.Rust/Cargo.lock src/LiteGateway.Proxy.Rust/
COPY src/LiteGateway.Proxy.Rust/src src/LiteGateway.Proxy.Rust/src
RUN cargo build --manifest-path src/LiteGateway.Proxy.Rust/Cargo.toml --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /src/src/LiteGateway.Proxy.Rust/target/release/lite-gateway-proxy-rust /usr/local/bin/lite-gateway-proxy-rust

ENV RUST_LOG=warn

EXPOSE 8080 8443 9443

ENTRYPOINT ["lite-gateway-proxy-rust"]
