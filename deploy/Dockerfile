# Build the relay and ship it in a slim runtime image.
#
# The image is built on a dev device and pushed to cp1 as a tarball
# (`deploy/deploy.sh`) -- cp1 holds no GitHub credential and no Rust toolchain,
# per the infra rule that the server authenticates to nothing.
FROM rust:1.92-slim-trixie AS build
WORKDIR /src
# Only what the server actually needs to compile (the client's GUI/media deps
# are not in this graph).
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p enclave-server --locked

FROM debian:trixie-slim
# The relay opens no outbound TLS connections and shells out to nothing, so the
# runtime stays at the base image plus the binary.
RUN useradd --system --create-home --home-dir /data --uid 10001 enclave
COPY --from=build /src/target/release/enclave-server /usr/local/bin/enclave-server
# State (accounts, OPAQUE setup, op-logs, queue, offered files) is written
# relative to the working directory, so /data is the single mount to back up.
WORKDIR /data
USER enclave
EXPOSE 8443/tcp 8444/udp
# Bind all interfaces INSIDE the container; the host publish in
# docker-compose.yml is what restricts exposure to the tailnet address.
ENTRYPOINT ["/usr/local/bin/enclave-server", "0.0.0.0:8443", "0.0.0.0:8444"]
