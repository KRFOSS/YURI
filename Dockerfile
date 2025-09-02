FROM rust:latest AS builder

RUN apt update -y && apt install -y musl-tools && rustup target add x86_64-unknown-linux-musl

WORKDIR /app

COPY . .

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM debian:stable-slim

RUN apt update -y && apt install -y ca-certificates

WORKDIR /app

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/yu-ri .

CMD ["./yu-ri"]
