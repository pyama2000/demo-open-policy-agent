FROM rust:1.71.1 AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM busybox:1.36.1-uclibc AS binary

FROM gcr.io/distroless/cc
COPY --from=builder /app/target/release/server /
COPY --from=binary /bin/wget /usr/bin/wget
EXPOSE 8080
ENTRYPOINT ["./server"]
