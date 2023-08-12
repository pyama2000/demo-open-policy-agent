FROM rust:1.71.1 AS builder
ARG PROTOC_VERSION=24.0
ARG PROTOC_ARCH="aarch_64"
WORKDIR /tmp
RUN curl -L "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-${PROTOC_ARCH}.zip" -o protoc.zip && \
    unzip protoc.zip && \
    mv bin/* /usr/local/bin/ && \
    mv include/* /usr/local/include/
WORKDIR /app
COPY . .
RUN cargo build --release

FROM alpine:3.18.3 AS binary
ARG GRPC_HEALTH_PROBE_VERSION=v0.4.19
ARG GRPC_HEALTH_PROBE_VERSION_ARCH="arm64"
RUN wget -qO/bin/grpc_health_probe "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-${GRPC_HEALTH_PROBE_VERSION_ARCH}" && \
    chmod +x /bin/grpc_health_probe

FROM gcr.io/distroless/cc
COPY --from=builder /app/target/release/server /
COPY --from=binary /bin/grpc_health_probe /bin/grpc_health_probe
EXPOSE 50051
ENTRYPOINT ["./server"]
