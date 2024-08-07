FROM golang:1.21.13 AS build
WORKDIR /src
ENV CGO_ENABLED=0
ENV BUILD_GOARCH="arm64"
RUN git clone --depth 1 https://github.com/open-policy-agent/opa-envoy-plugin.git /src
RUN make build-linux-static

FROM busybox:1.36.1-uclibc AS binary

FROM scratch
COPY --from=build /src/opa_envoy_linux_arm64 /bin/opa_envoy
COPY --from=binary /bin/wget /bin/wget
EXPOSE 8181/tcp
EXPOSE 8181/udp
ENTRYPOINT ["/bin/opa_envoy"]
