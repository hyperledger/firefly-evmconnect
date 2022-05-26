FROM golang:1.17-buster AS builder
ARG BUILD_VERSION
ENV BUILD_VERSION=${BUILD_VERSION}
ADD . /evmconnect
WORKDIR /evmconnect
RUN make

FROM debian:buster-slim
WORKDIR /evmconnect
RUN apt update -y \
 && apt install -y curl jq \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /evmconnect/firefly-evmconnect /usr/bin/evmconnect

ENTRYPOINT [ "/usr/bin/evmconnect" ]
