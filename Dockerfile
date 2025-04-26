FROM golang:1.23-alpine3.20 AS builder
RUN apk add make
ARG BUILD_VERSION
ENV BUILD_VERSION=${BUILD_VERSION}
ADD --chown=1001:0 . /evmconnect
WORKDIR /evmconnect
RUN mkdir /.cache \
    && chgrp -R 0 /.cache \
    && chmod -R g+rwX /.cache
USER 1001
RUN make

# Copy the migrations from FFTM down into our local migrations directory
RUN DB_MIGRATIONS_DIR=$(go list -f '{{.Dir}}' github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi | sed 's|pkg/ffcapi|db|') \
    && cp -R $DB_MIGRATIONS_DIR db


FROM debian:buster-slim
WORKDIR /evmconnect
RUN chgrp -R 0 /evmconnect \
    && chmod -R g+rwX /evmconnect
RUN apt update -y \
    && apt install -y curl jq \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sL "https://github.com/golang-migrate/migrate/releases/download/$(curl -sL https://api.github.com/repos/golang-migrate/migrate/releases/latest | jq -r '.name')/migrate.linux-amd64.tar.gz" | tar xz \
    && chmod +x ./migrate \
    && mv ./migrate /usr/bin/migrate
COPY --from=builder --chown=1001:0 /evmconnect/firefly-evmconnect /usr/bin/evmconnect
COPY --from=builder --chown=1001:0 /evmconnect/db/ /evmconnect/db/
USER 1001

ENTRYPOINT [ "/usr/bin/evmconnect" ]
