FROM golang:1.19-buster AS builder
ARG BUILD_VERSION
ENV BUILD_VERSION=${BUILD_VERSION}
ADD . /evmconnect
WORKDIR /evmconnect
RUN make

# Copy the migrations from FFTM down into our local migrations directory
RUN DB_MIGRATIONS_DIR=$(go list -f '{{.Dir}}' github.com/hyperledger/firefly-transaction-manager/pkg/ffcapi | sed 's|pkg/ffcapi|db|') \
 && cp -R $DB_MIGRATIONS_DIR db


FROM debian:buster-slim
WORKDIR /evmconnect
RUN apt update -y \
 && apt install -y curl jq \
 && rm -rf /var/lib/apt/lists/* \
 && curl -sL "https://github.com/golang-migrate/migrate/releases/download/$(curl -sL https://api.github.com/repos/golang-migrate/migrate/releases/latest | jq -r '.name')/migrate.linux-amd64.tar.gz" | tar xz \
 && chmod +x ./migrate \
 && mv ./migrate /usr/bin/migrate
COPY --from=builder /evmconnect/firefly-evmconnect /usr/bin/evmconnect
COPY --from=builder /evmconnect/db/ /evmconnect/db/

ENTRYPOINT [ "/usr/bin/evmconnect" ]
