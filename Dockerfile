FROM rust:1.97 AS rust_builder
ARG TARGETARCH
RUN apt-get update && apt-get install -y musl-tools
RUN git clone https://github.com/brave-intl/challenge-bypass-ristretto-ffi /src
WORKDIR /src
# Keep in lockstep with the challenge-bypass-ristretto-ffi version in go.mod so
# the compiled static lib exports match the cgo bindings.
RUN git checkout 450ec6bab8472c95e4ecadf8a3ef9d38f7073fe2
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) RUST_TARGET=x86_64-unknown-linux-musl ;; \
      arm64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    rustup target add "${RUST_TARGET}"; \
    CARGO_PROFILE_RELEASE_LTO=true cargo rustc --target="${RUST_TARGET}" --release --crate-type staticlib

FROM golang:1.26 AS go_builder
WORKDIR /src
# Resolve modules in their own layer so editing source does not re-download the
# dependency graph on every build.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Wildcard avoids repeating the arch/triple mapping here; exactly one musl
# target dir exists in rust_builder.
COPY --from=rust_builder /src/target/*-unknown-linux-musl/release/libchallenge_bypass_ristretto_ffi.a /usr/lib/libchallenge_bypass_ristretto_ffi.a

ARG VERSION
ARG COMMIT
ARG BUILD_TIME
RUN go build -ldflags "\
    -X main.Version=${VERSION} \
    -X main.BuildTime=${BUILD_TIME} \
    -X main.Commit=${COMMIT} \
    -linkmode external -extldflags \"-static\"" \
    -tags "osusergo netgo static_build" \
    -o challenge-bypass-server main.go
CMD ["/src/challenge-bypass-server"]

FROM ubuntu:26.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=go_builder /src/challenge-bypass-server /bin/
COPY migrations /src/migrations
EXPOSE 2416
ENV DATABASE_URL=
ENV DBCONFIG="{}"
ENV MAX_DB_CONNECTION=100
ENV AWS_REGION="us-west-2"
ENV EXPIRATION_WINDOW=7
ENV RENEWAL_WINDOW=30
ENV DYNAMODB_ENDPOINT=
CMD ["/bin/challenge-bypass-server"]
