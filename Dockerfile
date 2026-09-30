FROM rust:1.96 AS rust_builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools
# act/ffi builds ONE static library: challenge-bypass-ristretto-ffi (pinned in
# act/ffi/Cargo.toml; keep in lockstep with go.mod so the exports match the cgo
# bindings) plus the ACT bindings. Two Rust staticlibs cannot be linked into one
# static binary (duplicate libstd), so the ristretto lib is no longer built alone.
COPY act/ffi /src
WORKDIR /src
RUN cargo build --locked --target=x86_64-unknown-linux-musl --release

FROM golang:1.26 AS go_builder
RUN apt-get update && apt-get install -y ca-certificates postgresql-client python3-pip awscli
RUN curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(go env GOPATH)/bin latest
RUN mkdir /src
WORKDIR /src
COPY . .
RUN go mod download
COPY --from=rust_builder /src/target/x86_64-unknown-linux-musl/release/libcbp_act_ffi.a /usr/lib/libchallenge_bypass_ristretto_ffi.a

ARG VERSION
ARG COMMIT
ARG BUILD_TIME
# Drop `act` to build without Anonymous Credit Tokens (routes then return 501).
ARG BUILD_TAGS="osusergo netgo static_build act"
RUN go build -ldflags "\
    -X main.Version=${VERSION} \
    -X main.BuildTime=${BUILD_TIME} \
    -X main.Commit=${COMMIT} \
    -linkmode external -extldflags \"-static\"" \
    -tags "${BUILD_TAGS}" \
    -o challenge-bypass-server main.go
# ACT end-to-end smoke test, runnable inside a task: /bin/act-smoke -url http://localhost:2416
RUN go build -ldflags "-linkmode external -extldflags \"-static\"" \
    -tags "osusergo netgo static_build act" \
    -o act-smoke ./act/cmd/act-smoke
CMD ["/src/challenge-bypass-server"]

FROM ubuntu:26.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y ca-certificates awscli less && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates
COPY --from=go_builder /src/challenge-bypass-server /bin/
COPY --from=go_builder /src/act-smoke /bin/
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
