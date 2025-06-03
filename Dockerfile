FROM rust:1.69 AS rust_builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools
RUN git clone https://github.com/brave-intl/challenge-bypass-ristretto-ffi /src
WORKDIR /src
RUN git checkout 1.0.1
RUN CARGO_PROFILE_RELEASE_LTO=true cargo rustc --target=x86_64-unknown-linux-musl --release --crate-type staticlib

FROM golang:1.24 AS go_builder
RUN apt-get update && apt-get install -y ca-certificates postgresql-client python3-pip awscli
RUN curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(go env GOPATH)/bin latest
RUN mkdir /src
WORKDIR /src
COPY . .
RUN go mod download
COPY --from=rust_builder /src/target/x86_64-unknown-linux-musl/release/libchallenge_bypass_ristretto_ffi.a /usr/lib/libchallenge_bypass_ristretto_ffi.a
RUN go build -ldflags '-linkmode external -extldflags "-static"' -tags 'osusergo netgo static_build' -o challenge-bypass-server main.go
CMD ["/src/challenge-bypass-server"]

FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y ca-certificates awscli less && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates
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
