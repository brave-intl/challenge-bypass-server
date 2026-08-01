FROM rust:1.97-alpine3.24 AS rust_builder
# musl is this image's native target on both amd64 and arm64, so the staticlib
# needs no cross-target setup and always lands in target/release.
RUN apk add --no-cache git
RUN git clone https://github.com/brave-intl/challenge-bypass-ristretto-ffi /src
WORKDIR /src
# Keep in lockstep with the challenge-bypass-ristretto-ffi version in go.mod so
# the compiled static lib exports match the cgo bindings.
RUN git checkout 450ec6bab8472c95e4ecadf8a3ef9d38f7073fe2
RUN CARGO_PROFILE_RELEASE_LTO=true cargo rustc --release --crate-type staticlib

FROM golang:1.26-alpine3.24 AS go_builder
# cgo needs a C toolchain to link against the Rust staticlib; on musl that is
# gcc + musl-dev.
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
# Resolve modules in their own layer so editing source does not re-download the
# dependency graph on every build.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=rust_builder /src/target/release/libchallenge_bypass_ristretto_ffi.a /usr/lib/libchallenge_bypass_ristretto_ffi.a

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

FROM alpine:3.24
# No apk install: the base already ships the CA bundle that crypto/x509 reads
# (ca-certificates-bundle), and the binary is static, so it needs nothing else.
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
