FROM rust:1.99-alpine3.24 AS rust_builder
# musl is this image's native target on both amd64 and arm64, so the staticlib
# needs no cross-target setup and always lands in target/release.
# gcc + musl-dev: blake3 (an ACT dependency) compiles C/asm.
RUN apk add --no-cache gcc musl-dev
# act/ffi builds ONE static library: challenge-bypass-ristretto-ffi (pinned in
# act/ffi/Cargo.toml; keep in lockstep with go.mod so the exports match the cgo
# bindings) plus the ACT bindings. Two Rust staticlibs cannot be linked into one
# static binary (duplicate libstd), so the ristretto lib is no longer built alone.
COPY act/ffi /src
WORKDIR /src
RUN cargo build --locked --release

FROM golang:1.27-alpine3.24 AS go_builder
# cgo needs a C toolchain to link against the Rust staticlib; on musl that is
# gcc + musl-dev.
RUN apk add --no-cache gcc musl-dev
# musl gives each thread only 128 KB of stack, and cgo calls run on Go's
# threads. lib.rs already isolates Params::new on a 1 MiB thread, and 1 MiB
# here provides stack margin for any deep Rust FFI call.
ENV CGO_LDFLAGS="-Wl,-z,stack-size=1048576"
WORKDIR /src
# Resolve modules in their own layer so editing source does not re-download the
# dependency graph on every build.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=rust_builder /src/target/release/libcbp_act_ffi.a /usr/lib/libchallenge_bypass_ristretto_ffi.a

ARG VERSION
ARG COMMIT
ARG BUILD_TIME
# Drop `act` to build without Anonymous Credit Tokens (routes then return 501).
ARG BUILD_TAGS="osusergo netgo static_build act"
RUN mkdir -p /out && go build -ldflags "\
    -X main.Version=${VERSION} \
    -X main.BuildTime=${BUILD_TIME} \
    -X main.Commit=${COMMIT} \
    -linkmode external -extldflags \"-static\"" \
    -tags "${BUILD_TAGS}" \
    -o /out/challenge-bypass-server main.go && \
    cp /out/challenge-bypass-server /src/challenge-bypass-server
# Build /bin/act-smoke only when the `act` build tag is enabled.
RUN if echo " ${BUILD_TAGS} " | grep -q " act "; then \
      go build -ldflags "-linkmode external -extldflags \"-static\"" \
        -tags "osusergo netgo static_build act" \
        -o /out/act-smoke ./act/cmd/act-smoke; \
    fi
CMD ["/src/challenge-bypass-server"]

FROM alpine:3.24
# No apk install: the base already ships the CA bundle that crypto/x509 reads
# (ca-certificates-bundle), and the binary is static, so it needs nothing else.
COPY --from=go_builder /out/ /bin/
COPY migrations /src/migrations
EXPOSE 2416
ENV DATABASE_URL=
ENV DBCONFIG="{}"
ENV MAX_DB_CONNECTION=100
ENV AWS_REGION="us-west-2"
ENV EXPIRATION_WINDOW=7
ENV RENEWAL_WINDOW=30
ENV DYNAMODB_ENDPOINT=
ENV ACT_ENABLED=false
CMD ["/bin/challenge-bypass-server"]
