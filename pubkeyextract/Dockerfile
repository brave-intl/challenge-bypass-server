FROM rust:1.69 as rust_builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools
RUN git clone https://github.com/brave-intl/challenge-bypass-ristretto-ffi /src
WORKDIR /src
RUN git checkout 1.0.1
RUN CARGO_PROFILE_RELEASE_LTO=true cargo rustc --target=x86_64-unknown-linux-musl --release --crate-type staticlib

FROM golang:1.20 as go_builder
RUN mkdir /src
WORKDIR /src
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY --from=rust_builder /src/target/x86_64-unknown-linux-musl/release/libchallenge_bypass_ristretto_ffi.a /usr/lib/libchallenge_bypass_ristretto_ffi.a
COPY . .
RUN ld -lchallenge_bypass_ristretto_ffi --verbose
RUN go build --ldflags '-extldflags "-static"' -o main main.go
CMD ["/src/main"]

FROM alpine:3.6
COPY --from=go_builder /src/main /bin/
CMD ["/bin/main"]
