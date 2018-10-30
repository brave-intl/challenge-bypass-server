FROM rustlang/rust:nightly as rust_builder
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools
RUN git clone https://github.com/evq/challenge-bypass-ristretto-ffi /src
WORKDIR /src
RUN git checkout fixDecodeErr
RUN cargo build --target=x86_64-unknown-linux-musl 

FROM golang:1.11 as go_builder
RUN apt-get update && apt-get install -y postgresql-client
COPY --from=rust_builder /src/target/x86_64-unknown-linux-musl/debug/libchallenge_bypass_ristretto.a /usr/lib/
COPY . /src
WORKDIR /src
RUN go build --ldflags '-extldflags "-static"' -o challenge-bypass-server main.go

FROM alpine:3.6
COPY --from=go_builder /src/examples/golang.out /bin/
EXPOSE ${PORT}
CMD ["/bin/golang.out"]
