FROM rustlang/rust@sha256:c30cc9c38f29f7d5f81613aa7969b6b8b7e2808271f6f362b0e106ce7bf6f22c as rust_builder
RUN rustup target add x86_64-unknown-linux-gnu
RUN apt-get update
RUN git clone https://github.com/brave-intl/challenge-bypass-ristretto-ffi /src
WORKDIR /src
RUN git checkout 1.0.1
RUN cargo build --target=x86_64-unknown-linux-gnu --features nightly --release

FROM golang:1.16.15-buster as go_builder
RUN apt-get update && apt-get install -y postgresql-client
RUN mkdir /src
WORKDIR /src
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY --from=rust_builder /src/target/x86_64-unknown-linux-gnu/release/libchallenge_bypass_ristretto_ffi.a /usr/lib/
COPY . .
RUN go build -v --ldflags '-extldflags "-static"' -o challenge-bypass-server main.go
CMD ["/src/challenge-bypass-server"]

FROM alpine:3.6
COPY --from=go_builder /src/challenge-bypass-server /bin/
COPY migrations /src/migrations
EXPOSE 2416
ENV DATABASE_URL=
ENV DBCONFIG="{}"
ENV MAX_DB_CONNECTION=100
CMD ["/bin/challenge-bypass-server"]
