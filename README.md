# Blinded Tokens Microservice

This is a fork of the [Challenge Bypass Server](https://github.com/privacypass/challenge-bypass-server), that implements the HTTP REST interface, persistence in Postgresql, multiple issuers, etc.

It also uses [cgo bindings to a rust library to implement the cryptographic protocol](https://github.com/brave-intl/challenge-bypass-ristretto-ffi).

## Dependencies

Install Docker.

## Run/build using docker

```
docker-compose up
```

## Linting

This project uses [golangci-lint](https://golangci-lint.run/) for linting, this is run by CI and should be run before raising a PR.

To run locally use `make lint` which runs linting using docker however if you want to run it locally using a binary release (which can be faster) follow the [installation instructions for your platform](https://golangci-lint.run/usage/install/) and then run `golangci-lint run -v ./...`

## Testing
Run the below command in order to test changes, if you have an M1 / M2 MAc follow the steps below to setup docker to be able to run the tests 
```
make docker-test
```

### Have an M1 mac?
1.) In Docker Desktop, go to: `Settings -> Docker Engine` <br />
 #### Modify file to include
 ```
  "runtimes": {
    "runtimes": {
      "linux": {
        "path": "linux"
      }
    }
  }
 ```
2.) Modify Docker File
#### Replace `rust_builder` with:
```
FROM arm64v8/rust:1.69 as rust_builder
RUN rustup target add aarch64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools:arm64
RUN git clone https://github.com/brave-intl/challenge-bypass-ristretto-ffi /src
WORKDIR /src
RUN git checkout 1.0.1
RUN CARGO_PROFILE_RELEASE_LTO=true cargo rustc --target=aarch64-unknown-linux-musl --release --crate-type staticlib
```

#### Replace `go_builder` with:
```
FROM arm64v8/golang:1.18 as go_builder
RUN apt-get update && apt-get install -y ca-certificates postgresql-client python3-pip
RUN pip install awscli --upgrade
RUN curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(go env GOPATH)/bin latest
RUN mkdir /src
WORKDIR /src
COPY . .
RUN go mod download
COPY --from=rust_builder /src/target/aarch64-unknown-linux-musl/release/libchallenge_bypass_ristretto_ffi.a /usr/lib/libchallenge_bypass_ristretto_ffi.a
ENV GOARCH=arm64
RUN go build -ldflags '-linkmode external -extldflags "-static"' -tags 'osusergo netgo static_build' -o challenge-bypass-server main.go
CMD ["/src/challenge-bypass-server"]
```

## Deployment

For testing purposes this repo can be deployed to Heroku. The settings set in environment variables `DBCONFIG` and `DATABASE_URL` override other options.
