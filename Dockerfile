FROM rust:1.90.0-slim-trixie AS builder

ARG GITHUB_SHA="$(git rev-parse HEAD)"
LABEL com.shorter.git-commit="${GITHUB_SHA}"


# fixing the issue with getting OOMKilled in BuildKit
RUN mkdir /shorter
COPY . /shorter/

WORKDIR /shorter
# install the dependencies
RUN apt-get update && apt-get -q install -y \
    git \
    clang \
    pkg-config \
    mold
ENV CC="/usr/bin/clang"
RUN cargo build --quiet --release --bin shorter
RUN chmod +x /shorter/target/release/shorter

# FROM gcr.io/distroless/cc-debian12 AS shorter
FROM rust:1.90.0-slim-trixie AS secondary

RUN apt-get -y remove --allow-remove-essential \
    binutils cpp cpp-14 gcc gcc grep gzip ncurses-bin ncurses-base sed && apt-get autoremove -y && apt-get clean && rm -rf /var/lib/apt/lists/* && rm -rf /usr/local/cargo /usr/local/rustup

# # ======================
# https://github.com/GoogleContainerTools/distroless/blob/main/examples/rust/Dockerfile
COPY --from=builder /shorter/target/release/shorter /
WORKDIR /
RUN useradd -m nonroot

FROM scratch AS final
ARG DESCRIPTION="Rusty little S3-compatible object storage server"
ARG GITHUB_SHA="unknown"
LABEL DESCRIPTION="${DESCRIPTION}"
LABEL com.shorter.git-commit="${GITHUB_SHA}"

COPY --from=secondary / /

ENV SHORTER_DB_PATH="/data/shorter.sqlite3"

USER nonroot
ENTRYPOINT ["./shorter"]


