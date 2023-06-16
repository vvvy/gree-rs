ARG RUST_VERSION=1.70.0

FROM rust:$RUST_VERSION

# Install Zig
ARG ZIG_VERSION=0.10.1
RUN curl -L "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-$(uname -m)-${ZIG_VERSION}.tar.xz" | tar -J -x -C /usr/local && \
    ln -s "/usr/local/zig-linux-$(uname -m)-${ZIG_VERSION}/zig" /usr/local/bin/zig

# Install Rust targets
RUN rustup target add \
    arm-unknown-linux-gnueabihf \
    arm-unknown-linux-musleabihf

# Install cargo-zigbuild
RUN cargo install cargo-zigbuild

WORKDIR /project

ENTRYPOINT ["cargo", "zigbuild"]
