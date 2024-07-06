# gree
Controlling Gree Smart air conditioning units via Rust

See examples.

## Building with docker

This Dockerfile uses `zig` and `cargo-zigbuild` for easy cross-compilation. 

Build docker image

```bash
docker build --tag vvv/cargo-zigbuild:1.70.0 .
```

Build example (works also in `powershell`)

```bash
docker run --rm -v "$(pwd):/project" vvv/cargo-zigbuild:1.70.0 --target arm-unknown-linux-gnueabihf.2.24 --examples --release
```

or, to save some time in repetitive builds (useful only if your host OS is Linux or (maybe) WSL; for non-WSL Win host the 
effect is negative):

```bash
docker run --rm -v "$(pwd):/project" -v "$(pwd)/../tmp/cache:/root/.cache" -v "$(pwd)/../tmp/registry:/usr/local/cargo/registry" vvv/cargo-zigbuild:1.70.0 --target arm-unknown-linux-gnueabihf.2.24 --examples --release
```


## Links

* https://github.com/tomikaa87/gree-remote - Protocol description, API in several languages, CLI in python