# libvirt-rpc

Pure rust implementation of [libvirt](https://libvirt.org) protocol (no C bindings required).

## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
libvirt-rpc = "0.1"
```

Next, add this to your crate:

```rust
extern crate libvirt_rpc;
```

Documentation: TBD

# LICENSE

This repository contains xdr protocol definitions from libvirt repository licensed under LGPL.
IANAL, but it seems like it makes it LGPL.