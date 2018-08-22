# domain-resolv-preview

An asynchronous DNS stub resolver.

*This crate is currently under development and cannot actually resolve
anything just yet.*


## Beware

This crate uses the upcoming async/await features of the Rust compiler as
well as the revised _futures_ crate currently released as _futures-preview._
As such, it will only work with a reasonably recent nightly compiler.

This, of course, will change once async/await and future _futures_ have been
stabilized.


## Usage

First, add this to your `Cargo.toml`:

```toml
[dependencies]
domain-resolv-preview = "0.3"
```

Then, add this to your crate root:

```rust
extern crate domain_resolv;
```

Note that the extern crate name is `domain_resolv`.

