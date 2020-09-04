%% extends "README_base.md"
%% block body
ZwoHash implements a very fast hash algorithm optimized for the use in
hash tables. It has low per-hash overhead, which is important when hashing small
keys. It is non-cryptographic and deterministic and as such not suited for
inserting untrusted user-provided input into hash tables, unless other denial of
service countermeasures are taken. As such it covers the same use cases as
[rustc's FxHash][rustc_hash].

Compared to FxHash, ZwoHash provides essentially the same hashing speed while
aiming for more uniform outputs. When used in a hash table ZwoHash is almost
always able to match the performance of FxHash while outperforming it by quite
a bit for some common inputs for which FxHash's output is particularly poor.

The hash algorithm used by ZwoHash is very similar to that of FxHash, both
process one `usize` at a time and perform the same number and kind of
operations per `usize`. ZwoHash though, replaces the last iteration with a
slightly more expensive operation that provides better output guarantees. The
additional overhead (independent of the size of the hashed data) consists of
performing a wide multiplication instead of a truncated multiplication and one
additional subtraction. This is very little overhead, and almost doesn't
register when using ZwoHash in a hash table.

ZwoHash guarantees that any input bit can affect any bit of the output. FxHash
does not guarantee this, and even beyond that, ZwoHash's output is more
uniform. When used in a hash table, this often reduces the number of collisions
and thus the number of required probes for each access. This can result in
ZwoHash outperforming FxHash in that setting.

Sometimes, given inputs for which FxHash is especially ill-suited, ZwoHash
outperforms FxHash by a large margin. This includes integer keys that all are a
multiple of a power of two, floating point values with a short base-2
representation, pointers returned from the allocator and other inputs that only
differ in the higher bits of the last processed `usize`.

## Usage

If the `std` feature (enabled by default) is used this crate also exports the
type aliases `HashMap` and `HashSet` which are re-exports of
[`std::collection`][collections] with the hashing algorithm set to ZwoHash. See
their respective documentation for how to use them.

This crate always exports the `ZwoHasher` type which implements the std/core
traits `Hasher` and `Default`, see [`core::hash`][core_hash] for how to use
this within Rust's hashing framework.

## Benchmarks

ZwoHash comes with set of [criterion] benchmarks that test it against FxHash.
You can run them on your machine using `cargo bench`. This takes several
minutes.

## Feedback

The above claims are based on the limited benchmarking I performed so far.
Should you decide to give ZwoHash a try, I would be very much interested in
hearing back from you. I'm especially interested in real-world benchmarks where
ZwoHash is outperformed by FxHash, but I'd also love to hear where ZwoHash
improves performance. Feel free to file issues for this.

## no_std

ZwoHash can be used from no_std code by disabling the default `std` feature of
this crate.
%% endblock
%% block links
[rustc_hash]: https://crates.io/crates/rustc-hash
[criterion]: https://crates.io/crates/criterion
[core_hash]: https://doc.rust-lang.org/core/hash/index.html
[collections]: https://doc.rust-lang.org/std/collections/index.html
%% endblock
