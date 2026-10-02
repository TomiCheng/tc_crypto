# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Rules

- Comments and documentation are written in English only — doc comments,
  README, changelog, and inline comments alike.
- Never wire a README into rustdoc (`#![doc = include_str!("../README.md")]`).
  The README's badges and relative links do not survive rustdoc rendering.
  Crate documentation lives in `//!` and `///` comments; the README repeats what
  a reader on crates.io needs.
- No breaking changes. Public API work is additive: adding items, trait
  implementations, or default methods. If a change cannot be made additively,
  stop and raise it rather than altering an existing signature or behavior.
- Every crate README opens with the badge block: crates.io, docs.rs, CI,
  license, and rustc.
- Crate READMEs use no Markdown tables; crates.io renders them badly. Traits,
  types and features are flat one-line bullets (`` `Item` — what it does. ``),
  with any further detail in the paragraph below the list. Benchmark results
  and how to reproduce them live in the crate's `BENCHES.md`, which is in the
  `include` list, and the README links to it. `BENCHES.md` is read on GitHub,
  so its results may use tables.

The crate list and workspace-wide checks live in the root
[README.md](README.md); read it rather than restating it here. Every crate is
`no_std` and needs no allocator by default.

`tc_buffered_cipher` holds the `BufferedCipher` and `BufferedCipherInit`
contracts, the Rust form of Bouncy Castle's `IBufferedCipher`, its own
`CipherDirection` with `From` conversions to and from those of
`tc_block_cipher` and `tc_stream_cipher`, `BufferedError`, and one adapter per
family under Bouncy Castle's names: the block adapters over `tc_block_modes`,
the padded ones over `tc_block_padding`, `BufferedStreamCipher` over
`tc_stream_cipher`, and `BufferedAeadBlockCipher` and `BufferedAeadCipher`
over `tc_aead_cipher`. It depends on those crates and `tc_zeroize` on every
target, and CI enforces that set with `cargo tree` on the
`wasm32-unknown-unknown`, `aarch64-unknown-none` and x86 targets. Its only
feature, `alloc`, is default-off and adds `BufferedBlockCipher` and
`PaddedBufferedBlockCipher`, which size their buffers from the mode at run
time; the `Fixed` forms keep theirs inline. The stream and AEAD support is
deliberately not behind features: making it optional now would break builds
that disable default features.

The traits keep their error and parameter types generic and need no
allocator; type erasure for a name-based factory belongs to a crate built on
top, not here. Parameter types only carry values, and the wrapped cipher
validates them in `init`. The block and stream adapters report
`BufferedError`; the AEAD adapters keep their engine's error type so that a
failed tag check or a refused nonce reuse arrives unchanged, and `Display` on
`BufferedError` describes only its own layer, leaving the cipher's error to
`source`. The `Fixed` block adapters panic in `new` when `N` differs from the
mode's block size. Padded encryption follows a full final block with a block
of padding alone, whatever the scheme, as Bouncy Castle does.

Every adapter is constant time exactly when the cipher it wraps is; lengths
are public. Padded decryption reveals the padding length and validity, a
padding oracle, and its documentation says so and points to authenticated
encryption. `tests/documentation.rs` requires each declaration it scans to say
which, and matches the phrase within one line, so never wrap a line between
"constant" or "variable" and "time". Keep the timing contract of each item
stated in its doc comment. The block adapters wipe their buffers on reset and
on drop through `Zeroizing`, which keeps an outer `Drop` out of the way.

`unsafe` code is forbidden at the crate root.

Rust 1.85 is guaranteed for every build, since every dependency is a `tc_*`
crate; dev-dependencies are exempt. The MSRV job therefore runs `cargo check`
on 1.85 with and without `alloc`; tests run on stable. `.cargo/config.toml`
sets `incompatible-rust-versions = "allow"` so `Cargo.lock` tracks the latest
releases and stable CI tests what current toolchains resolve. Adding a
third-party dependency to a default build or a first-party feature hands the
1.85 guarantee to that crate; raise it before doing so.

A crate depends on a workspace sibling through `path` plus `version`, so the
workspace builds and tests against the local crate while the published package
requires the release. When a change needs a sibling API that is not released
yet, raise the `version` requirement to the release that adds it; that release
has to be published first.

## Conventions

Each crate ships its own `README.md`, `CHANGELOG.md`, `LICENSE-MIT`,
`LICENSE-APACHE`, and an explicit `include` list in `Cargo.toml`. Changelog
entries are written as `## <version> - Unreleased` and dated in a separate
commit at release, with `### Added` and `### Compatibility` sections.

Adding a crate to the workspace means five edits beyond the crate itself: the
`members` list, a `-p <crate>` on the single `cargo package --locked` step in
the CI `quality` job (the only place package archives are verified; packaging
the crates in one invocation checks each against its siblings' local sources
rather than their releases), a `cargo tree` check of its dependency set in the
CI `portable` job, a row in the root `README.md`, and
workspace inheritance for `edition`, `rust-version`, `license`, and
`repository`. A missing `rust-version` also leaves clippy suggesting APIs newer
than 1.85.

Documentation is part of the contract: crates use `#![deny(missing_docs)]`,
doctests carry the executable examples, and CI runs `cargo doc` with
`RUSTDOCFLAGS: -D warnings`, with and without `--all-features`. Doc links to
feature-gated items break the build without that feature, so name them in plain
code spans. An additive public API change belongs in the crate README's
contract lists — "Types", "Traits" and "Features" in
`tc_buffered_cipher/README.md` — and in the changelog, not only in the code.

Work happens on `feat/*` branches off `develop`; pull requests target `develop`,
which merges to `main`. Commit messages use an imperative subject and a wrapped
body that explains the reasoning, not a bullet list of the diff.

Note: the root `Cargo.toml` uses CRLF line endings while the rest of the tree
uses LF. Tools that rewrite whole files will flip it and produce a noisy diff.
