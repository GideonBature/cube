# Local patches to vendored Argo

Vendored from `https://github.com/idealgroup/argo` at revision
`aa28ba884f9af3d41265774a882d4efd9f4d9b95`, the revision recorded in `docs/implementation.md`
section 2. The upstream `LICENSE` is kept next to this file.

The tree is otherwise unmodified. Every change is marked with a `PATCH(cube)` comment at the site.

## 1. Verifier preprocessing is keyed by the verifier key

**File:** `src/garble/groth16_verifier/mod.rs`

**Upstream behaviour:** `garble_preprocess` caches `e(G, H1)^{2^i}` / `e(G, H2)^{2^i}` in a
process-global `static PREPROCESSED_VK: RwLock<Option<GarblePreprocessedVk>>` and returns the first
value it ever computed, without checking which verifier key produced it.

**Why that is wrong:** the cached powers are a function of the key's `H1`/`H2`. Garbling a second,
different key in the same process reused the first key's powers while the table carried the second
key's equation, so that table evaluates its own valid proofs as failures. One verifier key per
process was not a documented restriction, so this was a latent correctness bug for any process
holding more than one key.

**Patch:** the cache entry now stores the key's canonical encoding next to the powers and is only
reused when the identity matches. A miss recomputes. Concurrent garbling of two different keys can
therefore recompute rather than share, but no caller can receive another key's powers: each caller
returns the value it computed itself. The cache is last-writer-wins, so it is a cache and not a
source of truth.

**Validation:** `crates/cube-argo/tests/garbling.rs` garbles two different keys in one process and
requires each table to accept its own proof and to disclose on the other key's proof. Reverting this
patch makes that test fail at the second key's own valid proof, which is the upstream behaviour being
corrected.

## 2. The package is its own workspace

**File:** `Cargo.toml`

**Why:** as a path dependency inside the Cube workspace, Cargo would otherwise treat this package as
an implicit workspace member, pulling 7.8k lines of upstream code into `cargo fmt --all` and
`clippy --all-targets -- -D warnings`. The Cube workspace also lists this path in `exclude`.

## Not patched, recorded instead

- **`garble_groth16` takes a `u64` seed.** The whole garbling is seeded from 64 bits, which is an
  upstream API limit. `crates/cube-argo` domain-separates the seed it passes but cannot raise the
  ceiling.
- **`Table::evaluate` discards the input-validity disclosure value.** It calls
  `input_validity::evaluate(..)?` and drops the returned `Fq`, so a malformed input that should
  disclose evidence does not contribute any. Changing that would change the cryptographic contract,
  so it is recorded as an open defect rather than patched here.
- **`.cargo/config.toml` target `rustflags`.** The vendored build is invoked from the Cube workspace,
  so these per-target `aes_armv8` cfgs are not applied. The portable AES path is used unless the
  workspace sets the cfg itself.
