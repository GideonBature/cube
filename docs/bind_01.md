# BIND-01: binding a proof assertion to the bytes Bitcoin enforces

**Status:** partially resolved. This document specifies the binding construction, and
`src/constructive/graph/assertion.rs` implements it. The remaining gap is named in section 7: a
fully unilateral operator assertion needs a public input-label commitment that Argo's MAC interface
does not provide.

**Companion:** [specification.md](specification.md) sections 7, 8 and 9.2,
[implementation.md](implementation.md) section 5.3.

## 1. What has to be true

A claim output already commits one value structurally:

```text
<statement digest D:32> OP_DROP <beneficiary key:32> OP_CHECKSIG
```

The digest is inside the tapscript, so the output key fixes it; a spend that reveals any other
script fails the taproot commitment. An `Assert` edge adds a Groth16 proof and an Argo table
evaluation on top of that. Bitcoin checks scripts and signatures, not pairings, so four properties
have to be supplied by construction rather than assumed:

| Property | Meaning |
|---|---|
| **S** statement binding | The scalar `x` the table evaluates is the claim's `D`, not a re-contextualised proof |
| **I** input binding | The evaluated `(A, B, C, x)` is exactly the published input, byte for byte |
| **E** evidence | An invalid evaluation yields the disclosure secret `s`, and `s` can be spent on-chain |
| **T** no false dispute | A valid evaluation does not yield `s`, so an honest assertion cannot be disputed |

## 2. What Argo already authenticates, and what it does not

Argo setup produces three things: a garbling table, a disclosure secret `s`, and an input MAC key
`K`. For one proof `P = (A, B, C, x)` the setup holder computes `M = MAC_K(P)`. Anyone holding the
table evaluates `(P, M)` and gets either `0` (accepted) or `s`. Without `K`, no party can produce a
MAC for any other input, so a published `(P, M)` can be evaluated and nothing else can.

That is the useful half. The adapter exposes it as `AuthenticatedInput`:

```text
u32 LE(input length) || Input canonical bytes
u32 LE(MAC length)   || InputMac canonical bytes
```

with the digest `TaggedHash("CubeV1/AuthenticatedInput/v0", bytes)`. `AuthenticatedInput` is
canonical, and `from_bytes` rejects a second encoding of the same value.

The other half is the limitation that shapes the rest of this design. **A MAC that was not made for
the input is not evidence.** Argo's sub-tables fail to decode it, and `Table::evaluate` returns an
error before the conditional reveal can run. `crates/cube-argo/tests/garbling.rs` records the actual
result: an honest input carrying another input's MAC produces `Err(EvaluationFailed)`, not `s`.

An operator holding the setup's MAC key could therefore publish a valid MAC next to a different
invalid proof, provoke an error, and leave a challenger with nothing to spend. A MAC authenticates
an input *to the table*; it is not a public commitment *to the chain*. Something else has to bind
the published bytes.

## 3. The binding layer: the value owner signs the input digest

The party whose value is at stake is the setup holder. For a beneficiary claim that is the
beneficiary: it runs or verifies the setup, so it knows `s` and holds `K`. The operator receives
only the `AuthenticatedInput` for the proof it wants to assert.

The beneficiary binds the input by signing the `Assert` input. The claim's assertion leaf is:

```text
<D:32> OP_DROP <B:32> OP_DROP <beneficiary key:32> OP_CHECKSIG
```

with

```text
B = TaggedHash("CubeV1/Assertion/v0", encode(AssertionTerms))
```

and `AssertionTerms` carrying, in a fixed order:

| Field | Width | Why |
|---|---|---|
| schema version | 1 | Frozen encoding |
| statement digest `D` | 32 | Ties the assertion to the claim's statement |
| claim id | 32 | A salt unique to the claim |
| setup instance ID | 16 | One instance per contested output |
| verifier key identity | 32 | The relation cannot be swapped |
| table digest | 32 | The challenger checks the table it obtained |
| secret commitment | 32 | The `Disprove` hashlock |
| authenticated input digest | 32 | The exact bytes evaluated |
| challenge window (blocks) | 4 | The `Take` CSV |
| operator key | 32 | The only key that can `Take` |
| beneficiary key | 32 | The only key that can `Disprove` |

The BIP-341 sighash of the `Assert` input covers the assertion output, whose taproot output key
commits both leaves and therefore `B`, and `B` commits the input digest. The beneficiary's signature
is over that sighash. The operator cannot replace the input after the signature; the challenger can
evaluate exactly the bytes that were signed.

The outpoint and value are deliberately **not** in `B`. The claim script exists before the claim
output exists, so a script that embedded its own outpoint would be circular. The salt is the claim
id; the specific UTXO and value are bound by the sighash over the input the signature covers.

This is the role a BitVM3 input label plays in the Boolean setting: a public, on-chain-checkable
commitment to the input actually evaluated. It is a signature rather than a label tree because
Argo's input encoding is field-and-digit based and exposes no per-bit labels; a separate tree would
not be consumed by the table and would prove nothing about the evaluation.

## 4. The assertion output

```text
input  0: the contested output (claim v2 assertion leaf, beneficiary signature)
output 0: the assertion taproot, value = contested - miner fee
```

with two leaves and no key path:

```text
Take      <B:32> OP_DROP <challenge blocks> OP_CSV OP_DROP <operator key:32> OP_CHECKSIG
Disprove  <B:32> OP_DROP OP_SHA256 <secret commitment:32> OP_EQUALVERIFY
          <beneficiary key:32> OP_CHECKSIG
```

The disclosure commitment is a plain hash, because `OP_SHA256` is all the leaf can compute:

```text
secret_commitment = SHA256(s_le:32)
```

The instance binding is not in this hash: it is in `B`, which the same leaf embeds. A secret reused
across two instances therefore opens both hashlocks, but each assertion output still commits a
different `B`; preventing reuse is a setup-procedure rule, not something the script can detect.

The `Take` input sequence is `Sequence::from_height(challenge_blocks)`; the relative timelock is
measured from the assertion's confirmation. The `Disprove` spend has no timelock: it is valid as soon
as the assertion output exists, which is what gives the challenge window its meaning.

`Disprove` requires the beneficiary's signature. A third party who evaluates an invalid assertion
and learns `s` can notify the beneficiary, but cannot redirect the value. This is the bounded pilot
choice; a permissionless bounty needs a covenant that pays a submitter output, which Bitcoin
tapscript cannot express without an additional construction.

## 5. Flow

1. **Setup** (beneficiary): garble the verifier key, commit `table_digest` and
   `secret_commitment`; publish the table through the data channel.
2. **Prove** (operator): produce `P` for `D`.
3. **Authenticate** (beneficiary): check `x == OS2IP_BE(D)`, call `authenticate(P)`, evaluate the
   authenticated input, and sign the `Assert` input only if the result is `Accepted`. The signature
   is the binding; the `Disprove` leaf is the backstop for a client that skipped the evaluation or
   for a setup later shown unsound.
4. **Assert** (operator): publish the assertion output, the 277-byte `AssertionTerms` and the
   `AuthenticatedInput` bytes.
5. **Evaluate** (anyone): fetch the table, check `table_digest`, evaluate the published bytes. The
   result is `Accepted` or `Disclosed(s)`; an error is a liveness failure, never acceptance.
6. **Take** (operator): after `challenge_blocks`, spend the `Take` leaf.
7. **Disprove** (beneficiary): before the `Take` confirms, spend the `Disprove` leaf with `s`.

## 6. Attacks this construction rejects

| Attempt | What stops it |
|---|---|
| Valid proof for another statement | `x` is bound to `D` by the signed `B`; the claim's taproot embeds `D` |
| Invalid proof | Evaluation returns `s`; `Disprove` spends the output |
| Swapping `A`, `B`, `C` after authentication | The beneficiary's signature covers the input digest; the assertion output key changes |
| Swapping the MAC for another input | Same: the signature covers the MAC bytes. The table's error is not needed |
| Replaying an assertion for another claim/outpoint | The claim id is inside `B`, and the signature covers the actual outpoint and value in the sighash |
| Substituting the table | `table_digest` is inside `B`; a challenger refuses a mismatching table |
| Reusing a table for a second assertion | The instance ID is in `B`, so the two assertions have different outputs, but a leaked secret opens both hashlocks; one-time use is a setup-procedure rule, not something the script can detect |
| Wrong secret | The hashlock checks the committed SHA-256 preimage |
| Premature `Take` | `OP_CSV` against the committed input sequence |
| A third party learns `s` | It can spend `Disprove` only with the beneficiary's signature |

## 7. What is still open

- **Unilateral assertion.** Without the beneficiary's signature the operator cannot assert. A
  fully unilateral path needs a public input-label commitment whose opening is on-chain-checkable
  and is consumed by the garbling. Argo does not expose one at the pinned revision, so BIND-01
  remains open for that profile. The MAC-plus-signature construction is the participant-scoped
  profile: protection comes from the participant's own setup and signature.
- **Graph economics.** Which output is contested (a claim, a fee output or an operator bond) is a
  graph decision. The mechanism does not assume an answer, and `GRAPH-01` stays open.
- **Claim v2.** The assertion leaf changes the claim taproot. A claim that carries it needs a
  recovery-package version that carries the second leaf and control block. The v1 package is
  unchanged.
- **Data availability.** The 277-byte terms, 36,928 bytes of authenticated input and an
  18,067,073-byte table have to be retrievable before the challenge deadline. `B` is a commitment;
  a challenger cannot recover the terms from it. A digest on chain is not publication; `DA-01`
  stays open.
- **Setup security.** One-time instances, participant-scoped setup transcripts, the malicious
  security variant and the secret's entropy are separate `P5` work. A test setup is not a
  production setup.
- **In-circuit authorization.** The relation still does not verify BIP-340; the graph signatures
  are the authorization, as recorded in `src/constructive/graph/mod.rs`.
