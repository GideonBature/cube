//! Signing for the graph edges, using the repository's own MuSig2 and BIP-340 primitives.
//!
//! Two distinct key-path shapes appear in the scenarios:
//!
//! - the **deposit**, whose key path is a MuSig2 aggregate of the participant and the Engine over
//!   the taproot-tweaked output key. Both signers are simulated in one process, exactly as
//!   `tests/liftv2_regtest.rs` does, because the Bitcoin question being answered is whether the
//!   aggregate satisfies the output key;
//! - ordinary **P2TR fee inputs**, whose key path is one tweaked BIP-340 key.
//!
//! The refund path is a script-path spend and is built here too, because its sequence is the
//! relative timelock and getting that wrong is the failure mode `liftv2-refund` exists to observe.
//!
//! Nonces are derived deterministically from `(secret, message, counter)`. A real signer must use a
//! fresh random seed and must never reuse a nonce; a reproducible fixture needs a stable one.

use anyhow::{bail, Context, Result};
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{TapLeafHash, TapTweakHash};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use cube::constructive::taproot::TapRoot;
use cube::transmutative::hash::{Hash, HashTag};
use cube::transmutative::musig::keyagg::MusigKeyAggCtx;
use cube::transmutative::musig::session::MusigSessionCtx;
use secp::{Point, Scalar};

/// The code-separator position of a script with no `OP_CODESEPARATOR`.
const NO_CODE_SEPARATOR: u32 = 0xffff_ffff;

/// Returns the BIP-340 keypair for a raw secret.
pub fn keypair(secret: [u8; 32]) -> Result<Keypair> {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&secret).context("invalid secret key")?;
    Ok(Keypair::from_secret_key(&secp, &key))
}

/// Returns the x-only public key of a raw secret.
pub fn xonly(secret: [u8; 32]) -> Result<[u8; 32]> {
    Ok(keypair(secret)?.x_only_public_key().0.serialize())
}

/// Signs a 32-byte digest with a raw secret using BIP-340.
pub fn sign_digest(digest: [u8; 32], secret: [u8; 32]) -> Result<[u8; 64]> {
    let secp = Secp256k1::new();
    Ok(secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair(secret)?)
        .serialize())
}

/// Verifies a BIP-340 signature locally, before spending an RPC round trip on it.
pub fn verify_digest(key: [u8; 32], digest: [u8; 32], signature: [u8; 64]) -> Result<()> {
    let secp = Secp256k1::new();
    secp.verify_schnorr(
        &bitcoin::secp256k1::schnorr::Signature::from_slice(&signature)
            .context("invalid signature")?,
        &Message::from_digest(digest),
        &XOnlyPublicKey::from_slice(&key).context("invalid x-only key")?,
    )
    .context("the signature does not verify against the output key")
}

/// Returns the even-Y point of an x-only key, which is how LiftV2 lifts its keys.
pub fn point_from_xonly(key: [u8; 32]) -> Result<Point> {
    let mut compressed = Vec::with_capacity(33);
    compressed.push(0x02);
    compressed.extend(key);
    Point::from_slice(&compressed).context("invalid x-only key")
}

/// Returns the secret-key scalar, normalised to the even-Y lift of its public point.
///
/// `return_liftv2_taproot` lifts every x-only key to its even-Y point, so a signer whose secret
/// produces an odd-Y point must negate its scalar to be recognised as that signer.
pub fn scalar_of(secret: [u8; 32]) -> Result<Scalar> {
    let scalar = Scalar::from_slice(&secret).context("invalid secret scalar")?;
    Ok(scalar.negate_if(scalar.base_point_mul().parity()))
}

/// Derives a deterministic MuSig2 nonce secret.
fn secret_nonce(secret: [u8; 32], message: [u8; 32], index: u8) -> Scalar {
    let mut preimage = Vec::with_capacity(65);
    preimage.extend(secret);
    preimage.extend(message);
    preimage.push(index);
    let digest = preimage.hash(Some(HashTag::CustomString(
        "Cube/musig/nonce/v0".to_string(),
    )));
    Scalar::from_slice(&digest).expect("a tagged digest is a valid scalar")
}

/// Aggregates the LiftV2 keys with the taproot tweak applied.
fn key_agg_ctx(taproot: &TapRoot, signers: &[[u8; 32]]) -> Result<MusigKeyAggCtx> {
    let mut keys = Vec::with_capacity(signers.len());
    for secret in signers {
        keys.push(point_from_xonly(xonly(*secret)?)?);
    }
    let tweak = Scalar::from_slice(&taproot.tap_tweak()).context("invalid taproot tweak")?;
    MusigKeyAggCtx::new(&keys, Some(tweak)).context("MuSig2 key aggregation failed")
}

/// Produces a MuSig2 signature over `message` for the LiftV2 key path.
///
/// The aggregate must equal the output key before a signature is attempted: a mismatch means the
/// fixture keys and the taproot disagree, and signing would only hide that.
pub fn musig_sign(
    taproot: &TapRoot,
    signers: &[[u8; 32]],
    message: [u8; 32],
) -> Result<([u8; 64], [u8; 32])> {
    if signers.len() != 2 {
        bail!("the LiftV2 key path has exactly two signers");
    }

    // 1 The tweaked aggregate must be the on-chain output key.
    let key_agg_ctx = key_agg_ctx(taproot, signers)?;
    let agg_key_xonly = key_agg_ctx.agg_key().serialize_xonly();
    let spk = taproot
        .spk()
        .context("the LiftV2 taproot has no scriptpubkey")?;
    if spk.get(2..34) != Some(agg_key_xonly.as_slice()) {
        bail!("the MuSig2 aggregate does not equal the taproot output key");
    }

    let mut session = MusigSessionCtx::new(&key_agg_ctx, message).context("MuSig2 session")?;

    // 2 Exchange public nonces.
    for secret in signers {
        let hiding = secret_nonce(*secret, message, 0);
        let binding = secret_nonce(*secret, message, 1);
        let key = point_from_xonly(xonly(*secret)?)?;
        if !session.insert_nonce(key, hiding.base_point_mul(), binding.base_point_mul()) {
            bail!("MuSig2 rejected a nonce");
        }
    }
    if !session.ready() {
        bail!("the MuSig2 session is not ready with both nonces");
    }

    // 3 Exchange partial signatures.
    for secret in signers {
        let hiding = secret_nonce(*secret, message, 0);
        let binding = secret_nonce(*secret, message, 1);
        let key = point_from_xonly(xonly(*secret)?)?;
        let partial = session
            .partial_sign(scalar_of(*secret)?, hiding, binding)
            .context("MuSig2 partial signature")?;
        if !session.insert_partial_sig(key, partial) {
            bail!("MuSig2 rejected a partial signature");
        }
    }

    // 4 Aggregate and self-check.
    let signature = session.full_agg_sig().context("no aggregate signature")?;
    verify_digest(agg_key_xonly, message, signature)?;
    Ok((signature, agg_key_xonly))
}

/// Returns the BIP-341 key-path sighash of one input.
pub fn key_path_sighash(
    transaction: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32]> {
    let sighash = SighashCache::new(transaction)
        .taproot_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            None,
            None,
            TapSighashType::Default,
        )
        .context("taproot key-path sighash")?;
    Ok(sighash.to_byte_array())
}

/// Signs one input of `transaction` through the LiftV2 MuSig2 key path and returns its witness.
pub fn deposit_key_path_witness(
    taproot: &TapRoot,
    signers: &[[u8; 32]],
    transaction: &Transaction,
    input_index: usize,
    prevout: &TxOut,
) -> Result<Witness> {
    let digest = key_path_sighash(transaction, input_index, std::slice::from_ref(prevout))?;
    let (signature, _) = musig_sign(taproot, signers, digest)?;
    Ok(Witness::from_slice(&[signature.to_vec()]))
}

/// Signs one input of a transaction with an ordinary tweaked P2TR key.
pub fn p2tr_key_path_signature(
    secret: [u8; 32],
    transaction: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 64]> {
    let secp = Secp256k1::new();
    let key = keypair(secret)?;
    let xonly = key.x_only_public_key().0;
    let tweak = TapTweakHash::from_key_and_tweak(xonly, None).to_scalar();
    let signer = key
        .add_xonly_tweak(&secp, &tweak)
        .context("cannot tweak the fee key")?;
    let digest = key_path_sighash(transaction, input_index, prevouts)?;
    let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &signer);
    // The signature is against the tweaked output key, not the internal key.
    secp.verify_schnorr(
        &signature,
        &Message::from_digest(digest),
        &signer.x_only_public_key().0,
    )
    .context("the fee-input signature does not verify")?;
    Ok(signature.serialize())
}

/// Builds and signs the LiftV2 refund transaction through the script path.
///
/// The sequence is the relative timelock itself, so the transaction is non-final until the deposit
/// outpoint has `delay_blocks` confirmations. The script names the account key, which must be the
/// signer.
pub fn refund_transaction(
    taproot: &TapRoot,
    outpoint: OutPoint,
    prevout: &TxOut,
    destination: ScriptBuf,
    delay_blocks: u16,
    fee_sats: u64,
    account_secret: [u8; 32],
) -> Result<Transaction> {
    let tree = taproot.tree().context("the LiftV2 taproot has no tree")?;
    let leaf = tree
        .leaves()
        .into_iter()
        .next()
        .context("the LiftV2 taproot has no leaf")?;
    let script = leaf.tap_script();
    let leaf_hash = TapLeafHash::from_byte_array(leaf.tapleaf_hash());
    let control_block = taproot
        .control_block(0)
        .context("no control block")?
        .to_vec();

    let value = prevout
        .value
        .to_sat()
        .checked_sub(fee_sats)
        .context("the miner fee exceeds the deposit")?;
    let mut transaction = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(u32::from(delay_blocks)),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: destination,
        }],
    };

    let sighash = SighashCache::new(&transaction)
        .taproot_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(prevout)),
            None,
            Some((leaf_hash, NO_CODE_SEPARATOR)),
            TapSighashType::Default,
        )
        .context("refund script-path sighash")?;
    let signature = sign_digest(sighash.to_byte_array(), account_secret)?;
    verify_digest(xonly(account_secret)?, sighash.to_byte_array(), signature)?;

    transaction.input[0].witness =
        Witness::from_slice(&[signature.to_vec(), script, control_block]);
    Ok(transaction)
}
