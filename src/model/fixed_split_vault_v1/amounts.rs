use crate::model::fixed_split_vault_v1::error::SplitVaultError;
use crate::model::fixed_split_vault_v1::types::{
    BOB_WEIGHT_BPS, BPS_DENOMINATOR, CAROL_WEIGHT_BPS, MINIMUM_CLAIM_SATS,
};

/// The exact allocation produced by one accepted `FundSplit`.
///
/// The relation `D = bob_sats + carol_sats` always holds, and `bob_remainder_bps` is the integer
/// remainder that the future Groth16 circuit must re-prove as
/// `D * 7000 = bob_sats * 10000 + bob_remainder_bps` with `0 <= bob_remainder_bps < 10000`
/// (specification.md section 7.3, item 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitAmounts {
    /// `G - E`: the value that is actually allocated to the two beneficiaries.
    pub distributable_sats: u64,
    /// Bob's allocation, `floor(D * 7000 / 10000)`.
    pub bob_sats: u64,
    /// Carol's allocation, `D - bob_sats`. Carol receives the integer remainder.
    pub carol_sats: u64,
    /// The quotient/remainder witness of Bob's floor division.
    pub bob_remainder_bps: u16,
}

/// Computes the fixed 70/30 allocation for a gross amount and a disclosed execution fee.
///
/// The computation uses checked wide arithmetic for the multiplication and exact range checks
/// before storing `u64` satoshis. No floating point is involved and no satoshi is created or lost.
///
/// Rejections are checked in this frozen order so that two implementations agree on the returned
/// error as well as on the accepted value:
///
/// 1. `G == 0`
/// 2. `E >= G`
/// 3. `floor(D * 7000 / 10000) == 0` or `D - Bob == 0`
/// 4. either allocation below `MINIMUM_CLAIM_SATS`
pub fn split_amounts(
    gross_sats: u64,
    execution_fee_sats: u64,
) -> Result<SplitAmounts, SplitVaultError> {
    // 1 Reject a zero gross amount.
    if gross_sats == 0 {
        return Err(SplitVaultError::GrossAmountIsZero);
    }

    // 2 Reject an execution fee that is not strictly below the gross amount.
    //    `0 <= E < G` is required so that the distributable amount is strictly positive.
    if execution_fee_sats >= gross_sats {
        return Err(SplitVaultError::ExecutionFeeNotBelowGross {
            gross_sats,
            execution_fee_sats,
        });
    }

    // 3 Compute the distributable amount. The subtraction cannot underflow after step 2.
    let distributable_sats = gross_sats - execution_fee_sats;

    // 4 Multiply in a wide integer: `D * 7000` needs 13 more bits than `D` and must not wrap.
    let weighted_bob = (distributable_sats as u128) * (BOB_WEIGHT_BPS as u128);

    // 5 Divide by the basis-point denominator. The quotient is at most `D * 0.7`, so it fits u64;
    //   the conversion is still checked so that the range claim is enforced rather than assumed.
    let bob_wide = weighted_bob / (BPS_DENOMINATOR as u128);
    let bob_sats = u64::try_from(bob_wide).map_err(|_| SplitVaultError::AllocationOverflow {
        allocation_wide: bob_wide,
    })?;

    // 6 Record the integer remainder as the circuit witness.
    let bob_remainder_bps = (weighted_bob % (BPS_DENOMINATOR as u128)) as u16;

    // 7 Carol receives the integer remainder of the distributable amount.
    let carol_sats = distributable_sats - bob_sats;

    // 8 Reject a zero allocation on either side.
    if bob_sats == 0 || carol_sats == 0 {
        return Err(SplitVaultError::ZeroBeneficiaryAllocation {
            bob_sats,
            carol_sats,
        });
    }

    // 9 Reject allocations below the selected minimum claim value.
    if bob_sats < MINIMUM_CLAIM_SATS || carol_sats < MINIMUM_CLAIM_SATS {
        return Err(SplitVaultError::BelowMinimumClaim {
            bob_sats,
            carol_sats,
            minimum_sats: MINIMUM_CLAIM_SATS,
        });
    }

    // 10 Return the exact allocation.
    Ok(SplitAmounts {
        distributable_sats,
        bob_sats,
        carol_sats,
        bob_remainder_bps,
    })
}

/// Returns the number of basis points that Carol is entitled to.
///
/// Kept next to `split_amounts` so that a reviewer can confirm that the two weights always sum to
/// the denominator.
pub const fn carol_weight_bps() -> u16 {
    CAROL_WEIGHT_BPS
}
