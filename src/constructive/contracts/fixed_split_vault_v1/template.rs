use crate::constructive::calldata::element_type::CalldataElementType;
use crate::executive::executable::compiler::compiler::ProgramCompiler;
use crate::executive::executable::executable::Executable;
use crate::executive::executable::method::method_type::MethodType;
use crate::executive::executable::method::program_method::ProgramMethod;
use crate::executive::opcode::opcode::Opcode;
use crate::executive::opcode::opcodes::altstack::{
    op_fromaltstack::OP_FROMALTSTACK, op_toaltstack::OP_TOALTSTACK,
};
use crate::executive::opcode::opcodes::arithmetic::{
    op_add::OP_ADD, op_div::OP_DIV, op_mul::OP_MUL, op_not::OP_NOT, op_sub::OP_SUB,
    op_within::OP_WITHIN,
};
use crate::executive::opcode::opcodes::bitwise::op_equal::OP_EQUAL;
use crate::executive::opcode::opcodes::callinfo::op_caller::OP_CALLER;
use crate::executive::opcode::opcodes::coin::{
    op_self_balance::OP_SELF_BALANCE, op_transfer::OP_TRANSFER,
};
use crate::executive::opcode::opcodes::flow::{op_returnall::OP_RETURNALL, op_verify::OP_VERIFY};
use crate::executive::opcode::opcodes::memory::{op_mread::OP_MREAD, op_mwrite::OP_MWRITE};
use crate::executive::opcode::opcodes::push::{
    op_10::OP_10, op_14::OP_14, op_2::OP_2, op_3::OP_3, op_7::OP_7, op_false::OP_FALSE,
    op_true::OP_TRUE,
};
use crate::executive::opcode::opcodes::shadowing::{
    op_shadow_alloc::OP_SHADOW_ALLOC, op_shadow_alloc_val::OP_SHADOW_ALLOC_VAL,
    op_shadow_allocs_sum::OP_SHADOW_ALLOCS_SUM, op_shadow_down::OP_SHADOW_DOWN,
    op_shadow_up::OP_SHADOW_UP,
};
use crate::executive::opcode::opcodes::stack::{
    op_2drop::OP_2DROP, op_drop::OP_DROP, op_dup::OP_DUP, op_pick::OP_PICK,
};
use crate::executive::opcode::opcodes::storage::{op_sread::OP_SREAD, op_swrite::OP_SWRITE};

/// The program name of the allowlisted template.
pub const PROGRAM_NAME: &str = "fixed_split_vault_v1";

/// The method name of `FundSplit`.
pub const FUND_SPLIT_METHOD_NAME: &str = "fund_split";

/// The method name of `RedeemShare`.
pub const REDEEM_SHARE_METHOD_NAME: &str = "redeem_share";

/// The numerator of Bob's frozen 70/30 weight, reduced from 7000 / 10000.
///
/// The weight is reduced to single-byte constants so the script can push them with `OP_7` and
/// `OP_10` instead of encoding multi-byte integers. `floor(D * 7 / 10)` equals
/// `floor(D * 7000 / 10000)` for every integer `D`, so the reduction does not change any
/// allocation, including the remainder that Carol receives.
pub const BOB_WEIGHT: u8 = 7;

/// The reduced basis-point denominator.
pub const WEIGHT_DENOMINATOR: u8 = 10;

/// Contract memory slot holding `D`, the distributable amount.
pub const MEMORY_SLOT_D: u8 = 0x01;

/// Contract memory slot holding `B`, Bob's allocation.
pub const MEMORY_SLOT_B: u8 = 0x02;

/// Contract memory slot holding `C`, Carol's allocation.
pub const MEMORY_SLOT_C: u8 = 0x03;

/// Contract **state** key holding the lifecycle phase.
///
/// Contract memory is per-call scratch space; contract state is what survives between calls. The
/// phase therefore lives in state, keyed by this byte.
pub const STATE_KEY_PHASE: u8 = 0x0e;

/// Phase value: `FundSplit` has allocated both shares.
pub const PHASE_ALLOCATED: u8 = 0x01;

/// Phase value: one beneficiary has redeemed, the other has not.
pub const PHASE_PARTIALLY_REDEEMED: u8 = 0x02;

/// Phase value: both beneficiaries have redeemed. The vault is terminal.
pub const PHASE_CLOSED: u8 = 0x03;

/// Returns the `FixedSplitVaultV1` template program.
///
/// # Interpreter constraints this script is written against
///
/// The CubeVM primitives used here fall into two groups, and the difference matters:
///
/// - **Top-relative** (used freely): `OP_DUP`, `OP_DROP`, `OP_2DROP`, `OP_TOALTSTACK`,
///   `OP_FROMALTSTACK`, `OP_MWRITE`, `OP_MREAD`, and every consuming opcode (`OP_SUB`,
///   `OP_MUL`, `OP_DIV`, `OP_EQUAL`, `OP_VERIFY`, `OP_TRANSFER`, the shadow opcodes).
/// - **Bottom-relative** (avoided): `OP_PICK`, `OP_ROLL`, `OP_SWAP`, `OP_ROT`, `OP_NIP` and
///   `OP_2DUP` all address their operand through `item_by_depth`, which is indexed from the
///   *bottom* of the stack rather than the top. They are therefore not used for general stack
///   shuffling; only `OP_PICK` with a depth that is stable for the lifetime of the call is used,
///   to read a beneficiary key that never moves.
///
/// # `fund_split`
///
/// Five arguments, pushed in declaration order, so the stack is (bottom to top):
///
/// ```text
/// bob_key | carol_key | gross | execution_fee | fee_account
/// ```
///
/// `gross` is the `Payable` argument: the value the caller transfers into the contract in the same
/// call. The script then
///
/// 1. requires the contract balance to equal `gross`, and the outstanding shadow allocation sum
///    to be zero,
/// 2. transfers `execution_fee` from the contract to `fee_account`,
/// 3. reads `D` as the balance the contract now holds (`gross - execution_fee`),
/// 4. computes `B = floor(D * 7 / 10)` and `C = D - B` and parks both in contract memory,
/// 5. allocates Bob with `B` and Carol with `C` inside the contract shadow space.
///
/// Deriving `D` from the contract balance rather than recomputing `gross - execution_fee` means
/// the split is applied to value the contract actually holds. The balance guard keeps that honest:
/// if the call under-funds the contract, or the contract carries a stray balance, the call fails
/// instead of splitting the wrong base.
///
/// Every arithmetic opcode pushes a success flag; each one is consumed by `OP_VERIFY`, which
/// aborts on underflow or overflow.
///
/// # `redeem_share`
///
/// No arguments. It reads the caller with `OP_CALLER`, rejects a contract caller, requires a
/// nonzero shadow allocation, releases that entire allocation from the shadow space and pays it to
/// the caller natively. The shadow is released before the transfer because
/// `contract_balance_down` refuses to take a balance below the outstanding allocations.
pub fn template() -> Executable {
    // 1 Construct the `fund_split` method.
    let fund_split = ProgramMethod::new(
        FUND_SPLIT_METHOD_NAME.to_string(),
        MethodType::Callable,
        vec![
            CalldataElementType::Account,
            CalldataElementType::Account,
            CalldataElementType::Payable,
            CalldataElementType::U32,
            CalldataElementType::Account,
        ],
        fund_split_script(),
    )
    .expect("the fund_split method must be constructible");

    // 2 Construct the `redeem_share` method.
    let redeem_share = ProgramMethod::new(
        REDEEM_SHARE_METHOD_NAME.to_string(),
        MethodType::Callable,
        vec![],
        redeem_share_script(),
    )
    .expect("the redeem_share method must be constructible");

    // 3 Construct the program.
    Executable::new(
        PROGRAM_NAME.to_string(),
        None,
        vec![fund_split, redeem_share],
    )
    .expect("the template program must be constructible")
}

/// Returns the compiled bytecode of the template.
///
/// This is the value an allowlist must pin: changing any opcode changes the hash, and a changed
/// hash must not be accepted as the same template.
pub fn template_bytes() -> Vec<u8> {
    template().compile().expect("the template must compile")
}

/// Returns the template hash a deployment must be checked against.
pub fn template_hash() -> [u8; 32] {
    template().contract_id()
}

/// Returns the `fund_split` method script.
fn fund_split_script() -> Vec<Opcode> {
    vec![
        // Stack (bottom to top): bob | carol | gross | execution_fee | fee_account
        //
        // --- 0. Guard: the vault must never have been funded. ---
        // The phase is written once by a successful `fund_split` and is never cleared, so this
        // makes funding terminal: not only a live vault, but also a vault whose beneficiaries
        // have already redeemed everything, is refused. An absent key reads as an empty item,
        // which `OP_NOT` turns into a passing flag.
        Opcode::OP_14(OP_14),
        Opcode::OP_SREAD(OP_SREAD),
        Opcode::OP_NOT(OP_NOT),
        Opcode::OP_VERIFY(OP_VERIFY),
        //
        // --- 1. Guard: the contract must hold exactly the declared gross. ---
        // This runs before the fee leaves the contract, so the balance is still `gross`. A call
        // that under-funds the contract, or a contract carrying a stray balance, would otherwise
        // split a base the caller never authorised.
        Opcode::OP_SELF_BALANCE(OP_SELF_BALANCE),
        Opcode::OP_2(OP_2),
        Opcode::OP_PICK(OP_PICK),
        Opcode::OP_EQUAL(OP_EQUAL),
        Opcode::OP_VERIFY(OP_VERIFY),
        //
        // --- 2. Guard: the vault must not already hold allocations. ---
        // This rejects a second funding of a live vault. It does not yet reject a second funding
        // after a full redemption, because the template persists no phase; that needs the
        // state-manager phase from the reference model.
        Opcode::OP_SHADOW_ALLOCS_SUM(OP_SHADOW_ALLOCS_SUM),
        Opcode::OP_NOT(OP_NOT),
        Opcode::OP_VERIFY(OP_VERIFY),
        //
        // --- 3. Transfer the execution fee to the fee account. ---
        // `OP_TRANSFER` pops the kind, then the account, then the amount, so the top three items
        // must be `false`, `fee_account`, `execution_fee` — which is already the argument order.
        Opcode::OP_FALSE(OP_FALSE),
        Opcode::OP_TRANSFER(OP_TRANSFER),
        // Stack: bob | carol | gross
        //
        // --- 4. Read the distributable amount from the contract balance. ---
        // After the transfer the contract holds exactly `gross - execution_fee`, which is `D`.
        Opcode::OP_DROP(OP_DROP),
        Opcode::OP_SELF_BALANCE(OP_SELF_BALANCE),
        // Park `D` in contract memory; `OP_MWRITE` pops the slot, then the value.
        Opcode::OP_TRUE(OP_TRUE),
        Opcode::OP_MWRITE(OP_MWRITE),
        // `OP_MWRITE` pushes whether the slot already existed; the script does not use it.
        Opcode::OP_DROP(OP_DROP),
        // Stack: bob | carol
        //
        // --- 5. B = floor(D * 7 / 10). ---
        Opcode::OP_TRUE(OP_TRUE),
        Opcode::OP_MREAD(OP_MREAD),
        Opcode::OP_DUP(OP_DUP),
        Opcode::OP_7(OP_7),
        Opcode::OP_MUL(OP_MUL),
        Opcode::OP_VERIFY(OP_VERIFY),
        // `OP_DIV` divides the top of the stack by the item below it, so park the product while
        // the denominator is pushed. It then pushes the remainder, the quotient and a success flag.
        Opcode::OP_TOALTSTACK(OP_TOALTSTACK),
        Opcode::OP_10(OP_10),
        Opcode::OP_FROMALTSTACK(OP_FROMALTSTACK),
        Opcode::OP_DIV(OP_DIV),
        Opcode::OP_VERIFY(OP_VERIFY),
        // Drop the remainder: Carol receives `D - B`, not the remainder alone.
        Opcode::OP_TOALTSTACK(OP_TOALTSTACK),
        Opcode::OP_DROP(OP_DROP),
        Opcode::OP_FROMALTSTACK(OP_FROMALTSTACK),
        // Park `B`.
        Opcode::OP_2(OP_2),
        Opcode::OP_MWRITE(OP_MWRITE),
        // `OP_MWRITE` pushes whether the slot already existed; the script does not use it.
        Opcode::OP_DROP(OP_DROP),
        // Stack: bob | carol | D
        //
        // --- 6. C = D - B. ---
        // `OP_SUB` subtracts the item below the top from the top, so `B` is pushed first.
        Opcode::OP_2(OP_2),
        Opcode::OP_MREAD(OP_MREAD),
        Opcode::OP_TRUE(OP_TRUE),
        Opcode::OP_MREAD(OP_MREAD),
        Opcode::OP_SUB(OP_SUB),
        Opcode::OP_VERIFY(OP_VERIFY),
        // Park `C`.
        Opcode::OP_3(OP_3),
        Opcode::OP_MWRITE(OP_MWRITE),
        // `OP_MWRITE` pushes whether the slot already existed; the script does not use it.
        Opcode::OP_DROP(OP_DROP),
        // Drop `D`; nothing else needs it.
        Opcode::OP_DROP(OP_DROP),
        // Stack: bob | carol
        //
        // --- 7. Allocate Bob and credit Bob with B. ---
        // Depth 0 addresses `bob`, which never moves for the rest of the call.
        Opcode::OP_2(OP_2),
        Opcode::OP_MREAD(OP_MREAD),
        Opcode::OP_FALSE(OP_FALSE),
        Opcode::OP_PICK(OP_PICK),
        Opcode::OP_SHADOW_ALLOC(OP_SHADOW_ALLOC),
        Opcode::OP_FALSE(OP_FALSE),
        Opcode::OP_PICK(OP_PICK),
        Opcode::OP_SHADOW_UP(OP_SHADOW_UP),
        // Stack: bob | carol
        //
        // --- 8. Allocate Carol and credit Carol with C. ---
        // Depth 1 addresses `carol`.
        Opcode::OP_3(OP_3),
        Opcode::OP_MREAD(OP_MREAD),
        Opcode::OP_TRUE(OP_TRUE),
        Opcode::OP_PICK(OP_PICK),
        Opcode::OP_SHADOW_ALLOC(OP_SHADOW_ALLOC),
        Opcode::OP_TRUE(OP_TRUE),
        Opcode::OP_PICK(OP_PICK),
        Opcode::OP_SHADOW_UP(OP_SHADOW_UP),
        // Stack: bob | carol
        //
        // --- 9. Record the phase. ---
        // Written last, so a failure anywhere above leaves the vault unfunded from the state
        // machine's point of view as well as the balance's.
        Opcode::OP_TRUE(OP_TRUE),
        Opcode::OP_14(OP_14),
        Opcode::OP_SWRITE(OP_SWRITE),
        //
        // --- 10. Drop the keys and return a single true item. ---
        Opcode::OP_2DROP(OP_2DROP),
        Opcode::OP_TRUE(OP_TRUE),
        Opcode::OP_RETURNALL(OP_RETURNALL),
    ]
}

/// Returns the `redeem_share` method script.
fn redeem_share_script() -> Vec<Opcode> {
    vec![
        // --- 1. Read the caller and reject a contract caller. ---
        // `OP_CALLER` pushes the caller id and a kind flag, false for an account.
        Opcode::OP_CALLER(OP_CALLER),
        Opcode::OP_NOT(OP_NOT),
        Opcode::OP_VERIFY(OP_VERIFY),
        // Stack: caller
        //
        // --- 2. Require a phase in which a redemption is possible. ---
        // `OP_WITHIN` pops the maximum, then the minimum, then the number, and accepts
        // `1 <= phase <= 2`: ALLOCATED or PARTIALLY_REDEEMED. An unfunded vault (no key) and a
        // closed vault (phase 3) are both refused.
        Opcode::OP_14(OP_14),
        Opcode::OP_SREAD(OP_SREAD),
        Opcode::OP_TRUE(OP_TRUE),
        Opcode::OP_2(OP_2),
        Opcode::OP_WITHIN(OP_WITHIN),
        Opcode::OP_VERIFY(OP_VERIFY),
        //
        // --- 3. Require a nonzero shadow allocation. ---
        Opcode::OP_DUP(OP_DUP),
        Opcode::OP_SHADOW_ALLOC_VAL(OP_SHADOW_ALLOC_VAL),
        Opcode::OP_VERIFY(OP_VERIFY),
        // Stack: caller | amount
        //
        // --- 4. Park the amount and the caller in contract memory. ---
        // Both are needed twice: once to release the shadow, once to pay it out.
        Opcode::OP_TRUE(OP_TRUE),
        Opcode::OP_MWRITE(OP_MWRITE),
        // `OP_MWRITE` pushes whether the slot already existed; the script does not use it.
        Opcode::OP_DROP(OP_DROP),
        Opcode::OP_2(OP_2),
        Opcode::OP_MWRITE(OP_MWRITE),
        // `OP_MWRITE` pushes whether the slot already existed; the script does not use it.
        Opcode::OP_DROP(OP_DROP),
        // Stack: empty
        //
        // --- 5. Release the allocation from the shadow space. ---
        // `OP_SHADOW_DOWN` pops the account, then the amount.
        Opcode::OP_TRUE(OP_TRUE),
        Opcode::OP_MREAD(OP_MREAD),
        Opcode::OP_2(OP_2),
        Opcode::OP_MREAD(OP_MREAD),
        Opcode::OP_SHADOW_DOWN(OP_SHADOW_DOWN),
        // Stack: empty
        //
        // --- 6. Pay the released amount to the caller. ---
        Opcode::OP_TRUE(OP_TRUE),
        Opcode::OP_MREAD(OP_MREAD),
        Opcode::OP_2(OP_2),
        Opcode::OP_MREAD(OP_MREAD),
        Opcode::OP_FALSE(OP_FALSE),
        Opcode::OP_TRANSFER(OP_TRANSFER),
        // Stack: empty
        //
        // --- 7. Advance the phase. ---
        // `next = 2 + (remaining == 0 ? 1 : 0)`, i.e. PARTIALLY_REDEEMED while a share is still
        // owed somewhere, and CLOSED once the shadow space is empty. Computed arithmetically so
        // the script needs no branch.
        Opcode::OP_SHADOW_ALLOCS_SUM(OP_SHADOW_ALLOCS_SUM),
        Opcode::OP_NOT(OP_NOT),
        Opcode::OP_2(OP_2),
        Opcode::OP_ADD(OP_ADD),
        Opcode::OP_VERIFY(OP_VERIFY),
        Opcode::OP_14(OP_14),
        Opcode::OP_SWRITE(OP_SWRITE),
        //
        // --- 8. Return a single true item. ---
        Opcode::OP_TRUE(OP_TRUE),
        Opcode::OP_RETURNALL(OP_RETURNALL),
    ]
}

/// Returns the frozen weights used by the script, for tests and documentation.
pub const fn frozen_weights() -> (u8, u8) {
    (BOB_WEIGHT, WEIGHT_DENOMINATOR)
}
