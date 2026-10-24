//! Tests for the template allowlist.
//!
//! The allowlist decides which compiled programs may become contracts. Its enforcement point is the
//! `Deploy` entry, which needs the full engine context; these tests pin the predicate itself and the
//! property that makes it meaningful: a program's identity changes when its code changes.

use cube::constructive::calldata::element_type::CalldataElementType;
use cube::constructive::contracts::fixed_split_vault_v1;
use cube::constructive::contracts::is_allowlisted_template;
use cube::executive::executable::executable::Executable;
use cube::executive::executable::method::method_type::MethodType;
use cube::executive::executable::method::program_method::ProgramMethod;
use cube::executive::opcode::opcode::Opcode;
use cube::executive::opcode::opcodes::flow::op_nop::OP_NOP;
use cube::executive::opcode::opcodes::flow::op_returnall::OP_RETURNALL;
use cube::executive::opcode::opcodes::push::op_true::OP_TRUE;

/// A program that is deliberately not the reviewed template.
fn unreviewed_program() -> Executable {
    let method = ProgramMethod::new(
        "noop".to_string(),
        MethodType::Callable,
        Vec::<CalldataElementType>::new(),
        vec![
            Opcode::OP_TRUE(OP_TRUE),
            Opcode::OP_NOP(OP_NOP),
            Opcode::OP_NOP(OP_NOP),
            Opcode::OP_RETURNALL(OP_RETURNALL),
        ],
    )
    .expect("the fixture method must construct");

    Executable::new("unreviewed_fixture".to_string(), None, vec![method])
        .expect("the fixture program must construct")
}

#[test]
fn the_split_template_is_allowlisted() {
    assert!(is_allowlisted_template(
        fixed_split_vault_v1::template_hash()
    ));
}

#[test]
fn an_unreviewed_program_is_not_allowlisted() {
    let program = unreviewed_program();
    assert!(!is_allowlisted_template(program.contract_id()));
    assert_ne!(
        program.contract_id(),
        fixed_split_vault_v1::template_hash(),
        "the fixture must not accidentally hash to the reviewed template"
    );
}

#[test]
fn the_template_hash_is_deterministic_and_code_dependent() {
    // 1 Repeated construction yields the same identity.
    assert_eq!(
        fixed_split_vault_v1::template_hash(),
        fixed_split_vault_v1::template_hash()
    );

    // 2 A different program yields a different identity, which is what makes the allowlist a check
    //   on code rather than on a name.
    assert_ne!(
        unreviewed_program().contract_id(),
        fixed_split_vault_v1::template().contract_id()
    );
}
