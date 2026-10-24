use crate::constructive::entity::account::root_account::root_account::RootAccount;
use crate::constructive::entries::entry_kinds::call::call::Call;
use crate::constructive::entries::entry_kinds::call::ext::pre_validations::validate_overall::validate_overall_error::CallValidateOverallError;
use crate::inscriptive::graveyard::graveyard::GRAVEYARD;
use crate::inscriptive::registry::registry::REGISTRY;

impl Call {
    /// Validates the `Call` end-to-end before execution.
    ///
    /// This is the check the `Engine` runs before a `Call` is admitted to a batch. It rejects:
    ///
    /// 1. an unregistered caller root account,
    /// 2. a caller root account whose key material or authorization signature does not check out,
    /// 3. a target outside the accepted batch window,
    /// 4. a contract that is not registered,
    /// 5. a method index outside that contract's method table,
    /// 6. a missing ops budget.
    ///
    /// It deliberately does not check balances: the BLS signature only proves *who* authorised the
    /// call, and the fee and payable debits are enforced at execution time where the coin manager
    /// is authoritative.
    pub async fn validate_overall(
        &self,
        execution_batch_height: u64,
        registry: &REGISTRY,
        graveyard: &GRAVEYARD,
    ) -> Result<(), CallValidateOverallError> {
        // 1 Reject unregistered caller root accounts.
        if matches!(&self.account, RootAccount::UnregisteredRootAccount(_)) {
            return Err(CallValidateOverallError::UnregisteredRootAccountNotAllowedError);
        }

        // 2 Validate the caller root account's key material and authorization signature.
        self.account
            .validate_root_account(registry, graveyard)
            .await
            .map_err(CallValidateOverallError::ValidateRootAccountError)?;

        // 3 Validate the target against the execution batch height.
        if let Err((targeted_at_batch_height, execution_batch_height_err)) =
            self.target.validate(execution_batch_height)
        {
            return Err(CallValidateOverallError::ValidateTargetError {
                targeted_at_batch_height,
                execution_batch_height: execution_batch_height_err,
            });
        }

        // 4 Require a registered contract with a readable method table.
        let contract_id = self.contract.contract_id();
        let methods_len = {
            let _registry = registry.lock().await;
            _registry
                .get_contract_methods_len_by_contract_id(contract_id)
                .ok_or(CallValidateOverallError::ContractNotFoundError(contract_id))?
        };

        // 5 Require the method index to exist in that table.
        if usize::from(self.method_index.index()) >= methods_len {
            return Err(CallValidateOverallError::MethodNotFoundError {
                contract_id,
                method_index: self.method_index.index(),
                methods_len,
            });
        }

        // 6 Require an explicitly bounded ops budget: an absent budget would silently become zero
        //   and fail the first opcode instead of naming the configuration error.
        if self.ops_budget().is_none() {
            return Err(CallValidateOverallError::MissingOpsBudgetError);
        }

        // 7 Return Ok.
        Ok(())
    }
}
