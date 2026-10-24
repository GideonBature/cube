use crate::constructive::entries::entry_kinds::call::call::Call;
use crate::constructive::entries::entry_kinds::call::ext::signature::bls_sign::error::bls_sign_error::CallBLSSignError;
use crate::transmutative::bls::sign::bls_sign as bls_sign_message;
use crate::transmutative::key::KeyHolder;

impl Call {
    /// Signs the `Call` signature message (sighash) with the BLS secret key.
    ///
    /// The BLS signature authorises this exact `Call` payload: the account, the contract, the
    /// method index, the calldata, the ops budget and price, and the target. A changed byte
    /// produces a different sighash and therefore requires a new signature.
    pub fn bls_sign(&self, keyholder: &KeyHolder) -> Result<[u8; 96], CallBLSSignError> {
        // 1 Get the call sighash.
        let sighash = self.sighash().map_err(CallBLSSignError::SighashError)?;

        // 2 Get the BLS secret key from the keyholder.
        let bls_secret_key = keyholder.bls_secret_key();

        // 3 Sign the call sighash with the BLS secret key.
        let bls_signature = bls_sign_message(bls_secret_key, sighash);

        // 4 Return the BLS signature.
        Ok(bls_signature)
    }
}
