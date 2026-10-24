use crate::constructive::entries::entry_kinds::call::call::Call;
use crate::constructive::entries::entry_kinds::call::ext::signature::bls_verify::error::bls_verify_error::CallBLSVerifyError;
use crate::transmutative::bls::verify::bls_verify as bls_verify_message;

impl Call {
    /// Verifies a BLS signature over this `Call`'s signature message (sighash).
    ///
    /// The signature must be produced by the BLS key of the calling root account. This binds the
    /// caller to the exact payload bytes; it does not by itself prove that the account holds
    /// enough balance for the call's fee or payable value.
    pub fn bls_verify(&self, bls_signature: [u8; 96]) -> Result<(), CallBLSVerifyError> {
        // 1 Get the call sighash.
        let sighash = self.sighash().map_err(CallBLSVerifyError::SighashError)?;

        // 2 Get the BLS public key from the calling root account.
        let bls_public_key = self.account.bls_key();

        // 3 Verify the BLS signature over the sighash.
        match bls_verify_message(&bls_public_key, sighash, bls_signature) {
            // 3.a The BLS signature is valid.
            true => Ok(()),

            // 3.b The BLS signature is invalid.
            false => Err(CallBLSVerifyError::InvalidBLSSignatureError),
        }
    }
}
