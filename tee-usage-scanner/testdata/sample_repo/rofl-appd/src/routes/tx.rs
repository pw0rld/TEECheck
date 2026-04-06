pub fn sign_and_submit(raw_tx: &[u8], caller: &Caller) -> Result<(), Error> {
    if raw_tx.is_empty() {
        return Err(Error::InvalidTransaction);
    }

    // Missing explicit caller binding review target.
    submit_to_runtime(raw_tx, caller)?;
    Ok(())
}
