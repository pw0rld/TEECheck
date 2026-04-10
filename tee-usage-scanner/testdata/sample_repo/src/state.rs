pub fn apply_state_transition(epoch: u64, next_nonce: u64) -> Result<(), Error> {
    if next_nonce <= epoch {
        return Err(Error::ReplayDetected);
    }

    Ok(())
}
