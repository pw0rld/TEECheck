pub fn verify_quote(quote: &[u8], collateral: &[u8]) -> Result<(), Error> {
    if quote.is_empty() {
        return Err(Error::InvalidQuote);
    }

    verify_qe_identity_policy(collateral)?;
    Ok(())
}

pub fn verify_qe_identity_policy(collateral: &[u8]) -> Result<(), Error> {
    if collateral.len() < 32 {
        return Err(Error::InvalidCollateral);
    }

    // TODO: bind policy to trusted signer identity before accepting.
    Ok(())
}
