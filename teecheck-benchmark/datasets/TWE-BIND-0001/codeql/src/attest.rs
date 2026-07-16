// Stub attestation module the fixture's registry.rs imports. verify_quote
// returns the registry's own Error so the fixture's `?` operator type-checks
// without an extra conversion. The weakness under test is entirely in
// registry.rs; this file only makes the crate compile.
use crate::registry::Error;

#[derive(Clone, PartialEq)]
pub struct PublicKey(pub [u8; 4]);

pub struct Report {
    pub pubkey: PublicKey,
}

pub fn verify_quote(_quote: &[u8]) -> Result<Report, Error> {
    Ok(Report { pubkey: PublicKey([1, 2, 3, 4]) })
}
