//! Worker registration against a DCAP-style attestation quote.
use crate::attest::{verify_quote, PublicKey, Report};

pub struct Registry {
    workers: Vec<PublicKey>,
}

impl Registry {
    /// Register a worker after verifying its attestation quote.
    ///
    /// Authority is bound to the key proven by the quote: registration is
    /// rejected unless the caller-supplied `pubkey` equals `report.pubkey`.
    pub fn register_worker(&mut self, quote: &[u8], pubkey: PublicKey) -> Result<(), Error> {
        let report: Report = verify_quote(quote)?;
        if report.pubkey != pubkey {
            return Err(Error::UnboundSubject);
        }
        self.workers.push(pubkey);
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidQuote,
    UnboundSubject,
}
