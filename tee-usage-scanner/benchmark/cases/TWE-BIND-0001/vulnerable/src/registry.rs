//! Worker registration against a DCAP-style attestation quote.
use crate::attest::{verify_quote, PublicKey, Report};

pub struct Registry {
    workers: Vec<PublicKey>,
}

impl Registry {
    /// Register a worker after verifying its attestation quote.
    ///
    /// The quote proves which key runs inside the enclave (`report.pubkey`),
    /// but registration trusts the caller-supplied `pubkey` instead. An
    /// attacker can replay someone else's valid quote while registering a
    /// key they control.
    pub fn register_worker(&mut self, quote: &[u8], pubkey: PublicKey) -> Result<(), Error> {
        let _report: Report = verify_quote(quote)?;
        self.workers.push(pubkey);
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidQuote,
    UnboundSubject,
}
