// Placeholder — overlaid by the variant's src/registry.rs at build time. It
// mirrors the fixture's module surface (an Error enum) so the skeleton also
// compiles on its own.
use crate::attest::{verify_quote, PublicKey, Report};

pub struct Registry {
    #[allow(dead_code)]
    workers: Vec<PublicKey>,
}

impl Registry {
    #[allow(dead_code)]
    pub fn probe(&self, quote: &[u8]) -> Result<(), Error> {
        let _r: Report = verify_quote(quote)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidQuote,
    UnboundSubject,
}
