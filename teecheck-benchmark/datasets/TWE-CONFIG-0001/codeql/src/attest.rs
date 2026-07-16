// Placeholder — overlaid by the variant's src/attest.rs at build time.
pub struct Evidence {
    pub mode: Mode,
    pub quote: Vec<u8>,
}

#[derive(PartialEq)]
pub enum Mode {
    Dcap,
    Simulated,
}

pub fn verify_attestation(_evidence: &Evidence) -> Result<(), Error> {
    Err(Error::InvalidQuote)
}

#[derive(Debug)]
pub enum Error {
    SimulationRejected,
    InvalidQuote,
}
