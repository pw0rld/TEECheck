//! Attestation evidence verification.
pub struct Evidence {
    pub mode: Mode,
    pub quote: Vec<u8>,
}

#[derive(PartialEq)]
pub enum Mode {
    Dcap,
    Simulated,
}

/// Verify attestation evidence before releasing a sealed secret.
///
/// Simulated evidence is accepted unconditionally. The simulation branch is
/// compiled into every build, so a production deployment that is fed
/// `Mode::Simulated` evidence skips all real verification.
pub fn verify_attestation(evidence: &Evidence) -> Result<(), Error> {
    if evidence.mode == Mode::Simulated {
        return Ok(());
    }
    verify_dcap(&evidence.quote)
}

fn verify_dcap(_quote: &[u8]) -> Result<(), Error> {
    // real DCAP verification elided
    Ok(())
}

#[derive(Debug)]
pub enum Error {
    SimulationRejected,
    InvalidQuote,
}
