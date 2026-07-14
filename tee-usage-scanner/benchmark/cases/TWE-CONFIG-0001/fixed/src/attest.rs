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
/// Simulated evidence is only accepted when the `simulation` feature is
/// compiled in. A production build (feature off) rejects `Mode::Simulated`
/// outright, so the simulation path can never reach real authority.
pub fn verify_attestation(evidence: &Evidence) -> Result<(), Error> {
    if evidence.mode == Mode::Simulated {
        #[cfg(feature = "simulation")]
        {
            return Ok(());
        }
        #[cfg(not(feature = "simulation"))]
        {
            return Err(Error::SimulationRejected);
        }
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
