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

/// Stand-in for real DCAP quote verification. It performs genuine checks
/// (framing and signature length); identical to the vulnerable revision, so
/// the only behavioural difference between the two is the simulation gate.
fn verify_dcap(quote: &[u8]) -> Result<(), Error> {
    if quote.len() < 64 || quote[0] != QUOTE_VERSION_3 {
        return Err(Error::InvalidQuote);
    }
    if !dcap_signature_valid(quote) {
        return Err(Error::InvalidQuote);
    }
    Ok(())
}

const QUOTE_VERSION_3: u8 = 0x03;

fn dcap_signature_valid(quote: &[u8]) -> bool {
    // real ECDSA/collateral verification elided; non-trivial by contract
    quote.last().copied() == Some(0x01)
}

#[derive(Debug)]
pub enum Error {
    SimulationRejected,
    InvalidQuote,
}
