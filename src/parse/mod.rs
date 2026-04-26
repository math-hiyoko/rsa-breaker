#[cfg(feature = "pem")]
mod pem;

#[cfg(feature = "der")]
mod der;

#[cfg(feature = "openssh")]
mod openssh;

use crate::{error::ParseError, key::PublicKey};

#[cfg(feature = "pem")]
use pem::parse_pem;

#[cfg(feature = "der")]
use der::parse_der;

#[cfg(feature = "openssh")]
use openssh::parse_openssh;

pub(crate) fn parse_auto(input: &[u8]) -> Result<PublicKey, ParseError> {
    log::trace!("Commencing parsing public key");
    if looks_like_text(input) {
        let s = std::str::from_utf8(input)
            .map_err(|_| ParseError::InvalidTextInput)?
            .trim();

        #[cfg(feature = "pem")]
        if s.starts_with("-----BEGIN ") {
            log::info!("public key format is pem.");
            return parse_pem(s);
        }

        #[cfg(feature = "openssh")]
        if looks_like_openssh_public_key(s) {
            log::info!("public key format is openssh.");
            return parse_openssh(s);
        }
    }

    log::info!("public key format is der.");
    #[cfg(feature = "der")]
    return parse_der(input);
}

fn looks_like_text(input: &[u8]) -> bool {
    input
        .iter()
        .all(|b| matches!(b, b'\t' | b'\n' | b'\r' | b' '..=b'~'))
}

#[cfg(feature = "openssh")]
fn looks_like_openssh_public_key(s: &str) -> bool {
    s.starts_with("ssh-rsa ")
}
