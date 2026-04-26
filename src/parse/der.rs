use rsa::{pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};

use crate::{
    error::ParseError,
    key::{KeyEncoding, PrivateKeyContainer, PublicKey},
};

pub(super) fn parse_der(input: &[u8]) -> Result<PublicKey, ParseError> {
    if let Ok(key) = rsa::RsaPublicKey::from_pkcs1_der(input) {
        let n = num_bigint::BigUint::from_bytes_be(&key.n().to_bytes_be());
        let e = num_bigint::BigUint::from_bytes_be(&key.e().to_bytes_be());
        log::info!("n = {n}");
        log::info!("e = {e}");
        return Ok(PublicKey {
            encoding: KeyEncoding::Der,
            privatekey_container: PrivateKeyContainer::Pkcs1,
            n,
            e,
        });
    }

    if let Ok(key) = rsa::RsaPublicKey::from_public_key_der(input) {
        let n = num_bigint::BigUint::from_bytes_be(&key.n().to_bytes_be());
        let e = num_bigint::BigUint::from_bytes_be(&key.e().to_bytes_be());
        log::info!("n = {n}");
        log::info!("e = {e}");
        return Ok(PublicKey {
            encoding: KeyEncoding::Der,
            privatekey_container: PrivateKeyContainer::Pkcs8,
            n,
            e,
        });
    }

    Err(ParseError::UnsupportedFormat)
}
