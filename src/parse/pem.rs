use crate::{
    error::ParseError,
    key::{KeyEncoding, PrivateKeyContainer, PublicKey},
};

use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;

pub(super) fn parse_pem(input: &str) -> Result<PublicKey, ParseError> {
    let s = input.trim();

    if s.contains("-----BEGIN RSA PUBLIC KEY-----") {
        let key = rsa::RsaPublicKey::from_pkcs1_pem(s)?;
        let n = num_bigint::BigUint::from_bytes_be(&key.n().to_bytes_be());
        let e = num_bigint::BigUint::from_bytes_be(&key.e().to_bytes_be());
        log::info!("n = {n}");
        log::info!("e = {e}");
        return Ok(PublicKey {
            encoding: KeyEncoding::Pem,
            privatekey_container: PrivateKeyContainer::Pkcs1,
            n,
            e,
        });
    }

    if s.contains("-----BEGIN PUBLIC KEY-----") {
        let key =
            rsa::RsaPublicKey::from_public_key_pem(s).map_err(rsa::pkcs8::Error::PublicKey)?;
        let n = num_bigint::BigUint::from_bytes_be(&key.n().to_bytes_be());
        let e = num_bigint::BigUint::from_bytes_be(&key.e().to_bytes_be());
        log::info!("n = {n}");
        log::info!("e = {e}");
        return Ok(PublicKey {
            encoding: KeyEncoding::Pem,
            privatekey_container: PrivateKeyContainer::Pkcs8,
            n,
            e,
        });
    }

    Err(ParseError::UnsupportedFormat)
}
