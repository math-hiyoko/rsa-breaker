use crate::{
    error::ParseError,
    key::{KeyEncoding, PrivateKeyContainer, PublicKey},
};

#[cfg(feature = "openssh")]
pub(super) fn parse_openssh(input: &str) -> Result<PublicKey, ParseError> {
    let s = input.trim();
    let public = ssh_key::PublicKey::from_openssh(s)?;

    match public.key_data() {
        ssh_key::public::KeyData::Rsa(key) => {
            let n = num_bigint::BigUint::from_bytes_be(key.n.as_bytes());
            let e = num_bigint::BigUint::from_bytes_be(key.e.as_bytes());
            log::info!("n = {n}");
            log::info!("e = {e}");
            Ok(PublicKey {
                encoding: KeyEncoding::OpenSsh,
                privatekey_container: PrivateKeyContainer::OpenSsh,
                n,
                e,
            })
        }
        _ => Err(ParseError::UnsupportedFormat),
    }
}
