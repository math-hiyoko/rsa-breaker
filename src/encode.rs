use rsa::{
    pkcs1::EncodeRsaPrivateKey,
    pkcs8::EncodePrivateKey,
    traits::{PrivateKeyParts, PublicKeyParts},
};

use crate::{
    error::EncodeError,
    key::{KeyEncoding, PrivateKey, PrivateKeyContainer},
};

pub(crate) fn encode_private_key(
    path: &std::path::Path,
    private_key: PrivateKey,
) -> Result<(), EncodeError> {
    let (encoding, container) = (private_key.encoding, private_key.container);
    let private_key = rsa::RsaPrivateKey::from_p_q(
        rsa::BigUint::from_bytes_be(&private_key.p.to_bytes_be()),
        rsa::BigUint::from_bytes_be(&private_key.q.to_bytes_be()),
        rsa::BigUint::from_bytes_be(&private_key.e.to_bytes_be()),
    )?;
    match (encoding, container) {
        #[cfg(feature = "openssh")]
        (KeyEncoding::OpenSsh, PrivateKeyContainer::OpenSsh) => {
            let public_key = ssh_key::public::RsaPublicKey {
                e: ssh_key::Mpint::try_from(private_key.e())?,
                n: ssh_key::Mpint::try_from(private_key.n())?,
            };
            let primes = private_key.primes();
            let private_key = ssh_key::private::RsaPrivateKey {
                d: ssh_key::Mpint::try_from(private_key.d())?,
                iqmp: ssh_key::Mpint::from_bytes(&private_key.qinv().unwrap().to_bytes_be().1)?,
                p: ssh_key::Mpint::try_from(primes[0].clone())?,
                q: ssh_key::Mpint::try_from(primes[1].clone())?,
            };
            let private_key = ssh_key::PrivateKey::new(
                ssh_key::private::KeypairData::Rsa(ssh_key::private::RsaKeypair {
                    public: public_key,
                    private: private_key,
                }),
                "",
            )?;
            private_key.write_openssh_file(path, ssh_key::LineEnding::LF)?
        }
        #[cfg(feature = "pem")]
        (KeyEncoding::Pem, PrivateKeyContainer::Pkcs1) => {
            private_key.write_pkcs1_pem_file(path, rsa::pkcs1::LineEnding::LF)?
        }
        #[cfg(feature = "pem")]
        (KeyEncoding::Pem, PrivateKeyContainer::Pkcs8) => {
            private_key.write_pkcs8_pem_file(path, rsa::pkcs8::LineEnding::LF)?
        }
        #[cfg(feature = "der")]
        (KeyEncoding::Der, PrivateKeyContainer::Pkcs1) => private_key.write_pkcs1_der_file(path)?,
        #[cfg(feature = "der")]
        (KeyEncoding::Der, PrivateKeyContainer::Pkcs8) => private_key.write_pkcs8_der_file(path)?,
        _ => {
            return Err(EncodeError::UnsupportedCombination);
        }
    };
    Ok(())
}
