pub(crate) enum KeyEncoding {
    Pem,
    Der,
    OpenSsh,
}

pub(crate) enum PrivateKeyContainer {
    Pkcs1,
    Pkcs8,
    OpenSsh,
}

pub(crate) struct PublicKey {
    pub encoding: KeyEncoding,
    pub privatekey_container: PrivateKeyContainer,
    pub n: num_bigint::BigUint,
    pub e: num_bigint::BigUint,
}

pub(crate) struct PrivateKey {
    pub encoding: KeyEncoding,
    pub container: PrivateKeyContainer,
    pub p: num_bigint::BigUint,
    pub q: num_bigint::BigUint,
    pub e: num_bigint::BigUint,
}
