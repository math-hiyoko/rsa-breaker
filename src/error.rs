use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum ParseError {
    #[error("invalid input")]
    InvalidTextInput,

    #[error("unsupported key format")]
    UnsupportedFormat,

    #[error("pkcs1 error: {0}")]
    Pkcs1(#[from] rsa::pkcs1::Error),

    #[error("pkcs8 error: {0}")]
    Pkcs8(#[from] rsa::pkcs8::Error),

    #[cfg(feature = "openssh")]
    #[error("ssh-key error: {0}")]
    Ssh(#[from] ssh_key::Error),
}

#[derive(Debug, Error)]
pub(crate) enum EncodeError {
    #[error("failed to solve public key: {0}")]
    SolveError(String),

    #[error("private key error: {0}")]
    CreateKeyError(#[from] rsa::Error),

    #[error("unsupported key format combination")]
    UnsupportedCombination,

    #[error("pkcs1 error: {0}")]
    Pkcs1(#[from] rsa::pkcs1::Error),

    #[error("pkcs8 error: {0}")]
    Pkcs8(#[from] rsa::pkcs8::Error),

    #[error("pkcs8 spki error: {0}")]
    Spki(#[from] rsa::pkcs8::spki::Error),

    #[cfg(feature = "openssh")]
    #[error("ssh-key error: {0}")]
    Ssh(#[from] ssh_key::Error),
}
