use crate::{
    error::EncodeError,
    key::{PrivateKey, PublicKey},
};

pub(crate) fn solve_key(public_key: PublicKey) -> Result<PrivateKey, EncodeError> {
    log::trace!("Commencing key solving");
    let (p, q) = match gnfs::algorithms::factor(&num_bigint::BigInt::from_biguint(
        num_bigint::Sign::Plus,
        public_key.n.clone(),
    )) {
        Ok((mut p, mut q)) => {
            if p < q {
                std::mem::swap(&mut p, &mut q);
            }
            log::info!("p = {p}");
            log::info!("q = {q}");
            (p.to_biguint().unwrap(), q.to_biguint().unwrap())
        }
        Err(e) => {
            return Err(EncodeError::SolveError(e));
        }
    };
    Ok(PrivateKey {
        encoding: public_key.encoding,
        container: public_key.privatekey_container,
        p,
        q,
        e: public_key.e,
    })
}
