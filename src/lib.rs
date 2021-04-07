use serde::{Deserialize, Serialize};

pub use ed25519_dalek::Keypair;

use ed25519_dalek::{PublicKey, SecretKey, Signature, Signer, Verifier};
use signature::Signature as _;
use tdn_types::{
    group::GroupId,
    primitive::{new_io_error, PeerAddr, Result},
};

#[cfg(feature = "user")]
pub mod user;

const PROOF_LENGTH: usize = 64; // use ed25519 signaure length.

#[derive(Default, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, Debug)]
pub struct Proof(Vec<u8>);

impl Proof {
    pub fn prove(kp: &Keypair, addr: &PeerAddr) -> Proof {
        Proof(kp.sign(&addr.0).as_bytes().to_vec())
    }

    pub fn verify(&self, gid: &GroupId, addr: &PeerAddr) -> Result<()> {
        if self.0.len() != PROOF_LENGTH {
            return Err(new_io_error("proof length failure!"));
        }
        let sign =
            Signature::from_bytes(&self.0).map_err(|_e| new_io_error("proof serialize failure"))?;
        let pk =
            PublicKey::from_bytes(&gid.0).map_err(|_e| new_io_error("public serialize failure"))?;

        pk.verify(&addr.0, &sign)
            .map_err(|_e| new_io_error("proof verify failure"))
    }
}

pub fn genereate_id(seed: &[u8]) -> (GroupId, Keypair) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed);

    // it must be return.
    loop {
        let tmp_hash = hasher.finalize();
        if let Ok(sk) = SecretKey::from_bytes(tmp_hash.as_bytes()) {
            let pk: PublicKey = (&sk).into();
            return (
                GroupId(pk.to_bytes()),
                Keypair {
                    public: pk,
                    secret: sk,
                },
            );
        } else {
            hasher.update(tmp_hash.as_bytes());
        }
    }
}
