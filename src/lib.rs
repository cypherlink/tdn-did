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
    pub fn prove(kp: &Keypair, maddr: &PeerAddr, raddr: &PeerAddr) -> Proof {
        let mut bytes = vec![];
        bytes.extend(&maddr.0);
        bytes.extend(&raddr.0);
        Proof(kp.sign(&bytes).as_bytes().to_vec())
    }

    pub fn verify(&self, gid: &GroupId, maddr: &PeerAddr, raddr: &PeerAddr) -> Result<()> {
        if self.0.len() != PROOF_LENGTH {
            return Err(new_io_error("proof length failure!"));
        }
        let sign =
            Signature::from_bytes(&self.0).map_err(|_e| new_io_error("proof serialize failure"))?;
        let pk =
            PublicKey::from_bytes(&gid.0).map_err(|_e| new_io_error("public serialize failure"))?;

        let mut bytes = vec![];
        bytes.extend(&maddr.0);
        bytes.extend(&raddr.0);

        pk.verify(&bytes, &sign)
            .map_err(|_e| new_io_error("proof verify failure"))
    }

    pub fn to_hex(&self) -> String {
        let mut hex = String::new();
        hex.extend(self.0.iter().map(|byte| format!("{:02x?}", byte)));
        hex
    }

    pub fn from_hex(s: &str) -> Result<Proof> {
        let s = s.to_string();
        if s.len() % 2 == 1 {
            return Err(new_io_error("Hex is invalid"));
        }

        let mut bytes = vec![];

        for i in 0..(s.len() / 2) {
            let res = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|_e| new_io_error("Hex is invalid"))?;
            bytes.push(res);
        }

        Ok(Proof(bytes))
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
