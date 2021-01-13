use serde::{Deserialize, Serialize};
use tdn_types::primitive::{new_io_error, PeerAddr, Result};

pub use ed25519_dalek::{PublicKey, SecretKey};

pub mod user;
pub use user::User;

#[derive(Default, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash, Debug)]
pub struct Did([u8; 32]);

#[derive(Default)]
pub struct Proof([u8; 32]);

impl Did {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_string(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    pub fn to_string_with_suffix(&self, suffix: &str) -> String {
        let mut s = bs58::encode(&self.0).into_string();
        s.push_str(suffix);
        s
    }

    pub fn from_string(s: &str) -> Result<Did> {
        bs58::decode(s)
            .into_vec()
            .map(|vec| {
                let mut did = [0u8; 32];
                did.copy_from_slice(&vec);
                Did(did)
            })
            .map_err(|_e| new_io_error("did from string error."))
    }
}

pub fn genereate_id(seed: &[u8]) -> (Did, SecretKey) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed);

    // it must be return.
    loop {
        let tmp_hash = hasher.finalize();
        if let Ok(sk) = SecretKey::from_bytes(tmp_hash.as_bytes()) {
            let pk: PublicKey = (&sk).into();
            return (Did(pk.to_bytes()), sk);
        } else {
            hasher.update(tmp_hash.as_bytes());
        }
    }
}

pub fn _zkp_proof(_peer_addr: &PeerAddr, _m_id: &Did, _sk: &SecretKey, _r_id: &Did) -> Proof {
    todo!()
}

pub fn _zkp_verify(_proof: &Proof, _peer_addr: &PeerAddr, _r_id: &Did, _sk: &SecretKey) -> bool {
    todo!()
}
