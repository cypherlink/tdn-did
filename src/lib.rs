use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tdn_types::primitive::{new_io_error, PeerAddr, Result};

pub mod user;
pub use user::User;

#[derive(Default, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Did([u8; 32]);

#[derive(Default)]
pub struct Secret([u8; 32]);

#[derive(Default)]
pub struct Proof([u8; 32]);

impl Did {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(self.0.len() * 2);
        s.extend(self.0.iter().map(|b| format!("{:02x}", b)));
        s
    }

    pub fn from_hex(s: impl ToString) -> Result<Self> {
        let s = s.to_string();
        if s.len() != 64 {
            return Err(new_io_error("hex is invalid"));
        }

        let mut value = [0u8; 32];

        for i in 0..(s.len() / 2) {
            let res = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|_e| new_io_error("hex is invalid"))?;
            value[i] = res;
        }

        Ok(Self(value))
    }
}

pub fn genereate_id(seed: &[u8]) -> (Did, Secret) {
    let mut sha = Sha3_256::new();
    sha.update(seed);

    let mut did = [0u8; 32];
    did.copy_from_slice(&sha.finalize()[..]);

    (Did(did), Secret([0u8; 32]))
}

pub fn _zkp_proof(_peer_addr: &PeerAddr, _m_id: &Did, _sk: &Secret, _r_id: &Did) -> Proof {
    todo!()
}

pub fn _zkp_verify(_proof: &Proof, _peer_addr: &PeerAddr, _r_id: &Did, _sk: &Secret) -> bool {
    todo!()
}
