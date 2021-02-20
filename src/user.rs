use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use signature::Signature as _;
use tdn_types::primitive::{PeerAddr, Result};

use crate::Did;

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub id: Did,
    pub addr: PeerAddr,
    pub name: String,
    pub avatar: Vec<u8>,
    pub sign1: [u8; 32], // use two for auto-serialize. Lazy.
    pub sign2: [u8; 32],
}

impl User {
    pub fn new(
        id: Did,
        addr: PeerAddr,
        name: String,
        avatar: Vec<u8>,
        kp: &Keypair,
    ) -> Result<Self> {
        let sign = kp.sign(&addr.0).to_bytes();
        let mut sign1 = [0u8; 32];
        let mut sign2 = [0u8; 32];
        sign1.copy_from_slice(&sign[..32]);
        sign2.copy_from_slice(&sign[32..]);

        Ok(Self {
            id,
            addr,
            name,
            avatar,
            sign1,
            sign2,
        })
    }

    /// verify if addr is signature by Did.
    pub fn verify(&self) -> bool {
        let mut sign_bytes = [0u8; 64];
        sign_bytes[..32].copy_from_slice(&self.sign1);
        sign_bytes[32..].copy_from_slice(&self.sign1);
        if let Ok(sign) = Signature::from_bytes(&sign_bytes) {
            if let Ok(pk) = PublicKey::from_bytes(&self.id.0) {
                return pk.verify(&self.addr.0, &sign).is_ok();
            }
        }

        false
    }

    pub fn new_simple(id: Did) -> Self {
        User {
            id,
            addr: PeerAddr::default(),
            name: String::new(),
            avatar: vec![],
            sign1: [0u8; 32],
            sign2: [0u8; 32],
        }
    }

    pub fn is_simple(&self) -> bool {
        self.addr == PeerAddr::default()
    }
}
