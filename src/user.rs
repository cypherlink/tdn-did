use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};
use tdn_types::{
    group::GroupId,
    primitive::{PeerAddr, Result},
};

use crate::Proof;

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub id: GroupId,
    pub addr: PeerAddr,
    pub name: String,
    pub avatar: Vec<u8>,
    pub proof: Proof,
}

impl User {
    pub fn new(
        id: GroupId,
        addr: PeerAddr,
        name: String,
        avatar: Vec<u8>,
        kp: &Keypair,
    ) -> Result<Self> {
        let proof = Proof::prove(kp, &addr);

        Ok(Self {
            id,
            addr,
            name,
            avatar,
            proof,
        })
    }

    /// verify if addr is signature by Did.
    pub fn verify(&self) -> Result<()> {
        self.proof.verify(&self.id, &self.addr)
    }

    pub fn new_simple(id: GroupId, addr: PeerAddr, kp: &Keypair) -> Self {
        let proof = Proof::prove(kp, &addr);
        User {
            id,
            proof,
            addr,
            name: String::new(),
            avatar: vec![],
        }
    }

    pub fn is_simple(&self) -> bool {
        self.name.len() == 0
    }
}
