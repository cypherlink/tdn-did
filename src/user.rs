use serde::{Deserialize, Serialize};
use tdn_types::primitive::PeerAddr;

use crate::{genereate_id, Did, SecretKey};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct User {
    pub id: Did,
    pub addr: PeerAddr,
    pub name: String,
}

impl User {
    pub fn new(id: Did, addr: PeerAddr, name: String) -> Self {
        Self { id, addr, name }
    }

    pub fn new_simple(id: Did) -> Self {
        let mut u = User::default();
        u.id = id;
        u
    }

    pub fn is_simple(&self) -> bool {
        self.addr == PeerAddr::default()
    }

    pub fn generate(addr: PeerAddr, name: impl ToString, seed: impl ToString) -> (User, SecretKey) {
        let (did, sk) = genereate_id(seed.to_string().as_bytes());
        (User::new(did, addr, name.to_string()), sk)
    }
}
