use serde::{Deserialize, Serialize};
use tdn_types::primitive::PeerAddr;

use crate::{genereate_id, Did, Secret};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct User {
    pub id: Did,
    pub addr: PeerAddr,
    pub name: String,
    pub avatar: String,
    pub bio: String,
}

impl User {
    pub fn new(id: Did, addr: PeerAddr, name: String, avatar: String, bio: String) -> Self {
        Self {
            id,
            addr,
            name,
            avatar,
            bio,
        }
    }

    pub fn new_simple(id: Did) -> Self {
        let mut u = User::default();
        u.id = id;
        u
    }

    pub fn is_simple(&self) -> bool {
        self.addr == PeerAddr::default()
    }
}

pub fn generate(
    addr: PeerAddr,
    name: String,
    avatar: String,
    bio: String,
    seed: &[u8],
) -> (User, Secret) {
    let (did, sk) = genereate_id(seed);
    (User::new(did, addr, name, avatar, bio), sk)
}
