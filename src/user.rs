use serde::{Deserialize, Serialize};
use tdn_types::{
    group::GroupId,
    primitive::{PeerAddr, Result},
};

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub id: GroupId,
    pub addr: PeerAddr,
    pub name: String,
    pub avatar: Vec<u8>,
}

impl User {
    pub fn new(id: GroupId, addr: PeerAddr, name: String, avatar: Vec<u8>) -> Result<Self> {
        Ok(Self {
            id,
            addr,
            name,
            avatar,
        })
    }
}
