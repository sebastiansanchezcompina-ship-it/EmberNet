use serde::{Serialize, Deserialize};

pub const MAGIC_BYTES: u16 = 0xEB01; 
pub const CURRENT_VERSION: u8 = 1;
// ID especial para "A todos" (Broadcast)
pub const BROADCAST_ID: [u8; 8] = [0; 8];

#[repr(u8)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum MessageType {
    Hello = 0x01,     
    PeerList = 0x02,  
    Chat = 0x03,      
    FileChunk = 0x04, 
    Ack = 0x05,       
    Unknown = 0xFF,   
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    pub magic: u16,
    pub version: u8,
    pub msg_type: MessageType,
    pub ttl: u8,
    pub flags: u8,
    pub msg_id: u64,
    pub src_id: [u8; 8],
    pub dest_id: [u8; 8], // 👈 NUEVO CAMPO: ¿Para quién es esto?
    pub sender_pubkey: [u8; 32],
    pub payload_len: u16,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Frame {
    pub header: Header,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Frame {
    pub fn is_valid_structure(&self) -> bool {
        if self.header.magic != MAGIC_BYTES { return false; }
        if self.header.payload_len as usize != self.payload.len() { return false; }
        if self.header.ttl == 0 { return false; }
        true
    }

    pub fn decrement_ttl(&mut self) -> bool {
        if self.header.ttl > 0 {
            self.header.ttl -= 1;
            true
        } else {
            false
        }
    }
}