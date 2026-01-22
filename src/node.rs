use crate::protocol::{Frame, MessageType, BROADCAST_ID};
use crate::replay_cache::{ReplayCache, ReplayKey};
use crate::rate_limiter::RateLimiter;
use crate::crypto;
use crate::chunker::{Assembler, Chunk};
use ed25519_dalek::{Verifier, VerifyingKey, Signature};
use std::convert::TryInto;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Instant, Duration};
use std::fs::{self, File};
use std::io::Write;

#[derive(Debug)]
pub enum State { Idle, Processing }

// ⚠️ ESTO ES LO QUE FALTABA: log_output
pub struct ProcessResult {
    pub frame_to_relay: Option<Frame>,         
    pub ack_to_send: Option<(SocketAddr, u64)>,
    pub log_output: Option<String>, // 👈 El canal hacia la pantalla
}

pub struct Node {
    pub state: State,
    pub my_id: [u8; 8],
    replay_cache: ReplayCache,
    rate_limiter: RateLimiter,
    pub peers: HashMap<SocketAddr, Instant>,
    assembler: Assembler,
}

impl Node {
    pub fn new(my_id: [u8; 8]) -> Self {
        let _ = fs::create_dir_all("downloads");
        Self {
            state: State::Idle,
            my_id,
            replay_cache: ReplayCache::new(),
            rate_limiter: RateLimiter::new(),
            peers: HashMap::new(),
            assembler: Assembler::new(),
        }
    }

    pub fn add_peer(&mut self, addr: SocketAddr) {
        self.peers.insert(addr, Instant::now());
    }

    pub fn prune_dead_nodes(&mut self, timeout: Duration) -> Vec<SocketAddr> {
        self.assembler.cleanup_stale(); 
        let now = Instant::now();
        let mut dead_nodes = Vec::new();
        self.peers.retain(|addr, last_seen| {
            if now.duration_since(*last_seen) > timeout {
                dead_nodes.push(*addr);
                false
            } else { true }
        });
        dead_nodes
    }

    pub fn on_frame(&mut self, mut frame: Frame, src: SocketAddr) -> ProcessResult {
        self.state = State::Processing;
        // Inicializamos log_output como None
        let mut result = ProcessResult { frame_to_relay: None, ack_to_send: None, log_output: None };

        if !frame.is_valid_structure() {
            self.state = State::Idle; return result;
        }

        let key = ReplayKey { sender: frame.header.src_id, msg_id: frame.header.msg_id.to_le_bytes() };
        if self.replay_cache.seen(key) { self.state = State::Idle; return result; }

        if !self.verify_signature(&frame) {
            // Enviamos el error a la pantalla en vez de println!
            result.log_output = Some(format!("⛔ Firma inválida de {}", src));
            self.state = State::Idle; return result;
        }

        self.peers.insert(src, Instant::now());

        let is_broadcast = frame.header.dest_id == BROADCAST_ID;
        let is_for_me = frame.header.dest_id == self.my_id;

        if !is_broadcast && !is_for_me {
            if frame.header.msg_type != MessageType::PeerList && frame.header.msg_type != MessageType::Hello {
                if frame.decrement_ttl() { result.frame_to_relay = Some(frame); }
                self.state = State::Idle;
                return result;
            }
        }

        match crypto::decrypt(&frame.payload) {
            Some(decrypted_payload) => {
                match frame.header.msg_type {
                    MessageType::Hello => {
                         if self.peers.insert(src, Instant::now()).is_none() { 
                             result.log_output = Some(format!("👋 NUEVO VECINO: {}", src)); 
                         }
                    },
                    MessageType::PeerList => {
                        if let Ok(new_peers) = bincode::deserialize::<Vec<SocketAddr>>(&decrypted_payload) {
                            for peer in new_peers {
                                if !self.peers.contains_key(&peer) && peer != src {
                                    self.peers.insert(peer, Instant::now());
                                    result.log_output = Some(format!("💡 Ruta aprendida: {}", peer));
                                }
                            }
                        }
                    },
                    MessageType::Chat => {
                        let texto = String::from_utf8_lossy(&decrypted_payload);
                        if is_for_me && !is_broadcast {
                            // Privado
                            result.log_output = Some(format!("🕵️‍♂️ PRIVADO DE [{:02x?}]: {}", &frame.header.src_id[0..4], texto));
                            result.ack_to_send = Some((src, frame.header.msg_id));
                        } else {
                            // Chat normal
                            result.log_output = Some(format!("💬 [{:02x?}] dice: {}", &frame.header.src_id[0..4], texto));
                        }
                        if !self.peers.contains_key(&src) { self.peers.insert(src, Instant::now()); }
                    },
                    MessageType::FileChunk => {
                        if is_for_me || is_broadcast {
                            if let Ok(chunk) = bincode::deserialize::<Chunk>(&decrypted_payload) {
                                // Notificar cada 50 paquetes para ver que está vivo
                                if chunk.index % 50 == 0 {
                                     // result.log_output = Some(format!("⏳ Bajando... {}/{}", chunk.index, chunk.total));
                                }
                                
                                if let Some(full_data) = self.assembler.add_chunk(chunk) {
                                    if full_data.starts_with(b"FILE:") {
                                        if let Some(separator_index) = full_data.iter().position(|&r| r == b'|') {
                                            let name_part = &full_data[5..separator_index];
                                            let file_content = &full_data[separator_index + 1..];
                                            let filename = String::from_utf8_lossy(name_part);
                                            let path = format!("downloads/{}", filename);
                                            match File::create(&path) {
                                                Ok(mut file) => {
                                                    let _ = file.write_all(file_content);
                                                    result.log_output = Some(format!("💾 ARCHIVO GUARDADO: {}", path));
                                                },
                                                Err(e) => result.log_output = Some(format!("❌ Error disco: {}", e)),
                                            }
                                        }
                                    } else {
                                        let texto = String::from_utf8_lossy(&full_data);
                                        result.log_output = Some(format!("📦 MENSAJE REARMADO: {}", texto));
                                    }
                                    result.ack_to_send = Some((src, frame.header.msg_id));
                                }
                            }
                        }
                    },
                    MessageType::Ack => {
                        if is_for_me {
                            if let Ok(original_msg_id) = bincode::deserialize::<u64>(&decrypted_payload) {
                                result.log_output = Some(format!("✅ Confirmado (ID: {})", original_msg_id));
                            }
                        }
                    },
                    _ => {}
                }
            },
            None => { /* Error de llave, ignorar */ }
        }

        self.state = State::Idle;
        if is_broadcast && frame.decrement_ttl() { 
            result.frame_to_relay = Some(frame); 
        } else if !is_broadcast && !is_for_me && frame.decrement_ttl() {
             result.frame_to_relay = Some(frame); 
        }
        
        result
    }
    
    fn verify_signature(&self, frame: &Frame) -> bool {
        let pubkey_bytes = frame.header.sender_pubkey;
        let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) { Ok(k) => k, Err(_) => return false };
        let signature_bytes: [u8; 64] = match frame.signature.as_slice().try_into() { Ok(b) => b, Err(_) => return false };
        let signature = Signature::from_bytes(&signature_bytes);
        let mut h = frame.header.clone(); h.ttl = 0; h.flags = 0; 
        let mut d = bincode::serialize(&h).unwrap(); d.extend_from_slice(&frame.payload);
        verifying_key.verify(&d, &signature).is_ok()
    }
}