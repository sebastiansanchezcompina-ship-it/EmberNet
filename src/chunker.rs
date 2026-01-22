use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::Instant;

const CHUNK_SIZE: usize = 500; 

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Chunk {
    pub msg_id: u64,
    pub total: u32,  // 👈 ANTES u8, AHORA u32 (4 mil millones)
    pub index: u32,  // 👈 ANTES u8, AHORA u32
    pub data: Vec<u8>,
}

pub struct Assembler {
    //                                👇 u32 aquí también
    buffer: HashMap<u64, (u32, HashMap<u32, Vec<u8>>, Instant)>,
}

impl Assembler {
    pub fn new() -> Self {
        Self { buffer: HashMap::new() }
    }

    pub fn split_message(msg_id: u64, data: &[u8]) -> Vec<Chunk> {
        let mut chunks = Vec::new();
        // Calculamos usando u32
        let total_chunks = (data.len() as f32 / CHUNK_SIZE as f32).ceil() as u32;

        for (i, chunk_data) in data.chunks(CHUNK_SIZE).enumerate() {
            chunks.push(Chunk {
                msg_id,
                total: total_chunks,
                index: i as u32, // Convertimos i a u32
                data: chunk_data.to_vec(),
            });
        }
        chunks
    }

    pub fn add_chunk(&mut self, chunk: Chunk) -> Option<Vec<u8>> {
        let entry = self.buffer.entry(chunk.msg_id).or_insert((chunk.total, HashMap::new(), Instant::now()));
        
        entry.1.insert(chunk.index, chunk.data);

        // Diagnóstico detallado
        if chunk.index == chunk.total - 1 {
            let tenems = entry.1.len();
            let total = chunk.total as usize;
            if tenems != total {
                println!("⚠️ ALERTA: Llegó el último, pero tengo {} de {} piezas.", tenems, total);
            }
        }

        if entry.1.len() == chunk.total as usize {
            let mut full_data = Vec::new();
            for i in 0..chunk.total {
                if let Some(part) = entry.1.get(&i) {
                    full_data.extend_from_slice(part);
                }
            }
            self.buffer.remove(&chunk.msg_id);
            return Some(full_data);
        }

        None
    }

    pub fn cleanup_stale(&mut self) {
        let now = Instant::now();
        self.buffer.retain(|_, (_, _, time)| now.duration_since(*time).as_secs() < 60);
    }
}