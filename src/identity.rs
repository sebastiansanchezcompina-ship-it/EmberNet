use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Serialize, Deserialize}; // 👈 Importante para guardar en archivo
use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Clone, Debug, Serialize, Deserialize)] // 👈 Agregamos Serialize y Deserialize
pub struct Identity {
    pub signing: SigningKey,
    pub verify: VerifyingKey,
}

impl Identity {
    // Esta es la función que te faltaba y por eso fallaba lib.rs
    pub fn node_id(&self) -> [u8; 8] {
        let mut id = [0u8; 8];
        // Usamos los primeros 8 bytes de la llave pública como ID
        id.copy_from_slice(&self.verify.to_bytes()[..8]);
        id
    }

    pub fn load_or_generate(path: &str, port: u16) -> Self {
        let file_path = std::path::Path::new(path).join(format!("identity_{}.bin", port));

        // Intentar cargar
        if let Ok(data) = std::fs::read(&file_path) {
            if let Ok(id) = bincode::deserialize::<Self>(&data) {
                log::info!("💾 Identidad cargada desde: {:?}", file_path);
                return id;
            }
        }

        // Si falla o no existe, generar nueva
        // 1. Creamos un array de 32 bytes aleatorios
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed); // 👈 Llenamos con entropía del sistema

        // 2. Creamos la llave usando esos bytes (el método que sugirió el compilador)
        let signing = SigningKey::from_bytes(&seed); 
        let verify = signing.verifying_key();
        let new_id = Self { signing, verify };

        // Guardar para la próxima vez
        if let Ok(data) = bincode::serialize(&new_id) {
            let _ = std::fs::write(&file_path, data);
            log::info!("✨ Nueva identidad guardada en: {:?}", file_path);
        }

        new_id
    }
}