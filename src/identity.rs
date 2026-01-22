use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use rand::rngs::OsRng;
use rand::RngCore; // 👈 Necesario para llenar los bytes aleatorios
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct SavedIdentity {
    secret_bytes: Vec<u8>, 
    public_key_hex: String, 
}

pub struct Identity {
    pub signing: SigningKey,
    pub verify: VerifyingKey,
}

impl Identity {
    pub fn load_or_generate(port: u16) -> Self {
        let filename = format!("identity_{}.json", port);
        let path = Path::new(&filename);

        if path.exists() {
            println!("📂 Cargando identidad existente desde {}...", filename);
            match fs::read_to_string(path) {
                Ok(json_content) => {
                    if let Ok(saved) = serde_json::from_str::<SavedIdentity>(&json_content) {
                        let array_bytes: [u8; 32] = match saved.secret_bytes.try_into() {
                            Ok(arr) => arr,
                            Err(_) => {
                                println!("⚠️ Archivo corrupto. Generando nueva.");
                                return Self::generate_and_save(&filename);
                            }
                        };
                        let signing = SigningKey::from_bytes(&array_bytes);
                        let verify = signing.verifying_key();
                        return Self { signing, verify };
                    }
                },
                Err(_) => println!("⚠️ Error leyendo archivo."),
            }
        }

        println!("🆕 Creando nueva identidad...");
        Self::generate_and_save(&filename)
    }

    fn generate_and_save(filename: &str) -> Self {
        // 🛠️ ARREGLO DEL ERROR:
        // En lugar de SigningKey::generate, hacemos esto:
        
        // 1. Generamos 32 bytes de ruido aleatorio puro
        let mut secret_bytes_arr = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes_arr);

        // 2. Creamos la llave usando esos bytes (esto es lo que pedía el compilador: from_bytes)
        let signing = SigningKey::from_bytes(&secret_bytes_arr);
        let verify = signing.verifying_key();

        // Guardamos
        let secret_bytes = secret_bytes_arr.to_vec();
        let public_key_hex = hex::encode(verify.to_bytes());

        let saved = SavedIdentity {
            secret_bytes,
            public_key_hex,
        };

        if let Ok(json) = serde_json::to_string_pretty(&saved) {
            let _ = fs::write(filename, json);
            println!("💾 Identidad guardada en {}", filename);
        }

        Self { signing, verify }
    }

    pub fn node_id(&self) -> [u8; 8] {
        let pub_bytes = self.verify.to_bytes();
        let mut id = [0u8; 8];
        id.copy_from_slice(&pub_bytes[0..8]);
        id
    }
}