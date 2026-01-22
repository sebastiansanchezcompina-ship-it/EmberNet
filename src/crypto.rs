use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce 
};
use rand::RngCore;

// 🔑 CLAVE MAESTRA DE LA RED (32 bytes)
// En un futuro, esto podría negociarse con Diffie-Hellman (X25519).
// Por ahora, usamos una clave compartida (Pre-Shared Key) para que funcione.
// ¡Si cambias una letra aquí, los nodos dejarán de entenderse!
const NETWORK_KEY: &[u8; 32] = b"EMBER_MESH_SECRET_KEY_v1_2024_OK";

/// Encripta los datos usando XChaCha20-Poly1305
/// Devuelve: [NONCE (24 bytes) | CIPHERTEXT (datos cifrados)]
pub fn encrypt(plaintext: &[u8]) -> Vec<u8> {
    // 1. Iniciamos el cifrador con la clave maestra
    let cipher = XChaCha20Poly1305::new(NETWORK_KEY.into());

    // 2. Generamos un "Nonce" (Número de uso único) aleatorio de 24 bytes
    // Esto es vital: asegura que si envías "Hola" dos veces, el cifrado se vea diferente.
    let mut nonce = XNonce::default();
    OsRng.fill_bytes(&mut nonce);

    // 3. Encriptamos
    // Poly1305 añade automáticamente un "Tag" de autenticación.
    // Si alguien altera un bit del mensaje cifrado, el descifrado fallará.
    let ciphertext = cipher.encrypt(&nonce, plaintext).expect("Fallo de encriptación");

    // 4. Empaquetamos: Primero el Nonce (público), luego el contenido (secreto)
    let mut packet = nonce.to_vec();
    packet.extend_from_slice(&ciphertext);
    
    packet
}

/// Intenta descifrar un paquete
pub fn decrypt(data: &[u8]) -> Option<Vec<u8>> {
    // El paquete debe tener al menos 24 bytes (el tamaño del nonce)
    if data.len() < 24 {
        return None;
    }

    // 1. Separamos el Nonce del contenido cifrado
    let nonce_bytes = &data[..24];
    let ciphertext = &data[24..];

    let cipher = XChaCha20Poly1305::new(NETWORK_KEY.into());
    let nonce = XNonce::from_slice(nonce_bytes);

    // 2. Intentamos descifrar
    // Esto fallará (devolverá None) si la clave es incorrecta O si el mensaje fue alterado.
    cipher.decrypt(nonce, ciphertext).ok()
}