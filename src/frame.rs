use ed25519_dalek::{
    Signature,
    SigningKey,
    VerifyingKey,
    Verifier,
    Signer,
};
use rand::RngCore;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct SignedFrame {
    pub src_id: [u8; 8],
    pub msg_id: u64,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>, // 👈 CAMBIO AQUÍ
    pub pubkey: Vec<u8>,    // 👈 Y AQUÍ
}

impl SignedFrame {
    pub fn sign(
        src_id: [u8; 8],
        payload: Vec<u8>,
        signing: &SigningKey,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let msg_id = rng.next_u64();

        let mut data = Vec::new();
        data.extend_from_slice(&src_id);
        data.extend_from_slice(&msg_id.to_le_bytes());
        data.extend_from_slice(&payload);

        let signature = signing.sign(&data).to_bytes().to_vec();
        let pubkey = signing.verifying_key().to_bytes().to_vec();

        Self {
            src_id,
            msg_id,
            payload,
            signature,
            pubkey,
        }
    }

    pub fn verify(&self) -> bool {
        if self.signature.len() != 64 || self.pubkey.len() != 32 {
            return false;
        }

        let mut data = Vec::new();
        data.extend_from_slice(&self.src_id);
        data.extend_from_slice(&self.msg_id.to_le_bytes());
        data.extend_from_slice(&self.payload);

        let pubkey = VerifyingKey::from_bytes(self.pubkey.as_slice().try_into().unwrap()).unwrap();
        let sig = Signature::from_bytes(self.signature.as_slice().try_into().unwrap());

        pubkey.verify(&data, &sig).is_ok()
    }
}
