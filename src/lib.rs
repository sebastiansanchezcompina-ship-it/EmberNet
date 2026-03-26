pub mod identity;
pub mod protocol;
pub mod transport;
pub mod replay_cache;
pub mod rate_limiter;
pub mod node;
pub mod crypto;
pub mod chunker;

use std::sync::{Arc, Mutex};
use std::thread;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use android_logger::Config;
use log::LevelFilter;

use crate::protocol::{Frame, Header, MessageType, MAGIC_BYTES, CURRENT_VERSION, BROADCAST_ID};
use rand::RngCore;
use ed25519_dalek::Signer;

use node::Node;
use identity::Identity;
use transport::Transport;

// --- VARIABLES GLOBALES ---
static mut NODE_HANDLE: Option<Arc<Mutex<Node>>> = None;
static mut TRANSPORT_HANDLE: Option<Transport> = None;
static mut IDENTITY_HANDLE: Option<Arc<Identity>> = None;
static mut MESSAGE_QUEUE: Option<Arc<Mutex<Vec<String>>>> = None;

// 🟢 FUNCIÓN 1: INICIALIZAR + HEARTBEAT + RECEPTOR 💓
#[no_mangle]
pub extern "system" fn Java_com_example_ember_EmberLib_init(
    mut env: JNIEnv, 
    _class: JClass,
    storage_path: JString,
    port: i32,
) -> jstring {
    android_logger::init_once(Config::default().with_max_level(LevelFilter::Debug));
    
    // Convertimos la ruta de Java a String de Rust
    let path: String = env.get_string(&storage_path).expect("Error path").into();
    let port = port as u16;

    // Cargamos la identidad
    let id = Arc::new(Identity::load_or_generate(&path, port)); 
    let node_id = id.node_id();

    // Creamos las variables
    let trans = Transport::bind(port); 
    let node_inst = Arc::new(Mutex::new(Node::new(node_id)));

    unsafe {
        NODE_HANDLE = Some(node_inst.clone());
        TRANSPORT_HANDLE = Some(trans.try_clone());
        IDENTITY_HANDLE = Some(Arc::clone(&id)); 
        MESSAGE_QUEUE = Some(Arc::new(Mutex::new(Vec::new())));
    }

    // --- 💓 HILO DE HEARTBEAT ---
    let t_hb = trans.try_clone();
    let id_hb = Arc::clone(&id);
    let node_id_hb = id_hb.node_id();
    let pubkey_hb = id_hb.verify.to_bytes();

    thread::spawn(move || {
        let pc_addr = "10.0.2.2:4004";
        loop {
            let enc = crypto::encrypt(b"");
            let frame = build_frame(&id_hb, node_id_hb, pubkey_hb, BROADCAST_ID, MessageType::Hello, enc);

            if let Ok(packet) = bincode::serialize(&frame) {
                if let Ok(addr) = pc_addr.parse() {
                    let _ = t_hb.send(&packet, addr);
                }
            }
            thread::sleep(std::time::Duration::from_secs(5));
        }
    });

    // --- 📥 HILO RECEPTOR (Lógica Principal) ---
    let t_lis = trans.try_clone();
    let node_clone = node_inst.clone();

    thread::spawn(move || {
        loop {
            // 1. Recibir datos del socket
            if let Some((data, src)) = t_lis.recv() {
                // 2. Deserializar el Frame
                if let Ok(frame) = bincode::deserialize::<Frame>(&data) {
                    
                    // 3. Procesar en el Nodo
                    let mut n = node_clone.lock().unwrap();
                    let resultado = n.on_frame(frame, src); // 👈 AQUÍ OBTENEMOS EL RESULTADO

                    // --- A: LOGS A PANTALLA ---
                    if let Some(texto_log) = resultado.log_output {
                        unsafe {
                            let queue_ptr = &raw const MESSAGE_QUEUE; 
                            if let Some(queue) = &*queue_ptr { 
                                let mut q = queue.lock().unwrap();
                                q.push(texto_log);
                            }
                        }
                    }

                    // --- B: REENVÍO (MESH) ---
                    if let Some(f) = resultado.frame_to_relay { 
                        if let Ok(packet) = bincode::serialize(&f) {
                            for (peer_addr, _) in &n.peers {
                                if *peer_addr != src { 
                                    let _ = t_lis.send(&packet, *peer_addr);
                                }
                            }
                        }
                    }

                    // --- C: ACKS (CONFIRMACIONES) ---
                    // Este código ahora está en el lugar correcto, donde 't_lis' y 'resultado' existen
                    if let Some((target_ack, msg_id)) = resultado.ack_to_send {
                        let payload_ack = msg_id.to_le_bytes().to_vec();

                        unsafe {
                            let id_ptr = &raw const IDENTITY_HANDLE;
                            if let Some(id_arc) = &*id_ptr {
                                let id = id_arc.as_ref();
                                
                                let frame_ack = build_frame(
                                    id, 
                                    id.node_id(), 
                                    id.verify.to_bytes(), 
                                    BROADCAST_ID, 
                                    MessageType::Ack, 
                                    payload_ack
                                );

                                if let Ok(packet) = bincode::serialize(&frame_ack) {
                                    let _ = t_lis.send(&packet, target_ack);
                                }
                            }
                        }
                    } 
                    // Fin ACKs

                } 
            } 
        } 
    });

    let output = format!("Nodo OK. ID: {:02x?}", node_id);
    env.new_string(output).expect("Error string").into_raw()
}

// 🔵 FUNCIÓN 2: ENVIAR
#[no_mangle]
pub extern "system" fn Java_com_example_ember_EmberLib_send(
    mut env: JNIEnv, 
    _class: JClass,
    target_ip: JString,
    message: JString,
) -> jstring {
    let target_str: String = env.get_string(&target_ip).expect("Error IP").into();
    let msg_content: String = env.get_string(&message).expect("Error MSG").into();

    unsafe {
        let transport_ptr = &raw const TRANSPORT_HANDLE;
        let id_ptr = &raw const IDENTITY_HANDLE;

        if let (Some(transport), Some(id_arc)) = (&*transport_ptr, &*id_ptr) {
            let id = id_arc.as_ref();
            
            let encrypted_payload = crypto::encrypt(msg_content.as_bytes());
            let frame = build_frame(id, id.node_id(), id.verify.to_bytes(), BROADCAST_ID, MessageType::Chat, encrypted_payload);

            if let Ok(packet) = bincode::serialize(&frame) {
                if let Ok(addr) = target_str.parse() {
                    let _ = transport.send(&packet, addr);
                }
            }
        }
    }
    env.new_string("Enviado").unwrap().into_raw()
}

// 🟡 FUNCIÓN 3: POLLING DE MENSAJES
#[no_mangle]
pub extern "system" fn Java_com_example_ember_EmberLib_pollMessage(
    env: JNIEnv, 
    _class: JClass,
) -> jstring {
    unsafe {
        let queue_ptr = &raw const MESSAGE_QUEUE;
        if let Some(queue) = &*queue_ptr {
            let mut q = queue.lock().unwrap();
            if !q.is_empty() {
                return env.new_string(q.remove(0)).unwrap().into_raw();
            }
        }
    }
    env.new_string("").unwrap().into_raw()
}

// 🟢 FUNCIÓN 4: OBTENER VECINOS (Corregida y Limpia)
#[no_mangle]
pub extern "system" fn Java_com_example_ember_EmberLib_getPeers(
    env: JNIEnv, 
    _class: JClass,
) -> jstring {
    unsafe {
        let node_ptr = &raw const NODE_HANDLE;
        if let Some(node_arc) = &*node_ptr {
            if let Ok(node) = node_arc.lock() {
                let mut lista = String::new();
                for (socket_addr, _) in &node.peers {
                    if !lista.is_empty() {
                        lista.push_str(","); 
                    }
                    lista.push_str(&socket_addr.to_string());
                }
                return env.new_string(lista).unwrap().into_raw();
            }
        }
    }
    env.new_string("").unwrap().into_raw()
}

// 🔴 FUNCIÓN 5: BLOQUEAR CON DIAGNÓSTICO
#[no_mangle]
pub extern "system" fn Java_com_example_ember_EmberLib_toggleBlock(
    mut env: JNIEnv, 
    _class: JClass,
    target_id_hex: JString,
) -> jstring {
    // 1. Obtenemos lo que escribiste
    let raw_str: String = env.get_string(&target_id_hex).expect("Error ID").into();
    
    // 📢 LOG VISIBLE: Esto SÍ saldrá en Logcat (tag: Ember)
    log::info!("INTENTO BLOQUEO: Texto recibido: '{}'", raw_str);

    // Limpiamos espacios invisibles por si acaso (trim)
    let clean_str = raw_str.trim();

    // 2. Intentamos convertir
    match hex::decode(clean_str) {
        Ok(decoded) => {
            // Verificamos longitud
            if decoded.len() == 8 {
                let mut id_bytes = [0u8; 8];
                id_bytes.copy_from_slice(&decoded);
                
                unsafe {
                    let node_ptr = &raw const NODE_HANDLE;
                    if let Some(node_arc) = &*node_ptr {
                        if let Ok(mut node) = node_arc.lock() {
                            let is_blocked = node.toggle_block(id_bytes);
                            let msg = if is_blocked { "BLOQUEADO 🚫" } else { "DESBLOQUEADO ✅" };
                            log::info!("EXITO: Usuario {}", msg);
                            return env.new_string(msg).unwrap().into_raw();
                        }
                    }
                }
                return env.new_string("Error: Nodo no disponible").unwrap().into_raw();
            } else {
                // Error de longitud
                let error_msg = format!("Error: Longitud incorrecta ({} bytes, se esperan 8)", decoded.len());
                log::error!("{}", error_msg);
                return env.new_string(error_msg).unwrap().into_raw();
            }
        },
        Err(e) => {
            // Error de caracteres (ej: escribiste una 'Z' o 'G' que no es hex, o longitud impar)
            let error_msg = format!("Error Hex: 'Impar' o 'Letra mala'. Detalle: {:?}", e);
            log::error!("{}", error_msg);
            return env.new_string(error_msg).unwrap().into_raw();
        }
    }
}

// FUNCIÓN AUXILIAR
fn build_frame(id: &Identity, src_id: [u8; 8], pubkey: [u8; 32], dest_id: [u8; 8], msg_type: MessageType, payload: Vec<u8>) -> Frame {
    let mut rng = rand::thread_rng();
    let msg_id = rng.next_u64();
    let header = Header { magic: MAGIC_BYTES, version: CURRENT_VERSION, msg_type, ttl: 3, flags: 0, msg_id, src_id, dest_id, sender_pubkey: pubkey, payload_len: payload.len() as u16 };
    let mut h2 = header.clone(); h2.ttl = 0; h2.flags = 0;
    let mut d = bincode::serialize(&h2).unwrap(); d.extend_from_slice(&payload);
    let sig = id.signing.sign(&d).to_bytes().to_vec();
    Frame { header, payload, signature: sig }
}