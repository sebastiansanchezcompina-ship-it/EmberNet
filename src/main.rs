mod identity;
mod protocol;
mod transport;
mod replay_cache;
mod rate_limiter;
mod node;
mod crypto;
mod chunker;

use identity::Identity;
use protocol::{Frame, Header, MessageType, MAGIC_BYTES, CURRENT_VERSION, BROADCAST_ID};
use transport::Transport;
use node::Node;
use chunker::Assembler;

use std::env;
use std::fs;
use std::io::{self, Stdout};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration};
use ed25519_dalek::Signer;
use rand::RngCore;

// --- Librerías de Interfaz (TUI) ---
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style, Modifier},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, List, ListItem, Paragraph},
    Terminal,
};

// Estructura para manejar el estado de la App
struct App {
    messages: Vec<String>,
    input: String,
    node_id_hex: String,
    port: u16,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { 
        println!("Uso: cargo run <MI_PUERTO> [IP_VECINO:PUERTO]");
        return Ok(());
    }
    
    let port: u16 = args[1].parse().expect("Puerto inválido");
    let initial_peer: Option<SocketAddr> = if args.len() > 2 {
        let peer_addr_str = &args[2];
        Some(peer_addr_str.parse().expect("Dirección inválida"))
    } else { None };

    // --- Configuración Inicial ---
    let id = Identity::load_or_generate(port);
    let node_id = id.node_id();
    let pubkey_bytes = id.verify.to_bytes();
    let node_id_hex = hex::encode(node_id);

    let transport = Transport::bind(port);
    let t_lis = transport.try_clone();
    let t_relay = transport.try_clone();
    let t_ack = transport.try_clone();
    let t_hb = transport.try_clone();
    let t_main = transport.try_clone();

    let id_hb = Identity { signing: ed25519_dalek::SigningKey::from_bytes(&id.signing.to_bytes()), verify: id.verify.clone() };
    let node_id_hb = node_id;
    let pubkey_hb = pubkey_bytes;
    let id_ack = Identity { signing: ed25519_dalek::SigningKey::from_bytes(&id.signing.to_bytes()), verify: id.verify.clone() };

    let node = Arc::new(Mutex::new(Node::new(node_id)));

    if let Some(peer) = initial_peer {
        let mut n = node.lock().unwrap(); n.add_peer(peer); drop(n); 
        let enc = crypto::encrypt(b"");
        let frame = build_frame(&id, node_id, pubkey_bytes, BROADCAST_ID, MessageType::Hello, enc);
        transport.send(&bincode::serialize(&frame).unwrap(), peer);
    }

    let (tx, rx) = mpsc::channel::<String>();

    // 1. Hilo de Mantenimiento
    let node_hb = node.clone();
    let tx_hb = tx.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(5));
            let mut n = node_hb.lock().unwrap();
            let dead = n.prune_dead_nodes(Duration::from_secs(15));
            if !dead.is_empty() { 
                for d in dead { let _ = tx_hb.send(format!("💀 Timeout: {}", d)); }
            }
            let peers: Vec<SocketAddr> = n.peers.keys().cloned().collect();
            drop(n);
            if !peers.is_empty() {
                let enc = crypto::encrypt(b"");
                let frame = build_frame(&id_hb, node_id_hb, pubkey_hb, BROADCAST_ID, MessageType::Hello, enc);
                let pkt = bincode::serialize(&frame).unwrap();
                for peer in peers { t_hb.send(&pkt, peer); }
            }
        }
    });

    // 2. Hilo Receptor
    let node_clone = node.clone();
    let tx_net = tx.clone();
    thread::spawn(move || {
        loop {
            if let Some((data, src)) = t_lis.recv() {
                if let Ok(frame) = bincode::deserialize::<Frame>(&data) {
                    let mut n = node_clone.lock().unwrap();
                    let res = n.on_frame(frame, src); 
                    
                    if let Some(log_msg) = res.log_output {
                         let _ = tx_net.send(log_msg);
                    }

                    let peers: Vec<SocketAddr> = n.peers.keys().cloned().collect();
                    drop(n);

                    if let Some(relay) = res.frame_to_relay {
                        let pkt = bincode::serialize(&relay).unwrap();
                        for peer in peers { if peer != src { t_relay.send(&pkt, peer); } }
                    }
                    if let Some((target, msg_id)) = res.ack_to_send {
                        let py = bincode::serialize(&msg_id).unwrap();
                        let enc = crypto::encrypt(&py);
                        let af = build_frame(&id_ack, node_id, pubkey_bytes, BROADCAST_ID, MessageType::Ack, enc);
                        t_ack.send(&bincode::serialize(&af).unwrap(), target);
                    }
                }
            }
        }
    });

    // --- INICIO DE LA UI ---
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = App {
        messages: vec![
            "█▀▀ █▀▄▀█ █▄▄ █▀▀ █▀█".to_string(),
            "██▄ █ ▀ █ █▄█ ██▄ █▀▄ v1.2 (PC Stable)".to_string(), // 👈 Aquí puse tu versión
            format!("🆔 NODE ID: {}", node_id_hex),
            "--------------------------------".to_string(),
        ],
        input: String::new(),
        node_id_hex: node_id_hex.clone(),
        port,
    };

    let res = run_app(&mut terminal, app, rx, node, id, node_id, pubkey_bytes, t_main);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    mut app: App,
    rx: mpsc::Receiver<String>,
    node: Arc<Mutex<Node>>,
    id: Identity,
    my_node_id: [u8; 8],
    my_pubkey: [u8; 32],
    transport: Transport,
) -> io::Result<()> {
    
    let matrix_style = Style::default().fg(Color::Green).bg(Color::Black);
    let border_style = Style::default().fg(Color::DarkGray);

    loop {
        terminal.draw(|f| {
            let size = f.area();
            let block = Block::default().style(Style::default().bg(Color::Black));
            f.render_widget(block, size);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), 
                    Constraint::Min(1),    
                    Constraint::Length(3), 
                ].as_ref())
                .split(f.area());

            let title_text = format!(" EMBER MESH | PORT: {} | ID: {} ", app.port, &app.node_id_hex[0..8]);
            let title = Paragraph::new(title_text)
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(border_style));
            f.render_widget(title, chunks[0]);

            let messages_ordered: Vec<ListItem> = app.messages.iter().rev()
                .map(|m| {
                    let style = if m.starts_with(">") {
                        Style::default().fg(Color::Yellow)
                    } else if m.contains("TIMEOUT") || m.contains("Error") {
                        Style::default().fg(Color::Red)
                    } else if m.contains("ARCHIVO") {
                        Style::default().fg(Color::Magenta)
                    } else {
                        matrix_style
                    };
                    ListItem::new(Line::from(Span::styled(m, style)))
                })
                .collect();

            let chat_box = List::new(messages_ordered)
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(border_style)
                    .title(" COMM LOG "));
            f.render_widget(chat_box, chunks[1]);

            let input_box = Paragraph::new(format!(">{}█", app.input)) 
                .style(Style::default().fg(Color::White))
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Double) 
                    .border_style(Style::default().fg(Color::Green))
                    .title(" COMMAND INPUT "));
            f.render_widget(input_box, chunks[2]);
            
            f.set_cursor_position((chunks[2].x + app.input.len() as u16 + 1, chunks[2].y + 1));
        })?;

        for msg in rx.try_iter() {
            app.messages.insert(0, msg);
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Esc => return Ok(()),
                    KeyCode::Enter => {
                        let input_text: String = app.input.drain(..).collect();
                        if !input_text.is_empty() {
                            process_command(&input_text, &mut app, &node, &id, my_node_id, my_pubkey, &transport);
                        }
                    },
                    KeyCode::Char(c) => { app.input.push(c); },
                    KeyCode::Backspace => { app.input.pop(); },
                    _ => {}
                }
            }
        }
    }
}

fn process_command(
    text: &str, 
    app: &mut App, 
    node: &Arc<Mutex<Node>>, 
    id: &Identity, 
    node_id: [u8; 8], 
    pubkey: [u8; 32],
    transport: &Transport
) {
    app.messages.insert(0, format!("> {}", text));

    let mut dest_id = BROADCAST_ID;
    let mut data_to_send = Vec::new();

    if text == "/help" {
        app.messages.insert(0, "CMD: /dm <ID> <msg>, /send <file>, /status".to_string());
        return;
    }
    
    if text == "/status" {
        let n = node.lock().unwrap();
        app.messages.insert(0, format!("📊 VECINOS ACTIVOS: {:?}", n.peers.keys()));
        return;
    }

    if text.starts_with("/dm ") {
        let parts: Vec<&str> = text.splitn(3, ' ').collect();
        if parts.len() < 3 { return; }
        if let Ok(bytes) = hex::decode(parts[1]) {
            if bytes.len() <= 8 {
                let mut full_id = [0u8; 8];
                for (i, b) in bytes.iter().enumerate() { if i < 8 { full_id[i] = *b; } }
                dest_id = full_id;
                data_to_send = parts[2].as_bytes().to_vec();
            }
        }
    } else if text.starts_with("/send ") {
        let path_str = text.replace("/send ", "");
        let path = Path::new(&path_str);
        if let Ok(fb) = fs::read(path) {
            let fnm = path.file_name().unwrap().to_string_lossy();
            app.messages.insert(0, format!("📄 LEYENDO: {}...", fnm));
            let h = format!("FILE:{}|", fnm);
            data_to_send.extend_from_slice(h.as_bytes());
            data_to_send.extend_from_slice(&fb);
        } else {
            app.messages.insert(0, "❌ ERROR: Archivo no encontrado".to_string());
            return;
        }
    } else {
        data_to_send = text.as_bytes().to_vec();
    }

    let peers: Vec<SocketAddr> = { let n = node.lock().unwrap(); n.peers.keys().cloned().collect() };
    
    if data_to_send.len() > 800 {
        app.messages.insert(0, "📦 INICIANDO FRAGMENTACIÓN...".to_string());
        let mut rng = rand::thread_rng();
        let big_msg_id = rng.next_u64();
        let chunks = Assembler::split_message(big_msg_id, &data_to_send);
        
        for chunk in chunks {
            let chunk_bytes = bincode::serialize(&chunk).unwrap();
            let encrypted_chunk = crypto::encrypt(&chunk_bytes);
            let frame = build_frame(id, node_id, pubkey, dest_id, MessageType::FileChunk, encrypted_chunk);
            let packet = bincode::serialize(&frame).unwrap();
            
            for peer in &peers { 
                transport.send(&packet, *peer); 
                thread::sleep(Duration::from_millis(250));
            }
        }
        app.messages.insert(0, "✅ ENVÍO COMPLETADO".to_string());
    } else {
        let enc = crypto::encrypt(&data_to_send);
        let frame = build_frame(id, node_id, pubkey, dest_id, MessageType::Chat, enc);
        let packet = bincode::serialize(&frame).unwrap();
        for peer in &peers { transport.send(&packet, *peer); }
    }
}

fn build_frame(id: &Identity, src_id: [u8; 8], pubkey: [u8; 32], dest_id: [u8; 8], msg_type: MessageType, payload: Vec<u8>) -> Frame {
    let mut rng = rand::thread_rng();
    let msg_id = rng.next_u64();
    let header = Header { magic: MAGIC_BYTES, version: CURRENT_VERSION, msg_type, ttl: 3, flags: 0, msg_id, src_id, dest_id, sender_pubkey: pubkey, payload_len: payload.len() as u16 };
    let mut h2 = header.clone(); h2.ttl = 0; h2.flags = 0;
    let mut d = bincode::serialize(&h2).unwrap(); d.extend_from_slice(&payload);
    let sig = id.signing.sign(&d).to_bytes().to_vec();
    Frame { header, payload, signature: sig }
}