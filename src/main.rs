// src/main.rs

// 👇 IMPORTANTE: Usamos 'ember_core' en lugar de 'mod'
use ember_core::identity::Identity;
use ember_core::protocol::{Frame, Header, MessageType, MAGIC_BYTES, CURRENT_VERSION, BROADCAST_ID};
use ember_core::transport::Transport;
use ember_core::node::Node;
use ember_core::chunker::Assembler;
use ember_core::crypto;

use std::env;
use std::fs;
use std::io::{self, Stdout};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration};
use rand::RngCore;
use ed25519_dalek::Signer;

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
    let id = Identity::load_or_generate(".", port);
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

    // Hilo Mantenimiento
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

    // Hilo Receptor
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

    // --- UI ---
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = App {
        messages: vec![
            "📱 MODO HÍBRIDO: Android Lib + PC Client".to_string(),
            format!("🆔 ID: {}", node_id_hex),
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
            let size = f.size();
            let block = Block::default().style(Style::default().bg(Color::Black));
            f.render_widget(block, size);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3), 
                    Constraint::Min(1),    
                    Constraint::Length(3), 
                ].as_ref())
                .split(f.size());

            let title = Paragraph::new(format!(" EMBER MESH | PORT: {} ", app.port))
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).border_type(BorderType::Rounded).border_style(border_style));
            f.render_widget(title, chunks[0]);

            let messages_ordered: Vec<ListItem> = app.messages.iter().rev()
                .map(|m| ListItem::new(Line::from(Span::styled(m, matrix_style))))
                .collect();

            let chat_box = List::new(messages_ordered)
                .block(Block::default().borders(Borders::ALL).title(" LOG "));
            f.render_widget(chat_box, chunks[1]);

            let input_box = Paragraph::new(format!(">{}█", app.input)) 
                .style(Style::default().fg(Color::White))
                .block(Block::default().borders(Borders::ALL).title(" INPUT "));
            f.render_widget(input_box, chunks[2]);
        })?;

        for msg in rx.try_iter() { app.messages.insert(0, msg); }

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

fn process_command(text: &str, app: &mut App, node: &Arc<Mutex<Node>>, id: &Identity, node_id: [u8; 8], pubkey: [u8; 32], transport: &Transport) {
    app.messages.insert(0, format!("> {}", text));
    let peers: Vec<SocketAddr> = { let n = node.lock().unwrap(); n.peers.keys().cloned().collect() };
    let enc = crypto::encrypt(text.as_bytes());
    let frame = build_frame(id, node_id, pubkey, BROADCAST_ID, MessageType::Chat, enc);
    let packet = bincode::serialize(&frame).unwrap();
    for peer in &peers { transport.send(&packet, *peer); }
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