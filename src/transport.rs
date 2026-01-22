use std::net::UdpSocket;
use std::sync::Arc;
use std::net::SocketAddr;

#[derive(Clone)]
pub struct Transport {
    socket: Arc<UdpSocket>,
}

impl Transport {
    pub fn bind(port: u16) -> Self {
        let addr = format!("0.0.0.0:{}", port);
        let socket = UdpSocket::bind(&addr).expect("No se pudo enlazar al puerto UDP");
        
        // Configuración importante para rendimiento
        socket.set_nonblocking(true).expect("Fallo al poner en no-bloqueante");

        Self {
            socket: Arc::new(socket),
        }
    }

    pub fn send(&self, data: &[u8], target: SocketAddr) {
        // Ignoramos errores de envío (UDP es fire-and-forget)
        let _ = self.socket.send_to(data, target);
    }

    pub fn recv(&self) -> Option<(Vec<u8>, SocketAddr)> {
        // 🛑 CAMBIO IMPORTANTE: 
        // Aumentamos el buffer a 65535 (Máximo teórico de UDP)
        // Para asegurar que NUNCA cortemos un paquete por falta de espacio.
        let mut buf = [0u8; 65535]; 

        match self.socket.recv_from(&mut buf) {
            Ok((amt, src)) => {
                // Devolvemos solo la parte que tiene datos
                Some((buf[..amt].to_vec(), src))
            },
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                None // No hay mensajes, todo bien
            },
            Err(_) => {
                None // Otro error
            },
        }
    }
    
    // Función auxiliar para clonar la referencia al socket (necesario para threads)
    pub fn try_clone(&self) -> Self {
        Self {
            socket: self.socket.clone(),
        }
    }
}