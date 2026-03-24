use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;

use crate::protocol::{AgentMessage, OutboundCommand};

/// Spawn the IO thread. Returns a receiver for agent messages and a sender for outbound commands.
pub fn spawn_io_thread(
    stream: TcpStream,
) -> (mpsc::Receiver<AgentMessage>, mpsc::Sender<OutboundCommand>) {
    let (agent_tx, agent_rx) = mpsc::channel::<AgentMessage>();
    let (cmd_tx, cmd_rx) = mpsc::channel::<OutboundCommand>();

    let mut read_stream = stream.try_clone().expect("clone TcpStream for reader");
    let mut write_stream = stream;

    // Reader thread: read from TCP, split on \n, deserialize, send to main
    let agent_tx_clone = agent_tx;
    thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        let mut line_buf = Vec::with_capacity(8192);

        loop {
            match read_stream.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    for &byte in &buf[..n] {
                        if byte == b'\n' {
                            if !line_buf.is_empty() {
                                if let Ok(line) = std::str::from_utf8(&line_buf) {
                                    match serde_json::from_str::<AgentMessage>(line) {
                                        Ok(msg) => {
                                            if agent_tx_clone.send(msg).is_err() {
                                                return; // main thread gone
                                            }
                                        }
                                        Err(e) => {
                                            // Route through channel so it appears in the TUI
                                            // log instead of corrupting the terminal via eprintln.
                                            // Truncate the raw line to avoid flooding the log.
                                            let preview: String = line.chars().take(80).collect();
                                            let _ = agent_tx_clone.send(AgentMessage::Error {
                                                msg: format!("[IO] parse error: {} (line: {}...)", e, preview),
                                            });
                                        }
                                    }
                                }
                                line_buf.clear();
                            }
                        } else {
                            line_buf.push(byte);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[IO] read error: {}", e);
                    break;
                }
            }
        }
    });

    // Writer thread: recv commands from main, serialize, write to TCP
    thread::spawn(move || {
        while let Ok(cmd) = cmd_rx.recv() {
            match serde_json::to_string(&cmd) {
                Ok(json) => {
                    let line = format!("{}\n", json);
                    if write_stream.write_all(line.as_bytes()).is_err() {
                        break;
                    }
                    if write_stream.flush().is_err() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("[IO] serialize error: {}", e);
                }
            }
        }
    });

    (agent_rx, cmd_tx)
}
