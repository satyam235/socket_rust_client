use rust_socketio::{event, ClientBuilder, Payload, RawClient};
use serde_json::json;
use std::time::Duration;
use reqwest::header::HeaderValue;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define a callback for receiving messages
    let receive_callback = |payload: Payload, socket: RawClient| {
        match payload {
            Payload::Binary(bin_data) => println!("Received binary: {:#?}", bin_data),
            Payload::Text(text_values) => {
                for value in text_values {
                    println!("Received text: {}", value);
                }
            }
            Payload::String(str_value) => {
                println!("Received string: {}", str_value);
            }
        }
        
        // Example of emitting a response
        if let Err(e) = socket.emit("test", json!({"got ack": true})) {
            eprintln!("Error emitting test event: {}", e);
        }
    };

    // Define an error callback
    let error_callback = |err, _| {
        eprintln!("Socket.IO Error: {:#?}", err);
    };

    print!("Hello, world!");

    let pos_connection_callback = |payload: Payload, socket: RawClient| {

        print!("Connection callback");
        match payload {
            Payload::Text(text_values) => {
                for value in text_values {
                    println!("Received text: {}", value);
                }
            }
            Payload::Binary(bin_data) => println!("Received bytes: {:#?}", bin_data),
            Payload::String(str_value) => {
                println!("Received string: {}", str_value);
            }
        }
    };


    let url = format!("http://localhost:5678");
    let socket = ClientBuilder::new(&url)
        .namespace("/")
        .opening_header("agentID", HeaderValue::from_static("Rustagent1"))
        .on("error", error_callback)
        .on("agent_pong", |_, _| println!("Agent ponged"))
        .on("open", pos_connection_callback)
        .connect()?;

    std::thread::sleep(Duration::from_secs(30));
    // Emit a JSON payload to the "foo" event
    let json_payload = json!({"token": 123});
    // socket.emit("subscribe", json_payload)?;

    socket.emit("subscribe", json!({"room": "Rustagent1"}))?;
    socket.emit("agent_ping", json!({}))?;

    
    // Demonstration of emitting with acknowledgement
    let ack_callback = |message: Payload, _| {
        println!("Acknowledgement received!");
        match message {
            Payload::Text(text_values) => {
                for value in text_values {
                    println!("Ack text data: {}", value);
                }
            }
            Payload::Binary(bin_data) => {
                println!("Binary ack data: {:#?}", bin_data);
            }
            Payload::String(str_value) => {
                println!("String ack data: {}", str_value);
            }
        }
    };

    let ack_payload = json!({"myAckData": 123});
    socket.emit_with_ack(
        "test", 
        ack_payload, 
        Duration::from_secs(2), 
        ack_callback
    )?;

    // Keep the connection alive for a bit
    std::thread::sleep(Duration::from_secs(60));

    // Disconnect
    socket.disconnect()?;

    Ok(())
}