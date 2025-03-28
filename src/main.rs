use rust_socketio::{ClientBuilder, Payload, RawClient};
use serde_json::json;
use std::{env, fs, process};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{sync::{Arc, Mutex}, thread, time::{Duration, Instant}};
use reqwest::header::HeaderValue;
use chrono::{Local, NaiveTime, Utc};
use std::collections::HashMap;
use reqwest::{Client, Method, Error as ReqwestError};
use serde_json::Value;
use whoami::username;



const CONFIG_PATH: &str = "/usr/local/bin/secops_config.txt";
const CHECK_INTERVAL: u64 = 30;
const PONG_TIMEOUT: u64 = 30; // Increased timeout to 30 seconds
const VERSION: &str = "1.0.0";

fn read_config() -> HashMap<String, String> {
    let mut config = HashMap::new();
    config.insert("BASE_URL".to_string(), "https://api.app.secopsolution.com/secops/v1.0/".to_string());
    config.insert("agent_mode".to_string(), "ENDPOINT".to_string());
    config.insert("secops_jump_host".to_string(), "false".to_string());

    if let Ok(contents) = fs::read_to_string(CONFIG_PATH) {
        for line in contents.lines() {
            if let Some((key, value)) = line.split_once('=') {
                config.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    config
}


// Function to print version
fn print_version() {
    println!("SecOps Agent Version: {}", VERSION);
}

// Function to check for admin/root privileges
#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    use std::process::Command;

    let output = Command::new("net")
        .args(["session"])
        .output()
        .unwrap_or_else(|_| panic!("Failed to execute command"));

   return  output.status.success()
}

#[cfg(not(target_os = "windows"))]
fn is_elevated() -> bool {
    true // Assume non-Windows platforms have root check handled elsewhere.
}

#[cfg(unix)]
fn is_admin() -> bool {
    use nix::unistd::Uid;

    let current_uid = Uid::current();

    if !current_uid.is_root() {
        return false;
    } else {
        return true
    }


}

// Key pair generation function
use rsa::{
    RsaPrivateKey, 
    RsaPublicKey, 
    pkcs8::{
        EncodePrivateKey, 
        EncodePublicKey
    }
};
use rand::rngs::OsRng;

fn generate_key_pair() -> Result<(RsaPrivateKey, Vec<u8>), Box<dyn std::error::Error>> {
    // Generate a key pair
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);

    // Convert public key to PEM format
    let public_key_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;

    // Optional: Log or send public key to backend
    send_public_key_to_backend(&public_key_pem)?;

    Ok((private_key, public_key_pem.into_bytes()))
}

// Mock function for sending public key to backend
fn send_public_key_to_backend(public_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Implement actual backend communication here
    println!("Sending public key to backend: {}", public_key);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = read_config();
    let agent_id = config.get("A_ID").expect("Agent ID not found in config");
    let base_url = config.get("BASE_URL").unwrap();
    let agent_mode = config.get("agent_mode").unwrap();
    let scheduled_time = config.get("scheduled_time");
    let secops_jump_host: bool = config.get("secops_jump_host").map_or(false, |v| v == "true");

    println!("Agent ID: {}", agent_id);
    println!("Base URL: {}", base_url);
    println!("Agent Mode: {}", agent_mode);
    println!("SecOps Jump Host: {}", secops_jump_host);
    println!("Scheduled Time: {:?}", scheduled_time);

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();

    // Check for version flag
    if args.contains(&"-V".to_string()) || args.contains(&"--version".to_string()) {
        print_version();
        process::exit(0);
    }

    if cfg!(target_os = "windows") {
        if !is_elevated() {
            println!("Please run this program with admin/root privileges");
            // process::exit(1);
        }
    } else {
        if !is_admin() {
            println!("Please run this program with admin/root privileges");
        }
    }

    // Check admin privileges
    if is_admin() {
        println!("Running with admin/root privileges");
    } else {
        println!("Not running with admin/root privileges");
    }

    // Generate key pair
    match generate_key_pair() {
        Ok((private_key, public_key)) => {
            println!("Key pair generated successfully");
            // Optionally save keys to files or use them
            fs::write("private_key.pem", 
                private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap())
                .expect("Unable to write private key");
            fs::write("public_key.pem", public_key)
                .expect("Unable to write public key");
        },
        Err(e) => {
            eprintln!("Failed to generate key pair: {}", e);
            // Retry logic can be implemented here
            std::thread::sleep(std::time::Duration::from_secs(60));
            // Recursive retry or more sophisticated retry mechanism
        }
    }

    loop {
        println!("Config loaded successfully. Agent ID: {}", agent_id);
        
        let url = format!("http://localhost:5678");
        
        // Shared state for connection and last pong
        let connection_successful = Arc::new(AtomicBool::new(false));
        let connection_successful_clone = Arc::clone(&connection_successful);
        
        let last_pong_received = Arc::new(Mutex::new(Instant::now()));
        let last_pong_received_clone = Arc::clone(&last_pong_received);
        
        // Flag to control ping sending
        let can_send_ping = Arc::new(Mutex::new(false));
        let can_send_ping_clone = Arc::clone(&can_send_ping);
        
        let socket = match ClientBuilder::new(&url)
            .namespace("/")
            .reconnect(false)
            .opening_header("agentID", HeaderValue::from_str(&agent_id).unwrap())
            .on("open", move |client, _| {
                connection_successful_clone.store(true, Ordering::Relaxed);
                println!("Connected to server.");
                // Allow ping to be sent
                *can_send_ping_clone.lock().unwrap() = true;
            })
            .on("agent_pong", move |_, _| {
                let mut last_pong = last_pong_received_clone.lock().unwrap();
                *last_pong = Instant::now();
                println!("Agent pong received and timestamp updated to {:?}", last_pong);
            })
            .connect()
        {
            Ok(socket) => socket,
            Err(e) => {
                eprintln!("Failed to connect: {}. Retrying in 10 seconds...", e);
                thread::sleep(Duration::from_secs(10));
                continue;
            }
        };
        
        // Wait for connection to be established
        while !connection_successful.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));
        }

        // Subscribe to room
        if let Err(e) = socket.emit("subscribe", json!({"room": agent_id})) {
            eprintln!("Error subscribing to room: {}", e);
        }

        // Ping management loop
        let mut time_lapsed = 0;
        let mut ping_sent = false;
        loop {
            // Check if we can send ping and it's time to do so
            if time_lapsed >= CHECK_INTERVAL || time_lapsed == 0 {
                time_lapsed = 0;
                
                // Only send ping if allowed and not already sent
                let can_ping = *can_send_ping.lock().unwrap();
                if can_ping && !ping_sent {
                    println!("Sending agent_ping");
                    if let Err(e) = socket.emit("agent_ping", json!({})) {
                        eprintln!("Error sending agent_ping: {}", e);
                    } else {
                        ping_sent = true;
                    }
                }
            }
            
            // Check scheduled time if applicable
            if let Some(ref sched_time) = scheduled_time {
                if let Ok(sched_time) = NaiveTime::parse_from_str(sched_time, "%H:%M:%S") {
                    let now = Utc::now().time();
                    if now >= sched_time {
                        println!("Scheduled scan triggered at {}", now);
                        // Call function to initiate scan
                    }
                }
            }

            // Increment time and check for ping interval
            time_lapsed += 1;
            
            // Check for pong timeout with precise tracking
            let last_pong = *last_pong_received.lock().unwrap();
            let elapsed_since_pong = last_pong.elapsed().as_secs();
            
            println!("Elapsed since last pong: {} seconds", elapsed_since_pong);
            
            if elapsed_since_pong > PONG_TIMEOUT {
                eprintln!("No pong received in {} seconds. Reconnecting...", PONG_TIMEOUT);
                break;
            }

            // Reset ping_sent if pong is received recently
            if ping_sent && elapsed_since_pong < 5 {
                ping_sent = false;
            }

            thread::sleep(Duration::from_secs(1));
        }
    }
}