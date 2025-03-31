use rust_socketio::{ClientBuilder, Payload, RawClient};
use serde_json::json;
use std::fs::{remove_file, File};
use std::{env, fs, process, time};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{sync::{Arc, Mutex}, thread, time::{Duration, Instant}};
use reqwest::header::HeaderValue;
use chrono::{Local, NaiveTime, Utc};
use std::collections::HashMap;
use reqwest::{Client, Method, Error as ReqwestError};
use chrono::{DateTime, TimeZone};
use std::io::{Read, Write}; 
use std::sync::{RwLock};
use lazy_static::lazy_static;
use once_cell::sync::OnceCell;
use std::path::MAIN_SEPARATOR;
use std::fs::OpenOptions;
use rsa::{pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding}, RsaPrivateKey, RsaPublicKey, Oaep};
use rand::rngs::OsRng;
use base64::{encode, decode};
use sha2::Sha256;

const CONFIG_PATH: &str = "/usr/local/bin/secops_config.txt";
const CHECK_INTERVAL: u64 = 30;
const PONG_TIMEOUT: u64 = 30; // Increased timeout to 30 seconds
const VERSION: &str = "1.0.0";


pub struct log_type {
    info: String,
    error: String,
    warning: String,
}


fn generate_key_pair() -> Result<(RsaPrivateKey, RsaPublicKey), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);
    Ok((private_key, public_key))
}

fn encrypt_message(public_key: &RsaPublicKey, message: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let encrypted = public_key.encrypt(&mut rng, Oaep::new::<Sha256>(), message.as_bytes())?;
    Ok(encode(&encrypted))
}

fn decrypt_message(private_key: &RsaPrivateKey, encrypted_message: &str) -> Result<String, Box<dyn std::error::Error>> {
    let encrypted_bytes = decode(encrypted_message)?;
    let decrypted = private_key.decrypt(Oaep::new::<Sha256>(), &encrypted_bytes)?;
    Ok(String::from_utf8(decrypted)?)
}


lazy_static::lazy_static! {

    pub static ref LOG_TYPE: log_type = log_type {
        info: "INFO".to_string(),
        error: "ERROR".to_string(),
        warning: "WARNING".to_string(),
    };

    pub static ref TEMP_DIR: String = if cfg!(target_os = "windows") {
        env::temp_dir().to_string_lossy().to_string()
    } else {
        "/tmp".to_string()
    };

    pub static ref LOCAL_STORAGE: String = if cfg!(target_os = "windows") {
        format!("{}{}secops_cli{}", TEMP_DIR.as_str(), MAIN_SEPARATOR, MAIN_SEPARATOR)
    } else {
        "/etc/secops_cli".to_string()
    };

    pub static ref LOGFILE_PATH: String = if cfg!(target_os = "windows") {
        format!("{}{}log{}secops{}secops_service{}", TEMP_DIR.as_str(), MAIN_SEPARATOR, MAIN_SEPARATOR, MAIN_SEPARATOR, MAIN_SEPARATOR)
    } else {
        "/var/log/secops/secops_service/".to_string()
    };

    pub static ref BINARY_DIRECTORY: String = if cfg!(target_os = "windows") {
        "C:\\Program Files (x86)\\Secops Solution CLI".to_string()
    } else {
        "/usr/local/bin".to_string()
    };

    pub static ref HELPER_PROCESS_NAME: String = if cfg!(target_os = "windows") {
        "secops_uninstaller.exe".to_string()
    } else {
        "secops_uninstaller".to_string()
    };

    pub static ref PREFERENCES_FILE_PATH: String = if cfg!(target_os = "windows") {
        format!("{}{}secops_cli{}", TEMP_DIR.as_str(), MAIN_SEPARATOR, MAIN_SEPARATOR)
    } else {
        "/etc/secops_cli".to_string()
    };

    pub static ref CONFIG_FILE_PATH: String = if cfg!(target_os = "windows") {
        "C:\\Program Files (x86)\\Secops Solution CLI\\secops_config.txt".to_string()
    } else {
        "/usr/local/bin/secops_config.txt".to_string()
    };

    pub static ref SECOPS_SYSTEM_TRAY_BINARY_PATH: String = if cfg!(target_os = "windows") {
        "C:\\Program Files (x86)\\Secops Solution CLI\\secops_system_tray.exe".to_string()
    } else {
        "/usr/local/bin/secops_system_tray".to_string()
    };

    pub static ref INSTALL_DIR: String = if cfg!(target_os = "windows") {
        "C:\\Program Files (x86)\\Secops Solution CLI".to_string()
    } else {
        "/usr/local/bin".to_string()
    };

    pub static ref AGENT_REGISTRATION_MODULE_PATH: String = if cfg!(target_os = "windows") {
        "C:\\Program Files (x86)\\Secops Solution CLI\\secops_agent_registration_module.exe".to_string()
    } else {
        "/usr/local/bin/secops_agent_registration_module".to_string()
    };

    pub static  ref LOGFILE_NAME : String = if cfg!(target_os = "windows") {
        "secops_service.log".to_string()
    } else {
        "secops_service.log".to_string()
    };

}


lazy_static! {
    static ref CONFIG: RwLock<HashMap<String, String>> = RwLock::new(HashMap::new());
}

fn read_config(config_path: &str)  {
    let mut config = HashMap::new();
    config.insert("BASE_URL".to_string(), "https://api.app.secopsolution.com/secops/v1.0/".to_string());
    config.insert("agent_mode".to_string(), "ENDPOINT".to_string());
    config.insert("secops_jump_host".to_string(), "false".to_string());

    if let Ok(contents) = fs::read_to_string(config_path) {
        for line in contents.lines() {
            if let Some((key, value)) = line.split_once('=') {
                config.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    // Store config in global state
    let mut global_config = CONFIG.write().unwrap();
    *global_config = config;
}


// Function to print version
fn print_version() {
    println!("SecOps Agent Version: {}", VERSION);
}

fn get_config_file_path() -> String {
    // Check if it is a windows system or not
    if cfg!(target_os = "windows") {
        // check if this file exists
        if !(fs::read_to_string("C:\\Program Files (x86)\\Secops Solution CLI\\config.txt").is_err()) {
            return "C:\\Program Files (x86)\\Secops Solution CLI\\secops_config.txt".to_string();
        }
        return "C:\\Program Files (x86)\\Secops Solution CLI\\config.txt".to_string();
    } else {
        // check if this file exists
        if !(fs::read_to_string("/usr/local/bin/secops_config.txt").is_err()) {
            return "/usr/local/bin/secops_config.txt".to_string();
        }
        return "/usr/local/bin/config.txt".to_string();
    }
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

#[cfg(target_os = "windows")]
fn is_admin() -> bool {
    true
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



// Mock function for sending public key to backend
fn send_public_key_to_backend(public_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Implement actual backend communication here
    println!("Sending public key to backend: {}", public_key);
    Ok(())
}

fn initiate_local_scan() {
    println!("Initiating local scan");
}

fn get_config_value(key: &str) -> Option<String> {
    let config = CONFIG.read().unwrap();
    config.get(key).cloned() // Return a cloned value
}

fn update_config_value(key: &str, value: &str) {
    let mut config = CONFIG.write().unwrap();
    config.insert(key.to_string(), value.to_string());
}

fn remove_config_sh() {
    if env::consts::OS != "windows" {
        let config_path = "/usr/local/bin/config.sh";
        if fs::metadata(config_path).is_ok() {
            match remove_file(config_path) {
                Ok(_) =>println!("file removed"),
                Err(e) => println!("{}", e)
            }
        }
    }
}

fn prepare_working_dirs() -> bool {
    if let Err(e) = fs::create_dir_all(LOCAL_STORAGE.as_str()) {
        create_log_entry(
            "prepare_working_dirs",
            LOG_TYPE.error.to_string(),
            &format!("Error Creating Working Directories: {}", e)
        );
        return false;
    }

    if let Err(e) = fs::create_dir_all(LOGFILE_PATH.as_str()) {
        create_log_entry(
            "prepare_working_dirs",
            LOG_TYPE.error.to_string(),
            &format!("Error Creating Working Directories: {}", e)
        );
        return false;
    }

    true
}


fn write_logs_to_file(log: &LogEntry) {
    match check_log_file() {
        Some(log_file_path) => {
            let mut file = match OpenOptions::new().append(true).create(true).open(&log_file_path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("\nFailed to open log file: {}\n", e);
                    return;
                }
            };

            let log_entry = format!(
                "[{}] - [{}] - [{}] - {} \n",
                Utc::now().format("%Y-%m-%d %H:%M:%S"), log.log_type, log.function_name, log.message
            );

            if let Err(e) = file.write_all(log_entry.as_bytes()) {
                eprintln!("\nFailed to write logs to file: {}\n", e);
            }
        }
        None => {
            eprintln!("\nFailed to determine log file path\n");
        }
    }
}

// LogEntry struct to store log information

struct LogEntry {
    function_name: String,
    log_type: String,
    message: String,
}


fn create_log_entry(function_name: &str, log_type: String, message: &str) {
    let log_entry = LogEntry {
        function_name: function_name.to_string(),
        log_type: log_type,
        message: message.to_string(),
    };
    write_logs_to_file(&log_entry);
}

// Dummy function to get log file path
fn check_log_file() -> Option<String> {
    // return LOGFILE_PATH.to_string();
    Some(format!("{}{}{}", LOGFILE_PATH.as_str(), MAIN_SEPARATOR, LOGFILE_NAME.as_str()))
}



/******  c97a6765-7c31-485b-a105-8878b1479ae3  *******/fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = get_config_file_path();
    
    println!("Using Config File : {}", config_path);
    read_config(config_path.as_str());

    remove_config_sh();

    prepare_working_dirs();

    create_log_entry("main", LOG_TYPE.info.to_string(), "SecOps Agent Service Started");

    let agent_id = get_config_value("A_ID").expect("Agent ID not found in get_config_value");
    let base_url: String = get_config_value("BASE_URL").unwrap();
    let agent_mode = get_config_value("agent_mode").unwrap();
    let secops_jump_host: bool = get_config_value("secops_jump_host").map_or(false, |v| v == "true");

    if agent_id.is_empty() {
        create_log_entry("main", LOG_TYPE.info.to_string(), "Agent ID not found");
    }

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
        create_log_entry("main", LOG_TYPE.error.to_string(), "Running without admin/root privileges");
        process::exit(1);
    }

    match generate_key_pair() {
        Ok((private_key, public_key)) => {
            println!("Key pair generated successfully");

            fs::write("private_key.pem", private_key.to_pkcs8_pem(LineEnding::LF)?.to_string())
                .expect("Unable to write private key");
            fs::write("public_key.pem", public_key.to_public_key_pem(LineEnding::LF)?)
                .expect("Unable to write public key");

            let message = "Hello, Rust!";
            match encrypt_message(&public_key, message) {
                Ok(encrypted) => {
                    println!("Encrypted: {}", encrypted);
                    match decrypt_message(&private_key, &encrypted) {
                        Ok(decrypted) => println!("Decrypted: {}", decrypted),
                        Err(e) => eprintln!("Decryption failed: {}", e),
                    }
                },
                Err(e) => eprintln!("Encryption failed: {}", e),
            }
        },
        Err(e) => eprintln!("Failed to generate key pair: {}", e),
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

            let scheduled_time = get_config_value("scheduled_time");
            let last_schedule_scan = get_config_value("last_schedule_scan");

            
            // Check scheduled time if applicable
            if let Some(ref sched_time) = scheduled_time{
                if let Ok(sched_time) = chrono::NaiveTime::parse_from_str(&sched_time, "%H:%M:%S") {
                    // convert sched_time to utc
                    let today = Utc::now().date_naive();
                    let sched_datetime = Utc.from_utc_datetime(
                        &today.and_time(sched_time)
                    );
                    let now = Utc::now().time();
                    let todaysDate = Utc::now().date_naive().to_string();  
                    // let todaysDate_reference = todaysDate; 
                    
                    if (last_schedule_scan.is_none() || last_schedule_scan.as_deref() == Some("None") || last_schedule_scan.as_deref() != Some(&todaysDate)) && now >= sched_time {
                        
                        println!("Scheduled scan triggered at {}", now);
                        
                        initiate_local_scan();

                        update_config_value("last_schedule_scan",&todaysDate);
                        let last_schedule_scan = get_config_value("last_schedule_scan");

                        // Traverse through the lines of config file
                        if let Ok(mut file) = File::open(&config_path) {
                            let mut lines = String::new();
                            if let Ok(content) = std::fs::read_to_string(&config_path) {
                                // Split the file content into lines
                                let lines: Vec<String> = content.lines().map(|line| line.to_string()).collect();
                                let mut updated_lines = Vec::new();
                                let mut found = false;
                                
                                // Process each line
                                for line in lines {
                                    if line.starts_with("last_schedule_scan=") && !found {
                                        // Replace only the first occurrence of last_schedule_scan
                                        updated_lines.push(format!("last_schedule_scan={}", last_schedule_scan.clone().unwrap()));
                                        found = true; // Mark that we've replaced it once
                                    } else {
                                        // Keep all other lines unchanged
                                        updated_lines.push(line);
                                    }
                                }
                                
                                // Join the lines back together and write to file
                                let updated_content = updated_lines.join("\n") + "\n"; // Add newline at end
                                if let Err(e) = std::fs::write(&config_path, updated_content) {
                                    eprintln!("Error writing to config file: {}", e);
                                }
                            }
                        }
                    }
                }
            }

            // Increment time and check for ping interval
            time_lapsed += 1;
            
            // Check for pong timeout with precise tracking
            let last_pong = *last_pong_received.lock().unwrap();
            let elapsed_since_pong = last_pong.elapsed().as_secs();
            
            // println!("Elapsed since last pong: {} seconds", elapsed_since_pong);
            
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