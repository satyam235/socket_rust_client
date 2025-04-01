use rust_socketio::{ClientBuilder, Payload, RawClient};
use std::fs::{remove_file, File};
use std::{env, fs, process, time};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{sync::{Arc, Mutex}, thread, time::{Duration, Instant}};
use reqwest::header::HeaderValue;
use chrono::{Local, NaiveTime, Utc};
use std::collections::HashMap;
use chrono::{DateTime, TimeZone};
use std::io::{Read, Write}; 
use std::sync::{RwLock};
use lazy_static::lazy_static;
use once_cell::sync::OnceCell;
use std::path::MAIN_SEPARATOR;
use std::fs::OpenOptions;
use rsa::{RsaPrivateKey, RsaPublicKey, Oaep,pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding}};
// use rsa::oaep::Oaep;
use rand::rngs::OsRng;
use base64::{encode, decode};
use sha2::Sha256;
use reqwest::{blocking::Client, Method, Response, header};
use serde_json::{Value, json};
use std::error::Error;
use rand::thread_rng;

const CONFIG_PATH: &str = "/usr/local/bin/secops_config.txt";
const CHECK_INTERVAL: u64 = 30;
const PONG_TIMEOUT: u64 = 30; // Increased timeout to 30 seconds
const VERSION: &str = "1.0.0";


pub struct log_type {
    info: String,
    error: String,
    warning: String,
}

struct LogEntry {
    function_name: String,
    log_type: String,
    message: String,
}


lazy_static::lazy_static! {

    pub static ref LOG_TYPE: log_type = log_type {
        info: "INFO".to_string(),
        error: "ERROR".to_string(),
        warning: "WARNING".to_string(),
    };

    pub static ref SERVER_SECRET_KEY: String = "1taeEsDrioWlGRPsUT6KITKc/z+Je1WPkC8PBMM3PCE=".to_string();

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
    static ref SERVER_PRIVATE_KEY: Mutex<Option<RsaPrivateKey>> = Mutex::new(None);
    static ref SERVER_PUBLIC_KEY: Mutex<Option<RsaPublicKey>> = Mutex::new(None);
    static ref MAX_NO_OF_KEY_SHARING_ATTEMPTS: Mutex<u32> = Mutex::new(10);
    static ref NO_OF_KEY_SHARING_ATTEMPTS: Mutex<u32> = Mutex::new(0);
}

fn generate_key_pair() -> Result<(RsaPrivateKey, RsaPublicKey), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);
    *SERVER_PRIVATE_KEY.lock().unwrap() = Some(private_key.clone()); // Clone to avoid move
    *SERVER_PUBLIC_KEY.lock().unwrap() = Some(public_key.clone());   // Clone to avoid move
    Ok((private_key, public_key))
}

fn get_public_key_pem() -> Option<String> {
    SERVER_PUBLIC_KEY.lock().unwrap().as_ref().map(|key| {
        key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to encode public key")
    })
}

fn get_private_key_pem() -> Option<String> {
    SERVER_PRIVATE_KEY.lock().unwrap().as_ref().map(|key| {
        key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to encode private key")
            .to_string() // Convert Zeroizing<String> to String
    })
}


fn encrypt_message(message: &str, public_key: &RsaPublicKey) -> Option<String> {
    let mut rng = thread_rng();

    let encrypted_data = public_key.encrypt(
        &mut rng,
        Oaep::new::<Sha256>(), // ✅ Updated syntax
        message.as_bytes(),
    ).ok()?;

    Some(base64::encode(encrypted_data))
}

fn decrypt_message(encrypted_message: &str, private_key: &RsaPrivateKey) -> Option<String> {
    let encrypted_data = base64::decode(encrypted_message).ok()?;
    
    let decrypted_data = private_key.decrypt(
        Oaep::new::<Sha256>(), // ✅ Updated syntax
        &encrypted_data,
    ).ok()?;

    Some(String::from_utf8(decrypted_data).ok()?)
}

/// Function to make an HTTP request with GET or POST method
fn send_request(
    base_url: &str,
    endpoint: &str,
    params: Option<&[(&str, &str)]>,
    payload: Option<&Value>,
    method: Method
) -> Result<Value, Box<dyn Error>> {
    let client = Client::new();
    let full_url = format!("{}{}", base_url, endpoint);
    
    let mut request_builder = client.request(method.clone(), &full_url);

    request_builder = request_builder.header(header::CONTENT_TYPE, "application/json");

    if params.is_none() && payload.is_none() {
        request_builder = request_builder.header(header::CONTENT_TYPE, "application/json");
    }
    
    // if let Some(params) = params {
    //     request_builder = request_builder.query(params);
    // }

    println!("Request URL: {}", full_url);
    println!("Request Method: {}", method);
    println!("Request Payload: {:#?}", payload);
    
    if let Some(payload) = payload {
        let payload_str = serde_json::to_string(payload)?;
        // let body = reqwest::Body::from(payload_str);
        // let payload_str_cloned = payload_str.clone();
        println!("Request Payload string: {}", payload_str);
        request_builder = request_builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(payload_str);  // Convert to bytes explicitly
    }
    let response = request_builder.send()?;
    let status = response.status();
    let response_text = response.text()?;

    if status.is_success() {
        println!("Request successful");
        let json_response: Value = serde_json::from_str(&response_text).unwrap_or(json!({"error": "Invalid JSON response"}));
        Ok(json_response)
    } else {
        println!("Request failed with status: {}", status);
        Err(format!("Request failed with status: {}", status).into())
    }
    
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
            return "C:\\Program Files (x86)\\Secops Solution CLI\\config.txt".to_string();
        }
        return "C:\\Program Files (x86)\\Secops Solution CLI\\secops_config.txt".to_string();
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


fn create_log_entry(function_name: &str, log_type: String, message: &str) {
    let log_entry = LogEntry {
        function_name: function_name.to_string(),
        log_type: log_type.clone(),
        message: message.to_string(),
    };
    write_logs_to_file(&log_entry);

    let endpoint = "agent/logging";
    let agent_id = get_config_value("A_ID").expect("Agent ID not found in get_config_value");
    let base_url = get_config_value("BASE_URL").expect("Base URL not found in get_config_value");

    let log_entry_json = json!({
        "time": Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        "message": message.to_string(),
        "function_name": function_name.to_string(),
        "status": "SUCCESS",
        "log_type": log_type,
        "agent_id": agent_id
    });

    let log_entry_str = serde_json::to_string(&log_entry_json).unwrap();

    let payload_data = json!({
        "log_entry" :  log_entry_str
    });
    let payload = Some(&payload_data);

    match send_request(&base_url, endpoint, None, payload, Method::POST) {
        Ok(response) => println!("Response: {:?}", response),
        Err(e) => eprintln!("Request failed: {}", e),
    }

}

// Dummy function to get log file path
fn check_log_file() -> Option<String> {
    // return LOGFILE_PATH.to_string();
    Some(format!("{}{}{}", LOGFILE_PATH.as_str(), MAIN_SEPARATOR, LOGFILE_NAME.as_str()))
}

fn share_public_key_with_backend() -> Result<(), Box<dyn std::error::Error>> {

    let public_key = get_public_key_pem().expect("Public key not found in get_public_key_pem");
    let agent_id = get_config_value("A_ID").expect("Agent ID not found in get_config_value");
    let base_url = get_config_value("BASE_URL").expect("Base URL not found in get_config_value");
    let endpoint = "agent/share_key";
    let payload_data = json!({
        "public_key" :  public_key,
        "agent_id" : agent_id,
        "secret_key": *SERVER_SECRET_KEY
    });
    let payload = Some(&payload_data);
    match send_request(&base_url, endpoint, None, payload, Method::POST) {
        Ok(response) => {
            println!("Response: {:?}", response);
            Ok(())
        },
        Err(e) => {
            eprintln!("Request failed: {}", e);
            Err(e)
        },
    }
}

fn generate_and_share_server_keys() -> Result<(), Box<dyn std::error::Error>> {
    let mut attempts = NO_OF_KEY_SHARING_ATTEMPTS.lock().unwrap();
    let max_attempts = *MAX_NO_OF_KEY_SHARING_ATTEMPTS.lock().unwrap();

    create_log_entry(
        "generate_and_share_server_keys",
        LOG_TYPE.info.to_string(),
        "Generating and sharing server keys",
    );

    if *attempts >= max_attempts {
        println!("Max key-sharing attempts reached!");
        return Err("Max key-sharing attempts reached!".into());
    }

    *attempts += 1; // Increment attempt count

    // Use a loop to retry instead of recursion
    for _ in 0..max_attempts {
        match generate_key_pair() {
            Ok((private_key, public_key)) => {
                println!("Key pair generated successfully");

                match share_public_key_with_backend() {
                    Ok(_) => {
                        println!("Public key shared successfully");
                        create_log_entry(
                            "generate_and_share_server_keys",
                            LOG_TYPE.info.to_string(),
                            "Public key shared successfully",
                        );
                        return Ok(()); // ✅ Exit function on success
                    }
                    Err(e) => {
                        eprintln!("Failed to share public key: {}", e);
                        create_log_entry(
                            "generate_and_share_server_keys",
                            LOG_TYPE.error.to_string(),
                            &format!("Failed to share public key: {}", e),
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to generate key pair: {}", e);
                create_log_entry(
                    "generate_and_share_server_keys",
                    LOG_TYPE.error.to_string(),
                    &format!("Failed to generate key pair: {}", e),
                );
            }
        }

        // Wait before retrying (optional)
        std::thread::sleep(std::time::Duration::from_secs(10));
    }

    // If max attempts are reached, return error
    Err("Max key-sharing attempts exceeded!".into())
}



fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    generate_and_share_server_keys();

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