use rsa::pkcs8::der::asn1::Null;
use rust_socketio::{client, ClientBuilder, Payload, RawClient};
use std::fs::{create_dir, create_dir_all, remove_file, File};
use std::{env, fs, process, time};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::{sync::{Arc, Mutex}, thread, time::{Duration, Instant}};
use reqwest::header::HeaderValue;
use chrono::{format, Local, NaiveTime, Utc};
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
use std::path::{Path, PathBuf};
use std::io::{self, BufRead, BufReader};
use regex::Regex;
use std::net::TcpStream;
use std::process::{Command, Stdio};

const CONFIG_PATH: &str = "/usr/local/bin/secops_config.txt";
const CHECK_INTERVAL: u64 = 3;
const PONG_TIMEOUT: u64 = 30;
const VERSION: &str = "V1.0.40";
const AGENT_MODE_ENDPOINT :&str = "ENDPOINT";
const AGENT_MODE_JUMP_HOST :&str = "JUMP_HOST";
const AGENT_MODE :&str = AGENT_MODE_ENDPOINT;
const UBUNTU_18_OS_NAME: &str = "ubuntu-18.04";
const UBUNTU_20_OS_NAME: &str = "ubuntu-20.04";
const UBUNTU_22_OS_NAME: &str = "ubuntu-22.04";

const SECOPS_UBUNTU_18_JUMP_HOST_SERVICE_BINARY_FILE_NAME: &str = "SecOpsJumpHostServiceBinaryUbuntu18";
const SECOPS_UBUNTU_20_JUMP_HOST_SERVICE_BINARY_FILE_NAME: &str = "SecOpsJumpHostServiceBinaryUbuntu20";
const SECOPS_UBUNTU_22_JUMP_HOST_SERVICE_BINARY_FILE_NAME: &str = "SecOpsJumpHostServiceBinaryUbuntu22";

static FAILED_SOCKET_CONNECTION_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
static MAX_FAILED_SOCKET_CONNECTION_ATTEMPTS: AtomicUsize = AtomicUsize::new(30);


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
        "C:\\Windows\\Temp".to_string()
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

    pub static ref SECOPS_BINARY_DIRECTORY: String = if cfg!(target_os = "windows") {
        format!("{}{}{}", TEMP_DIR.as_str(), MAIN_SEPARATOR, "secops")
    } else {
        format!("{}{}{}", TEMP_DIR.as_str(), MAIN_SEPARATOR, "secops")
    };

}


lazy_static! {
    static ref CONFIG: RwLock<HashMap<String, String>> = RwLock::new(HashMap::new());
    static ref SERVER_PRIVATE_KEY: Mutex<Option<RsaPrivateKey>> = Mutex::new(None);
    static ref SERVER_PUBLIC_KEY: Mutex<Option<RsaPublicKey>> = Mutex::new(None);
    static ref MAX_NO_OF_KEY_SHARING_ATTEMPTS: Mutex<u32> = Mutex::new(10);
    static ref NO_OF_KEY_SHARING_ATTEMPTS: Mutex<u32> = Mutex::new(0);
}

struct SecopsLogger;

impl SecopsLogger {
    fn info(&self, message: &str) {
        self.log(LOG_TYPE.info.to_string(), message);
    }

    fn error(&self, message: &str) {
        self.log(LOG_TYPE.error.to_string(), message);
    }

    fn warning(&self, message: &str) {
        self.log(LOG_TYPE.warning.to_string(), message);
    }

    fn log(&self, log_type: String, message: &str) {
        // Get function name from backtrace if needed
        let function_name = "secops_service"; // Default function name
        
        let log_entry = LogEntry {
            function_name: function_name.to_string(),
            log_type: log_type.clone(),
            message: message.to_string(),
        };
        append_logs_to_file(&log_entry);

        let endpoint = "agent/logging";
        let agent_id = match get_config_value("A_ID") {
            Some(id) => id,
            None => {
                eprintln!("Agent ID not found");
                return;
            }
        };
        let base_url = match get_config_value("BASE_URL") {
            Some(url) => url,
            None => {
                eprintln!("Base URL not found");
                return;
            }
        };

        let log_entry_json = json!({
            "time": Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            "message": message.to_string(),
            "function_name": function_name.to_string(),
            "status": "SUCCESS",
            "log_type": log_type,
            "agent_id": agent_id
        });

        let log_entry_str = match serde_json::to_string(&log_entry_json) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to serialize log entry: {}", e);
                return;
            }
        };

        println!("Log: {}: {}", log_type, message);

        let payload_data = json!({
            "log_entry": log_entry_str
        });
        let payload = Some(&payload_data);

        match send_request(&base_url, endpoint, None, payload, Method::POST) {
            Ok(_) => (),
            Err(e) => eprintln!("Failed to send log to server: {}", e),
        }
    }
}

// Create a global instance
lazy_static! {
    static ref secops_logger: SecopsLogger = SecopsLogger {};
}

fn escape_ansi(line: &str) -> String {
    lazy_static::lazy_static! {
        static ref ANSI_ESCAPE: Regex = Regex::new(r"(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]").unwrap();
    }
    
    ANSI_ESCAPE.replace_all(line, "").to_string()
}

fn check_binary() -> Result<PathBuf, bool> {
    secops_logger.info("Entering check_binary");
    if env::consts::OS == "windows" {
        let binary_path = Path::new(BINARY_DIRECTORY.as_str()).join("secops_cli_windows-latest.exe");
        
        // check if binary exists
        if !binary_path.exists() {
            secops_logger.warning(&format!("Agent Binary not found: {}", binary_path.display()));
            download_secops_agent_binary("secops_cli_windows-latest.exe",TEMP_DIR.as_str(),false);
            if !binary_path.exists() {
                secops_logger.error(&format!("Agent Binary not found after download: {}", binary_path.display()));
                return Err(false);
            }
        }
        secops_logger.info(&format!("Using agent binary: {}", binary_path.display()));
        secops_logger.info("Exiting check_binary");
        Ok(binary_path)
    } else {
        let dir_files = match fs::read_dir(BINARY_DIRECTORY.as_str()) {
            Ok(entries) => {
                entries
                    .filter_map(|entry| entry.ok())
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .collect::<Vec<String>>()
            }
            Err(_) => return Err(false),
        };
        if dir_files.is_empty() {
            secops_logger.error("No binaries found in directory");
            return Err(false);
        }
        let binary_name = if dir_files.contains(&"secops_cli_ubuntu-20.04".to_string()) {
            "secops_cli_ubuntu-20.04"
        } else if dir_files.contains(&"secops_cli_ubuntu-18.04".to_string()) {
            "secops_cli_ubuntu-18.04"
        } else if dir_files.contains(&"secops_cli_ubuntu-22.04".to_string()) {
            "secops_cli_ubuntu-22.04"
        } else if dir_files.contains(&"secops_cli_amazon_linux-2023".to_string()) {
              "secops_cli_amazon_linux-2023"
        } else if dir_files.contains(&"secops_cli_rocky_linux".to_string()) {
            "secops_cli_rocky_linux"
        } else if dir_files.contains(&"secops_cli_centos_7".to_string()) {
            "secops_cli_centos_7"
        } else if dir_files.contains(&"secops_cli_centos_8".to_string()) {
            "secops_cli_centos_8"
        } else if dir_files.contains(&"secops_cli_macos_arm64".to_string()) {
             "secops_cli_macos_arm64"
        } else if dir_files.contains(&"secops_cli_macos_x86_64".to_string()) {
           "secops_cli_macos_x86_64"
        } else {
            secops_logger.error("No matching binary name found");
            return Err(false);
        };
        
        let binary_path = Path::new(BINARY_DIRECTORY.as_str()).join(binary_name.to_string());
        secops_logger.info(&format!("Using agent binary: {}", binary_path.display()));
        secops_logger.info("Exiting check_binary");
        Ok(binary_path)
    }
}

fn check_health() -> HashMap<String, String> {
    secops_logger.info("Entering check_health");
    let fail_return: HashMap<String, String> = [
        ("status".to_string(), "FAIL".to_string()),
        ("message".to_string(), "Binary not found".to_string()),
    ].iter().cloned().collect();

    // Try-catch equivalent in Rust with Result handling
    match (|| -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        let binary_path = check_binary().map_err(|_| "Binary check failed")?;
        
        let cli_process = Command::new(binary_path)
            .arg("-V")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        
        let mut output = Vec::new();
        
        if let Some(stdout) = cli_process.stdout {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line)?;
            
            if bytes_read == 0 {
                secops_logger.warning("No output from CLI process");
                return Ok(fail_return);
            }
            
            line = line.trim().to_string();
            line = escape_ansi(&line);
            
            if line.contains("V") && line.contains(".") {
                output.push(line.clone());
                secops_logger.info(&line);
            }
        } else {
            secops_logger.error("No stdout from CLI process");
            return Ok(fail_return);
        }
        
        let res = if !output.is_empty() {
            [
                ("version".to_string(), output.join("")),
                ("status".to_string(), "SUCCESS".to_string()),
            ].iter().cloned().collect()
        } else {
            [
                ("version".to_string(), "Not Found".to_string()),
                ("status".to_string(), "FAIL".to_string()),
            ].iter().cloned().collect()
        };
        
        Ok(res)
    })() {
        Ok(result) => {
            secops_logger.info("Exiting check_health successfully");
            result
        },
        Err(ex) => {
            let err = "Exception Occurred while checking the health of the service";
            secops_logger.error(&format!("{}{}", err, ex));
            [
                ("status".to_string(), "FAIL".to_string()),
                ("message".to_string(), err.to_string()),
            ].iter().cloned().collect()
        }
    }
}

fn check_agent_health() ->  Result<(), Box<dyn std::error::Error>> {
    let health_check_response = check_health();
    let agent_id = match get_config_value("A_ID") {
        Some(id) => id,
        None => {
            secops_logger.error("Agent ID not found in get_config_value");
            return Err("Agent ID not found".into());
        }
    };
    let base_url = match get_config_value("BASE_URL") {
        Some(url) => url,
        None => {
            secops_logger.error("Base URL not found in get_config_value");
            return Err("Base URL not found".into());
        }
    };
    let end_point = "agent/health_check_upload";
    let url = format!("{}{}", base_url, end_point);

    let json_payload = json!({
        "agent_id": agent_id,
        "version": health_check_response.get("version").map(|v| Value::String(v.clone())).unwrap_or(Value::String("Unknown".to_string())),
        "server_version": VERSION,
        "status": health_check_response
    });
    let payload = Some(&json_payload);

    match send_request(base_url.as_str(), end_point, None, payload, Method::POST) {
        Ok(response) => {
            secops_logger.info("Agent health check uploaded successfully");
            Ok(())
        },
        Err(e) => {
            secops_logger.error(&format!("Agent health check failed: {}", e));
            eprintln!("Request failed: {}", e);
            Err(e)
        }
        
    }

}

fn check_jwt_status(jwt_token: String) ->  bool {
   
    let agent_id = match get_config_value("A_ID") {
        Some(id) => id,
        None => {
            secops_logger.error("Agent ID not found in get_config_value");
            return false;
        }
    };
    let base_url = match get_config_value("BASE_URL") {
        Some(url) => url,
        None => {
            secops_logger.error("Base URL not found in get_config_value");
            return false;
        }
    };
    let end_point = "agent/validate_jwt";
    let url = format!("{}{}", base_url, end_point);

    if jwt_token.is_empty() {
        secops_logger.error("No JWT token found");
        return false
    } else {
        
        let client = Client::new();
        let full_url = format!("{}{}", base_url, end_point);
    
        let mut request_builder = client.request(Method::GET, &full_url);

        request_builder = match HeaderValue::from_str(&format!("Bearer {}", jwt_token)) {
            Ok(header_val) => request_builder.header(header::AUTHORIZATION, header_val),
            Err(e) => {
                secops_logger.error(&format!("Invalid AUTHORIZATION header: {}", e));
                return false;
            }
        };
    
        let response = match request_builder.send() {
            Ok(resp) => resp,
            Err(e) => {
                secops_logger.error(&format!("Failed to send JWT validation request: {}", e));
                return false;
            }
        };
        let status = response.status();
        let response_text = match response.text() {
            Ok(text) => text,
            Err(e) => {
                secops_logger.error(&format!("Failed to read JWT validation response: {}", e));
                return false;
            }
        };

        if status.is_success() {
            let json_response: Value = serde_json::from_str(&response_text).unwrap_or(json!({"error": "Invalid JSON response"}));

            if let Some(success) = json_response.get("success") {
                if success.as_bool().unwrap_or(false) {
                    secops_logger.info("JWT validation successful");
                    return true
                } else {
                    secops_logger.error( &format!("JWT validation failed: {}", json_response.get("error").unwrap()));
                    return false
                }
            } else {
                secops_logger.error( &format!("JWT validation failed: {}", json_response.get("error").unwrap()));
                return false
            }
        } else {
            println!("Request failed with status: {} url : {}", status,full_url);
            secops_logger.error( &format!("JWT validation failed: {}", response_text));
            return false
        }
    }
    

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
        match key.to_public_key_pem(rsa::pkcs8::LineEnding::LF) {
            Ok(pem) => pem,
            Err(e) => {
                secops_logger.error(&format!("Failed to encode public key: {}", e));
                return String::new();
            }
        }
    })
}

fn get_private_key_pem() -> Option<String> {
    SERVER_PRIVATE_KEY.lock().unwrap().as_ref().map(|key| {
        match key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF) {
            Ok(pem) => pem.to_string(),
            Err(e) => {
                secops_logger.error(&format!("Failed to encode private key: {}", e));
                return String::new();
            }
        }
    })
}

fn decrypt_message(encrypted_message: &str) -> String {
    let private_key_guard = SERVER_PRIVATE_KEY.lock().unwrap(); // Store MutexGuard

    let private_key = match private_key_guard.as_ref() {
        Some(key) => key,
        None => {
            secops_logger.error("Error: Private key not found");
            return "Error: Private key not found".to_string();
        }
    };

    let encrypted_message = encrypted_message.trim().trim_matches('"');

    println!("Attempting to decode Base64: {}", encrypted_message);

    let encrypted_data = match base64::decode(encrypted_message.trim()) {
        Ok(data) => data,
        Err(e) => {
            secops_logger.error(&format!("Error: Failed to decode Base64 -> {}", e));
            return "".to_string();
        }
    };

    let decrypted_data = match private_key.decrypt(Oaep::new::<Sha256>(), &encrypted_data) {
        Ok(data) => data,
        Err(_) => {
            secops_logger.error("Error: Decryption failed");
            return "".to_string();
        }
    };

    match String::from_utf8(decrypted_data) {
        Ok(decoded_str) => decoded_str,
        Err(_) => {
            secops_logger.error("Error: Failed to convert decrypted data to UTF-8");
            return "".to_string();
        }
    }
}


/// Function to make an HTTP request with GET or POST method
fn send_request(base_url: &str, endpoint: &str, params: Option<&[(&str, &str)]>, payload: Option<&Value>, method: Method) -> Result<Value, Box<dyn Error>> {
    let client = Client::new();
    let full_url = format!("{}{}", base_url, endpoint);
    
    let mut request_builder = client.request(method.clone(), &full_url);

    request_builder = request_builder.header(header::CONTENT_TYPE, "application/json");

    if params.is_none() && payload.is_none() {
        request_builder = request_builder.header(header::CONTENT_TYPE, "application/json");
    }
    
    if let Some(payload) = payload {
        let payload_str = match serde_json::to_string(payload) {
            Ok(s) => s,
            Err(e) => {
                secops_logger.error(&format!("Failed to serialize payload: {}", e));
                return Err(e.into());
            }
        };
        request_builder = request_builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(payload_str);  // Convert to bytes explicitly
    }
    let response = request_builder.send()?;
    let status = response.status();
    let response_text = response.text()?;

    if status.is_success() {
        let json_response: Value = serde_json::from_str(&response_text).unwrap_or(json!({"error": "Invalid JSON response"}));
        Ok(json_response)
    } else {
        println!("Request failed with status: {} url : {}", status,full_url);
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
fn print_server_version() {
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

fn initiate_local_vulnerability_scan() {

    let task = json!({
        "operation": "local_scan",
        "ip_address":"127.0.0.1",
        "jwt_token": "NO_JWT",
        "scan_profile":"Full Scan",
        "scan_type": "local_scan",
        "user_email": "",
        "full_scan": true
    });
    
    secops_logger.info("Initiating local vulnerability scan");
    let cli_command_json = serde_json::to_value(task).unwrap();
    run_task(cli_command_json);

}

fn initiate_local_patch_scan() {
    let task = json!({
        "operation": "local_patch_scan",
        "ip_address":"127.0.0.1",
        "jwt_token": "NO_JWT",
        "scan_profile":"Full Scan",
        "scan_type": "local_patch_scan",
        "user_email": "",
        "full_scan": true
    });
    secops_logger.info("Initiating local patch scan");
    let cli_command_json = serde_json::to_value(task).unwrap();
    run_task(cli_command_json);
}

fn get_config_value(key: &str) -> Option<String> {
    let config = CONFIG.read().unwrap();
    config.get(key).cloned() // Return a cloned value
}

fn set_config_value(key: &str, value: &str) {
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
    secops_logger.info("Preparing working directories");
    let dir_list = vec![
        LOCAL_STORAGE.as_str(),
        SECOPS_BINARY_DIRECTORY.as_str(),
        LOGFILE_PATH.as_str(),
    ];

    for dir in dir_list {
        if !Path::new(dir).exists() {
            if let Err(e) = create_dir_all(dir) {
                secops_logger.error(&format!("Failed to create directory {}: {}", dir, e));
                return false;
            } else {
                secops_logger.info(&format!("Created directory: {}", dir));
            }
        } else {
            secops_logger.info(&format!("Directory already exists: {}", dir));
        }
    }
    secops_logger.info("Working directories ready");
    true
}

fn append_logs_to_file(log: &LogEntry) {
    println!("Log: {}: {}", log.log_type, log.message);
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

fn check_log_file() -> Option<String> {
    Some(format!("{}{}{}", LOGFILE_PATH.as_str(), MAIN_SEPARATOR, LOGFILE_NAME.as_str()))
}

fn share_public_key_with_backend() -> Result<(), Box<dyn std::error::Error>> {

    let public_key = match get_public_key_pem() {
        Some(pk) if !pk.is_empty() => pk,
        _ => {
            secops_logger.error("Public key not found in get_public_key_pem");
            return Err("Public key not found".into());
        }
    };
    let agent_id = match get_config_value("A_ID") {
        Some(id) => id,
        None => {
            secops_logger.error("Agent ID not found in get_config_value");
            return Err("Agent ID not found".into());
        }
    };
    let base_url = match get_config_value("BASE_URL") {
        Some(url) => url,
        None => {
            secops_logger.error("Base URL not found in get_config_value");
            return Err("Base URL not found".into());
        }
    };
    let endpoint = "agent/share_key";
    let payload_data = json!({
        "public_key" :  public_key,
        "agent_id" : agent_id,
        "secret_key": *SERVER_SECRET_KEY
    });
    let payload = Some(&payload_data);
    match send_request(&base_url, endpoint, None, payload, Method::POST) {
        Ok(response) => {
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

    secops_logger.info("Generating and sharing server keys");

    if *attempts >= max_attempts {
        println!("Max key-sharing attempts reached!");
        return Err("Max key-sharing attempts reached!".into());
    }

    *attempts += 1; // Increment attempt count

    // Use a loop to retry instead of recursion
    for _ in 0..max_attempts {
        match generate_key_pair() {
            Ok((private_key, public_key)) => {

                secops_logger.info("Key generated sucessfully, attempting to share with backend");

                match share_public_key_with_backend() {
                    Ok(_) => {
                        secops_logger.info("Key shared successfully with backend");
                        return Ok(()); // ✅ Exit function on success
                    }
                    Err(e) => {
                        secops_logger.error(&format!("Failed to share public key with the backend: {}", e));
                    }
                }
            }
            Err(e) => {
                secops_logger.error(&format!("Failed to generate key pair: {}", e));
            }
        }

        // Wait before retrying (optional)
        std::thread::sleep(std::time::Duration::from_secs(10));
    }

    // If max attempts are reached, return error
    Err("Max key-sharing attempts exceeded!".into())
}

fn schedule_local_agent_scan(scheduled_time: &str) {
    let mut lines = Vec::new();
    let mut scheduled_time_exist_flag = false;

    let config_file_path = get_config_file_path();

    secops_logger.info(&format!("Attempting to set schedule scan for agent at {}", scheduled_time));
    
    // Read the config file if it exists
    if Path::new(&config_file_path).exists() {
        if let Ok(file) = File::open(config_file_path) {
            for line in io::BufReader::new(file).lines() {
                if let Ok(mut line) = line {
                    if line.starts_with("scheduled_time=") {
                        line = format!("scheduled_time={}", scheduled_time);
                        scheduled_time_exist_flag = true;
                    } else if scheduled_time_exist_flag && line.starts_with("last_schedule_scan=") {
                        line = "last_schedule_scan=None".to_string();
                    }
                    lines.push(line);
                }
            }
        }
    }

    let config_file_path = get_config_file_path();
    
    // Write back the modified content
    if scheduled_time_exist_flag {
        if let Ok(mut file) = File::create(config_file_path.clone()) {
            for line in &lines {
                writeln!(file, "{}", line).unwrap();
            }
        }
    } else {
        let mut file = OpenOptions::new().append(true).create(true).open(&config_file_path).unwrap();
        writeln!(file, "scheduled_time={}", scheduled_time).unwrap();
        writeln!(file, "last_schedule_scan=None").unwrap();
    }
    
    unsafe {
        set_config_value("scheduled_time", scheduled_time);
        set_config_value("last_schedule_scan", "None");
    }
    
    secops_logger.info("Local scan scheduled successfully");
    acknowledge_agent_configuration_setup_status("schedule_scan");
    secops_logger.info("Acknowledged agent configuration setup status for schedule_scan");
}

fn acknowledge_agent_configuration_setup_status(config_param: &str) {
    let base_url: String = match get_config_value("BASE_URL") {
        Some(url) => url,
        None => {
            secops_logger.error("BASE_URL not found in config");
            return;
        }
    };
    let payload_data = json!({
        "config_param": config_param,
        "agent_id": match get_config_value("A_ID") {
            Some(id) => id,
            None => {
                secops_logger.error("A_ID not found in config");
                return;
            }
        }
    });
    let payload = Some(&payload_data);

    match send_request(&base_url, "agent/acknowledge_configuration_setup", None, payload, Method::POST) {
        Ok(response) => {
            secops_logger.info("Configuration setup status acknowledged");
        },
        Err(e) => {
            secops_logger.error(&format!("Failed to acknowledge configuration setup status: {}", e));
        },
    }
}

fn set_agent_mode(agent_mode: &str) {
    let mut lines = Vec::new();
    let mut agent_mode_exist_flag = false;

    let config_file_path = get_config_file_path();
    
    if Path::new(&config_file_path).exists() {
        if let Ok(file) = File::open(config_file_path) {
            for line in io::BufReader::new(file).lines() {
                if let Ok(mut line) = line {
                    if line.starts_with("agent_mode=") {
                        line = format!("agent_mode={}", agent_mode);
                        agent_mode_exist_flag = true;
                    }
                    lines.push(line);
                }
            }
        }
    }
    
    let config_file_path = get_config_file_path();
    if agent_mode_exist_flag {
        if let Ok(mut file) = File::create(config_file_path) {
            for line in &lines {
                writeln!(file, "{}", line).unwrap();
            }
        }
    } else {
        let mut file = OpenOptions::new().append(true).create(true).open(&config_file_path).unwrap();
        writeln!(file, "agent_mode={}", agent_mode).unwrap();
    }
    
   set_config_value("agent_mode", agent_mode);
    
    if agent_mode == AGENT_MODE_JUMP_HOST {
        if !is_secops_file_transfer_service_running() {
            secops_logger.info("Attempting to run SecOps jump host service");
            initiate_secops_jump_host_service();
        } else {
            secops_logger.info("SecOps jump host service already running, no need to start it");
        }
    } else {
        if cfg!(unix) {
            if is_secops_file_transfer_service_running() {
                stop_secops_jump_host_service();
            }
        }
    }
    
    secops_logger.info("Agent mode configured successfully.");
    acknowledge_agent_configuration_setup_status("agent_mode");
}

fn get_jump_host_binary_file_name() -> Option<String> {

    return Some("SecOpsJumpHostLinuxBinary".to_string());

    // let ubuntu_cli_name_list: HashMap<&str, &str> = HashMap::from([
    //     (UBUNTU_18_OS_NAME, SECOPS_UBUNTU_18_JUMP_HOST_SERVICE_BINARY_FILE_NAME),
    //     (UBUNTU_20_OS_NAME, SECOPS_UBUNTU_20_JUMP_HOST_SERVICE_BINARY_FILE_NAME),
    //     (UBUNTU_22_OS_NAME, SECOPS_UBUNTU_22_JUMP_HOST_SERVICE_BINARY_FILE_NAME),
    // ]);

    // let current_dir = INSTALL_DIR.as_str();

    // if let Ok(entries) = fs::read_dir(current_dir) {
    //     for entry in entries.flatten() {
    //         if let Some(file_name) = entry.file_name().to_str() {
    //             for (cli_name, binary_name) in &ubuntu_cli_name_list {
    //                 if file_name.contains(cli_name) {
    //                     return Some(binary_name.to_string());
    //                 }
    //             }
    //         }
    //     }
    // }

    // None
}

fn download_secops_agent_binary(filename :&str,download_folder:&str,run_chmod:bool) {
    let agent_id = get_config_value("A_ID");
    let base_url = match get_config_value("BASE_URL") {
        Some(url) => url,
        None => {
            secops_logger.error("BASE_URL not found in get_config_value");
            return;
        }
    };
    let endpoint_url = "utility/download_agent_file";

    let file_download_path = format!("{}{}{}",download_folder,MAIN_SEPARATOR,filename);
    let json_payload = json!({
        "agent_id": agent_id,
        "file_name": filename
    });
    let payload: Option<&Value> = Some(&json_payload);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("Content-Type", match "application/json".parse() {
        Ok(val) => val,
        Err(e) => {
            secops_logger.error(&format!("Failed to parse header: {}", e));
            return;
        }
    });

    secops_logger.info(&format!("Attempting to download binary: {}", filename));

    // make the request and download the file

    let secops_path = Path::new(SECOPS_BINARY_DIRECTORY.as_str());

    if !secops_path.is_dir() {
        if secops_path.exists() {
            secops_logger.info(&format!("A file named {} exists, attempting to remove it", *SECOPS_BINARY_DIRECTORY));

            if let Err(ex) = fs::remove_file(secops_path) {
                secops_logger.info( &format!("Error removing file {}: {}", *SECOPS_BINARY_DIRECTORY, ex));
            }
        }

        secops_logger.info(&format!("Creating working directory {}", *SECOPS_BINARY_DIRECTORY));
        
        if let Err(ex) = fs::create_dir_all(secops_path) {
            secops_logger.info( &format!("Error creating working directory {}. Exception: {}", *SECOPS_BINARY_DIRECTORY, ex));
        } else {
            secops_logger.info(&format!("Created working directory {}", *SECOPS_BINARY_DIRECTORY));
        }
    }

    let client = Client::new();
    let full_url = format!("{}{}", base_url, endpoint_url);
    
    let mut request_builder = client.request(Method::POST, full_url.clone());

    request_builder = request_builder.header(header::CONTENT_TYPE, "application/json");
    
    if let Some(payload) = payload {
        let payload_str = match serde_json::to_string(payload) {
            Ok(s) => s,
            Err(e) => {
                secops_logger.error(&format!("Failed to serialize payload: {}", e));
                return;
            }
        };
        request_builder = request_builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(payload_str);  // Convert to bytes explicitly
    }
    let mut response = match request_builder.send() {
        Ok(resp) => resp,
        Err(e) => {
            secops_logger.error(&format!("Failed to send download request: {}", e));
            return;
        }
    };
    let status = response.status();
    if status.is_success() {
        let mut file = match File::create(file_download_path.clone()) {
            Ok(f) => f,
            Err(e) => {
                secops_logger.error(&format!("Failed to create file: {}", e));
                return;
            }
        };
        if let Err(e) = response.copy_to(&mut file) {
            secops_logger.error(&format!("Failed to write downloaded file: {}", e));
            return;
        }
        if run_chmod {
            let chmod_command = format!("chmod +x {}", file_download_path);
            let chmod_output = match Command::new("bash")
                .arg("-c")
                .arg(chmod_command)
                .output() {
                    Ok(output) => output,
                    Err(e) => {
                        secops_logger.error(&format!("Failed to run chmod command: {}", e));
                        return;
                    }
            };
            if chmod_output.status.success() {
                println!("Chmod command executed successfully");
            } else {
                println!("Chmod command failed with status: {}", chmod_output.status);
            }
        }
        println!("File downloaded successfully to {}", file_download_path);
        secops_logger.info(&format!("File downloaded successfully to {}", file_download_path));
    } else {
        println!("Request failed with status: {} url : {}", status,full_url);
        secops_logger.error(&format!("Request failed with status: {} url : {}", status,full_url));
    }
}

fn initiate_secops_jump_host_service() {
    let local_working_dir = format!("{}{}{}",TEMP_DIR.to_string(),MAIN_SEPARATOR,"secops");
    // check if this dir exists or not if not create it
    if !Path::new(&local_working_dir).exists() {
        create_dir(&local_working_dir);
    }
    
    secops_logger.info("Attempting to run SecOps jump host service");

    match get_jump_host_binary_file_name() {
        Some(binary) => {
            let binary_full_path = format!("{}{}{}",local_working_dir,MAIN_SEPARATOR,binary);

            secops_logger.info(&format!("Checking if binary {} exists",binary_full_path));

            // check if this file exists or not if download it
            if !Path::new(&binary_full_path).exists() {
                secops_logger.info(&format!("Binary {} not found, downloading it",binary_full_path));
                download_secops_agent_binary(&binary,&local_working_dir,true);
            } else {
                secops_logger.info(&format!("Binary {} found, skipping download",binary_full_path));
            }
            
            let command_str = format!("cd {} && ./{} &",local_working_dir,binary);
            match Command::new("bash")
                .arg("-c")
                .arg(command_str)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn() {
                    Ok(_) => {
                        secops_logger.info("SecOps Jump Host service started in the background.");
                    },
                    Err(e) => {
                        secops_logger.error(&format!("SecOps Jump Host service failed to start: {}", e));
                    }
            };
            
        },
        None => secops_logger.error("Unable to find SecOps Jump host binary"),
    }


}

fn stop_secops_jump_host_service() {
    let command = "if pgrep -f SecOpsJumpHostServiceBinary; then pgrep -f SecOpsJumpHostServiceBinary | xargs kill -9; fi";
    if let Err(err) = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        secops_logger.error(&format!("Error while stopping SecOps service: {:?}", err));
    }
}

fn is_secops_file_transfer_service_running() -> bool {
    let host = "127.0.0.1";
    let port = 5679;
    match TcpStream::connect((host, port)) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn run_task(task_json:Value)  {
    secops_logger.info("Entering run_task");
    let agent_id = match get_config_value("A_ID") {
        Some(id) => id,
        None => {
            secops_logger.error("Agent ID not found in get_config_value");
            return;
        }
    };
    let base_url = match get_config_value("BASE_URL") {
        Some(url) => url,
        None => {
            secops_logger.error("Base URL not found in get_config_value");
            return;
        }
    };
    let cli_binary_path = match check_binary() {
        Ok(path) => path,
        Err(_) => {
            secops_logger.error("Binary not found in check_binary");
            return;
        }
    };

    secops_logger.info(&format!("Attempting to run task using : {}", cli_binary_path.display()));

    secops_logger.info(&format!("Task JSON: {:?}", task_json));

    let operation = task_json["operation"].as_str().unwrap_or("").to_string();

    if operation.is_empty() {
        secops_logger.error("No Operation Specified");
        secops_logger.info("Exiting run_task early due to missing operation");
        return;
    }

    if operation == "schedule_local_scan"{
        let schedule_time = task_json["scheduled_time"].as_str().unwrap_or("None").to_string();
        if schedule_time.is_empty() {
            secops_logger.error("No Schedule Time Specified");
            return;
        }
        schedule_local_agent_scan(&schedule_time);
        secops_logger.info("Exiting run_task after schedule_local_scan");
        return;
    }

    if operation == "set_agent_mode" {
        let agent_mode = task_json["agent_mode"].as_str().unwrap_or("").to_string();
        if agent_mode.is_empty() {
            secops_logger.error( "No Agent Mode Specified");
            return;
        }
        set_agent_mode(&agent_mode);
        secops_logger.info("Exiting run_task after set_agent_mode");
        return;
    }

    secops_logger.info(&format!("Attempting to run operation : {} task_config:{:?}", operation, task_json));

    let mut argument_dict: HashMap<String, Value> = HashMap::new();
    argument_dict.insert(operation.to_string(), task_json);
    argument_dict
        .entry(operation.to_string())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .unwrap()
        .insert("Agent_ID".to_string(), Value::String(agent_id.to_string()));

    let current_timestamp = Local::now().format("%Y%m%d_%H%M%S_%3f").to_string();

    // check if secops_binary_config is in the argument_dict[operation]
    if argument_dict.get(&operation).unwrap().get("secops_binary_config").is_some() {

        
        let temp_dir = format!("{}", SECOPS_BINARY_DIRECTORY.as_str());

        // Ensure secops directory exists
        if !Path::new(&temp_dir).exists() {
            fs::create_dir_all(&temp_dir).expect("Failed to create secops directory");
        }

        let secops_binary_config_file_path = if operation == "config_audit_scan" {
            Path::new(&temp_dir).join(format!("SecOpsConfigAuditBinaryConfig_{}.json", current_timestamp))
        } else {
            Path::new(&temp_dir).join(format!("SecOpsPatchBinaryConfig_{}.json", current_timestamp))
        };

        if let Some(secops_binary_config) = argument_dict.get_mut(&operation) {
            if let Some(secops_binary_config_value) = secops_binary_config.get("secops_binary_config") {
                if let Some(secops_binary_config_str) = secops_binary_config_value.as_str() {
                    
                    let secops_binary_config_json: Value =
                        serde_json::from_str(secops_binary_config_str).unwrap();

                    let mut file =
                        File::create(&secops_binary_config_file_path).expect("Failed to create file");
                    
                    file.write_all(
                        serde_json::to_string_pretty(&secops_binary_config_json)
                            .unwrap()
                            .as_bytes(),
                    ).expect("Failed to write to file");

                    // Update argument_dict with file path
                    secops_binary_config.as_object_mut().unwrap().insert(
                        "secops_binary_config_file_path".to_string(),
                        Value::String(secops_binary_config_file_path.to_string_lossy().into_owned()),
                    );

                    secops_binary_config.as_object_mut().unwrap().remove("secops_binary_config");
                    argument_dict
                        .entry(operation.to_string())
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                        .unwrap()
                        .insert("secops_binary_config_file_path".to_string(), Value::String(secops_binary_config_file_path.to_string_lossy().into_owned()));
                }
            }
        }

    }

    let argument_dict_str = match serde_json::to_string(&argument_dict) {
        Ok(s) => s,
        Err(e) => {
            secops_logger.error(&format!("Failed to serialize argument_dict: {}", e));
            return;
        }
    };

    // write this json to a file
    // check if it is windows or not
    let task_config_path = if cfg!(target_os = "windows") {
        format!("{}\\task_config_{}.json", SECOPS_BINARY_DIRECTORY.as_str(), current_timestamp)
    } else {
        format!("{}/task_config_{}.json", SECOPS_BINARY_DIRECTORY.as_str(), current_timestamp)
    };
    

    let mut file = match File::create(task_config_path.clone()) {
        Ok(f) => f,
        Err(e) => {
            secops_logger.error(&format!("Failed to create task config file: {}", e));
            return;
        }
    };
    if let Err(e) = file.write_all(argument_dict_str.as_bytes()) {
        secops_logger.error(&format!("Failed to write to task_config.json: {}", e));
        return;
    }
    
    secops_logger.info(&format!("Task config file created at: {}", task_config_path));
    let mut command_args = vec!["-configPath", &task_config_path];


    // Spawn the process
    let _cli_process = match Command::new(cli_binary_path)
        .args(command_args)
        .stdout(Stdio::null())  // Do not capture stdout
        .stderr(Stdio::null())  // Do not capture stderr
        .spawn()  // Start the process and return immediately
    {
        Ok(proc) => proc,
        Err(e) => {
            secops_logger.error(&format!("Failed to start process: {}", e));
            return;
        }
    };

    // Handle the spawned process (e.g., read output)
    secops_logger.info("Task started successfully");
    secops_logger.info("Exiting run_task");
}

fn check_secops_uninstaller_binary_exists() -> bool {
    let secops_helper_path = format!("{}/{}", *SECOPS_BINARY_DIRECTORY, *HELPER_PROCESS_NAME);
    let binary_helper_path = format!("{}/{}", *BINARY_DIRECTORY, *HELPER_PROCESS_NAME);

    // Check if the file exists in SECOPS_BINARY_DIRECTORY
    if Path::new(&secops_helper_path).exists() {
        return true;
    }

    // If not found, check in BINARY_DIRECTORY and copy if exists
    if Path::new(&binary_helper_path).exists() {
        if let Err(e) = fs::copy(&binary_helper_path, &secops_helper_path) {
            eprintln!("Error copying file: {}", e);
            return false;
        }
        return true;
    }

    false
}

fn uninstall_agent(data: Payload) {
    
    match data {

        Payload::String(s) => {
            println!("Task event received: {}", s);
            let json_data: serde_json::Value = serde_json::from_str(&s).unwrap();
            let task_id = json_data["task_id"].as_str().unwrap_or_default();
            println!("Task ID: {}", task_id);   
        }
        Payload::Binary(_) => {
            // Handle binary payload
            println!("Task event received, binary type payload");
        }
        Payload::Text(t) => {
            // Handle text payload
            secops_logger.info("Uninstallation task received for agent");

            let mut request_json: HashMap<String, Value> = HashMap::new();
            let json_str = serde_json::to_string(&t).unwrap_or_else(|_| "[]".to_string());

            if let Ok(json_array) = serde_json::from_str::<Value>(&json_str) {
                
                if let Some(json_str) = json_array.as_array().and_then(|arr| arr.get(0)).and_then(|val| val.as_str()) {
                    // Now parse the inner JSON string
                    if let Ok(inner_json) = serde_json::from_str::<Value>(json_str) {
                        
                        if let Some(obj) = inner_json.as_object() {
                            for (key, value) in obj {
                                request_json.insert(key.to_string(), value.clone());
                            }
                        }
                    } else {
                        println!("Failed to parse inner JSON string.");
                    }
                }
            } else {
                println!("Failed to parse JSON from text payload.");
            }

            let jwt_token = request_json["access_token"].as_str().unwrap_or_default();
            let agent_id = request_json["agent_id"].as_str().unwrap_or_default();
            let server_agent_id = get_config_value("A_ID").unwrap();

            if agent_id != server_agent_id {
                secops_logger.error( &format!("Agent ID mismatch, expected: {}, received: {}", server_agent_id, agent_id));
                return;
            }

            if jwt_token.is_empty() {
                secops_logger.error( "No JWT token found");
                return;
            }

            if !check_jwt_status(jwt_token.to_string()) {
                secops_logger.error( &format!("Error checking JWT token status"));
                return;
            }

            if !check_secops_uninstaller_binary_exists() {
                secops_logger.error( "SecOps Uninstaller binary not found");
                return;
            }

            let secops_helper_path = format!("{}/{}", *SECOPS_BINARY_DIRECTORY, *HELPER_PROCESS_NAME);

            secops_logger.info( &format!("Attempting to uninstalling agent: {}", agent_id));

            if cfg!(target_os = "windows") {
                // Windows: Spawn a new process without waiting for it
                if let Err(e) = std::process::Command::new(secops_helper_path)
                    .arg(&format!("{}:{}", agent_id,agent_id))
                    .spawn()
                {
                    eprintln!("Error spawning helper process on Windows: {}", e);
                }
            } else {
                // Linux/macOS: Log the action and execute the command with sudo
                if let Err(e) = Command::new("sudo")
                    .arg(secops_helper_path)
                    .arg(&format!("{}:{}", agent_id,agent_id))
                    .spawn()
                {
                    eprintln!("Error spawning helper process on Unix: {}", e);
                }
        
                // Optional: Give it a moment to start
                thread::sleep(Duration::from_secs(1));
            }

            secops_logger.info( &format!("Uninstallation task started successfully"));
        }
    }
}

fn start_agent_update(data: Payload) {
    
    match data {

        Payload::String(s) => {
            println!("Task event received: {}", s);
            let json_data: serde_json::Value = serde_json::from_str(&s).unwrap();
            let task_id = json_data["task_id"].as_str().unwrap_or_default();
            println!("Task ID: {}", task_id);   
        }
        Payload::Binary(_) => {
            // Handle binary payload
            println!("Task event received, binary type payload");
        }
        Payload::Text(t) => {
            // Handle text payload
            secops_logger.info("Agent update task received");

            let mut request_json: HashMap<String, Value> = HashMap::new();
            let json_str = serde_json::to_string(&t).unwrap_or_else(|_| "[]".to_string());

            if let Ok(json_array) = serde_json::from_str::<Value>(&json_str) {
                
                if let Some(json_str) = json_array.as_array().and_then(|arr| arr.get(0)).and_then(|val| val.as_str()) {
                    // Now parse the inner JSON string
                    if let Ok(inner_json) = serde_json::from_str::<Value>(json_str) {
                        
                        if let Some(obj) = inner_json.as_object() {
                            for (key, value) in obj {
                                request_json.insert(key.to_string(), value.clone());
                            }
                        }
                    } else {
                        secops_logger.error( "Failed to parse inner JSON string.");
                    }
                }
            } else {
                secops_logger.error( "Failed to parse JSON from text payload.");
            }

            let agent_id = request_json["agent_id"].as_str().unwrap_or_default();
            let server_agent_id = get_config_value("A_ID").unwrap();

            if agent_id != server_agent_id {
                secops_logger.error( &format!("Agent ID mismatch, expected: {}, received: {}", server_agent_id, agent_id));
                return;
            }

            let update_type = request_json["update_type"].as_str().unwrap_or_default();
            let agent_operating_system = request_json["agent_operating_system"].as_str().unwrap_or_default();
            let agent_operating_system_version = request_json["agent_operating_system_version"].as_str().unwrap_or_default();

            if update_type.is_empty() {
                secops_logger.error("No update type found");
                return;
            }

            if update_type != "Agent" && update_type != "Server" && update_type != "Both" {
                secops_logger.error("Invalid update type");
                return;
            }

            if agent_operating_system.is_empty() {
                secops_logger.error("No agent operating system found");
                return;
            }

            if agent_operating_system_version.is_empty() {
                secops_logger.error("No agent operating system version found");
                return;
            }

            let mut agent_os = agent_operating_system.to_string();
            let mut agent_os_version = agent_operating_system_version.to_string();

            agent_os = agent_os.replace(" ", "_");
            agent_os_version = agent_os_version.replace(" ", "_");

            if let Err(ex) = check_binary() {
                secops_logger.error( &format!("Error in check_binary: {}", ex));
            }

            let secops_path = Path::new(SECOPS_BINARY_DIRECTORY.as_str());

            if !secops_path.is_dir() {
                if secops_path.exists() {
                    secops_logger.info(&format!("A file named {} exists, attempting to remove it", *SECOPS_BINARY_DIRECTORY));
        
                    if let Err(ex) = fs::remove_file(secops_path) {
                        secops_logger.error(&format!("Error removing file {}: {}", *SECOPS_BINARY_DIRECTORY, ex));
                    }
                }
        
                secops_logger.info(&format!("Creating working directory {}", *SECOPS_BINARY_DIRECTORY));
                
                if let Err(ex) = fs::create_dir_all(secops_path) {
                    secops_logger.error(&format!("Error creating working directory {}. Exception: {}", *SECOPS_BINARY_DIRECTORY, ex));
                } else {
                    secops_logger.info(&format!("Created working directory {}", *SECOPS_BINARY_DIRECTORY));
                }
            }

            let agent_os_lower = agent_os.to_lowercase();
            let update_type_lower = update_type.to_lowercase();

            secops_logger.info(&format!("Attempting to run updater for agent OS: {}", agent_os_lower));

            if agent_os_lower.contains("windows") {

                let secops_windows_updater_path = format!("{}/secops_windows_updater.exe", *INSTALL_DIR);

                if Path::new(&secops_windows_updater_path).exists() {
                    secops_logger.info( "Windows Updater binary found");

                    // Launch the updater using Windows process spawning
                    let _ = std::process::Command::new(secops_windows_updater_path)
                        .arg(agent_id)
                        .arg(agent_operating_system)
                        .arg(agent_operating_system_version)
                        .arg(update_type)
                        .spawn()
                        .expect("Failed to launch Windows Updater");

                } else {
                    secops_logger.error("Windows Updater not found");
                }
            } else {
                let secops_linux_updater_path = format!("{}/secops_linux_updater", *INSTALL_DIR);

                if Path::new(&secops_linux_updater_path).exists() {
                    secops_logger.info("Linux Updater binary found");

                    // Run the Linux updater with sudo and launch it in a new session
                    let _ = Command::new("sudo")
                        .arg(secops_linux_updater_path)
                        .arg(agent_id)
                        .arg(agent_operating_system)
                        .arg(agent_operating_system_version)
                        .arg(update_type)
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .expect("Failed to launch Linux Updater");

                    secops_logger.info("Linux Updater started");

                } else {
                    secops_logger.error( "Linux Updater not found");
                }
            }

            secops_logger.info(&format!("Agent updater started for agent OS: {}", agent_os_lower));

            if update_type_lower.contains("both") {
                secops_logger.info("Both update types selected, exiting.");
                std::process::exit(0);
            }

        }
    }
}


// Get the current failed attempts
fn get_failed_attempts() -> usize {
    FAILED_SOCKET_CONNECTION_ATTEMPTS.load(Ordering::Relaxed)
}

// Increment the failed attempts counter
fn increment_failed_attempts() {
    FAILED_SOCKET_CONNECTION_ATTEMPTS.fetch_add(1, Ordering::Relaxed);

    if get_failed_attempts() >= get_max_failed_attempts() {
        secops_logger.info("Max failed socket connection attempts reached. Restarting Service ...");
        restart_secops_service();
    } else {
        secops_logger.info(&format!("Failed socket connection attempts: {}", get_failed_attempts()));
    }
}

// Reset the failed attempts counter
fn reset_failed_attempts() {
    FAILED_SOCKET_CONNECTION_ATTEMPTS.store(0, Ordering::Relaxed);
}

// Get the max allowed failed attempts
fn get_max_failed_attempts() -> usize {
    MAX_FAILED_SOCKET_CONNECTION_ATTEMPTS.load(Ordering::Relaxed)
}

// Set a new max failed attempts value
fn set_max_failed_attempts(value: usize) {
    MAX_FAILED_SOCKET_CONNECTION_ATTEMPTS.store(value, Ordering::Relaxed);
}

fn restart_secops_service() {
    let agent_id = get_config_value("A_ID").expect("Agent ID not found in get_config_value");

    secops_logger.info("Attempting to restart SecopsService");

    let os_name = env::consts::OS;

    if os_name == "windows" {
        let service_name = "SecopsService";
        if let Ok(current_dir) = env::current_exe() {
            let current_dir = current_dir.parent().unwrap_or_else(|| Path::new("."));
            let batch_script = current_dir.join("restart_service.bat");

            if let Ok(mut file) = File::create(&batch_script) {
                let script_content = r#"
                    @echo off
                    echo Restarting service: SecopsService
                    sc stop SecopsService
                    timeout /t 3 /nobreak >nul
                    sc start SecopsService
                    echo Service restarted successfully!
                    exit
                "#;
                file.write_all(script_content.as_bytes()).unwrap();
            }

            if let Err(e) = Command::new("cmd")
            .arg("/C")
            .arg(batch_script.to_str().unwrap())
            .spawn() // Spawns an independent process

            {
                secops_logger.error("Error restarting service, please restart manually");    
            }
        }
    } else {
        let binary_path = "example_binary_path"; // Replace this with actual path check logic
        if binary_path.contains("mac") {
            let service_restart = Command::new("sudo")
                .arg("launchctl")
                .arg("kickstart")
                .arg("-k")
                .arg("system/secops_service")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();

            match service_restart {
                Ok(status) if status.success() => {
                   secops_logger.info( "Service restarted");
                }
                _ => {
                    secops_logger.error("Error restarting service, please restart manually");
                }
            }
        } else {
            let service_restart = Command::new("sudo")
                .arg("systemctl")
                .arg("restart")
                .arg("secops_service.service")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();

            match service_restart {
                Ok(status) if status.success() => {
                    secops_logger.info( "Service restarted");
                }
                _ => {
                    secops_logger.error("Error restarting service, please restart manually");
                }
            }
        }
    }
}


fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    secops_logger.info("Starting run_server");
    if cfg!(target_os = "windows") {
        if !is_elevated() {
            println!("Please run this program with admin/root privileges");
            process::exit(1);
        }
    } else {
        if !is_admin() {
            println!("Please run this program with admin/root privileges");
        }
    }

    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();

    // Check for version flag
    if args.contains(&"-V".to_string()) || args.contains(&"--version".to_string()) {
        print_server_version();
        process::exit(0);
    }

    let config_path = get_config_file_path();
    read_config(config_path.as_str());

    remove_config_sh();

    prepare_working_dirs();

    secops_logger.info("SecOps Agent Service Started");

    let agent_id = match get_config_value("A_ID") {
        Some(id) => id,
        None => {
            secops_logger.error("Agent ID not found in get_config_value");
            process::exit(1);
        }
    };
    let base_url: String = match get_config_value("BASE_URL") {
        Some(url) => url,
        None => {
            secops_logger.error("BASE_URL not found in get_config_value");
            process::exit(1);
        }
    };
    let agent_mode = match get_config_value("agent_mode") {
        Some(mode) => mode,
        None => {
            secops_logger.error("agent_mode not found in get_config_value");
            process::exit(1);
        }
    };
    let secops_jump_host: bool = get_config_value("secops_jump_host").map_or(false, |v| v == "true");

    if agent_id.is_empty() {
        secops_logger.error("Agent ID not found");
        process::exit(1);
    }

    // check if AGENT_REGISTRATION_MODULE_PATH exists or not
    // If it exists remove the file
    let agent_registration_module_path = Path::new(AGENT_REGISTRATION_MODULE_PATH.as_str());
    if Path::new(AGENT_REGISTRATION_MODULE_PATH.as_str()).exists() {
        if let Err(e) = fs::remove_file(AGENT_REGISTRATION_MODULE_PATH.as_str()) {
            secops_logger.error(&format!("Failed to remove file: {}", e));
        }
    }

    generate_and_share_server_keys();

    secops_logger.info("Setting up socket event handlers");

    let handle_task_event = move |message: Payload, _| {
        
        match message {
            Payload::String(s) => {
                let json_data: serde_json::Value = serde_json::from_str(&s).unwrap();
                let task_id = json_data["task_id"].as_str().unwrap_or_default();
            }
            Payload::Binary(_) => {
                // Handle binary payload
                println!("Task event received, binary type payload");
            }
            Payload::Text(t) => {
                // Handle text payload
                let mut cli_command: HashMap<String, Value> = HashMap::new();
                let json_str = serde_json::to_string(&t).unwrap_or_else(|_| "[]".to_string());

                if let Ok(json_data) = serde_json::from_str::<Value>(&json_str) {
                    if let Some(obj) = json_data[0].as_object() {
                        for (key, value) in obj {
                            let decrypted_key = decrypt_message(key);
                            if value.is_string() && !["jwt_token", "ssh_key", "script", "secops_binary_config", "asset_details"].contains(&decrypted_key.as_str()) {
                                let decrypted_value = decrypt_message(&value.to_string());
                                cli_command.insert(decrypted_key.to_string(), Value::String(decrypted_value));
                            } else {
                                cli_command.insert(decrypted_key, value.clone());
                            }
                        }
                    }

                } else {
                    println!("Failed to parse JSON from text payload.");
                    secops_logger.info("message failed to parse json");
                }

                let cli_command_json = match serde_json::to_value(cli_command) {
                    Ok(val) => val,
                    Err(e) => {
                        secops_logger.error(&format!("Failed to convert task to JSON: {}", e));
                        return;
                    }
                };
                println!("CLI Command JSON: {}", cli_command_json);
                run_task(cli_command_json);

            }
        }
    };

    check_agent_health();

    initiate_local_patch_scan();

    set_max_failed_attempts(30);

    secops_logger.info("Entering main event loop");
    loop {
        let agent_id = get_config_value("A_ID").expect("Agent ID not found in get_config_value");
        println!("Config loaded successfully. Agent ID: {}", agent_id);

        let mut url = format!("wss://socket.app.secopsolution.com");

        if base_url == "https://api.app.secopsolution.com/secops/v1.0/" {
            url = format!("wss://socket.app.secopsolution.com");
        } else {
            url = base_url.replace("/secops/v1.0/","");
            if url.contains("https://") {
                url = url.replace("https://","wss://");
            } else {
                url = url.replace("http://","ws://");
                url = url.replace("8000","5678");
            }
        }
        
        let url = format!("http://172.28.181.199:5678");

        secops_logger.info(&format!("Connecting to the websocket server at {}", url));
        
        let current_socket: Arc<Mutex<Option<RawClient>>> = Arc::new(Mutex::new(None));
        let current_socket_clone = Arc::clone(&current_socket);

        // Shared state for connection and last pong
        let connection_successful = Arc::new(AtomicBool::new(false));
        
        let last_pong_received = Arc::new(Mutex::new(Instant::now()));
        


        if let Some(prev_socket) = current_socket.lock().unwrap().take() {
            prev_socket.disconnect();
        }
        
        let socket = match ClientBuilder::new(&url)
            .namespace("/")
            .reconnect(false)
            .reconnect_on_disconnect(false)
            .opening_header("agentID", match HeaderValue::from_str(&agent_id) {
                Ok(h) => h,
                Err(e) => {
                    secops_logger.error(&format!("Invalid agentID header: {}", e));
                    continue;
                }
            })
            .on("open", {
                let connection_successful_clone = Arc::clone(&connection_successful);
                let current_socket_clone = Arc::clone(&current_socket_clone);
                move |message, client| {
                    connection_successful_clone.store(true, Ordering::Relaxed);
                    let mut socket_guard = current_socket_clone.lock().unwrap();
                    *socket_guard = Some(client.clone());
                    secops_logger.info("Connected to the websocket server");
                    reset_failed_attempts();
                }
            })
            .on("agent_pong", {
                let last_pong_received_clone = Arc::clone(&last_pong_received);
                move |data, _| {   
                    let mut last_pong = last_pong_received_clone.lock().unwrap();
                    *last_pong = Instant::now();
                    secops_logger.info("Received Heartbeat from server");
                }
            })            
            .on("task", handle_task_event)
            .on("health_check", move |_, _| {
                check_agent_health();
            })
            .on("uninstall", move |data, _| {
                uninstall_agent(data);
            })
            .on("push_updates", move |data, _| {
                start_agent_update(data);
            })
            .on("close", {
                let current_socket_clone = Arc::clone(&current_socket);
                let connection_successful_clone = Arc::clone(&connection_successful);
                let last_pong_received_clone = Arc::clone(&last_pong_received);
                move |data, _| {
                    secops_logger.error( &format!("Connection to the websocket server closed, error: {:#?}", data));
                    increment_failed_attempts();
                    let mut socket_guard = current_socket_clone.lock().unwrap();
                    *socket_guard = None;
                    secops_logger.info( "Attempting to reconnect...");
                    connection_successful_clone.store(false, Ordering::Relaxed);

                    // Reset the last pong received time
                    let mut last_pong = last_pong_received_clone.lock().unwrap();
                    *last_pong = Instant::now();
                }
            })
            .connect() {
                Ok(socket) => {
                    // Close the previous connection if it exists
                    if let Some(prev_socket) = current_socket.lock().unwrap().take() {
                        prev_socket.disconnect();
                    }
            
                    socket
                }
                Err(e) => {
                    increment_failed_attempts();
                    eprintln!("Failed to connect: {}. Retrying in 10 seconds...", e);
                    thread::sleep(Duration::from_secs(10));
                    continue; // Retry connection
                }
            };

        
        
        // Wait for connection to be established
        while !connection_successful.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));
        }

        let agent_id = get_config_value("A_ID").expect("Agent ID not found in get_config_value");

        // Subscribe to room
        if let Err(e) = socket.emit("subscribe", json!({"room": agent_id})) {
            eprintln!("Error subscribing to room: {}", e);
        }

        // Ping management loop
        let mut time_lapsed = 0;
        let mut ping_sent = false;
        let mut jump_host_service_polling_counter   = 0;
        loop {

            // check if connection_successful is set to false if so disconnect and attempt to reconnect
            if !connection_successful.load(Ordering::Relaxed) {
                secops_logger.error("Websocket disconnected, attempting to reconnect ...");
                socket.disconnect();
                break;
            }
            
            // Check if we can send ping and it's time to do so
            if time_lapsed >= CHECK_INTERVAL || time_lapsed == 0 {
                time_lapsed = 0;
                

                if !connection_successful.load(Ordering::Relaxed) {
                    secops_logger.error( "Websocket disconnected, attempting to reconnect ...");
                    socket.disconnect();
                    break;
                }
                
                // Send ping
                if !ping_sent {
                    if let Err(e) = socket.emit("agent_ping", json!({})) {
                        ping_sent = true;
                        secops_logger.error(&format!("Error sending heartbeat to server: {}", e));
                    } else {
                        ping_sent = true;
                        secops_logger.info("Heartbeat sent to server");
                    }
                    
                }
            }

            let scheduled_time = get_config_value("scheduled_time");
            let last_schedule_scan = get_config_value("last_schedule_scan");

            
            // Check scheduled time if applicable
            if let Some(ref sched_time) = scheduled_time {
                if let Ok(sched_time_parsed) = chrono::NaiveTime::parse_from_str(sched_time, "%H:%M:%S") {
                    // Get current time in UTC timezone
                    let now_utc = Utc::now();
                    let now_naive_utc = now_utc.time();
                    let todays_date = now_utc.date_naive().to_string();
                    
                    // For debugging
                    secops_logger.info(&format!("Checking scheduled scan: scheduled_time={}, current_utc_time={}, last_scan={}", sched_time, now_naive_utc, last_schedule_scan.as_deref().unwrap_or("None")));

                    // Compare times directly in UTC context
                    if (last_schedule_scan.is_none() || 
                        last_schedule_scan.as_deref() == Some("None") || 
                        last_schedule_scan.as_deref() != Some(&todays_date)) && 
                        now_naive_utc >= sched_time_parsed {
                        
                        println!("Scheduled scan triggered at {} UTC", now_utc);
                        secops_logger.info(&format!("Scheduled scan triggered at {} UTC", now_utc));
                        
                        initiate_local_vulnerability_scan();

                        set_config_value("last_schedule_scan", &todays_date);
                        let last_schedule_scan = get_config_value("last_schedule_scan");

                        // Update the config file
                        if let Ok(content) = std::fs::read_to_string(&config_path) {
                            let lines: Vec<String> = content.lines().map(|line| line.to_string()).collect();
                            let mut updated_lines = Vec::new();
                            let mut found = false;
                            
                            for line in lines {
                                if line.starts_with("last_schedule_scan=") && !found {
                                    updated_lines.push(format!("last_schedule_scan={}", last_schedule_scan.clone().unwrap()));
                                    found = true;
                                } else {
                                    updated_lines.push(line);
                                }
                            }
                            
                            let updated_content = updated_lines.join("\n") + "\n";
                            if let Err(e) = std::fs::write(&config_path, updated_content) {
                                secops_logger.error(&format!("Error writing to config file: {}", e));
                            }
                        }
                    }
                }
            }

            if agent_mode == AGENT_MODE_JUMP_HOST {
                if jump_host_service_polling_counter == 6 {
                        if !is_secops_file_transfer_service_running(){
                            secops_logger.info( "SecOps file transfer service not running. Initiating service.");
                            initiate_secops_jump_host_service();
                        } else {
                            secops_logger.info("SecOps file transfer service running. Skipping service creation.");
                        }
                        jump_host_service_polling_counter = 0;
                } else {
                    jump_host_service_polling_counter += 1;
                }
            }

            // Increment time and check for ping interval
            time_lapsed += 1;
            
            // Check for pong timeout with precise tracking
            let last_pong = *last_pong_received.lock().unwrap();
            let elapsed_since_pong = last_pong.elapsed().as_secs();
            
            if elapsed_since_pong > PONG_TIMEOUT {
                increment_failed_attempts();
                secops_logger.error(&format!("No Heartbeat received in {} seconds. Attempting a create fresh connection ...", PONG_TIMEOUT));
                socket.disconnect();
                break;
            }

            // Reset ping_sent if pong is received recently
            if ping_sent && elapsed_since_pong < 5 {
                ping_sent = false;
            }

            thread::sleep(Duration::from_secs(10));
        }
    }
}


// Actual execution wrapped in a closure to handle any unexpected exits
pub fn actual_main() -> Result<(), Box<dyn std::error::Error>> {
    // Move original main code here to wrap it with panic and exit handling
    match std::panic::catch_unwind(|| run_server()) {
        Ok(result) => {
            if let Err(e) = result {
                secops_logger.error(&format!("Main function returned error: {}", e));
                restart_secops_service();
            }
            Ok(())
        },
        Err(_) => {
            secops_logger.error("Process panicked outside of panic handler");
            restart_secops_service();
            Ok(())
        }
    }
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    secops_logger.info("Starting main");
    actual_main()
}