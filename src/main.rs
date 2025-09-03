use std::fs;
use std::io::{self, Write};
use std::path::Path;
use clap::{Parser, Subcommand};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce
};
use keyring::Entry;
use rand::RngCore;

#[derive(Parser)]
#[command(name = "rust-file-crypto")]
#[command(about = "A simple file encryption/decryption tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file
    Encrypt {
        /// Path to the file to encrypt
        file_path: String,
    },
    /// Decrypt a file
    Decrypt {
        /// Path to the file to decrypt
        file_path: String,
    },
}

const SERVICE_NAME: &str = "rust-file-crypto";
const USERNAME: &str = "default-user";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { file_path } => {
            encrypt_file(&file_path)?;
        }
        Commands::Decrypt { file_path } => {
            decrypt_file(&file_path)?;
        }
    }

    Ok(())
}

fn get_or_create_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // First try to use keyring
    if let Ok(entry) = Entry::new(SERVICE_NAME, USERNAME) {
        match entry.get_password() {
            Ok(key_hex) => {
                // Convert hex string back to bytes
                return hex::decode(key_hex).map_err(|e| format!("Failed to decode stored key: {}", e).into());
            }
            Err(_) => {
                // Generate new key
                let mut key = vec![0u8; 32]; // 256-bit key for AES-256
                OsRng.fill_bytes(&mut key);
                
                // Try to store key in keyring
                let key_hex = hex::encode(&key);
                if entry.set_password(&key_hex).is_ok() {
                    println!("Generated new encryption key and stored it securely in keyring.");
                    return Ok(key);
                }
            }
        }
    }
    
    // Fallback to local file storage
    let key_file = ".rust-file-crypto-key";
    
    if Path::new(key_file).exists() {
        let key_hex = fs::read_to_string(key_file)?;
        let key = hex::decode(key_hex.trim())?;
        return Ok(key);
    }
    
    // Generate new key and store in file
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    let key_hex = hex::encode(&key);
    fs::write(key_file, &key_hex)?;
    
    println!("Generated new encryption key and stored it in local file (keyring unavailable).");
    println!("Warning: Key file should be kept secure and backed up.");
    
    Ok(key)
}

fn encrypt_file(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(file_path);
    
    if !path.exists() {
        return Err(format!("File not found: {}", file_path).into());
    }
    
    if !path.is_file() {
        return Err(format!("Path is not a file: {}", file_path).into());
    }
    
    // Read the file content
    let plaintext = fs::read(file_path)?;
    
    // Get encryption key
    let key_bytes = get_or_create_key()?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt the data
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    
    // Combine nonce and ciphertext
    let mut encrypted_data = Vec::new();
    encrypted_data.extend_from_slice(&nonce_bytes);
    encrypted_data.extend_from_slice(&ciphertext);
    
    // Create encrypted file path
    let encrypted_path = format!("{}.encrypted", file_path);
    
    // Write encrypted data to new file
    fs::write(&encrypted_path, encrypted_data)?;
    
    println!("File encrypted successfully: {}", encrypted_path);
    
    // Ask user if they want to delete the original file
    print!("Do you want to delete the original file? (y/N): ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    if input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes" {
        fs::remove_file(file_path)?;
        println!("Original file deleted.");
    } else {
        println!("Original file kept.");
    }
    
    Ok(())
}

fn decrypt_file(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(file_path);
    
    if !path.exists() {
        return Err(format!("File not found: {}", file_path).into());
    }
    
    if !path.is_file() {
        return Err(format!("Path is not a file: {}", file_path).into());
    }
    
    // Read the encrypted file content
    let encrypted_data = fs::read(file_path)?;
    
    if encrypted_data.len() < 12 {
        return Err("Invalid encrypted file format".into());
    }
    
    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Get decryption key
    let key_bytes = get_or_create_key()?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    
    // Decrypt the data
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {:?}", e))?;
    
    // Create decrypted file path (remove .encrypted extension if present)
    let decrypted_path = if file_path.ends_with(".encrypted") {
        file_path.strip_suffix(".encrypted").unwrap().to_string()
    } else {
        format!("{}.decrypted", file_path)
    };
    
    // Write decrypted data to new file
    fs::write(&decrypted_path, plaintext)?;
    
    println!("File decrypted successfully: {}", decrypted_path);
    
    // Ask user if they want to delete the encrypted file
    print!("Do you want to delete the encrypted file? (y/N): ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    if input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes" {
        fs::remove_file(file_path)?;
        println!("Encrypted file deleted.");
    } else {
        println!("Encrypted file kept.");
    }
    
    Ok(())
}
