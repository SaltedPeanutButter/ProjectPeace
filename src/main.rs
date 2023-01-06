use std::{env, path::PathBuf, process::exit, io::Write, fs};
use log::{info, warn, error};
use settings::{Settings, SettingError};
use rpassword;

// This module provides dirty cryptographic functions
mod crypto;

// This module provides the placeholder for different application settings
mod settings;

// This module provides dirty macros
mod custom_macros;

// This module provides const-&str messages for user interfaces
mod text;

// This module provides functions to work with user' files
mod file_ops;

const REPOSITORY_DIR_NAME: &str = ".project_peace";

fn main() {
    clear!();

    let root_dir = env::current_dir().unwrap();
    let repository_dir = root_dir.join(REPOSITORY_DIR_NAME);

    // Check if repository dir exists
    if !(repository_dir.exists() && repository_dir.is_dir()) {
        info!("Repository dir not found");
        let settings = create_project_peace(&repository_dir);
        match settings.dump(&repository_dir) {
            Err(SettingError::UnwritableSettingFile) => error_with_code!(13),
            _ => (),
        }
        exit(0);
    }
    info!("Repository dir found at {}", repository_dir.display());

    // Run status check for essential files
    let status = run_status_check(&repository_dir);
    if !status {
        error_with_code!(10);
    }

    // Load project settings
    let settings = load_settings(&repository_dir);

    // Inform and prompt users
    println!("{}", text::PP_DETECTED);
    println!("{}", text::PP_PROMPT);

    // User input loop
    loop {
        let option = input!("Your choice (1) > ");

        // Assign default value
        let option = if option.is_empty() { "1".to_string() } else { option };
        
        // Convert option to u8
        match option.parse::<u8>() {
            Ok(1) => configure_project_peace(&repository_dir, &settings),
            Ok(2) => start_project_peace(&repository_dir, &settings),
            _ => {
                println!("{}", "Invalid option!");
                continue;
            },
        };
    };

}

fn run_status_check(repo_dir: &PathBuf) -> bool {
    let mut status_flag = true;

    // Check for RSA (encrypted) private and public key files
    let pk_path = repo_dir.join(crypto::RSA_PRIV_KEY_FILENAME);
    if !(pk_path.exists() && pk_path.is_file()) {
        warn!("Private key file not found");
        status_flag = false;
    } else {
        info!("Private key file found at {}", pk_path.display());
    }
    
    let pk_path = repo_dir.join(crypto::RSA_PUB_KEY_FILENAME);
    if !(pk_path.exists() && pk_path.is_file()) {
        warn!("Public key file not found");
        status_flag = false;
    } else {
        info!("Public key file found at {}", pk_path.display())
    };

    // Check for project setting file
    let obj_path = repo_dir.join(settings::PROJECT_SETTINGS_FILENAME);
    if !(obj_path.exists() && obj_path.is_file()) {
        warn!("Setting file not found");
        status_flag = false;
    } else {
        info!("Setting file found at {}", pk_path.display());
    }
    return status_flag;
}

fn load_settings(repo_dir: &PathBuf) -> Settings {
    match Settings::load(&repo_dir) {
        Ok(v) => {
            info!("Settings loaded from {}", repo_dir.display());
            v
        },
        Err(SettingError::UnreadableSettingFile) => {
            error!("Unable to read setting file");
            error_with_code!(11)
        },
        Err(SettingError::CorruptedSettingFile) => {
            error!("Setting file is corrupted");
            error_with_code!(12)
        },
        _ => load_settings(repo_dir),
    }
}

fn create_project_peace(repo_dir: &PathBuf) -> Settings {
    println!("{}", text::PP_CREATE);

    // Create default settings
    let mut settings = Settings::new();

    // Ask for storage name
    let storage_name = settings.storage_dir_name;
    let storage_name = input!("Enter a name for storage ({storage_name}) > ");
    settings.storage_dir_name = storage_name.clone();

    // Create storage dir
    let storage_dir = repo_dir.parent().unwrap();
    let storage_dir = storage_dir.join(storage_name.clone());
    match fs::create_dir(storage_dir.clone()) {
        Ok(_) => info!("New storage dir is created at {}", storage_dir.display()),
        Err(_) => {
            error!("Unable to create new storage dir");
            error_with_code!(20)
        },
    }

    // Ask for passphrase using passphrase loop
    println!("{}", text::PP_CREATE_PASSPHRASE_INFO);
    let passphrase = loop {
        let pp = rpassword::prompt_password("Enter passphrase: ").unwrap();
        let again = rpassword::prompt_password("Enter passphrase again: ").unwrap();
        if pp == again {
            break pp;
        }
    };

    // Create cipher from passphrase
    let mut cipher = crypto::CryptoMachine::new(passphrase);

    // Prompt users to start adding files to it
    clear!();
    println!("{}", text::PP_CREATE_ADD_FILES);
    input!();

    // Commit files added
    file_ops::commit(&repo_dir, &storage_dir, &mut cipher);
    println!("{}", text::PP_CREATE_ADD_FILES_COMPLETE);

    settings
}

fn configure_project_peace(repo_dir: &PathBuf, settings: &Settings) -> ! {
    // Get path to storage dir
    let storage_dir = repo_dir.parent().unwrap();
    let storage_dir = storage_dir.join(settings.storage_dir_name.clone());

    //
    exit(0)
}

#[allow(unused)]
fn start_project_peace(repo_dir: &PathBuf, settings: &Settings) -> ! {
    println!("{}", text::PP_CREATE);
    exit(0)
}