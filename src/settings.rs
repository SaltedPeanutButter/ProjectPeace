use std::{path::PathBuf, fs};

use serde::{Deserialize, Serialize};

pub const PROJECT_SETTINGS_FILENAME: &str = "settings.json";

#[derive(Serialize, Deserialize)]
pub struct Settings {
    pub version: u8,
    pub storage_dir_name: String,
}

pub enum SettingError {
    UnreadableSettingFile,
    UnwritableSettingFile,
    
    CorruptedSettingFile,
}

impl Settings {
    pub fn new() -> Self {
        Self {
            version: 1,
            storage_dir_name: "Project Peace".to_string()
        }
    }

    pub fn load(repo_dir: &PathBuf) -> Result<Self, SettingError> {
        let file = repo_dir.join(PROJECT_SETTINGS_FILENAME);
        let file = match fs::read_to_string(file) {
            Ok(v) => v,
            Err(_) => return Err(SettingError::UnreadableSettingFile),
        };
        match serde_json::from_str(&file) {
            Ok(v) => Ok(v),
            Err(_) => Err(SettingError::CorruptedSettingFile),
        }
    }

    pub fn dump(&self, repo_dir: &PathBuf) -> Result<(), SettingError> {
        let file = repo_dir.join(PROJECT_SETTINGS_FILENAME);
        Ok(())
    }
}