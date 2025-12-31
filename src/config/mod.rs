use std::path::PathBuf;
use anyhow::Result;
use directories::ProjectDirs;
use std::fs;
use crate::models::Config;

pub struct ConfigManager;

impl ConfigManager {
    pub fn get_config_path() -> PathBuf {
        let proj_dirs = ProjectDirs::from("com", "wazuh", "wazuh-tui")
            .unwrap_or_else(|| ProjectDirs::from("", "", "wazuh-tui").unwrap());
        let config_dir = proj_dirs.config_dir();
        if !config_dir.exists() {
            fs::create_dir_all(config_dir).ok();
        }
        config_dir.join("config.toml")
    }

    pub fn load() -> Result<Config> {
        let path = Self::get_config_path();
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(config: &Config) -> Result<()> {
        let path = Self::get_config_path();
        let content = toml::to_string_pretty(config)?;
        fs::write(path, content)?;
        Ok(())
    }
}
