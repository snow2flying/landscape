#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostnameRegistryConfig {
    pub lan_suffix: String,
}

impl Default for HostnameRegistryConfig {
    fn default() -> Self {
        Self {
            lan_suffix: crate::DEFAULT_DNS_LAN_SUFFIX.to_string(),
        }
    }
}

impl HostnameRegistryConfig {
    pub fn update_from_file_config(
        &mut self,
        config: &crate::config::settings::LandscapeHostnameRegistryConfig,
    ) {
        if let Some(v) = &config.lan_suffix {
            self.lan_suffix = v.clone();
        }
    }
}
