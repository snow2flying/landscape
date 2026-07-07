use serde::{Deserialize, Serialize};

use crate::database::repository::LandscapeDBStore;
use crate::iface::config::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::service::ServiceConfigError;
use crate::store::storev2::LandscapeStore;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WifiServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    pub config: String,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeStore for WifiServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for WifiServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
    fn get_update_at(&self) -> f64 {
        self.update_at
    }
    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

impl WifiServiceConfig {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        if self.enable && self.config.trim().is_empty() {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "config must not be empty when enabled".to_string(),
            });
        }
        if self.config.len() > 8192 {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("config length ({}) exceeds 8192", self.config.len()),
            });
        }
        Ok(())
    }
}

impl ZoneAwareConfig for WifiServiceConfig {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::LanOrUndefined
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::WiFi
    }
}
