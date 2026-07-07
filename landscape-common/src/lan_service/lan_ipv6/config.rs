use serde::{Deserialize, Serialize};

use super::dhcpv6_config::DHCPv6ServerConfig;
use super::ipv6_ra::RouterFlags;
use super::prefix_group::LanPrefixGroupConfig;
use super::source_config::LanIPv6SourceConfig;
use crate::config_service::iface::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::database::repository::LandscapeDBStore;
use crate::store::storev2::LandscapeStore;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum IPv6ServiceMode {
    #[default]
    Slaac,
    Stateful,
    SlaacDhcpv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SourceServiceKind {
    Ra,
    Na,
    IaPd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PrefixGroupServiceKind {
    Ra,
    Na,
    IaPd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LanIPv6ServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    pub config: LanIPv6Config,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<String> for LanIPv6ServiceConfig {
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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LanIPv6Config {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub mode: IPv6ServiceMode,
    pub ad_interval: u32,
    #[serde(default = "ra_flag_default")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub ra_flag: RouterFlags,
    #[serde(default)]
    pub sources: Vec<LanIPv6SourceConfig>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub dhcpv6: Option<DHCPv6ServerConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LanIPv6ConfigV2 {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub mode: IPv6ServiceMode,
    pub ad_interval: u32,
    #[serde(default = "ra_flag_default")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub ra_flag: RouterFlags,
    #[serde(default)]
    pub prefix_groups: Vec<LanPrefixGroupConfig>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub dhcpv6: Option<DHCPv6ServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LanIPv6ServiceConfigV2 {
    pub iface_name: String,
    pub enable: bool,
    pub config: LanIPv6ConfigV2,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<String> for LanIPv6ServiceConfigV2 {
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

impl From<LanIPv6ServiceConfig> for LanIPv6ServiceConfigV2 {
    fn from(value: LanIPv6ServiceConfig) -> Self {
        Self {
            iface_name: value.iface_name,
            enable: value.enable,
            config: value.config.into(),
            update_at: value.update_at,
        }
    }
}

pub fn ra_flag_default() -> RouterFlags {
    0xc0.into()
}

impl LandscapeStore for LanIPv6ServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeStore for LanIPv6ServiceConfigV2 {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl ZoneAwareConfig for LanIPv6ServiceConfig {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::LanOnly
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::LanIpv6
    }
}

impl ZoneAwareConfig for LanIPv6ServiceConfigV2 {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::LanOnly
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::LanIpv6
    }
}
