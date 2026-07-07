// ===========================================================================
// Old unified types below — kept for backward compat with old DB table.
// Will be removed in a future major version cleanup.
// ===========================================================================

use std::collections::HashSet;
use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};

use super::dhcpv6_config::DHCPv6ServerConfig;
use crate::config_service::iface::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::database::repository::LandscapeDBStore;
use crate::service::ServiceConfigError;
use crate::store::storev2::LandscapeStore;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IPV6RAServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    pub config: IPV6RAConfig,

    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl LandscapeDBStore<String> for IPV6RAServiceConfig {
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
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum IPV6RaConfigSource {
    Static(IPv6RaStaticConfig),
    Pd(IPv6RaPdConfig),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IPv6RaStaticConfig {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub base_prefix: Ipv6Addr,
    pub sub_prefix_len: u8,
    pub sub_index: u32,
    pub ra_preferred_lifetime: u32,
    pub ra_valid_lifetime: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IPv6RaPdConfig {
    pub depend_iface: String,
    pub prefix_len: u8,
    pub subnet_index: u32,
    pub ra_preferred_lifetime: u32,
    pub ra_valid_lifetime: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IPV6RAConfig {
    pub ad_interval: u32,
    #[serde(default = "ra_flag_default")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub ra_flag: RouterFlags,
    pub source: Vec<IPV6RaConfigSource>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub dhcpv6: Option<DHCPv6ServerConfig>,
}

impl IPV6RAConfig {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        let mut base_prefixes = HashSet::<Ipv6Addr>::new();
        let mut depend_ifaces = HashSet::<String>::new();
        let mut sub_indices = HashSet::<u32>::new();

        for src in &self.source {
            match src {
                IPV6RaConfigSource::Static(cfg) => {
                    if !base_prefixes.insert(cfg.base_prefix) {
                        return Err(ServiceConfigError::InvalidConfig {
                            reason: format!("Duplicate base_prefix found: {}", cfg.base_prefix),
                        });
                    }

                    if !sub_indices.insert(cfg.sub_index) {
                        return Err(ServiceConfigError::InvalidConfig {
                            reason: format!(
                                "Duplicate sub_index/subnet_index found: {}",
                                cfg.sub_index
                            ),
                        });
                    }
                }
                IPV6RaConfigSource::Pd(cfg) => {
                    if !depend_ifaces.insert(cfg.depend_iface.clone()) {
                        return Err(ServiceConfigError::InvalidConfig {
                            reason: format!("Duplicate depend_iface found: {}", cfg.depend_iface),
                        });
                    }

                    if !sub_indices.insert(cfg.subnet_index) {
                        return Err(ServiceConfigError::InvalidConfig {
                            reason: format!(
                                "Duplicate sub_index/subnet_index found: {}",
                                cfg.subnet_index
                            ),
                        });
                    }
                }
            }
        }

        if let Some(dhcpv6) = &self.dhcpv6 {
            dhcpv6.validate()?;
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RouterFlags {
    pub managed_address_config: bool,
    pub other_config: bool,
    pub home_agent: bool,
    pub prf: u8,
    pub nd_proxy: bool,
    pub reserved: u8,
}

impl From<u8> for RouterFlags {
    fn from(byte: u8) -> Self {
        Self {
            managed_address_config: (byte & 0b1000_0000) != 0,
            other_config: (byte & 0b0100_0000) != 0,
            home_agent: (byte & 0b0010_0000) != 0,
            prf: (byte & 0b0001_1000) >> 3,
            nd_proxy: (byte & 0b0000_0100) != 0,
            reserved: byte & 0b0000_0011,
        }
    }
}

impl Into<u8> for RouterFlags {
    fn into(self) -> u8 {
        (self.managed_address_config as u8) << 7
            | (self.other_config as u8) << 6
            | (self.home_agent as u8) << 5
            | (self.prf << 3)
            | (self.nd_proxy as u8) << 2
            | self.reserved
    }
}

fn ra_flag_default() -> RouterFlags {
    0xc0.into()
}

impl IPV6RAConfig {
    pub fn new(depend_iface: String) -> Self {
        let source = vec![IPV6RaConfigSource::Pd(IPv6RaPdConfig {
            depend_iface,
            ra_preferred_lifetime: 300,
            ra_valid_lifetime: 300,
            prefix_len: 64,
            subnet_index: 1,
        })];
        Self {
            source,
            ra_flag: ra_flag_default(),
            ad_interval: 300,
            dhcpv6: None,
        }
    }
}

impl LandscapeStore for IPV6RAServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl ZoneAwareConfig for IPV6RAServiceConfig {
    fn iface_name(&self) -> &str {
        &self.iface_name
    }
    fn zone_requirement() -> ZoneRequirement {
        ZoneRequirement::LanOnly
    }
    fn service_kind() -> ServiceKind {
        ServiceKind::Icmpv6Ra
    }
}
