use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use uuid::Uuid;

use crate::database::repository::LandscapeDBStore;
use crate::service::ServiceConfigError;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

use super::config::StaticMapPair;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum StaticNatV4Target {
    Address {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        ipv4: Ipv4Addr,
    },
    Local,
    Device {
        device_id: Uuid,
    },
}

impl StaticNatV4Target {
    pub fn address(ipv4: Ipv4Addr) -> Self {
        Self::Address { ipv4 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StaticNatMappingV4Config {
    #[serde(default = "gen_database_uuid")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub id: Uuid,
    pub enable: bool,
    pub remark: String,
    #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
    pub wan_iface_name: Option<String>,
    pub mapping_pair_ports: Vec<StaticMapPair>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub lan_target: Option<StaticNatV4Target>,
    pub l4_protocols: Vec<u8>,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = false))]
    pub update_at: f64,
}

impl StaticNatMappingV4Config {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        if self.enable && self.mapping_pair_ports.is_empty() {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "mapping_pair_ports must not be empty when enabled".to_string(),
            });
        }

        if self.enable {
            match self.lan_target.as_ref() {
                None => {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "enabled static NAT mapping must define a LAN target".to_string(),
                    });
                }
                Some(StaticNatV4Target::Device { device_id }) if device_id.is_nil() => {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "device target must select a valid enrolled device".to_string(),
                    });
                }
                _ => {}
            }
        }

        for (i, pair) in self.mapping_pair_ports.iter().enumerate() {
            if pair.wan_port == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("mapping_pair_ports[{i}].wan_port must not be 0"),
                });
            }
            if pair.lan_port == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("mapping_pair_ports[{i}].lan_port must not be 0"),
                });
            }
        }

        for (i, &proto) in self.l4_protocols.iter().enumerate() {
            if proto != 6 && proto != 17 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("l4_protocols[{i}] ({proto}) must be 6 (TCP) or 17 (UDP)"),
                });
            }
        }

        Ok(())
    }
}

impl LandscapeDBStore<Uuid> for StaticNatMappingV4Config {
    fn get_id(&self) -> Uuid {
        self.id
    }
    fn get_update_at(&self) -> f64 {
        self.update_at
    }
    fn set_update_at(&mut self, ts: f64) {
        self.update_at = ts;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStaticNatMappingV4Config {
    pub mapping_pair_ports: Vec<StaticMapPair>,
    pub lan_ipv4: Ipv4Addr,
    pub l4_protocols: Vec<u8>,
}
