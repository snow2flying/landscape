use std::collections::HashMap;
use std::fmt;
use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};

use crate::database::repository::LandscapeDBStore;
use crate::dhcp::v6_server::config::DHCPv6ServerConfig;
use crate::iface::config::{ServiceKind, ZoneAwareConfig, ZoneRequirement};
use crate::ipv6::ra::RouterFlags;
use crate::ipv6_pd::LDIAPrefix;
use crate::service::ServiceConfigError;
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum PrefixParentSource {
    Static {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        base_prefix: Ipv6Addr,
        parent_prefix_len: u8,
    },
    Pd {
        depend_iface: String,
        planned_parent_prefix_len: u8,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RaPrefixConfig {
    pub pool_index: u32,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NaPrefixConfig {
    pub pool_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PdPrefixRangeConfig {
    pub pool_len: u8,
    pub start_index: u32,
    pub end_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LanPrefixGroupConfig {
    pub group_id: String,
    pub parent: PrefixParentSource,
    #[serde(default)]
    pub ra: Option<RaPrefixConfig>,
    #[serde(default)]
    pub na: Option<NaPrefixConfig>,
    #[serde(default)]
    pub pd: Option<PdPrefixRangeConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrefixGroupParentKey {
    Static(Ipv6Addr, u8),
    Pd(String, u8),
}

type PrefixInfoMap = HashMap<String, Option<LDIAPrefix>>;

fn normalize_ipv6_prefix(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let value = u128::from_be_bytes(addr.octets());
    let masked = if prefix_len == 0 {
        0
    } else if prefix_len >= 128 {
        value
    } else {
        let mask = (!0u128) << (128 - prefix_len as u32);
        value & mask
    };
    Ipv6Addr::from(masked.to_be_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExpandedParentKey {
    Static(Ipv6Addr, u8),
    PdActual(Ipv6Addr, u8),
    PdFallback(String, u8),
}

impl PrefixParentSource {
    pub fn parent_key(&self) -> PrefixGroupParentKey {
        match self {
            PrefixParentSource::Static { base_prefix, parent_prefix_len } => {
                PrefixGroupParentKey::Static(*base_prefix, *parent_prefix_len)
            }
            PrefixParentSource::Pd { depend_iface, planned_parent_prefix_len } => {
                PrefixGroupParentKey::Pd(depend_iface.clone(), *planned_parent_prefix_len)
            }
        }
    }

    pub fn parent_prefix_len(&self) -> u8 {
        match self {
            PrefixParentSource::Static { parent_prefix_len, .. } => *parent_prefix_len,
            PrefixParentSource::Pd { planned_parent_prefix_len, .. } => *planned_parent_prefix_len,
        }
    }

    pub fn resolved_parent_prefix_len(&self, prefix_infos: Option<&PrefixInfoMap>) -> u8 {
        match self {
            PrefixParentSource::Static { parent_prefix_len, .. } => *parent_prefix_len,
            PrefixParentSource::Pd { depend_iface, planned_parent_prefix_len } => prefix_infos
                .and_then(|infos| infos.get(depend_iface))
                .and_then(|prefix| prefix.as_ref())
                .map(|prefix| prefix.prefix_len)
                .unwrap_or(*planned_parent_prefix_len),
        }
    }

    pub fn expanded_parent_key(&self, prefix_infos: Option<&PrefixInfoMap>) -> ExpandedParentKey {
        match self {
            PrefixParentSource::Static { base_prefix, parent_prefix_len } => {
                ExpandedParentKey::Static(*base_prefix, *parent_prefix_len)
            }
            PrefixParentSource::Pd { depend_iface, planned_parent_prefix_len } => {
                if let Some(prefix) = prefix_infos
                    .and_then(|infos| infos.get(depend_iface))
                    .and_then(|prefix| prefix.as_ref())
                {
                    ExpandedParentKey::PdActual(
                        normalize_ipv6_prefix(prefix.prefix_ip, prefix.prefix_len),
                        prefix.prefix_len,
                    )
                } else {
                    ExpandedParentKey::PdFallback(depend_iface.clone(), *planned_parent_prefix_len)
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParentPrefixKey {
    Static(Ipv6Addr),
    Pd(String),
}

impl fmt::Display for ParentPrefixKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParentPrefixKey::Static(addr) => write!(f, "static({})", addr),
            ParentPrefixKey::Pd(iface) => write!(f, "pd({})", iface),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum LanIPv6SourceConfig {
    RaStatic {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        base_prefix: Ipv6Addr,
        pool_index: u32,
        preferred_lifetime: u32,
        valid_lifetime: u32,
    },
    RaPd {
        depend_iface: String,
        pool_index: u32,
        preferred_lifetime: u32,
        valid_lifetime: u32,
    },
    NaStatic {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        base_prefix: Ipv6Addr,
        pool_index: u32,
    },
    NaPd {
        depend_iface: String,
        pool_index: u32,
    },
    PdStatic {
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        base_prefix: Ipv6Addr,
        base_prefix_len: u8,
        pool_index: u32,
        pool_len: u8,
    },
    PdPd {
        depend_iface: String,
        max_source_prefix_len: u8,
        pool_index: u32,
        pool_len: u8,
    },
}

impl LanIPv6SourceConfig {
    pub fn parent_key(&self) -> ParentPrefixKey {
        match self {
            LanIPv6SourceConfig::RaStatic { base_prefix, .. }
            | LanIPv6SourceConfig::NaStatic { base_prefix, .. } => {
                ParentPrefixKey::Static(*base_prefix)
            }
            LanIPv6SourceConfig::PdStatic { base_prefix, .. } => {
                ParentPrefixKey::Static(*base_prefix)
            }
            LanIPv6SourceConfig::RaPd { depend_iface, .. }
            | LanIPv6SourceConfig::NaPd { depend_iface, .. }
            | LanIPv6SourceConfig::PdPd { depend_iface, .. } => {
                ParentPrefixKey::Pd(depend_iface.clone())
            }
        }
    }

    pub fn service_kind(&self) -> SourceServiceKind {
        match self {
            LanIPv6SourceConfig::RaStatic { .. } | LanIPv6SourceConfig::RaPd { .. } => {
                SourceServiceKind::Ra
            }
            LanIPv6SourceConfig::NaStatic { .. } | LanIPv6SourceConfig::NaPd { .. } => {
                SourceServiceKind::Na
            }
            LanIPv6SourceConfig::PdStatic { .. } | LanIPv6SourceConfig::PdPd { .. } => {
                SourceServiceKind::IaPd
            }
        }
    }

    pub fn pool_index(&self) -> u32 {
        match self {
            LanIPv6SourceConfig::RaStatic { pool_index, .. }
            | LanIPv6SourceConfig::RaPd { pool_index, .. }
            | LanIPv6SourceConfig::NaStatic { pool_index, .. }
            | LanIPv6SourceConfig::NaPd { pool_index, .. }
            | LanIPv6SourceConfig::PdStatic { pool_index, .. }
            | LanIPv6SourceConfig::PdPd { pool_index, .. } => *pool_index,
        }
    }

    pub fn pool_len(&self) -> u8 {
        match self {
            LanIPv6SourceConfig::RaStatic { .. }
            | LanIPv6SourceConfig::RaPd { .. }
            | LanIPv6SourceConfig::NaStatic { .. }
            | LanIPv6SourceConfig::NaPd { .. } => 64,
            LanIPv6SourceConfig::PdStatic { pool_len, .. }
            | LanIPv6SourceConfig::PdPd { pool_len, .. } => *pool_len,
        }
    }

    pub fn is_static(&self) -> bool {
        matches!(
            self,
            LanIPv6SourceConfig::RaStatic { .. }
                | LanIPv6SourceConfig::NaStatic { .. }
                | LanIPv6SourceConfig::PdStatic { .. }
        )
    }

    pub fn base_prefix(&self) -> Option<Ipv6Addr> {
        match self {
            LanIPv6SourceConfig::RaStatic { base_prefix, .. }
            | LanIPv6SourceConfig::NaStatic { base_prefix, .. }
            | LanIPv6SourceConfig::PdStatic { base_prefix, .. } => Some(*base_prefix),
            _ => None,
        }
    }

    pub fn depend_iface(&self) -> Option<&str> {
        match self {
            LanIPv6SourceConfig::RaPd { depend_iface, .. }
            | LanIPv6SourceConfig::NaPd { depend_iface, .. }
            | LanIPv6SourceConfig::PdPd { depend_iface, .. } => Some(depend_iface),
            _ => None,
        }
    }
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

fn legacy_source_parent(source: &LanIPv6SourceConfig) -> PrefixParentSource {
    match source {
        LanIPv6SourceConfig::RaStatic { base_prefix, .. }
        | LanIPv6SourceConfig::NaStatic { base_prefix, .. } => {
            PrefixParentSource::Static { base_prefix: *base_prefix, parent_prefix_len: 60 }
        }
        LanIPv6SourceConfig::PdStatic { base_prefix, base_prefix_len, .. } => {
            PrefixParentSource::Static {
                base_prefix: *base_prefix,
                parent_prefix_len: *base_prefix_len,
            }
        }
        LanIPv6SourceConfig::RaPd { depend_iface, .. }
        | LanIPv6SourceConfig::NaPd { depend_iface, .. } => PrefixParentSource::Pd {
            depend_iface: depend_iface.clone(),
            planned_parent_prefix_len: 60,
        },
        LanIPv6SourceConfig::PdPd { depend_iface, max_source_prefix_len, .. } => {
            PrefixParentSource::Pd {
                depend_iface: depend_iface.clone(),
                planned_parent_prefix_len: *max_source_prefix_len,
            }
        }
    }
}

fn legacy_source_group_id(index: usize, source: &LanIPv6SourceConfig) -> String {
    let kind = match source.service_kind() {
        SourceServiceKind::Ra => "ra",
        SourceServiceKind::Na => "na",
        SourceServiceKind::IaPd => "pd",
    };

    let base = match legacy_source_parent(source) {
        PrefixParentSource::Static { base_prefix, parent_prefix_len } => {
            format!("legacy:static:{}:{}/{}", kind, base_prefix, parent_prefix_len)
        }
        PrefixParentSource::Pd { depend_iface, planned_parent_prefix_len } => {
            format!("legacy:pd:{}:{}/{}", kind, depend_iface, planned_parent_prefix_len)
        }
    };

    format!("{}:{}", base.replace("//", "/"), index)
}

fn legacy_source_to_group(index: usize, source: &LanIPv6SourceConfig) -> LanPrefixGroupConfig {
    let (ra, na, pd) = match source {
        LanIPv6SourceConfig::RaStatic {
            pool_index, preferred_lifetime, valid_lifetime, ..
        }
        | LanIPv6SourceConfig::RaPd { pool_index, preferred_lifetime, valid_lifetime, .. } => (
            Some(RaPrefixConfig {
                pool_index: *pool_index,
                preferred_lifetime: *preferred_lifetime,
                valid_lifetime: *valid_lifetime,
            }),
            None,
            None,
        ),
        LanIPv6SourceConfig::NaStatic { pool_index, .. }
        | LanIPv6SourceConfig::NaPd { pool_index, .. } => {
            (None, Some(NaPrefixConfig { pool_index: *pool_index }), None)
        }
        LanIPv6SourceConfig::PdStatic { pool_index, pool_len, .. }
        | LanIPv6SourceConfig::PdPd { pool_index, pool_len, .. } => (
            None,
            None,
            Some(PdPrefixRangeConfig {
                pool_len: *pool_len,
                start_index: *pool_index,
                end_index: *pool_index,
            }),
        ),
    };

    LanPrefixGroupConfig {
        group_id: legacy_source_group_id(index, source),
        parent: legacy_source_parent(source),
        ra,
        na,
        pd,
    }
}

impl From<LanIPv6Config> for LanIPv6ConfigV2 {
    fn from(value: LanIPv6Config) -> Self {
        let prefix_groups = value
            .sources
            .iter()
            .enumerate()
            .map(|(index, source)| legacy_source_to_group(index, source))
            .collect();

        Self {
            mode: value.mode,
            ad_interval: value.ad_interval,
            ra_flag: value.ra_flag,
            prefix_groups,
            dhcpv6: value.dhcpv6,
        }
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

fn ra_flag_default() -> RouterFlags {
    0xc0.into()
}

fn is_ula(addr: Ipv6Addr) -> bool {
    let first_byte = addr.octets()[0];
    (first_byte & 0xfe) == 0xfc
}

fn blocks_overlap(_parent_prefix_len: u8, idx_a: u64, len_a: u8, idx_b: u64, len_b: u8) -> bool {
    let max_len = len_a.max(len_b);
    let scale_a = 1u64 << (max_len - len_a) as u64;
    let start_a = idx_a * scale_a;
    let end_a = start_a + scale_a;
    let scale_b = 1u64 << (max_len - len_b) as u64;
    let start_b = idx_b * scale_b;
    let end_b = start_b + scale_b;
    start_a < end_b && start_b < end_a
}

fn range_blocks_overlap(start_a: u64, end_a: u64, start_b: u64, end_b: u64) -> bool {
    start_a <= end_b && start_b <= end_a
}

#[derive(Debug, Clone)]
pub struct ExpandedPrefixEntry {
    pub parent: ExpandedParentKey,
    pub parent_prefix_len: u8,
    pub service_kind: PrefixGroupServiceKind,
    pub start_index: u32,
    pub end_index: u32,
    pub pool_len: u8,
}

impl ExpandedPrefixEntry {
    pub fn is_dynamic(&self) -> bool {
        matches!(self.parent, ExpandedParentKey::PdActual(..) | ExpandedParentKey::PdFallback(..))
    }

    pub fn effective_index_range(&self, _is_dynamic: bool) -> (u64, u64) {
        let start = self.start_index as u64;
        let end = self.end_index as u64;
        (start, end)
    }
}

impl LanPrefixGroupConfig {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        self.validate_with_prefix_infos(None)
    }

    pub fn validate_with_prefix_infos(
        &self,
        prefix_infos: Option<&PrefixInfoMap>,
    ) -> Result<(), ServiceConfigError> {
        if self.group_id.trim().is_empty() {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "Prefix group id must not be empty".to_string(),
            });
        }

        match &self.parent {
            PrefixParentSource::Static { parent_prefix_len, .. } => {
                if *parent_prefix_len == 0 || *parent_prefix_len > 127 {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!(
                            "Static parent_prefix_len ({}) must be between 1 and 127",
                            parent_prefix_len
                        ),
                    });
                }
            }
            PrefixParentSource::Pd { planned_parent_prefix_len, .. } => {
                if *planned_parent_prefix_len == 0 || *planned_parent_prefix_len > 127 {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!(
                            "PD planned_parent_prefix_len ({}) must be between 1 and 127",
                            planned_parent_prefix_len
                        ),
                    });
                }
            }
        }

        if let Some(pd) = &self.pd {
            if pd.pool_len == 0 || pd.pool_len > 128 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("PD pool_len ({}) must be between 1 and 128", pd.pool_len),
                });
            }
            if pd.end_index < pd.start_index {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "PD range end_index ({}) must be >= start_index ({})",
                        pd.end_index, pd.start_index
                    ),
                });
            }
        }

        let parent_len = self.parent.resolved_parent_prefix_len(prefix_infos);
        let is_pd_parent = matches!(self.parent, PrefixParentSource::Pd { .. });
        if let Some(ra) = &self.ra {
            if is_pd_parent && ra.pool_index == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "RA pool_index ({}) must be >= 1 when parent is PD-derived (subnet 0 is reserved for WAN)",
                        ra.pool_index
                    ),
                });
            }
            if 64 <= parent_len {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "RA requires parent_prefix_len ({}) to be less than 64",
                        parent_len
                    ),
                });
            }
            if !self.group_has_capacity(ra.pool_index, ra.pool_index, 64, parent_len) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("RA pool_index ({}) exceeds available capacity", ra.pool_index),
                });
            }
        }
        if let Some(na) = &self.na {
            if is_pd_parent && na.pool_index == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_NA pool_index ({}) must be >= 1 when parent is PD-derived (subnet 0 is reserved for WAN)",
                        na.pool_index
                    ),
                });
            }
            if 64 <= parent_len {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_NA requires parent_prefix_len ({}) to be less than 64",
                        parent_len
                    ),
                });
            }
            if !self.group_has_capacity(na.pool_index, na.pool_index, 64, parent_len) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_NA pool_index ({}) exceeds available capacity",
                        na.pool_index
                    ),
                });
            }
        }
        if let Some(pd) = &self.pd {
            if is_pd_parent && pd.start_index == 0 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_PD start_index ({}) must be >= 1 when parent is PD-derived (subnet 0 is reserved for WAN)",
                        pd.start_index
                    ),
                });
            }
            if pd.pool_len <= parent_len {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_PD pool_len ({}) must be greater than parent_prefix_len ({})",
                        pd.pool_len, parent_len
                    ),
                });
            }
            if !self.group_has_capacity(pd.start_index, pd.end_index, pd.pool_len, parent_len) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "IA_PD range {}-{} exceeds available capacity for pool_len /{}",
                        pd.start_index, pd.end_index, pd.pool_len
                    ),
                });
            }
        }

        Ok(())
    }

    fn group_has_capacity(
        &self,
        start_index: u32,
        end_index: u32,
        target_len: u8,
        parent_len: u8,
    ) -> bool {
        if target_len <= parent_len {
            return false;
        }
        let max_blocks = 1u64.checked_shl((target_len - parent_len) as u32).unwrap_or(u64::MAX);
        (end_index as u64) < max_blocks && start_index <= end_index
    }

    pub fn active_entries(&self, mode: IPv6ServiceMode) -> Vec<ExpandedPrefixEntry> {
        self.active_entries_with_prefix_infos(mode, None)
    }

    pub fn active_entries_with_prefix_infos(
        &self,
        mode: IPv6ServiceMode,
        prefix_infos: Option<&PrefixInfoMap>,
    ) -> Vec<ExpandedPrefixEntry> {
        let mut result = Vec::new();
        let parent = self.parent.expanded_parent_key(prefix_infos);
        let parent_prefix_len = self.parent.resolved_parent_prefix_len(prefix_infos);
        let include_ra = matches!(mode, IPv6ServiceMode::Slaac | IPv6ServiceMode::SlaacDhcpv6);
        let include_na = matches!(mode, IPv6ServiceMode::Stateful | IPv6ServiceMode::SlaacDhcpv6);
        let include_pd = matches!(mode, IPv6ServiceMode::Stateful | IPv6ServiceMode::SlaacDhcpv6);

        if include_ra {
            if let Some(ra) = &self.ra {
                result.push(ExpandedPrefixEntry {
                    parent: parent.clone(),
                    parent_prefix_len,
                    service_kind: PrefixGroupServiceKind::Ra,
                    start_index: ra.pool_index,
                    end_index: ra.pool_index,
                    pool_len: 64,
                });
            }
        }
        if include_na {
            if let Some(na) = &self.na {
                result.push(ExpandedPrefixEntry {
                    parent: parent.clone(),
                    parent_prefix_len,
                    service_kind: PrefixGroupServiceKind::Na,
                    start_index: na.pool_index,
                    end_index: na.pool_index,
                    pool_len: 64,
                });
            }
        }
        if include_pd {
            if let Some(pd) = &self.pd {
                result.push(ExpandedPrefixEntry {
                    parent,
                    parent_prefix_len,
                    service_kind: PrefixGroupServiceKind::IaPd,
                    start_index: pd.start_index,
                    end_index: pd.end_index,
                    pool_len: pd.pool_len,
                });
            }
        }
        result
    }
}

pub fn validate_prefix_groups(groups: &[LanPrefixGroupConfig]) -> Result<(), ServiceConfigError> {
    validate_prefix_groups_with_prefix_infos(groups, None)
}

pub fn validate_prefix_groups_with_prefix_infos(
    groups: &[LanPrefixGroupConfig],
    prefix_infos: Option<&PrefixInfoMap>,
) -> Result<(), ServiceConfigError> {
    let expanded_groups: Vec<Vec<ExpandedPrefixEntry>> = groups
        .iter()
        .map(|group| {
            group.validate_with_prefix_infos(prefix_infos)?;

            let entries =
                group.active_entries_with_prefix_infos(IPv6ServiceMode::SlaacDhcpv6, prefix_infos);
            for i in 0..entries.len() {
                for j in (i + 1)..entries.len() {
                    validate_expanded_pair(
                        &entries[i],
                        &entries[j],
                        entries[i].parent_prefix_len,
                        true,
                    )?;
                }
            }

            Ok(entries)
        })
        .collect::<Result<_, ServiceConfigError>>()?;

    for i in 0..expanded_groups.len() {
        for j in (i + 1)..expanded_groups.len() {
            let left_entries = &expanded_groups[i];
            let right_entries = &expanded_groups[j];

            for left in left_entries {
                for right in right_entries {
                    if left.parent != right.parent {
                        continue;
                    }
                    validate_expanded_pair(left, right, left.parent_prefix_len, false)?;
                }
            }
        }
    }

    Ok(())
}

fn validate_expanded_pair(
    a: &ExpandedPrefixEntry,
    b: &ExpandedPrefixEntry,
    parent_len: u8,
    allow_ra_na_share: bool,
) -> Result<(), ServiceConfigError> {
    if allow_ra_na_share
        && matches!(
            (a.service_kind, b.service_kind),
            (PrefixGroupServiceKind::Ra, PrefixGroupServiceKind::Na)
                | (PrefixGroupServiceKind::Na, PrefixGroupServiceKind::Ra)
        )
    {
        return Ok(());
    }

    let dynamic = a.is_dynamic();
    let (start_a, end_a) = a.effective_index_range(dynamic);
    let (start_b, end_b) = b.effective_index_range(dynamic);

    if a.service_kind == PrefixGroupServiceKind::IaPd
        && b.service_kind == PrefixGroupServiceKind::IaPd
    {
        if range_blocks_overlap(start_a, end_a, start_b, end_b) {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "IA_PD ranges conflict under the same parent prefix".to_string(),
            });
        }
        return Ok(());
    }

    if a.service_kind == PrefixGroupServiceKind::IaPd {
        for idx in start_a..=end_a {
            if blocks_overlap(parent_len, idx, a.pool_len, start_b, b.pool_len) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "Prefix group results conflict under the same parent prefix"
                        .to_string(),
                });
            }
        }
        return Ok(());
    }

    if b.service_kind == PrefixGroupServiceKind::IaPd {
        for idx in start_b..=end_b {
            if blocks_overlap(parent_len, start_a, a.pool_len, idx, b.pool_len) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "Prefix group results conflict under the same parent prefix"
                        .to_string(),
                });
            }
        }
        return Ok(());
    }

    if blocks_overlap(parent_len, start_a, a.pool_len, start_b, b.pool_len) {
        return Err(ServiceConfigError::InvalidConfig {
            reason: "Prefix group results conflict under the same parent prefix".to_string(),
        });
    }

    Ok(())
}

fn effective_pool_index(src: &LanIPv6SourceConfig) -> u64 {
    src.pool_index() as u64
}

impl LanIPv6Config {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        for src in &self.sources {
            validate_source_entry(src)?;
        }

        let active_sources = self.active_sources();
        validate_sources_no_conflict(&active_sources)?;

        match self.mode {
            IPv6ServiceMode::Slaac => self.validate_slaac(),
            IPv6ServiceMode::Stateful => self.validate_stateful(),
            IPv6ServiceMode::SlaacDhcpv6 => self.validate_slaac_dhcpv6(),
        }
    }

    pub fn active_sources(&self) -> Vec<LanIPv6SourceConfig> {
        self.sources
            .iter()
            .filter(|s| match self.mode {
                IPv6ServiceMode::Slaac => s.service_kind() == SourceServiceKind::Ra,
                IPv6ServiceMode::Stateful => {
                    s.service_kind() == SourceServiceKind::Na
                        || s.service_kind() == SourceServiceKind::IaPd
                }
                IPv6ServiceMode::SlaacDhcpv6 => true,
            })
            .cloned()
            .collect()
    }

    fn validate_slaac(&self) -> Result<(), ServiceConfigError> {
        let ra_count =
            self.sources.iter().filter(|s| s.service_kind() == SourceServiceKind::Ra).count();
        if ra_count == 0 {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "Slaac mode requires at least one RA prefix source".to_string(),
            });
        }
        if self.ra_flag.managed_address_config {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "Slaac mode requires M flag to be 0".to_string(),
            });
        }
        if let Some(dhcpv6) = &self.dhcpv6 {
            if dhcpv6.enable {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: "Slaac mode does not allow DHCPv6 to be enabled".to_string(),
                });
            }
        }
        Ok(())
    }

    fn validate_stateful(&self) -> Result<(), ServiceConfigError> {
        if !self.ra_flag.managed_address_config || !self.ra_flag.other_config {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "Stateful mode requires M=1 and O=1".to_string(),
            });
        }
        let na_count =
            self.sources.iter().filter(|s| s.service_kind() == SourceServiceKind::Na).count();
        if na_count == 0 {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "Stateful mode requires at least one DHCPv6 NA prefix source".to_string(),
            });
        }
        let dhcpv6 = self.dhcpv6.as_ref().ok_or(ServiceConfigError::InvalidConfig {
            reason: "Stateful mode requires DHCPv6 configuration".to_string(),
        })?;
        if !dhcpv6.enable {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "Stateful mode requires DHCPv6 to be enabled".to_string(),
            });
        }
        dhcpv6.validate()?;
        Ok(())
    }

    fn validate_slaac_dhcpv6(&self) -> Result<(), ServiceConfigError> {
        if !self.ra_flag.managed_address_config || !self.ra_flag.other_config {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "SlaacDhcpv6 mode requires M=1 and O=1".to_string(),
            });
        }
        let ra_sources: Vec<_> =
            self.sources.iter().filter(|s| s.service_kind() == SourceServiceKind::Ra).collect();
        if ra_sources.is_empty() {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "SlaacDhcpv6 mode requires at least one RA prefix source".to_string(),
            });
        }
        for src in &ra_sources {
            match src {
                LanIPv6SourceConfig::RaStatic { base_prefix, .. } => {
                    if !is_ula(*base_prefix) {
                        return Err(ServiceConfigError::InvalidConfig {
                            reason: format!(
                                "SlaacDhcpv6 mode requires RA sources to be ULA (fc00::/7), got: {}",
                                base_prefix
                            ),
                        });
                    }
                }
                LanIPv6SourceConfig::RaPd { .. } => {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "SlaacDhcpv6 mode only allows Static RA sources".to_string(),
                    });
                }
                _ => {}
            }
        }
        let dhcpv6_source_count = self
            .sources
            .iter()
            .filter(|s| {
                s.service_kind() == SourceServiceKind::Na
                    || s.service_kind() == SourceServiceKind::IaPd
            })
            .count();
        if dhcpv6_source_count == 0 {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "SlaacDhcpv6 mode requires at least one DHCPv6 prefix source (Na or Pd)"
                    .to_string(),
            });
        }
        let dhcpv6 = self.dhcpv6.as_ref().ok_or(ServiceConfigError::InvalidConfig {
            reason: "SlaacDhcpv6 mode requires DHCPv6 configuration".to_string(),
        })?;
        if !dhcpv6.enable {
            return Err(ServiceConfigError::InvalidConfig {
                reason: "SlaacDhcpv6 mode requires DHCPv6 to be enabled".to_string(),
            });
        }
        dhcpv6.validate()?;
        Ok(())
    }

    pub fn sources_by_kind(&self, kind: SourceServiceKind) -> Vec<&LanIPv6SourceConfig> {
        self.sources.iter().filter(|s| s.service_kind() == kind).collect()
    }

    pub fn new(depend_iface: String) -> Self {
        let sources = vec![LanIPv6SourceConfig::RaPd {
            depend_iface,
            pool_index: 0,
            preferred_lifetime: 300,
            valid_lifetime: 300,
        }];
        Self {
            mode: IPv6ServiceMode::Slaac,
            sources,
            ra_flag: ra_flag_default(),
            ad_interval: 300,
            dhcpv6: None,
        }
    }
}

impl LanIPv6ConfigV2 {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        self.validate_with_prefix_infos(None)
    }

    pub fn validate_with_prefix_infos(
        &self,
        prefix_infos: Option<&PrefixInfoMap>,
    ) -> Result<(), ServiceConfigError> {
        validate_prefix_groups_with_prefix_infos(&self.prefix_groups, prefix_infos)?;

        match self.mode {
            IPv6ServiceMode::Slaac => {
                if !self.prefix_groups.iter().any(|group| group.ra.is_some()) {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "Slaac mode requires at least one RA prefix group".to_string(),
                    });
                }
                if self.ra_flag.managed_address_config {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "Slaac mode requires M flag to be 0".to_string(),
                    });
                }
                if let Some(dhcpv6) = &self.dhcpv6 {
                    if dhcpv6.enable {
                        return Err(ServiceConfigError::InvalidConfig {
                            reason: "Slaac mode does not allow DHCPv6 to be enabled".to_string(),
                        });
                    }
                }
            }
            IPv6ServiceMode::Stateful => {
                if !self.prefix_groups.iter().any(|group| group.na.is_some()) {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "Stateful mode requires at least one IA_NA prefix group"
                            .to_string(),
                    });
                }
                if !self.ra_flag.managed_address_config || !self.ra_flag.other_config {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "Stateful mode requires M=1 and O=1".to_string(),
                    });
                }
                let dhcpv6 = self.dhcpv6.as_ref().ok_or(ServiceConfigError::InvalidConfig {
                    reason: "Stateful mode requires DHCPv6 configuration".to_string(),
                })?;
                if !dhcpv6.enable {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "Stateful mode requires DHCPv6 to be enabled".to_string(),
                    });
                }
                dhcpv6.validate()?;
            }
            IPv6ServiceMode::SlaacDhcpv6 => {
                let ra_groups: Vec<_> =
                    self.prefix_groups.iter().filter(|group| group.ra.is_some()).collect();
                if ra_groups.is_empty() {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "SlaacDhcpv6 mode requires at least one RA prefix group"
                            .to_string(),
                    });
                }
                for group in &ra_groups {
                    match &group.parent {
                        PrefixParentSource::Static { base_prefix, .. } => {
                            if !is_ula(*base_prefix) {
                                return Err(ServiceConfigError::InvalidConfig {
                                    reason: format!(
                                        "SlaacDhcpv6 mode requires RA prefix groups to be ULA (fc00::/7), got: {}",
                                        base_prefix
                                    ),
                                });
                            }
                        }
                        PrefixParentSource::Pd { .. } => {
                            return Err(ServiceConfigError::InvalidConfig {
                                reason: "SlaacDhcpv6 mode only allows Static RA prefix groups"
                                    .to_string(),
                            });
                        }
                    }
                }
                if !self.ra_flag.managed_address_config || !self.ra_flag.other_config {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "SlaacDhcpv6 mode requires M=1 and O=1".to_string(),
                    });
                }
                let dhcpv6_source_count = self
                    .prefix_groups
                    .iter()
                    .filter(|group| group.na.is_some() || group.pd.is_some())
                    .count();
                if dhcpv6_source_count == 0 {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason:
                            "SlaacDhcpv6 mode requires at least one DHCPv6 prefix group (NA or PD)"
                                .to_string(),
                    });
                }
                let dhcpv6 = self.dhcpv6.as_ref().ok_or(ServiceConfigError::InvalidConfig {
                    reason: "SlaacDhcpv6 mode requires DHCPv6 configuration".to_string(),
                })?;
                if !dhcpv6.enable {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: "SlaacDhcpv6 mode requires DHCPv6 to be enabled".to_string(),
                    });
                }
                dhcpv6.validate()?;
            }
        }

        Ok(())
    }

    pub fn active_entries(&self) -> Vec<ExpandedPrefixEntry> {
        self.active_entries_with_prefix_infos(None)
    }

    pub fn active_entries_with_prefix_infos(
        &self,
        prefix_infos: Option<&PrefixInfoMap>,
    ) -> Vec<ExpandedPrefixEntry> {
        self.prefix_groups
            .iter()
            .flat_map(|group| group.active_entries_with_prefix_infos(self.mode, prefix_infos))
            .collect()
    }
}

pub fn validate_cross_interface_v2(
    new_config: &LanIPv6ServiceConfigV2,
    other_configs: &[LanIPv6ServiceConfigV2],
) -> Result<(), ServiceConfigError> {
    validate_cross_interface_v2_with_prefix_infos(new_config, other_configs, None)
}

pub fn validate_cross_interface_v2_with_prefix_infos(
    new_config: &LanIPv6ServiceConfigV2,
    other_configs: &[LanIPv6ServiceConfigV2],
    prefix_infos: Option<&PrefixInfoMap>,
) -> Result<(), ServiceConfigError> {
    let new_entries = new_config.config.active_entries_with_prefix_infos(prefix_infos);

    for other in other_configs {
        if other.iface_name == new_config.iface_name || !other.enable {
            continue;
        }

        for left in &new_entries {
            for right in other.config.active_entries_with_prefix_infos(prefix_infos) {
                if left.parent != right.parent {
                    continue;
                }
                validate_expanded_pair(left, &right, left.parent_prefix_len, false)?;
            }
        }
    }

    Ok(())
}

fn validate_source_entry(src: &LanIPv6SourceConfig) -> Result<(), ServiceConfigError> {
    match src {
        LanIPv6SourceConfig::PdStatic { base_prefix_len, pool_index, pool_len, .. } => {
            if *pool_len <= *base_prefix_len {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "PdStatic pool_len ({}) must be > base_prefix_len ({})",
                        pool_len, base_prefix_len
                    ),
                });
            }
            if *pool_len > 128 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("PdStatic pool_len ({}) must be <= 128", pool_len),
                });
            }
            let max_blocks =
                1u64.checked_shl((*pool_len - *base_prefix_len) as u32).unwrap_or(u64::MAX);
            if (*pool_index as u64) >= max_blocks {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "PdStatic pool_index ({}) exceeds max blocks ({}) for base_prefix_len={}, pool_len={}",
                        pool_index, max_blocks, base_prefix_len, pool_len
                    ),
                });
            }
        }
        LanIPv6SourceConfig::PdPd { pool_len, .. } => {
            if *pool_len == 0 || *pool_len > 128 {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!("PdPd pool_len ({}) must be between 1 and 128", pool_len),
                });
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_sources_no_conflict(
    sources: &[LanIPv6SourceConfig],
) -> Result<(), ServiceConfigError> {
    let mut groups: HashMap<ParentPrefixKey, Vec<&LanIPv6SourceConfig>> = HashMap::new();
    for src in sources {
        groups.entry(src.parent_key()).or_default().push(src);
    }

    for (key, group) in &groups {
        let len = group.len();
        for i in 0..len {
            for j in (i + 1)..len {
                check_pair_conflict(key, group[i], group[j])?;
            }
        }
    }

    Ok(())
}

fn check_pair_conflict(
    key: &ParentPrefixKey,
    a: &LanIPv6SourceConfig,
    b: &LanIPv6SourceConfig,
) -> Result<(), ServiceConfigError> {
    let kind_a = a.service_kind();
    let kind_b = b.service_kind();

    if (kind_a == SourceServiceKind::Ra && kind_b == SourceServiceKind::Na)
        || (kind_a == SourceServiceKind::Na && kind_b == SourceServiceKind::Ra)
    {
        return Ok(());
    }

    let parent_len = get_effective_parent_len(a, b);
    let idx_a = effective_pool_index(a);
    let len_a = a.pool_len();
    let idx_b = effective_pool_index(b);
    let len_b = b.pool_len();

    if blocks_overlap(parent_len, idx_a, len_a, idx_b, len_b) {
        return Err(ServiceConfigError::InvalidConfig {
            reason: format!(
                "Source conflict under parent {}: (pool_index={}, effective_index={}, pool_len={}) overlaps with (pool_index={}, effective_index={}, pool_len={}); PD-derived sources reserve WAN subnet 0",
                key,
                a.pool_index(),
                idx_a,
                len_a,
                b.pool_index(),
                idx_b,
                len_b,
            ),
        });
    }

    Ok(())
}

fn get_effective_parent_len(a: &LanIPv6SourceConfig, b: &LanIPv6SourceConfig) -> u8 {
    let len_a = match a {
        LanIPv6SourceConfig::PdStatic { base_prefix_len, .. } => Some(*base_prefix_len),
        LanIPv6SourceConfig::PdPd { max_source_prefix_len, .. } => Some(*max_source_prefix_len),
        _ => None,
    };
    let len_b = match b {
        LanIPv6SourceConfig::PdStatic { base_prefix_len, .. } => Some(*base_prefix_len),
        LanIPv6SourceConfig::PdPd { max_source_prefix_len, .. } => Some(*max_source_prefix_len),
        _ => None,
    };

    match (len_a, len_b) {
        (Some(a), Some(b)) => a.max(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => 0,
    }
}

pub fn validate_cross_interface(
    new_config: &LanIPv6ServiceConfig,
    other_configs: &[LanIPv6ServiceConfig],
) -> Result<(), ServiceConfigError> {
    let new_iface = &new_config.iface_name;
    let new_sources = new_config.config.active_sources();

    for other in other_configs {
        if other.iface_name == *new_iface {
            continue;
        }
        if !other.enable {
            continue;
        }

        let other_active = other.config.active_sources();

        for new_src in &new_sources {
            for other_src in &other_active {
                if new_src.parent_key() != other_src.parent_key() {
                    continue;
                }
                if new_src.is_static() != other_src.is_static() {
                    continue;
                }
                let kind_new = new_src.service_kind();
                let kind_other = other_src.service_kind();
                if (kind_new == SourceServiceKind::Ra && kind_other == SourceServiceKind::Na)
                    || (kind_new == SourceServiceKind::Na && kind_other == SourceServiceKind::Ra)
                {
                    continue;
                }
                let parent_len = get_effective_parent_len(new_src, other_src);
                if blocks_overlap(
                    parent_len,
                    effective_pool_index(new_src),
                    new_src.pool_len(),
                    effective_pool_index(other_src),
                    other_src.pool_len(),
                ) {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!(
                            "Cross-interface conflict: {} source (pool_index={}, effective_index={}, pool_len={}) on '{}' overlaps with (pool_index={}, effective_index={}, pool_len={}) on '{}'; PD-derived sources reserve WAN subnet 0",
                            new_src.parent_key(),
                            new_src.pool_index(),
                            effective_pool_index(new_src),
                            new_src.pool_len(),
                            new_iface,
                            other_src.pool_index(),
                            effective_pool_index(other_src),
                            other_src.pool_len(),
                            other.iface_name,
                        ),
                    });
                }
            }
        }
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_ra_na_same_index_ok() {
        let sources = vec![
            LanIPv6SourceConfig::RaStatic {
                base_prefix: "fd00::".parse().unwrap(),
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            },
            LanIPv6SourceConfig::NaStatic {
                base_prefix: "fd00::".parse().unwrap(),
                pool_index: 1,
            },
        ];
        assert!(validate_sources_no_conflict(&sources).is_ok());
    }

    #[test]
    fn static_ra_ra_same_index_conflict() {
        let sources = vec![
            LanIPv6SourceConfig::RaStatic {
                base_prefix: "fd00::".parse().unwrap(),
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            },
            LanIPv6SourceConfig::RaStatic {
                base_prefix: "fd00::".parse().unwrap(),
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            },
        ];
        assert!(validate_sources_no_conflict(&sources).is_err());
    }

    #[test]
    fn static_na_na_same_index_conflict() {
        let sources = vec![
            LanIPv6SourceConfig::NaStatic {
                base_prefix: "fd00::".parse().unwrap(),
                pool_index: 1,
            },
            LanIPv6SourceConfig::NaStatic {
                base_prefix: "fd00::".parse().unwrap(),
                pool_index: 1,
            },
        ];
        assert!(validate_sources_no_conflict(&sources).is_err());
    }

    #[test]
    fn static_ra_pd_block_overlap() {
        let sources = vec![
            LanIPv6SourceConfig::RaStatic {
                base_prefix: "fd00::".parse().unwrap(),
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            },
            LanIPv6SourceConfig::PdStatic {
                base_prefix: "fd00::".parse().unwrap(),
                base_prefix_len: 48,
                pool_index: 0,
                pool_len: 62,
            },
        ];
        assert!(validate_sources_no_conflict(&sources).is_err());
    }

    #[test]
    fn static_pd_same_block_conflict() {
        let sources = vec![
            LanIPv6SourceConfig::PdStatic {
                base_prefix: "fd00::".parse().unwrap(),
                base_prefix_len: 48,
                pool_index: 0,
                pool_len: 62,
            },
            LanIPv6SourceConfig::PdStatic {
                base_prefix: "fd00::".parse().unwrap(),
                base_prefix_len: 48,
                pool_index: 0,
                pool_len: 62,
            },
        ];
        assert!(validate_sources_no_conflict(&sources).is_err());
    }

    #[test]
    fn static_pd_adjacent_blocks_ok() {
        let sources = vec![
            LanIPv6SourceConfig::PdStatic {
                base_prefix: "fd00::".parse().unwrap(),
                base_prefix_len: 48,
                pool_index: 0,
                pool_len: 62,
            },
            LanIPv6SourceConfig::PdStatic {
                base_prefix: "fd00::".parse().unwrap(),
                base_prefix_len: 48,
                pool_index: 1,
                pool_len: 62,
            },
        ];
        assert!(validate_sources_no_conflict(&sources).is_ok());
    }

    #[test]
    fn pd_ra_na_same_index_ok() {
        let sources = vec![
            LanIPv6SourceConfig::RaPd {
                depend_iface: "eth0".to_string(),
                pool_index: 0,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            },
            LanIPv6SourceConfig::NaPd { depend_iface: "eth0".to_string(), pool_index: 0 },
        ];
        assert!(validate_sources_no_conflict(&sources).is_ok());
    }

    #[test]
    fn pd_ra_index_inside_pd_block_conflict() {
        let sources = vec![
            LanIPv6SourceConfig::RaPd {
                depend_iface: "eth0".to_string(),
                pool_index: 3,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            },
            LanIPv6SourceConfig::PdPd {
                depend_iface: "eth0".to_string(),
                max_source_prefix_len: 56,
                pool_index: 0,
                pool_len: 62,
            },
        ];
        assert!(validate_sources_no_conflict(&sources).is_err());
    }

    #[test]
    fn pd_pd_adjacent_blocks_ok() {
        let sources = vec![
            LanIPv6SourceConfig::PdPd {
                depend_iface: "eth0".to_string(),
                max_source_prefix_len: 56,
                pool_index: 0,
                pool_len: 62,
            },
            LanIPv6SourceConfig::PdPd {
                depend_iface: "eth0".to_string(),
                max_source_prefix_len: 56,
                pool_index: 1,
                pool_len: 62,
            },
        ];
        assert!(validate_sources_no_conflict(&sources).is_ok());
    }

    #[test]
    fn pd_pd_different_pool_len_overlap() {
        let sources = vec![
            LanIPv6SourceConfig::PdPd {
                depend_iface: "eth0".to_string(),
                max_source_prefix_len: 56,
                pool_index: 0,
                pool_len: 62,
            },
            LanIPv6SourceConfig::PdPd {
                depend_iface: "eth0".to_string(),
                max_source_prefix_len: 56,
                pool_index: 1,
                pool_len: 63,
            },
        ];
        assert!(validate_sources_no_conflict(&sources).is_err());
    }

    #[test]
    fn pd_pd_different_pool_len_no_overlap() {
        let sources = vec![
            LanIPv6SourceConfig::PdPd {
                depend_iface: "eth0".to_string(),
                max_source_prefix_len: 56,
                pool_index: 0,
                pool_len: 62,
            },
            LanIPv6SourceConfig::PdPd {
                depend_iface: "eth0".to_string(),
                max_source_prefix_len: 56,
                pool_index: 7,
                pool_len: 64,
            },
        ];
        assert!(validate_sources_no_conflict(&sources).is_ok());
    }

    #[test]
    fn static_diff_prefix_same_index_ok() {
        let sources = vec![
            LanIPv6SourceConfig::RaStatic {
                base_prefix: "fd00::".parse().unwrap(),
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            },
            LanIPv6SourceConfig::RaStatic {
                base_prefix: "2001:db8::".parse().unwrap(),
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            },
        ];
        assert!(validate_sources_no_conflict(&sources).is_ok());
    }

    #[test]
    fn pd_diff_iface_same_index_ok() {
        let sources = vec![
            LanIPv6SourceConfig::RaPd {
                depend_iface: "eth0".to_string(),
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            },
            LanIPv6SourceConfig::RaPd {
                depend_iface: "eth1".to_string(),
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            },
        ];
        assert!(validate_sources_no_conflict(&sources).is_ok());
    }

    #[test]
    fn empty_sources_ok() {
        assert!(validate_sources_no_conflict(&[]).is_ok());
    }

    #[test]
    fn single_entry_ok() {
        let sources = vec![LanIPv6SourceConfig::RaStatic {
            base_prefix: "fd00::".parse().unwrap(),
            pool_index: 0,
            preferred_lifetime: 300,
            valid_lifetime: 600,
        }];
        assert!(validate_sources_no_conflict(&sources).is_ok());
    }

    #[test]
    fn pool_len_not_greater_than_parent_len() {
        let src = LanIPv6SourceConfig::PdStatic {
            base_prefix: "fd00::".parse().unwrap(),
            base_prefix_len: 48,
            pool_index: 0,
            pool_len: 48,
        };
        assert!(validate_source_entry(&src).is_err());
    }

    #[test]
    fn pool_len_exceeds_128() {
        let src = LanIPv6SourceConfig::PdStatic {
            base_prefix: "fd00::".parse().unwrap(),
            base_prefix_len: 48,
            pool_index: 0,
            pool_len: 129,
        };
        assert!(validate_source_entry(&src).is_err());
    }

    #[test]
    fn pool_index_out_of_range() {
        let src = LanIPv6SourceConfig::PdStatic {
            base_prefix: "fd00::".parse().unwrap(),
            base_prefix_len: 48,
            pool_index: 16384,
            pool_len: 62,
        };
        assert!(validate_source_entry(&src).is_err());
    }

    fn make_service_config(iface: &str, sources: Vec<LanIPv6SourceConfig>) -> LanIPv6ServiceConfig {
        make_service_config_with_mode(iface, sources, IPv6ServiceMode::SlaacDhcpv6)
    }

    fn make_service_config_with_mode(
        iface: &str,
        sources: Vec<LanIPv6SourceConfig>,
        mode: IPv6ServiceMode,
    ) -> LanIPv6ServiceConfig {
        LanIPv6ServiceConfig {
            iface_name: iface.to_string(),
            enable: true,
            config: LanIPv6Config {
                mode,
                ad_interval: 300,
                ra_flag: ra_flag_default(),
                sources,
                dhcpv6: None,
            },
            update_at: 0.0,
        }
    }

    #[test]
    fn cross_iface_same_pd_same_index_conflict() {
        let new = make_service_config(
            "lan1",
            vec![LanIPv6SourceConfig::RaPd {
                depend_iface: "eth0".to_string(),
                pool_index: 0,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            }],
        );
        let others = vec![make_service_config(
            "lan2",
            vec![LanIPv6SourceConfig::RaPd {
                depend_iface: "eth0".to_string(),
                pool_index: 0,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            }],
        )];
        assert!(validate_cross_interface(&new, &others).is_err());
    }

    #[test]
    fn cross_iface_same_pd_diff_block_ok() {
        let new = make_service_config(
            "lan1",
            vec![LanIPv6SourceConfig::PdPd {
                depend_iface: "eth0".to_string(),
                max_source_prefix_len: 56,
                pool_index: 0,
                pool_len: 62,
            }],
        );
        let others = vec![make_service_config(
            "lan2",
            vec![LanIPv6SourceConfig::PdPd {
                depend_iface: "eth0".to_string(),
                max_source_prefix_len: 56,
                pool_index: 1,
                pool_len: 62,
            }],
        )];
        assert!(validate_cross_interface(&new, &others).is_ok());
    }

    #[test]
    fn cross_iface_diff_pd_same_index_ok() {
        let new = make_service_config(
            "lan1",
            vec![LanIPv6SourceConfig::RaPd {
                depend_iface: "eth0".to_string(),
                pool_index: 0,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            }],
        );
        let others = vec![make_service_config(
            "lan2",
            vec![LanIPv6SourceConfig::RaPd {
                depend_iface: "eth1".to_string(),
                pool_index: 0,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            }],
        )];
        assert!(validate_cross_interface(&new, &others).is_ok());
    }

    #[test]
    fn cross_iface_ra_static_vs_pd_static_overlap() {
        let new = make_service_config(
            "lan1",
            vec![LanIPv6SourceConfig::RaStatic {
                base_prefix: "fd00::".parse().unwrap(),
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            }],
        );
        let others = vec![make_service_config(
            "lan2",
            vec![LanIPv6SourceConfig::PdStatic {
                base_prefix: "fd00::".parse().unwrap(),
                base_prefix_len: 48,
                pool_index: 0,
                pool_len: 62,
            }],
        )];
        assert!(validate_cross_interface(&new, &others).is_err());
    }

    #[test]
    fn test_blocks_overlap_same_index_same_len() {
        assert!(blocks_overlap(48, 0, 64, 0, 64));
    }

    #[test]
    fn test_blocks_overlap_adjacent() {
        assert!(!blocks_overlap(48, 0, 64, 1, 64));
    }

    #[test]
    fn test_blocks_overlap_nested() {
        assert!(blocks_overlap(48, 0, 62, 2, 64));
    }

    #[test]
    fn test_blocks_no_overlap_different_sizes() {
        assert!(!blocks_overlap(48, 0, 62, 4, 64));
    }

    #[test]
    fn legacy_service_config_converts_to_v2() {
        let legacy = make_service_config(
            "lan1",
            vec![
                LanIPv6SourceConfig::RaPd {
                    depend_iface: "eth0".to_string(),
                    pool_index: 1,
                    preferred_lifetime: 300,
                    valid_lifetime: 600,
                },
                LanIPv6SourceConfig::PdStatic {
                    base_prefix: "fd00::".parse().unwrap(),
                    base_prefix_len: 56,
                    pool_index: 2,
                    pool_len: 60,
                },
            ],
        );

        let converted: LanIPv6ServiceConfigV2 = legacy.into();
        assert_eq!(converted.config.prefix_groups.len(), 2);
        assert!(matches!(
            converted.config.prefix_groups[0].parent,
            PrefixParentSource::Pd { planned_parent_prefix_len: 60, .. }
        ));
        assert!(matches!(
            converted.config.prefix_groups[1].parent,
            PrefixParentSource::Static { parent_prefix_len: 56, .. }
        ));
    }

    #[test]
    fn v2_stateful_requires_enabled_dhcpv6() {
        let config = LanIPv6ConfigV2 {
            mode: IPv6ServiceMode::Stateful,
            ad_interval: 300,
            ra_flag: ra_flag_default(),
            prefix_groups: vec![LanPrefixGroupConfig {
                group_id: "stateful-na".to_string(),
                parent: PrefixParentSource::Static {
                    base_prefix: "fd00::".parse().unwrap(),
                    parent_prefix_len: 60,
                },
                ra: None,
                na: Some(NaPrefixConfig { pool_index: 0 }),
                pd: None,
            }],
            dhcpv6: None,
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn v2_slaac_does_not_allow_enabled_dhcpv6() {
        let config = LanIPv6ConfigV2 {
            mode: IPv6ServiceMode::Slaac,
            ad_interval: 300,
            ra_flag: RouterFlags {
                managed_address_config: false,
                other_config: false,
                ..ra_flag_default()
            },
            prefix_groups: vec![LanPrefixGroupConfig {
                group_id: "slaac-ra".to_string(),
                parent: PrefixParentSource::Static {
                    base_prefix: "fd00::".parse().unwrap(),
                    parent_prefix_len: 60,
                },
                ra: Some(RaPrefixConfig {
                    pool_index: 0,
                    preferred_lifetime: 300,
                    valid_lifetime: 600,
                }),
                na: None,
                pd: None,
            }],
            dhcpv6: Some(DHCPv6ServerConfig { enable: true, ..DHCPv6ServerConfig::default() }),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn v2_slaac_dhcpv6_rejects_pd_ra_groups() {
        let config = LanIPv6ConfigV2 {
            mode: IPv6ServiceMode::SlaacDhcpv6,
            ad_interval: 300,
            ra_flag: ra_flag_default(),
            prefix_groups: vec![
                LanPrefixGroupConfig {
                    group_id: "ra-pd".to_string(),
                    parent: PrefixParentSource::Pd {
                        depend_iface: "eth0".to_string(),
                        planned_parent_prefix_len: 60,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index: 1,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: None,
                    pd: None,
                },
                LanPrefixGroupConfig {
                    group_id: "na-static".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: "fd00::".parse().unwrap(),
                        parent_prefix_len: 60,
                    },
                    ra: None,
                    na: Some(NaPrefixConfig { pool_index: 1 }),
                    pd: None,
                },
            ],
            dhcpv6: Some(DHCPv6ServerConfig {
                enable: true,
                ia_na: Some(crate::dhcp::v6_server::config::DHCPv6IANAConfig {
                    max_prefix_len: 64,
                    pool_start: 0x100,
                    pool_end: Some(0x200),
                    preferred_lifetime: 300,
                    valid_lifetime: 600,
                }),
                ia_pd: None,
            }),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn v2_same_group_rejects_ra_pd_overlap() {
        let config = LanPrefixGroupConfig {
            group_id: "same-parent".to_string(),
            parent: PrefixParentSource::Pd {
                depend_iface: "eth0".to_string(),
                planned_parent_prefix_len: 60,
            },
            ra: Some(RaPrefixConfig {
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            }),
            na: None,
            pd: Some(PdPrefixRangeConfig { pool_len: 64, start_index: 1, end_index: 1 }),
        };

        assert!(validate_prefix_groups(&[config]).is_err());
    }

    #[test]
    fn v2_same_group_allows_ra_na_share() {
        let config = LanPrefixGroupConfig {
            group_id: "same-parent".to_string(),
            parent: PrefixParentSource::Pd {
                depend_iface: "eth0".to_string(),
                planned_parent_prefix_len: 60,
            },
            ra: Some(RaPrefixConfig {
                pool_index: 1,
                preferred_lifetime: 300,
                valid_lifetime: 600,
            }),
            na: Some(NaPrefixConfig { pool_index: 1 }),
            pd: None,
        };

        assert!(validate_prefix_groups(&[config]).is_ok());
    }

    #[test]
    fn v2_pd_parent_capacity_falls_back_to_planned_prefix_len_without_runtime_prefix() {
        let config = LanPrefixGroupConfig {
            group_id: "capacity-ok".to_string(),
            parent: PrefixParentSource::Pd {
                depend_iface: "eth0".to_string(),
                planned_parent_prefix_len: 60,
            },
            ra: None,
            na: Some(NaPrefixConfig { pool_index: 15 }),
            pd: None,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn v2_pd_parent_capacity_rejects_indices_beyond_planned_prefix_len_without_runtime_prefix() {
        let config = LanPrefixGroupConfig {
            group_id: "capacity-bad".to_string(),
            parent: PrefixParentSource::Pd {
                depend_iface: "eth0".to_string(),
                planned_parent_prefix_len: 60,
            },
            ra: None,
            na: Some(NaPrefixConfig { pool_index: 16 }),
            pd: None,
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn v2_pd_parent_capacity_prefers_runtime_prefix_len_when_available() {
        let config = LanPrefixGroupConfig {
            group_id: "capacity-runtime".to_string(),
            parent: PrefixParentSource::Pd {
                depend_iface: "eth0".to_string(),
                planned_parent_prefix_len: 60,
            },
            ra: None,
            na: Some(NaPrefixConfig { pool_index: 38 }),
            pd: None,
        };

        let mut prefix_infos = HashMap::new();
        prefix_infos.insert(
            "eth0".to_string(),
            Some(LDIAPrefix {
                preferred_lifetime: 300,
                valid_lifetime: 600,
                prefix_len: 56,
                prefix_ip: "2001:db8::".parse().unwrap(),
                last_update_time: 0.0,
            }),
        );

        assert!(config.validate_with_prefix_infos(Some(&prefix_infos)).is_ok());
    }

    #[test]
    fn v2_same_runtime_pd_parent_conflicts_even_if_planned_lengths_differ() {
        let groups = vec![
            LanPrefixGroupConfig {
                group_id: "group-a".to_string(),
                parent: PrefixParentSource::Pd {
                    depend_iface: "eth0".to_string(),
                    planned_parent_prefix_len: 60,
                },
                ra: Some(RaPrefixConfig {
                    pool_index: 1,
                    preferred_lifetime: 300,
                    valid_lifetime: 600,
                }),
                na: None,
                pd: None,
            },
            LanPrefixGroupConfig {
                group_id: "group-b".to_string(),
                parent: PrefixParentSource::Pd {
                    depend_iface: "eth0".to_string(),
                    planned_parent_prefix_len: 56,
                },
                ra: None,
                na: None,
                pd: Some(PdPrefixRangeConfig { pool_len: 64, start_index: 1, end_index: 1 }),
            },
        ];

        let mut prefix_infos = HashMap::new();
        prefix_infos.insert(
            "eth0".to_string(),
            Some(LDIAPrefix {
                preferred_lifetime: 300,
                valid_lifetime: 600,
                prefix_len: 56,
                prefix_ip: "2001:db8::".parse().unwrap(),
                last_update_time: 0.0,
            }),
        );

        assert!(validate_prefix_groups_with_prefix_infos(&groups, Some(&prefix_infos)).is_err());
    }

    #[test]
    fn v2_cross_interface_conflicts_when_runtime_pd_prefix_matches_across_ifaces() {
        let new_config = LanIPv6ServiceConfigV2 {
            iface_name: "lan-a".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Slaac,
                ad_interval: 300,
                ra_flag: ra_flag_default(),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "group-a".to_string(),
                    parent: PrefixParentSource::Pd {
                        depend_iface: "wan0".to_string(),
                        planned_parent_prefix_len: 60,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index: 0,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: None,
                    pd: None,
                }],
                dhcpv6: None,
            },
            update_at: 0.0,
        };

        let other_configs = vec![LanIPv6ServiceConfigV2 {
            iface_name: "lan-b".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Stateful,
                ad_interval: 300,
                ra_flag: RouterFlags::from(0xc0u8),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "group-b".to_string(),
                    parent: PrefixParentSource::Pd {
                        depend_iface: "wan1".to_string(),
                        planned_parent_prefix_len: 56,
                    },
                    ra: None,
                    na: None,
                    pd: Some(PdPrefixRangeConfig { pool_len: 64, start_index: 0, end_index: 0 }),
                }],
                dhcpv6: Some(DHCPv6ServerConfig {
                    enable: true,
                    ia_na: Some(crate::dhcp::v6_server::config::DHCPv6IANAConfig {
                        max_prefix_len: 64,
                        pool_start: 0x100,
                        pool_end: None,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    ia_pd: None,
                }),
            },
            update_at: 0.0,
        }];

        let mut prefix_infos = HashMap::new();
        prefix_infos.insert(
            "wan0".to_string(),
            Some(LDIAPrefix {
                preferred_lifetime: 300,
                valid_lifetime: 600,
                prefix_len: 56,
                prefix_ip: "2001:db8::".parse().unwrap(),
                last_update_time: 0.0,
            }),
        );
        prefix_infos.insert(
            "wan1".to_string(),
            Some(LDIAPrefix {
                preferred_lifetime: 300,
                valid_lifetime: 600,
                prefix_len: 56,
                prefix_ip: "2001:db8::".parse().unwrap(),
                last_update_time: 0.0,
            }),
        );

        assert!(validate_cross_interface_v2_with_prefix_infos(
            &new_config,
            &other_configs,
            Some(&prefix_infos),
        )
        .is_err());
    }

    #[test]
    fn v2_cross_interface_ra_and_na_cannot_share_same_prefix() {
        let new_config = LanIPv6ServiceConfigV2 {
            iface_name: "lan-a".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Slaac,
                ad_interval: 300,
                ra_flag: ra_flag_default(),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "group-a".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: "fd00::".parse().unwrap(),
                        parent_prefix_len: 56,
                    },
                    ra: Some(RaPrefixConfig {
                        pool_index: 0,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    na: None,
                    pd: None,
                }],
                dhcpv6: None,
            },
            update_at: 0.0,
        };

        let other_configs = vec![LanIPv6ServiceConfigV2 {
            iface_name: "lan-b".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Stateful,
                ad_interval: 300,
                ra_flag: RouterFlags::from(0xc0u8),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "group-b".to_string(),
                    parent: PrefixParentSource::Static {
                        base_prefix: "fd00::".parse().unwrap(),
                        parent_prefix_len: 56,
                    },
                    ra: None,
                    na: Some(NaPrefixConfig { pool_index: 0 }),
                    pd: None,
                }],
                dhcpv6: Some(DHCPv6ServerConfig {
                    enable: true,
                    ia_na: Some(crate::dhcp::v6_server::config::DHCPv6IANAConfig {
                        max_prefix_len: 64,
                        pool_start: 0x100,
                        pool_end: None,
                        preferred_lifetime: 300,
                        valid_lifetime: 600,
                    }),
                    ia_pd: None,
                }),
            },
            update_at: 0.0,
        }];

        assert!(validate_cross_interface_v2(&new_config, &other_configs).is_err());
    }
}
