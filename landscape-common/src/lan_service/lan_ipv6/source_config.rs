use std::collections::HashMap;
use std::fmt;
use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};

use super::config::{
    ra_flag_default, IPv6ServiceMode, LanIPv6Config, LanIPv6ConfigV2, LanIPv6ServiceConfig,
    SourceServiceKind,
};
use super::prefix_group::{
    is_ula, LanPrefixGroupConfig, NaPrefixConfig, PdPrefixRangeConfig, PrefixParentSource,
    RaPrefixConfig,
};
use crate::service::ServiceConfigError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

fn effective_pool_index(src: &LanIPv6SourceConfig) -> u64 {
    src.pool_index() as u64
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

    if super::prefix_group::blocks_overlap(parent_len, idx_a, len_a, idx_b, len_b) {
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
                if super::prefix_group::blocks_overlap(
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

#[cfg(test)]
mod tests {
    use super::super::config::{ra_flag_default, LanIPv6ServiceConfigV2};
    use super::*;

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
}
