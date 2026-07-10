pub mod config;

use std::net::Ipv4Addr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;

use crate::event::hub::{
    EnrolledDeviceEvent, EnrolledDeviceEventReader, IPv4AssignEvent, IPv4AssignEventReader,
};

pub use config::HostnameRegistryConfig;

struct HostnameRecord {
    ipv4: Ipv4Addr,
    /// true if registered by an enrolled device (always wins over DHCP leases).
    from_enrolled_device: bool,
}

pub struct HostnameRegistry {
    hostname_map: Arc<DashMap<String, HostnameRecord>>,
    config: Arc<ArcSwap<HostnameRegistryConfig>>,
}

impl HostnameRegistry {
    pub fn new(
        config: HostnameRegistryConfig,
        initial_devices: Vec<(String, Ipv4Addr)>,
        ipv4_reader: IPv4AssignEventReader,
        device_reader: EnrolledDeviceEventReader,
    ) -> Arc<Self> {
        let hostname_map: Arc<DashMap<String, HostnameRecord>> = Arc::new(DashMap::new());

        for (hostname, ipv4) in &initial_devices {
            if let Ok(punycode) = idna::domain_to_ascii(hostname) {
                hostname_map
                    .insert(punycode, HostnameRecord { ipv4: *ipv4, from_enrolled_device: true });
            }
        }

        let registry = Arc::new(Self {
            hostname_map: hostname_map.clone(),
            config: Arc::new(ArcSwap::from_pointee(config)),
        });

        // Listener 1: EnrolledDeviceEvent (device CRUD)
        let map = hostname_map.clone();
        tokio::spawn(async move {
            use tokio::sync::broadcast::error::RecvError;
            let mut reader = device_reader;
            loop {
                match reader.recv().await {
                    Ok(EnrolledDeviceEvent::Updated { old, new }) => {
                        // Remove old hostname
                        if let Some(ref old_device) = old {
                            if let Some(ref old_hostname) = old_device.hostname {
                                if let Ok(punycode) = idna::domain_to_ascii(old_hostname) {
                                    map.remove(&punycode);
                                }
                            }
                        }
                        // Insert new hostname (always enrolled, highest priority)
                        if let (Some(ref hostname), Some(ipv4)) = (&new.hostname, new.ipv4) {
                            if let Ok(punycode) = idna::domain_to_ascii(hostname) {
                                map.insert(
                                    punycode,
                                    HostnameRecord { ipv4, from_enrolled_device: true },
                                );
                            }
                        }
                    }
                    Ok(EnrolledDeviceEvent::Deleted { old }) => {
                        if let Some(ref hostname) = old.hostname {
                            if let Ok(punycode) = idna::domain_to_ascii(hostname) {
                                map.remove(&punycode);
                            }
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        tracing::warn!("hostname_registry: device event lagged by {n}");
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });

        // Listener 2: IPv4AssignEvent (DHCP lease allocation/expiry)
        let map = hostname_map.clone();
        tokio::spawn(async move {
            use tokio::sync::broadcast::error::RecvError;
            let mut reader = ipv4_reader;
            loop {
                match reader.recv().await {
                    Ok(IPv4AssignEvent::Allocated(info)) => {
                        if let Some(hostname) = info.hostname {
                            if let Ok(punycode) = idna::domain_to_ascii(&hostname) {
                                let should_insert = match map.get(&punycode) {
                                    Some(existing) if existing.from_enrolled_device => {
                                        tracing::debug!(
                                            "hostname_registry: ignoring DHCP hostname '{}' -> {} because enrolled device already registered",
                                            hostname, info.ip
                                        );
                                        false
                                    }
                                    _ => true,
                                };
                                if should_insert {
                                    map.insert(
                                        punycode,
                                        HostnameRecord {
                                            ipv4: info.ip,
                                            from_enrolled_device: false,
                                        },
                                    );
                                }
                            }
                        }
                    }
                    Ok(IPv4AssignEvent::Expired(info)) => {
                        if let Some(hostname) = info.hostname {
                            if let Ok(punycode) = idna::domain_to_ascii(&hostname) {
                                let should_remove = match map.get(&punycode) {
                                    Some(existing) if existing.from_enrolled_device => false,
                                    _ => true,
                                };
                                if should_remove {
                                    map.remove(&punycode);
                                }
                            }
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        tracing::warn!("hostname_registry: ipv4 event lagged by {n}");
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });

        registry
    }

    pub fn update_config(&self, config: HostnameRegistryConfig) {
        self.config.store(Arc::new(config));
    }

    pub fn is_local_domain(&self, fqdn: &str) -> bool {
        let suffix = &self.config.load().lan_suffix;
        if suffix.is_empty() {
            return false;
        }
        let dot_suffix = {
            let mut s = String::with_capacity(suffix.len() + 1);
            s.push('.');
            s.push_str(suffix);
            s
        };
        let name = fqdn.strip_suffix('.').unwrap_or(fqdn);
        name.ends_with(&dot_suffix) && name != dot_suffix
    }

    pub fn resolve_a(&self, fqdn: &str) -> Option<Ipv4Addr> {
        let suffix = &self.config.load().lan_suffix;
        if suffix.is_empty() {
            return None;
        }
        let dot_suffix = {
            let mut s = String::with_capacity(suffix.len() + 1);
            s.push('.');
            s.push_str(suffix);
            s
        };
        let name = fqdn.strip_suffix('.').unwrap_or(fqdn);
        let hostname = name.strip_suffix(&dot_suffix)?;
        let hostname = idna::domain_to_ascii(hostname).ok()?;
        self.hostname_map.get(&hostname).map(|r| r.ipv4)
    }

    /// Creates a registry for testing purposes with empty event readers.
    pub fn new_for_test(config: HostnameRegistryConfig) -> Arc<Self> {
        let (_tx, rx) = tokio::sync::broadcast::channel(64);
        let (_tx2, rx2) = tokio::sync::broadcast::channel(64);
        Self::new(
            config,
            vec![],
            IPv4AssignEventReader::new(rx),
            EnrolledDeviceEventReader::new(rx2),
        )
    }
}
