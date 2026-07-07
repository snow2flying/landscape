use std::net::Ipv4Addr;

use landscape_macro::LdApiError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DhcpError {
    #[error("DHCPv4 service config for '{id}' not found")]
    #[api_error(id = "dhcp.config_not_found", status = 404)]
    ConfigNotFound { id: String },

    #[error(
        "DHCP IP range conflict with interface '{conflict_iface}': {range_start} - {range_end}"
    )]
    #[api_error(id = "dhcp.ip_conflict", status = 409)]
    IpConflict { conflict_iface: String, range_start: Ipv4Addr, range_end: Ipv4Addr },
}
