use landscape_macro::LdApiError;

use crate::config::FlowId;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DnsError {
    #[error("Invalid domain name '{domain}'")]
    #[api_error(id = "dns_domain.invalid", status = 400)]
    Invalid { domain: String },

    #[error("DNS flow '{0}' not found")]
    #[api_error(id = "dns_check.flow_not_found", status = 404)]
    FlowNotFound(FlowId),

    #[error("DNS cache refresh requires a matched upstream rule for '{0}'")]
    #[api_error(id = "dns_check.refresh_requires_rule", status = 409)]
    RefreshRequiresRule(String),

    #[error("DNS cache refresh is not available for redirected domain '{0}'")]
    #[api_error(id = "dns_check.refresh_redirected", status = 409)]
    RefreshRedirected(String),

    #[error("DNS cache refresh failed for '{0}'")]
    #[api_error(id = "dns_check.refresh_failed", status = 502)]
    RefreshFailed(String),
}
