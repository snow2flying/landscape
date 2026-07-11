use hickory_proto::rr::Name;
use landscape_common::dns::error::DnsError;

pub struct PreprocessedDomain {
    raw: String,
    name: String,
    labels: Vec<String>,
    dns_name: Name,
}

impl PreprocessedDomain {
    pub fn new(fqdn: &str) -> Result<Self, DnsError> {
        let name = fqdn.strip_suffix('.').unwrap_or(fqdn).to_ascii_lowercase();
        let labels: Vec<String> = name.split('.').map(String::from).collect();
        let dns_name =
            Name::from_utf8(&name).map_err(|_| DnsError::Invalid { domain: fqdn.to_string() })?;
        let raw = format!("{}.", name);
        Ok(Self { raw, name, labels, dns_name })
    }

    pub fn as_dns_name(&self) -> &Name {
        &self.dns_name
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn tld(&self) -> &str {
        self.labels.last().map(|s| s.as_str()).unwrap_or(&self.name)
    }

    pub fn arpa_sld(&self) -> Option<&str> {
        if self.labels.len() >= 2 && self.labels.last().map(|s| s.as_str()) == Some("arpa") {
            Some(&self.labels[self.labels.len() - 2])
        } else {
            None
        }
    }

    pub fn arpa_prefix(&self) -> Option<&str> {
        self.name.strip_suffix(".arpa")
    }

    pub fn hostname_for_tld(&self, tld: &str) -> Option<&str> {
        let suffix = format!(".{}", tld);
        self.name.strip_suffix(&suffix).filter(|h| !h.is_empty())
    }
}
