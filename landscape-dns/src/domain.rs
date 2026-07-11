pub struct PreprocessedDomain {
    raw: String,
    name: String,
    labels: Vec<String>,
}

impl PreprocessedDomain {
    pub fn new(domain: &str) -> Self {
        let name = domain.strip_suffix('.').unwrap_or(domain).to_ascii_lowercase();
        let labels: Vec<String> = name.split('.').map(String::from).collect();
        Self { raw: domain.to_string(), name, labels }
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
