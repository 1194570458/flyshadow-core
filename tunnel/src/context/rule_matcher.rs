use ipnet::IpNet;

use crate::context::proxy_type::ProxyType;

pub trait RuleMatcher: Send + Sync {
    fn new(domain: String, proxy_type: i32) -> Self where Self: Sized;
    fn do_match(&self, domain: &String) -> Option<ProxyType>;
}


pub struct AllDomainMatcher {
    domain: String,
    proxy_type: i32,
}

impl RuleMatcher for AllDomainMatcher {
    fn new(domain: String, proxy_type: i32) -> Self {
        AllDomainMatcher {
            domain,
            proxy_type,
        }
    }

    fn do_match(&self, domain: &String) -> Option<ProxyType> {
        if self.domain.eq(domain) {
            Some(ProxyType::from_index(self.proxy_type))
        } else {
            None
        }
    }
}

pub struct SuffixDomainMatcher {
    domain: String,
    proxy_type: i32,
}

impl RuleMatcher for SuffixDomainMatcher {
    fn new(domain: String, proxy_type: i32) -> Self {
        SuffixDomainMatcher {
            domain,
            proxy_type,
        }
    }

    fn do_match(&self, domain: &String) -> Option<ProxyType> {
        if domain.ends_with::<&String>(&self.domain) {
            Some(ProxyType::from_index(self.proxy_type))
        } else { None }
    }
}

pub struct KeywordDomainMatcher {
    domain: String,
    proxy_type: i32,
}

impl RuleMatcher for KeywordDomainMatcher {
    fn new(domain: String, proxy_type: i32) -> Self {
        KeywordDomainMatcher {
            domain,
            proxy_type,
        }
    }

    fn do_match(&self, domain: &String) -> Option<ProxyType> {
        if domain.contains::<&String>(&self.domain) {
            Some(ProxyType::from_index(self.proxy_type))
        } else { None }
    }
}

pub struct IPV4DomainMatcher {
    cidr_rule: Option<IpNet>,
    proxy_type: i32,
}

impl RuleMatcher for IPV4DomainMatcher {
    fn new(domain: String, proxy_type: i32) -> Self {
        let cidr_rule = match domain.parse::<IpNet>() {
            Ok(r) => { Some(r) }
            Err(_) => { None }
        };
        IPV4DomainMatcher {
            cidr_rule,
            proxy_type,
        }
    }

    fn do_match(&self, domain: &String) -> Option<ProxyType> {
        let ip_to_check = match domain.parse::<IpNet>() {
            Ok(r) => { r }
            Err(_) => { return None; }
        };

        if self.cidr_rule.is_none() {
            return None;
        }

        if self.cidr_rule.as_ref().unwrap().contains::<&IpNet>(&ip_to_check.into()) {
            Some(ProxyType::from_index(self.proxy_type))
        } else {
            None
        }
    }
}

pub struct GEOIPMatcher {
    geo_ip_name: String,
    proxy_type: i32,
}

impl RuleMatcher for GEOIPMatcher {
    fn new(domain: String, proxy_type: i32) -> Self {
        GEOIPMatcher {
            geo_ip_name: domain,
            proxy_type,
        }
    }

    fn do_match(&self, domain: &String) -> Option<ProxyType> {
        None
    }
}

pub struct MatchMatcher {
    proxy_type: i32,
}

impl RuleMatcher for MatchMatcher {
    fn new(_domain: String, proxy_type: i32) -> Self {
        MatchMatcher {
            proxy_type,
        }
    }

    fn do_match(&self, _domain: &String) -> Option<ProxyType> {
        Some(ProxyType::from_index(self.proxy_type))
    }
}
