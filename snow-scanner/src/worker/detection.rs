use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use diesel::deserialize::FromSqlRow;
use dns_ptr_resolver::ResolvedResult;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::{Name, Resolver};

use crate::ip_addr::is_global_hardcoded;

#[derive(Debug, Clone, Copy, FromSqlRow, PartialEq)]
pub enum Scanners {
    Stretchoid,
    Binaryedge,
    Shadowserver,
    Censys,
    InternetMeasurement,
}

pub fn get_dns_client() -> Resolver {
    let server_ip = "1.1.1.1";

    let server = NameServerConfigGroup::from_ips_clear(
        &[IpAddr::from_str(server_ip).unwrap()],
        53, // Port 53
        true,
    );

    let config = ResolverConfig::from_parts(None, vec![], server);
    let mut options = ResolverOpts::default();
    options.timeout = Duration::from_secs(5);
    options.attempts = 1; // One try

    Resolver::new(config, options).unwrap()
}

pub fn validate_ip(ip: IpAddr) -> bool {
    // unspecified => 0.0.0.0
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return false;
    }
    return is_global_hardcoded(ip);
}

pub fn detect_scanner(ptr_result: &ResolvedResult) -> Result<Option<Scanners>, ()> {
    match &ptr_result.result {
        Some(name) => detect_scanner_from_name(&name),
        None => Ok(None),
    }
}

pub fn detect_scanner_from_name(name: &Name) -> Result<Option<Scanners>, ()> {
    match name {
        ref name
            if name
                .trim_to(2)
                .eq_case(&Name::from_str("binaryedge.ninja.").expect("Should parse")) =>
        {
            Ok(Some(Scanners::Binaryedge))
        }
        ref name
            if name
                .trim_to(2)
                .eq_case(&Name::from_str("stretchoid.com.").expect("Should parse")) =>
        {
            Ok(Some(Scanners::Stretchoid))
        }
        ref name
            if name
                .trim_to(2)
                .eq_case(&Name::from_str("shadowserver.org.").expect("Should parse")) =>
        {
            Ok(Some(Scanners::Shadowserver))
        }
        &_ => Ok(None),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_detect_scanner_from_name() {
        let ptr = Name::from_str("scan-47e.shadowserver.org.").unwrap();

        assert_eq!(
            detect_scanner_from_name(&ptr).unwrap(),
            Some(Scanners::Shadowserver)
        );
    }

    #[test]
    fn test_detect_scanner() {
        let cname_ptr = Name::from_str("111.0-24.197.62.64.in-addr.arpa.").unwrap();
        let ptr = Name::from_str("scan-47e.shadowserver.org.").unwrap();

        assert_eq!(
            detect_scanner(&ResolvedResult {
                query: cname_ptr,
                result: Some(ptr),
                error: None
            })
            .unwrap(),
            Some(Scanners::Shadowserver)
        );
    }
}
