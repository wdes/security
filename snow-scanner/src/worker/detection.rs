use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use diesel::deserialize::FromSqlRow;
use dns_ptr_resolver::ResolvedResult;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::{Name, Resolver};

#[derive(Debug, Clone, Copy, FromSqlRow)]
pub enum Scanners {
    Stretchoid,
    Binaryedge,
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
        &_ => Ok(None),
    }
}
