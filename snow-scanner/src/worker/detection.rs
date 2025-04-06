use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::Resolver;

use crate::ip_addr::is_global_hardcoded;

pub fn get_dns_server_config(server_ips: &Vec<IpAddr>) -> NameServerConfigGroup {
    NameServerConfigGroup::from_ips_clear(
        server_ips, 53, // Port 53
        true,
    )
}

pub fn get_dns_client(server: &NameServerConfigGroup) -> Resolver {
    let config = ResolverConfig::from_parts(None, vec![], server.clone());
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
