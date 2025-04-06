use rand::seq::SliceRandom;
use rand::thread_rng;
use std::net::IpAddr;
use weighted_rs::{RoundrobinWeight, Weight};

pub fn get_dns_rr() -> RoundrobinWeight<Vec<IpAddr>> {
    use std::str::FromStr;

    // https://gist.github.com/mutin-sa/5dcbd35ee436eb629db7872581093bc5
    let dns_servers: Vec<IpAddr> = vec![
        IpAddr::from_str("1.1.1.1").unwrap(),
        IpAddr::from_str("1.0.0.1").unwrap(),
        IpAddr::from_str("8.8.8.8").unwrap(),
        IpAddr::from_str("8.8.4.4").unwrap(),
        IpAddr::from_str("9.9.9.9").unwrap(),
        IpAddr::from_str("9.9.9.10").unwrap(),
        IpAddr::from_str("2.56.220.2").unwrap(), // G-Core DNS
        IpAddr::from_str("95.85.95.85").unwrap(), // G-Core DNS
        IpAddr::from_str("193.110.81.0").unwrap(), // dns0.eu	AS50902
        IpAddr::from_str("185.253.5.0").unwrap(), // dns0.eu	AS50902
        IpAddr::from_str("74.82.42.42").unwrap(), // Hurricane Electric	[AS6939]
    ];

    let mut rr: RoundrobinWeight<Vec<IpAddr>> = RoundrobinWeight::new();
    // For each entry in the list we create a lot of two DNS servers to use
    for _ in &dns_servers {
        let mut client_servers = dns_servers.clone();
        client_servers.shuffle(&mut thread_rng());
        client_servers.truncate(2);
        rr.add(client_servers, 1);
    }
    rr
}
