//
// Port of the official Rust implementation
// Source: https://github.com/dani-garcia/vaultwarden/blob/1.32.1/src/util.rs
//

/// TODO: This is extracted from IpAddr::is_global, which is unstable:
/// https://doc.rust-lang.org/nightly/std/net/enum.IpAddr.html#method.is_global
/// Remove once https://github.com/rust-lang/rust/issues/27709 is merged
#[allow(clippy::nonminimal_bool)]
#[cfg(any(not(feature = "unstable"), test))]
pub fn is_global_hardcoded(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            !(ip.octets()[0] == 0 // "This network"
            || ip.is_private()
            || (ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000 == 0b0100_0000)) //ip.is_shared()
            || ip.is_loopback()
            || ip.is_link_local()
            // addresses reserved for future protocols (`192.0.0.0/24`)
            ||(ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0)
            || ip.is_documentation()
            || (ip.octets()[0] == 198 && (ip.octets()[1] & 0xfe) == 18) // ip.is_benchmarking()
            || (ip.octets()[0] & 240 == 240 && !ip.is_broadcast()) //ip.is_reserved()
            || ip.is_broadcast())
        }
        std::net::IpAddr::V6(ip) => {
            !(ip.is_unspecified()
            || ip.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(ip.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(ip.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(ip.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(ip.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(ip.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(ip.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(ip.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    || matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if (0x20..=0x2F).contains(&b))
                ))
            || ((ip.segments()[0] == 0x2001) && (ip.segments()[1] == 0xdb8)) // ip.is_documentation()
            || ((ip.segments()[0] & 0xfe00) == 0xfc00) //ip.is_unique_local()
            || ((ip.segments()[0] & 0xffc0) == 0xfe80)) //ip.is_unicast_link_local()
        }
    }
}

#[cfg(not(feature = "unstable"))]
pub use is_global_hardcoded as is_global;

#[cfg(feature = "unstable")]
#[inline(always)]
pub fn is_global(ip: std::net::IpAddr) -> bool {
    ip.is_global()
}

/// These are some tests to check that the implementations match
/// The IPv4 can be all checked in 30 seconds or so and they are correct as of nightly 2023-07-17
/// The IPV6 can't be checked in a reasonable time, so we check over a hundred billion random ones, so far correct
/// Note that the is_global implementation is subject to change as new IP RFCs are created
///
/// To run while showing progress output:
/// cargo +nightly test --release --features sqlite,unstable -- --nocapture --ignored
#[cfg(test)]
#[cfg(feature = "unstable")]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    #[ignore]
    fn test_ipv4_global() {
        for a in 0..u8::MAX {
            println!("Iter: {}/255", a);
            for b in 0..u8::MAX {
                for c in 0..u8::MAX {
                    for d in 0..u8::MAX {
                        let ip = IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d));
                        assert_eq!(
                            ip.is_global(),
                            is_global_hardcoded(ip),
                            "IP mismatch: {}",
                            ip
                        )
                    }
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn test_ipv6_global() {
        use rand::Rng;

        std::thread::scope(|s| {
            for t in 0..16 {
                let handle = s.spawn(move || {
                    let mut v = [0u8; 16];
                    let mut rng = rand::thread_rng();

                    for i in 0..20 {
                        println!("Thread {t} Iter: {i}/50");
                        for _ in 0..500_000_000 {
                            rng.fill(&mut v);
                            let ip = IpAddr::V6(std::net::Ipv6Addr::from(v));
                            assert_eq!(
                                ip.is_global(),
                                is_global_hardcoded(ip),
                                "IP mismatch: {ip}"
                            );
                        }
                    }
                });
            }
        });
    }
}
