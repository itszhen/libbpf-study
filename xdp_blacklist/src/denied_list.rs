
use anyhow::{bail, Result};
use libbpf_rs::{MapFlags, MapCore};
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct DeniedListManager<M1, M2>
where
    M1: MapCore,
    M2: MapCore,
{
    denied_ips_map: M1,
    denied_ipv6_map: M2,
}

impl<M1, M2> DeniedListManager<M1, M2>
where
    M1: MapCore,
    M2: MapCore,
{
    pub fn new(denied_ips_map: M1, denied_ipv6_map: M2) -> Self {
        Self {
            denied_ips_map,
            denied_ipv6_map,
        }
    }

    /// Add an IPv4 address or CIDR to the denied list
    pub fn add_ipv4(&self, ip: &str, prefixlen: u32) -> Result<()> {
        if prefixlen > 32 {
            bail!("Invalid prefix length for IPv4: {}", prefixlen);
        }

        let ipv4: Ipv4Addr = ip.parse()?;
        let ip_bytes = ipv4.octets();

        // Create LPM trie key: [prefixlen (4 bytes) + ip (4 bytes)]
        let mut key: Vec<u8> = Vec::with_capacity(8);
        key.extend_from_slice(&prefixlen.to_ne_bytes());
        key.extend_from_slice(&ip_bytes);

        let flag: u8 = 1;
        self.denied_ips_map
            .update(&key, &[flag], MapFlags::empty())
            .map_err(|e| anyhow::anyhow!("Failed to add IPv4 to denied list: {}", e))?;

        println!("Added {}/{} to denied IPv4 list", ip, prefixlen);
        Ok(())
    }

    /// Delete an IPv4 address or CIDR from the denied list
    pub fn delete_ipv4(&self, ip: &str, prefixlen: u32) -> Result<()> {
        if prefixlen > 32 {
            bail!("Invalid prefix length for IPv4: {}", prefixlen);
        }

        let ipv4: Ipv4Addr = ip.parse()?;
        let ip_bytes = ipv4.octets();

        // Create LPM trie key: [prefixlen (4 bytes) + ip (4 bytes)]
        let mut key: Vec<u8> = Vec::with_capacity(8);
        key.extend_from_slice(&prefixlen.to_ne_bytes());
        key.extend_from_slice(&ip_bytes);

        self.denied_ips_map
            .delete(&key)
            .map_err(|e| anyhow::anyhow!("Failed to delete IPv4 from denied list: {}", e))?;

        println!("Deleted {}/{} from denied IPv4 list", ip, prefixlen);
        Ok(())
    }

    /// Add an IPv6 address or CIDR to the denied list
    pub fn add_ipv6(&self, ip: &str, prefixlen: u32) -> Result<()> {
        if prefixlen > 128 {
            bail!("Invalid prefix length for IPv6: {}", prefixlen);
        }

        let ipv6: Ipv6Addr = ip.parse()?;
        let ip_bytes = ipv6.octets();

        // Create LPM trie key: [prefixlen (4 bytes) + ipv6 (16 bytes)]
        let mut key: Vec<u8> = Vec::with_capacity(20);
        key.extend_from_slice(&prefixlen.to_ne_bytes());
        key.extend_from_slice(&ip_bytes);

        let flag: u8 = 1;
        self.denied_ipv6_map
            .update(&key, &[flag], MapFlags::empty())
            .map_err(|e| anyhow::anyhow!("Failed to add IPv6 to denied list: {}", e))?;

        println!("Added {}/{} to denied IPv6 list", ip, prefixlen);
        Ok(())
    }

    /// Delete an IPv6 address or CIDR from the denied list
    pub fn delete_ipv6(&self, ip: &str, prefixlen: u32) -> Result<()> {
        if prefixlen > 128 {
            bail!("Invalid prefix length for IPv6: {}", prefixlen);
        }

        let ipv6: Ipv6Addr = ip.parse()?;
        let ip_bytes = ipv6.octets();

        // Create LPM trie key: [prefixlen (4 bytes) + ipv6 (16 bytes)]
        let mut key: Vec<u8> = Vec::with_capacity(20);
        key.extend_from_slice(&prefixlen.to_ne_bytes());
        key.extend_from_slice(&ip_bytes);

        self.denied_ipv6_map
            .delete(&key)
            .map_err(|e| anyhow::anyhow!("Failed to delete IPv6 from denied list: {}", e))?;

        println!("Deleted {}/{} from denied IPv6 list", ip, prefixlen);
        Ok(())
    }

    /// List all IPv4 entries in the denied list
    pub fn list_ipv4(&self) -> Result<()> {
        println!("Denied IPv4 list:");
        let mut count = 0;

        for key in self.denied_ips_map.keys() {
            if key.len() != 8 {
                continue;
            }

            let prefixlen = u32::from_ne_bytes([key[0], key[1], key[2], key[3]]);
            let ip_bytes = [key[4], key[5], key[6], key[7]];
            let ip = Ipv4Addr::from(ip_bytes);

            println!("  {}/{}", ip, prefixlen);
            count += 1;
        }

        if count == 0 {
            println!("  (empty)");
        }

        Ok(())
    }

    /// List all IPv6 entries in the denied list
    pub fn list_ipv6(&self) -> Result<()> {
        println!("Denied IPv6 list:");
        let mut count = 0;

        for key in self.denied_ipv6_map.keys() {
            if key.len() != 20 {
                continue;
            }

            let prefixlen = u32::from_ne_bytes([key[0], key[1], key[2], key[3]]);
            let ip_bytes: [u8; 16] = key[4..20].try_into().unwrap();
            let ip = Ipv6Addr::from(ip_bytes);

            println!("  {}/{}", ip, prefixlen);
            count += 1;
        }

        if count == 0 {
            println!("  (empty)");
        }

        Ok(())
    }
}
