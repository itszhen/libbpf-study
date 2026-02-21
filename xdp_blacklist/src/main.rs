use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};

use anyhow::{bail, Result};
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use structopt::StructOpt;
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use std::path::Path;

mod xdpaborted {
    include!(concat!(env!("OUT_DIR"), "/xdpaborted.skel.rs"));
}
use xdpaborted::*;

#[derive(Debug, StructOpt)]
enum Command {
    /// Run the XDP program
    Run {
        /// Interface index to attach XDP program
        #[structopt(default_value = "0")]
        ifindex: i32,
    },
    /// Add an IPv4 address or CIDR to the denied list
    AddIpv4 {
        /// IPv4 address or CIDR (e.g., 192.168.1.0/24 or 127.0.0.1)
        cidr: String,
    },
    /// Delete an IPv4 address or CIDR from the denied list
    DeleteIpv4 {
        /// IPv4 address or CIDR (e.g., 192.168.1.0/24 or 127.0.0.1)
        cidr: String,
    },
    /// Add an IPv6 address or CIDR to the denied list
    AddIpv6 {
        /// IPv6 address or CIDR (e.g., 2001:db8::/32 or ::1)
        cidr: String,
    },
    /// Delete an IPv6 address or CIDR from the denied list
    DeleteIpv6 {
        /// IPv6 address or CIDR (e.g., 2001:db8::/32 or ::1)
        cidr: String,
    },
    /// List all denied IPv4 addresses
    ListIpv4,
    /// List all denied IPv6 addresses
    ListIpv6,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    match opts {
        Command::Run { ifindex } => {
            run_xdp(ifindex)?;
        }
        Command::AddIpv4 { cidr } => {
            // Parse CIDR notation (e.g., 192.168.1.0/24 or 127.0.0.1)
            let parts: Vec<&str> = cidr.split('/').collect();
            let ip = parts[0];
            let prefixlen: u32 = if parts.len() > 1 {
                parts[1].parse().unwrap_or(32)
            } else {
                32
            };
            add_ipv4(ip, prefixlen)?;
        }
        Command::DeleteIpv4 { cidr } => {
            // Parse CIDR notation (e.g., 192.168.1.0/24 or 127.0.0.1)
            let parts: Vec<&str> = cidr.split('/').collect();
            let ip = parts[0];
            let prefixlen: u32 = if parts.len() > 1 {
                parts[1].parse().unwrap_or(32)
            } else {
                32
            };
            delete_ipv4(ip, prefixlen)?;
        }
        Command::AddIpv6 { cidr } => {
            // Parse CIDR notation (e.g., 2001:db8::/32 or ::1)
            let parts: Vec<&str> = cidr.split('/').collect();
            let ip = parts[0];
            let prefixlen: u32 = if parts.len() > 1 {
                parts[1].parse().unwrap_or(128)
            } else {
                128
            };
            add_ipv6(ip, prefixlen)?;
        }
        Command::DeleteIpv6 { cidr } => {
            // Parse CIDR notation (e.g., 2001:db8::/32 or ::1)
            let parts: Vec<&str> = cidr.split('/').collect();
            let ip = parts[0];
            let prefixlen: u32 = if parts.len() > 1 {
                parts[1].parse().unwrap_or(128)
            } else {
                128
            };
            delete_ipv6(ip, prefixlen)?;
        }
        Command::ListIpv4 => {
            list_ipv4()?;
        }
        Command::ListIpv6 => {
            list_ipv6()?;
        }
    }

    Ok(())
}

fn add_ipv4(ip: &str, prefixlen: u32) -> Result<()> {
    bump_memlock_rlimit()?;
    
    let map_path = Path::new("/sys/fs/bpf/xdp_denied_ips_map");
    
    // Try to open the pinned map first
    if map_path.exists() {
        let map = MapHandle::from_pinned_path(map_path)?;
        let ipv4: Ipv4Addr = ip.parse()?;
        let ip_bytes = ipv4.octets();

        let mut key: Vec<u8> = Vec::with_capacity(8);
        // LPM trie key format: [prefixlen (4 bytes, host byte order) + ip (4 bytes, network byte order)]
        key.extend_from_slice(&prefixlen.to_ne_bytes());
        key.extend_from_slice(&ip_bytes);

        let flag: u8 = 1;
        map.update(&key, &[flag], MapFlags::empty())
            .map_err(|e| anyhow::anyhow!("Failed to add IPv4 to denied list: {}", e))?;

        println!("Added {}/{} to denied IPv4 list", ip, prefixlen);
    } else {
        // Create and pin the map if it doesn't exist
        let skel_builder = XdpabortedSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = skel_builder.open(&mut open_object)?;
        let mut skel = open_skel.load()?;

        let ipv4: Ipv4Addr = ip.parse()?;
        let ip_bytes = ipv4.octets();

        let mut key: Vec<u8> = Vec::with_capacity(8);
        // LPM trie key format: [prefixlen (4 bytes, host byte order) + ip (4 bytes, network byte order)]
        key.extend_from_slice(&prefixlen.to_ne_bytes());
        key.extend_from_slice(&ip_bytes);

        let flag: u8 = 1;
        skel.maps.denied_ips_map
            .update(&key, &[flag], MapFlags::empty())
            .map_err(|e| anyhow::anyhow!("Failed to add IPv4 to denied list: {}", e))?;

        // Pin the map
        skel.maps.denied_ips_map.pin(map_path)
            .map_err(|e| anyhow::anyhow!("Failed to pin map: {}", e))?;

        println!("Added {}/{} to denied IPv4 list", ip, prefixlen);
    }
    Ok(())
}

fn delete_ipv4(ip: &str, prefixlen: u32) -> Result<()> {
    bump_memlock_rlimit()?;
    
    let map_path = Path::new("/sys/fs/bpf/xdp_denied_ips_map");
    
    if !map_path.exists() {
        bail!("Denied IPs map does not exist. Please add an IP first.");
    }
    
    let map = MapHandle::from_pinned_path(map_path)?;
    let ipv4: Ipv4Addr = ip.parse()?;
    let ip_bytes = ipv4.octets();

    let mut key: Vec<u8> = Vec::with_capacity(8);
    key.extend_from_slice(&prefixlen.to_ne_bytes());
    key.extend_from_slice(&ip_bytes);

    map.delete(&key)
        .map_err(|e| anyhow::anyhow!("Failed to delete IPv4 from denied list: {}", e))?;

    println!("Deleted {}/{} from denied IPv4 list", ip, prefixlen);
    Ok(())
}

fn add_ipv6(ip: &str, prefixlen: u32) -> Result<()> {
    bump_memlock_rlimit()?;
    
    let map_path = Path::new("/sys/fs/bpf/xdp_denied_ipv6_map");
    
    // Try to open the pinned map first
    if map_path.exists() {
        let map = MapHandle::from_pinned_path(map_path)?;
        let ipv6: Ipv6Addr = ip.parse()?;
        let ip_bytes = ipv6.octets();

        let mut key: Vec<u8> = Vec::with_capacity(20);
        // LPM trie key format: [prefixlen (4 bytes, host byte order) + ipv6 (16 bytes, network byte order)]
        key.extend_from_slice(&prefixlen.to_ne_bytes());
        key.extend_from_slice(&ip_bytes);

        let flag: u8 = 1;
        map.update(&key, &[flag], MapFlags::empty())
            .map_err(|e| anyhow::anyhow!("Failed to add IPv6 to denied list: {}", e))?;

        println!("Added {}/{} to denied IPv6 list", ip, prefixlen);
    } else {
        // Create and pin the map if it doesn't exist
        let skel_builder = XdpabortedSkelBuilder::default();
        let mut open_object = MaybeUninit::uninit();
        let open_skel = skel_builder.open(&mut open_object)?;
        let mut skel = open_skel.load()?;

        let ipv6: Ipv6Addr = ip.parse()?;
        let ip_bytes = ipv6.octets();

        let mut key: Vec<u8> = Vec::with_capacity(20);
        // LPM trie key format: [prefixlen (4 bytes, host byte order) + ipv6 (16 bytes, network byte order)]
        key.extend_from_slice(&prefixlen.to_ne_bytes());
        key.extend_from_slice(&ip_bytes);

        let flag: u8 = 1;
        skel.maps.denied_ipv6_map
            .update(&key, &[flag], MapFlags::empty())
            .map_err(|e| anyhow::anyhow!("Failed to add IPv6 to denied list: {}", e))?;

        // Pin the map
        skel.maps.denied_ipv6_map.pin(map_path)
            .map_err(|e| anyhow::anyhow!("Failed to pin map: {}", e))?;

        println!("Added {}/{} to denied IPv6 list", ip, prefixlen);
    }
    Ok(())
}

fn delete_ipv6(ip: &str, prefixlen: u32) -> Result<()> {
    bump_memlock_rlimit()?;
    
    let map_path = Path::new("/sys/fs/bpf/xdp_denied_ipv6_map");
    
    if !map_path.exists() {
        bail!("Denied IPv6 map does not exist. Please add an IPv6 address first.");
    }
    
    let map = MapHandle::from_pinned_path(map_path)?;
    let ipv6: Ipv6Addr = ip.parse()?;
    let ip_bytes = ipv6.octets();

    let mut key: Vec<u8> = Vec::with_capacity(20);
    key.extend_from_slice(&prefixlen.to_ne_bytes());
    key.extend_from_slice(&ip_bytes);

    map.delete(&key)
        .map_err(|e| anyhow::anyhow!("Failed to delete IPv6 from denied list: {}", e))?;

    println!("Deleted {}/{} from denied IPv6 list", ip, prefixlen);
    Ok(())
}

fn list_ipv4() -> Result<()> {
    bump_memlock_rlimit()?;
    
    let map_path = Path::new("/sys/fs/bpf/xdp_denied_ips_map");
    
    if !map_path.exists() {
        println!("Denied IPv4 list:");
        println!("  (empty)");
        return Ok(());
    }
    
    let map = MapHandle::from_pinned_path(map_path)?;
    println!("Denied IPv4 list:");
    let mut count = 0;
    
    for key in map.keys() {
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

fn list_ipv6() -> Result<()> {
    bump_memlock_rlimit()?;
    
    let map_path = Path::new("/sys/fs/bpf/xdp_denied_ipv6_map");
    
    if !map_path.exists() {
        println!("Denied IPv6 list:");
        println!("  (empty)");
        return Ok(());
    }
    
    let map = MapHandle::from_pinned_path(map_path)?;
    println!("Denied IPv6 list:");
    let mut count = 0;
    
    for key in map.keys() {
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

fn run_xdp(ifindex: i32) -> Result<()> {
    bump_memlock_rlimit()?;

    let skel_builder = XdpabortedSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let mut open_skel = skel_builder.open(&mut open_object)?;

    // Set map reuse paths before loading
    let ipv4_map_path = Path::new("/sys/fs/bpf/xdp_denied_ips_map");
    let ipv6_map_path = Path::new("/sys/fs/bpf/xdp_denied_ipv6_map");

    if ipv4_map_path.exists() {
        // Reuse the existing pinned map
        open_skel.maps.denied_ips_map.set_pin_path(ipv4_map_path)?;
    }

    if ipv6_map_path.exists() {
        // Reuse the existing pinned map
        open_skel.maps.denied_ipv6_map.set_pin_path(ipv6_map_path)?;
    }

    let mut skel = open_skel.load()?;

    let ipv4_map_path = Path::new("/sys/fs/bpf/xdp_denied_ips_map");
    let ipv6_map_path = Path::new("/sys/fs/bpf/xdp_denied_ipv6_map");

    // Pin the maps to make them accessible from other processes
    if !ipv4_map_path.exists() {
        skel.maps.denied_ips_map.pin(ipv4_map_path)
            .map_err(|e| anyhow::anyhow!("Failed to pin IPv4 map: {}", e))?;
    }

    if !ipv6_map_path.exists() {
        skel.maps.denied_ipv6_map.pin(ipv6_map_path)
            .map_err(|e| anyhow::anyhow!("Failed to pin IPv6 map: {}", e))?;
    }
    
    let link = skel.progs.xdp_aborted.attach_xdp(ifindex)?;
    skel.links = XdpabortedLinks {
        xdp_aborted: Some(link),
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let mut count = 0;
    while running.load(Ordering::SeqCst) {
        // 每5秒打印一次计数
        if count % 5 == 0 {
            // 读取IPv4计数 (key=0)
            let key_ipv4: u32 = 0;
            let value_ipv4: Option<u64> = skel.maps.xdp_stats_map
                                        .lookup(&key_ipv4.to_ne_bytes(), libbpf_rs::MapFlags::empty())
                                        .expect("Failed to lookup IPv4 stats")
                                        .map(|v| {
                                            // 将 Vec<u8> 转换为 u64
                                            // 假设 v 是 8 字节的 Vec<u8>
                                            let bytes: [u8; 8] = v.try_into()
                                                .expect("Expected 8 bytes for u64");
                                            u64::from_ne_bytes(bytes)
                                        });
            
            // 读取IPv6计数 (key=1)
            let key_ipv6: u32 = 1;
            let value_ipv6: Option<u64> = skel.maps.xdp_stats_map
                                        .lookup(&key_ipv6.to_ne_bytes(), libbpf_rs::MapFlags::empty())
                                        .expect("Failed to lookup IPv6 stats")
                                        .map(|v| {
                                            // 将 Vec<u8> 转换为 u64
                                            let bytes: [u8; 8] = v.try_into()
                                                .expect("Expected 8 bytes for u64");
                                            u64::from_ne_bytes(bytes)
                                        });
            
            eprintln!("IPv4 packets: {}, IPv6 packets: {}", 
                value_ipv4.unwrap_or(0), value_ipv6.unwrap_or(0));
        }
        count += 1;
        thread::sleep(time::Duration::from_secs(1));
    }

    Ok(())
}