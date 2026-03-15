use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};

use anyhow::{bail, Result};
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use libbpf_rs::MapCore;
use structopt::StructOpt;

mod xdpredirect {
    include!(concat!(env!("OUT_DIR"), "/xdpredirect.skel.rs"));
}
use xdpredirect::*;

#[derive(Debug, StructOpt)]
struct Command {
    /// Interface index to attach XDP program
    #[structopt(default_value = "0")]
    ifindex: i32,

    /// MAC address of the interface (format: xx:xx:xx:xx:xx:xx)
    #[structopt(long)]
    mac: Option<String>,

    /// Bridge rule: source_mac->dest_mac (format: xx:xx:xx:xx:xx:xx->yy:yy:yy:yy:yy:yy)
    #[structopt(long, multiple = true, parse(try_from_str = parse_bridge_rule))]
    bridge_rule: Vec<(String, String)>,
}

// 自定义解析函数，将 "xx:xx:xx:xx:xx:xx->yy:yy:yy:yy:yy:yy" 格式解析为 (source_mac, dest_mac)
fn parse_bridge_rule(s: &str) -> Result<(String, String)> {
    if let Some(idx) = s.find("->") {
        let src = &s[..idx];
        let dst = &s[idx+2..];

        // 验证MAC地址格式
        parse_mac(src)?;
        parse_mac(dst)?;

        Ok((src.to_string(), dst.to_string()))
    } else {
        bail!("Invalid bridge rule format: {}. Expected source_mac->dest_mac", s);
    }
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) != 0 } {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn parse_mac(mac_str: &str) -> Result<[u8; 6]> {
    let mut mac = [0u8; 6];
    let parts: Vec<&str> = mac_str.split(':').collect();

    if parts.len() != 6 {
        bail!("Invalid MAC address format: {}", mac_str);
    }

    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| anyhow::anyhow!("Invalid MAC address octet: {}", part))?;
    }

    Ok(mac)
}

fn setup_bridge_rules(skel: &mut XdpredirectSkel, rules: &[(String, String)]) -> Result<()> {
    for (src_mac_str, dst_mac_str) in rules {
        let src_mac = parse_mac(src_mac_str)?;
        let dst_mac = parse_mac(dst_mac_str)?;

        // 添加桥接规则
        let src_key = [src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]];
        let src_value = [dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]];

        skel.maps.bridge_rules.update(&src_key, &src_value, libbpf_rs::MapFlags::NO_EXIST)?;

        println!("Added bridge rule: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                 src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
                 dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    }

    Ok(())
}

fn setup_interface_mac(skel: &mut XdpredirectSkel, ifindex: i32, mac_str: Option<String>) -> Result<()> {
    let mac = if let Some(mac_str) = mac_str {
        parse_mac(&mac_str)?
    } else {
        // 如果没有提供MAC地址，尝试从系统获取
        get_interface_mac(ifindex)?
    };

    let key = ifindex.to_le_bytes();
    let value = [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]];

    skel.maps.iface_map.update(&key, &value, libbpf_rs::MapFlags::NO_EXIST)?;

    println!("Set interface {} MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
             ifindex, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    Ok(())
}

fn get_interface_mac(_ifindex: i32) -> Result<[u8; 6]> {
    // 在实际应用中，这里应该通过系统调用获取接口MAC地址
    // 这里我们返回一个示例MAC地址
    Ok([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    bump_memlock_rlimit()?;

    let skel_builder = XdpredirectSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;

    // 设置接口MAC地址
    setup_interface_mac(&mut skel, opts.ifindex, opts.mac)?;

    // 设置桥接规则
    if !opts.bridge_rule.is_empty() {
        setup_bridge_rules(&mut skel, &opts.bridge_rule)?;
    }

    // 重新加载程序以应用新的配置
    let skel_builder2 = XdpredirectSkelBuilder::default();
    let mut open_object2 = MaybeUninit::uninit();
    let open_skel2 = skel_builder2.open(&mut open_object2)?;
    let mut skel = open_skel2.load()?;
    let link = skel.progs.xdp_bridge.attach_xdp(opts.ifindex)?;
    skel.links = XdpredirectLinks {
        xdp_bridge: Some(link),
    };

    println!("XDP Bridge program loaded on interface {}", opts.ifindex);
    if !opts.bridge_rule.is_empty() {
        println!("Bridge rules configured:");
        for (src, dst) in &opts.bridge_rule {
            println!("  {}->{}", src, dst);
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        eprint!(".");
        thread::sleep(time::Duration::from_secs(1));
    }

    println!("
Shutting down XDP Bridge program...");
    Ok(())
}
