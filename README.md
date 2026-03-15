# libbpf-study: Exploring libbpf/BPF CO-RE framework
Originally from: libbpf/libbpf-bootstrap

Make sure you have cloned this repo using `--recurse` and installed the dependencies
before you try to build the examples.

## exp_minimal

`minimal` is just that – a minimal practical BPF application example. It
doesn't use or require BPF CO-RE, so should run on quite old kernels. It
installs a tracepoint handler which is triggered once every second. It uses
`bpf_printk()` BPF helper to communicate with the world. To see it's output,
read `/sys/kernel/debug/tracing/trace_pipe` file as a root:

```shell
$ cd exp_minimal
$ make
$ sudo ./minimal
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: BPF triggered from PID 3840345.
           <...>-3840345 [010] d... 3220702.101265: bpf_trace_printk: BPF triggered from PID 3840345.
```

`minimal` is great as a bare-bones experimental playground to quickly try out
new ideas or BPF features.

## exp_xdp

`xdp` is an example written in Rust (using libbpf-rs).
It attaches to the ingress path of networking device,
logs the size of each packet,
parses the packet's Ethernet header, IP header, and TCP/UDP header,
counts the number of IPv4 and IPv6 packets,
returning `XDP_PASS` to allow the packet to be passed up to the kernel's networking stack.

```shell
$ cd exp_xdp
$ cargo build --release
$ sudo ./target/release/xdp 1
..........
```

The `xdp` output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
 systemd-resolve-533     [001] ..s11  1930.880170: bpf_trace_printk: === Packet Received ===
 systemd-resolve-533     [001] ..s11  1930.880172: bpf_trace_printk: packet size: 307
 systemd-resolve-533     [001] ..s11  1930.880172: bpf_trace_printk: Ethernet Header:
 systemd-resolve-533     [001] ..s11  1930.880173: bpf_trace_printk:   Destination: 00:00:00:00:00:00
 systemd-resolve-533     [001] ..s11  1930.880174: bpf_trace_printk:   Source: 00:00:00:00:00:00
 systemd-resolve-533     [001] ..s11  1930.880175: bpf_trace_printk:   Type: 0x0800
 systemd-resolve-533     [001] ..s11  1930.880175: bpf_trace_printk: It is an IPv4 Packect
 systemd-resolve-533     [001] ..s11  1930.880175: bpf_trace_printk: IP Header:
 systemd-resolve-533     [001] ..s11  1930.880176: bpf_trace_printk:   Version: 4, IHL: 5
 systemd-resolve-533     [001] ..s11  1930.880176: bpf_trace_printk:   TOS: 0, Total Length: 293
 systemd-resolve-533     [001] ..s11  1930.880177: bpf_trace_printk:   TTL: 1, Protocol: 17
 systemd-resolve-533     [001] ..s11  1930.880178: bpf_trace_printk:   Source: 127.0.0.53
 systemd-resolve-533     [001] ..s11  1930.880179: bpf_trace_printk:   Destination: 127.0.0.1
 systemd-resolve-533     [001] ..s11  1930.880179: bpf_trace_printk: UDP Header:
 systemd-resolve-533     [001] ..s11  1930.880179: bpf_trace_printk:   Source Port: 53
 systemd-resolve-533     [001] ..s11  1930.880180: bpf_trace_printk:   Dest Port: 41810
 systemd-resolve-533     [001] ..s11  1930.880180: bpf_trace_printk:   Length: 273
```

The `xdp` counter map in `xdp_stats_map` should look
something like this:

```shell
$ sudo bpftool map dump name xdp_stats_map
[{
        "key": 0,
        "value": 489
    },{
        "key": 1,
        "value": 0
    }
]
```

## xdp_blacklist

`blacklist` is an example written in Rust (using libbpf-rs) that dynamically manages a blacklist of IP addresses.
It attaches to the ingress path of a network device, logging the size and type of each packet.
If a packet's IP address is found in the blacklist, it returns `XDP_ABORTED` to deny the packet.
If the packet is not an IP packet, or its IP is not in the blacklist, it returns `XDP_PASS` to allow the packet to be passed up to the kernel's networking stack. Additionally, it counts the number of IPv4 and IPv6 packets.

```shell
$ cd xdp_blacklist
$ cargo build --release
$ sudo ./target/release/xdp
xdp 0.1.0

USAGE:
    xdp <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    add-ipv4       Add an IPv4 address or CIDR to the denied list
    add-ipv6       Add an IPv6 address or CIDR to the denied list
    delete-ipv4    Delete an IPv4 address or CIDR from the denied list
    delete-ipv6    Delete an IPv6 address or CIDR from the denied list
    help           Prints this message or the help of the given subcommand(s)
    list-ipv4      List all denied IPv4 addresses
    list-ipv6      List all denied IPv6 addresses
    run            Run the XDP program
```

Adding and listing denied IPv4 and IPv6 addresses:

```shell
$ sudo ./target/release/xdp add-ipv4 0.0.0.0/0
Added 0.0.0.0/0 to denied IPv4 list

$ sudo ./target/release/xdp list-ipv4
Denied IPv4 list:
  0.0.0.0/0

$ sudo ./target/release/xdp add-ipv6 ::1/64
Added ::1/64 to denied IPv6 list

$ sudo ./target/release/xdp list-ipv6
Denied IPv6 list:
  ::1/64
```

Running the XDP program:

```shell
$ sudo ./target/release/xdp run 1
IPv4 packets: 0, IPv6 packets: 0
IPv4 packets: 0, IPv6 packets: 0
IPv4 packets: 0, IPv6 packets: 0
```

Deleting denied IPv4 addresses and the packet counter can increase:

```shell
$ sudo ./target/release/xdp delete-ipv4 0.0.0.0/0
Deleted 0.0.0.0/0 from denied IPv4 list

$ sudo ./target/release/xdp run 1
IPv4 packets: 0, IPv6 packets: 0
IPv4 packets: 0, IPv6 packets: 0
IPv4 packets: 0, IPv6 packets: 0
Pv4 packets: 30, IPv6 packets: 0
```

## xdp_bridge

`xdp_bridge` is an example written in Rust (using libbpf-rs) that demonstrates packet bridging functionality. It can forward packets between network interfaces, similar to a network switch. The program allows configuration of interface MAC addresses and bridging rules. When packets are received, it updates the source and destination MAC addresses according to the rules and forwards them.

```shell
$ cd xdp_bridge
$ cargo build --release
$ sudo ./target/release/xdp 2 --mac 02:00:00:00:00:02 --bridge-rule "02:00:00:00:00:01->02:00:00:00:00:02"
Set interface 2 MAC: 02:00:00:00:00:02
Added bridge rule: 02:00:00:00:00:01 -> 02:00:00:00:00:02
XDP Bridge program loaded on interface 2
Bridge rules configured:
  02:00:00:00:00:01->02:00:00:00:00:02
..........
```

This command loads the XDP bridge program on interface 2, sets the interface MAC address to 02:00:00:00:00:02, and adds a bridging rule: forward packets with source MAC address 02:00:00:00:00:01 to destination MAC address 02:00:00:00:00:02.

The bridge rule format uses "->" to separate the source and destination MAC addresses, making it more readable: "source_mac->dest_mac".

The program's output in `/sys/kernel/debug/tracing/trace_pipe` might look like this:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: === Packet Received on Interface 2 ===
            <...>-3840345 [010] d... 3220701.101144: bpf_trace_printk: Current MAC: 02:00:00:00:00:02
            <...>-3840345 [010] d... 3220701.101145: bpf_trace_printk: Dest MAC: 02:00:00:00:00:01
            <...>-3840345 [010] d... 3220701.101146: bpf_trace_printk: Source MAC: 02:00:00:00:00:01
            <...>-3840345 [010] d... 3220701.101147: bpf_trace_printk: Packet Type: 0x0800
            <...>-3840345 [010] d... 3220701.101148: bpf_trace_printk: Found bridge rule - forwarding packet
```

This program can be used in various scenarios such as network traffic monitoring, load balancing, or network security.