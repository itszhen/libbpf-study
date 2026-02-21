# libbpf-study My learning branch for studying the scaffolding of libbpf/BPF CO-RE.
Original repository: libbpf/libbpf-bootstrap

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
returning `XDP_PASS` to allow the packet to be passed up to the kernel’s networking stack.

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
