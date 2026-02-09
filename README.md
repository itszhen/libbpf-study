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

`xdp` is an example written in Rust (using libbpf-rs). It attaches to
the ingress path of networking device and logs the size of each packet,
returning `XDP_PASS` to allow the packet to be passed up to the kernel’s
networking stack.

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
           <...>-823887  [000] d.s1 602386.079100: bpf_trace_printk: packet size: 75
           <...>-823887  [000] d.s1 602386.079141: bpf_trace_printk: packet size: 66
           <...>-2813507 [000] d.s1 602386.696702: bpf_trace_printk: packet size: 77
           <...>-2813507 [000] d.s1 602386.696735: bpf_trace_printk: packet size: 66
```
