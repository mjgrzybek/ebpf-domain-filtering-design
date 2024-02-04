# Introduction
This design document presents an overview of the system, outlining its architecture, capabilities, and technical implementation details. The TOOL system is designed to offer users the ability to detect and prevent unknown network connections, thereby enhancing the security posture of their systems.

By leveraging the power of eBPF, the TOOL system provides granular control over network traffic, allowing users to define custom rules for filtering connections based on various criteria. 

the TOOL system runs in "detect" mode for passive monitoring or "prevent" mode for proactive blocking against unauthorized access and malicious activities.

# Requirements analysis
- Two modes
    - detect mode
        - understand and inspect the network behavior 
    - prevent mode
        - enforce configured rules by blockicg unknown/unwanted network traffic
- UX
    - input
        - easy and encoruaging to write and read
        - config syntax should be easy to validate with schema 
        - in widely acknowledged format
            - yaml (incl. json) + jsonschema
            - cuelang maybe?
            - not xml :)
    - output
        - otel integration for
            - traces
            - metrics
            - log 
        - audit.log accessible for priviledged user only
            - human readable log records
            - no need to be parse-friendly becasue otel logs can be used for that
        - expose API
        - allow 3rd party software to subscribe for events from us
    - should allow users effectivly configure the system against potential threats
    - reasonable defaults
    - documented features with examples
    - playground/online editor like [editor.networkpolicy.io](editor.networkpolicy.io)
- Security
    - only priviledged user can access audit.log or daemon configuration
    - should not alter packets' content
- Error handling
    - user decides what to do with errors
    - drop packets by default?
- Scalability
    - should be able to handle high traffic
    - should be able to handle high number of rules

# System overview
![System overview](./system-overview.png)
TOOL leverages ebpf therefore it's split into two parts - user space and kernel space.

## User space
Daemon running in userspace is responsible for ebpf programs orchestration and integration with OS, user and 3rd party software.

It requires capabilities: `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`.

### Configuration processor
Module responsible for processing the configuration.
It creates rules for the engine and provides configuration to other modules.

### Engine
The Engine manages the execution of ebpf programs, taking its input from rules established by the Configuration Processor.

The TOOL is shipped with predefined set of capabilities. Capability is a pair of ebpf program templates and Engine logic. 

Templates are populated with specific values derived from the rules, after which they are compiled and loaded into the kernel.

### otel exporter
OpenTelemetry exporter is responsible for exporting traces, metrics and logs to the OpenTelemetry collector.
 
### event publisher
Event publisher is responsible allowing 3rd party software to subscribe for events from us. Event subscriber can be any software that can consume events from us, so user is responsible for providing an adapter for that software.

## Kernel space - ebpf programs
Ebpf programs are loaded to kernel and are responsible for tracking and filtering network traffic.

Packet drops should happen on ebpf program level when possible.

Moving logic to user space is acceptable when it's not possible to calculate decision based on single packet content in ebpf program.

## Communication between kernel and user space
Communication between kernel and user space is done via bpf maps.

Map type and data structure is ebpf-program (capabality) specific.

# Feature capabalities
The issue we aim to address is the identification and blocking of undesired network connections. In this context, we define a network connection as a L3 connection between hosts in an IPv4 or IPv6 network.

We will primarily concentrate on the most frequently used L4 protocols, which include TCP, UDP. Additionally, we will consider L7 protocols such as HTTP, HTTPS, DNS, SSH.

Following is a list of features that the TOOL will support for filtering network connections:

## L3
    - IP filtering
    - IP ranges

## L4
### TCP
    - Port ranges
    - Connection duration
### UDP
    - Port ranges

## L7
### HTTP
    - Domain
    - Asterisk for domains?
        - no, it's a security threat. Attacker could exploit it by registering a domain matching wildcard, e.g.: `*facebook*` -> `baitfacebook.co`
    - Subdomains
    - Path
    - HTTP methods
    - HTTP headers
    - Protocol version
### HTTPS
    - CA filtering based on CN, exp date, issuer, etc.
    - TLS version

### DNS
    - Domain allowlist
    - DNS server allowlist
    - DNS over TLS

### SSH
    - incomming connections filtering by IP (IP range) or public key
    - outgoing connections filtering by IP (IP range) or hostname

## Other
    - anomalies detection based on previous traffic
    - profiling, statistics

# Technical implementation details
## Configuration processor
The TOOL system will be configured using a configuration file. The configuration file will be in YAML format and will be validated using JSON schema.

The configuration file will contain the following sections:
- `mode` - the mode in which the TOOL system will operate (detect or prevent)
- `rules` - a list of rules that define the filtering criteria for network connections
- `logging` 
- `otel` 
- `event_publisher` 

### Rules
Each rule will contain the following fields:
- `name` - a unique name for the rule
- `action` - the action to be taken when the rule is matched (allow or block)
- `layer3` - L3 filtering criteria
- `layer4` - L4 filtering criteria
- `layer7` - L7 filtering criteria

## Engine
The Engine is responsible for:
- loading an unloading of ebpf programs
- reading and processing ebpf programs' events passed via ebpf map
- reacting on configuration changes

It will take its input from rules established by the Configuration Processor.

For example, for a rule that blocks all connections from a specific IP address, an ebpf program will emit an event when a connection to that IP address is detected.  

```c
BPF_PERF_OUTPUT(output); 
 
 enum decision {
    DETECTED, // connection detected but prevention mode is not enabled
    ALLOWED,
    BLOCKED,
};

// Structure to hold data that will be sent to user space
struct event {
    u32 ip_src;
    enum decision decision;
};

// naive implementation, array based, O(n) search complexity
// in real world, we would use a hash map with O(1) search complexity
bool is_ip_allowed(u32 ip) {
    u32 allowedIps[] = { 
        // dynamically generated by the Engine, based on user-defined rule content
    }

    u32 allowedIpsLen = sizeof(allowedIps) / sizeof(allowedIps[0]);

    for (u32 i = 0; i < allowedIpsLen; i++) {
        if (allowedIps[i] == ip) {
            return true;
        }
    }

    return false;
}

SEC("xdp")
int filter_ip(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *iph = data + sizeof(struct ethhdr);

    ip = get_source_ip(iph);
    is_allowed = is_ip_allowed(ip);

    struct event event = {
        .ip_src = ip,
        .decision = is_allowed ? ALLOWED : BLOCKED,
    };
    output.perf_submit(ctx, &event, sizeof(event)); 

    return is_allowed ? XDP_PASS : XDP_DROP;
}

```

## ebpf programs
There are few places where ebpf programs can be attached to. <br>
We need to decide on performance and maintainability trade-offs when choosing the right place for ebpf programs.

### XDP
Works only for incomming traffic. It's the fastest way to process packets because it's done before packet is processed by kernel's network stack.

`xdp_md` struct exposes data about the packet:
- `ethhdr` - ethernet header
- `iphdr` - IP header
- `tcphdr` - TCP header
- `udphdr` - UDP header

It allows to realively easily filter traffic based on L3 and L4 criteria.

### Traffic control
Works for both incomming and outgoing traffic.
While it's more flexible than XDP, it's a bit slower because packet is already processd in kernel's netowrk stack. 

Incomming traffic in handled by XDP, so we can use tc for outgoing (egress) traffic.

### Socket filter
Socket filter can be used for L7 traffic filtering.<br>
Our case is descibed here: [https://eunomia.dev/tutorials/23-http/#capturing-http-traffic-with-ebpf-socket-filter](https://eunomia.dev/tutorials/23-http/#capturing-http-traffic-with-ebpf-socket-filter)

While L3-4 processing required only single packet as an input, in L7 we need to process multiple packets to understand the context of the connection.
It means for L7 filters we need to move logic from ebpf program to user space.<br>
It will incure some performance penalty, but it seems acceptable due to nature of L7 protocols. Performance should be measured before drawing any conclusions.

### Syscall tracepoints
Another possible way for L7 filtering is to use syscall tracepoints. <br>
L7 session data can be collected from syscalls and then processed in user space.

As mentioned [here](https://eunomia.dev/tutorials/23-http/#hook-locations-and-flow), syscalls that typically need to be hooked include: `socket`, `bind`, `listen`, `accept`, `read`, `write`.

# Limitation and Constraints
## Environments
To install and use the TOOL, user needs to have superuser privileges. It is not a problem when working in on premise or IaaC environments. <br>

However, in PaaS or SaaS environments, it needs to be supported by the provider.
## Linux distributions
No limitations, as long as the kernel supports eBPF.
## Kernel versions
Depending on scope of features provided, different kernel versions may be required: [BPF Features by Linux Kernel Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
## Hardware
The TOOL is hardware agnostic.<br>
SmartNIC can improve performance of XDP programs because it offloads packet processing from CPU to NIC.
## Scalability
Need to be tested in test environment with network traffic generator against various hardware configurations.

# Sources
- https://link.springer.com/article/10.1007/s10922-022-09687-z
- https://eunomia.dev/tutorials/23-http/
- https://stackoverflow.com/questions/76637174/how-to-write-an-ebpf-xdp-program-to-drop-tcp-packets-containing-a-certain-byte-p
- https://developers.redhat.com/blog/2021/04/01/get-started-with-xdp#task_1__write_and_run_a_simple_program_with_xdp
- https://www.datadoghq.com/blog/xdp-intro/
- https://www.stackpath.com/blog/bpf-hook-points-part-1/
- https://unix.stackexchange.com/questions/688065/how-do-packets-flow-through-the-kernel
- Learning eBPF - Liz Rice 