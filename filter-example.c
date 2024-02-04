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
    // content dynamically generated, based on rule
    u32 allowedIps[] = { 
        // ...
    }

    // allowedIps array length in c
    allowedIpsLen = sizeof(allowedIps) / sizeof(allowedIps[0]);

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

    struct event data = {
        .ip_src = ip,
        .decision = is_allowed ? ALLOWED : BLOCKED,
    };
    output.perf_submit(ctx, &data, sizeof(data)); 

    return is_allowed ? XDP_PASS : XDP_DROP;
}
