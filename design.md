# Introduction
This design document presents an overview of the system, outlining its architecture, capabilities, and technical implementation details. The TOOL system is designed to offer users the ability to detect and prevent unknown network connections, thereby enhancing the security posture of their systems.

By leveraging the power of eBPF, the TOOL system provides granular control over network traffic, allowing users to define custom rules for filtering connections based on various criteria. 

the TOOL system runs in "detect" mode for passive monitoring or "prevent" mode for proactive blocking against unauthorized access and malicious activities.

# Requirements analysis
- two modes
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

# System overview
![Alt text](./system-overview.png)
TOOL leverages ebpf therefore it's split into two parts - user space and kernel space.

## User space daemon
Daemon running in userspace is responsible for ebpf programs orchestration and integration with OS, user and 3rd party software.




## Kernel space - ebpf programs

## Communication between kernel and user space

# User experience

# Feature capabalities
    - anomalies detection
    - suggestion based on traffic
    - offer profiling, statistics
# Technical implementation details

# Limitation and Constraints

# Testing and validdation

# Conclusion