# Implementing Domain Filtering in eBPF
Read about THE_TOOL capabilities at _URL_ and how to get started with THE_TOOL at _URL_.

One of the main capabilities of THE_TOOL is to stop unknown network connections. On the one
hand, THE_TOOL should be able to run on “detect” mode to understand and inspect the network
behavior. On the other hand, THE_TOOL should be able to run on “prevent” mode and block
unknown network connections.

The exercise is to create a system design for implementing the feature that detects and blocks
network connections.

Please explain, by any means you find necessary - words, diagrams, code snippets as examples,
and external code sources, how you can implement this feature. Please pay attention to the
following:

- What would be the user experience with the feature you included - what is the input the
user provides, and what is the output?
- What are the feature capabilities - IP filtering? Domain filtering? Asterisk for domains?
Subdomains? IP ranges?
- Technical implementation details - How eBPF code would be loaded, what hooks were
used, how the code would look for each BPF program, and how the data would be
transferred from kernel to user.
- Limitation of the provided solution - Environments, distributions, kernel versions, etc.
Please provide as much detail as possible for your design and anything that could help to
understand, like snippets or diagrams.

## Notes:
- For this exercise, you shouldn’t be an expert in software supply-chain security or
understand all the recent vulnerabilities in that area. We do look for the ability to take
complex features in the security realm and analyze them end to end.

- You can submit it in any way you feel comfortable - sending a PDF, sharing a doc,
sharing a GitHub repository, etc.