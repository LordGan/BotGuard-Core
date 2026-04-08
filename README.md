# 🛡️ BotGuard-Core

Zero-Jitter, Kernel-Level Observability for ROS 2.

BotGuard Core is an open-source security and performance monitor for ROS 2, powered by eBPF. It provides deep visibility into your robot's software stack without requiring any changes to your source code or middleware configuration.

## 🚀 Key Features

*   **eBPF Node Mapper**: Real-time mapping of Linux PIDs to ROS 2 Node names. Know exactly which process is responsible for which node.
*   **Passive Network Auditor**: Monitor DDS and Zenoh traffic latency, throughput, and jitter directly from the kernel.
*   **Security Observability**: Detect unauthorized nodes or unexpected "listeners" joining the ROS graph.
*   **Zero-Overhead**: By operating in the kernel, BotGuard avoids the context-switching penalties of traditional monitoring tools.

## 📦 Installation
*Coming soon...*

## 📜 Transparency & Licensing

BotGuard Core is licensed under GPLv2. We believe that the "eyes" of your robot should be open and auditable.

> [!NOTE]
> BotGuard Core provides **Passive Monitoring only**. For active defense (blocking attacks), hardware-bound licensing, and fleet-wide management, please see **BotGuard Pro**.
