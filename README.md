# BotGuard-Core: eBPF-Powered ROS 2 Sentinel 🛡️

**BotGuard-Core** is a next-generation security monitor for ROS 2. Built on **eBPF (Extended Berkeley Packet Filter)**, it operates within the Linux kernel to provide "Zero Trust" visibility into your robot's software ecosystem. 

Unlike standard firewalls or network sniffers, BotGuard is **application-aware**, identifying ROS 2 nodes "at birth" before they even send their first packet.

---

## 🎯 The Aim
The primary goal of BotGuard Core is to solve the **"Invisibility Problem"** in modern robotics:
*   **SHM Silence**: Capturing discovery traffic that never touches the network (Shared Memory).
*   **Attribution**: Instantly linking network packets to their specific Process IDs (PIDs) and Binary names.
*   **Domain Blindness**: Detecting unauthorized nodes regardless of their `ROS_DOMAIN_ID`.

---

## 🚀 Final Features (Current State)
*   **Sentinel Engine**: Hooks directly into `rmw_create_node` within the ROS 2 middleware using Uprobes for 100% identification reliability.
*   **Process Unmasker**: Automatically resolves PIDs to their binary names (e.g., `firefox`, `talker`, `pulseaudio`) to distinguish system noise from robot traffic.
*   **Deep Packet Inspection (DPI)**: Real-time RTPS discovery parsing to identify node names and topics.
*   **Live Dashboard**: A professional Terminal UI (TUI) providing real-time situational awareness.

---

## 🛠️ How to Run

### Prerequisites
*   Ubuntu 22.04+ (Kernel 5.15+)
*   ROS 2 Humble (installed at `/opt/ros/humble`)
*   Rust (Nightly toolchain for eBPF)

### 1. Build the eBPF Kernel
```bash
cargo +nightly run --package xtask -- build-ebpf
```

### 2. Build the Userspace Dashboard
```bash
cargo build --package botguard-userspace
```

### 3. Launch the Monitor
```bash
sudo ./target/debug/botguard-userspace
```
*Press **'q'** to exit and restore the terminal.*

---

## 🗺️ Roadmap: The Next Update
The current version focuses on **Internal Identification and Monitoring**. The next milestone includes:
*   **Identifying External Packets**: Auto-detecting and flagging traffic from unauthorized IP addresses on the network.
*   **XDP Sentinel Firewall**: Implementing the kernel-level "Pruning" engine (XDP_DROP) to block unauthorized traffic before it reaches the ROS 2 stack.

---

*“Security shouldn't be a locked door; it should be a live Sentinel.”* 🤖
