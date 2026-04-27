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

## 🚀 Features (Current State)
*   **Sentinel Engine**: Hooks directly into `rmw_create_node` using Uprobes for 100% internal identification reliability.
*   **Network Identity**: Kernel TC (Traffic Control) monitor captures Source IP and MAC addresses of remote participants.
*   **Deep Packet Inspection (DPI)**: Real-time RTPS discovery parsing to "unmask" both local and remote nodes.
*   **Live Dashboard**: A Terminal UI (TUI) with prioritized sorting (Remote > Local > Noise).

---

## 🛠️ How to Run

### 1. Build the eBPF Kernel
```bash
cargo +nightly run --package xtask -- build-ebpf
```

### 2. Launch the Monitor
```bash
cargo build --package botguard-userspace
sudo ./target/debug/botguard-userspace
```

### 🌐 Monitoring Different Interfaces
By default, the network sentinel guards `eth0`. To monitor a different interface (like WiFi or Docker), update `botguard-userspace/src/main.rs`:

```rust
let iface = "wlan0"; // For WiFi Robots
// let iface = "docker0"; // For Simulation
```

## 🛡️ Identity Types
- 🛡️ **[Internal]**: Detected via kernel Uprobes. Shows **PID** and **Binary Name**.
- 🌐 **[External]**: Detected via Kernel TC monitor. Shows **IP** and **MAC Address**.

---

*“Security shouldn't be a locked door; it should be a live Sentinel.”* 🤖
