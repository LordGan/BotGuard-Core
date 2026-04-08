use aya::programs::{TracePoint, UProbe};
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::perf::AsyncPerfEventArray;
use aya_log::EbpfLogger;
use botguard_common::PacketEvent;
use bytes::BytesMut;
use log::{info, warn};
use tokio::signal;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Bump rlimit
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        warn!("remove limit on locked memory failed");
    }

    // Load eBPF
    let bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/botguard"
    ))?;
    
    // Leak the BPF handle so it's 'static' and can be used in background tasks safely.
    let bpf = Box::leak(Box::new(bpf));

    if let Err(e) = EbpfLogger::init(bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Attach to sys_enter_sendto tracepoint
    let program: &mut TracePoint = bpf.program_mut("botguard_sendto").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_sendto")?;

    // Attach to sys_enter_sendmsg tracepoint
    let program: &mut TracePoint = bpf.program_mut("botguard_sendmsg").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_sendmsg")?;

    // Attach THE SENTINEL (UProbe)
    // We target the heart of the ROS 2 Humble middleware
    let rmw_lib = "/opt/ros/humble/lib/librmw_fastrtps_cpp.so";
    if std::path::Path::new(rmw_lib).exists() {
        let program: &mut UProbe = bpf.program_mut("botguard_sentinel").unwrap().try_into()?;
        program.load()?;
        // Hook the node creation function
        program.attach(Some("rmw_create_node"), 0, rmw_lib, None)?;
        info!("🛰️ Sentinel Mode ATTACHED to: {}", rmw_lib);
    } else {
        warn!("⚠️ ROS 2 Humble library not found at {}, Sentinel Mode skipped.", rmw_lib);
    }

    info!("🛡️ BotGuard Core Passive Mapper is ACTIVE!");

    let perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap())?;
    let perf_array = Box::leak(Box::new(perf_array));

    // Use a JoinSet to manage the tasks
    let mut tasks = tokio::task::JoinSet::new();
    
    // Shared state to track which PIDs we've already announced to avoid noise
    let known_pids = Arc::new(Mutex::new(HashSet::new()));

    for cpu_id in aya::util::online_cpus().map_err(|(s, _e)| anyhow::anyhow!(s))? {
        let mut buf = perf_array.open(cpu_id, None)?;
        let known_pids = known_pids.clone();

        tasks.spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(std::mem::size_of::<PacketEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(e) => e,
                    Err(_) => break,
                };
                
                for i in 0..events.read {
                    let buf = &buffers[i];
                    let ptr = buf.as_ptr() as *const PacketEvent;
                    let event = unsafe { ptr.read_unaligned() };
                    
                    let packet_len = (event.len as usize).min(botguard_common::MAX_PACKET_SIZE);
                    let data = &event.packet[..packet_len];

                    if event.len == 0xDEED {
                        // Sentinel birth event! Data is the node name string.
                        let name = std::str::from_utf8(data).unwrap_or("unknown").trim_matches(char::from(0));
                        if name == "unknown" || name.is_empty() {
                            let hex = data.iter().take(16).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                            info!("🤖 SENTINEL: Node Born (Name hidden) | PID: {} | Memory Peek: [{}]", event.pid, hex);
                        } else {
                            info!("🤖 SENTINEL: ROS 2 Node Born -> [{}] (PID: {})", name, event.pid);
                        }
                        known_pids.lock().unwrap().insert(event.pid);
                    } else {
                        // Regular activity - only show it if it's new or looks like ROS 2
                        let is_new = known_pids.lock().unwrap().insert(event.pid);
                        
                        if let Some(node_name) = find_node_name(data) {
                            info!("🤖 ROS 2 NODE DETECTED: [{}] (PID: {})", node_name, event.pid);
                        } else if is_new && event.len > 0 {
                            if data.starts_with(b"RTPS") {
                                info!("📡 RTPS Discovery from PID: {} (Name hidden deeper...)", event.pid);
                            } else {
                                let hex = data.iter().take(8).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                                info!("📡 New Activity from PID: {} | Hex: [{}...]", event.pid, hex);
                            }
                        }
                    }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C... (or background tasks to exit)");
    
    // Select between Ctrl-C and the background tasks
    tokio::select! {
        _ = signal::ctrl_c() => info!("Ctrl-C received, exiting..."),
        _ = async { while let Some(_) = tasks.join_next().await {} } => info!("All tasks finished, exiting..."),
    }

    Ok(())
}

fn find_node_name(data: &[u8]) -> Option<String> {
    // Look for the RTPS pattern for Participant Name
    // Usually PID_ENTITY_NAME is 0x0062 (98 in decimal) 
    // In ParameterList it's stored as [0x62, 0x00, length_low, length_high, data...]
    for i in 0..(data.len().saturating_sub(8)) {
        if data[i] == 0x62 && data[i+1] == 0x00 {
            let len = u16::from_le_bytes([data[i+2], data[i+3]]) as usize;
            // Basic sanity check: names aren't 0 or huge
            if len > 1 && len < 64 && i + 4 + len <= data.len() {
                let name_bytes = &data[i+4..i+4+len];
                if let Ok(name) = std::str::from_utf8(name_bytes) {
                    let cleaned = name.trim_matches(char::from(0)).trim();
                    if !cleaned.is_empty() {
                        return Some(cleaned.to_string());
                    }
                }
            }
        }
    }
    None
}
