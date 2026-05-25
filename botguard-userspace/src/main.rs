use aya::programs::{TracePoint, UProbe, SchedClassifier, tc};
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::perf::AsyncPerfEventArray;
use aya_log::EbpfLogger;
use botguard_common::PacketEvent;
use bytes::BytesMut;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ratatui::{
    backend::CrosstermBackend,
    widgets::{Block, Borders, List, ListItem, Table, Row, Cell, Paragraph},
    layout::{Layout, Constraint, Direction},
    style::{Style, Color, Modifier},
    Terminal, Frame,
};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

struct NodeInfo {
    name: String,
    proc_name: String,
    last_seen: Instant,
    pkts_sent: u64,
    pkts_recv: u64,
    bytes_sent: u64,
    bytes_recv: u64,
    pubs: u32,
    subs: u32,
    srvs: u32,
    clis: u32,
    src_ip: Option<String>,
    src_mac: Option<String>,
    bytes_sent_prev: u64,
    bytes_recv_prev: u64,
    tx_rate: f64,
    rx_rate: f64,
    last_rate_calc: Instant,
}

struct MonitorState {
    nodes: HashMap<String, NodeInfo>,
    recent_events: VecDeque<String>,
    active_rmw: String,
}

impl MonitorState {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            recent_events: VecDeque::with_capacity(20),
            active_rmw: "None".to_string(),
        }
    }

    fn add_event(&mut self, event: String) {
        if self.recent_events.len() >= 15 {
            self.recent_events.pop_back();
        }
        self.recent_events.push_front(event);
    }

    fn update_rates(&mut self) {
        let now = Instant::now();
        for node in self.nodes.values_mut() {
            let elapsed = now.duration_since(node.last_rate_calc).as_secs_f64();
            if elapsed >= 0.95 {
                let sent_diff = node.bytes_sent.saturating_sub(node.bytes_sent_prev);
                let recv_diff = node.bytes_recv.saturating_sub(node.bytes_recv_prev);
                
                node.tx_rate = sent_diff as f64 / elapsed;
                node.rx_rate = recv_diff as f64 / elapsed;
                
                node.bytes_sent_prev = node.bytes_sent;
                node.bytes_recv_prev = node.bytes_recv;
                node.last_rate_calc = now;
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let state = Arc::new(Mutex::new(MonitorState::new()));
    
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
    }

    let bpf_res = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/botguard"
    ));

    let bpf = match bpf_res {
        Ok(b) => Box::leak(Box::new(b)),
        Err(e) => {
            restore_terminal(&mut terminal)?;
            return Err(e.into());
        }
    };

    let _ = EbpfLogger::init(bpf);

    let _ = attach_tracepoint(bpf, "botguard_sendto", "syscalls", "sys_enter_sendto");
    let _ = attach_tracepoint(bpf, "botguard_sendmsg", "syscalls", "sys_enter_sendmsg");

    let rmw_lib = "/opt/ros/humble/lib/librmw_fastrtps_cpp.so";
    if std::path::Path::new(rmw_lib).exists() {
        attach_uprobe(bpf, "botguard_node_sentinel", "rmw_create_node", rmw_lib)?;
        attach_uprobe(bpf, "botguard_pub_sentinel", "rmw_create_publisher", rmw_lib)?;
        attach_uprobe(bpf, "botguard_sub_sentinel", "rmw_create_subscription", rmw_lib)?;
        attach_uprobe(bpf, "botguard_srv_sentinel", "rmw_create_service", rmw_lib)?;
        attach_uprobe(bpf, "botguard_cli_sentinel", "rmw_create_client", rmw_lib)?;
        state.lock().unwrap().active_rmw = rmw_lib.to_string();
    }

    let iface = "docker0"; 
    
    match attach_tc(bpf, "botguard_network_sentinel", iface) {
        Ok(_) => state.lock().unwrap().recent_events.push_front(format!("🌐 Sentinel Active on: {}", iface)),
        Err(e) => {
            state.lock().unwrap().recent_events.push_front(format!("❌ Sentinel Failed on {}: {}", iface, e));
        }
    }

    let perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS").unwrap())?;
    let perf_array = Box::leak(Box::new(perf_array));

    let mut tasks = tokio::task::JoinSet::new();

    for cpu_id in aya::util::online_cpus().unwrap_or_default() {
        let mut buf = perf_array.open(cpu_id, None)?;
        let state = state.clone();

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
                    let event_buf = &buffers[i];
                    let ptr = event_buf.as_ptr() as *const PacketEvent;
                    let raw_event = unsafe { ptr.read_unaligned() };
                    
                    let packet_len = (raw_event.len as usize).min(botguard_common::MAX_PACKET_SIZE);
                    let data = &raw_event.packet[..packet_len];

                    use botguard_common::EventType;
                    let is_uprobe = matches!(
                        raw_event.event_type,
                        EventType::Node | EventType::Publisher | EventType::Subscription | EventType::Service | EventType::Client
                    );

                    if !is_uprobe {
                        if data.len() < 4 || data[0] != b'R' || data[1] != b'T' || data[2] != b'P' || data[3] != b'S' {
                            continue;
                        }
                    }

                    let mut s = state.lock().unwrap();
                    let key = if raw_event.pid > 0 {
                        raw_event.pid.to_string()
                    } else if raw_event.src_ip != 0 {
                        format!("{:08x}", raw_event.src_ip)
                    } else {
                        "0".to_string()
                    };

                    let mut event_msg = None;
                    let node = s.nodes.entry(key).or_insert_with(|| NodeInfo {
                        name: "Unknown".to_string(),
                        proc_name: if raw_event.pid > 0 { get_process_name(raw_event.pid) } else { "REMOTE".to_string() },
                        last_seen: Instant::now(),
                        pkts_sent: 0,
                        pkts_recv: 0,
                        bytes_sent: 0,
                        bytes_recv: 0,
                        pubs: 0,
                        subs: 0,
                        srvs: 0,
                        clis: 0,
                        src_ip: if raw_event.src_ip != 0 { Some(format_ip(raw_event.src_ip)) } else { None },
                        src_mac: if raw_event.src_mac != [0; 6] { Some(format_mac(raw_event.src_mac)) } else { None },
                        bytes_sent_prev: 0,
                        bytes_recv_prev: 0,
                        tx_rate: 0.0,
                        rx_rate: 0.0,
                        last_rate_calc: Instant::now(),
                    });
                    
                    node.last_seen = Instant::now();

                    if is_uprobe {
                        if raw_event.len > 0 {
                            if let Ok(name) = std::str::from_utf8(data) {
                                let cleaned = name.trim_matches(char::from(0)).trim();
                                if !cleaned.is_empty() {
                                    match raw_event.event_type {
                                        EventType::Node => {
                                            if node.name == "Unknown" || node.name == "Remote Participant" {
                                                node.name = cleaned.to_string();
                                                event_msg = Some(format!("➕ Node Born: [{}] (PID: {})", cleaned, raw_event.pid));
                                            }
                                        }
                                        EventType::Publisher => {
                                            node.pubs += 1;
                                            event_msg = Some(format!("📡 Pub Create: [{}] (PID: {})", cleaned, raw_event.pid));
                                        }
                                        EventType::Subscription => {
                                            node.subs += 1;
                                            event_msg = Some(format!("📥 Sub Create: [{}] (PID: {})", cleaned, raw_event.pid));
                                        }
                                        EventType::Service => {
                                            node.srvs += 1;
                                            event_msg = Some(format!("⚙️ Srv Create: [{}] (PID: {})", cleaned, raw_event.pid));
                                        }
                                        EventType::Client => {
                                            node.clis += 1;
                                            event_msg = Some(format!("🔗 Cli Create: [{}] (PID: {})", cleaned, raw_event.pid));
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    } else {
                        if data.len() >= 4 && data[0] == b'R' && data[1] == b'T' && data[2] == b'P' && data[3] == b'S' {
                            if raw_event.event_type == EventType::RawPacket {
                                node.pkts_sent += 1;
                                node.bytes_sent += raw_event.len as u64;
                            } else if raw_event.event_type == EventType::ExternalNode {
                                node.pkts_recv += 1;
                                node.bytes_recv += raw_event.len as u64;
                            }

                            if let Some(discovered_name) = find_node_name(data) {
                                if node.name == "Unknown" || node.name == "Remote Participant" {
                                    node.name = discovered_name.clone();
                                    if raw_event.event_type == EventType::ExternalNode {
                                        event_msg = Some(format!("🤖 Discovery: [{}] (Remote: {})", discovered_name, node.src_ip.as_deref().unwrap_or("?")));
                                    } else {
                                        event_msg = Some(format!("🤖 Discovery: [{}] (PID: {})", discovered_name, raw_event.pid));
                                    }
                                }
                            } else if raw_event.event_type == EventType::ExternalNode && node.name == "Unknown" {
                                node.name = "Remote Participant".to_string();
                            }
                        }
                    }
                    
                    if let Some(msg) = event_msg {
                        s.add_event(msg);
                    }
                }
            }
        });
    }

    loop {
        {
            state.lock().unwrap().update_rates();
        }
        terminal.draw(|f| ui(f, &state.lock().unwrap()))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') || key.code == KeyCode::Char('c') && key.modifiers.contains(event::KeyModifiers::CONTROL) {
                    break;
                }
                if key.code == KeyCode::Char('x') {
                    // Clear state (hidden feature)
                    state.lock().unwrap().nodes.clear();
                }
            }
        }
    }

    restore_terminal(&mut terminal)?;
    Ok(())
}

fn get_process_name(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "Unknown".to_string())
}

fn attach_tracepoint(bpf: &mut Ebpf, name: &str, category: &str, event: &str) -> anyhow::Result<()> {
    if let Some(prog) = bpf.program_mut(name) {
        let tp: &mut TracePoint = prog.try_into()?;
        tp.load()?;
        tp.attach(category, event)?;
    }
    Ok(())
}

fn attach_uprobe(bpf: &mut Ebpf, prog_name: &str, symbol: &str, lib: &str) -> anyhow::Result<()> {
    if let Some(program) = bpf.program_mut(prog_name) {
        let prog: &mut UProbe = program.try_into()?;
        prog.load()?;
        prog.attach(Some(symbol), 0, lib, None)?;
    }
    Ok(())
}

fn attach_tc(bpf: &mut Ebpf, prog_name: &str, iface: &str) -> anyhow::Result<()> {
    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = bpf.program_mut(prog_name).unwrap().try_into()?;
    program.load()?;
    program.attach(iface, tc::TcAttachType::Ingress)?;
    Ok(())
}

fn format_ip(ip: u32) -> String {
    format!("{}.{}.{}.{}", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF)
}

fn format_mac(mac: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

fn format_bandwidth(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_rate(rate: f64) -> String {
    if rate < 1024.0 {
        format!("{:.1} B/s", rate)
    } else if rate < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", rate / 1024.0)
    } else if rate < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} MB/s", rate / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB/s", rate / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 1 {
        format!("{}ms", d.subsec_millis())
    } else if secs < 60 {
        format!("{}s", secs)
    } else {
        format!("{}m {}s", secs / 60, secs % 60)
    }
}

fn ui(f: &mut Frame, state: &MonitorState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(10),
        ].as_ref())
        .split(f.size());

    let title = Paragraph::new(format!("🛡️ BotGuard Core Sentinel | Active RMW: {}", state.active_rmw))
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(title, chunks[0]);

    let header_cells = ["Identity", "Source", "Pub/Sub", "Srv/Cli", "TX (Sent)", "RX (Received)", "Seen"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let mut sorted_nodes: Vec<(&String, &NodeInfo)> = state.nodes.iter().collect();
    sorted_nodes.sort_by(|a, b| {
        let a_prio = if a.1.src_ip.is_some() { 2 } else if a.1.name != "Unknown" { 1 } else { 0 };
        let b_prio = if b.1.src_ip.is_some() { 2 } else if b.1.name != "Unknown" { 1 } else { 0 };

        if a_prio != b_prio {
            b_prio.cmp(&a_prio)
        } else {
            b.1.last_seen.cmp(&a.1.last_seen)
        }
    });

    let rows = sorted_nodes.iter().map(|(id, info)| {
        let identity = if info.src_ip.is_some() {
            format!("🌐 {}", info.name)
        } else {
            let display_name = if info.name == "/" || info.name == "Unknown" {
                &info.proc_name
            } else {
                &info.name
            };
            format!("🛡️ {}", display_name)
        };
        let source = if let Some(ip) = &info.src_ip {
            format!("{} ({})", ip, info.src_mac.as_deref().unwrap_or("?"))
        } else {
            format!("PID: {} ({})", id, info.proc_name)
        };

        let tx_str = if info.bytes_sent > 0 || info.pkts_sent > 0 {
            format!("{} ({}) @ {}", format_bandwidth(info.bytes_sent), info.pkts_sent, format_rate(info.tx_rate))
        } else {
            "-".to_string()
        };
        let rx_str = if info.bytes_recv > 0 || info.pkts_recv > 0 {
            format!("{} ({}) @ {}", format_bandwidth(info.bytes_recv), info.pkts_recv, format_rate(info.rx_rate))
        } else {
            "-".to_string()
        };

        let cells = vec![
            Cell::from(identity),
            Cell::from(source),
            Cell::from(format!("{}/{}", info.pubs, info.subs)),
            Cell::from(format!("{}/{}", info.srvs, info.clis)),
            Cell::from(tx_str),
            Cell::from(rx_str),
            Cell::from(format_duration(info.last_seen.elapsed()) + " ago"),
        ];
        Row::new(cells)
    });

    let table = Table::new(rows, [
        Constraint::Percentage(15),
        Constraint::Percentage(18),
        Constraint::Percentage(8),
        Constraint::Percentage(8),
        Constraint::Percentage(21),
        Constraint::Percentage(21),
        Constraint::Percentage(9),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Active ROS 2 / System Nodes"))
    .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    
    f.render_widget(table, chunks[1]);

    let events: Vec<ListItem> = state.recent_events
        .iter()
        .map(|e| ListItem::new(e.clone()))
        .collect();
    let event_list = List::new(events)
        .block(Block::default().borders(Borders::ALL).title("Sentinel Activity Stream"));
    f.render_widget(event_list, chunks[2]);
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn find_node_name(data: &[u8]) -> Option<String> {
    for i in 0..(data.len().saturating_sub(12)) {
        // Little Endian pattern: PID_ENTITY_NAME is 0x0062 -> serialized as [0x62, 0x00]
        if data[i] == 0x62 && data[i+1] == 0x00 {
            let param_len = u16::from_le_bytes([data[i+2], data[i+3]]) as usize;
            if param_len >= 4 && i + 4 + param_len <= data.len() {
                let str_len = u32::from_le_bytes([data[i+4], data[i+5], data[i+6], data[i+7]]) as usize;
                if str_len > 1 && str_len <= param_len - 4 && i + 8 + str_len <= data.len() {
                    let name_bytes = &data[i+8..i+8+str_len];
                    if let Ok(name) = std::str::from_utf8(name_bytes) {
                        let cleaned = name.trim_matches(char::from(0)).trim();
                        if !cleaned.is_empty() {
                            return Some(cleaned.to_string());
                        }
                    }
                }
            }
        }
        // Big Endian pattern: PID_ENTITY_NAME is 0x0062 -> serialized as [0x00, 0x62]
        else if data[i] == 0x00 && data[i+1] == 0x62 {
            let param_len = u16::from_be_bytes([data[i+2], data[i+3]]) as usize;
            if param_len >= 4 && i + 4 + param_len <= data.len() {
                let str_len = u32::from_be_bytes([data[i+4], data[i+5], data[i+6], data[i+7]]) as usize;
                if str_len > 1 && str_len <= param_len - 4 && i + 8 + str_len <= data.len() {
                    let name_bytes = &data[i+8..i+8+str_len];
                    if let Ok(name) = std::str::from_utf8(name_bytes) {
                        let cleaned = name.trim_matches(char::from(0)).trim();
                        if !cleaned.is_empty() {
                            return Some(cleaned.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}
