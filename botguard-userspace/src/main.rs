use aya::programs::{TracePoint, UProbe};
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::perf::AsyncPerfEventArray;
use aya_log::EbpfLogger;
use botguard_common::PacketEvent;
use bytes::BytesMut;
use tokio::time::sleep;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// TUI Imports
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
    packets: u64,
}

struct MonitorState {
    nodes: HashMap<u32, NodeInfo>,
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Setup TUI
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let state = Arc::new(Mutex::new(MonitorState::new()));
    
    // Bump rlimit
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        // Fallback for UI log
    }

    // Load eBPF
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

    // Attach Tracepoints
    let _ = attach_tracepoint(bpf, "botguard_sendto", "syscalls", "sys_enter_sendto");
    let _ = attach_tracepoint(bpf, "botguard_sendmsg", "syscalls", "sys_enter_sendmsg");

    // Attach Sentinel
    let rmw_lib = "/opt/ros/humble/lib/librmw_fastrtps_cpp.so";
    if std::path::Path::new(rmw_lib).exists() {
        if let Ok(program) = bpf.program_mut("botguard_sentinel").unwrap().try_into() {
            let prog: &mut UProbe = program;
            let _ = prog.load();
            let _ = prog.attach(Some("rmw_create_node"), 0, rmw_lib, None);
            state.lock().unwrap().active_rmw = rmw_lib.to_string();
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

                    let mut s = state.lock().unwrap();
                    let node = s.nodes.entry(raw_event.pid).or_insert_with(|| NodeInfo {
                        name: "Unknown".to_string(),
                        proc_name: get_process_name(raw_event.pid),
                        last_seen: Instant::now(),
                        packets: 0,
                    });
                    
                    node.last_seen = Instant::now();
                    node.packets += 1;

                    if raw_event.len == 0xDEED || (raw_event.len > 0 && raw_event.len < 128) {
                        // Handle Sentinel or Potential string discovery
                        if let Ok(name) = std::str::from_utf8(data) {
                            let cleaned = name.trim_matches(char::from(0)).trim();
                            if !cleaned.is_empty() && cleaned.len() > 2 {
                                if node.name == "Unknown" || raw_event.len == 0xDEED {
                                    node.name = cleaned.to_string();
                                    s.add_event(format!("➕ Node Born: [{}] (PID: {})", cleaned, raw_event.pid));
                                }
                            }
                        }
                    } else if let Some(discovered_name) = find_node_name(data) {
                        node.name = discovered_name.clone();
                        s.add_event(format!("🤖 Discovery: [{}] (PID: {})", discovered_name, raw_event.pid));
                    }
                }
            }
        });
    }

    // UI Render Loop
    loop {
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

    // Cleanup
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

    // Title
    let title = Paragraph::new(format!("🛡️ BotGuard Core Sentinel | Active RMW: {}", state.active_rmw))
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(title, chunks[0]);

    // Node Table
    let header_cells = ["PID", "Node Name", "Binary", "Packets", "Seen"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows = state.nodes.iter().map(|(pid, info)| {
        let cells = vec![
            Cell::from(pid.to_string()),
            Cell::from(info.name.clone()),
            Cell::from(format!("({})", info.proc_name)),
            Cell::from(info.packets.to_string()),
            Cell::from(format!("{:?} ago", info.last_seen.elapsed())),
        ];
        Row::new(cells)
    });

    let table = Table::new(rows, [
        Constraint::Percentage(10),
        Constraint::Percentage(35),
        Constraint::Percentage(20),
        Constraint::Percentage(15),
        Constraint::Percentage(20),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title("Active ROS 2 / System Nodes"))
    .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    
    f.render_widget(table, chunks[1]);

    // Event Stream
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
    for i in 0..(data.len().saturating_sub(8)) {
        if data[i] == 0x62 && data[i+1] == 0x00 {
            let len = u16::from_le_bytes([data[i+2], data[i+3]]) as usize;
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
