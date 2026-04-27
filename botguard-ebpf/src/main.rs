#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{tracepoint, map, uprobe, classifier},
    maps::{PerfEventArray, PerCpuArray},
    programs::{TracePointContext, ProbeContext, TcContext},
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
};
use botguard_common::{PacketEvent, EventType};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    udp::UdpHdr,
};

#[map]
static mut EVENTS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

#[map]
static mut SCRATCHPAD: PerCpuArray<PacketEvent> = PerCpuArray::with_max_entries(1, 0);

#[classifier]
pub fn botguard_network_sentinel(ctx: TcContext) -> i32 {
    let _ = try_botguard_network_capture(&ctx);
    0
}

#[tracepoint]
pub fn botguard_sendto(ctx: TracePointContext) -> u32 {
    let _ = try_botguard_capture(&ctx, 24, 32);
    0
}

#[tracepoint]
pub fn botguard_sendmsg(ctx: TracePointContext) -> u32 {
    let _ = try_botguard_capture(&ctx, 24, 32); 
    0
}

#[uprobe]
pub fn botguard_node_sentinel(ctx: ProbeContext) -> u32 {
    let regs = unsafe { &*ctx.regs };
    let name_ptr = regs.rsi as *const u8;
    handle_sentinel(&ctx, name_ptr, EventType::Node)
}

#[uprobe]
pub fn botguard_pub_sentinel(ctx: ProbeContext) -> u32 {
    let regs = unsafe { &*ctx.regs };
    let name_ptr = regs.rdx as *const u8;
    handle_sentinel(&ctx, name_ptr, EventType::Publisher)
}

#[uprobe]
pub fn botguard_sub_sentinel(ctx: ProbeContext) -> u32 {
    let regs = unsafe { &*ctx.regs };
    let name_ptr = regs.rdx as *const u8;
    handle_sentinel(&ctx, name_ptr, EventType::Subscription)
}

#[uprobe]
pub fn botguard_srv_sentinel(ctx: ProbeContext) -> u32 {
    let regs = unsafe { &*ctx.regs };
    let name_ptr = regs.rdx as *const u8;
    handle_sentinel(&ctx, name_ptr, EventType::Service)
}

#[uprobe]
pub fn botguard_cli_sentinel(ctx: ProbeContext) -> u32 {
    let regs = unsafe { &*ctx.regs };
    let name_ptr = regs.rdx as *const u8;
    handle_sentinel(&ctx, name_ptr, EventType::Client)
}

fn handle_sentinel(ctx: &ProbeContext, name_ptr: *const u8, event_type: EventType) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if name_ptr as usize > 0 {
        if let Some(ptr) = unsafe { SCRATCHPAD.get_ptr_mut(0) } {
            let event = unsafe { &mut *ptr };
            event.pid = pid;
            event.event_type = event_type;
            event.len = 0;
            event.src_ip = 0;
            event.src_mac = [0; 6];
            
            unsafe {
                let len = bpf_probe_read_user_str_bytes(name_ptr, &mut event.packet)
                    .map(|s| s.len())
                    .unwrap_or(0);
                
                if len > 0 {
                    event.len = len as u32;
                    let _ = EVENTS.output(ctx, event, 0);
                }
            }
        }
    }
    0
}

fn try_botguard_capture(ctx: &TracePointContext, buff_off: usize, len_off: usize) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    
    let buff_ptr: *const u8 = unsafe { ctx.read_at(buff_off).map_err(|_| 0u32)? };
    let len: usize = unsafe { ctx.read_at(len_off).map_err(|_| 0u32)? };

    if len > 0 {
        let event = unsafe { 
            let ptr = SCRATCHPAD.get_ptr_mut(0).ok_or(0u32)?;
            &mut *ptr
        };

        event.pid = pid;
        event.len = len as u32;
        event.event_type = EventType::RawPacket;
        event.src_ip = 0;
        event.src_mac = [0; 6];

        unsafe {
            event.packet = bpf_probe_read_user(buff_ptr as *const [u8; 128]).map_err(|_| 0u32)?;
            EVENTS.output(ctx, event, 0);
        }
    }

    Ok(0)
}

fn try_botguard_network_capture(ctx: &TcContext) -> Result<(), ()> {

    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    let ether_type = eth_hdr.ether_type;
    if ether_type != EtherType::Ipv4 {
        return Ok(());
    }

    let ip_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let proto = ip_hdr.proto;
    if proto != network_types::ip::IpProto::Udp {
        return Ok(());
    }

    let udp_hdr: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
    let dest_port = u16::from_be(udp_hdr.dest);
    let src_port = u16::from_be(udp_hdr.source);
    
    if (dest_port < 7400 || dest_port > 7500) && (src_port < 7400 || src_port > 7500) {
        return Ok(());
    }
    if let Some(ptr) = unsafe { SCRATCHPAD.get_ptr_mut(0) } {
        let event = unsafe { &mut *ptr };
        event.pid = 0;
        event.event_type = EventType::ExternalNode;
        event.src_ip = u32::from_be(ip_hdr.src_addr);
        event.src_mac = eth_hdr.src_addr;
        
        let payload_off = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN;
        
        let skb_len = ctx.len() as usize;
        if skb_len > payload_off {
             let _ = ctx.load_bytes(payload_off, &mut event.packet).map_err(|_| ())?;
             event.len = 128;
        } else {
            event.len = 0;
        }

        unsafe {
            EVENTS.output(ctx, event, 0);
        }
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
