#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{tracepoint, map, uprobe},
    maps::{PerfEventArray, PerCpuArray},
    programs::{TracePointContext, ProbeContext},
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
};
use botguard_common::PacketEvent;

#[map]
static mut EVENTS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

#[map]
static mut SCRATCHPAD: PerCpuArray<PacketEvent> = PerCpuArray::with_max_entries(1, 0);

#[tracepoint]
pub fn botguard_sendto(ctx: TracePointContext) -> u32 {
    let _ = try_botguard_capture(&ctx, 24, 32);
    0
}

#[tracepoint]
pub fn botguard_sendmsg(ctx: TracePointContext) -> u32 {
    // For sendmsg, the buffer is inside a struct, but we can still 
    // try to read the raw pointer at 24 for a quick peek or just focus on sendto first.
    let _ = try_botguard_capture(&ctx, 24, 32); 
    0
}

#[uprobe]
pub fn botguard_sentinel(ctx: ProbeContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // x86_64 Calling Convention:
    // arg0: rdi, arg1: rsi, arg2: rdx
    // x86_64 Calling Convention:
    // arg0: rdi, arg1: rsi, arg2: rdx
    let regs = unsafe { &*ctx.regs };
    let name_ptr = regs.rsi as *const u8;
    let _ns_ptr = regs.rdx as *const u8;

    if name_ptr as usize > 0 {
        if let Some(ptr) = unsafe { SCRATCHPAD.get_ptr_mut(0) } {
            let event = unsafe { &mut *ptr };
            event.pid = pid;
            event.len = 0xDEED; // Special marker for Sentinel events
            
            unsafe {
                // Read the name and measure the resulting byte slice
                let len = bpf_probe_read_user_str_bytes(name_ptr, &mut event.packet)
                    .map(|s| s.len())
                    .unwrap_or(0);
                
                if len > 0 {
                    event.len = len as u32;
                }
                let _ = EVENTS.output(&ctx, event, 0);
            }
        }
    }

    0
}

fn try_botguard_capture(ctx: &TracePointContext, buff_off: usize, len_off: usize) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    
    // Read buffer pointer and length
    let buff_ptr: *const u8 = unsafe { ctx.read_at(buff_off).map_err(|_| 0u32)? };
    let len: usize = unsafe { ctx.read_at(len_off).map_err(|_| 0u32)? };

    if len > 0 {
        let event = unsafe { 
            let ptr = SCRATCHPAD.get_ptr_mut(0).ok_or(0u32)?;
            &mut *ptr
        };

        event.pid = pid;
        event.len = len as u32;

        unsafe {
            // High-level safe read for 128 bytes (fits on stack)
            event.packet = bpf_probe_read_user(buff_ptr as *const [u8; 128]).map_err(|_| 0u32)?;
            
            EVENTS.output(ctx, event, 0);
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
