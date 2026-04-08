#![no_std]

// The size of the packet buffer we'll send to userspace.
// Reduced to 128 to strictly stay within the 512-byte BPF stack limit.
pub const MAX_PACKET_SIZE: usize = 128;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PacketEvent {
    pub pid: u32,
    pub len: u32,
    pub packet: [u8; MAX_PACKET_SIZE],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}
