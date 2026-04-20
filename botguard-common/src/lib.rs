#![no_std]

// The size of the packet buffer we'll send to userspace.
// Reduced to 128 to strictly stay within the 512-byte BPF stack limit.
pub const MAX_PACKET_SIZE: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EventType {
    Node = 0,
    Publisher = 1,
    Subscription = 2,
    Service = 3,
    Client = 4,
    RawPacket = 5,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PacketEvent {
    pub pid: u32,
    pub len: u32,
    pub event_type: EventType,
    pub packet: [u8; MAX_PACKET_SIZE],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}
