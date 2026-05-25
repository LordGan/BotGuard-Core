#![no_std]

pub const MAX_PACKET_SIZE: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EventType {
    Node = 0,
    Publisher = 1,
    Subscription = 2,
    Service = 3,
    Client = 4,
    RawPacket = 5,
    ExternalNode = 6,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct PacketEvent {
    pub pid: u32,
    pub len: u32,
    pub event_type: EventType,
    pub src_ip: u32,
    pub src_mac: [u8; 6],
    pub packet: [u8; MAX_PACKET_SIZE],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}
