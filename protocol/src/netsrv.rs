// SPDX-License-Identifier: GPL-2.0-only
//
//! netsrv server wire (block 0x800..=0x8FF). Network stack RPC
//! surface. vfs's `/proc/net/*` generators and the POSIX socket
//! layer route here.

/// Register the netsrv/netdrv SHM ring.
///
/// Request from netsrv:
/// - `regs[0]`: mmsrv SHM MO index returned by `MM_SHM_CREATE`; `0` is valid.
/// - `caps[0]`: transferable cap to the same SHM memory object.
///
/// Reply from netdrv:
/// - `regs[0]`: MAC address bytes 0..4 packed big-endian.
/// - `regs[1]`: MAC address bytes 4..6 packed big-endian.
/// - `regs[2]`: link status (`1` = up).
pub const NETDRV_REGISTER: u64 = 0xC0;
/// netsrv asks netdrv to drain TX frames from the shared ring.
pub const NETDRV_TX_KICK: u64 = 0xC1;
/// netdrv asks netsrv to drain RX frames from the shared ring.
pub const NETSRV_RX_KICK: u64 = 0xC2;

/// Read the live network configuration snapshot. Reply layout:
/// `regs[0]=state`, `regs[1]=our_ip`, `regs[2]=subnet_mask`,
/// `regs[3]=gateway_ip`, `regs[4]=dns_server`, `regs[5]=rx_bytes`,
/// `regs[6]=rx_packets`, `regs[7]=tx_bytes`, `regs[8]=tx_packets`.
pub const NET_GET_CONFIG: u64 = 0x800;
/// Look up the Nth ARP entry. `regs[0]=index`. Reply:
/// `regs[0]=present`, `regs[1]=ip`, `regs[2]=mac` (packed
/// big-endian into the lower 48 bits).
pub const NET_GET_ARP_ENTRY: u64 = 0x801;
pub const NET_SOCKET: u64 = 0x8A0;
pub const NET_CONNECT: u64 = 0x8A1;
pub const NET_SEND: u64 = 0x8A2;
pub const NET_RECV: u64 = 0x8A3;
pub const NET_CLOSE: u64 = 0x8A4;
pub const NET_BIND: u64 = 0x8A5;
pub const NET_LISTEN: u64 = 0x8A6;
pub const NET_ACCEPT: u64 = 0x8A7;
pub const NET_SENDTO: u64 = 0x8A8;
pub const NET_RECVFROM: u64 = 0x8A9;
pub const NET_SHUTDOWN: u64 = 0x8AA;
pub const NET_GETSOCKNAME: u64 = 0x8AB;
pub const NET_GETPEERNAME: u64 = 0x8AC;
pub const NET_SETSOCKOPT: u64 = 0x8AD;
pub const NET_GETSOCKOPT: u64 = 0x8AE;
pub const NET_POLL_STATUS: u64 = 0x8AF;
pub const NET_REGISTER_VFS: u64 = 0x8B0;
pub const NET_COMPLETE: u64 = 0x8B1;
pub const NET_DNS_RESOLVE: u64 = 0x8B2;
pub const NET_DNS_RESOLVE_PTR: u64 = 0x8B3;
pub const NET_RECV_WAIT: u64 = 0x8B4;
pub const NET_ACCEPT_WAIT: u64 = 0x8B5;
pub const NET_RECVFROM_WAIT: u64 = 0x8B6;
pub const NET_SEND_WAIT: u64 = 0x8B7;
pub const NET_SENDTO_WAIT: u64 = 0x8B8;
