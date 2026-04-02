// SPDX-License-Identifier: GPL-2.0-only
//! DNS client API for SaltyOS.
//!
//! Provides hostname resolution by communicating with the dnssrv service.
//! The default path resolves dnssrv lazily via namesrv and caches the
//! resulting endpoint capability for subsequent lookups.

use trona::consts::kernel::*;
use trona::consts::posix::*;
use trona::consts::server::*;
use trona::invoke;
use trona::ipc;
use trona::protocol::*;
use trona::slot_alloc;
use crate::tls;
use trona::types::core::*;
use trona::types::posix::*;

const CAP_SELF_CSPACE: u64 = 2;

/// Cached dnssrv endpoint resolved lazily through namesrv.
static mut DNSSRV_EP: Cap = 0;
/// Dedicated receive slot reused for dnssrv endpoint lookup.
static mut DNSSRV_LOOKUP_SLOT: Cap = 0;

unsafe fn resolve_dnssrv_ep() -> Result<Cap, u64> {
    unsafe {
        let cached = *(&raw const DNSSRV_EP);
        if cached != 0 {
            return Ok(cached);
        }

        let ep_slot = {
            let slot = *(&raw const DNSSRV_LOOKUP_SLOT);
            if slot != 0 {
                slot
            } else {
                let slot = match slot_alloc::slot_alloc() {
                    Some(slot) => slot,
                    None => return Err(TRONA_OUT_OF_MEMORY),
                };
                *(&raw mut DNSSRV_LOOKUP_SLOT) = slot;
                slot
            }
        };

        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, ep_slot);
        ipc::set_receive_slot_ctx(tls::current_ipc_ctx(), CAP_SELF_CSPACE, ep_slot, 0);

        let name = b"dnssrv";
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = NS_LOOKUP;
        msg.regs[0] = name.len() as u64;
        msg.length = 1 + (name.len() as u64 + 7) / 8;

        let dst = &raw mut msg.regs[1] as *mut u8;
        ::core::ptr::copy_nonoverlapping(name.as_ptr(), dst, name.len());

        let err = crate::ipc_call_retry_idempotent(
            CAP_NAMESRV_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return Err(err as u64);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }

        *(&raw mut DNSSRV_EP) = ep_slot;
        Ok(ep_slot)
    }
}

unsafe fn dns_resolve_multi_result_with_ep(hostname: &[u8], dnssrv_ep: u64) -> Result<DnsResult, u64> {
    unsafe {
        if hostname.is_empty() || hostname.len() > 120 {
            return Err(TRONA_INVALID_ARGUMENT);
        }

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = DNS_RESOLVE;
        msg.regs[0] = hostname.len() as u64;

        // SAFETY: Pack hostname bytes into regs[1..]. The TronaMsg regs array
        // has 20 entries (160 bytes), and hostname is at most 120 bytes, so
        // this copy stays within bounds.
        let dst = &raw mut msg.regs[1] as *mut u8;
        ::core::ptr::copy_nonoverlapping(hostname.as_ptr(), dst, hostname.len());
        msg.length = 1 + ((hostname.len() as u64 + 7) / 8);

        let err = crate::ipc_call_retry_idempotent(
            dnssrv_ep,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return Err(err as u64);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }

        let ip_count = reply.regs[0] as u32;
        if ip_count == 0 {
            return Err(TRONA_NOT_FOUND);
        }

        let count = if ip_count > DNS_MAX_RESULTS as u32 {
            DNS_MAX_RESULTS as u32
        } else {
            ip_count
        };
        let mut result = DnsResult {
            count,
            ttl: reply.regs[1] as u32,
            addrs: [0; DNS_MAX_RESULTS],
        };
        for i in 0..count as usize {
            result.addrs[i] = reply.regs[2 + i] as u32;
        }
        Ok(result)
    }
}

pub unsafe fn dns_resolve_multi_result(hostname: &[u8]) -> Result<DnsResult, u64> {
    unsafe {
        let ep = resolve_dnssrv_ep()?;
        dns_resolve_multi_result_with_ep(hostname, ep)
    }
}

/// Resolve a hostname to IPv4 address(es).
///
/// `hostname` is a byte slice (NOT null-terminated) of the hostname to resolve.
/// `dnssrv_ep` is the capability slot of the dnssrv endpoint.
///
/// On success, returns the primary resolved IPv4 address (host byte order).
/// On failure, returns 0.
///
/// # Safety
///
/// Caller must ensure the IPC context is initialized and `dnssrv_ep` is a
/// valid endpoint capability slot connected to the dnssrv service.
pub unsafe fn dns_resolve_with_ep(hostname: &[u8], dnssrv_ep: u64) -> u32 {
    unsafe {
        match dns_resolve_multi_result_with_ep(hostname, dnssrv_ep) {
            Ok(result) if result.count > 0 => result.addrs[0],
            _ => 0,
        }
    }
}

/// Resolve a hostname using the default dnssrv endpoint.
///
/// # Safety
///
/// Caller must ensure the IPC context is initialized.
pub unsafe fn dns_resolve(hostname: &[u8]) -> u32 {
    unsafe {
        match resolve_dnssrv_ep() {
            Ok(ep) => dns_resolve_with_ep(hostname, ep),
            Err(_) => 0,
        }
    }
}

/// Resolve a hostname to up to 4 IPv4 addresses.
///
/// Returns a `DnsResult` with `count > 0` on success.
/// Addresses are in host byte order.
///
/// # Safety
///
/// Caller must ensure the IPC context is initialized and `dnssrv_ep` is a
/// valid endpoint capability slot connected to the dnssrv service.
pub unsafe fn dns_resolve_multi_with_ep(hostname: &[u8], dnssrv_ep: u64) -> DnsResult {
    unsafe { dns_resolve_multi_result_with_ep(hostname, dnssrv_ep).unwrap_or_else(|_| DnsResult::zeroed()) }
}

/// Resolve a hostname to up to 4 IPv4 addresses using the default dnssrv
/// endpoint.
///
/// # Safety
///
/// Caller must ensure the IPC context is initialized.
pub unsafe fn dns_resolve_multi(hostname: &[u8]) -> DnsResult {
    unsafe {
        match resolve_dnssrv_ep() {
            Ok(ep) => dns_resolve_multi_with_ep(hostname, ep),
            Err(_) => DnsResult::zeroed(),
        }
    }
}

unsafe fn hostname_from_cstr<'a>(name: *const u8) -> Option<&'a [u8]> {
    unsafe {
        if name.is_null() {
            return None;
        }
        let mut len = 0usize;
        while *name.add(len) != 0 && len < 120 {
            len += 1;
        }
        if len == 0 || len >= 120 {
            return None;
        }
        Some(::core::slice::from_raw_parts(name, len))
    }
}

/// Parse a dotted-decimal IPv4 string into a `u32` in host byte order.
///
/// Returns `Some(ip)` on success, `None` if the string is not a valid
/// numeric IPv4 address. Example: `b"10.0.2.2"` -> `Some(0x0A00_0202)`.
pub fn parse_ipv4_numeric(s: &[u8]) -> Option<u32> {
    let mut octets = [0u32; 4];
    let mut octet_idx = 0usize;
    let mut cur: u32 = 0;
    let mut digits = 0u32;

    for &b in s {
        if b == b'.' {
            if digits == 0 || octet_idx >= 3 {
                return None;
            }
            if cur > 255 {
                return None;
            }
            octets[octet_idx] = cur;
            octet_idx += 1;
            cur = 0;
            digits = 0;
        } else if b >= b'0' && b <= b'9' {
            cur = cur * 10 + (b - b'0') as u32;
            digits += 1;
            if digits > 3 {
                return None;
            }
        } else {
            return None;
        }
    }

    if digits == 0 || octet_idx != 3 || cur > 255 {
        return None;
    }
    octets[3] = cur;

    Some((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3])
}

/// Resolve a hostname and fill a DnsAddrInfo struct.
///
/// `node` is a null-terminated hostname string.
/// `result` receives the resolved address info.
/// Returns 0 on success, -1 on failure.
///
/// # Safety
///
/// `node` must point to a valid null-terminated byte string.
/// `result` must point to a valid, writable `DnsAddrInfo`.
pub unsafe fn posix_getaddrinfo(node: *const u8, result: *mut DnsAddrInfo) -> i32 {
    unsafe {
        if node.is_null() || result.is_null() {
            return -1;
        }

        // Measure null-terminated string length
        let mut len = 0usize;
        while *node.add(len) != 0 && len < 120 {
            len += 1;
        }
        if len == 0 || len >= 120 {
            return -1;
        }

        let hostname = ::core::slice::from_raw_parts(node, len);
        let ip = dns_resolve(hostname);
        if ip == 0 {
            return -1;
        }

        (*result).family = AF_INET;
        (*result).socktype = SOCK_STREAM;
        (*result).protocol = IPPROTO_TCP;
        (*result).addr.family = AF_INET as u16;
        (*result).addr.port = 0;
        (*result).addr.addr = ip;
        0
    }
}

/// Resolve a null-terminated hostname to an IPv4 address.
///
/// Returns the IPv4 address in host byte order, or 0 on failure.
///
/// # Safety
///
/// `name` must point to a valid null-terminated byte string.
pub unsafe fn posix_gethostbyname(name: *const u8) -> u32 {
    unsafe { posix_gethostbyname_result(name).unwrap_or(0) }
}

pub unsafe fn posix_gethostbyname_result(name: *const u8) -> Result<u32, u64> {
    unsafe {
        let hostname = match hostname_from_cstr(name) {
            Some(hostname) => hostname,
            None => return Err(TRONA_INVALID_ARGUMENT),
        };
        let result = dns_resolve_multi_result(hostname)?;
        if result.count == 0 {
            Err(TRONA_NOT_FOUND)
        } else {
            Ok(result.addrs[0])
        }
    }
}

/// Resolve an IPv4 address to a hostname (reverse DNS).
///
/// `ip` is the IPv4 address in host byte order.
/// `hostname_out` receives the resolved hostname.
/// `hostname_max` is the buffer size.
/// Returns the hostname length on success, 0 on failure.
///
/// # Safety
///
/// `hostname_out` must point to a writable buffer of at least `hostname_max` bytes.
pub unsafe fn dns_reverse_lookup(ip: u32, hostname_out: *mut u8, hostname_max: usize) -> usize {
    unsafe {
        let ep = match resolve_dnssrv_ep() {
            Ok(ep) => ep,
            Err(_) => return 0,
        };

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = DNS_REVERSE_LOOKUP;
        msg.regs[0] = ip as u64;
        msg.length = 1;

        let err = crate::ipc_call_retry_idempotent(
            ep,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            return 0;
        }

        let result_len = reply.regs[0] as usize;
        let copy_len = ::core::cmp::min(result_len, hostname_max);
        if copy_len > 0 {
            if hostname_out.is_null() {
                return 0;
            }
            // SAFETY: Reading hostname bytes packed in reply registers.
            let src = &reply.regs[1] as *const u64 as *const u8;
            ::core::ptr::copy_nonoverlapping(src, hostname_out, copy_len);
        }
        copy_len
    }
}

/// Flush the dnssrv DNS cache.
///
/// # Safety
///
/// Caller must ensure the IPC context is initialized.
pub unsafe fn dns_cache_flush() {
    unsafe {
        let ep = match resolve_dnssrv_ep() {
            Ok(ep) => ep,
            Err(_) => return,
        };

        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();

        msg.label = DNS_CACHE_FLUSH;
        msg.length = 0;

        let _ = ipc::call_ctx(
            tls::current_ipc_ctx(),
            ep,
            &raw const msg,
            &raw mut reply,
        );
    }
}
