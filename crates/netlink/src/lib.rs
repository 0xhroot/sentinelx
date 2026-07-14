use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use sentinelx_telemetry::provider::{Result, TelemetryProvider};
use sentinelx_telemetry::types::{
    ProviderInfo, ProviderStatus, TelemetryEvent, TelemetryEventType,
};

const NETLINK_ROUTE: i32 = 0;
const RTMGRP_LINK: u32 = 1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
const RTMGRP_IPV6_ROUTE: u32 = 0x400;
const RTMGRP_NEIGH: u32 = 0x200;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWNEIGH: u16 = 28;
const RTM_DELNEIGH: u16 = 29;

#[allow(dead_code)]
const NLM_F_REQUEST: u16 = 0x01;
#[allow(dead_code)]
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;

const EVENT_BUFFER_SIZE: usize = 8192;

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlAttr {
    nla_len: u16,
    nla_type: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ifinfomsg {
    ifi_family: u8,
    _pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ifaddrmsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Rtmsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetlinkConfig {
    pub monitor_interfaces: bool,
    pub monitor_routes: bool,
    pub monitor_addresses: bool,
    pub monitor_neighbors: bool,
    pub buffer_size: u32,
}

impl Default for NetlinkConfig {
    fn default() -> Self {
        Self {
            monitor_interfaces: true,
            monitor_routes: true,
            monitor_addresses: true,
            monitor_neighbors: false,
            buffer_size: EVENT_BUFFER_SIZE as u32,
        }
    }
}

fn nl_msg_hdr_from_bytes(buf: &[u8], offset: usize) -> Option<NlMsgHdr> {
    if offset + std::mem::size_of::<NlMsgHdr>() > buf.len() {
        return None;
    }
    // SAFETY: We verified bounds. NlMsgHdr is repr(C) with aligned fields.
    Some(unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const NlMsgHdr) })
}

fn nl_attr_from_bytes(buf: &[u8], offset: usize) -> Option<NlAttr> {
    if offset + std::mem::size_of::<NlAttr>() > buf.len() {
        return None;
    }
    // SAFETY: We verified bounds. NlAttr is repr(C) with aligned fields.
    Some(unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const NlAttr) })
}

fn extract_string_from_nla(buf: &[u8], attr_offset: usize) -> Option<String> {
    let attr = nl_attr_from_bytes(buf, attr_offset)?;
    let data_len = (attr.nla_len as usize).checked_sub(std::mem::size_of::<NlAttr>())?;
    let data_start = attr_offset + std::mem::size_of::<NlAttr>();

    if data_start + data_len > buf.len() {
        return None;
    }

    let data = &buf[data_start..data_start + data_len];
    let end = data.iter().position(|&b| b == 0).unwrap_or(data_len);
    let lossy = String::from_utf8_lossy(&data[..end]).into_owned();
    lossy.into()
}

fn create_netlink_socket(groups: u32) -> std::io::Result<RawFd> {
    // SAFETY: socket() creates a new netlink socket. AF_NETLINK + SOCK_RAW
    // with NETLINK_ROUTE is standard for network monitoring.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_groups = groups;

    // SAFETY: addr is a valid sockaddr_nl with the netlink address family.
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };

    if rc < 0 {
        let err = std::io::Error::last_os_error();
        // SAFETY: fd is valid, we just opened it.
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    Ok(fd)
}

#[allow(dead_code)]
fn send_netlink_request(
    fd: RawFd,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    groups: u32,
) -> std::io::Result<()> {
    let mut nl_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    nl_addr.nl_family = libc::AF_NETLINK as u16;
    nl_addr.nl_pid = 0;
    nl_addr.nl_groups = groups;

    let hdr = NlMsgHdr {
        nlmsg_len: std::mem::size_of::<NlMsgHdr>() as u32,
        nlmsg_type,
        nlmsg_flags,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    // SAFETY: We send a properly formatted netlink message header.
    // The kernel will validate the message format.
    let rc = unsafe {
        libc::sendto(
            fd,
            &hdr as *const NlMsgHdr as *const libc::c_void,
            std::mem::size_of::<NlMsgHdr>(),
            0,
            &nl_addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };

    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: F_GETFL and F_SETFL are standard POSIX operations on a valid fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: Setting O_NONBLOCK on a valid fd.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn run_read_loop(
    fd: RawFd,
    running: Arc<AtomicBool>,
    event_tx: mpsc::Sender<TelemetryEvent>,
    events_received: Arc<AtomicU64>,
    events_dropped: Arc<AtomicU64>,
    config: NetlinkConfig,
) {
    let mut buf = vec![0u8; config.buffer_size as usize];

    while running.load(Ordering::Relaxed) {
        // SAFETY: fd is a valid netlink socket. buf is writable with buf.len() bytes.
        // O_NONBLOCK was set, so this returns immediately if no data.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

        if n < 0 {
            let errno = nix::errno::Errno::last();
            match errno {
                nix::errno::Errno::EAGAIN => {
                    thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                nix::errno::Errno::EINTR => continue,
                _ => {
                    debug!("netlink recv error ({}), exiting read loop", errno);
                    break;
                }
            }
        }

        if n == 0 {
            break;
        }

        let total = n as usize;
        let mut offset = 0usize;

        while offset + std::mem::size_of::<NlMsgHdr>() <= total {
            let hdr = match nl_msg_hdr_from_bytes(&buf, offset) {
                Some(h) => h,
                None => break,
            };

            let msg_len = hdr.nlmsg_len as usize;
            if msg_len < std::mem::size_of::<NlMsgHdr>() || offset + msg_len > total {
                break;
            }

            match hdr.nlmsg_type {
                NLMSG_DONE | NLMSG_ERROR => {
                    offset += align_to(msg_len, 4);
                    continue;
                }
                RTM_NEWLINK | RTM_DELLINK => {
                    if config.monitor_interfaces {
                        parse_link_event(
                            &buf,
                            offset,
                            &hdr,
                            &event_tx,
                            &events_received,
                            &events_dropped,
                        );
                    }
                }
                RTM_NEWADDR | RTM_DELADDR => {
                    if config.monitor_addresses {
                        parse_addr_event(
                            &buf,
                            offset,
                            &hdr,
                            &event_tx,
                            &events_received,
                            &events_dropped,
                        );
                    }
                }
                RTM_NEWROUTE | RTM_DELROUTE => {
                    if config.monitor_routes {
                        parse_route_event(
                            &buf,
                            offset,
                            &hdr,
                            &event_tx,
                            &events_received,
                            &events_dropped,
                        );
                    }
                }
                RTM_NEWNEIGH | RTM_DELNEIGH if config.monitor_neighbors => {
                    parse_neigh_event(
                        &buf,
                        offset,
                        &hdr,
                        &event_tx,
                        &events_received,
                        &events_dropped,
                    );
                }
                _ => {}
            }

            offset += align_to(msg_len, 4);
        }
    }
}

fn align_to(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

fn parse_link_event(
    buf: &[u8],
    offset: usize,
    hdr: &NlMsgHdr,
    event_tx: &mpsc::Sender<TelemetryEvent>,
    events_received: &AtomicU64,
    events_dropped: &AtomicU64,
) {
    let ifinfo_offset = offset + std::mem::size_of::<NlMsgHdr>();
    if ifinfo_offset + std::mem::size_of::<Ifinfomsg>() > buf.len() {
        return;
    }

    // SAFETY: Bounds checked above. Ifinfomsg is repr(C) with no padding.
    let ifinfo: Ifinfomsg =
        unsafe { std::ptr::read_unaligned(buf.as_ptr().add(ifinfo_offset) as *const Ifinfomsg) };

    let attrs_offset = ifinfo_offset + std::mem::size_of::<Ifinfomsg>();
    let attrs_end = offset + hdr.nlmsg_len as usize;
    let ifname = find_ifname_attr(buf, attrs_offset, attrs_end).unwrap_or_default();

    let event_type = if hdr.nlmsg_type == RTM_NEWLINK {
        TelemetryEventType::NetConnect
    } else {
        TelemetryEventType::NetClose
    };

    let event = TelemetryEvent::new("netlink", event_type).with_metadata(serde_json::json!({
        "interface_index": ifinfo.ifi_index,
        "interface_name": ifname,
        "flags": ifinfo.ifi_flags,
        "event": if hdr.nlmsg_type == RTM_NEWLINK { "new_link" } else { "del_link" },
    }));

    if event_tx.blocking_send(event).is_ok() {
        events_received.fetch_add(1, Ordering::Relaxed);
    } else {
        events_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

fn parse_addr_event(
    buf: &[u8],
    offset: usize,
    hdr: &NlMsgHdr,
    event_tx: &mpsc::Sender<TelemetryEvent>,
    events_received: &AtomicU64,
    events_dropped: &AtomicU64,
) {
    let ifaddr_offset = offset + std::mem::size_of::<NlMsgHdr>();
    if ifaddr_offset + std::mem::size_of::<Ifaddrmsg>() > buf.len() {
        return;
    }

    // SAFETY: Bounds checked above. Ifaddrmsg is repr(C) with no padding.
    let ifaddr: Ifaddrmsg =
        unsafe { std::ptr::read_unaligned(buf.as_ptr().add(ifaddr_offset) as *const Ifaddrmsg) };

    let attrs_offset = ifaddr_offset + std::mem::size_of::<Ifaddrmsg>();
    let attrs_end = offset + hdr.nlmsg_len as usize;
    let ifname = find_ifname_attr(buf, attrs_offset, attrs_end).unwrap_or_default();
    let addr_str = find_address_attr(buf, attrs_offset, attrs_end, ifaddr.ifa_family);

    let event = TelemetryEvent::new("netlink", TelemetryEventType::NetBind).with_metadata(
        serde_json::json!({
            "interface_index": ifaddr.ifa_index,
            "interface_name": ifname,
            "address": addr_str,
            "prefix_len": ifaddr.ifa_prefixlen,
            "family": ifaddr.ifa_family,
            "event": if hdr.nlmsg_type == RTM_NEWADDR { "new_addr" } else { "del_addr" },
        }),
    );

    if event_tx.blocking_send(event).is_ok() {
        events_received.fetch_add(1, Ordering::Relaxed);
    } else {
        events_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

fn parse_route_event(
    buf: &[u8],
    offset: usize,
    hdr: &NlMsgHdr,
    event_tx: &mpsc::Sender<TelemetryEvent>,
    events_received: &AtomicU64,
    events_dropped: &AtomicU64,
) {
    let rtmsg_offset = offset + std::mem::size_of::<NlMsgHdr>();
    if rtmsg_offset + std::mem::size_of::<Rtmsg>() > buf.len() {
        return;
    }

    // SAFETY: Bounds checked above. Rtmsg is repr(C) with no padding.
    let rtmsg: Rtmsg =
        unsafe { std::ptr::read_unaligned(buf.as_ptr().add(rtmsg_offset) as *const Rtmsg) };

    let event_type = if hdr.nlmsg_type == RTM_NEWROUTE {
        TelemetryEventType::NetConnect
    } else {
        TelemetryEventType::NetClose
    };

    let event = TelemetryEvent::new("netlink", event_type).with_metadata(serde_json::json!({
        "family": rtmsg.rtm_family,
        "dst_len": rtmsg.rtm_dst_len,
        "src_len": rtmsg.rtm_src_len,
        "table": rtmsg.rtm_table,
        "protocol": rtmsg.rtm_protocol,
        "scope": rtmsg.rtm_scope,
        "type": rtmsg.rtm_type,
        "event": if hdr.nlmsg_type == RTM_NEWROUTE { "new_route" } else { "del_route" },
    }));

    if event_tx.blocking_send(event).is_ok() {
        events_received.fetch_add(1, Ordering::Relaxed);
    } else {
        events_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

fn parse_neigh_event(
    _buf: &[u8],
    _offset: usize,
    hdr: &NlMsgHdr,
    event_tx: &mpsc::Sender<TelemetryEvent>,
    events_received: &AtomicU64,
    events_dropped: &AtomicU64,
) {
    let event_type = if hdr.nlmsg_type == RTM_NEWNEIGH {
        TelemetryEventType::NetConnect
    } else {
        TelemetryEventType::NetClose
    };

    let event = TelemetryEvent::new("netlink", event_type).with_metadata(serde_json::json!({
        "event": if hdr.nlmsg_type == RTM_NEWNEIGH { "new_neighbor" } else { "del_neighbor" },
        "msg_len": hdr.nlmsg_len,
    }));

    if event_tx.blocking_send(event).is_ok() {
        events_received.fetch_add(1, Ordering::Relaxed);
    } else {
        events_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

fn find_ifname_attr(buf: &[u8], start: usize, end: usize) -> Option<String> {
    let mut off = start;
    while off + std::mem::size_of::<NlAttr>() <= end {
        let attr = nl_attr_from_bytes(buf, off)?;
        if attr.nla_len == 0 {
            break;
        }
        // IFLA_IFNAME = 3
        if attr.nla_type == 3 {
            return extract_string_from_nla(buf, off);
        }
        off += align_to(attr.nla_len as usize, 4);
    }
    None
}

fn find_address_attr(buf: &[u8], start: usize, end: usize, family: u8) -> Option<String> {
    let mut off = start;
    while off + std::mem::size_of::<NlAttr>() <= end {
        let attr = nl_attr_from_bytes(buf, off)?;
        if attr.nla_len == 0 {
            break;
        }
        // IFA_ADDRESS = 1
        if attr.nla_type == 1 {
            let data_len = (attr.nla_len as usize) - std::mem::size_of::<NlAttr>();
            let data_start = off + std::mem::size_of::<NlAttr>();
            if data_start + data_len > buf.len() {
                return None;
            }
            let data = &buf[data_start..data_start + data_len];
            return match family {
                // AF_INET
                2 if data.len() >= 4 => {
                    Some(format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]))
                }
                // AF_INET6
                10 if data.len() >= 16 => {
                    let segs: Vec<String> = data
                        .chunks(2)
                        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                        .collect();
                    Some(segs.join(":"))
                }
                _ => None,
            };
        }
        off += align_to(attr.nla_len as usize, 4);
    }
    None
}

pub struct NetlinkProvider {
    config: NetlinkConfig,
    status: ProviderStatus,
    events_received: Arc<AtomicU64>,
    events_dropped: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    netlink_fd: Arc<AtomicI32>,
    task_handle: Option<JoinHandle<()>>,
}

impl NetlinkProvider {
    pub fn new(config: NetlinkConfig) -> Self {
        Self {
            config,
            status: ProviderStatus::Stopped,
            events_received: Arc::new(AtomicU64::new(0)),
            events_dropped: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            netlink_fd: Arc::new(AtomicI32::new(-1)),
            task_handle: None,
        }
    }
}

#[async_trait]
impl TelemetryProvider for NetlinkProvider {
    fn name(&self) -> &str {
        "netlink"
    }

    fn description(&self) -> &str {
        "Netlink telemetry provider (real AF_NETLINK socket monitoring)"
    }

    fn status(&self) -> ProviderStatus {
        self.status.clone()
    }

    async fn initialize(&mut self, event_tx: mpsc::Sender<TelemetryEvent>) -> Result<()> {
        info!("Initializing netlink provider");
        self.status = ProviderStatus::Initializing;

        let mut groups: u32 = 0;
        if self.config.monitor_interfaces {
            groups |= RTMGRP_LINK;
        }
        if self.config.monitor_addresses {
            groups |= RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
        }
        if self.config.monitor_routes {
            groups |= RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
        }
        if self.config.monitor_neighbors {
            groups |= RTMGRP_NEIGH;
        }

        let fd = match create_netlink_socket(groups) {
            Ok(fd) => fd,
            Err(e) => {
                warn!(
                    "Failed to create netlink socket: {}, degrading gracefully",
                    e
                );
                self.status = ProviderStatus::Degraded;
                return Ok(());
            }
        };

        if let Err(e) = set_nonblocking(fd) {
            warn!("Failed to set nonblocking on netlink fd: {}", e);
        }

        self.netlink_fd.store(fd, Ordering::SeqCst);
        self.running.store(true, Ordering::SeqCst);
        self.status = ProviderStatus::Running;

        let running = Arc::clone(&self.running);
        let events_received = Arc::clone(&self.events_received);
        let events_dropped = Arc::clone(&self.events_dropped);
        let config = self.config.clone();

        self.task_handle = Some(tokio::task::spawn_blocking(move || {
            run_read_loop(
                fd,
                running,
                event_tx,
                events_received,
                events_dropped,
                config,
            );
        }));

        info!("netlink provider initialized (fd={})", fd);
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down netlink provider");
        self.running.store(false, Ordering::SeqCst);

        let fd = self.netlink_fd.swap(-1, Ordering::SeqCst);
        if fd >= 0 {
            // SAFETY: fd is the netlink socket we own. Closing it unblocks the reader.
            unsafe {
                libc::close(fd);
            }
        }

        if let Some(handle) = self.task_handle.take() {
            if let Err(e) = handle.await {
                if !e.is_cancelled() {
                    warn!("netlink read-loop task panicked: {}", e);
                }
            }
        }

        self.status = ProviderStatus::Stopped;
        info!("netlink provider shut down");
        Ok(())
    }

    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            name: self.name().to_string(),
            status: self.status.clone(),
            events_received: self.events_received.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            started_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netlink_config_default() {
        let config = NetlinkConfig::default();
        assert!(config.monitor_interfaces);
        assert!(config.monitor_routes);
        assert!(config.monitor_addresses);
        assert!(!config.monitor_neighbors);
        assert_eq!(config.buffer_size, EVENT_BUFFER_SIZE as u32);
    }

    #[test]
    fn netlink_config_custom() {
        let config = NetlinkConfig {
            monitor_interfaces: false,
            monitor_routes: false,
            monitor_addresses: true,
            monitor_neighbors: true,
            buffer_size: 4096,
        };
        assert!(!config.monitor_interfaces);
        assert!(!config.monitor_routes);
        assert!(config.monitor_addresses);
        assert!(config.monitor_neighbors);
        assert_eq!(config.buffer_size, 4096);
    }

    #[test]
    fn netlink_provider_creation() {
        let provider = NetlinkProvider::new(NetlinkConfig::default());
        assert_eq!(provider.name(), "netlink");
        assert_eq!(provider.status(), ProviderStatus::Stopped);
    }

    #[tokio::test]
    async fn netlink_provider_degrades_without_root() {
        let mut provider = NetlinkProvider::new(NetlinkConfig::default());
        let (tx, _rx) = mpsc::channel(16);
        let result = provider.initialize(tx).await;
        assert!(result.is_ok());
        let s = provider.status();
        assert!(
            s == ProviderStatus::Running || s == ProviderStatus::Degraded,
            "expected Running or Degraded, got {:?}",
            s
        );
        provider.shutdown().await.unwrap();
        assert_eq!(provider.status(), ProviderStatus::Stopped);
    }

    #[test]
    fn netlink_provider_info() {
        let provider = NetlinkProvider::new(NetlinkConfig::default());
        let info = provider.info();
        assert_eq!(info.name, "netlink");
        assert_eq!(info.events_received, 0);
        assert_eq!(info.events_dropped, 0);
    }

    #[test]
    fn align_to_test() {
        assert_eq!(align_to(0, 4), 0);
        assert_eq!(align_to(1, 4), 4);
        assert_eq!(align_to(4, 4), 4);
        assert_eq!(align_to(5, 4), 8);
        assert_eq!(align_to(13, 4), 16);
    }

    #[test]
    fn nl_msg_hdr_from_bytes_valid() {
        let hdr = NlMsgHdr {
            nlmsg_len: 16,
            nlmsg_type: RTM_NEWLINK,
            nlmsg_flags: 0,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        let bytes: Vec<u8> = unsafe {
            std::slice::from_raw_parts(
                &hdr as *const NlMsgHdr as *const u8,
                std::mem::size_of::<NlMsgHdr>(),
            )
            .to_vec()
        };
        let parsed = nl_msg_hdr_from_bytes(&bytes, 0).unwrap();
        assert_eq!(parsed.nlmsg_type, RTM_NEWLINK);
        assert_eq!(parsed.nlmsg_len, 16);
    }

    #[test]
    fn nl_msg_hdr_from_bytes_short() {
        let buf = vec![0u8; 4];
        assert!(nl_msg_hdr_from_bytes(&buf, 0).is_none());
    }

    #[test]
    fn nl_msg_hdr_from_bytes_offset() {
        let mut buf = vec![0u8; 32];
        let hdr = NlMsgHdr {
            nlmsg_len: 16,
            nlmsg_type: RTM_NEWADDR,
            nlmsg_flags: 0,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                &hdr as *const NlMsgHdr as *const u8,
                buf.as_mut_ptr().add(16),
                std::mem::size_of::<NlMsgHdr>(),
            );
        }
        let parsed = nl_msg_hdr_from_bytes(&buf, 16).unwrap();
        assert_eq!(parsed.nlmsg_type, RTM_NEWADDR);
    }

    #[test]
    fn nl_attr_from_bytes_valid() {
        let attr = NlAttr {
            nla_len: 8,
            nla_type: 3,
        };
        let bytes: Vec<u8> = unsafe {
            std::slice::from_raw_parts(
                &attr as *const NlAttr as *const u8,
                std::mem::size_of::<NlAttr>(),
            )
            .to_vec()
        };
        let parsed = nl_attr_from_bytes(&bytes, 0).unwrap();
        assert_eq!(parsed.nla_type, 3);
        assert_eq!(parsed.nla_len, 8);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = NetlinkConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let de: NetlinkConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.monitor_interfaces, de.monitor_interfaces);
        assert_eq!(config.monitor_routes, de.monitor_routes);
    }

    #[test]
    fn nlmsg_constants() {
        assert_eq!(RTM_NEWLINK, 16);
        assert_eq!(RTM_DELLINK, 17);
        assert_eq!(RTM_NEWADDR, 20);
        assert_eq!(RTM_DELADDR, 21);
        assert_eq!(RTM_NEWROUTE, 24);
        assert_eq!(RTM_DELROUTE, 25);
        assert_eq!(RTM_NEWNEIGH, 28);
        assert_eq!(RTM_DELNEIGH, 29);
        assert_eq!(NLMSG_DONE, 3);
        assert_eq!(NLMSG_ERROR, 2);
    }

    #[test]
    fn find_ifname_attr_empty() {
        let buf = vec![0u8; 32];
        assert!(find_ifname_attr(&buf, 0, 0).is_none());
    }

    #[test]
    fn extract_string_from_nla_empty() {
        let buf = vec![0u8; 32];
        assert!(extract_string_from_nla(&buf, 0).is_none());
    }
}
