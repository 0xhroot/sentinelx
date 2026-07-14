use crate::commands::{print_separator, BOLD, CYAN, GREEN, RESET, YELLOW};
use sentinelx_network::NetworkScanner;

pub fn run() {
    println!("{}{}Network Connections{}", BOLD, CYAN, RESET);
    println!();

    let scanner = NetworkScanner::new();
    let connections = scanner.scan_all();

    if connections.is_empty() {
        println!("{}No active connections found.{}", YELLOW, RESET);
        return;
    }

    println!(
        "{}{:<6} {:<14} {:<25} {:<25} {:<14} {:<8} {:<12}{}",
        BOLD, "PROTO", "STATE", "LOCAL", "REMOTE", "PROCESS", "PID", "UID", RESET
    );
    print_separator();

    for conn in &connections {
        let proto_str = match conn.protocol {
            sentinelx_common::types::Protocol::Tcp => "TCP",
            sentinelx_common::types::Protocol::Tcp6 => "TCP6",
            sentinelx_common::types::Protocol::Udp => "UDP",
            sentinelx_common::types::Protocol::Udp6 => "UDP6",
            sentinelx_common::types::Protocol::Unix => "UNIX",
        };

        let state_str = match conn.state {
            sentinelx_common::types::ConnectionState::Established => "ESTABLISHED",
            sentinelx_common::types::ConnectionState::Listen => "LISTEN",
            sentinelx_common::types::ConnectionState::TimeWait => "TIME_WAIT",
            sentinelx_common::types::ConnectionState::CloseWait => "CLOSE_WAIT",
            sentinelx_common::types::ConnectionState::SynSent => "SYN_SENT",
            sentinelx_common::types::ConnectionState::SynRecv => "SYN_RECV",
            sentinelx_common::types::ConnectionState::FinWait1 => "FIN_WAIT1",
            sentinelx_common::types::ConnectionState::FinWait2 => "FIN_WAIT2",
            sentinelx_common::types::ConnectionState::Close => "CLOSE",
            sentinelx_common::types::ConnectionState::LastAck => "LAST_ACK",
            sentinelx_common::types::ConnectionState::Closing => "CLOSING",
            sentinelx_common::types::ConnectionState::Unknown => "UNKNOWN",
        };

        let local = format!("{}:{}", conn.local_addr.ip, conn.local_addr.port);
        let remote = conn
            .remote_addr
            .as_ref()
            .map(|r| format!("{}:{}", r.ip, r.port))
            .unwrap_or_else(|| "*:*".to_string());

        let proc_name = conn.process_name.as_deref().unwrap_or("-");
        let pid_str = conn
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());

        let _row_color = if conn.state == sentinelx_common::types::ConnectionState::Established {
            GREEN
        } else if conn.state == sentinelx_common::types::ConnectionState::Listen {
            CYAN
        } else {
            ""
        };

        println!(
            "  {:<6} {:<14} {:<25} {:<25} {:<14} {:<8} {:<12}",
            proto_str,
            truncate_utf8(state_str, 13),
            truncate_utf8(&local, 24),
            truncate_utf8(&remote, 24),
            truncate_utf8(proc_name, 13),
            pid_str,
            conn.uid,
        );
    }

    println!();
    print_separator();
    let tcp_est = connections
        .iter()
        .filter(|c| c.state == sentinelx_common::types::ConnectionState::Established)
        .count();
    let tcp_listen = connections
        .iter()
        .filter(|c| c.state == sentinelx_common::types::ConnectionState::Listen)
        .count();
    println!(
        "{}Total:{} {}   {}Established:{} {}   {}Listening:{} {}",
        BOLD,
        RESET,
        connections.len(),
        GREEN,
        RESET,
        tcp_est,
        CYAN,
        RESET,
        tcp_listen,
    );
}

fn truncate_utf8(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count > max_chars {
        let truncated: String = s.chars().take(max_chars - 1).collect();
        format!("{}…", truncated)
    } else {
        s.to_string()
    }
}
