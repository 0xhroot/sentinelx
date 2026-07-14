# SentinelX Phase 9: Native eBPF Kernel Sensor Architecture

## Overview

Phase 9 transforms SentinelX from a userspace-only detection platform into a kernel-instrumented EDR system. It replaces all stub telemetry providers with real kernel instrumentation using eBPF (Aya), fanotify, netlink, and audit sockets, providing high-fidelity event detection with graceful degradation.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Kernel Space                          │
│                                                              │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌───────────┐  │
│  │ eBPF     │  │ fanotify  │  │ NETLINK  │  │ NETLINK   │  │
│  │ Programs │  │ Events    │  │ ROUTE    │  │ AUDIT     │  │
│  │ (Aya)    │  │           │  │          │  │           │  │
│  └────┬─────┘  └─────┬─────┘  └────┬─────┘  └─────┬─────┘  │
│       │              │              │              │         │
│       └──────────────┴──────┬───────┴──────────────┘         │
│                             │                                │
└─────────────────────────────┼────────────────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │   Ring Buffers /    │
                    │   Socket Read Loop  │
                    └─────────┬──────────┘
                              │
┌─────────────────────────────┼────────────────────────────────┐
│                        User Space                             │
│                              │                                │
│  ┌───────────────────────────▼────────────────────────────┐  │
│  │              TelemetryProvider Trait                    │  │
│  │                                                         │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │  │ Ebpf    │ │ Fanotify │ │ Netlink  │ │ Auditd   │  │  │
│  │  │Provider │ │ Provider │ │ Provider │ │ Provider │  │  │
│  │  └────┬────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │  │
│  │       │           │            │             │         │  │
│  │       └───────────┴──────┬─────┴─────────────┘         │  │
│  │                          │                             │  │
│  │                    ┌─────▼──────┐                      │  │
│  │                    │TelemetryBus│                      │  │
│  │                    └─────┬──────┘                      │  │
│  └──────────────────────────┼─────────────────────────────┘  │
│                              │                                │
│  ┌───────────────────────────▼────────────────────────────┐  │
│  │                   Pipeline                             │  │
│  │  Discovery → Metadata → Assessment → Evidence →        │  │
│  │  Correlation → Incident → Threat → Response            │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              ProviderManager                           │  │
│  │  Capability Detection → Provider Selection → Fallback  │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Provider Crate Implementations

### 1. eBPF Provider (`crates/ebpf/`)

**Technology:** Aya 0.14 userspace eBPF framework

**Architecture:**
- `EbpfEngine`: Core engine managing eBPF programs, maps, and event processing
- `EbpfTelemetryProvider`: TelemetryProvider trait implementation
- Capability detection via `capget` syscall (CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON)

**Supported Program Types:**
| Type | Kernel Hook | Events Detected |
|------|-------------|-----------------|
| Tracepoint | `sched:sched_process_exec` | ProcessExec |
| Tracepoint | `sched:sched_process_exit` | ProcessExit |
| Tracepoint | `sched:sched_process_fork` | ProcessFork |
| Kprobe | `__x64_sys_setuid` | ProcessSetuid |
| Kprobe | `__x64_sys_setgid` | ProcessSetgid |
| Kprobe | `security_bpf_prog_load` | KernelBpfLoad |
| XDP | Network packet processing | NetConnect, NetBind |

**Event Flow:**
1. eBPF programs write to ring buffer (BPF_MAP_TYPE_RINGBUF)
2. `EbpfEngine::read_events()` polls ring buffer
3. `BpfRawEvent` (repr(C)) parsed from raw bytes
4. Mapped to `TelemetryEvent` via `bpf_event_to_telemetry()`

**Graceful Degradation:**
- If no BTF: Fall back to tracepoint-only mode
- If no CAP_BPF: Mark as Degraded
- If program load fails: Continue with remaining programs

### 2. fanotify Provider (`crates/fanotify/`)

**Technology:** Linux fanotify syscalls via libc

**Architecture:**
- `FanotifyProvider`: TelemetryProvider trait implementation
- Blocking read loop on OS thread (`tokio::task::spawn_blocking`)
- O_NONBLOCK prevents async runtime blocking

**Syscalls Used:**
- `fanotify_init(FAN_CLASS_NOTIF, O_RDONLY | O_CLOEXEC | O_NONBLOCK)`
- `fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN | FAN_MODIFY | ..., AT_FDCWD, path)`

**Event Mapping:**
| fanotify Event | TelemetryEventType |
|---------------|-------------------|
| `FAN_ACCESS` | FileRead |
| `FAN_OPEN` | FileOpen |
| `FAN_MODIFY` | FileWrite |
| `FAN_CLOSE_WRITE` | FileClose |
| `FAN_DELETE` | FileDelete |
| `FAN_OPEN_PERM` | FileExecute |
| `FAN_ATTRIB` | FilePermChange |

**Default Watched Paths:** `/etc`, `/usr`, `/boot`

**Graceful Degradation:**
- If not root/CAP_SYS_ADMIN: Mark as Degraded
- If fanotify_init fails: Mark as Error

### 3. Netlink Provider (`crates/netlink/`)

**Technology:** Real AF_NETLINK socket with NETLINK_ROUTE

**Architecture:**
- `NetlinkProvider`: TelemetryProvider trait implementation
- Raw `socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)` with multicast groups
- Non-blocking read loop on OS thread

**Subscribed Groups:**
| Group | Events Monitored |
|-------|-----------------|
| `RTMGRP_LINK` | Network interface up/down |
| `RTMGRP_IPV4_IFADDR` | IPv4 address changes |
| `RTMGRP_IPV6_IFADDR` | IPv6 address changes |
| `RTMGRP_IPV4_ROUTE` | IPv4 route changes |
| `RTMGRP_IPV6_ROUTE` | IPv6 route changes |
| `RTMGRP_NEIGH` | ARP/neighbor table changes |

**Event Mapping:**
| Netlink Message | TelemetryEventType |
|----------------|-------------------|
| `RTM_NEWLINK/RTM_DELLINK` | NetConnect/NetClose |
| `RTM_NEWADDR/RTM_DELADDR` | NetBind |
| `RTM_NEWROUTE/RTM_DELROUTE` | NetConnect/NetClose |
| `RTM_NEWNEIGH/RTM_DELNEIGH` | NetConnect/NetClose |

**Netlink Message Parsing:**
- `NlMsgHdr` → message type, flags, sequence
- `Ifinfomsg` → interface index, flags
- `NlAttr` TLV (Type-Length-Value) attributes parsed recursively
- Interface names, IPv4/IPv6 addresses extracted from attributes

### 4. Audit Provider (`crates/audit/`)

**Technology:** Real NETLINK_AUDIT socket

**Architecture:**
- `AuditdProvider`: TelemetryProvider trait implementation
- Raw `socket(PF_NETLINK, SOCK_RAW, NETLINK_AUDIT)`
- Sends `AUDIT_GET` on init, `AUDIT_SET` to enable
- Parses SYSCALL, EXECVE, CRED, PATH audit record types

**Syscall to Event Mapping (x86_64):**
| Syscall # | Name | TelemetryEventType |
|-----------|------|-------------------|
| 59 | execve | ProcessExec |
| 56 | fork | ProcessFork |
| 57 | clone | ProcessClone |
| 105 | setuid | ProcessSetuid |
| 106 | setgid | ProcessSetgid |
| 0 | read | FileRead |
| 1 | write | FileWrite |
| 2 | open | FileOpen |
| 87 | unlink | FileDelete |
| 82 | rename | FileRename |
| 90 | chmod | FilePermChange |
| 92 | chown | FileOwnChange |
| 41 | socket | NetConnect |
| 42 | connect | NetConnect |
| 49 | bind | NetBind |
| 175 | init_module | KernelModuleLoad |
| 313 | bpf | KernelBpfLoad |

**Audit Record Parsing:**
- `SYSCALL(a0=59, a1=..., pid=100, ...)` → Extract syscall number, PID
- `EXECVE(argc=1, argv0="/bin/ls")` → Command execution details
- `CRED(pid=100, uid=0, old_uid=1000)` → Privilege changes
- `PATH(item=0, name="/etc/passwd")` → File access paths

**Key-Value Extraction:**
- Boundary-aware parsing handles nested parentheses: `SYSCALL(a0=59, pid=100)`
- Space-delimited fields: `type=SYSCALL msg=audit(1234567890.123:456)`
- Quote/comma/parenthesis stripping for clean values

## ProviderManager (`crates/telemetry/src/provider_manager.rs`)

The ProviderManager handles capability detection and provider selection:

**Capability Detection:**
- `detect_ebpf()`: Checks `/sys/kernel/btf/vmlinux` + CAP_BPF/CAP_SYS_ADMIN
- `detect_fanotify()`: Checks CAP_SYS_ADMIN
- `detect_netlink()`: Always available (AF_NETLINK is unrestricted)
- `detect_audit()`: Checks CAP_AUDIT_WRITE/CAP_AUDIT_CONTROL
- `detect_proc_connector()`: Always available (/proc filesystem)

**Capability Priority (Fallback Order):**
1. eBPF (preferred - highest fidelity)
2. fanotify (filesystem monitoring)
3. netlink (network monitoring)
4. audit (audit subsystem)

**Latency Tracking:**
- `LatencyTracker` uses `AtomicU64` for lock-free operation
- Records per-event latency in microseconds
- Reports average and maximum latency per provider

**Reports:**
- `CapabilityReport`: availability status per capability
- `ProviderHealthReport`: health status with uptime and drop rate
- `KernelLatencyReport`: average/max latency per provider
- `TelemetryRateReport`: events received/dropped per provider

## Backend API Routes

New endpoints added to the Axum backend:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /api/telemetry/providers/health` | GET | Detailed provider health with uptime and drop rates |
| `GET /api/telemetry/providers/latency` | GET | Kernel latency reports per provider |
| `GET /api/telemetry/providers/rate` | GET | Telemetry event rates per provider |
| `GET /api/telemetry/providers/capabilities` | GET | Detected kernel capabilities and preferred order |

**Health Response Example:**
```json
{
    "providers": [
        {
            "name": "ebpf",
            "status": "running",
            "events_received": 12345,
            "events_dropped": 0,
            "started_at": "2025-01-15T10:30:00Z",
            "uptime_seconds": 3600,
            "drop_rate_percent": 0.0
        }
    ],
    "summary": {
        "total": 5,
        "running": 4,
        "degraded": 1,
        "stopped": 0
    }
}
```

**Capabilities Response Example:**
```json
{
    "capabilities": [
        {"capability": "Ebpf", "available": true, "reason": "BTF available, sufficient capabilities"},
        {"capability": "Fanotify", "available": true, "reason": "CAP_SYS_ADMIN available"},
        {"capability": "Netlink", "available": true, "reason": "AF_NETLINK sockets available"},
        {"capability": "Audit", "available": false, "reason": "Requires CAP_AUDIT_WRITE"},
        {"capability": "ProcConnector", "available": true, "reason": "Always available"}
    ],
    "preferred_order": ["Ebpf", "Fanotify", "Netlink", "ProcConnector"],
    "active_providers": ["ebpf", "fanotify", "netlink", "proc_connector"]
}
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `sentinelx ebpf` | Shows eBPF kernel sensor status and capabilities |
| `sentinelx providers-health` | Shows detailed telemetry provider health diagnostics |

**ebpf Command Output:**
- Kernel capabilities (BTF, CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON)
- eBPF program types (tracepoints, kprobes, XDP, perf events)
- Supported event types
- Preferred provider order

**providers-health Command Output:**
- Capability detection results
- Active providers list
- Kernel latency per provider
- Telemetry event rates

## Benchmarks

`crates/benchmarks/benches/telemetry_throughput.rs` contains Criterion benchmarks for:

- **Bus publish throughput**: Measures event publishing at different channel capacities
- **Bus subscribe/receive throughput**: Measures event reception at different volumes
- **Event creation overhead**: Per-event-type creation cost
- **MPSC channel throughput**: Raw tokio channel performance as baseline

## Error Handling & Graceful Degradation

All providers follow the same degradation pattern:

1. **Initialization failure** → Set `ProviderStatus::Degraded`
2. **Event read failure** → Increment `events_dropped`, continue
3. **Capability missing** → Log reason, continue without that provider
4. **Socket/fd error** → Close fd, set status to `Error`
5. **Runtime error** → Log error, continue with other providers

**Safety Defaults:**
- `dry_run=true` for response actions
- `never_kill_init=true` - PID 1 is always protected
- `never_unload_core_modules=true` - Critical kernel modules protected
- Protected PIDs: [1]
- Protected modules: [vmlinux, core, nvidia, drm, kvm]

## Test Coverage

| Crate | Tests | Focus |
|-------|-------|-------|
| sentinelx-ebpf | 29 | Capability detection, event parsing, program loading |
| sentinelx-fanotify | 22 | Syscall wrappers, event mapping, fd lifecycle |
| sentinelx-netlink | 14 | Socket creation, NLA parsing, event mapping |
| sentinelx-audit | 19 | Audit record parsing, syscall mapping, key extraction |
| sentinelx-telemetry (provider_manager) | 12 | Capability detection, latency tracking, health reports |
| **Total new** | **96** | |

## Integration Points

### Backend (main.rs)
```rust
let provider_manager = Arc::new(ProviderManager::detect());
// Registered in AppState for API routes
```

### CLI (commands/kernel.rs)
```rust
// sentinelx ebpf - Shows capability detection and eBPF status
// sentinelx providers-health - Shows provider health and latency
```

### Telemetry Engine
```rust
// Providers registered via engine.register_provider()
// ProviderManager tracks capabilities independently
// Bus publishes events from all providers to subscribers
```

## Performance Characteristics

- **eBPF**: Near-zero overhead when programs are attached; ring buffer is lock-free
- **fanotify**: Minimal overhead; OS handles event queuing
- **netlink**: Low overhead; kernel sends events via multicast
- **audit**: Moderate overhead; depends on audit rules complexity
- **Bus**: Lock-free `mpsc` channel for event ingestion; `broadcast` for fan-out

## Security Considerations

- All providers require appropriate Linux capabilities
- eBPF programs are loaded via Aya (verified by kernel)
- fanotify marks are restricted to mount points
- Netlink sockets are unicast (no privilege required for basic monitoring)
- Audit socket requires CAP_AUDIT_WRITE for event generation
- No credentials or secrets are logged or stored
