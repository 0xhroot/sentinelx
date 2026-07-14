use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use sentinelx_telemetry::{create_synthetic_event, BusConfig, TelemetryBus, TelemetryEventType};

fn bench_bus_publish(c: &mut Criterion) {
    let mut group = c.benchmark_group("telemetry_bus_publish");

    for capacity in [1000, 10000, 100000] {
        group.bench_with_input(
            BenchmarkId::new("publish", capacity),
            &capacity,
            |b, &capacity| {
                let rt = Runtime::new().unwrap();
                let config = BusConfig {
                    channel_capacity: capacity,
                    broadcast_capacity: 256,
                    ..Default::default()
                };
                let bus = TelemetryBus::new(config);

                b.iter(|| {
                    let event = create_synthetic_event("bench", TelemetryEventType::ProcessCreate);
                    rt.block_on(bus.publish(event));
                });
            },
        );
    }

    group.finish();
}

fn bench_bus_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("telemetry_bus_throughput");

    for num_events in [100, 1000, 10000] {
        group.bench_with_input(
            BenchmarkId::new("publish_batch", num_events),
            &num_events,
            |b, &num_events| {
                let rt = Runtime::new().unwrap();
                let config = BusConfig {
                    channel_capacity: 100000,
                    broadcast_capacity: 256,
                    ..Default::default()
                };
                let bus = TelemetryBus::new(config);

                b.iter(|| {
                    rt.block_on(async {
                        for _ in 0..num_events {
                            let event =
                                create_synthetic_event("bench", TelemetryEventType::ProcessCreate);
                            bus.publish(event).await;
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_bus_subscribe_receive(c: &mut Criterion) {
    let mut group = c.benchmark_group("telemetry_bus_subscribe_receive");

    for num_events in [100, 1000, 10000] {
        group.bench_with_input(
            BenchmarkId::new("subscribe_batch", num_events),
            &num_events,
            |b, &num_events| {
                let rt = Runtime::new().unwrap();
                let config = BusConfig {
                    channel_capacity: 100000,
                    broadcast_capacity: 256,
                    ..Default::default()
                };
                let bus = TelemetryBus::new(config);
                let mut rx = bus.subscribe();

                b.iter(|| {
                    rt.block_on(async {
                        for _ in 0..num_events {
                            let event =
                                create_synthetic_event("bench", TelemetryEventType::ProcessCreate);
                            bus.publish(event).await;
                        }
                        for _ in 0..num_events {
                            let _ = rx.recv().await;
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

fn bench_event_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("telemetry_event_creation");

    let event_types = [
        ("process_create", TelemetryEventType::ProcessCreate),
        ("process_exec", TelemetryEventType::ProcessExec),
        ("file_open", TelemetryEventType::FileOpen),
        ("file_write", TelemetryEventType::FileWrite),
        ("net_connect", TelemetryEventType::NetConnect),
        ("net_bind", TelemetryEventType::NetBind),
        ("kernel_module_load", TelemetryEventType::KernelModuleLoad),
        ("kernel_bpf_load", TelemetryEventType::KernelBpfLoad),
    ];

    for (name, event_type) in &event_types {
        group.bench_with_input(
            BenchmarkId::new("create", name),
            event_type,
            |b, event_type| {
                b.iter(|| {
                    create_synthetic_event("bench", event_type.clone());
                });
            },
        );
    }

    group.finish();
}

fn bench_event_categories(c: &mut Criterion) {
    let mut group = c.benchmark_group("telemetry_event_categories");

    let categories = [
        ("process", TelemetryEventType::ProcessCreate),
        ("filesystem", TelemetryEventType::FileWrite),
        ("network", TelemetryEventType::NetConnect),
        ("kernel", TelemetryEventType::KernelModuleLoad),
    ];

    for (name, event_type) in &categories {
        group.bench_with_input(
            BenchmarkId::new("create_category", name),
            event_type,
            |b, event_type| {
                b.iter(|| {
                    create_synthetic_event("bench", event_type.clone());
                });
            },
        );
    }

    group.finish();
}

fn bench_mpsc_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("telemetry_mpsc_channel");

    for capacity in [1000, 10000, 100000] {
        group.bench_with_input(
            BenchmarkId::new("mpsc_send_recv", capacity),
            &capacity,
            |b, &capacity| {
                let rt = Runtime::new().unwrap();
                let (tx, mut rx) = mpsc::channel(capacity);

                b.iter(|| {
                    rt.block_on(async {
                        for _ in 0..1000 {
                            let event =
                                create_synthetic_event("bench", TelemetryEventType::ProcessCreate);
                            let _ = tx.send(event).await;
                        }
                        for _ in 0..1000 {
                            let _ = rx.recv().await;
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_bus_publish,
    bench_bus_throughput,
    bench_bus_subscribe_receive,
    bench_event_creation,
    bench_event_categories,
    bench_mpsc_throughput,
);
criterion_main!(benches);
