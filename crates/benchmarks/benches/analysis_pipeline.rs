use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinelx_common::traits::Detector;

fn bench_timeline_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("timeline_engine");
    group.sample_size(50);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let threats = rt.block_on(async {
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(sentinelx_kernel::KernelIntegrityDetector::new()),
            Box::new(sentinelx_kernel::HookDetector::new()),
            Box::new(sentinelx_memory::MemoryIntegrityChecker::new()),
            Box::new(sentinelx_integrity::IntegrityChecker::new()),
            Box::new(sentinelx_persistence::PersistenceScanner::new()),
        ];

        let mut all = Vec::new();
        for d in &detectors {
            if let Ok(t) = d.detect().await {
                all.extend(t);
            }
        }
        all
    });

    group.bench_function("add_events_100", |b| {
        b.iter(|| {
            let mut engine = sentinelx_timeline::TimelineEngine::new();
            for threat in threats.iter().cycle().take(100) {
                engine.add_event(black_box(threat.clone()));
            }
            black_box(&engine);
        });
    });

    group.bench_function("sort_by_time", |b| {
        b.iter_with_large_drop(|| {
            let mut engine = sentinelx_timeline::TimelineEngine::new();
            for threat in threats.iter().cycle().take(200) {
                engine.add_event(threat.clone());
            }
            engine.sort_by_time();
            engine
        });
    });

    group.bench_function("correlate", |b| {
        b.iter_with_large_drop(|| {
            let mut engine = sentinelx_timeline::TimelineEngine::new();
            for threat in threats.iter().cycle().take(200) {
                engine.add_event(threat.clone());
            }
            engine.sort_by_time();
            black_box(engine.correlate());
        });
    });

    group.bench_function("generate_attack_narrative", |b| {
        b.iter_with_large_drop(|| {
            let mut engine = sentinelx_timeline::TimelineEngine::new();
            for threat in threats.iter().cycle().take(100) {
                engine.add_event(threat.clone());
            }
            engine.sort_by_time();
            black_box(engine.generate_attack_narrative());
        });
    });

    group.finish();
}

fn bench_correlation_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_engine");
    group.sample_size(30);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let threats = rt.block_on(async {
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(sentinelx_kernel::KernelIntegrityDetector::new()),
            Box::new(sentinelx_kernel::HookDetector::new()),
            Box::new(sentinelx_memory::MemoryIntegrityChecker::new()),
            Box::new(sentinelx_integrity::IntegrityChecker::new()),
            Box::new(sentinelx_persistence::PersistenceScanner::new()),
        ];

        let mut all = Vec::new();
        for d in &detectors {
            if let Ok(t) = d.detect().await {
                all.extend(t);
            }
        }
        all
    });

    group.bench_function("correlate_50_events", |b| {
        b.iter(|| {
            let mut engine = sentinelx_correlation::CorrelationEngine::new();
            for threat in threats.iter().cycle().take(50) {
                engine.add_event(threat.clone());
            }
            black_box(engine.correlate());
        });
    });

    group.bench_function("correlate_200_events", |b| {
        b.iter(|| {
            let mut engine = sentinelx_correlation::CorrelationEngine::new();
            for threat in threats.iter().cycle().take(200) {
                engine.add_event(threat.clone());
            }
            black_box(engine.correlate());
        });
    });

    group.finish();
}

fn bench_reporting(c: &mut Criterion) {
    let mut group = c.benchmark_group("reporting");
    group.sample_size(20);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let threats = rt.block_on(async {
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(sentinelx_kernel::KernelIntegrityDetector::new()),
            Box::new(sentinelx_kernel::HookDetector::new()),
            Box::new(sentinelx_memory::MemoryIntegrityChecker::new()),
            Box::new(sentinelx_integrity::IntegrityChecker::new()),
            Box::new(sentinelx_persistence::PersistenceScanner::new()),
        ];

        let mut all = Vec::new();
        for d in &detectors {
            if let Ok(t) = d.detect().await {
                all.extend(t);
            }
        }
        all
    });

    group.bench_function("generate_json_report", |b| {
        let generator = sentinelx_reporting::ReportGenerator::new();
        b.iter(|| {
            black_box(generator.generate_json_report(&threats));
        });
    });

    group.bench_function("generate_summary_report", |b| {
        let generator = sentinelx_reporting::ReportGenerator::new();
        b.iter(|| {
            black_box(generator.generate_summary_report(&threats));
        });
    });

    group.finish();
}

fn bench_hash_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_operations");
    group.sample_size(100);

    group.bench_function("sha256_1kb", |b| {
        let data = vec![0u8; 1024];
        b.iter(|| {
            black_box(sentinelx_common::HashValue::new(&data));
        });
    });

    group.bench_function("sha256_1mb", |b| {
        let data = vec![0u8; 1024 * 1024];
        b.iter(|| {
            black_box(sentinelx_common::HashValue::new(&data));
        });
    });

    group.bench_function("sha256_10mb", |b| {
        let data = vec![0u8; 10 * 1024 * 1024];
        b.iter(|| {
            black_box(sentinelx_common::HashValue::new(&data));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_timeline_operations,
    bench_correlation_engine,
    bench_reporting,
    bench_hash_operations,
);

criterion_main!(benches);
