use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinelx_common::traits::Detector;

fn bench_full_scan_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_scan_sequential");
    group.sample_size(10);

    group.bench_function("all_5_detectors", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        b.iter(|| {
            rt.block_on(async {
                let detectors: Vec<Box<dyn Detector>> = vec![
                    Box::new(sentinelx_kernel::KernelIntegrityDetector::new()),
                    Box::new(sentinelx_kernel::HookDetector::new()),
                    Box::new(sentinelx_memory::MemoryIntegrityChecker::new()),
                    Box::new(sentinelx_integrity::IntegrityChecker::new()),
                    Box::new(sentinelx_persistence::PersistenceScanner::new()),
                ];

                let mut all_threats = Vec::new();
                for detector in &detectors {
                    if let Ok(threats) = detector.detect().await {
                        all_threats.extend(threats);
                    }
                }
                black_box(all_threats);
            });
        });
    });

    group.finish();
}

fn bench_full_scan_concurrent(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_scan_concurrent");
    group.sample_size(10);

    group.bench_function("all_5_detectors_join_all", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        b.iter(|| {
            rt.block_on(async {
                let handle1 = tokio::spawn(async {
                    sentinelx_kernel::KernelIntegrityDetector::new()
                        .detect()
                        .await
                });
                let handle2 =
                    tokio::spawn(async { sentinelx_kernel::HookDetector::new().detect().await });
                let handle3 = tokio::spawn(async {
                    sentinelx_memory::MemoryIntegrityChecker::new()
                        .detect()
                        .await
                });
                let handle4 = tokio::spawn(async {
                    sentinelx_integrity::IntegrityChecker::new().detect().await
                });
                let handle5 = tokio::spawn(async {
                    sentinelx_persistence::PersistenceScanner::new()
                        .detect()
                        .await
                });

                let mut all_threats = Vec::new();
                for handle in [handle1, handle2, handle3, handle4, handle5] {
                    if let Ok(Ok(threats)) = handle.await {
                        all_threats.extend(threats);
                    }
                }
                black_box(all_threats);
            });
        });
    });

    group.finish();
}

fn bench_scan_to_timeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_to_timeline");
    group.sample_size(10);

    group.bench_function("scan_build_timeline_correlate", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        b.iter(|| {
            rt.block_on(async {
                let detectors: Vec<Box<dyn Detector>> = vec![
                    Box::new(sentinelx_kernel::KernelIntegrityDetector::new()),
                    Box::new(sentinelx_kernel::HookDetector::new()),
                    Box::new(sentinelx_memory::MemoryIntegrityChecker::new()),
                    Box::new(sentinelx_integrity::IntegrityChecker::new()),
                    Box::new(sentinelx_persistence::PersistenceScanner::new()),
                ];

                let mut all_threats = Vec::new();
                for detector in &detectors {
                    if let Ok(threats) = detector.detect().await {
                        all_threats.extend(threats);
                    }
                }

                let mut timeline = sentinelx_timeline::TimelineEngine::new();
                for threat in all_threats {
                    timeline.add_event(threat);
                }
                timeline.sort_by_time();
                let _narrative = timeline.generate_attack_narrative();
                let _clusters = timeline.correlate();
                black_box(timeline);
            });
        });
    });

    group.finish();
}

fn bench_scan_to_report(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_to_report");
    group.sample_size(10);

    group.bench_function("scan_generate_json_report", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        b.iter(|| {
            rt.block_on(async {
                let detectors: Vec<Box<dyn Detector>> = vec![
                    Box::new(sentinelx_kernel::KernelIntegrityDetector::new()),
                    Box::new(sentinelx_kernel::HookDetector::new()),
                    Box::new(sentinelx_memory::MemoryIntegrityChecker::new()),
                    Box::new(sentinelx_integrity::IntegrityChecker::new()),
                    Box::new(sentinelx_persistence::PersistenceScanner::new()),
                ];

                let mut all_threats = Vec::new();
                for detector in &detectors {
                    if let Ok(threats) = detector.detect().await {
                        all_threats.extend(threats);
                    }
                }

                let generator = sentinelx_reporting::ReportGenerator::new();
                let report = generator.generate_json_report(&all_threats);
                black_box(report);
            });
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_full_scan_sequential,
    bench_full_scan_concurrent,
    bench_scan_to_timeline,
    bench_scan_to_report,
);

criterion_main!(benches);
