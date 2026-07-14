use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sentinelx_common::traits::Detector;

fn bench_kernel_integrity(c: &mut Criterion) {
    let mut group = c.benchmark_group("kernel_integrity_detector");
    group.sample_size(50);

    group.bench_function("detect", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let detector = sentinelx_kernel::KernelIntegrityDetector::new();
        b.iter(|| {
            rt.block_on(async {
                black_box(detector.detect().await.unwrap());
            })
        });
    });

    group.finish();
}

fn bench_kernel_hooks(c: &mut Criterion) {
    let mut group = c.benchmark_group("hook_detector");
    group.sample_size(50);

    group.bench_function("detect", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let detector = sentinelx_kernel::HookDetector::new();
        b.iter(|| {
            rt.block_on(async {
                black_box(detector.detect().await.unwrap());
            })
        });
    });

    group.finish();
}

fn bench_memory_integrity(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_integrity_detector");
    group.sample_size(30);

    group.bench_function("detect", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let detector = sentinelx_memory::MemoryIntegrityChecker::new();
        b.iter(|| {
            rt.block_on(async {
                black_box(detector.detect().await.unwrap());
            })
        });
    });

    group.finish();
}

fn bench_file_integrity(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_integrity_detector");
    group.sample_size(30);

    group.bench_function("detect", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let detector = sentinelx_integrity::IntegrityChecker::new();
        b.iter(|| {
            rt.block_on(async {
                black_box(detector.detect().await.unwrap());
            })
        });
    });

    group.finish();
}

fn bench_persistence(c: &mut Criterion) {
    let mut group = c.benchmark_group("persistence_scanner");
    group.sample_size(20);

    group.bench_function("detect", |b| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let detector = sentinelx_persistence::PersistenceScanner::new();
        b.iter(|| {
            rt.block_on(async {
                black_box(detector.detect().await.unwrap());
            })
        });
    });

    group.finish();
}

fn bench_process_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("process_scanner");
    group.sample_size(30);

    group.bench_function("scan_all", |b| {
        let scanner = sentinelx_process::ProcessScanner::new();
        b.iter(|| {
            black_box(scanner.scan_all());
        });
    });

    group.finish();
}

fn bench_network_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("network_scanner");
    group.sample_size(30);

    group.bench_function("scan_all", |b| {
        let scanner = sentinelx_network::NetworkScanner::new();
        b.iter(|| {
            black_box(scanner.scan_all());
        });
    });

    group.finish();
}

fn bench_module_trust(c: &mut Criterion) {
    let mut group = c.benchmark_group("module_trust_checker");
    group.sample_size(50);

    group.bench_function("check_all", |b| {
        let scanner = sentinelx_module::ModuleScanner::new();
        let checker = sentinelx_module::ModuleTrustChecker::new();
        let modules = scanner.scan_proc_modules();
        b.iter(|| {
            for module in &modules {
                black_box(checker.check(module));
            }
        });
    });

    group.finish();
}

fn bench_forensics_collect_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("forensics_collect_all");
    group.sample_size(10);

    group.bench_function("collect_all", |b| {
        let collector = sentinelx_forensics::ForensicsCollector::new();
        b.iter(|| {
            black_box(collector.collect_all());
        });
    });

    group.finish();
}

fn bench_forensics_process_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("forensics_process_tree");
    group.sample_size(10);

    group.bench_function("collect_process_tree", |b| {
        let collector = sentinelx_forensics::ForensicsCollector::new();
        b.iter(|| {
            black_box(collector.collect_process_tree());
        });
    });

    group.finish();
}

fn bench_forensics_network_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("forensics_network_state");
    group.sample_size(10);

    group.bench_function("collect_network_state", |b| {
        let collector = sentinelx_forensics::ForensicsCollector::new();
        b.iter(|| {
            black_box(collector.collect_network_state());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_kernel_integrity,
    bench_kernel_hooks,
    bench_memory_integrity,
    bench_file_integrity,
    bench_persistence,
    bench_process_scan,
    bench_network_scan,
    bench_module_trust,
    bench_forensics_collect_all,
    bench_forensics_process_tree,
    bench_forensics_network_state,
);

criterion_main!(benches);
