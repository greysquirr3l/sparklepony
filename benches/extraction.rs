//! Benchmarks for PST WEEE extraction

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pst_weee::filter::validate_email;

fn email_validation_benchmark(c: &mut Criterion) {
    let long_email = format!("{}@example.com", "a".repeat(50));
    let emails: Vec<&str> = vec![
        "user@example.com",
        "john.doe@company.org",
        "test123@domain.co.uk",
        "invalid-email",
        "noreply@bounce.company.com",
        &long_email,
    ];

    let mut group = c.benchmark_group("email_validation");

    for email in &emails {
        let id: String = email.chars().take(20).collect();
        group.bench_with_input(BenchmarkId::new("validate", &id), email, |b, email| {
            b.iter(|| validate_email(email, 20));
        });
    }

    group.finish();
}

criterion_group!(benches, email_validation_benchmark);
criterion_main!(benches);
