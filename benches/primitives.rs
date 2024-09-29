#![allow(unknown_lints, clippy::incompatible_msrv, missing_docs)]

use primitives::{bits::address::Address, bytes::Bytes};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::hint::black_box;

fn primitives(c: &mut Criterion) {
    let mut g = c.benchmark_group("primitives");
    g.bench_function("address/checksum", |b| {
        let address = Address::random();
        let out = &mut [0u8; 42];
        b.iter(|| {
            unsafe {
             let x = address.to_checksum_inner(black_box(out), None);
             black_box(x);
            }
      
        })
    });
    for size in [32, 64, 128, 256].iter() {
        g.bench_with_input(BenchmarkId::new("bytes", size), size, |b, &size| {
            let bytes = Bytes::from(vec![0xAA; size]); 
            b.iter(|| {
                unsafe {
                    let x = black_box(&bytes).to_hex(false);
                    black_box(x);
                }
            })
        });
    }
    g.finish();
}

criterion_group!(benches, primitives);
criterion_main!(benches);
