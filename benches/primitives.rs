#![allow(
    unknown_lints,
    clippy::incompatible_msrv,
    missing_docs,
    dead_code,
    unsafe_code
)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use primitives::{bits::address::Address, bits::fixed::FixedBytes, bytes::Bytes, signature::parity::Parity};
use std::hint::black_box;

fn primitives(c: &mut Criterion) {
    let mut g = c.benchmark_group("primitives");
    g.bench_function("address/checksum", |b: &mut criterion::Bencher<'_>| {
        let address = Address::random();
        let out = &mut [0u8; 42];
        b.iter(|| {
            let x = address.to_checksum_inner(black_box(out), None);
            black_box(x);
        })
    });
    for size in [32, 64, 128, 256].iter() {
        g.bench_with_input(BenchmarkId::new("bytes", size), size, |b, &size| {
            let bytes = Bytes::from(vec![0xAA; size]);
            b.iter(|| {
                let x = black_box(&bytes).to_hex(false);
                black_box(x);
            })
        });
    }
    g.bench_function("IS_ZERO_SIMD", |b: &mut criterion::Bencher<'_>| {
        let bytes = [0xAA; 256];
        let bytes = FixedBytes::new(bytes);
        b.iter(|| unsafe {
            let x = black_box(&bytes).is_zero_simd();
            black_box(x);
        })
    });
    g.bench_function("IS_ZERO", |b: &mut criterion::Bencher<'_>| {
        let bytes = [0xAA; 256];
        let bytes = FixedBytes::new(bytes);
        b.iter(|| {
            let x = black_box(&bytes).is_zero();
            black_box(x);
        })
    });
    for size in [10, 100, 1000, 10000].iter() {
        g.bench_with_input(BenchmarkId::new("parity_invert", size), size, |b, &size| {
            let parities: Vec<Parity> = (0..size).map(|i| {
                match i % 3 {
                    0 => Parity::Eip155(i as u64),
                    1 => Parity::NonEip155(i & 1 == 0),
                    _ => Parity::Parity(i & 1 == 0),
                }
            }).collect();
            
            b.iter(|| {
                let mut inverted = parities.clone();
                for parity in &mut inverted {
                    *parity = black_box(parity.inverted());
                }
                black_box(inverted);
            })
        });
    }

    for size in [10, 100, 1000, 10000].iter() {
        g.bench_with_input(BenchmarkId::new("parity_invert_simd", size), size, |b, &size| {
            let parities: Vec<Parity> = (0..size).map(|i| {
                match i % 3 {
                    0 => Parity::Eip155(i as u64),
                    1 => Parity::NonEip155(i & 1 == 0),
                    _ => Parity::Parity(i & 1 == 0),
                }
            }).collect();
            
            b.iter(|| {
                let mut inverted = parities.clone();
                unsafe {
                    Parity::invert_simd(black_box(&mut inverted));
                }
                black_box(inverted);
            })
        });
    }


    g.finish();
}

criterion_group!(benches, primitives);
criterion_main!(benches);
