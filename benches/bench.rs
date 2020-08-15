use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};
use ordered_float::OrderedFloat;
use rand::{
    distributions::{Distribution, Uniform},
    seq::SliceRandom,
    Rng,
};
use rustc_hash::{FxHashSet, FxHasher};
use std::hash::{Hash, Hasher};
use zwohash::{HashSet, ZwoHasher};

#[derive(Debug)]
enum HashFn {
    ZwoHash,
    FxHash,
}

impl std::fmt::Display for HashFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

fn zwo_hash(data: &(impl Hash + ?Sized)) -> u64 {
    let mut hasher = ZwoHasher::default();
    data.hash(&mut hasher);
    hasher.finish()
}

fn fx_hash(data: &(impl Hash + ?Sized)) -> u64 {
    let mut hasher = FxHasher::default();
    data.hash(&mut hasher);
    hasher.finish()
}

fn compare_hashes(group: &mut BenchmarkGroup<WallTime>, name: &str, data: &(impl Hash + ?Sized)) {
    group.bench_with_input(BenchmarkId::new(name, HashFn::ZwoHash), &data, |b, data| {
        b.iter(|| zwo_hash(data))
    });
    group.bench_with_input(BenchmarkId::new(name, HashFn::FxHash), &data, |b, data| {
        b.iter(|| fx_hash(data))
    });
}

fn compare_hash_sets(group: &mut BenchmarkGroup<WallTime>, name: &str, data: &[impl Hash + Eq]) {
    group.bench_with_input(BenchmarkId::new(name, HashFn::ZwoHash), data, |b, data| {
        b.iter(|| {
            let mut set = HashSet::default();
            for i in data {
                set.insert(i);
            }
            set
        })
    });
    group.bench_with_input(BenchmarkId::new(name, HashFn::FxHash), data, |b, data| {
        b.iter(|| {
            let mut set = FxHashSet::default();
            for i in data {
                set.insert(i);
            }
            set
        })
    });
}

fn hashing_ints(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing ints");

    compare_hashes(&mut group, "u8", &42u8);
    compare_hashes(&mut group, "u16", &0x243fu16);
    compare_hashes(&mut group, "u32", &0xb7e15163u32);
    compare_hashes(&mut group, "u64", &0x9e3779b97f4a7c16u64);
}

fn hashing_short_slices(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing short slices");

    compare_hashes(&mut group, "len = 1", &b"h");
    compare_hashes(&mut group, "len = 3", &b"hel");
    compare_hashes(&mut group, "len = 4", &b"hell");
    compare_hashes(&mut group, "len = 7", &b"hello w");
    compare_hashes(&mut group, "len = 8", &b"hello wo");
    compare_hashes(&mut group, "len = 12", &b"hello world!");
    compare_hashes(
        &mut group,
        "len = 33",
        &b"hello world! this is a bit longer",
    );
}

fn hashing_long_slices(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing long slices");
    let mut rng = rand_pcg::Pcg64::new(1, 1);

    let long_slices: Vec<Vec<u8>> = [1 << 10, 1 << 15, 1 << 20]
        .iter()
        .map(|&length| (0..length).map(|_| rng.gen()).collect())
        .collect();

    for slice in long_slices.iter() {
        compare_hashes(
            &mut group,
            &format!("len = {}", slice.len()),
            slice.as_slice(),
        );
    }
}

fn building_int_sets(c: &mut Criterion) {
    let mut group = c.benchmark_group("building int sets");

    let mut rng = rand_pcg::Pcg64::new(1, 1);

    let mut bits_0_14: Vec<u64> = (0..1 << 14).collect();
    bits_0_14.shuffle(&mut rng);
    bits_0_14.truncate(1 << 13);

    let mut bits_4_18: Vec<u64> = (0..1 << 14).map(|i| i << 4).collect();
    bits_4_18.shuffle(&mut rng);
    bits_4_18.truncate(1 << 13);

    let mut bits_8_20: Vec<u64> = (0..1 << 14).map(|i| i << 8).collect();
    bits_8_20.shuffle(&mut rng);
    bits_8_20.truncate(1 << 13);

    let mut bits_16_30: Vec<u64> = (0..1 << 14).map(|i| i << 16).collect();
    bits_16_30.shuffle(&mut rng);
    bits_16_30.truncate(1 << 13);

    let mut bits_50_64: Vec<u64> = (0..1 << 14).map(|i| i << 50).collect();
    bits_50_64.shuffle(&mut rng);
    bits_50_64.truncate(1 << 13);

    compare_hash_sets(&mut group, "u64 bits 0..14", &bits_0_14);
    compare_hash_sets(&mut group, "u64 bits 4..18", &bits_4_18);
    compare_hash_sets(&mut group, "u64 bits 8..20", &bits_8_20);
    compare_hash_sets(&mut group, "u64 bits 50..64", &bits_16_30);
}

fn building_str_sets(c: &mut Criterion) {
    let mut group = c.benchmark_group("building str sets");
    group.sample_size(50);

    let wordlist = include_str!("UKACD18.txt");
    let mut words: Vec<&str> = wordlist.split('\n').collect();

    let mut rng = rand_pcg::Pcg64::new(1, 1);
    words.shuffle(&mut rng);

    for &count in &[2000, 20000, 200000] {
        compare_hash_sets(&mut group, &format!("{} words", count), &words[..count]);
    }
}

fn building_misc_sets(c: &mut Criterion) {
    let mut group = c.benchmark_group("building misc sets");
    group.sample_size(50);

    let mut rng = rand_pcg::Pcg64::new(1, 1);

    let range = Uniform::from(-64..=64);

    let points: Vec<[i32; 2]> = (0..1 << 14)
        .map(|_| [range.sample(&mut rng), range.sample(&mut rng)])
        .collect();

    compare_hash_sets(&mut group, "small [i32; 2]", &points);

    let mut int_floats: Vec<OrderedFloat<f64>> = (0..1 << 14).map(|i| (i as f64).into()).collect();
    int_floats.shuffle(&mut rng);
    compare_hash_sets(&mut group, "int f64", &int_floats);

    let mut sparse_slices: Vec<[u8; 8]> = (0..256 * 8)
        .map(|i| {
            let mut x = [0; 8];
            x[i >> 8] = i as u8;
            x
        })
        .collect();
    sparse_slices.shuffle(&mut rng);
    compare_hash_sets(&mut group, "sparse [u8; 8]", &sparse_slices);
}

criterion_group!(
    benches,
    hashing_ints,
    hashing_short_slices,
    hashing_long_slices,
    building_int_sets,
    building_str_sets,
    building_misc_sets,
);
criterion_main!(benches);
