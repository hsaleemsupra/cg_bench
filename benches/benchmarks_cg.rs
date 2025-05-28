use std::hint::black_box;
use bicycl::b_i_c_y_c_l::{Mpz, QFI, RandGen};
use bicycl::cpp_std::VectorOfUchar;
use bicycl::{cpp_core, rust_vec_to_cpp, VectorOfMpz, VectorOfQFI};
use bicycl::cpp_core::{CppBox, MutRef, Ref};
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use cg_bench::cg_encryption::{decrypt, encrypt_all, keygen};
use cg_bench::utils::get_cl;

fn get_rng() -> CppBox<RandGen> {

    let seed = [4u8; 32];
    let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
    let ref_seed: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
    let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
    let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe{cpp_core::Ref::from_raw_ref(&seed_mpz)};
    let rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };
    rng_cpp
}

fn rand_mpz_cleartext_bound() -> CppBox<Mpz> {
    let cl = get_cl();
    let mut rng_cpp = get_rng();
    let r = unsafe { Mpz::new_copy(&rng_cpp.random_mpz(cl.cleartext_bound())) };
    r
}

fn rand_mpz_encrypt_bound() -> CppBox<Mpz> {
    let cl = get_cl();
    let mut rng_cpp = get_rng();
    let r = unsafe { Mpz::new_copy(&rng_cpp.random_mpz(cl.encrypt_randomness_bound())) };
    r
}

fn rand_qfi() -> CppBox<QFI> {
    let cl = get_cl();
    let r = rand_mpz_encrypt_bound();

    let mut result_qfi = unsafe{QFI::new_0a()};
    let mutref_ff: MutRef<QFI> = unsafe {MutRef::from_raw_ref(&mut result_qfi)};
    unsafe {cl.power_of_h(mutref_ff, &r)};
    result_qfi
}

fn benchmark_cg(c: &mut Criterion) {

    // Create a benchmark group
    let mut group = c.benchmark_group("Class group (bls12381)");
    // Set the sample size for the benchmarking group
    group.sample_size(10);
    let n_config = [64, 128, 256, 512];
    let cl = get_cl();

    let rand_cleartext = rand_mpz_cleartext_bound();
    group.bench_with_input(BenchmarkId::new("Exponentiation in Known Order Group", "(f^r)".to_string()), &cl, |b, _cfg| {
        b.iter(|| {
            let result = unsafe {cl.power_of_f(&rand_cleartext)};
            black_box(&result);
        });
    });

    let rand_cipher_bound = rand_mpz_cleartext_bound();
    let mut result_qfi = unsafe{QFI::new_0a()};
    let mutref_result: MutRef<QFI> = unsafe {MutRef::from_raw_ref(&mut result_qfi)};
    group.bench_with_input(BenchmarkId::new("Exponentiation in Unknown Order Group", "(Ĝ^r)".to_string()), &cl, |b, _cfg| {
        b.iter(|| {
            unsafe {cl.power_of_h(mutref_result, &rand_cipher_bound)};
            black_box(&mutref_result);
        });
    });

    let aa = rand_qfi();
    let ref_aa : Ref<QFI> = unsafe {Ref::from_raw_ref(&aa)};
    let bb = rand_qfi();
    let ref_bb : Ref<QFI> = unsafe {Ref::from_raw_ref(&bb)};
    let mut result_qfi = unsafe{QFI::new_0a()};
    let mutref_result: MutRef<QFI> = unsafe {MutRef::from_raw_ref(&mut result_qfi)};
    group.bench_with_input(BenchmarkId::new("Addition in Unknown Order Group", "(G1.G2)".to_string()), &cl, |b, _cfg| {
        b.iter(|| {
            unsafe{ cl.cl_delta().nucomp(mutref_result, ref_aa, ref_bb)};
            black_box(&mutref_result);
        });
    });

    for i in n_config {

        let mut r_mpz_vec = unsafe{VectorOfMpz::new()};
        for _j in 0..i{
            let r = rand_mpz_encrypt_bound();
            let ref_r_mpz: Ref<Mpz> = unsafe {Ref::from_raw_ref(&r)};
            unsafe{r_mpz_vec.push_back(ref_r_mpz)};
        }
        let ref_r_mpz_vec: Ref<VectorOfMpz> = unsafe {Ref::from_raw_ref(&r_mpz_vec)};

        let mut rand_qfi_vec = unsafe{VectorOfQFI::new()};
        for _j in 0..i{
            let rand_qfi = rand_qfi();
            let ref_rand_qfi : Ref<QFI> = unsafe {Ref::from_raw_ref(&rand_qfi)};
            unsafe{rand_qfi_vec.push_back(ref_rand_qfi)};
        }
        let ref_rand_qfi_vec : Ref<VectorOfQFI> = unsafe {Ref::from_raw_ref(&rand_qfi_vec)};

        let mut result_qfi = unsafe{QFI::new_0a()};
        let mutref_result_qfi: MutRef<QFI> = unsafe {MutRef::from_raw_ref(&mut result_qfi)};
        group.bench_with_input(BenchmarkId::new("Multi-Exponentiation in Unknown Order Group", format!("n: {}", i)), &i, |b, _cfg| {
            b.iter(|| {
                unsafe{ cl.cl_g().mult_exp(mutref_result_qfi, ref_rand_qfi_vec, ref_r_mpz_vec)};
                black_box(&mutref_result);
            });
        });
    }

    let mut rng_cpp = get_rng();
    for i in n_config {

        let mut sks = Vec::new();
        let mut pks = Vec::new();
        for _j in 0..i{
            let(sk,pk) = keygen(&cl, &mut rng_cpp);
            sks.push(sk);
            pks.push(pk);
        }

        let msgs: Vec<_> = (0..i)
            .map(|_| rand_mpz_cleartext_bound())
            .collect();

        group.bench_with_input(BenchmarkId::new("Multi-receiver encryption", format!("n: {}", i)), &i, |b, _cfg| {
            b.iter(|| {
                let (cc, r) = encrypt_all(&cl, &mut rng_cpp, &pks, &msgs);
                black_box(&cc);
                black_box(&r);
            });
        });
    }
    
    let(sk,pk) = keygen(&cl, &mut rng_cpp);
    let msg = rand_mpz_cleartext_bound();
    let mut pks = Vec::new();
    pks.push(pk);

    let mut msgs = Vec::new();
    msgs.push(msg);

    let (cc, _r) = encrypt_all(&cl, &mut rng_cpp, &pks, &msgs);
    group.bench_with_input(BenchmarkId::new("Decryption ", "Single".to_string()), &cl, |b, _cfg| {
        b.iter(|| {
            let m = decrypt(&cl, &sk, &cc[0]);
            black_box(&m);
        });
    });
    
    group.finish();
}

criterion_group!(benches, benchmark_cg);
criterion_main!(benches);