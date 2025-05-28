use bicycl::b_i_c_y_c_l::{Mpz, RandGen};
use bicycl::b_i_c_y_c_l::utils::{CLHSMSecretKeyOfCLHSMqk as SecretKey, CLHSMPublicKeyOfCLHSMqk as PublicKey, CLHSMClearTextOfCLHSMqk as ClearText, CLHSMCipherTextOfCLHSMqk as CipherText};
use bicycl::b_i_c_y_c_l::CLHSMqk;
use bicycl::{cpp_core, CiphertextBox, MpzBox, PublicKeyBox, SecretKeyBox, VectorOfCLHSMClearTextOfCLHSMqk, VectorOfCLHSMPublicKeyOfCLHSMqk};
use bicycl::__ffi;
use bicycl::cpp_core::{CppBox, Ref};

pub fn encrypt_all(c: &CppBox<CLHSMqk>, rng_cpp: &mut CppBox<RandGen>, pks: &Vec<PublicKeyBox>, evaluations: &Vec<CppBox<Mpz>>) -> (Vec<CiphertextBox>, MpzBox) {

    let ref_c: cpp_core::Ref<CLHSMqk> = unsafe {cpp_core::Ref::from_raw_ref(c)};

    let mut pks_cpp = unsafe { VectorOfCLHSMPublicKeyOfCLHSMqk::new() };
    for pk in pks {
        let ref_pk: cpp_core::Ref<PublicKey> = unsafe {cpp_core::Ref::from_raw_ref(&pk.0)};
        unsafe { pks_cpp.push_back(ref_pk) };
    }

    let mut evals_cleartext = unsafe { VectorOfCLHSMClearTextOfCLHSMqk::new() };
    for i in 0..evaluations.len(){
        let cleartext = unsafe { ClearText::from_c_l_h_s_mqk_mpz(ref_c, &evaluations[i]) };
        unsafe { evals_cleartext.push_back(&cleartext) };
    }

    let ref_pks_cpp: cpp_core::Ref<VectorOfCLHSMPublicKeyOfCLHSMqk> = unsafe {cpp_core::Ref::from_raw_ref(&pks_cpp)};
    let ref_cleartext_cpp: cpp_core::Ref<VectorOfCLHSMClearTextOfCLHSMqk> = unsafe {cpp_core::Ref::from_raw_ref(&evals_cleartext)};
    let r = unsafe { Mpz::new_copy(&rng_cpp.random_mpz(c.encrypt_randomness_bound())) };

    let ciphers = unsafe { c.encrypt_all_3a(ref_pks_cpp, ref_cleartext_cpp, &r) };

    let mut ciphers_rust = Vec::new();
    for i in 0..unsafe{ciphers.size()}{

        let ffi_result = unsafe{__ffi::ctr_bicycl_ffi_BICYCL__Utils_CL_HSM_CipherText_BICYCL_CL_HSMqk_CL_HSM_CipherText7(cpp_core::CastInto::<Ref<bicycl::b_i_c_y_c_l::utils::CLHSMCipherTextOfCLHSMqk>>::cast_into(ciphers.at(i)).as_raw_ptr())};
        let cpp_cipher = unsafe{cpp_core::CppBox::from_raw(ffi_result)}.expect("attempted to construct a null CppBox");
         ciphers_rust.push(CiphertextBox(cpp_cipher));
    }

    (ciphers_rust,MpzBox(r))
}

pub fn decrypt(c: &cpp_core::CppBox<CLHSMqk>, sk: &SecretKeyBox, cipher: &CiphertextBox) -> MpzBox {

    let ref_sk: cpp_core::Ref<SecretKey> = unsafe {cpp_core::Ref::from_raw_ref(&sk.0)};
    let ref_cipher: cpp_core::Ref<CipherText> = unsafe {cpp_core::Ref::from_raw_ref(&cipher.0)};
    let mut cleartext = unsafe{ c.decrypt(ref_sk, ref_cipher)};
    let cleartext_mpz = unsafe{cleartext.get_mpz()};
    return MpzBox(cleartext_mpz);
}

pub fn keygen(c: &cpp_core::CppBox<CLHSMqk>, rng: &mut CppBox<RandGen>) -> (SecretKeyBox, PublicKeyBox) {

    let mutref_rng: cpp_core::MutRef<RandGen> = unsafe {cpp_core::MutRef::from_raw_ref(rng)};
    let sk = unsafe{ c.keygen_rand_gen(mutref_rng)};
    let pk = unsafe{ c.keygen_c_l_h_s_m_secret_key_of_c_l_h_s_mqk(&sk)};
    
    (SecretKeyBox(sk), PublicKeyBox(pk))
}