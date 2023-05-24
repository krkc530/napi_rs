use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalDeserialize;

use crate::tool::{abs_path};
use legogroth16::{
    verifier::{prepare_verifying_key, verify_qap_proof},
    Proof, Result, VerifyingKey,
};
use std::fs::read;

pub fn verify<E: Pairing>(name: &str) -> Result<()> {
    //params 가져오기
    let tmp_params: Vec<u8> = read(abs_path("./proof_file/verify_key.bin")).unwrap();
    let vk = VerifyingKey::<E>::deserialize_compressed(&*tmp_params).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);
    // println!("{:?}", pvk);

    // proof 가져오기
    let mut proof_path = String::new();
    proof_path.push_str("./proof_file/prove_");
    proof_path.push_str(name);
    proof_path.push_str(".bin");

    let tmp_proof: Vec<u8> = read(abs_path(proof_path.as_str())).unwrap();
    let proof = Proof::<E>::deserialize_compressed(&*tmp_proof).unwrap();

    verify_qap_proof(
        &pvk,
        proof.a,
        proof.b,
        proof.c,
        (proof.d + pvk.vk.gamma_abc_g1[0]).into(),
    )
}
