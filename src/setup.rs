use ark_ec::{pairing::Pairing, CurveGroup};
use ark_serialize::CanonicalSerialize;
use ark_std::{
  rand::{rngs::StdRng, RngCore, SeedableRng},
  UniformRand,
};
use legogroth16::{
  circom::CircomCircuit, generate_random_parameters_incl_cp_link, LinkPublicGenerators, ProvingKey,
  ProvingKeyWithLink,
};
use std::fs::write;

use crate::tool::{abs_path, save_generator_as_json, save_verify_key_as_json};

pub fn get_link_public_gens<R: RngCore, E: Pairing>(
  rng: &mut R,
  count: usize,
) -> LinkPublicGenerators<E> {
  let pedersen_gens = (0..count)
    .map(|_| E::G1::rand(rng).into_affine())
    .collect::<Vec<_>>();
  let g1 = E::G1::rand(rng).into_affine();
  let g2 = E::G2::rand(rng).into_affine();
  LinkPublicGenerators {
    pedersen_gens,
    g1,
    g2,
  }
}

pub fn gen_params<E: Pairing>(
  commit_witness_count: usize,
  circuit: CircomCircuit<E>,
  seed: u32,
) -> (ProvingKeyWithLink<E>, ProvingKey<E>) {
  let mut rng = StdRng::seed_from_u64(seed.into());
  let link_gens = get_link_public_gens(&mut rng, commit_witness_count + 1);
  let params_link = generate_random_parameters_incl_cp_link::<E, _, _>(
    circuit.clone(),
    link_gens.clone(),
    commit_witness_count,
    &mut rng,
  )
  .unwrap();
  // Parameters for generating proof without CP_link
  let params = circuit
    .generate_proving_key(commit_witness_count, &mut rng)
    .unwrap();
  (params_link, params)
}

pub fn get_params<E: Pairing>(r1cs_file_path: &str, seed: u32) {
  // 파일로 부터 circuit 구성
  let circuit = CircomCircuit::<E>::from_r1cs_file(abs_path(r1cs_file_path)).unwrap();

  // params 구성
  let (_, params) = gen_params::<E>(1, circuit.clone(), seed);

  let mut compressed_bytes: Vec<u8> = Vec::new();
  params.serialize_compressed(&mut compressed_bytes).unwrap();
  write(abs_path("./proof_file/params.bin"), &compressed_bytes).unwrap();

  compressed_bytes.clear();

  params
    .vk
    .serialize_compressed(&mut compressed_bytes)
    .unwrap();

  write(abs_path("./proof_file/verify_key.bin"), &compressed_bytes).unwrap();

  assert_eq!(save_verify_key_as_json((params.vk).clone()).is_ok(), true);
  assert_eq!(save_generator_as_json((params.vk).clone()).is_ok(), true);
}
