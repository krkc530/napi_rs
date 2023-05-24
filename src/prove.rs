use crate::tool::{abs_path, save_cm_as_json, save_cm_key, save_proof_as_json};
use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
  rand::{rngs::StdRng, SeedableRng},
  UniformRand,
};

use legogroth16::{
  circom::witness::WitnessCalculator,
  circom::CircomCircuit,
  prover::{create_random_proof, verify_witness_commitment},
  ProvingKey,
};
use std::fs::{read, write};

pub fn make_proof<E: Pairing, I: IntoIterator<Item = (String, Vec<E::ScalarField>)>>(
  inputs: I,
  name: &str,
) {
  let mut circuit =
    CircomCircuit::<E>::from_r1cs_file(abs_path("./circom/bn128/range_proof.r1cs")).unwrap();

  let tmp_params: Vec<u8> = read(abs_path("./proof_file/params.bin")).unwrap();

  let params: ProvingKey<E> = ProvingKey::<E>::deserialize_compressed(&*tmp_params).unwrap();

  let mut wits_calc =
    WitnessCalculator::<E>::from_wasm_file("./circom/bn128/range_proof.wasm").unwrap();
  let all_wires = wits_calc.calculate_witnesses::<I>(inputs, true).unwrap();

  assert_eq!(wits_calc.instance.get_input_count().unwrap(), 1);

  circuit.set_wires(all_wires);

  let cs = ConstraintSystem::<E::ScalarField>::new_ref();
  circuit.clone().generate_constraints(cs.clone()).unwrap();
  assert!(cs.is_satisfied().unwrap());

  let public_inputs = circuit.get_public_inputs().unwrap();
  let committed_witnesses = circuit
    .wires
    .clone()
    .unwrap()
    .into_iter()
    .skip(1 + public_inputs.len())
    .take(1)
    .collect::<Vec<_>>();
  // Randomness for the committed witness in proof.d
  let mut rng = StdRng::seed_from_u64(300u64);
  let v = E::ScalarField::rand(&mut rng);
  let proof = create_random_proof(circuit, v, &params, &mut rng).unwrap();
  // println!("{:?}", proof);
  println!("Proof generated");

  verify_witness_commitment(
    &params.vk,
    &proof,
    public_inputs.len(),
    &committed_witnesses,
    &v,
  )
  .unwrap();

  assert_eq!(
    save_cm_key(
      &params.vk,
      public_inputs.len(),
      &committed_witnesses,
      &v,
      name,
    )
    .is_ok(),
    true
  );

  let mut compressed_bytes: Vec<u8> = Vec::new();
  proof.serialize_compressed(&mut compressed_bytes).unwrap();
  let mut save_path = String::new();
  save_path.push_str("./proof_file/prove_");
  save_path.push_str(name);
  save_path.push_str(".bin");
  write(abs_path(save_path.as_str()), &compressed_bytes).unwrap();

  compressed_bytes.clear();

  (proof.d)
    .serialize_compressed(&mut compressed_bytes)
    .unwrap();
  let mut save_path = String::new();
  save_path.push_str("./proof_file/CM_");
  save_path.push_str(name);
  save_path.push_str(".bin");
  write(abs_path(save_path.as_str()), &compressed_bytes).unwrap();

  assert_eq!(save_proof_as_json::<E>(proof.clone(), name).is_ok(), true);
  assert_eq!(save_cm_as_json::<E>(proof, name).is_ok(), true);
}
