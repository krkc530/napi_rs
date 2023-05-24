#![deny(clippy::all)]
#![allow(dead_code)]

use std::collections::HashMap;

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use napi_derive::napi;
use std::fs::read;

mod prove;
mod setup;
mod tool;
mod verify;

use crate::prove::make_proof;
use crate::setup::get_params;
use crate::tool::{abs_path, get_sum_of_value_pedersen_cm, verify_cm, CM_key};
use crate::verify::verify;

#[napi]
pub fn plus_100(input: u32) -> u32 {
  input + 100
}

fn get_input_rand<E: Pairing>(num: String) -> HashMap<String, Vec<<E as Pairing>::ScalarField>> {
  let _rng = StdRng::seed_from_u64(100);
  let x = E::ScalarField::from(u64::from_str_radix(num.as_str(), 10).unwrap());

  let mut inputs = HashMap::new();
  inputs.insert("value".to_string(), vec![x]);
  inputs
}

#[napi]
fn get_range_proof_params_get_bls12_381() {
  let r1cs_file_path = "./circom/bn128/range_proof.r1cs";
  get_params::<Bn254>(r1cs_file_path)
}

#[napi]
fn get_proof(name: String, value: String) {
  let inputs = get_input_rand::<Bn254>(value);
  make_proof::<Bn254, _>(inputs, name.as_str());
}

#[napi]
fn verify_the_proof(name: String) {
  let result = verify::<Bn254>(name.as_str());
  println!("{:?}", result);
  assert_eq!(result.is_ok(), true)
}

#[napi]
fn get_total_Ped_cm(name_list: Vec<String>) {
  get_sum_of_value_pedersen_cm::<Bn254>(name_list);
}

#[napi]
fn verify_Ped_total_cm() {
  let cm_vec = read(abs_path("./proof_file/CM_total.bin")).unwrap();
  let cm: <Bn254 as Pairing>::G1Affine =
    <Bn254 as Pairing>::G1Affine::deserialize_compressed(&*cm_vec).unwrap();

  let tmp_cm_key: Vec<u8> = read(abs_path("./proof_file/CM_total_key.bin")).unwrap();
  let cm_key: CM_key<Bn254> = CM_key::<Bn254>::deserialize_compressed(&*tmp_cm_key).unwrap();
  // println!("{:?}", cm_key);
  let mut tmp = verify_cm::<Bn254>(
    [cm_key.gamma_abc_g1].to_vec(),
    cm_key.eta_gamma_inv_g1,
    cm_key.w,
    cm_key.v,
    cm,
  );
}
