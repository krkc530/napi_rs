use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::fields::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::AddAssign, ops::Neg, UniformRand, Zero};
use json_writer::JSONObjectWriter;
use legogroth16::{Proof, VerifyingKey};
use std::collections::hash_map::DefaultHasher;
use std::fs::File;
use std::fs::{read, write};
use std::hash::Hasher;
use std::io::{Error, Write};
use std::path::PathBuf;

pub fn get_sum_of_value_pedersen_cm<E: Pairing>(name_list: Vec<String>) {
  let list_size = name_list.len();

  let mut sum_w: <E as Pairing>::ScalarField = <E as Pairing>::ScalarField::zero();
  let mut sum_v: <E as Pairing>::ScalarField = <E as Pairing>::ScalarField::zero();
  let mut cm_key: CMKey<E>;

  let mut result: <E as Pairing>::G1Affine = AffineRepr::zero();
  let mut cm_path = String::new();
  let mut cm_key_path = String::new();

  let mut index = 0;
  let mut tmp_cm_vec: Vec<u8>;
  let mut tmp_cm: <E as Pairing>::G1Affine;

  while index < list_size {
    // println!("{:?}", result);
    // read Ped_cm for get total sum cm
    cm_path.push_str("./proof_file/CM_");
    cm_path.push_str(name_list[index].as_str());
    cm_path.push_str(".bin");

    tmp_cm_vec = read(abs_path(cm_path.as_str())).unwrap();
    tmp_cm = <E as Pairing>::G1Affine::deserialize_compressed(&*tmp_cm_vec).unwrap();

    // rad Ped_cm Key for update total sum cm_key
    cm_key_path.push_str("./proof_file/CM_key_");
    cm_key_path.push_str(name_list[index].as_str());
    cm_key_path.push_str(".bin");
    let tmp_cm_key: Vec<u8> = read(abs_path(cm_key_path.as_str())).unwrap();
    cm_key = CMKey::<E>::deserialize_compressed(&*tmp_cm_key).unwrap();

    sum_v.add_assign(cm_key.v);
    sum_w.add_assign(cm_key.w);

    result = add_cm::<E>(result, tmp_cm);

    cm_path.clear();
    cm_key_path.clear();

    if index == list_size - 1 {
      cm_key.w = sum_w;
      cm_key.v = sum_v;
      // save update cm_key as bin and json
      let mut key_data: Vec<u8> = Vec::new();
      cm_key.serialize_compressed(&mut key_data).unwrap();
      write(abs_path("./proof_file/CM_total_key.bin"), &key_data).unwrap();

      let mut object_str = String::new();
      let mut object_writer = JSONObjectWriter::new(&mut object_str);
      object_writer.value("gamma_abc_g1", cm_key.gamma_abc_g1.to_string().as_str());
      object_writer.value(
        "eta_gamma_inv_g1",
        cm_key.eta_gamma_inv_g1.to_string().as_str(),
      );
      object_writer.value("w", sum_w.to_string().as_str());
      object_writer.value("v", sum_v.to_string().as_str());

      object_writer.end();

      let mut file = File::create(abs_path("./json/Ped_cm/CM_Key_total.json")).expect("ERR");
      let _ = file.write_all(object_str.as_bytes());
    }
    index = index + 1;
  }

  // save result Ped cm data in file as bin and json
  let mut result_data: Vec<u8> = Vec::new();
  result.serialize_compressed(&mut result_data).unwrap();
  let mut save_ped_path = String::new();
  save_ped_path.push_str("./proof_file/CM_total.bin");
  write(abs_path(save_ped_path.as_str()), &result_data).unwrap();

  let mut object_str = String::new();
  let mut object_writer = JSONObjectWriter::new(&mut object_str);
  object_writer.value("cm", result.to_string().as_str());
  object_writer.end();

  let mut file = File::create(abs_path("./json/Ped_cm/CM_total.json")).expect("ERR");
  let _ = file.write_all(object_str.as_bytes());
}

pub fn add_cm<E: Pairing>(a: E::G1Affine, b: E::G1Affine) -> E::G1Affine {
  (a + b).into()
}

pub fn inv<E: Pairing>(point: <E as Pairing>::G2Affine) -> <E as Pairing>::G2Affine {
  let answer = point.into_group().neg().into_affine();
  answer
}

pub fn save_verify_key_as_json<E: Pairing>(vk: VerifyingKey<E>) -> Result<(), Error> {
  let mut object_str = String::new();

  let mut object_writer = JSONObjectWriter::new(&mut object_str);
  object_writer.value("alpha_g1", (vk.alpha_g1).to_string().as_str());
  object_writer.value("beta_g2", (inv::<E>(vk.beta_g2)).to_string().as_str());
  object_writer.value("delta_g2", (inv::<E>(vk.delta_g2)).to_string().as_str());
  object_writer.value("gamma_abc_g1", (vk.gamma_abc_g1[0]).to_string().as_str());
  object_writer.value("gamma_g2", (inv::<E>(vk.gamma_g2)).to_string().as_str());
  object_writer.value("commit_witness_count", 1);
  object_writer.end();

  let mut file = File::create(abs_path("./json/Proof_vk/VK.json"))?;
  file.write_all(object_str.as_bytes())
}

pub fn save_proof_as_json<E: Pairing>(proof: Proof<E>, name: &str) -> Result<(), Error> {
  let mut object_str = String::new();

  let mut object_writer = JSONObjectWriter::new(&mut object_str);
  object_writer.value("a_g1", (proof.a).to_string().as_str());
  object_writer.value("b_g2", (proof.b).to_string().as_str());
  object_writer.value("c_g1", (proof.c).to_string().as_str());
  object_writer.value("d_g1", (proof.d).to_string().as_str());
  object_writer.end();

  let mut proof_path = String::new();
  proof_path.push_str("./json/Proof_vk/proof_");
  proof_path.push_str(name);
  proof_path.push_str(".json");

  let mut file = File::create(abs_path(proof_path.as_str()))?;
  file.write_all(object_str.as_bytes())
}

pub fn save_cm_as_json<E: Pairing>(proof: Proof<E>, name: &str) -> Result<(), Error> {
  let mut object_str = String::new();

  let mut object_writer = JSONObjectWriter::new(&mut object_str);
  object_writer.value("cm", (proof.d).to_string().as_str());

  object_writer.end();

  let mut save_ped_path = String::new();
  save_ped_path.push_str("./json/Ped_cm/CM_");
  save_ped_path.push_str(name);
  save_ped_path.push_str(".json");

  let mut file = File::create(abs_path(save_ped_path.as_str()))?;
  file.write_all(object_str.as_bytes())
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct CMKey<E: Pairing> {
  pub gamma_abc_g1: <E as Pairing>::G1Affine,
  pub eta_gamma_inv_g1: <E as Pairing>::G1Affine,
  pub w: <E as Pairing>::ScalarField,
  pub v: <E as Pairing>::ScalarField,
}

pub fn save_cm_key<E: Pairing>(
  vk: &VerifyingKey<E>,
  _public_inputs_count: usize,
  witnesses_expected_in_commitment: &[E::ScalarField],
  v: &E::ScalarField,
  name: &str,
) -> Result<(), Error> {
  // save as bin file (compressed)
  let cm_vk: Vec<<E as Pairing>::G1Affine> = vk.get_commitment_key_for_witnesses();

  let cm_struct = CMKey::<E> {
    gamma_abc_g1: cm_vk[0],
    eta_gamma_inv_g1: cm_vk[1],
    w: witnesses_expected_in_commitment[0],
    v: *v,
  };

  let mut compressed: Vec<u8> = Vec::new();
  cm_struct.serialize_compressed(&mut compressed).unwrap();

  let mut vk_path = String::new();
  vk_path.push_str("./proof_file/CM_key_");
  vk_path.push_str(name);
  vk_path.push_str(".bin");

  // let mut compressed_bytes: Vec<u8> = Vec::new();
  // cm_vk.serialize_compressed(&mut compressed_bytes).unwrap();
  write(abs_path(vk_path.as_str()), &compressed).unwrap();

  // save as json file

  let mut object_str = String::new();
  let mut object_writer = JSONObjectWriter::new(&mut object_str);

  object_writer.value("gamma_abc_g1", (cm_vk[0]).to_string().as_str());
  object_writer.value("eta_gamma_inv_g1", (cm_vk[1]).to_string().as_str());

  object_writer.value(
    "w",
    witnesses_expected_in_commitment[0].to_string().as_str(),
  );
  object_writer.value("v", v.to_string().as_str());

  object_writer.end();

  let mut save_ped_path = String::new();
  save_ped_path.push_str("./json/Ped_cm/CM_key_");
  save_ped_path.push_str(name);
  save_ped_path.push_str(".json");

  let mut file = File::create(abs_path(save_ped_path.as_str()))?;
  file.write_all(object_str.as_bytes())
}

pub fn verify_cm<E: Pairing>(
  gamma_abc_g1: Vec<E::G1Affine>,
  eta_gamma_inv_g1: E::G1Affine,
  w: E::ScalarField,
  v: E::ScalarField,
  cm: E::G1Affine,
) -> Result<(), Error> {
  // let committed = cfg_iter!(w).map(|p| p.into_bigint()).collect::<Vec<_>>();
  let committed = w.into_bigint();

  // Check that proof.d is correctly constructed.
  let mut d = E::G1::msm_bigint(&gamma_abc_g1, &[committed]);
  d.add_assign(eta_gamma_inv_g1.mul_bigint(v.into_bigint()));

  // println!("\n{:?}\n", d.into_affine());

  if cm != d.into_affine() {
    println!("verify failed");
  } else {
    println!("verify success");
  }

  Ok(())
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct SigmaProof<E: Pairing> {
  pub t: E::G1Affine,
  pub s: E::ScalarField,
}

pub fn sigma_protocol<E: Pairing>(cm: E::G1Affine) -> Result<(), Error> {
  let cm_key_data: Vec<u8> = read(abs_path("./proof_file/CM_Key_total.bin")).unwrap();
  let cm_key: CMKey<E> = CMKey::deserialize_compressed(&*cm_key_data).unwrap();

  let g: E::G1Affine = cm_key.gamma_abc_g1;
  let h: E::G1Affine = cm_key.eta_gamma_inv_g1;
  let v: E::ScalarField = cm_key.v;
  let r: E::ScalarField = cm_key.w;

  let g_v: E::G1Affine = (g * v).into();

  // y = cm * (g^v(^-1)) = h^r
  // prove y = h^r
  let y: E::G1Affine = (cm + g_v.into_group().neg().into_affine()).into();

  // random
  let random: E::ScalarField = UniformRand::rand(&mut ark_std::test_rng());

  // t = h^random
  let t: E::G1Affine = (h * random).into();

  // c = Hash(h,y,t)

  let hasher = DefaultHasher::new();

  let mut h_data: Vec<u8> = Vec::new();
  h.serialize_uncompressed(&mut h_data).unwrap();
  let mut y_data: Vec<u8> = Vec::new();
  y.serialize_uncompressed(&mut y_data).unwrap();
  let mut t_data: Vec<u8> = Vec::new();
  t.serialize_uncompressed(&mut t_data).unwrap();

  let mut input = Vec::new();
  input.extend(h_data);
  input.extend(y_data);
  input.extend(t_data);

  let c = hasher.finish();

  // s = random + c * r;

  //BigInt::from(c).into_bigint()
  let tmp = E::ScalarField::from_be_bytes_mod_order(&(c.to_le_bytes()));

  let s: E::ScalarField = random + tmp * r;

  // save proof (t,s) as json

  let mut object_str = String::new();
  let mut object_writer = JSONObjectWriter::new(&mut object_str);

  object_writer.value("t", t.to_string().as_str());
  object_writer.value("s", s.to_string().as_str());

  object_writer.end();

  let mut file = File::create("./json/Ped_cm/Sigma_proof.json")?;
  file.write_all(object_str.as_bytes())
}

pub fn abs_path(relative_path: &str) -> String {
  let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  path.push(relative_path);
  path.to_string_lossy().to_string()
}

// let mut h_data: Vec<u8> = Vec::new();
// h.serialize_uncompressed(&mut h_data).unwrap();
// let mut y_data: Vec<u8> = Vec::new();
// y.serialize_uncompressed(&mut y_data).unwrap();
// let mut t_data: Vec<u8> = Vec::new();
// t.serialize_uncompressed(&mut t_data).unwrap();

// let mut input = Vec::new();
// input.extend(h_data);
// input.extend(y_data);
// input.extend(t_data);
