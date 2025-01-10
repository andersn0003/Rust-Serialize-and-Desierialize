
use axum::{
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use crate::{
    schema::ZkpSignUpSchema,
    zkpgenerate::{zkpproof_sign_in, zkpproof_sign_up},
};

use bellman::groth16::{Proof, VerifyingKey};
use bls12_381::{Bls12, Scalar, G1Affine, G2Affine};

pub use borsh::{BorshDeserialize, BorshSerialize};

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct ScalarWrapper([u8; 32]);

impl From<Scalar> for ScalarWrapper {
    fn from(scalar: Scalar) -> Self {
        ScalarWrapper(scalar.to_bytes())
    }
}

impl Into<Scalar> for ScalarWrapper {
    fn into(self) -> Scalar {
        Scalar::from_bytes(&self.0).unwrap()
    }
}

use crate::sol_connect::{user_sign_up, user_sign_in};

pub async fn zkp_signup(
    Json(body): Json<ZkpSignUpSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let embeddinghash_num = hash_to_array(&body.embedding_hash);
    let embeddinghash_num_arr = embeddinghash_num.unwrap();
    let microchipid_num_arr = body.microchip_id.to_be_bytes();
    let public_input = zkpproof_sign_up(embeddinghash_num_arr, microchipid_num_arr);
    println!("Public Input : {:?}", public_input);
    let public_input_to_send = vec![ScalarWrapper::from(public_input[0]), ScalarWrapper::from(public_input[1])];
    println!("Public Input to send : {:?}", public_input_to_send);
    user_sign_up(public_input_to_send);
    Ok({})
}

pub async fn zkp_signin(
    Json(body): Json<ZkpSignUpSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let embeddinghash_num = hash_to_array(&body.embedding_hash);
    let embeddinghash_num_arr = embeddinghash_num.unwrap();
    let microchipid_num_arr = body.microchip_id.to_be_bytes();
    let (proof, vk) = zkpproof_sign_in(embeddinghash_num_arr, microchipid_num_arr);
    println!("Proof: {:?}", proof);
    let proof_bytes = serialize_proof(&proof);
    let vk_to_send = serialize_verifying_key(&vk);
    user_sign_in(proof_bytes, vk_to_send);

    let zkp_response = serde_json::json!({"status": "success","data": serde_json::json!({
        "zkp": "Proof generated successfuly!"
    })});

    return Ok(Json(zkp_response));
}

fn hash_to_array(hash: &str) -> Result<[u8; 64], String> {
    if hash.len() != 64 {
        return Err(format!("Expected 64 characters, got {}", hash.len()));
    }

    let mut result = [0u8; 64];
    for (i, chunk) in hash.as_bytes().chunks(2).enumerate() {
        let hash_str = std::str::from_utf8(chunk).map_err(|_| "Invalid UTF-8 in hash")?;
        result[i] = u8::from_str_radix(hash_str, 16).map_err(|_| "Invalid hash digit")?;
    }
    Ok(result)
}

fn serialize_g1(element: &G1Affine) -> [u8; 48] {
    element.to_compressed()
}

fn serialize_g2(element: &G2Affine) -> [u8; 96] {
    element.to_compressed()
}

// Serialize the ZKP
fn serialize_proof(proof: &Proof<Bls12>) -> Vec<u8> {
    let mut serialized = Vec::new();
    serialized.extend_from_slice(&serialize_g1(&proof.a));
    serialized.extend_from_slice(&serialize_g2(&proof.b));
    serialized.extend_from_slice(&serialize_g1(&proof.c));
    serialized
}


// Serialize the VerifyingKey
fn serialize_verifying_key(vk: &VerifyingKey<Bls12>) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(serialize_g1(&vk.alpha_g1));
    bytes.extend(serialize_g1(&vk.beta_g1)); 
    bytes.extend(serialize_g2(&vk.beta_g2));   
    bytes.extend(serialize_g2(&vk.gamma_g2));
    bytes.extend(serialize_g1(&vk.delta_g1));  
    bytes.extend(serialize_g2(&vk.delta_g2));  
    for ic in &vk.ic {
        bytes.extend(serialize_g1(ic));       
    }
    bytes
}



// fn deserialize_g1(bytes: &[u8]) -> G1Affine{


//     // Convert slice to a fixed-size array
//     let fixed_bytes: [u8; 48] = bytes.try_into().unwrap();

//     // Deserialize the compressed G1Affine point
//     return G1Affine::from_compressed(&fixed_bytes).unwrap();
// }

// fn deserialize_g2(bytes: &[u8]) -> G2Affine {
//     // Convert slice to a fixed-size array
//     let fixed_bytes: [u8; 96] = bytes.try_into().unwrap();

//     // Deserialize the compressed G1Affine point
//     return G2Affine::from_compressed(&fixed_bytes).unwrap();
// }

// fn deserialize_proof(bytes: &[u8]) -> Proof<Bls12> {
//     assert_eq!(bytes.len(), 192, "Invalid proof length");

//     let a_bytes = &bytes[..48];
//     let b_bytes = &bytes[48..144];
//     let c_bytes = &bytes[144..];

//     let a = deserialize_g1(a_bytes);
//     let b = deserialize_g2(b_bytes);
//     let c = deserialize_g1(c_bytes);

//     Proof { a, b, c }
// }

// fn deserialize_verifying_key(data: &[u8]) -> Option<VerifyingKey<Bls12>> {
//     if data.len() < 48 * 3 + 96 * 3 {
//         return None;
//     }

//     let alpha_g1_bytes = &data[..48];
//     let beta_g1_bytes = &data[48..96];
//     let beta_g2_bytes = &data[96..192];
//     let gamma_g2_bytes = &data[192..288];
//     let delta_g1_bytes = &data[288..336];
//     let delta_g2_bytes = &data[336..432];

//     println!("Alpha G1 bytes: {:?}", alpha_g1_bytes);
//     println!("Beta G1 bytes: {:?}", beta_g1_bytes);
//     println!("Beta G2 bytes: {:?}", beta_g2_bytes);
//     println!("Gamma G2 bytes: {:?}", gamma_g2_bytes);
//     println!("Delta G1 bytes: {:?}", delta_g1_bytes);
//     println!("Delta G2 bytes: {:?}", delta_g2_bytes);

//     let alpha_g1 = deserialize_g1(alpha_g1_bytes);
//     println!("Alpha G1: {:?}", alpha_g1);
//     let beta_g1 = deserialize_g1(beta_g1_bytes);
//     println!("Beta G1: {:?}", beta_g1);
//     let beta_g2 = deserialize_g2(beta_g2_bytes);
//     println!("Beta G2: {:?}", beta_g2);
//     let gamma_g2 = deserialize_g2(gamma_g2_bytes);
//     println!("Gamma G2: {:?}", gamma_g2);
//     let delta_g1 = deserialize_g1(delta_g1_bytes);
//     println!("Delta G1: {:?}", delta_g1);
//     let delta_g2 = deserialize_g2(delta_g2_bytes);
//     println!("Delta G2: {:?}", delta_g2);

//     let ic_data = &data[432..];
//     let ic_count = ic_data.len() / 48;
//     let mut ic = Vec::new();
//     for i in 0..ic_count {
//         let ic_bytes: [u8; 48] = ic_data[i * 48..(i + 1) * 48].try_into().ok()?;
//         let ic_point = deserialize_g1(&ic_bytes);
//         ic.push(ic_point);
//     }

//     Some(VerifyingKey {
//         alpha_g1,
//         beta_g1,
//         beta_g2,
//         gamma_g2,
//         delta_g1,
//         delta_g2,
//         ic,
//     })
// }


// pub fn user_sign_in(proof_bytes: Vec<u8>, vk_bytes: Vec<u8>, public_input_bytes: Vec<ScalarWrapper>) {
//     print!("Begin user_sign_in instruction");

//     println!("Proof bytes length: {}", proof_bytes.len());
//     println!("VK bytes length: {}", vk_bytes.len());

//     let proof = deserialize_proof(&proof_bytes);
//     println!("proof===========> {:?}", proof);
//     let vk = deserialize_verifying_key(&vk_bytes).unwrap();
    
//     let pvk = prepare_verifying_key(&vk);

//     let public_input = vec![
//         public_input_bytes[0].clone().into(),
//         public_input_bytes[1].clone().into(),
//     ];
//     println!("proof===========> {:?}", public_input);
//     print!("Verifying proof...");
//     let result = verify_proof(&pvk, &proof, &public_input);
//     println!("Proof verification result: {}", result.is_ok());

// }