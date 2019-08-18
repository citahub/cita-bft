use crate::types::{Address, H256};
use bft::{Address as BftAddr, Proof, Signature as BftSig};
use bincode::{serialize, Infinite};
use crypto::Signature;
use libproto::blockchain::{Proof as ProtoProof, ProofType};
use proof::BftProof;
use std::collections::HashMap;

pub fn to_cita_proof(proof: &Proof) -> ProtoProof {
    let commits: HashMap<Address, Signature> = proof
        .precommit_votes
        .iter()
        .map(|(addr, sig)| (Address::from(&addr[..]), Signature::from(&sig[..])))
        .collect();
    let bft_proof = BftProof {
        proposal: H256::from(&proof.block_hash[..]),
        height: proof.height as usize,
        round: proof.round as usize,
        commits,
    };
    let mut proof = ProtoProof::new();
    let encoded_proof: Vec<u8> = serialize(&bft_proof, Infinite).unwrap();
    proof.set_content(encoded_proof);
    proof.set_field_type(ProofType::Bft);
    proof
}

pub fn to_bft_proof(proof: &BftProof) -> Proof {
    let precommit_votes: HashMap<BftAddr, BftSig> = proof
        .commits
        .iter()
        .map(|(addr, sig)| (addr.to_vec().into(), sig.0.to_vec().into()))
        .collect();
    Proof {
        block_hash: proof.proposal.to_vec().into(),
        height: proof.height as u64,
        round: proof.round as u64,
        precommit_votes,
    }
}
