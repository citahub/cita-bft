// CITA
// Copyright 2016-2017 Cryptape Technologies LLC.

// This program is free software: you can redistribute it
// and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any
// later version.

// This program is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
// PURPOSE. See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::convert::{From, Into};

use bincode::{serialize, Infinite};
use crate::types::{H256, Address};
use crate::core::params::PrivateKey;
use crypto::{pubkey_to_address, Signature, Sign, SIGNATURE_BYTES_LEN, Signer};
use pubsub::channel::{Receiver, Sender};
use proof::BftProof;
use bft::{BftMsg, BftSupport, Commit, Signature as BftSig, Address as BftAddr, Status, Node, Proof};
use hashable::Hashable;
use libproto::blockchain::{Block, Proof as ProtoProof, ProofType};
use libproto::router::{MsgType, RoutingKey, SubModules};
use libproto::{TryFrom, TryInto, Message, auth};
use std::collections::HashMap;

use engine::{unix_now, AsMillis};

pub type PubType = (String, Vec<u8>);

#[derive(Clone)]
pub struct BftBridge {
    rab_sender: Sender<PubType>,
    bft_sender: Sender<BftMsg>,
    feed_receiver: Receiver<PubType>,
    resp_receiver: Receiver<PubType>,
    stat_receiver: Receiver<PubType>,

    signer: PrivateKey,
    address: BftAddr,

    proof: HashMap<u64, Proof>,
    pre_hash: HashMap<u64, H256>,
    version:  HashMap<u64, u32>,

    is_snapshot: bool,
    is_cleared: bool,
}



impl BftBridge{
    pub fn new(rab_sender: Sender<PubType>,
               bft_sender: Sender<BftMsg>,
               feed_receiver: Receiver<PubType>,
               resp_receiver: Receiver<PubType>,
               stat_receiver: Receiver<PubType>,
               pk: PrivateKey) -> Self{
        let signer = Signer::from(pk.signer.clone());
        let address = signer.address.to_vec();
        BftBridge{
            rab_sender,
            bft_sender,
            feed_receiver,
            resp_receiver,
            stat_receiver,
            signer: pk,
            address,
            proof: HashMap::new(),
            pre_hash: HashMap::new(),
            version: HashMap::new(),
            is_snapshot: false,
            is_cleared: false,
        }
    }

    fn extract_status(&mut self, body: &[u8]) -> Status{
        let mut msg = Message::try_from(body).unwrap();
        let status = msg.take_rich_status().unwrap();
        let height = status.height;

        let pre_hash = H256::from_slice(&status.hash);
        self.pre_hash.entry(height).or_insert(pre_hash);
        self.version.entry(height).or_insert(status.version);

        let mut map = HashMap::new();
        status.get_nodes().iter().for_each(|node| {
            let counter = map.entry(node.to_vec()).or_insert(0u32);
            *counter += 1;
        });

        let authority_list: Vec<Node> = map.into_iter().map(|(node, n)|{
            Node{
                address: node,
                proposal_weight: n,
                vote_weight: 1,
            }
        }).collect();

        Status{
            height,
            interval: Some(status.interval),
            authority_list,
        }
    }
}

impl BftSupport for BftBridge {

    fn start(&mut self){
        loop{
            let (_, body) = self.stat_receiver.recv().unwrap();
            let status = self.extract_status(&body[..]);
            self.bft_sender.send(BftMsg::Status(status)).unwrap();
        }
    }

    fn check_block(&self, _block: &[u8], _height: u64) -> bool{
        true
    }
    /// A function to check signature.
    fn check_transaction(&mut self, block: &[u8], height: u64, round: u64) -> bool{
        let mut msg = Message::try_from(block).unwrap();
        let compact_block = msg.take_compact_block().unwrap();
        let mut verify_req = auth::VerifyBlockReq::new();
        verify_req.set_height(height);
        verify_req.set_round(round);
        verify_req.set_block(compact_block);
        let msg: Message = verify_req.into();
//        msg.set_origin(csp_msg.get_origin());   明天问下博宇这个参数是干什么的?
        self.rab_sender
            .send((
                routing_key!(Consensus >> VerifyBlockReq).into(),
                msg.clone().try_into().unwrap(),
            ))
            .unwrap();

        false
    }
    /// A funciton to transmit messages.
    fn transmit(&self, msg: BftMsg){
        match msg{
            BftMsg::Proposal(encode) => {
                self.rab_sender
                    .send((
                        routing_key!(Consensus >> CompactSignedProposal).into(),
                        encode,
                    ))
                    .unwrap();
            }

            BftMsg::Vote(encode) => {
                self.rab_sender
                    .send((
                        routing_key!(Consensus >> RawBytes).into(),
                        encode,
                    ))
                    .unwrap();
            }

            _ => warn!("transmit wrong msg type!"),
        }
    }
    /// A function to commit the proposal.
    fn commit(&mut self, _commit: Commit){


    }

    fn get_block(&self, height: u64) -> Option<Vec<u8>>{
        loop{
            let (_, body) = self.feed_receiver.recv().unwrap();
            let mut msg = Message::try_from(&body[..]).unwrap();
            let mut block_txs = msg.take_block_txs().unwrap();

            if height == block_txs.get_height() {
                let version = self.version.get(&height);
                let pre_hash = self.pre_hash.get(&height);
                let proof = self.proof.get(&height);
                if version.is_none() || pre_hash.is_none() || proof.is_none(){
                    return None;
                }
                let mut block = Block::new();
                block.set_version(*version.unwrap());
                block.set_body(block_txs.take_body().clone());
                block.mut_header().set_prevhash(pre_hash.unwrap().0.to_vec());
                let bft_proof = to_bft_proof(proof.unwrap());
                block.mut_header().set_proof(bft_proof);
                let block_time = unix_now();
                block.mut_header().set_timestamp(AsMillis::as_millis(&block_time));
                block.mut_header().set_height(height);
                let transactions_root = block.get_body().transactions_root();
                block.mut_header().set_transactions_root(transactions_root.to_vec());
                block.mut_header().set_proposer(self.address.clone());
                let blk = block.clone().compact().try_into().unwrap();
                return Some(blk);
            } else if height < block_txs.get_height() {
                return None;
            }
        }
    }

    fn sign(&self, hash: &[u8]) -> Option<BftSig>{
        if let Ok(signature) = Signature::sign(&self.signer.signer, &H256::from(hash)){
            return Some((&signature.0).to_vec());
        }
        None
    }

    fn check_sig(&self, signature: &[u8], hash: &[u8]) -> Option<BftAddr>{
        if signature.len() != SIGNATURE_BYTES_LEN {
            return None;
        }
        let signature = Signature::from(signature);
        if let Ok(pubkey) = signature.recover(&H256::from(hash)) {
            let address = pubkey_to_address(&pubkey);
            return Some(address.to_vec());
        }
        None
    }

    fn crypt_hash(&self, msg: &[u8]) -> Vec<u8>{
        msg.to_vec().crypt_hash().to_vec()
    }
}

fn to_bft_proof(proof: &Proof) -> ProtoProof {
    let commits: HashMap<Address, Signature> = proof.precommit_votes.iter()
        .map(|(addr, sig)|{
            (Address::from(&addr[..]), Signature::from(&sig[..]))
        }).collect();
    let bft_proof = BftProof{
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


#[cfg(test)]
mod test {
    use super::*;
    use bft::{Status, Node};
    use std::collections::HashMap;

    #[test]
    fn test_extract_status() {
        let rich_status = vec![vec![5u8], vec![4u8], vec![4u8], vec![7u8], vec![9u8],
                               vec![9u8], vec![4u8], vec![1u8], vec![9u8], vec![7u8],
                               vec![9u8], vec![8u8], vec![7u8], vec![9u8], vec![9u8],];

        let mut map = HashMap::new();
        rich_status.iter().for_each(|node| {
            let counter = map.entry(node.to_vec()).or_insert(0u32);
            *counter += 1;
        });

        let authority_list: Vec<Node> = map.into_iter().map(|(node, n)|{
            Node{
                address: node,
                proposal_weight: n,
                vote_weight: 1,
            }
        }).collect();

        println!("{:?}", authority_list);
    }
}