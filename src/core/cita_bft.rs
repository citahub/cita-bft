// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::convert::Into;
use authority_manage::AuthorityManage;
use bincode::{deserialize, serialize, Infinite};

use super::params::BftParams;
use super::voteset::{IndexProposal,Proposal};

use crate::core::votetime::TimeoutInfo;
use crate::core::wal::{LogType, Wal};

use crate::crypto::{pubkey_to_address, CreateKey, Sign, Signature, SIGNATURE_BYTES_LEN};
use engine::{unix_now, AsMillis, EngineError, Mismatch};
use libproto::blockchain::{Block, BlockTxs, BlockWithProof, RichStatus};
use libproto::consensus::{Proposal as ProtoProposal,
    SignedProposal, Vote as ProtoVote,
};

use libproto::router::{MsgType, RoutingKey, SubModules};
use libproto::{auth, Message};
use libproto::{TryFrom, TryInto};
use proof::BftProof;
use pubsub::channel::{Receiver, Sender};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::time::{Duration, Instant};

use crate::types::{Address, H256};
use cita_directories::DataPath;
use hashable::Hashable;
use super::ba::BinaryAgreement;
use super::bool_set::BoolSet;
use super::bool_multimap::BoolMultimap;

const INIT_HEIGHT: usize = 1;
const INIT_ROUND: usize = 0;

const MAX_PROPOSAL_TIME_COEF: usize = 10;

const TIMEOUT_RETRANSE_MULTIPLE: u32 = 15;
const TIMEOUT_LOW_ROUND_MESSAGE_MULTIPLE: u32 = 20;

pub type TransType = (String, Vec<u8>);
pub type PubType = (String, Vec<u8>);

const BVAL_TYPE : u8 = 0x01;
const AUX_TYPE : u8 = 0x02;
const TERM_TYPE : u8 = 0x08;

pub enum BftTurn {
    Message(TransType),
    Timeout(TimeoutInfo),
}

#[derive(Debug, Clone, Copy)]
enum VerifiedBlockStatus {
    Ok,
    Err,
    Init(u8),
}

impl VerifiedBlockStatus {
    pub fn value(self) -> i8 {
        match self {
            VerifiedBlockStatus::Ok => 1,
            VerifiedBlockStatus::Err => -1,
            VerifiedBlockStatus::Init(_) => 0,
        }
    }

    pub fn is_ok(self) -> bool {
        match self {
            VerifiedBlockStatus::Ok => true,
            _ => false,
        }
    }

    pub fn is_init(self) -> bool {
        match self {
            VerifiedBlockStatus::Init(_) => true,
            _ => false,
        }
    }
}

impl From<i8> for VerifiedBlockStatus {
    fn from(s: i8) -> Self {
        match s {
            1 => VerifiedBlockStatus::Ok,
            -1 => VerifiedBlockStatus::Err,
            0 => VerifiedBlockStatus::Init(0),
            _ => panic!("Invalid VerifiedBlockStatus."),
        }
    }
}

pub struct Bft {
    pub_sender: Sender<PubType>,
    timer_seter: Sender<TimeoutInfo>,
    receiver: Receiver<BftTurn>,

    params: BftParams,
    height: usize,

    pre_hash: Option<H256>,

    current_proposals: IndexProposal,
    height_proposals: BTreeMap<usize,IndexProposal>,
    bas :Vec<BinaryAgreement>,
    decides: Vec<Option<bool>>,

    wal_log: Wal,

    htime: Instant,
    auth_manage: AuthorityManage,
    consensus_idx: Option<u32>,
    //params meaning: key :index 0->height,1->round ,value:0->verified msg,1->verified result
    unverified_msg: BTreeMap<(usize, usize), (Message, VerifiedBlockStatus)>,
    // VecDeque might work, Almost always it is better to use Vec or VecDeque instead of LinkedList
    block_txs: VecDeque<(usize, BlockTxs)>,
    block_proof: Option<(usize, BlockWithProof)>,


    // The verified blocks with the bodies of transactions.
    verified_blocks: HashMap<H256, Block>,
    version: Option<u32>,
}

impl ::std::fmt::Debug for Bft {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "Bft {{ \
             h: {},, v: {:?} \
             pre_hash: {:?}, consensus_idx: {:?} \
             }}",
            self.height,
            self.version,
            self.pre_hash,
            self.consensus_idx,
        )
    }
}

impl ::std::fmt::Display for Bft {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "Bft h: {}",
            self.height,
        )
    }
}

impl Bft {
    pub fn new(
        s: Sender<PubType>,
        ts: Sender<TimeoutInfo>,
        r: Receiver<BftTurn>,
        params: BftParams,
    ) -> Bft {
        let proof = BftProof::default();

        let logpath = DataPath::wal_path();
        Bft {
            pub_sender: s,
            timer_seter: ts,
            receiver: r,
            bas: vec!(BinaryAgreement::new();100),
            decides: vec!(None;100),
            params,
            height: 0,
            pre_hash: None,
            wal_log: Wal::create(&*logpath).unwrap(),
            current_proposals: IndexProposal::new(),
            height_proposals: BTreeMap::new(),
            htime: Instant::now(),
            auth_manage: AuthorityManage::new(),
            consensus_idx: None,
            unverified_msg: BTreeMap::new(),
            block_txs: VecDeque::new(),
            block_proof: None,
            verified_blocks: HashMap::new(),
            version: None,
        }
    }

    pub fn get_validator_id(&self,address: &Address) -> Option<u32> {
        if self.auth_manage.validators.is_empty() {
            warn!("There are no authorities");
            return None;
        }

        for i in 0..self.auth_manage.validators.len() {
            if self.auth_manage.validators[i] == *address {
                return Some(i as u32);
            }
        }
        None
    }

    fn add_proposal(&mut self,height :usize,send_id: u32,proposal:Proposal)->bool {
        if height == self.height {
            return self.current_proposals.add_proposal(send_id, proposal);
        } else if height > self.height {
            self.height_proposals.entry(height).or_insert(IndexProposal::new()).add_proposal(send_id, proposal);
        }
        false
    }

    fn handle_proposal(&mut self,body: &[u8],) -> Result<usize, EngineError> {
        let mut csp_msg = if let Ok(csp_msg) = Message::try_from(body) {
            csp_msg
        } else {
            return Err(EngineError::UnexpectedMessage);
        };
        let result = csp_msg.clone().take_signed_proposal();
        if let Some(signed_proposal) = result {
            let signature = {
                let signature = signed_proposal.get_signature();
                if signature.len() != SIGNATURE_BYTES_LEN {
                    return Err(EngineError::InvalidSignature);
                }
                Signature::from(signature)
            };
            let proposal = signed_proposal.get_proposal().clone();
            let hash = {
                let message: Vec<u8> = (&proposal).try_into().unwrap();
                message.crypt_hash()
            };
            trace!("handle_proposal {} message {:?}", self, hash);
            if let Ok(pubkey) = signature.recover(&hash) {
                let height = proposal.get_height() as usize;
                let round = proposal.get_round() as usize;
                if height < self.height
                {
                    debug!("handle_proposal {} get old proposal", self);
                    return Err(EngineError::VoteMsgDelay(height));
                }

                let address = pubkey_to_address(&pubkey);
                trace!(
                    "handle_proposal {} h: {}, r: {}, sender: {:?}",
                    self,
                    height,
                    round,
                    address
                );

                if let Some(idx) = self.get_validator_id(&address) {
                    let block = proposal.clone().take_block();
                    let blk = block.clone().try_into().unwrap();
                    let proposal = Proposal {
                        block: block.try_into().unwrap(),
                        lock_round: None,
                        lock_votes: None,
                    };

                    if self.add_proposal(height,idx , proposal) {

                        // proposal should be sent to auth to verify
                        // multicast bval
                        self.bas[idx as usize].set_input(true);
                        self.send_bval(idx,0,true.into());
                    }
                }

                if height > self.height {
                    return Err(EngineError::VoteMsgForth(height));
                }
                return Ok(height);
            }
        }
        Err(EngineError::UnexpectedMessage)
    }

    fn send_bval(&mut self,idx:u32,round:usize,bval : BoolSet ) {
        self.pub_and_broadcast_message(self.height as u64,idx,round,BVAL_TYPE,bval);
    }

    fn send_aux(&mut self,idx:u32,round:usize,aux: BoolSet) {
        self.pub_and_broadcast_message(self.height as u64,idx,round,AUX_TYPE,aux.into());
    }

    fn send_term(&mut self,idx:u32,round:usize, term : bool) {
        self.pub_and_broadcast_message(self.height as u64,idx,round,TERM_TYPE,term.into());
    }

    fn pub_and_broadcast_message(
        &mut self,
        height: u64,
        idx: u32,// round here means address idx
        round:usize,
        mtype: u8,
        val : BoolSet,
    ) {
        let author = &self.params.signer;
        let msg = serialize(&(height, idx,round, mtype,val, author.address), Infinite).unwrap();
        let signature = Signature::sign(author.keypair.privkey(), &msg.crypt_hash()).unwrap();
        let sig = signature.clone();
        let msg = serialize(&(msg, sig), Infinite).unwrap();

        trace!(
            "pub_and_broadcast_message {} begin h: {}, r: {}, type: {} v {:?}",
            self,
            height,
            idx,
            mtype,
            val,
        );
        self.pub_message(msg.clone());
    }

    fn pub_message(&self, message: Vec<u8>) {
        let msg: Message = message.into();
        self.pub_sender
            .send((
                routing_key!(Consensus >> RawBytes).into(),
                msg.try_into().unwrap(),
            ))
            .unwrap();
    }

    fn handle_ba_message(&mut self,idx:u32,round:usize,mut send_id: u32,mut mtype:u8,mut val:BoolSet) {
        if mtype == BVAL_TYPE {
            if let Some((sendb,b)) = self.bas[idx as usize].handle_bval(round,send_id,val) {
                if sendb {
                    self.send_bval(idx,round,val);
                }
                //next phase process
                mtype = AUX_TYPE;
                send_id = self.consensus_idx.unwrap();
                val = b.into();
            }
        }
        if mtype == AUX_TYPE {
            if let Some(decide) = self.bas[idx as usize].handle_aux(round,send_id,val) {
                if let Some(decide) = decide.definite() {

                    self.decides[self.consensus_idx.unwrap() as usize] = Some(decide);

                    self.send_term(idx,round,decide.into());
                    mtype = TERM_TYPE;
                    send_id = self.consensus_idx.unwrap();
                    val = decide.into();
                }
            }
        }

        if mtype == TERM_TYPE {
            if let Some(decide) = self.bas[idx as usize].handle_term(round,send_id,val) {
                if self.decides[self.consensus_idx.unwrap() as usize].is_none() {
                    self.decides[self.consensus_idx.unwrap() as usize] = Some(decide);

                    if let Some(block) = self.handle_decision() {
                        self.pub_block(&block);
                    }
                }
            }
        }
    }

    fn handle_decision(&mut self) -> Option<BlockWithProof> {
        let mut with_header = false;
        let mut ids = Vec::new();

        if self.is_all_vote(self.decision_count()) {
            return None;
        }


       for i in 0..self.decides.len() {
           if self.decides[i] == Some(true) {
               ids.push(i as u32);
           }
       }

        let mut pblock = BlockWithProof::new();
        let mut txs = Vec::new();
        let proposals = self.current_proposals.get_proposals(ids);
        if proposals.is_empty() {
            return None;
        }
        for p in proposals {
            let mut inner_block = Block::try_from(&p.block).unwrap();
            if with_header {
                pblock.mut_blk().set_header(inner_block.clone().take_header());
            }
            txs.extend_from_slice(inner_block.take_body().get_transactions());
        }

        txs.sort_by(|a, b| a.get_tx_hash().partial_cmp(b.get_tx_hash()).unwrap());
        txs.dedup_by(|a,b| a.get_tx_hash() == a.get_tx_hash());
        pblock.mut_blk().mut_body().set_transactions(txs.into());

        Some(pblock)
    }

    fn decision_count(&self) -> usize {
        let mut count = 0;
        for i in self.decides.clone() {
            if i.is_some() {
                count += 1;
            }
        }
        count
    }

    fn clear(&mut self) {
        for x in self.decides.iter_mut() {
            *x = None;
        }
    }


    fn handle_message(
        &mut self,
        message: &[u8],
        wal_flag: bool,
    ) -> Result<usize, EngineError> {
        let res = deserialize(&message[..]);
        if let Ok(decoded) = res {
            let (message, signature): (Vec<u8>, &[u8]) = decoded;
            if signature.len() != SIGNATURE_BYTES_LEN {
                return Err(EngineError::InvalidSignature);
            }
            let signature = Signature::from(signature);
            if let Ok(pubkey) = signature.recover(&message.crypt_hash()) {
                let decoded :(u64,u32,usize,u8,BoolSet,Address) = deserialize(&message[..]).unwrap();
                let (h, idx,round, mtype,val, sender) = decoded;
                trace!(
                    "handle_message parse over h: {}, idx: {}, round {} mtype: {},val {:?} sender: {:?}",
                    h,
                    idx,
                    round,
                    mtype,
                    val,
                    sender,
                );

                if h < self.height as u64{
                    return Err(EngineError::UnexpectedMessage);
                }

                if pubkey_to_address(&pubkey) == sender {
                    if let Some(send_id) = self.get_validator_id(&sender) {
                        self.handle_ba_message(idx,round,send_id, mtype,val);
                        return Ok(self.height);
                    }
                }
            }
        }
        Err(EngineError::UnexpectedMessage)
    }

    pub fn pub_block(&self, block: &BlockWithProof) {
        let msg: Message = block.clone().into();
        self.pub_sender
            .send((
                routing_key!(Consensus >> BlockWithProof).into(),
                msg.try_into().unwrap(),
            ))
            .unwrap();
    }

    pub fn pub_proposal(&mut self, proposal: &Proposal) -> Vec<u8> {
        let mut proto_proposal = ProtoProposal::new();
        let pro_block = Block::try_from(&proposal.block).unwrap();
        proto_proposal.set_block(pro_block);
        proto_proposal.set_height(self.height as u64);
        let message: Vec<u8> = (&proto_proposal).try_into().unwrap();

        let author = &self.params.signer;
        let hash = message.crypt_hash();
        let signature = Signature::sign(author.keypair.privkey(), &hash).unwrap();

        let mut signed_proposal = SignedProposal::new();
        signed_proposal.set_proposal(proto_proposal);
        signed_proposal.set_signature(signature.to_vec());

        // Send signed_proposal to nextwork.
        let msg: Message = signed_proposal.into();
        let bmsg: Vec<u8> = (&msg).try_into().unwrap();
        self.pub_sender
            .send((
                routing_key!(Consensus >> SignedProposal).into(),
                msg.try_into().unwrap(),
            ))
            .unwrap();
        bmsg
    }

    fn is_above_threshold(&self, n: usize) -> bool {
        n * 3 > self.auth_manage.validator_n() * 2
    }

    fn is_faulty_plus_one(&self, n: usize) -> bool {
        self.auth_manage.validator_n()/3 + 1 == n
    }

    fn is_all_vote(&self, n: usize) -> bool {
        n == self.auth_manage.validator_n()
    }

    fn get_proposal_verified_result(&self, height: usize, round: usize) -> VerifiedBlockStatus {
        self.unverified_msg
            .get(&(height, round))
            .map_or(VerifiedBlockStatus::Ok, |res| res.1)
    }


//    fn pre_proc_commit(&mut self, height: usize, round: usize) -> bool {
//        trace!(
//            "pre_proc_commit {} begin h: {}, r: {}, last_commit_round: {:?}",
//            self,
//            height,
//            round,
//            self.last_commit_round
//        );
//        if self.height == height && self.round == round {
//            if let Some(cround) = self.last_commit_round {
//                if cround == round && self.proposal.is_some() {
//                    let ret = self.commit_block();
//                    if ret {
//                        self.verified_blocks.clear();
//                    }
//                    return ret;
//                }
//            }
//        }
//        trace!("pre_proc_commit failed");
//        false
//    }

//    fn save_wal_proof(&mut self, height: usize) {
//        let bmsg = serialize(&self.proof, Infinite).unwrap();
//        let _ = self.wal_log.save(height, LogType::Commits, &bmsg);
//    }

//    fn proc_commit_after(&mut self, height: usize, round: usize) -> bool {
//        let now_height = self.height;
//        debug!("proc_commit_after {} h: {}, r: {}", self, height, round);
//        if now_height < height + 1 {
//            self.change_state_step(height + 1, INIT_ROUND, Step::Propose, true);
//            if let Some(hash) = self.pre_hash {
//                let buf = hash.to_vec();
//                let _ = self.wal_log.save(height + 1, LogType::PrevHash, &buf);
//            }
//
//            if self.proof.height != now_height && now_height > 0 {
//                if let Some(phash) = self.proposal {
//                    let mut res = self
//                        .last_commit_round
//                        .and_then(|cround| self.generate_proof(now_height, cround, phash));
//                    if res.is_none() {
//                        res = self
//                            .lock_round
//                            .and_then(|cround| self.generate_proof(now_height, cround, phash));
//                    }
//                    if let Some(proof) = res {
//                        self.proof = proof;
//                    }
//                }
//            }
//            if !self.proof.is_default() {
//                if self.proof.height == now_height {
//                    self.save_wal_proof(now_height);
//                } else {
//                    trace!("try my best to save proof but not ok {}", self);
//                }
//            }
//            self.clean_saved_info();
//            self.clean_filter_info();
//            self.clean_block_txs();
//            return true;
//        }
//        false
//    }


//    fn commit_block(&mut self) -> bool {
//        // Commit the block using a complete signature set.
//        let height = self.height;
//        let round = self.round;
//
//        //to be optimize
//        self.clean_verified_info(height);
//        trace!("commit_block {:?} begin", self);
//        if let Some(hash) = self.proposal {
//            if self.locked_block.is_some() {
//                let gen_flag = self.proof.height != height;
//
//                //generate proof
//                let get_proof = if gen_flag {
//                    self.generate_proof(height, round, hash)
//                } else {
//                    Some(self.proof.clone())
//                };
//
//                if let Some(proof) = get_proof {
//                    if gen_flag {
//                        self.proof = proof.clone();
//                    }
//                    self.save_wal_proof(height + 1);
//
//                    let locked_block = self.locked_block.clone().unwrap();
//                    let locked_block_hash = locked_block.crypt_hash();
//
//                    // The self.locked_block is a compact block.
//                    // So, fetch the bodies of transactions from self.verified_blocks.
//                    if let Some(proposal_block) = self.verified_blocks.get(&locked_block_hash) {
//                        let mut proof_blk = BlockWithProof::new();
//                        proof_blk.set_blk(proposal_block.clone());
//                        proof_blk.set_proof(proof.into());
//
//                        // saved for retranse blockwithproof to chain
//                        self.block_proof = Some((height, proof_blk.clone()));
//                        info!(
//                            "commit_block {} consensus time {:?} proposal {} locked block hash {}",
//                            self,
//                            Instant::now() - self.htime,
//                            hash,
//                            locked_block_hash,
//                        );
//                        self.pub_block(&proof_blk);
//                        return true;
//                    }
//                } else {
//                    info!("commit_block {} proof is not ok", self);
//                    return false;
//                }
//            }
//        }
//        //goto next round
//        false
//    }

    /*
        fn proc_proposal(&mut self, height: usize, round: usize) -> bool {
            let proposal = self.proposals.get_proposal(height, round);
            if let Some(proposal) = proposal {
                trace!("proc_proposal {} begin h: {}, r: {}", self, height, round);
                if !proposal.check(height, &self.auth_manage.validators) {
                    warn!("proc proposal check authorities error");
                    return false;
                }
                //height 1's block not have prehash
                if let Some(hash) = self.pre_hash {
                    //prehash : self.prehash vs  proposal's block's prehash
                    let block = CompactBlock::try_from(&proposal.block).unwrap();
                    let mut block_prehash = Vec::new();
                    block_prehash.extend_from_slice(block.get_header().get_prevhash());
                    {
                        if hash != H256::from(block_prehash.as_slice()) {
                            warn!(
                                "proc_proposal {} pre_hash h: {}, r: {}",
                                self, height, round,
                            );
                            return false;
                        }
                    }

                    if !self.verify_version(&block) {
                        warn!(
                            "proc_proposal {} version error h: {}, r: {}",
                            self, height, round
                        );
                        return false;
                    }

                    //proof : self.params vs proposal's block's broof
                    let block_proof = block.get_header().get_proof();
                    let proof = BftProof::from(block_proof.clone());
                    debug!(
                        "proc_proposal h: {}, r: {}, proof: {:?}",
                        height, round, proof
                    );
                    if self.auth_manage.authority_h_old == height - 1 {
                        if !proof.check(height - 1, &self.auth_manage.validators_old) {
                            warn!(
                                "proof check error h {} validator old {:?}",
                                height, self.auth_manage.validators_old,
                            );
                            return false;
                        }
                    } else if !proof.check(height - 1, &self.auth_manage.validators) {
                        warn!(
                            "proof check error h {} validator {:?}",
                            height, self.auth_manage.validators,
                        );
                        return false;
                    }

                    if self.proof.height != height - 1 {
                        self.proof = proof;
                    }
                } else if height != INIT_HEIGHT {
                    return false;
                }

                let proposal_lock_round = proposal.lock_round;
                //we have lock block,try unlock
                if self.lock_round.is_some()
                    && proposal_lock_round.is_some()
                    && self.lock_round.unwrap() < proposal_lock_round.unwrap()
                    && proposal_lock_round.unwrap() < round
                {
                    //we see new lock block unlock mine
                    trace!(
                        "proc_proposal unlock locked block: height: {}, proposal: {:?}",
                        height,
                        self.proposal
                    );
                    self.clean_saved_info();
                }
                // still lock on a blk,next prevote it
                if self.lock_round.is_some() {
                    let lock_block = &self.locked_block.clone().unwrap();
                    self.proposal = Some(lock_block.crypt_hash());
                    trace!("proc_proposal still have locked block {:?}", self);
                } else {
                    // else use proposal block, self.lock_round is none
                    let compact_block = CompactBlock::try_from(&proposal.block).unwrap();
                    let block_hash = compact_block.crypt_hash();
                    self.proposal = Some(block_hash);
                    debug!("proc_proposal save the proposal's hash {:?}", self);
                    self.locked_block = Some(compact_block);
                }
                return true;
            }
            warn!("proc_proposal not find proposal h {} r {}", height, round);
            false
        }

        fn verify_version(&self, block: &CompactBlock) -> bool {
            if self.version.is_none() {
                warn!("verify_version {} self.version is none", self);
                return false;
            }
            let version = self.version.unwrap();
            if block.get_version() != version {
                warn!(
                    "verify_version {} failed block version: {}, current chain version: {}",
                    self,
                    block.get_version(),
                    version
                );
                false
            } else {
                true
            }
        }

        fn verify_req(
            &mut self,
            csp_msg: Message,
            compact_block: &CompactBlock,
            vheight: usize,
            vround: usize,
        ) -> bool {
            let tx_hashes = compact_block.get_body().get_tx_hashes();
            // If there is no transaction, the block don't have to be verified.
            if tx_hashes.is_empty() {
                self.verified_blocks.insert(
                    compact_block.crypt_hash(),
                    compact_block.clone().complete(Vec::new()),
                );
                return true;
            }
            let verify_ok = compact_block.check_hash();
            if verify_ok {
                let verify_req = {
                    let mut verify_req = auth::VerifyBlockReq::new();
                    verify_req.set_height(vheight as u64);
                    verify_req.set_round(vround as u64);
                    verify_req.set_block(compact_block.clone());
                    verify_req
                };
                let mut msg: Message = verify_req.into();
                msg.set_origin(csp_msg.get_origin());
                self.pub_sender
                    .send((
                        routing_key!(Consensus >> VerifyBlockReq).into(),
                        msg.clone().try_into().unwrap(),
                    ))
                    .unwrap();
                self.unverified_msg
                    .insert((vheight, vround), (csp_msg, VerifiedBlockStatus::Init(0)));
            }
            verify_ok
        }*/


    fn clean_saved_info(&mut self) {

    }

    fn clean_verified_info(&mut self, height: usize) {
        if height == 0 {
            self.unverified_msg.clear();
        } else {
            self.unverified_msg = self.unverified_msg.split_off(&(height + 1, 0));
        }
    }

    fn clean_block_txs(&mut self) {
        let height = self.height - 1;
        self.block_txs.retain(|&(hi, _)| hi >= height);
    }


//    fn clean_proposal_when_verify_failed(&mut self) {
//        let height = self.height;
//        let round = self.round;
//        self.clean_saved_info();
//        self.pub_and_broadcast_message(height, round, Step::Prevote, Some(H256::default()));
//        self.pub_and_broadcast_message(height, round, Step::Precommit, Some(H256::default()));
//        self.change_state_step(height, round, Step::Precommit, false);
//        self.proc_precommit(height, round);
//    }

    pub fn new_proposal(&mut self) {
            if self.version.is_none() {
                warn!("new_proposal {} self.version is none", self);
                return;
            }
            let version = self.version.unwrap();
            // proposal new blk
            let mut block = Block::new();
            block.set_version(version);

            let mut flag = false;

            for &mut (height, ref mut blocktxs) in &mut self.block_txs {
                trace!(
                    "new_proposal BLOCKTXS get height {}, self height {}",
                    height,
                    self.height
                );
                if height == self.height - 1 {
                    flag = true;
                    // If any transaction couldn't verified, then the proposals which include it will
                    // not verified.
                    // So, block generation will be blocked.
                    // Taking all transactions to avoid that.
                    // Next turn when proposing a new proposal in the same height, this node will use
                    // an empty block.
                    block.set_body(blocktxs.take_body().clone());
                    break;
                }
            }
            if !flag && self.height > INIT_HEIGHT {
                info!("new_proposal BLOCKTXS not give {} txs", self.height);
                return;
            }

            if self.pre_hash.is_some() {
                block
                    .mut_header()
                    .set_prevhash(self.pre_hash.unwrap().0.to_vec());
            } else {
                info!("new_proposal {} self.pre_hash is none", self);
            }

            let proof = BftProof::default();
            block.mut_header().set_proof(proof.into());

            let block_time = unix_now();
            let transactions_root = block.get_body().transactions_root();
            block
                .mut_header()
                .set_timestamp(AsMillis::as_millis(&block_time));
            block.mut_header().set_height(self.height as u64);
            block
                .mut_header()
                .set_transactions_root(transactions_root.to_vec());
            block
                .mut_header()
                .set_proposer(self.params.signer.address.to_vec());

            let bh = block.crypt_hash();
            info!(
                "new_proposal {} proposal new block with {} txs: block hash {:?}",
                self,
                block.get_body().get_transactions().len(),
                bh
            );
            let blk = block.clone().try_into().unwrap();
            // If we publish a proposal block, the block is verified by auth, already.
            self.verified_blocks.insert(bh, block);
            trace!(
                "new_proposal {} pub proposal proposor vote myslef in not locked",
                self
            );

            let proposal = Proposal {
                block: blk,
                lock_round: None,
                lock_votes: None,
            };

        let _bmsg = self.pub_proposal(&proposal);
        /*self.wal_log
            .save(self.height, LogType::Propose, &bmsg)
            .unwrap();*/
        self.add_proposal(self.height, self.consensus_idx.unwrap(), proposal);
    }

    pub fn timeout_process(&mut self, tminfo: &TimeoutInfo) {
//        trace!(
//            "timeout_process {} tminfo: {}, wait {:?}",
//            self,
//            tminfo,
//            Instant::now() - self.htime
//        );
//
//        if tminfo.height < self.height {
//            return;
//        }
//        if tminfo.height == self.height
//            && tminfo.round < self.round
//            && tminfo.step != Step::CommitWait
//        {
//            return;
//        }
//        if tminfo.height == self.height
//            && tminfo.round == self.round
//            && tminfo.step != self.step
//            && tminfo.step != Step::CommitWait
//        {
//            return;
//        }
//        if tminfo.step == Step::ProposeWait {
//            let pres = self.proc_proposal(tminfo.height, tminfo.round);
//            if !pres {
//                trace!(
//                    "timeout_process {} proc_proposal failed; tminfo: {}",
//                    self,
//                    tminfo
//                );
//            }
//            self.pre_proc_prevote();
//            self.change_state_step(tminfo.height, tminfo.round, Step::Prevote, false);
//            //one node need this
//            {
//                self.proc_prevote(tminfo.height, tminfo.round);
//            }
//        } else if tminfo.step == Step::Prevote {
//            self.pre_proc_prevote();
//        } else if tminfo.step == Step::PrevoteWait {
//            if self.pre_proc_precommit() {
//                self.change_state_step(tminfo.height, tminfo.round, Step::Precommit, false);
//                self.proc_precommit(tminfo.height, tminfo.round);
//            } else {
//                self.change_state_step(tminfo.height, tminfo.round, Step::PrecommitAuth, false);
//                let now = Instant::now();
//                let _ = self.timer_seter.send(TimeoutInfo {
//                    timeval: now + (self.params.timer.get_prevote() * TIMEOUT_RETRANSE_MULTIPLE),
//                    height: tminfo.height,
//                    round: tminfo.round,
//                    step: Step::PrecommitAuth,
//                });
//            }
//        } else if tminfo.step == Step::PrecommitAuth {
//            let mut wait_too_many_times = false;
//            // If consensus doesn't receive the result of block verification in a specific
//            // time-frame, use the original message to construct a request, then resend it to auth.
//            if let Some((csp_msg, result)) =
//                self.unverified_msg.get_mut(&(tminfo.height, tminfo.round))
//            {
//                if let VerifiedBlockStatus::Init(ref mut times) = *result {
//                    trace!("wait for the verification result {} times", times);
//                    if *times >= 3 {
//                        error!("do not wait for the verification result again");
//                        wait_too_many_times = true;
//                    } else {
//                        let verify_req = csp_msg
//                            .clone()
//                            .take_compact_signed_proposal()
//                            .unwrap()
//                            .create_verify_block_req();
//                        let mut msg: Message = verify_req.into();
//                        msg.set_origin(csp_msg.get_origin());
//                        self.pub_sender
//                            .send((
//                                routing_key!(Consensus >> VerifyBlockReq).into(),
//                                msg.try_into().unwrap(),
//                            ))
//                            .unwrap();
//                        let now = Instant::now();
//                        let _ = self.timer_seter.send(TimeoutInfo {
//                            timeval: now
//                                + (self.params.timer.get_prevote() * TIMEOUT_RETRANSE_MULTIPLE),
//                            height: tminfo.height,
//                            round: tminfo.round,
//                            step: Step::PrecommitAuth,
//                        });
//                        *times += 1;
//                    };
//                } else {
//                    warn!("already get verified result {:?}", *result);
//                }
//            };
//            // If waited the result of verification for a long while, we consider it was failed.
//            if wait_too_many_times {
//                self.clean_proposal_when_verify_failed();
//            }
//        } else if tminfo.step == Step::Precommit {
//            /*in this case,need resend prevote : my net server can be connected but other node's
//            server not connected when staring.  maybe my node receive enough vote(prevote),but others
//            did not receive enough vote,so even if my node step precommit phase, i need resend prevote also.
//            */
//            self.pre_proc_prevote();
//            self.pre_proc_precommit();
//        } else if tminfo.step == Step::PrecommitWait {
//            if self.pre_proc_commit(tminfo.height, tminfo.round) {
//                /*wait for new status*/
//                self.change_state_step(tminfo.height, tminfo.round, Step::Commit, false);
//            } else {
//                // clean the param if not locked
//                if self.lock_round.is_none() {
//                    self.clean_saved_info();
//                }
//                self.change_state_step(tminfo.height, tminfo.round + 1, Step::Propose, false);
//                self.redo_work();
//            }
//        } else if tminfo.step == Step::CommitWait {
//            let res = self.proc_commit_after(tminfo.height, tminfo.round);
//            if res {
//                self.htime = Instant::now();
//                self.redo_work();
//            }
//        }
    }

    pub fn process(&mut self, info: TransType) {
        let (key, body) = info;
        let rtkey = RoutingKey::from(&key);
        let mut msg = Message::try_from(&body[..]).unwrap();
        let from_broadcast = rtkey.is_sub_module(SubModules::Net);
        if from_broadcast && self.consensus_idx.is_some()  {
            match rtkey {
                routing_key!(Net >> SignedProposal) => {
                    let res = self.handle_proposal(&body[..]);
                    if let Ok(h) = res {
                        trace!(
                            "process {} recieve handle_proposal ok; h: {}",
                            self,
                            h,
                        );

                        // to be set bval_input
                        if h == self.height {
                            self.new_proposal();
                        }
                    } else {
                        trace!(
                            "process {} fail handle_proposal {}",
                            self,
                            res.err().unwrap()
                        );
                    }
                }

                routing_key!(Net >> RawBytes) => {
                    let raw_bytes = msg.take_raw_bytes().unwrap();
                    let _res = self.handle_message(&raw_bytes[..],false);

                }
                _ => {}
            }
        } else {
            match rtkey {
                // accept authorities_list from chain
                routing_key!(Chain >> RichStatus) => {
                    let rich_status = msg.take_rich_status().unwrap();
                    trace!(
                        "process {} get new local status {:?}",
                        self,
                        rich_status.height
                    );
                    self.receive_new_status(&rich_status);
                    let authorities: Vec<Address> = rich_status
                        .get_nodes()
                        .iter()
                        .map(|node| Address::from_slice(node))
                        .collect();
                    trace!("authorities: [{:?}]", authorities);

                    let validators: Vec<Address> = rich_status
                        .get_validators()
                        .iter()
                        .map(|node| Address::from_slice(node))
                        .collect();
                    trace!("validators: [{:?}]", validators);

                    if let Some(idx) =self.get_validator_id(&self.params.signer.address) {
                        self.consensus_idx = Some(idx);
                    }
                    self.auth_manage.receive_authorities_list(
                        rich_status.height as usize,
                        &authorities,
                        &validators,
                    );
                    let version = rich_status.get_version();
                    trace!("verison: {}", version);
                    self.version = Some(version);
                }

                routing_key!(Auth >> VerifyBlockResp) => {
                }

                routing_key!(Auth >> BlockTxs) => {
                    let block_txs = msg.take_block_txs().unwrap();
                    debug!(
                        "process {} recieve BlockTxs h: {}",
                        self,
                        block_txs.get_height(),
                    );
                    let height = block_txs.get_height() as usize;
                    let msg: Vec<u8> = (&block_txs).try_into().unwrap();
                    self.block_txs.push_back((height, block_txs));
                    //let _ = self.wal_log.save(height, LogType::AuthTxs, &msg);
                    {
                        self.new_proposal();
                        // Should be Resend ?
                    }
                }
                _ => {}
            }
        }
    }


    fn receive_new_status(&mut self, status: &RichStatus) {
        let status_height = status.height as usize;
        self.params.timer.set_total_duration(status.interval);

        let height = self.height;
        trace!(
            "receive_new_status {} receive height {}",
            self,
            status_height,
        );
        if height > 0 && status_height + 1 < height {
            return;
        }

        let pre_hash = H256::from_slice(&status.hash);
        self.pre_hash = Some(pre_hash);

        /*let now = Instant::now();
        let _ = self.timer_seter.send(TimeoutInfo {
            timeval: now + tv,
            height: status_height,
            round: new_round,
            step: Step::CommitWait,
        });*/
    }

    fn new_round_start(&mut self, height: usize) {
        self.new_proposal();
    }

    pub fn redo_work(&mut self) {
        /*let height = self.height;
        let round = self.round;
        let now = Instant::now();

        trace!("redo_work {} begin", self);
        if self.step == Step::Propose || self.step == Step::ProposeWait {
            self.new_round_start(height, round);
        } else if self.step == Step::Prevote || self.step == Step::PrevoteWait {
            self.pre_proc_prevote();
            self.proc_prevote(height, round);
            if self.step == Step::PrevoteWait {
                let _ = self.timer_seter.send(TimeoutInfo {
                    timeval: now + self.params.timer.get_prevote(),
                    height,
                    round,
                    step: Step::PrevoteWait,
                });
            }
        } else if self.step == Step::Precommit || self.step == Step::PrecommitWait {
            self.pre_proc_precommit();
            self.proc_precommit(height, round);
            if self.step == Step::PrecommitWait {
                let _ = self.timer_seter.send(TimeoutInfo {
                    timeval: now + self.params.timer.get_precommit(),
                    height,
                    round,
                    step: Step::PrecommitWait,
                });
            }
        } else if self.step == Step::Commit {
            /*when rebooting ,we did not know chain if is ready
                if chain garantee that when I sent commit_block,
                it can always issue block, no need for this.
            */
            if !self.commit_block() {
                if self.lock_round.is_none() {
                    self.clean_saved_info();
                }
                self.change_state_step(height, round + 1, Step::Propose, true);
                self.new_round_start(height, round + 1);
            } else {
                self.verified_blocks.clear();
            }
        } else if self.step == Step::CommitWait {
            // When CommitWait,need timeout_process to do some work
            let _ = self.timer_seter.send(TimeoutInfo {
                timeval: now,
                height,
                round,
                step: Step::CommitWait,
            });
        }*/
    }

    pub fn start(&mut self) {
        //self.load_wal_log();
        // TODO : broadcast some message, based on current state
        if self.height >= INIT_HEIGHT {
            self.redo_work();
        }

        loop {
            match self.receiver.recv() {
                Ok(BftTurn::Timeout(tm)) => {
                    self.timeout_process(&tm);
                }
                Ok(BftTurn::Message(info)) => {
                    self.process(info);
                }
                _ => {}
            }
        }
    }
}
