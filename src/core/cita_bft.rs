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

use std::convert::Into;

use authority_manage::AuthorityManage;
use bincode::{deserialize, serialize, Infinite};

use crate::core::params::BftParams;
use crate::core::voteset::{Proposal, ProposalCollector, VoteCollector, VoteMessage, VoteSet};

use crate::core::votetime::TimeoutInfo;
use crate::core::wal::{LogType, Wal};

use crate::crypto::{pubkey_to_address, CreateKey, Sign, Signature, SIGNATURE_BYTES_LEN};
use engine::{unix_now, AsMillis, EngineError, Mismatch};
use libproto::blockchain::{Block, BlockTxs, BlockWithProof, CompactBlock, RichStatus};
use libproto::consensus::{
    CompactProposal, CompactSignedProposal, SignedProposal, Vote as ProtoVote,
};
use libproto::router::{MsgType, RoutingKey, SubModules};
use libproto::snapshot::{Cmd, Resp, SnapshotResp};
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

const INIT_HEIGHT: usize = 1;
const INIT_ROUND: usize = 0;

const MAX_PROPOSAL_TIME_COEF: usize = 10;

const TIMEOUT_RETRANSE_MULTIPLE: u32 = 15;
const TIMEOUT_LOW_ROUND_MESSAGE_MULTIPLE: u32 = 20;

pub type TransType = (String, Vec<u8>);
pub type PubType = (String, Vec<u8>);

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

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Eq, Clone, Copy, Hash)]
pub enum Step {
    Propose = 0,
    ProposeWait = 1,
    Prevote = 2,
    PrevoteWait = 3,
    PrecommitAuth = 4,
    Precommit = 5,
    PrecommitWait = 6,
    Commit = 7,
    CommitWait = 8,
}

impl Default for Step {
    fn default() -> Step {
        Step::Propose
    }
}

impl From<u8> for Step {
    fn from(s: u8) -> Step {
        match s {
            0 => Step::Propose,
            1 => Step::ProposeWait,
            2 => Step::Prevote,
            3 => Step::PrevoteWait,
            4 => Step::PrecommitAuth,
            5 => Step::Precommit,
            6 => Step::PrecommitWait,
            7 => Step::Commit,
            8 => Step::CommitWait,
            _ => panic!("Invalid step."),
        }
    }
}

impl ::std::fmt::Display for Step {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", (*self) as u8)
    }
}

pub struct Bft {
    pub_sender: Sender<PubType>,
    timer_seter: Sender<TimeoutInfo>,
    receiver: Receiver<BftTurn>,

    params: BftParams,
    height: usize,
    round: usize,
    step: Step,
    proof: BftProof,
    pre_hash: Option<H256>,
    votes: VoteCollector,
    proposals: ProposalCollector,
    proposal: Option<H256>,
    lock_round: Option<usize>,
    locked_vote: Option<VoteSet>,
    // lock_round set, locked block means itself,else means proposal's block
    locked_block: Option<CompactBlock>,
    wal_log: Wal,
    send_filter: HashMap<Address, (usize, Step, Instant)>,
    last_commit_round: Option<usize>,
    htime: Instant,
    auth_manage: AuthorityManage,
    consensus_power: bool,
    //params meaning: key :index 0->height,1->round ,value:0->verified msg,1->verified result
    unverified_msg: BTreeMap<(usize, usize), (Message, VerifiedBlockStatus)>,
    // VecDeque might work, Almost always it is better to use Vec or VecDeque instead of LinkedList
    block_txs: VecDeque<(usize, BlockTxs)>,
    block_proof: Option<(usize, BlockWithProof)>,

    // The verified blocks with the bodies of transactions.
    verified_blocks: HashMap<H256, Block>,

    // when snaphsot restore, clear wal data
    is_snapshot: bool,

    // whether the datas above have been cleared.
    is_cleared: bool,

    version: Option<u32>,
}

impl ::std::fmt::Debug for Bft {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "Bft {{ \
             h: {}, r: {}, s: {}, v: {:?} \
             proof: {:?}, pre_hash: {:?}, proposal: {:?}, \
             lock_round: {:?}, last_commit_round: {:?}, \
             consensus_power: {:?}, is_snapshot: {}, is_cleared: {} \
             }}",
            self.height,
            self.round,
            self.step,
            self.version,
            self.proof,
            self.pre_hash,
            self.proposal,
            self.lock_round,
            self.last_commit_round,
            self.consensus_power,
            self.is_snapshot,
            self.is_cleared,
        )
    }
}

impl ::std::fmt::Display for Bft {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "Bft {{ h: {}, r: {}, s: {} }}",
            self.height, self.round, self.step,
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

            params,
            height: 0,
            round: INIT_ROUND,
            step: Step::Propose,
            proof,
            pre_hash: None,
            votes: VoteCollector::new(),
            proposals: ProposalCollector::new(),
            proposal: None,
            lock_round: None,
            locked_vote: None,
            locked_block: None,
            wal_log: Wal::create(&*logpath).unwrap(),
            send_filter: HashMap::new(),
            last_commit_round: None,
            htime: Instant::now(),
            auth_manage: AuthorityManage::new(),
            consensus_power: false,
            unverified_msg: BTreeMap::new(),
            block_txs: VecDeque::new(),
            block_proof: None,
            verified_blocks: HashMap::new(),
            is_snapshot: false,
            is_cleared: false,
            version: None,
        }
    }

    pub fn get_snapshot(&self) -> bool {
        self.is_snapshot
    }

    pub fn set_snapshot(&mut self, b: bool) {
        self.is_snapshot = b;
    }

    fn is_round_proposer(
        &self,
        height: usize,
        round: usize,
        address: &Address,
    ) -> Result<(), EngineError> {
        let p = &self.auth_manage;
        if p.authorities.is_empty() {
            warn!("There are no authorities");
            return Err(EngineError::NotAuthorized(Address::zero()));
        }
        let proposer_nonce = height + round;
        let proposer: &Address = p
            .authorities
            .get(proposer_nonce % p.authorities.len())
            .expect(
                "There are validator_n() authorities; \
                 taking number modulo validator_n() gives number in validator_n() range; qed",
            );
        if proposer == address {
            Ok(())
        } else {
            Err(EngineError::NotProposer(Mismatch {
                expected: *proposer,
                found: *address,
            }))
        }
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
        let compact_block = CompactBlock::try_from(&proposal.block).unwrap();
        let block_hash = compact_block.crypt_hash();

        let compact_proposal = {
            let mut compact_proposal = CompactProposal::new();
            compact_proposal.set_block(compact_block);
            compact_proposal.set_round(self.round as u64);
            compact_proposal.set_height(self.height as u64);
            if let Some(lock_round) = proposal.lock_round {
                let mut votes = Vec::new();
                for (sender, vote_message) in proposal.clone().lock_votes.unwrap().votes_by_sender {
                    let mut vote = ProtoVote::new();
                    if vote_message.proposal.is_none() {
                        continue;
                    }
                    vote.set_proposal(vote_message.proposal.unwrap().to_vec());
                    vote.set_sender(sender.to_vec());
                    vote.set_signature(vote_message.signature.to_vec());
                    votes.push(vote);
                }

                compact_proposal.set_islock(true);
                compact_proposal.set_lock_round(lock_round as u64);
                compact_proposal.set_lock_votes(votes.into());
            } else {
                compact_proposal.set_islock(false);
            }
            compact_proposal
        };

        let compact_signed_proposal = {
            let mut signed_proposal = CompactSignedProposal::new();
            let message: Vec<u8> = (&compact_proposal).try_into().unwrap();
            let author = &self.params.signer;
            let hash = message.crypt_hash();
            let signature = Signature::sign(author.keypair.privkey(), &hash).unwrap();
            trace!(
                "pub_proposal {} hash: {}, signature: {}",
                self,
                hash,
                signature
            );
            signed_proposal.set_proposal(compact_proposal);
            signed_proposal.set_signature(signature.to_vec());
            signed_proposal
        };

        // If consensus has the full verified block, then send it to executor.
        if let Some(block) = self.verified_blocks.get(&block_hash) {
            // Send SignedProposal to executor.
            let signed_proposal = compact_signed_proposal
                .clone()
                .complete(block.get_body().get_transactions().to_vec());
            let msg: Message = signed_proposal.into();
            self.pub_sender
                .send((
                    routing_key!(Consensus >> SignedProposal).into(),
                    msg.try_into().unwrap(),
                ))
                .unwrap();
        };

        // Send CompactSignedProposal to nextwork.
        let msg: Message = compact_signed_proposal.into();
        let bmsg: Vec<u8> = (&msg).try_into().unwrap();
        self.pub_sender
            .send((
                routing_key!(Consensus >> CompactSignedProposal).into(),
                msg.try_into().unwrap(),
            ))
            .unwrap();
        bmsg
    }

    fn pre_proc_prevote(&mut self) {
        let prop = self.proposal;
        let height = self.height;
        let round = self.round;

        if prop.is_none() {
            self.proc_proposal(height, round);
        }
        debug!("pre_proc_prevote {:?}", self);
        if self.lock_round.is_some() || prop.is_some() {
            self.pub_and_broadcast_message(height, round, Step::Prevote, prop);
        } else {
            trace!("pre_proc_prevote {} have nothing", self);
            self.pub_and_broadcast_message(height, round, Step::Prevote, Some(H256::default()));
        }
        //this is for timeout resending votes
        let now = Instant::now();
        let _ = self.timer_seter.send(TimeoutInfo {
            timeval: now + (self.params.timer.get_prevote() * TIMEOUT_RETRANSE_MULTIPLE),
            height,
            round,
            step: Step::Prevote,
        });
    }

    fn proc_prevote(&mut self, height: usize, round: usize) -> bool {
        debug!("proc_prevote {} begin h: {}, r: {}", self, height, round);
        if height < self.height
            || (height == self.height && round < self.round)
            || (height == self.height && self.round == round && self.step > Step::PrevoteWait)
        {
            return false;
        }

        let vote_set = self.votes.get_voteset(height, round, Step::Prevote);
        trace!("proc_prevote {} vote_set: {:?}", self, vote_set);
        if let Some(vote_set) = vote_set {
            if self.is_above_threshold(vote_set.count) {
                let mut tv = if self.is_all_vote(vote_set.count) {
                    Duration::new(0, 0)
                } else {
                    self.params.timer.get_prevote()
                };

                for (hash, count) in &vote_set.votes_by_proposal {
                    if self.is_above_threshold(*count) {
                        //we have lock block,and now polc  then unlock
                        if self.lock_round.is_some()
                            && self.lock_round.unwrap() < round
                            && round <= self.round
                        {
                            //we see new lock block unlock mine
                            trace!(
                                "proc_prevote {} unlock locked block height {}, hash {:?}",
                                self,
                                height,
                                hash
                            );
                            self.lock_round = None;
                            self.locked_vote = None;
                        }

                        if hash.is_zero() {
                            self.clean_saved_info();
                            tv = Duration::new(0, 0);
                        } else if self.proposal == Some(*hash) {
                            self.lock_round = Some(round);
                            self.locked_vote = Some(vote_set.clone());
                            tv = Duration::new(0, 0);
                        } else {
                            let mut clean_flag = true;
                            let op = self.proposals.get_proposal(height, round);
                            if let Some(op_raw) = op {
                                let pro_block = CompactBlock::try_from(&op_raw.block);
                                if let Ok(block) = pro_block {
                                    let bhash: H256 = block.crypt_hash();
                                    if bhash == *hash {
                                        self.locked_block = Some(block);
                                        self.proposal = Some(*hash);
                                        self.locked_vote = Some(vote_set.clone());
                                        self.lock_round = Some(round);
                                        clean_flag = false;
                                    }
                                }
                            }
                            if clean_flag {
                                self.clean_saved_info();
                            }
                        }
                        //more than one hash have threahold is wrong !! do some check ??
                        break;
                    }
                }

                if self.step == Step::Prevote || (self.round < round && self.step < Step::Commit) {
                    self.change_state_step(height, round, Step::PrevoteWait, false);
                    let now = Instant::now();
                    let _ = self.timer_seter.send(TimeoutInfo {
                        timeval: now + tv,
                        height,
                        round,
                        step: Step::PrevoteWait,
                    });
                }
                return true;
            }
        }
        false
    }

    fn is_above_threshold(&self, n: usize) -> bool {
        n * 3 > self.auth_manage.validator_n() * 2
    }

    fn is_all_vote(&self, n: usize) -> bool {
        n == self.auth_manage.validator_n()
    }

    fn get_proposal_verified_result(&self, height: usize, round: usize) -> VerifiedBlockStatus {
        self.unverified_msg
            .get(&(height, round))
            .map_or(VerifiedBlockStatus::Ok, |res| res.1)
    }

    fn pre_proc_precommit(&mut self) -> bool {
        let height = self.height;
        let round = self.round;
        let proposal = self.proposal;
        let mut lock_ok = false;

        let verify_result = self.get_proposal_verified_result(height, round);
        if let Some(lround) = self.lock_round {
            trace!("pre_proc_precommit {} locked round {}", self, lround);
            if lround == round {
                lock_ok = true;
            }
        }
        //polc is ok,but not verified , not send precommit
        if lock_ok && verify_result.is_init() {
            return false;
        }

        if lock_ok && verify_result.is_ok() {
            self.pub_and_broadcast_message(height, round, Step::Precommit, proposal);
        } else {
            self.pub_and_broadcast_message(height, round, Step::Precommit, Some(H256::default()));
        }

        let now = Instant::now();
        //timeout for resending vote msg
        let _ = self.timer_seter.send(TimeoutInfo {
            timeval: now + (self.params.timer.get_precommit() * TIMEOUT_RETRANSE_MULTIPLE),
            height: self.height,
            round: self.round,
            step: Step::Precommit,
        });
        true
    }

    fn retrans_vote(&mut self, height: usize, round: usize, step: Step) {
        self.pub_and_broadcast_message(height, round, step, Some(H256::default()));
    }

    fn proc_precommit(&mut self, height: usize, round: usize) -> bool {
        debug!("proc_precommit {} begin h: {}, r: {}", self, height, round);
        if height < self.height
            || (height == self.height && round < self.round)
            || (height == self.height && self.round == round && self.step > Step::PrecommitWait)
        {
            return false;
        }

        let vote_set = self.votes.get_voteset(height, round, Step::Precommit);
        trace!(
            "proc_precommit {} deal h: {}, r: {}, vote_set: {:?}",
            self,
            height,
            round,
            vote_set
        );
        if let Some(vote_set) = vote_set {
            if self.is_above_threshold(vote_set.count) {
                trace!(
                    "proc_precommit {} is_above_threshold h: {}, r: {}",
                    self,
                    height,
                    round
                );

                let mut tv = if self.is_all_vote(vote_set.count) {
                    Duration::new(0, 0)
                } else {
                    self.params.timer.get_precommit()
                };

                for (hash, count) in vote_set.votes_by_proposal {
                    if self.is_above_threshold(count) {
                        trace!(
                            "proc_precommit {} is_above_threshold hash: {:?}, count: {}",
                            self,
                            hash,
                            count
                        );
                        if hash.is_zero() {
                            tv = Duration::new(0, 0);
                            trace!("proc_precommit is zero");
                        } else if self.proposal.is_some() {
                            if hash != self.proposal.unwrap() {
                                trace!(
                                    "proc_precommit {:?} proposal is not right hash: {:?}",
                                    self,
                                    hash
                                );
                                self.clean_saved_info();
                                return false;
                            } else {
                                self.proposal = Some(hash);
                                self.last_commit_round = Some(round);
                                tv = Duration::new(0, 0);
                            }
                        } else {
                            trace!(
                                "proc_precommit {:?} hash is ok, but self.propose is none",
                                self
                            );
                            return false;
                        }
                        break;
                    }
                }

                if self.step == Step::Precommit || (self.round < round && self.step < Step::Commit)
                {
                    self.change_state_step(height, round, Step::PrecommitWait, false);
                    let now = Instant::now();
                    let _ = self.timer_seter.send(TimeoutInfo {
                        timeval: now + tv,
                        height,
                        round,
                        step: Step::PrecommitWait,
                    });
                }
                return true;
            }
        }
        false
    }

    fn pre_proc_commit(&mut self, height: usize, round: usize) -> bool {
        trace!(
            "pre_proc_commit {} begin h: {}, r: {}, last_commit_round: {:?}",
            self,
            height,
            round,
            self.last_commit_round
        );
        if self.height == height && self.round == round {
            if let Some(cround) = self.last_commit_round {
                if cround == round && self.proposal.is_some() {
                    let ret = self.commit_block();
                    if ret {
                        self.verified_blocks.clear();
                    }
                    return ret;
                }
            }
        }
        trace!("pre_proc_commit failed");
        false
    }

    fn save_wal_proof(&mut self, height: usize) {
        let bmsg = serialize(&self.proof, Infinite).unwrap();
        let _ = self.wal_log.save(height, LogType::Commits, &bmsg);
    }

    fn proc_commit_after(&mut self, height: usize, round: usize) -> bool {
        let now_height = self.height;
        debug!("proc_commit_after {} h: {}, r: {}", self, height, round);
        if now_height < height + 1 {
            self.change_state_step(height + 1, INIT_ROUND, Step::Propose, true);
            if let Some(hash) = self.pre_hash {
                let buf = hash.to_vec();
                let _ = self.wal_log.save(height + 1, LogType::PrevHash, &buf);
            }

            if self.proof.height != now_height && now_height > 0 {
                if let Some(phash) = self.proposal {
                    let mut res = self
                        .last_commit_round
                        .and_then(|cround| self.generate_proof(now_height, cround, phash));
                    if res.is_none() {
                        res = self
                            .lock_round
                            .and_then(|cround| self.generate_proof(now_height, cround, phash));
                    }
                    if let Some(proof) = res {
                        self.proof = proof;
                    }
                }
            }
            if !self.proof.is_default() {
                if self.proof.height == now_height {
                    self.save_wal_proof(now_height);
                } else {
                    trace!("try my best to save proof but not ok {}", self);
                }
            }
            self.clean_saved_info();
            self.clean_filter_info();
            self.clean_block_txs();
            return true;
        }
        false
    }

    fn generate_proof(&mut self, height: usize, round: usize, hash: H256) -> Option<BftProof> {
        let mut commits = HashMap::new();
        {
            let vote_set = self.votes.get_voteset(height, round, Step::Precommit);
            let mut num: usize = 0;
            if let Some(vote_set) = vote_set {
                for (sender, vote) in &vote_set.votes_by_sender {
                    if vote.proposal.is_none() {
                        continue;
                    }
                    if vote.proposal.unwrap() == hash {
                        num += 1;
                        commits.insert(*sender, vote.signature.clone());
                    }
                }
            }
            if !self.is_above_threshold(num) {
                return None;
            }
        }
        let mut proof = BftProof::default();
        proof.height = height;
        proof.round = round;
        proof.proposal = hash;
        proof.commits = commits;
        Some(proof)
    }

    fn commit_block(&mut self) -> bool {
        // Commit the block using a complete signature set.
        let height = self.height;
        let round = self.round;

        //to be optimize
        self.clean_verified_info(height);
        trace!("commit_block {:?} begin", self);
        if let Some(hash) = self.proposal {
            if self.locked_block.is_some() {
                let gen_flag = self.proof.height != height;

                //generate proof
                let get_proof = if gen_flag {
                    self.generate_proof(height, round, hash)
                } else {
                    Some(self.proof.clone())
                };

                if let Some(proof) = get_proof {
                    if gen_flag {
                        self.proof = proof.clone();
                    }
                    self.save_wal_proof(height + 1);

                    let locked_block = self.locked_block.clone().unwrap();
                    let locked_block_hash = locked_block.crypt_hash();

                    // The self.locked_block is a compact block.
                    // So, fetch the bodies of transactions from self.verified_blocks.
                    if let Some(proposal_block) = self.verified_blocks.get(&locked_block_hash) {
                        let mut proof_blk = BlockWithProof::new();
                        proof_blk.set_blk(proposal_block.clone());
                        proof_blk.set_proof(proof.into());

                        // saved for retranse blockwithproof to chain
                        self.block_proof = Some((height, proof_blk.clone()));
                        info!(
                            "commit_block {} consensus time {:?} proposal {} locked block hash {}",
                            self,
                            Instant::now() - self.htime,
                            hash,
                            locked_block_hash,
                        );
                        self.pub_block(&proof_blk);
                        return true;
                    }
                } else {
                    info!("commit_block {} proof is not ok", self);
                    return false;
                }
            }
        }
        //goto next round
        false
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

    fn pub_and_broadcast_message(
        &mut self,
        height: usize,
        round: usize,
        step: Step,
        hash: Option<H256>,
    ) {
        let author = &self.params.signer;
        let msg = serialize(&(height, round, step, author.address, hash), Infinite).unwrap();
        let signature = Signature::sign(author.keypair.privkey(), &msg.crypt_hash()).unwrap();
        let sig = signature.clone();
        let msg = serialize(&(msg, sig), Infinite).unwrap();

        trace!(
            "pub_and_broadcast_message {} begin h: {}, r: {}, s: {}",
            self,
            height,
            round,
            step,
        );
        self.pub_message(msg.clone());

        if self.height >= height || (self.height == height && self.round >= round) {
            let ret = self.votes.add(
                height,
                round,
                step,
                author.address,
                &VoteMessage {
                    proposal: hash,
                    signature,
                },
            );

            if ret {
                self.wal_log.save(height, LogType::Vote, &msg).unwrap();
            }
        }
    }

    fn is_validator(&self, address: &Address) -> bool {
        self.auth_manage.validators.contains(address)
    }

    fn change_state_step(&mut self, height: usize, round: usize, step: Step, newflag: bool) {
        trace!(
            "change_state_step {} -> {{ h: {}, r: {}, s: {}, newflag: {} }}",
            self,
            height,
            round,
            step,
            newflag
        );
        self.height = height;
        self.round = round;
        self.step = step;

        if newflag {
            let _ = self.wal_log.set_height(height);
        }

        let message = serialize(&(height, round, step), Infinite).unwrap();
        let _ = self.wal_log.save(height, LogType::State, &message);
    }

    fn handle_state(&mut self, msg: &[u8]) {
        if let Ok(decoded) = deserialize(msg) {
            let (h, r, s) = decoded;
            self.height = h;
            self.round = r;
            self.step = s;
        }
    }

    fn handle_message(
        &mut self,
        message: &[u8],
        wal_flag: bool,
    ) -> Result<(usize, usize, Step), EngineError> {
        let log_msg = message.to_owned();
        let res = deserialize(&message[..]);
        if let Ok(decoded) = res {
            let (message, signature): (Vec<u8>, &[u8]) = decoded;
            if signature.len() != SIGNATURE_BYTES_LEN {
                return Err(EngineError::InvalidSignature);
            }
            let signature = Signature::from(signature);
            if let Ok(pubkey) = signature.recover(&message.crypt_hash()) {
                let decoded = deserialize(&message[..]).unwrap();
                let (h, r, step, sender, hash) = decoded;
                trace!(
                    "handle_message {} parse over h: {}, r: {}, s: {}, sender: {:?}",
                    self,
                    h,
                    r,
                    step,
                    sender,
                );

                if h < self.height {
                    return Err(EngineError::UnexpectedMessage);
                }

                if self.is_validator(&sender) && pubkey_to_address(&pubkey) == sender {
                    let mut trans_flag = false;
                    let mut add_flag = false;
                    let now = Instant::now();

                    //deal with equal height,and round fall behind
                    if h == self.height && r < self.round {
                        let res = self.send_filter.get_mut(&sender);
                        if let Some(val) = res {
                            let (fround, fstep, ins) = *val;
                            if r > fround || (fround == r && step > fstep) {
                                add_flag = true;
                                //for re_transe msg for lag node
                                if r < self.round {
                                    trans_flag = true;
                                }
                            } else if fround == r
                                && step == fstep
                                && now - ins
                                    > self.params.timer.get_prevote()
                                        * TIMEOUT_LOW_ROUND_MESSAGE_MULTIPLE
                            {
                                add_flag = true;
                                trans_flag = true;
                            }
                        } else {
                            add_flag = true;
                        }
                    }

                    if add_flag {
                        self.send_filter.insert(sender, (r, step, now));
                    }
                    if trans_flag {
                        self.retrans_vote(h, r, step);
                        return Err(EngineError::UnexpectedMessage);
                    }

                    /*bellow commit content is suit for when chain not syncing ,but consensus need
                    process up */
                    if h > self.height || (h == self.height && r >= self.round) {
                        debug!(
                            "handle_message get vote: \
                             height {}, \
                             round {}, \
                             step {}, \
                             sender {:?}, \
                             hash {:?}, \
                             signature {} ",
                            h, r, step, sender, hash, signature
                        );
                        let ret = self.votes.add(
                            h,
                            r,
                            step,
                            sender,
                            &VoteMessage {
                                proposal: hash,
                                signature,
                            },
                        );
                        if ret {
                            if wal_flag {
                                self.wal_log.save(h, LogType::Vote, &log_msg).unwrap();
                            }
                            if h > self.height {
                                return Err(EngineError::VoteMsgForth(h));
                            }
                            return Ok((h, r, step));
                        }

                        return Err(EngineError::DoubleVote(sender));
                    }
                }
            }
        }
        Err(EngineError::UnexpectedMessage)
    }

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
                        return false;
                    }
                } else if !proof.check(height - 1, &self.auth_manage.validators) {
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
                    msg.try_into().unwrap(),
                ))
                .unwrap();
            self.unverified_msg
                .insert((vheight, vround), (csp_msg, VerifiedBlockStatus::Init(0)));
        }
        verify_ok
    }

    fn handle_proposal(
        &mut self,
        body: &[u8],
        wal_flag: bool,
        need_verify: bool,
    ) -> Result<(usize, usize), EngineError> {
        trace!(
            "handle_proposal {} begin wal_flag: {}, need_verify: {}",
            self,
            wal_flag,
            need_verify
        );
        let mut hash_v0_20_x = None;
        let mut csp_msg = if let Ok(csp_msg) = Message::try_from(body) {
            csp_msg
        } else {
            return Err(EngineError::UnexpectedMessage);
        };
        let result = csp_msg.clone().take_compact_signed_proposal().or_else(|| {
            // Only process the old version proposals from wal
            if !wal_flag {
                SignedProposal::try_from(body)
                    .ok()
                    .and_then(|signed_proposal| {
                        let message: Vec<u8> = signed_proposal.get_proposal().try_into().unwrap();
                        // Calculate hash with full signed proposal
                        hash_v0_20_x = Some(message.crypt_hash());
                        csp_msg = signed_proposal.compact().into();
                        csp_msg.clone().take_compact_signed_proposal()
                    })
            } else {
                None
            }
        });
        if let Some(compact_signed_proposal) = result {
            let signature = {
                let signature = compact_signed_proposal.get_signature();
                if signature.len() != SIGNATURE_BYTES_LEN {
                    return Err(EngineError::InvalidSignature);
                }
                Signature::from(signature)
            };
            let compact_proposal = compact_signed_proposal.get_proposal().clone();
            let hash = if let Some(hash) = hash_v0_20_x {
                hash
            } else {
                let message: Vec<u8> = (&compact_proposal).try_into().unwrap();
                message.crypt_hash()
            };
            trace!("handle_proposal {} message {:?}", self, hash);
            if let Ok(pubkey) = signature.recover(&hash) {
                let height = compact_proposal.get_height() as usize;
                let round = compact_proposal.get_round() as usize;
                if height < self.height
                    || (height == self.height && round < self.round)
                    || (height == self.height
                        && round == self.round
                        && self.step > Step::ProposeWait)
                {
                    debug!("handle_proposal {} get old proposal", self);
                    return Err(EngineError::VoteMsgDelay(height));
                }

                trace!(
                    "handle_proposal {} h: {}, r: {}, sender: {:?}",
                    self,
                    height,
                    round,
                    pubkey_to_address(&pubkey)
                );
                let compact_block = compact_proposal.clone().take_block();

                if need_verify && !self.verify_req(csp_msg, &compact_block, height, round) {
                    warn!("handle_proposal {} verify_req is error", self);
                    return Err(EngineError::InvalidTxInProposal);
                }

                let ret = self.is_round_proposer(height, round, &pubkey_to_address(&pubkey));
                if ret.is_err() {
                    warn!("handle_proposal {} is_round_proposer {:?}", self, ret);
                    return Err(ret.err().unwrap());
                }

                if (height == self.height && round >= self.round) || height > self.height {
                    if wal_flag {
                        self.wal_log.save(height, LogType::Propose, body).unwrap();
                    }
                    debug!(
                        "handle_proposal {} add proposal h: {}, r: {}",
                        self, height, round
                    );
                    let blk = compact_block.try_into().unwrap();
                    let mut lock_round = None;
                    let lock_votes = if compact_proposal.get_islock() {
                        lock_round = Some(compact_proposal.get_lock_round() as usize);
                        let mut vote_set = VoteSet::new();
                        for vote in compact_proposal.get_lock_votes() {
                            vote_set.add(
                                Address::from_slice(vote.get_sender()),
                                &VoteMessage {
                                    proposal: Some(H256::from_slice(vote.get_proposal())),
                                    signature: Signature::from(vote.get_signature()),
                                },
                            );
                        }
                        Some(vote_set)
                    } else {
                        None
                    };

                    let proposal = Proposal {
                        block: blk,
                        lock_round,
                        lock_votes,
                    };

                    self.proposals.add(height, round, proposal);

                    if height > self.height {
                        return Err(EngineError::VoteMsgForth(height));
                    }
                    return Ok((height, round));
                }
            }
        }
        Err(EngineError::UnexpectedMessage)
    }

    fn clean_saved_info(&mut self) {
        self.proposal = None;
        self.lock_round = None;
        self.locked_vote = None;
        self.locked_block = None;
        self.last_commit_round = None;
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

    fn clean_filter_info(&mut self) {
        self.send_filter.clear();
    }

    fn clean_proposal_when_verify_failed(&mut self) {
        let height = self.height;
        let round = self.round;
        self.clean_saved_info();
        self.pub_and_broadcast_message(height, round, Step::Prevote, Some(H256::default()));
        self.pub_and_broadcast_message(height, round, Step::Precommit, Some(H256::default()));
        self.change_state_step(height, round, Step::Precommit, false);
        self.proc_precommit(height, round);
    }

    pub fn new_proposal(&mut self) {
        let proposal = if let Some(lock_round) = self.lock_round {
            let lock_block = self.locked_block.clone().unwrap();
            let lock_vote = &self.locked_vote;
            {
                let lock_block_hash = lock_block.crypt_hash();
                self.proposal = Some(lock_block_hash);
                info!("new_proposal proposal lock block {:?}", self);
            }
            let blk = lock_block.try_into().unwrap();
            trace!("new_proposal {} proposer vote locked block", self);
            Proposal {
                block: blk,
                lock_round: Some(lock_round),
                lock_votes: lock_vote.clone(),
            }
        } else {
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
                    block.set_body(blocktxs.take_body());
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

            let proof = self.proof.clone();
            if proof.is_default() && self.height > INIT_HEIGHT {
                info!("new_proposal {} there is no proof", self);
                return;
            }
            if self.height > INIT_HEIGHT && proof.height != self.height - 1 {
                info!(
                    "new_proposal {} proof is old; proof height {}",
                    self, proof.height
                );
                return;
            }
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
            {
                self.proposal = Some(bh);
                self.locked_block = Some(block.clone().compact());
            }
            let blk = block.clone().compact().try_into().unwrap();
            // If we publish a proposal block, the block is verified by auth, already.
            self.verified_blocks.insert(bh, block);
            trace!(
                "new_proposal {} pub proposal proposor vote myslef in not locked",
                self
            );
            Proposal {
                block: blk,
                lock_round: None,
                lock_votes: None,
            }
        };
        let bmsg = self.pub_proposal(&proposal);
        self.wal_log
            .save(self.height, LogType::Propose, &bmsg)
            .unwrap();
        self.proposals.add(self.height, self.round, proposal);
    }

    pub fn timeout_process(&mut self, tminfo: &TimeoutInfo) {
        trace!(
            "timeout_process {} tminfo: {}, wait {:?}",
            self,
            tminfo,
            Instant::now() - self.htime
        );

        if self.get_snapshot() {
            info!("snapshotting...");
            return;
        }

        if tminfo.height < self.height {
            return;
        }
        if tminfo.height == self.height
            && tminfo.round < self.round
            && tminfo.step != Step::CommitWait
        {
            return;
        }
        if tminfo.height == self.height
            && tminfo.round == self.round
            && tminfo.step != self.step
            && tminfo.step != Step::CommitWait
        {
            return;
        }
        if tminfo.step == Step::ProposeWait {
            let pres = self.proc_proposal(tminfo.height, tminfo.round);
            if !pres {
                trace!(
                    "timeout_process {} proc_proposal failed; tminfo: {}",
                    self,
                    tminfo
                );
            }
            self.pre_proc_prevote();
            self.change_state_step(tminfo.height, tminfo.round, Step::Prevote, false);
            //one node need this
            {
                self.proc_prevote(tminfo.height, tminfo.round);
            }
        } else if tminfo.step == Step::Prevote {
            self.pre_proc_prevote();
        } else if tminfo.step == Step::PrevoteWait {
            if self.pre_proc_precommit() {
                self.change_state_step(tminfo.height, tminfo.round, Step::Precommit, false);
                self.proc_precommit(tminfo.height, tminfo.round);
            } else {
                self.change_state_step(tminfo.height, tminfo.round, Step::PrecommitAuth, false);
                let now = Instant::now();
                let _ = self.timer_seter.send(TimeoutInfo {
                    timeval: now + (self.params.timer.get_prevote() * TIMEOUT_RETRANSE_MULTIPLE),
                    height: tminfo.height,
                    round: tminfo.round,
                    step: Step::PrecommitAuth,
                });
            }
        } else if tminfo.step == Step::PrecommitAuth {
            let mut wait_too_many_times = false;
            // If consensus doesn't receive the result of block verification in a specific
            // time-frame, use the original message to construct a request, then resend it to auth.
            if let Some((csp_msg, result)) =
                self.unverified_msg.get_mut(&(tminfo.height, tminfo.round))
            {
                if let VerifiedBlockStatus::Init(ref mut times) = *result {
                    trace!("wait for the verification result {} times", times);
                    if *times >= 3 {
                        error!("do not wait for the verification result again");
                        wait_too_many_times = true;
                    } else {
                        let verify_req = csp_msg
                            .clone()
                            .take_compact_signed_proposal()
                            .unwrap()
                            .create_verify_block_req();
                        let mut msg: Message = verify_req.into();
                        msg.set_origin(csp_msg.get_origin());
                        self.pub_sender
                            .send((
                                routing_key!(Consensus >> VerifyBlockReq).into(),
                                msg.try_into().unwrap(),
                            ))
                            .unwrap();
                        let now = Instant::now();
                        let _ = self.timer_seter.send(TimeoutInfo {
                            timeval: now
                                + (self.params.timer.get_prevote() * TIMEOUT_RETRANSE_MULTIPLE),
                            height: tminfo.height,
                            round: tminfo.round,
                            step: Step::PrecommitAuth,
                        });
                        *times += 1;
                    };
                } else {
                    warn!("already get verified result {:?}", *result);
                }
            };
            // If waited the result of verification for a long while, we consider it was failed.
            if wait_too_many_times {
                self.clean_proposal_when_verify_failed();
            }
        } else if tminfo.step == Step::Precommit {
            /*in this case,need resend prevote : my net server can be connected but other node's
            server not connected when staring.  maybe my node receive enough vote(prevote),but others
            did not receive enough vote,so even if my node step precommit phase, i need resend prevote also.
            */
            self.pre_proc_prevote();
            self.pre_proc_precommit();
        } else if tminfo.step == Step::PrecommitWait {
            if self.pre_proc_commit(tminfo.height, tminfo.round) {
                /*wait for new status*/
                self.change_state_step(tminfo.height, tminfo.round, Step::Commit, false);
            } else {
                // clean the param if not locked
                if self.lock_round.is_none() {
                    self.clean_saved_info();
                }
                self.change_state_step(tminfo.height, tminfo.round + 1, Step::Propose, false);
                self.redo_work();
            }
        } else if tminfo.step == Step::CommitWait {
            let res = self.proc_commit_after(tminfo.height, tminfo.round);
            if res {
                self.htime = Instant::now();
                self.redo_work();
            }
        }
    }

    pub fn process(&mut self, info: TransType) {
        let (key, body) = info;
        let rtkey = RoutingKey::from(&key);
        let mut msg = Message::try_from(&body[..]).unwrap();
        let from_broadcast = rtkey.is_sub_module(SubModules::Net);
        let snapshot = !self.get_snapshot();
        if from_broadcast && self.consensus_power && snapshot {
            match rtkey {
                routing_key!(Net >> CompactSignedProposal) => {
                    let res = self.handle_proposal(&body[..], true, true);
                    if let Ok((h, r)) = res {
                        trace!(
                            "process {} recieve handle_proposal ok; h: {}, r: {}",
                            self,
                            h,
                            r,
                        );
                        if h == self.height && r == self.round && self.step < Step::Prevote {
                            self.step = Step::ProposeWait;
                            let now = Instant::now();
                            let _ = self.timer_seter.send(TimeoutInfo {
                                timeval: now + Duration::new(0, 0),
                                height: h,
                                round: r,
                                step: Step::ProposeWait,
                            });
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
                    let res = self.handle_message(&raw_bytes[..], true);

                    if let Ok((h, r, s)) = res {
                        if s == Step::Prevote {
                            self.proc_prevote(h, r);
                        } else {
                            self.proc_precommit(h, r);
                        }
                    }
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

                    if validators.contains(&self.params.signer.address) {
                        self.consensus_power = true;
                    } else {
                        info!(
                            "address[{:?}] is not consensus power !",
                            self.params.signer.address
                        );
                        self.consensus_power = false;
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
                    let resp = msg.take_verify_block_resp().unwrap();

                    let block = resp.get_block();
                    let vheight = resp.get_height() as usize;
                    let vround = resp.get_round() as usize;

                    let verify_res = if resp.get_pass() {
                        // Save the verified block which has passed verification by the auth.
                        self.verified_blocks
                            .insert(block.crypt_hash(), block.clone());
                        VerifiedBlockStatus::Ok
                    } else {
                        VerifiedBlockStatus::Err
                    };

                    if let Some(res) = self.unverified_msg.get_mut(&(vheight, vround)) {
                        res.1 = verify_res;
                        let block_bytes: Vec<u8> = block.try_into().unwrap();
                        let msg = serialize(
                            &(vheight, vround, verify_res.value(), block_bytes),
                            Infinite,
                        )
                        .unwrap();
                        let _ = self.wal_log.save(vheight, LogType::VerifiedBlock, &msg);
                        // Send SignedProposal to executor.
                        if let Some(compact_signed_proposal) =
                            res.0.clone().take_compact_signed_proposal()
                        {
                            let signed_proposal = compact_signed_proposal
                                .complete(block.get_body().get_transactions().to_vec());
                            let msg: Message = signed_proposal.into();
                            self.pub_sender
                                .send((
                                    routing_key!(Consensus >> SignedProposal).into(),
                                    msg.try_into().unwrap(),
                                ))
                                .unwrap();
                        }
                    };

                    info!(
                        "process {} recieve Auth VerifyBlockResp h: {}, r: {}, resp: {:?}",
                        self, vheight, vround, verify_res,
                    );
                    if vheight == self.height && vround == self.round {
                        //verify not ok,so clean the proposal info
                        if verify_res.is_ok() {
                            if self.step == Step::PrecommitAuth && self.pre_proc_precommit() {
                                self.change_state_step(vheight, vround, Step::Precommit, false);
                                self.proc_precommit(vheight, vround);
                            }
                        } else {
                            self.clean_proposal_when_verify_failed();
                        }
                    }
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
                    let _ = self.wal_log.save(height, LogType::AuthTxs, &msg);
                    let now_height = self.height;
                    let now_round = self.round;
                    let now_step = self.step;
                    if now_height == height + 1
                        && self
                            .is_round_proposer(now_height, now_round, &self.params.signer.address)
                            .is_ok()
                        && now_step == Step::ProposeWait
                        && self.proposal.is_none()
                    {
                        self.new_proposal();
                        let now = Instant::now();
                        let _ = self.timer_seter.send(TimeoutInfo {
                            timeval: now + Duration::new(0, 0),
                            height: now_height,
                            round: now_round,
                            step: Step::ProposeWait,
                        });
                    }
                }
                routing_key!(Snapshot >> SnapshotReq) => {
                    self.process_snapshot(msg);
                }
                _ => {}
            }
        }
    }

    fn process_snapshot(&mut self, mut msg: Message) {
        if let Some(req) = msg.take_snapshot_req() {
            match req.cmd {
                Cmd::Snapshot => {
                    info!("receive Snapshot::Snapshot: {:?}", req);
                    snapshot_response(&self.pub_sender, Resp::SnapshotAck, true);
                }
                Cmd::Begin => {
                    info!("receive Snapshot::Begin: {:?}", req);
                    self.set_snapshot(true);
                    self.is_cleared = false;
                    snapshot_response(&self.pub_sender, Resp::BeginAck, true);
                }
                Cmd::Restore => {
                    info!("receive Snapshot::Restore: {:?}", req);
                    snapshot_response(&self.pub_sender, Resp::RestoreAck, true);
                }
                Cmd::Clear => {
                    info!("receive Snapshot::Clear: {:?}", req);
                    let walpath = DataPath::wal_path();
                    let tmp_path = DataPath::root_node_path() + "/wal_tmp";
                    self.wal_log = Wal::create(&*tmp_path).unwrap();
                    let _ = fs::remove_dir_all(&walpath);
                    self.wal_log = Wal::create(&*walpath).unwrap();
                    let _ = fs::remove_dir_all(&tmp_path);

                    self.is_cleared = true;

                    snapshot_response(&self.pub_sender, Resp::ClearAck, true);
                }
                Cmd::End => {
                    info!("receive Snapshot::End: {:?}", req);
                    if self.is_cleared {
                        self.consensus_power = false;
                        self.clean_verified_info(0);
                        self.clean_saved_info();
                        self.clean_filter_info();
                        self.block_txs.clear();
                        self.proposals.proposals.clear();
                        self.votes.votes.clear();
                        self.proof = BftProof::from(req.get_proof().clone());
                        self.pre_hash = None;
                        self.block_proof = None;
                        self.change_state_step(
                            req.end_height as usize,
                            0,
                            Step::PrecommitAuth,
                            true,
                        );
                        self.save_wal_proof(req.end_height as usize);
                    }

                    self.set_snapshot(false);
                    self.is_cleared = false;

                    snapshot_response(&self.pub_sender, Resp::EndAck, true);
                }
            }
        }
    }

    fn receive_new_status(&mut self, status: &RichStatus) {
        let status_height = status.height as usize;
        self.params.timer.set_total_duration(status.interval);

        let height = self.height;
        let round = self.round;
        let step = self.step;
        trace!(
            "receive_new_status {} receive height {}",
            self,
            status_height,
        );
        if height > 0 && status_height + 1 < height {
            return;
        }

        let pre_hash = H256::from_slice(&status.hash);
        if height > 0 && status_height + 1 == height {
            // try efforts to save previous hash,when current block is not commit to chain
            if step < Step::CommitWait {
                self.pre_hash = Some(pre_hash);
            }

            // commit timeout since pub block to chain,so resending the block
            if step >= Step::Commit {
                if let Some((hi, ref bproof)) = self.block_proof {
                    if hi == height {
                        self.pub_block(bproof);
                    }
                }
            }
            return;
        }
        let new_round = if status_height == height {
            self.pre_hash = Some(pre_hash);
            self.round
        } else {
            INIT_ROUND
        };
        // try my effor to save proof,when I skipping commit_blcok by the chain sending new status.
        if self.proof.height != height {
            if let Some(hash) = self.proposal {
                let res = self.generate_proof(height, round, hash);
                if let Some(proof) = res {
                    self.proof = proof;
                }
            }
        }

        let cost_time = Instant::now() - self.htime;
        let mut tv = self.params.timer.get_commit();
        let interval = Duration::from_millis(status.interval);
        if height > status_height {
            tv = Duration::new(0, 0);
        } else if cost_time < interval {
            tv = interval - cost_time;
        }

        self.change_state_step(status_height, new_round, Step::CommitWait, false);
        info!(
            "receive_new_status {} get new chain status h: {}, r: {}, cost time: {:?}",
            self, status_height, new_round, cost_time
        );
        let now = Instant::now();
        let _ = self.timer_seter.send(TimeoutInfo {
            timeval: now + tv,
            height: status_height,
            round: new_round,
            step: Step::CommitWait,
        });
    }

    fn new_round_start(&mut self, height: usize, round: usize) {
        let coef = {
            if round > MAX_PROPOSAL_TIME_COEF {
                MAX_PROPOSAL_TIME_COEF
            } else {
                round
            }
        };
        let mut tv = self.params.timer.get_propose() * 2u32.pow(coef as u32);
        if self.proposals.get_proposal(height, round).is_some() {
            tv = Duration::new(0, 0);
        } else if self
            .is_round_proposer(height, round, &self.params.signer.address)
            .is_ok()
        {
            self.new_proposal();
            tv = Duration::new(0, 0);
        }
        //if is proposal,enter prevote stage immedietly
        self.step = Step::ProposeWait;
        let now = Instant::now();
        let _ = self.timer_seter.send(TimeoutInfo {
            timeval: now + tv,
            height,
            round,
            step: Step::ProposeWait,
        });
    }

    pub fn redo_work(&mut self) {
        let height = self.height;
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
        }
    }

    fn load_wal_log(&mut self) {
        let vec_buf = self.wal_log.load();
        for (mtype, vec_out) in vec_buf {
            let log_type: LogType = mtype.into();
            trace!("load_wal_log {} type {:?}({})", self, log_type, mtype);
            match log_type {
                LogType::Skip => {}
                LogType::Propose => {
                    let res = self.handle_proposal(&vec_out[..], false, true);
                    if let Ok((h, r)) = res {
                        let pres = self.proc_proposal(h, r);
                        if !pres {
                            trace!(
                                "load_wal_log {} proc_proposal failed h: {}, r: {}",
                                self,
                                h,
                                r
                            );
                        }
                    }
                }
                LogType::Vote => {
                    let res = self.handle_message(&vec_out[..], false);
                    if let Ok((h, r, s)) = res {
                        if s == Step::Prevote {
                            self.proc_prevote(h, r);
                        } else {
                            self.proc_precommit(h, r);
                        }
                    }
                }
                LogType::State => {
                    self.handle_state(&vec_out[..]);
                }
                LogType::PrevHash => {
                    let pre_hash = H256::from_slice(&vec_out);
                    self.pre_hash = Some(pre_hash);
                }
                LogType::Commits => {
                    trace!("load_wal_log {} wal proof begin", self);
                    if let Ok(proof) = deserialize(&vec_out) {
                        trace!("load_wal_log {} wal proof: {:?}", self, proof);
                        self.proof = proof;
                    }
                }
                LogType::VerifiedPropose => {
                    trace!("load_wal_log {} LogType::VerifiedPropose begin", self);
                    if let Ok(decode) = deserialize(&vec_out) {
                        let (vheight, vround, verified): (usize, usize, i8) = decode;
                        let status: VerifiedBlockStatus = verified.into();
                        if status.is_ok() {
                            self.unverified_msg.remove(&(vheight, vround));
                        } else {
                            self.clean_saved_info();
                        }
                    }
                }
                LogType::VerifiedBlock => {
                    trace!(" LogType::VerifiedBlock begining!");
                    if let Ok(decode) = deserialize(&vec_out) {
                        let (vheight, vround, verified, bytes): (usize, usize, i8, Vec<u8>) =
                            decode;
                        let status: VerifiedBlockStatus = verified.into();
                        let block = Block::try_from(&bytes).unwrap();
                        if status.is_ok() {
                            self.verified_blocks.insert(block.crypt_hash(), block);
                            self.unverified_msg.remove(&(vheight, vround));
                        } else {
                            self.clean_saved_info();
                        }
                    }
                }
                LogType::AuthTxs => {
                    trace!("load_wal_log {} LogType::AuthTxs begin", self);
                    let blocktxs = BlockTxs::try_from(&vec_out);
                    if let Ok(blocktxs) = blocktxs {
                        let height = blocktxs.get_height() as usize;
                        trace!(
                            "load_wal_log {} LogType::AuthTxs add height: {}",
                            self,
                            height
                        );
                        self.block_txs.push_back((height, blocktxs));
                    }
                }
            }
        }
    }

    pub fn start(&mut self) {
        self.load_wal_log();
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

fn snapshot_response(sender: &Sender<(String, Vec<u8>)>, ack: Resp, flag: bool) {
    info!("snapshot_response ack: {:?}, flag: {}", ack, flag);

    let mut resp = SnapshotResp::new();
    resp.set_resp(ack);
    resp.set_flag(flag);
    let msg: Message = resp.into();
    sender
        .send((
            routing_key!(Consensus >> SnapshotResp).into(),
            (&msg).try_into().unwrap(),
        ))
        .unwrap();
}
