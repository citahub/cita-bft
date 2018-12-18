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

use std::convert::{Into, TryFrom, TryInto};

use authority_manage::AuthorityManage;
use bincode::{deserialize, serialize, Infinite};

use core::params::BftParams;
use core::voteset::{
    verify_tx, verify_tx_version, Proposal, ProposalCollector, VoteCollector, VoteMessage, VoteSet,
};

use core::votetime::TimeoutInfo;
use core::wal::{LogType, Wal};

use crypto::{pubkey_to_address, CreateKey, Sign, Signature, SIGNATURE_BYTES_LEN};
use engine::{unix_now, AsMillis, EngineError, Mismatch};
use libproto::blockchain::{Block, BlockTxs, BlockWithProof, RichStatus};
use libproto::consensus::{Proposal as ProtoProposal, SignedProposal, Vote as ProtoVote};
use libproto::router::{MsgType, RoutingKey, SubModules};
use libproto::snapshot::{Cmd, Resp, SnapshotResp};
use libproto::{auth, Message, Origin, ZERO_ORIGIN};
use proof::BftProof;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::sync::mpsc::{Receiver, RecvError, Sender};
use std::time::{Duration, Instant};

use cita_directories::DataPath;
use hashable::Hashable;
use types::{Address, H256};

const INIT_HEIGHT: usize = 1;
const INIT_ROUND: usize = 0;

const MAX_PROPOSAL_TIME_COEF: usize = 10;

const TIMEOUT_RETRANSE_MULTIPLE: u32 = 15;
const TIMEOUT_LOW_ROUND_MESSAGE_MULTIPLE: u32 = 20;

pub type TransType = (String, Vec<u8>);
pub type PubType = (String, Vec<u8>);

#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
enum VerifiedProposalStatus {
    Ok = 1,
    Failed = -1,
    Undo = 0,
}

impl From<i8> for VerifiedProposalStatus {
    fn from(s: i8) -> VerifiedProposalStatus {
        match s {
            1 => VerifiedProposalStatus::Ok,
            -1 => VerifiedProposalStatus::Failed,
            0 => VerifiedProposalStatus::Undo,
            _ => panic!("Invalid VerifiedProposalStatus."),
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

fn gen_reqid_from_idx(h: u64, r: u64) -> u64 {
    ((h & 0xffff_ffff_ffff) << 16) | r
}

fn get_idx_from_reqid(reqid: u64) -> (u64, u64) {
    (reqid >> 16, reqid & 0xffff)
}

pub struct Bft {
    pub_sender: Sender<PubType>,
    pub_receiver: Receiver<TransType>,

    timer_seter: Sender<TimeoutInfo>,
    timer_notify: Receiver<TimeoutInfo>,

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
    locked_block: Option<Block>,
    wal_log: Wal,
    send_filter: HashMap<Address, (usize, Step, Instant)>,
    last_commit_round: Option<usize>,
    htime: Instant,
    auth_manage: AuthorityManage,
    consensus_power: bool,
    //params meaning: key :index 0->height,1->round ,value:0->verified msg,1->verified result
    unverified_msg: BTreeMap<(usize, usize), (Message, VerifiedProposalStatus)>,
    // VecDeque might work, Almost always it is better to use Vec or VecDeque instead of LinkedList
    block_txs: VecDeque<(usize, BlockTxs)>,
    block_proof: Option<(usize, BlockWithProof)>,

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
        r: Receiver<TransType>,
        ts: Sender<TimeoutInfo>,
        rs: Receiver<TimeoutInfo>,
        params: BftParams,
    ) -> Bft {
        let proof = BftProof::default();

        let logpath = DataPath::wal_path();
        Bft {
            pub_sender: s,
            pub_receiver: r,
            timer_seter: ts,
            timer_notify: rs,

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
            wal_log: Wal::new(&*logpath).unwrap(),
            send_filter: HashMap::new(),
            last_commit_round: None,
            htime: Instant::now(),
            auth_manage: AuthorityManage::new(),
            consensus_power: false,
            unverified_msg: BTreeMap::new(),
            block_txs: VecDeque::new(),
            block_proof: None,
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

    pub fn pub_proposal(&self, proposal: &Proposal) -> Vec<u8> {
        let mut proto_proposal = ProtoProposal::new();
        let pro_block = Block::try_from(&proposal.block).unwrap();
        proto_proposal.set_block(pro_block);
        proto_proposal.set_islock(proposal.lock_round.is_some());
        proto_proposal.set_round(self.round as u64);
        proto_proposal.set_height(self.height as u64);
        let is_lock = proposal.lock_round.is_some();
        if is_lock {
            proto_proposal.set_lock_round(proposal.lock_round.unwrap() as u64);

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

            proto_proposal.set_lock_votes(votes.into());
        }

        let message: Vec<u8> = (&proto_proposal).try_into().unwrap();
        let author = &self.params.signer;
        let hash = message.crypt_hash();
        let signature = Signature::sign(author.keypair.privkey(), &hash).unwrap();
        trace!(
            "pub_proposal {} hash: {}, signature: {}",
            self,
            hash,
            signature
        );
        let mut signed_proposal = SignedProposal::new();
        signed_proposal.set_proposal(proto_proposal);
        signed_proposal.set_signature(signature.to_vec());

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
                            if op.is_some() {
                                let pro_block = Block::try_from(&op.unwrap().block);
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

                if self.step == Step::Prevote {
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

    fn get_proposal_verified_result(&self, height: usize, round: usize) -> VerifiedProposalStatus {
        self.unverified_msg
            .get(&(height, round))
            .map_or(VerifiedProposalStatus::Ok, |res| res.1)
    }

    fn pre_proc_precommit(&mut self) -> bool {
        let height = self.height;
        let round = self.round;
        let proposal = self.proposal;
        let mut lock_ok = false;

        let verify_ok = self.get_proposal_verified_result(height, round);
        if let Some(lround) = self.lock_round {
            trace!("pre_proc_precommit {} locked round {}", self, lround);
            if lround == round {
                lock_ok = true;
            }
        }
        //polc is ok,but not verified , not send precommit
        if lock_ok && verify_ok == VerifiedProposalStatus::Undo {
            return false;
        }

        if lock_ok && verify_ok == VerifiedProposalStatus::Ok {
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

                if self.step == Step::Precommit {
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
                    return self.commit_block();
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
                //generate proof
                let mut get_proof = Some(self.proof.clone());

                let gen_flag = if self.proof.height != height {
                    get_proof = self.generate_proof(height, round, hash);
                    true
                } else {
                    false
                };

                if let Some(proof) = get_proof {
                    if gen_flag {
                        self.proof = proof.clone();
                    }
                    self.save_wal_proof(height + 1);

                    let mut proof_blk = BlockWithProof::new();
                    let blk = self.locked_block.clone();
                    proof_blk.set_blk(blk.unwrap());
                    proof_blk.set_proof(proof.into());

                    // saved for retranse blockwithproof to chain
                    self.block_proof = Some((height, proof_blk.clone()));
                    info!(
                        "commit_block {} consensus time {:?}",
                        self,
                        Instant::now() - self.htime
                    );
                    self.pub_block(&proof_blk);
                    return true;
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
            trace!("proc_proposal {} begin h: {}, r: {}", self, height, round,);
            if !proposal.check(height, &self.auth_manage.validators) {
                warn!("proc proposal check authorities error");
                return false;
            }
            //height 1's block not have prehash
            if let Some(hash) = self.pre_hash {
                //prehash : self.prehash vs  proposal's block's prehash
                let block = Block::try_from(&proposal.block).unwrap();
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
                // else use proposal block，self.lock_round is none
                let block = Block::try_from(&proposal.block).unwrap();
                let block_hash = block.crypt_hash();
                self.proposal = Some(block_hash);
                debug!("proc_proposal save the proposal's hash {:?}", self);
                self.locked_block = Some(block);
            }
            return true;
        }
        false
    }

    fn verify_version(&self, block: &Block) -> bool {
        if self.version.is_none() {
            warn!("verify_version {} self.version is none", self,);
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
            return false;
        }
        let transactions = block.get_body().get_transactions();
        let len = transactions.len();
        if len == 0 {
            return true;
        }
        transactions.into_iter().all(|tx| {
            let raw_tx = tx.get_transaction();
            let result = verify_tx_version(raw_tx, version);
            if !result {
                warn!(
                    "verify_version {} failed, tx version: {}, current chain version: {}",
                    self,
                    raw_tx.get_version(),
                    version
                );
            }
            result
        })
    }

    fn verify_req(&mut self, origin: Origin, block: &Block, vheight: usize, vround: usize) -> bool {
        let transactions = block.get_body().get_transactions();
        if transactions.is_empty() {
            return true;
        }
        let verify_ok = block.check_hash() && transactions.into_iter().all(|tx| {
            let raw_tx = tx.get_transaction();
            let result = verify_tx(raw_tx, vheight as u64);
            if !result {
                warn!(
                    "verify_req {} verify tx in proposal failed, tx {{ nonce: {}, valid_until_block: {} }}, proposal h: {}, r: {}",
                    self,
                    raw_tx.get_nonce(),
                    raw_tx.get_valid_until_block(),
                    vheight, vround
                );
            }
            result
        });
        if verify_ok {
            let reqid = gen_reqid_from_idx(vheight as u64, vround as u64);
            let verify_req = block.block_verify_req(reqid);
            trace!(
                "verify_req {} send block with {} txs; h: {}, r: {}, id: {}",
                self,
                transactions.len(),
                vheight,
                vround,
                reqid,
            );
            let mut msg: Message = verify_req.into();
            msg.set_origin(origin);
            self.pub_sender
                .send((
                    routing_key!(Consensus >> VerifyBlockReq).into(),
                    (&msg).try_into().unwrap(),
                ))
                .unwrap();
            self.unverified_msg
                .insert((vheight, vround), (msg, VerifiedProposalStatus::Undo));
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
        // compatibility with v0.20.x
        let result = Message::try_from(body)
            .ok()
            .and_then(|mut msg| msg.take_signed_proposal().map(|p| (p, msg.get_origin())))
            .or_else(|| {
                SignedProposal::try_from(body)
                    .ok()
                    .map(|p| (p, ZERO_ORIGIN))
            });
        if let Some((signed_proposal, origin)) = result {
            let signature = signed_proposal.get_signature();
            if signature.len() != SIGNATURE_BYTES_LEN {
                return Err(EngineError::InvalidSignature);
            }
            let signature = Signature::from(signature);

            let proto_proposal = signed_proposal.get_proposal();
            let message: Vec<u8> = proto_proposal.try_into().unwrap();
            let hash = message.crypt_hash();
            trace!("handle_proposal {} message {:?}", self, hash);
            if let Ok(pubkey) = signature.recover(&hash) {
                let height = proto_proposal.get_height() as usize;
                let round = proto_proposal.get_round() as usize;
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
                let block = proto_proposal.clone().take_block();

                if need_verify && !self.verify_req(origin, &block, height, round) {
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
                    let blk = block.try_into().unwrap();
                    let mut lock_round = None;
                    let lock_votes = if proto_proposal.get_islock() {
                        lock_round = Some(proto_proposal.get_lock_round() as usize);
                        let mut vote_set = VoteSet::new();
                        for vote in proto_proposal.get_lock_votes() {
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

    // use iter + cloned, do not copy all block_txs
    fn clean_block_txs(&mut self) {
        let height = self.height - 1;
        self.block_txs = self
            .block_txs
            .iter()
            .filter(|&&(hi, _)| hi >= height)
            .cloned()
            .collect();
    }

    fn clean_filter_info(&mut self) {
        self.send_filter.clear();
    }

    pub fn new_proposal(&mut self) {
        let proposal = if let Some(lock_round) = self.lock_round {
            let lock_blk = &self.locked_block;
            let lock_vote = &self.locked_vote;
            let lock_blk = lock_blk.clone().unwrap();
            {
                let lock_blk_hash = lock_blk.crypt_hash();
                self.proposal = Some(lock_blk_hash);
                info!("new_proposal proposal lock block {:?}", self);
            }
            let blk = lock_blk.try_into().unwrap();
            trace!("new_proposal {} proposer vote locked block", self,);
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

            for &(ref height, ref blocktxs) in &self.block_txs {
                trace!(
                    "new_proposal BLOCKTXS get height {}, self height {}",
                    *height,
                    self.height
                );
                if *height == self.height - 1 {
                    flag = true;
                    block.set_body(blocktxs.get_body().clone());
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
                "new_proposal {} proposal new block: block hash {:?}",
                self, bh
            );
            {
                self.proposal = Some(bh);
                self.locked_block = Some(block.clone());
            }
            let blk = block.try_into().unwrap();
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
            if let Some((msg, res)) = self.unverified_msg.get(&(tminfo.height, tminfo.round)) {
                if *res == VerifiedProposalStatus::Undo {
                    self.pub_sender
                        .send((
                            routing_key!(Consensus >> VerifyBlockReq).into(),
                            msg.try_into().unwrap(),
                        ))
                        .unwrap();
                } else {
                    warn!("already get verified resutl {:?}", *res);
                }
            };
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
                routing_key!(Net >> SignedProposal) => {
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
                        .into_iter()
                        .map(|node| Address::from_slice(node))
                        .collect();
                    trace!("authorities: [{:?}]", authorities);

                    let validators: Vec<Address> = rich_status
                        .get_validators()
                        .into_iter()
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
                    self.auth_manage
                        .receive_authorities_list(self.height, authorities, validators);
                    let version = rich_status.get_version();
                    trace!("verison: {}", version);
                    self.version = Some(version);
                }

                routing_key!(Auth >> VerifyBlockResp) => {
                    let resp = msg.take_verify_block_resp().unwrap();
                    let verify_id = resp.get_id();
                    let (vheight, vround) = get_idx_from_reqid(verify_id);
                    let vheight = vheight as usize;
                    let vround = vround as usize;

                    let verify_res = if resp.get_ret() == auth::Ret::OK {
                        VerifiedProposalStatus::Ok
                    } else {
                        VerifiedProposalStatus::Failed
                    };

                    if let Some(res) = self.unverified_msg.get_mut(&(vheight, vround)) {
                        res.1 = verify_res;
                        let msg =
                            serialize(&(vheight, vround, verify_res as i8), Infinite).unwrap();
                        let _ = self.wal_log.save(vheight, LogType::VerifiedPropose, &msg);
                    };

                    info!(
                        "process {} recieve VerifyBlockResp verify_id: {}, h: {}, r: {}, resp: {:?}",
                        self, verify_id, vheight, vround, verify_res
                    );
                    if vheight == self.height && vround == self.round {
                        //verify not ok,so clean the proposal info
                        if verify_res == VerifiedProposalStatus::Ok {
                            if self.step == Step::PrecommitAuth && self.pre_proc_precommit() {
                                self.change_state_step(vheight, vround, Step::Precommit, false);
                                self.proc_precommit(vheight, vround);
                            }
                        } else {
                            self.clean_saved_info();
                            self.pub_and_broadcast_message(
                                vheight,
                                vround,
                                Step::Prevote,
                                Some(H256::default()),
                            );
                            self.pub_and_broadcast_message(
                                vheight,
                                vround,
                                Step::Precommit,
                                Some(H256::default()),
                            );
                            self.change_state_step(vheight, vround, Step::Precommit, false);
                            self.proc_precommit(vheight, vround);
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
            let mut resp = SnapshotResp::new();
            let mut send = false;
            match req.cmd {
                Cmd::Snapshot => {
                    info!("[snapshot] receive cmd: Snapshot");
                }
                Cmd::Begin => {
                    info!("[snapshot] receive cmd: Begin");
                    self.set_snapshot(true);
                    self.is_cleared = false;

                    resp.set_resp(Resp::BeginAck);
                    resp.set_flag(true);
                    send = true;
                }
                Cmd::Restore => {
                    info!("[snapshot] receive cmd: Restore");
                }
                Cmd::Clear => {
                    info!("[snapshot] receive cmd: Clear");
                    let walpath = DataPath::wal_path();
                    let tmp_path = DataPath::root_node_path() + "/wal_tmp";
                    self.wal_log = Wal::new(&*tmp_path).unwrap();
                    let _ = fs::remove_dir_all(&walpath);
                    self.wal_log = Wal::new(&*walpath).unwrap();
                    let _ = fs::remove_dir_all(&tmp_path);

                    self.is_cleared = true;

                    resp.set_resp(Resp::ClearAck);
                    resp.set_flag(true);
                    send = true;
                }
                Cmd::End => {
                    info!("[snapshot] receive cmd: End");
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

                    resp.set_resp(Resp::EndAck);
                    resp.set_flag(true);
                    send = true;
                }
            }

            if send {
                let msg: Message = resp.into();
                self.pub_sender
                    .send((
                        routing_key!(Consensus >> SnapshotResp).into(),
                        (&msg).try_into().unwrap(),
                    ))
                    .unwrap();
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
            "receive_new_status {} get new chain status h: {}, r: {}, cost time: {:?} ",
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

        trace!("redo_work {} begin", self);
        if self.step == Step::Propose || self.step == Step::ProposeWait {
            self.new_round_start(height, round);
        } else if self.step == Step::Prevote || self.step == Step::PrevoteWait {
            self.pre_proc_prevote();
            self.proc_prevote(height, round);
            let now = Instant::now();
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
            let now = Instant::now();
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
            }
        } else if self.step == Step::CommitWait {
        }
    }

    fn load_wal_log(&mut self) {
        let vec_buf = self.wal_log.load();
        for (mtype, vec_out) in vec_buf {
            trace!("load_wal_log {} type {}", self, mtype);
            let log_type: LogType = mtype.into();
            match log_type {
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
                        let status: VerifiedProposalStatus = verified.into();
                        if status == VerifiedProposalStatus::Ok {
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
            let mut gtm = Err(RecvError);
            let mut ginfo = Err(RecvError);

            {
                let tn = &self.timer_notify;
                let pn = &self.pub_receiver;
                select!{
                    tm = tn.recv() => {
                        gtm = tm;
                    },
                    info = pn.recv() => {
                        ginfo = info;
                    }
                }
            }

            if let Ok(oktm) = gtm {
                self.timeout_process(&oktm);
            }

            if let Ok(tinfo) = ginfo {
                self.process(tinfo);
            }
        }
    }
}
