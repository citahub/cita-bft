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

use authority_manage::AuthorityManage;
use bft_rs::algorithm::Step;
use bft_rs::{BftMsg, Commit, Feed, Proposal as BftProposal, Status as BftStatus, Vote as BftVote};
use bincode::{deserialize, Infinite, serialize};
use core::collector::{ProposalCollector, VoteCollector, CACHE_NUMBER};
use core::error::BftError;
use core::transform::*;
use core::wal::Wal;
use crossbeam::crossbeam_channel::{Receiver as CrossReceiver, Sender as CrossSender};
use crypto::{CreateKey, pubkey_to_address, Sign, Signature, SIGNATURE_BYTES_LEN, Signer};
use engine::{AsMillis, unix_now};
use libproto::blockchain::{Block, BlockTxs, BlockWithProof, Transaction};
use libproto::{auth, Message, RawBytes};
use libproto::consensus::{Proposal as ProtoProposal, SignedProposal, Vote as ProtoVote};
use libproto::router::{MsgType, RoutingKey, SubModules};
use proof::BftProof;
use std::collections::{HashMap, VecDeque};
use std::convert::{Into, TryFrom, TryInto};
use std::str::FromStr;
use std::sync::mpsc::Sender;

use types::{Address, clean_0x, H256};
use util::datapath::DataPath;
use util::{BLOCKLIMIT, Hashable};

const INIT_HEIGHT: usize = 1;
//const TIMEOUT_OF_LOW_ROUND_VOTE: u64 = 1000;
const LOG_TYPE_SIGNED_PROPOSAL: u8 = 1;
const LOG_TYPE_RAW_BYTES: u8 = 2;
const LOG_TYPE_RICH_STATUS: u8 = 3;
const LOG_TYPE_BLOCK_TXS: u8 = 4;
const LOG_TYPE_VERIFY_BLOCK_PESP: u8 = 5;
const LOG_TYPE_PROPOSAL: u8 = 6;
const LOG_TYPE_VOTE: u8 = 7;
const LOG_TYPE_COMMIT: u8 = 8;

pub type BftResult<T> = Result<T, BftError>;
pub type RabMsg = (String, Vec<u8>);

pub enum MixMsg {
    RabMsg(RabMsg),
    BftMsg(BftMsg),
}

pub struct Bft {
    cita2rab: Sender<RabMsg>,
    cita2bft: CrossSender<BftMsg>,
    receiver: CrossReceiver<MixMsg>,
    signer: Signer,
    height: usize,
    proof: BftProof,
    pre_hash: Option<H256>,
    votes: VoteCollector,
    proposals: ProposalCollector,
    verified_proposals: Vec<H256>,
    wal_log: Wal,
    auth_manage: AuthorityManage,
    consensus_power: bool,
    feed_block: VecDeque<(usize, Block)>,
//    vote_recv_filter: HashMap<Address, (usize, Step, Instant)>,
}

impl ::std::fmt::Debug for Bft {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "Bft {{address: {:?}, height: {}, proof: {:?}, pre_hash: {:?}, consensus_power: {:?}}}",
            self.signer.address,
            self.height,
            self.proof,
            self.pre_hash,
            self.consensus_power,
        )
    }
}

impl ::std::fmt::Display for Bft {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "Bft {{address: {:?}, height: {}, consensus_power: {}}}",
            self.signer.address, self.height, self.consensus_power,
        )
    }
}

impl Bft {
    pub fn new(
        cita2rab: Sender<RabMsg>,
        cita2bft: CrossSender<BftMsg>,
        receiver: CrossReceiver<MixMsg>,
        signer: Signer,
    ) -> Bft {
        let wal_path = DataPath::wal_path();
        Bft {
            cita2rab,
            cita2bft,
            receiver,
            signer,
            height: INIT_HEIGHT,
            proof: BftProof::default(),
            pre_hash: None,
            votes: VoteCollector::new(),
            proposals: ProposalCollector::new(),
            verified_proposals: Vec::new(),
            wal_log: Wal::new(&*wal_path).unwrap(),
            auth_manage: AuthorityManage::new(),
            consensus_power: false,
            feed_block: VecDeque::new(),
//            vote_recv_filter: HashMap::new(),
        }
    }

    pub fn start(&mut self) -> BftResult<()>{
        self.load_wal_log()?;
        loop {
            match self.receiver.recv() {
                Ok(msg) => {
                    let _ = self.process(msg)?;
                }
                _ => {}
            }
        }
    }

    fn process(&mut self, msg: MixMsg) -> BftResult<()>{
        match msg {
            MixMsg::RabMsg(msg) => {
                let (key, body) = msg;
                let msg_type = RoutingKey::from(&key);
                let mut msg = Message::try_from(body).unwrap();
                let from_broadcast = msg_type.is_sub_module(SubModules::Net);
                if from_broadcast && self.consensus_power {
                    match msg_type {
                        routing_key!(Net >> SignedProposal) => {
                            let proposal = self.handle_signed_proposal(msg, true)?;
                            self.cita2bft.send(BftMsg::Proposal(proposal)).unwrap();
                        }

                        routing_key!(Net >> RawBytes) => {
                            let vote = self.handle_raw_bytes(msg, true)?;
                            self.cita2bft.send(BftMsg::Vote(vote)).unwrap();
                        }

                        _ => {}
                    }
                } else {
                    match msg_type {
                        routing_key!(Chain >> RichStatus) => {
                            let status = self.handle_rich_status(msg, true)?;
                            self.cita2bft.send(BftMsg::Status(status)).unwrap();
                            let height = self.height;//ProposalRoundCollector
                            let mut proposals = self.proposals.proposals.clone();
                            let mut round_proposals = proposals.get_mut(&height);
                            if let Some(round_proposals) = round_proposals {
                                for (_, signed_proposal) in round_proposals.round_proposals.clone().into_iter() {
                                    let proposal = self.handle_proposal_in_cache(signed_proposal)?;
                                    self.cita2bft.send(BftMsg::Proposal(proposal)).unwrap();
                                }
                            };

                            let mut votes = self.votes.votes.clone();
                            let mut round_votes = votes.get_mut(&height);
                            if let Some(round_votes) = round_votes {
                                for (_, step_votes) in round_votes.round_votes.iter() {
                                    for (_, vote_set) in step_votes.step_votes.iter() {
                                        for (bft_vote, _) in vote_set.vote_pair.iter() {
                                            let sender = Address::from_slice(&bft_vote.voter);
                                            self.check_raw_bytes_sender(height, &sender)?;
                                            let bft_vote: BftVote = bft_vote.clone();
                                            self.cita2bft.send(BftMsg::Vote(bft_vote)).unwrap();
                                        }
                                    }

                                }
                            }
                        }

                        routing_key!(Auth >> BlockTxs) => {
                            let feed = self.handle_block_txs(msg, true)?;
                            self.cita2bft.send(BftMsg::Feed(feed)).unwrap();
                        }

                        routing_key!(Auth >> VerifyBlockResp) => {
                            let proposal = self.handle_verify_block_resp(msg, true)?;
                            self.cita2bft.send(BftMsg::Proposal(proposal)).unwrap();
                        }

                        _ => {}
                    }
                }
            },
            MixMsg::BftMsg(msg) => {
                match msg {
                    BftMsg::Proposal(proposal) => {
                        let signed_proposal = self.handle_proposal(proposal, true)?;
                        self.cita2rab.send((
                            routing_key!(Consensus >> SignedProposal).into(),
                            signed_proposal.try_into().unwrap(),
                        )).unwrap();

                    }

                    BftMsg::Vote(vote) => {
                        let signed_vote = self.handle_vote(vote, true)?;
                        self.cita2rab.send((
                            routing_key!(Consensus >> RawBytes).into(),
                            signed_vote.try_into().unwrap(),
                        )).unwrap();
                    }

                    BftMsg::Commit(commit) => {
                        let block_with_proof = self.handle_commit(commit, true)?;
                        self.cita2rab.send((
                            routing_key!(Consensus >> BlockWithProof).into(),
                            block_with_proof.try_into().unwrap(),
                        )).unwrap();
                    }

                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn handle_signed_proposal(&mut self, mut msg: Message, need_wal: bool) -> BftResult<BftProposal> {
        let signed_proposal = msg.take_signed_proposal().unwrap();
        let signature = signed_proposal.get_signature();
        check_signature_len(signature)?;

        let proto_proposal = signed_proposal.get_proposal();
        let height = proto_proposal.get_height() as usize;
        let round = proto_proposal.get_round() as usize;
        if height < self.height - 1 {
            return Err(BftError::ObsoleteSignedProposal);
        }

        let signature = Signature::from(signature);
        let message: Vec<u8> = proto_proposal.try_into().unwrap();
        let hash = message.crypt_hash();
        let address = check_signature(&signature, &hash)?;

        let block = proto_proposal.get_block();
        check_block_txs(block, height)?;

        if height >= self.height {
            if height - self.height < CACHE_NUMBER {
                if need_wal {
                    let msg: Vec<u8> = msg.try_into().unwrap();
                    self.wal_log.save(height, LOG_TYPE_SIGNED_PROPOSAL, &msg).unwrap();
                }
                self.proposals.add(height, round, &signed_proposal);
            }
            if height > self.height {
                return Err(BftError::HigherProposal);
            }
        }
        let bft_proposal = extract_bft_proposal(&signed_proposal);

        self.check_proposer(height, round, &address)?;
        self.check_lock_votes(&proto_proposal, &hash)?;

        if height < self.height {
            return Ok(bft_proposal);
        }

        let block_hash = block.crypt_hash();
        if self.verified_proposals.contains(&block_hash) {
            return Ok(bft_proposal);
        }

        self.check_pre_hash(height, block)?;
        self.check_proof(height, block)?;
        let transactions = block.get_body().get_transactions();
        if transactions.len() == 0 {
            return Ok(bft_proposal);
        }
        self.send_auth_for_validation(block, height, round)?;
        Err(BftError::WaitForAuthValidation)
    }

    fn handle_proposal_in_cache(&mut self, signed_proposal: SignedProposal) -> BftResult<BftProposal> {
        let proto_proposal = signed_proposal.get_proposal();
        let signature = signed_proposal.get_signature();
        let height = proto_proposal.get_height() as usize;
        let round = proto_proposal.get_round() as usize;

        let signature = Signature::from(signature);
        let message: Vec<u8> = proto_proposal.try_into().unwrap();
        let hash = message.crypt_hash();
        let address = check_signature(&signature, &hash)?;

        self.check_proposer(height, round, &address)?;
        self.check_lock_votes(&proto_proposal, &hash)?;

        let bft_proposal = extract_bft_proposal(&signed_proposal);
        let block = proto_proposal.get_block();
        let block_hash = block.crypt_hash();
        if self.verified_proposals.contains(&block_hash) {
            return Ok(bft_proposal);
        }

        self.check_pre_hash(height, block)?;
        self.check_proof(height, block)?;
        let transactions = block.get_body().get_transactions();
        if transactions.len() == 0 {
            return Ok(bft_proposal);
        }
        self.send_auth_for_validation(block, height, round)?;
        Err(BftError::WaitForAuthValidation)
    }

    fn handle_verify_block_resp(&mut self, mut msg: Message, need_wal: bool) -> BftResult<BftProposal> {
        let resp = msg.take_verify_block_resp().unwrap();
        if resp.get_ret() != auth::Ret::OK {
            return Err(BftError::AuthVerifyFailed);
        }
        let verify_id = resp.get_id();
        let (height, round) = get_idx_from_reqid(verify_id);
        let height = height as usize;
        let round = round as usize;
        if height < self.height {
            return Err(BftError::ObsoleteVerifyBlockResp);
        }
        if need_wal {
            let msg: Vec<u8> = msg.try_into().unwrap();
            self.wal_log.save(height, LOG_TYPE_VERIFY_BLOCK_PESP, &msg).unwrap();
        }
        let signed_proposal = self.proposals.get_proposal(height, round).unwrap();
        let bft_proposal = extract_bft_proposal(&signed_proposal);
        let hash = H256::from_slice(&(bft_proposal.content));
        self.verified_proposals.push(hash);
        Ok(bft_proposal)
    }

    fn handle_raw_bytes(&mut self, mut msg: Message, need_wal: bool) -> BftResult<BftVote> {
        let raw_bytes = msg.take_raw_bytes().unwrap();
        let decoded = deserialize(&raw_bytes).unwrap();
        let (message, signature): (Vec<u8>, &[u8]) = decoded;
        check_signature_len(&signature)?;

        let signature = Signature::from(signature);
        let hash = message.crypt_hash();
        let address = check_signature(&signature, &hash)?;

        let decoded = deserialize(&message[..]).unwrap();
        let (height, round, step, sender, _):(u64, u64, Step, Vec<u8>, Vec<u8>) = decoded;
        let height = height as usize;
        let round = round as usize;
        let sender = Address::from_slice(&sender);
        if height < self.height - 1 {
            return Err(BftError::ObsoleteRawBytes);
        }
        if sender != address {
            return Err(BftError::MismatchingVoter);
        }

        let bft_vote = extract_bft_vote(&raw_bytes);
        let signed_vote = extract_signed_vote(&raw_bytes);

        if height >= self.height {
            if height - self.height < CACHE_NUMBER {
                if need_wal {
                    let msg: Vec<u8> = msg.try_into().unwrap();
                    self.wal_log.save(height, LOG_TYPE_RAW_BYTES, &msg).unwrap();
                }
                self.votes.add(height, round, step, &bft_vote, &signed_vote);
            }
            if height > self.height {
                return Err(BftError::HigherRawBytes);
            }
        }

        self.check_raw_bytes_sender(height, &sender)?;
        if height < self.height {
            return Ok(bft_vote);
        }
    //        self.check_filter(sender, round, step)?;
        Ok(bft_vote)
    }

    fn handle_block_txs(&mut self, mut msg: Message, need_wal: bool) -> BftResult<Feed> {
        let block_txs = msg.take_block_txs().unwrap();
        let height = block_txs.get_height() as usize;
        if height < self.height - 1 {
            return Err(BftError::ObsoleteBlockTxs);
        }
        if need_wal {
            let msg: Vec<u8> = msg.try_into().unwrap();
            self.wal_log.save(height, LOG_TYPE_BLOCK_TXS, &msg).unwrap();
        }
        let block = self.build_feed_block(block_txs)?;
        self.feed_block.push_back((height, block.clone()));
        let feed = extract_feed(&block);
        Ok(feed)
    }

    fn handle_rich_status(&mut self, mut msg: Message, need_wal: bool) -> BftResult<BftStatus> {
        let rich_status = msg.take_rich_status().unwrap();
        let height = rich_status.height as usize;
        if height < self.height {
            return Err(BftError::ObsoleteRichStatus);
        }
        if need_wal {
            let msg: Vec<u8> = msg.try_into().unwrap();
            self.wal_log.save(height, LOG_TYPE_RICH_STATUS, &msg).unwrap();
        }
        let pre_hash = H256::from_slice(&rich_status.hash);
        self.pre_hash = Some(pre_hash);

        let authorities: Vec<Address> = rich_status.get_nodes().into_iter().map(
            |node| Address::from_slice(node)).collect();
        self.auth_manage
            .receive_authorities_list(self.height, authorities.clone());

        if authorities.contains(&self.signer.address) {
            self.consensus_power = true;
        } else {
            self.consensus_power = false;
        }

        self.set_new_height(height)?;
        let bft_status = extract_bft_status(&rich_status);
        Ok(bft_status)
    }

    fn handle_proposal(&mut self, proposal: BftProposal, need_wal: bool) -> BftResult<SignedProposal> {
        let height = proposal.height;
        let round = proposal.round;
        if height < self.height {
            return Err(BftError::ObsoleteBftProposal);
        }
        if need_wal {
            let msg: Vec<u8> = serialize(&(proposal), Infinite).unwrap();
            self.wal_log.save(height, LOG_TYPE_PROPOSAL, &msg).unwrap();
        }
        let signed_proposal = self.build_signed_proposal(proposal)?;
        self.proposals.add(height, round, &signed_proposal);
        Ok(signed_proposal)
    }

    fn handle_vote(&mut self, vote: BftVote, need_wal: bool) -> BftResult<RawBytes> {
        let height = vote.height;
        if height < self.height {
            return Err(BftError::ObsoleteBftVote);
        }
        if need_wal {
            let msg: Vec<u8> = serialize(&(vote), Infinite).unwrap();
            self.wal_log.save(height, LOG_TYPE_VOTE, &msg).unwrap();
        }
        let raw_bytes = self.build_raw_bytes(vote.clone())?;
        let signed_vote = extract_signed_vote(&raw_bytes);
        self.votes.add(height, vote.round, vote.vote_type, &vote, &signed_vote);
        Ok(raw_bytes)
    }

    fn handle_commit(&mut self, commit: Commit, need_wal: bool) -> BftResult<BlockWithProof>{
        let height = commit.height;
        if height < self.height {
            return Err(BftError::ObsoleteCommit);
        }
        if need_wal {
            let msg: Vec<u8> = serialize(&(commit), Infinite).unwrap();
            self.wal_log.save(height, LOG_TYPE_COMMIT, &msg).unwrap();
        }
        let block_with_proof = self.build_block_with_proof(commit)?;
        Ok(block_with_proof)
    }

    fn build_raw_bytes(&mut self, vote: BftVote) -> BftResult<RawBytes>{
        let author = &self.signer;
        let msg = serialize(&(vote.height as u64, vote.round as u64, vote.vote_type, vote.voter, vote.proposal), Infinite).unwrap();
        let signature = Signature::sign(author.keypair.privkey(), &msg.crypt_hash()).unwrap();
        let sig = signature.clone();
        let msg = serialize(&(msg, sig), Infinite).unwrap();
        let raw_bytes: RawBytes = msg.try_into().unwrap();
        Ok(raw_bytes)
    }

    fn build_block_with_proof(&mut self, commit: Commit) -> BftResult<BlockWithProof>{
        let height = commit.height;
        let round = commit.round;
        let signed_proposal = self.proposals.get_proposal(height, round).unwrap();
        let block = signed_proposal.get_proposal().get_block();
        let hash = block.crypt_hash();
        let lock_votes = commit.lock_votes;
        let proof = self.generate_proof(height, round, hash, lock_votes)?;
        self.proof = proof.clone();

        let mut block_with_proof = BlockWithProof::new();
        block_with_proof.set_blk(block.clone());
        block_with_proof.set_proof(proof.into());
        Ok(block_with_proof)
    }

    fn generate_proof(&mut self, height: usize, round: usize, hash: H256, lock_votes: Vec<BftVote>) -> BftResult<BftProof> {
        let mut commits = HashMap::<Address, Signature>::new();
        {
            let vote_set = self.votes.get_vote_set(height, round, Step::Precommit);
            if let Some(vote_set) = vote_set {
                for vote in lock_votes {
                    if let Some(signed_vote) = vote_set.vote_pair.get(&vote) {
                        let sender = Address::from_slice(&vote.voter);
                        commits.insert(sender, signed_vote.signature.clone());
                    } else {
                        return Err(BftError::GenerateProofFailed);
                    }
                }
            } else {
                return Err(BftError::GenerateProofFailed);
            }
        }
        let mut proof = BftProof::default();
        proof.height = height;
        proof.round = round;
        proof.proposal = hash;
        proof.commits = commits;
        Ok(proof)
    }

    fn build_signed_proposal(&mut self, proposal: BftProposal) -> BftResult<SignedProposal>{
        let height = proposal.height;
        let round = proposal.round;
        let mut block = Block::new();
        if let Some(lock_round) = proposal.lock_round {
            let signed_proposal = self.proposals.get_proposal(height, lock_round).unwrap();
            block = signed_proposal.get_proposal().get_block().clone();
        } else {
            for &(ref feed_height, ref feed_block) in &self.feed_block {
                if *feed_height == height {
                    block = feed_block.to_owned();
                }
            }
        };
        let mut proto_proposal = ProtoProposal::new();
        proto_proposal.set_block(block);
        proto_proposal.set_height(height as u64);
        proto_proposal.set_round(round as u64);
        if let Some(lock_round) = proposal.lock_round {
            proto_proposal.set_lock_round(lock_round as u64);
            let vote_set = self.votes.get_vote_set(height, round, Step::Prevote).unwrap();
            let mut votes = Vec::new();
            for vote in proposal.clone().lock_votes.unwrap() {
                let mut proto_vote = ProtoVote::new();
                let signed_vote = vote_set.vote_pair.get(&vote).unwrap();
                proto_vote.set_proposal(vote.proposal.to_vec());
                proto_vote.set_sender(vote.voter.to_vec());
                proto_vote.set_signature(signed_vote.signature.to_vec());
                votes.push(proto_vote);
            }
            proto_proposal.set_lock_votes(votes.into());
        }
        let message: Vec<u8> = (&proto_proposal).try_into().unwrap();
        let author = &self.signer;
        let signature = Signature::sign(author.keypair.privkey(), &message.crypt_hash()).unwrap();

        let mut signed_proposal = SignedProposal::new();
        signed_proposal.set_proposal(proto_proposal);
        signed_proposal.set_signature(signature.to_vec());
        Ok(signed_proposal)
    }

    fn set_new_height(&mut self, height: usize) -> BftResult<()>{
        self.verified_proposals.clear();
//        self.vote_recv_filter.clear();
        self.feed_block = self.feed_block.iter().filter(|&&(hi, _)| hi >= height)
            .cloned().collect();
        self.height = height + 1;
        if let Err(_) = self.wal_log.set_height(self.height){
            return Err(BftError::SetWalHeightFailed);
        };
        Ok(())
    }

    fn build_feed_block(&self, block_txs: BlockTxs) -> BftResult<Block>{
        let mut block = Block::new();
        block.set_body(block_txs.get_body().clone());
        if self.pre_hash.is_some() {
            block.mut_header().set_prevhash(self.pre_hash.unwrap().0.to_vec());
        } else {
            return Err(BftError::SelfPreHashNotReady);
        }
        let proof = self.proof.clone();
        if (proof.is_default() || proof.height != self.height - 1) && self.height > INIT_HEIGHT {
            return Err(BftError::SelfProofNotReady);
        }
        block.mut_header().set_proof(proof.into());

        let block_time = unix_now();
        let transactions_root = block.get_body().transactions_root();
        block.mut_header().set_timestamp(block_time.as_millis());
        block.mut_header().set_height(self.height as u64);
        block.mut_header().set_transactions_root(transactions_root.to_vec());
        block.mut_header().set_proposer(self.signer.address.to_vec());
        Ok(block)
    }

//    fn check_filter(&mut self, sender: Address, round: usize, step: Step) -> BftResult<()> {
//        let res = self.vote_recv_filter.get_mut(&sender);
//        let now = Instant::now();
//        let mut add_flag = false;
//        if let Some(val) = res {
//            let (f_round, f_step, ins) = *val;
//            if round > f_round || (f_round == round && step > f_step) {
//                add_flag = true;
//            } else if f_round == round && step == f_step && now - ins > Duration::from_millis(TIMEOUT_OF_LOW_ROUND_VOTE)
//                {
//                    add_flag = true;
//                }
//        } else {
//            add_flag = true;
//        }
//
//        if add_flag {
//            self.vote_recv_filter.insert(sender, (round, step, now));
//            return Ok(());
//        }
//        Err(BftError::RawBytesReceivedFrequently)
//    }

    fn send_auth_for_validation(&mut self, block: &Block, height: usize, round: usize) -> BftResult<()>  {
        if height != self.height {
            return Err(BftError::ShouldNotHappen);
        }
        let reqid = gen_reqid_from_idx(height as u64, round as u64);
        let verify_req = block.block_verify_req(reqid);
        let msg: Message = verify_req.into();
        self.cita2rab
            .send((
                routing_key!(Consensus >> VerifyBlockReq).into(),
                (&msg).try_into().unwrap(),
            ))
            .unwrap();
        Ok(())
    }


    fn load_wal_log(&mut self) -> BftResult<()>{
        let vec_buf = self.wal_log.load();
        for (msg_type, msg) in vec_buf {
            match msg_type {
                LOG_TYPE_SIGNED_PROPOSAL => {
                    let msg = Message::try_from(msg).unwrap();
                    self.handle_signed_proposal(msg, false)?;
                }
                LOG_TYPE_RAW_BYTES => {
                    let msg = Message::try_from(msg).unwrap();
                    self.handle_raw_bytes(msg, false)?;
                }
                LOG_TYPE_RICH_STATUS => {
                    let msg = Message::try_from(msg).unwrap();
                    self.handle_rich_status(msg, false)?;
                }
                LOG_TYPE_BLOCK_TXS => {
                    let msg = Message::try_from(msg).unwrap();
                    self.handle_block_txs(msg, false)?;
                }
                LOG_TYPE_VERIFY_BLOCK_PESP => {
                    let msg = Message::try_from(msg).unwrap();
                    self.handle_verify_block_resp(msg, false)?;
                }
                LOG_TYPE_PROPOSAL => {
                    let proposal = deserialize(&msg[..]).unwrap();
                    self.handle_proposal(proposal, false)?;
                }
                LOG_TYPE_VOTE => {
                    let vote = deserialize(&msg[..]).unwrap();
                    self.handle_vote(vote, false)?;
                }
                LOG_TYPE_COMMIT => {
                    let commit = deserialize(&msg[..]).unwrap();
                    self.handle_commit(commit, false)?;
                }
                _ => {}
            }
        }

        Ok(())
    }


    fn check_proposer(&self, height: usize, round: usize, address: &Address) -> BftResult<()> {
        if height < self.height - 1 {
            return Err(BftError::ShouldNotHappen);
        }
        let p = &self.auth_manage;
        let mut authority_n = &p.authority_n;
        let mut authorities = &p.authorities;
        if height == *(&p.authority_h_old) {
            authority_n = &p.authority_n_old;
            authorities = &p.authorities_old;
        }
        if *authority_n == 0 {
            return Err(BftError::EmptyAuthManage);
        }
        let proposer_nonce = height + round;
        let proposer: &Address = authorities.get(proposer_nonce % authority_n).expect(
            "Counting proposer failed!",
        );
        if proposer == address {
            Ok(())
        } else {
            Err(BftError::InvalidProposer)
        }
    }

    fn check_raw_bytes_sender(&self, height: usize, sender: &Address) -> BftResult<()> {
        if height < self.height - 1 {
            return Err(BftError::ShouldNotHappen);
        }
        let p = &self.auth_manage;
        let mut authorities = &p.authorities;
        if height == *(&p.authority_h_old) {
            authorities = &p.authorities_old;
        }
        if !authorities.contains(sender) {
            return Err(BftError::InvalidVoter);
        }
        Ok(())
    }

    fn check_pre_hash(&self, height: usize, block: &Block) -> BftResult<()> {
        if height != self.height {
            return Err(BftError::ShouldNotHappen);
        }
        if let Some(hash) = self.pre_hash {
            let mut block_prehash = Vec::new();
            block_prehash.extend_from_slice(block.get_header().get_prevhash());
            if hash != H256::from(block_prehash.as_slice()) {
                return Err(BftError::MisMatchingPreHash);
            }
            return Ok(());
        }
        Err(BftError::EmptySelfPreHash)
    }

    fn check_proof(&mut self, height: usize, block: &Block) -> BftResult<()> {
        if height != self.height {
            return Err(BftError::ShouldNotHappen);
        }
        let block_proof = block.get_header().get_proof();
        let proof = BftProof::from(block_proof.clone());

        if self.auth_manage.authority_h_old == height - 1 {
            if !proof.check(height - 1, &self.auth_manage.authorities_old) {
                return Err(BftError::InvalidProof);
            }
        } else if !proof.check(height - 1, &self.auth_manage.authorities) {
            return Err(BftError::InvalidProof);
        }

        if self.proof.height != height - 1 {
            self.proof = proof;
        }
        Ok(())
    }

    fn check_lock_votes(&mut self, proto_proposal: &ProtoProposal, proposal_hash: &H256) -> BftResult<()> {
        let height = proto_proposal.get_height() as usize;
        if height < self.height - 1 {
            return Err(BftError::ShouldNotHappen);
        }

        let round = proto_proposal.get_round() as usize;

        let mut map = HashMap::new();
        if proto_proposal.get_islock() {
            for vote in proto_proposal.get_lock_votes() {
                let sender = self.check_proto_vote(height, round, proposal_hash, &vote)?;
                if let Some(_) = map.insert(sender, 1) {
                    return Err(BftError::RepeatLockVote);
                }
            }
        }

        let p = &self.auth_manage;
        let mut authority_n = p.authority_n;
        if height == *(&p.authority_h_old) {
            authority_n = p.authority_n_old;
        }

        if map.len() * 3 > authority_n * 2 {
            return Ok(());
        }
        Err(BftError::NotEnoughVotes)
    }

    fn check_proto_vote(&mut self, height: usize, round: usize, proposal_hash: &H256, vote: &ProtoVote) -> BftResult<Address> {
        if height < self.height - 1 {
            return Err(BftError::ShouldNotHappen);
        }

        let p = &self.auth_manage;
        let mut authorities = &p.authorities;
        if height == *(&p.authority_h_old) {
            authorities = &p.authorities_old;
        }

        let hash = H256::from_slice(vote.get_proposal());
        if hash != *proposal_hash {
            return Err(BftError::MismatchingVoteProposal);
        }

        let sender = Address::from_slice(vote.get_sender());
        if !authorities.contains(&sender) {
            return Err(BftError::InvalidVoter);
        }

        let signature = vote.get_signature();
        check_signature_len(signature)?;
        let message = serialize(&(height as u64, round as u64, Step::Prevote, sender, proposal_hash), Infinite).unwrap();
        let hash = message.crypt_hash();
        let signature = Signature::from(signature);
        let address = check_signature(&signature, &hash)?;
        if address != sender {
            return Err(BftError::MismatchingVoter);
        }

        let msg = serialize(&(message, signature), Infinite).unwrap();
        let raw_bytes: RawBytes = msg.try_into().unwrap();
        let bft_vote = extract_bft_vote(&raw_bytes);
        let signed_vote = extract_signed_vote(&raw_bytes);
        self.votes.add(height, round, Step::Prevote, &bft_vote, &signed_vote);

        Ok(sender)
    }
}

fn gen_reqid_from_idx(h: u64, r: u64) -> u64 {
    ((h & 0xffff_ffff_ffff) << 16) | r
}

fn get_idx_from_reqid(reqid: u64) -> (u64, u64) {
    (reqid >> 16, reqid & 0xffff)
}

fn check_signature_len(signature: &[u8]) -> BftResult<()> {
    let len = signature.len();
    if len != SIGNATURE_BYTES_LEN {
        return Err(BftError::InvalidSigLen);
    }
    Ok(())
}

fn check_signature(signature: &Signature, hash: &H256) -> BftResult<Address> {
    if let Ok(pubkey) = signature.recover(hash) {
        let address = pubkey_to_address(&pubkey);
        return Ok(address);
    }
    Err(BftError::InvalidSignature)
}

fn check_block_txs(block: &Block, height: usize) -> BftResult<()> {
    let transactions = block.get_body().get_transactions();
    let verify_ok = block.check_hash();
    if !verify_ok {
        return Err(BftError::TransactionRootCheckFailed);
    }
    for tx in transactions.into_iter() {
        check_tx(tx.get_transaction(), height as u64)?;
    }
    Ok(())
}

fn check_tx(tx: &Transaction, height: u64) -> BftResult<()> {
    let to = clean_0x(tx.get_to());
    if !to.is_empty() && Address::from_str(to).is_err() {
        return Err(BftError::InvalidTxTo);
    }
    let nonce = tx.get_nonce();
    if nonce.len() > 128 {
        return Err(BftError::InvalidTxNonce);
    }
    let valid_until_block = tx.get_valid_until_block();
    if height > valid_until_block || valid_until_block >= (height + BLOCKLIMIT) {
        return Err(BftError::InvalidUtilBlock);
    }
    Ok(())
}

#[inline]
fn safe_unwrap_result<T, E>(result: Result<T, E>, err: BftError) -> BftResult<T> {
    if let Ok(value) = result {
        return Ok(value);
    }
    Err(err)
}

#[inline]
fn safe_unwrap_option<T>(option: Option<T>, err: BftError) -> BftResult<T> {
    if let Some(value) = option {
        return Ok(value);
    }
    Err(err)
}