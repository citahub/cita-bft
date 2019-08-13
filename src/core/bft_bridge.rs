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

use crate::core::params::PrivateKey;
use crate::types::{Address, H256};
use bft::{
    get_proposal_hash, Address as BftAddr, BftActuator, BftMsg, BftSupport, Block as BftBlock,
    Commit, Hash as BftHash, Height, Node, Proof, Round, Signature as BftSig, Status, VerifyResp,
};
use bincode::{serialize, Infinite};
use crypto::{pubkey_to_address, Sign, Signature, Signer, SIGNATURE_BYTES_LEN};
use hashable::Hashable;
use libproto::blockchain::{
    Block, BlockTxs, BlockWithProof, CompactBlock, Proof as ProtoProof, ProofType, RichStatus,
    SignedTransaction,
};
use libproto::router::{MsgType, RoutingKey, SubModules};
use libproto::snapshot::{Cmd, Resp, SnapshotResp};
use libproto::{auth, auth::VerifyBlockResp, Message, Origin, TryFrom, TryInto, ZERO_ORIGIN};
use lru_cache::LruCache;
use proof::BftProof;
use pubsub::channel::{select, Receiver, RecvError, Sender};
use std::collections::{HashMap, VecDeque};

use engine::{unix_now, AsMillis};

pub const ORIGIN_N: usize = 100;

pub type PubType = (String, Vec<u8>);

#[derive(Debug)]
pub enum BridgeMsg {
    CheckBlockReq(BftBlock, BftHash, BftHash, Height, Round, BftAddr),
    CheckBlockResp(Result<VerifyResp, BridgeError>),
    Transmit(BftMsg),
    CommitReq(Commit),
    CommitResp(Result<Status, BridgeError>),
    GetBlockReq(Height, Proof),
    GetBlockResp(Result<(BftBlock, BftHash), BridgeError>),
    SignReq(BftHash),
    SignResp(Result<BftSig, BridgeError>),
}

pub struct P2B {
    pub check_block: Sender<BridgeMsg>,
    pub commit: Sender<BridgeMsg>,
    pub get_block: Sender<BridgeMsg>,
    pub sign: Sender<BridgeMsg>,
}

pub struct Processor {
    p2b: P2B,
    p2r: Sender<PubType>,
    p4b: Receiver<BridgeMsg>,
    p4r: Receiver<PubType>,
    bft_actuator: BftActuator,

    signer: PrivateKey,
    address: BftAddr,

    proof: HashMap<Height, Proof>,
    pre_hash: HashMap<Height, H256>,
    version: HashMap<Height, u32>,

    get_block_reqs: VecDeque<Height>,
    check_tx_reqs: VecDeque<(Height, Round)>,
    commit_reqs: VecDeque<Height>,

    get_block_resps: HashMap<Height, BlockTxs>,
    check_tx_resps: HashMap<(Height, Round), VerifyBlockResp>,
    verified_txs: HashMap<Height, HashMap<H256, SignedTransaction>>,

    origins: LruCache<BftHash, Origin>,
}

impl Processor {
    pub fn start(&mut self) {
        loop {
            let mut get_rab_msg = Err(RecvError);
            let mut get_bridge_msg = Err(RecvError);

            select! {
                recv(self.p4r) -> msg => get_rab_msg = msg,
                recv(self.p4b) -> msg => get_bridge_msg = msg,
            }

            let mut result = Ok(());

            if let Ok((key, body)) = get_rab_msg {
                result = self.process_rab_msg(key, body);
            }

            if let Ok(bridge_msg) = get_bridge_msg {
                result = self.process_bridge_msg(bridge_msg);
            }

            handle_error(result);
        }
    }

    fn process_rab_msg(&mut self, key: String, body: Vec<u8>) -> Result<(), BftError> {
        let rt_key = RoutingKey::from(&key);
        let mut msg = Message::try_from(&body[..])
            .map_err(|e| BftError::TryFromFailed(format!("{:?} of Message", e)))?;
        match rt_key {
            routing_key!(Net >> CompactSignedProposal) => {
                let encode = msg.take_raw_bytes().ok_or_else(|| {
                    BftError::TakeRawBytesFailed("of signed_proposal".to_string())
                })?;

                if let Some(signed_proposal_hash) =
                    get_proposal_hash(&encode, |msg: &[u8]| -> BftHash {
                        msg.to_vec().crypt_hash().to_vec().into()
                    })
                {
                    let origin = msg.get_origin();
                    self.origins.insert(signed_proposal_hash, origin);
                }
                self.bft_actuator
                    .send(BftMsg::Proposal(encode))
                    .map_err(|e| {
                        BftError::SendMsgFailed(format!(
                            "{:?} of signed_proposal to bft_actuator",
                            e
                        ))
                    })?;
            }

            routing_key!(Net >> RawBytes) => {
                let encode = msg
                    .take_raw_bytes()
                    .ok_or_else(|| BftError::TakeRawBytesFailed("of signed_vote".to_string()))?;
                self.bft_actuator.send(BftMsg::Vote(encode)).map_err(|e| {
                    BftError::SendMsgFailed(format!("{:?} of signed_vote to bft_actuator", e))
                })?;
            }

            routing_key!(Chain >> RichStatus) => {
                let rich_status = msg
                    .take_rich_status()
                    .ok_or(BftError::TakeRichStatusFailed)?;
                let status = self.extract_status(rich_status);
                let status_height = status.height;

                let mut flag = true;
                let mut front_h = self.commit_reqs.front();
                while front_h.is_some() {
                    let req_height = *front_h.unwrap();
                    if req_height == status_height {
                        self.p2b
                            .commit
                            .send(BridgeMsg::CommitResp(Ok(status.clone())))
                            .map_err(|e| {
                                BftError::SendMsgFailed(format!(
                                    "{:?} of commit_resp to bft_bridge",
                                    e
                                ))
                            })?;
                        flag = false;
                    }
                    if req_height > status_height {
                        break;
                    }
                    self.commit_reqs.pop_front();
                    front_h = self.commit_reqs.front();
                }
                if flag {
                    self.bft_actuator
                        .send(BftMsg::Status(status))
                        .map_err(|e| {
                            BftError::SendMsgFailed(format!("{:?} of status to bft_actuator", e))
                        })?;
                }
            }

            routing_key!(Auth >> BlockTxs) => {
                let block_txs = msg.take_block_txs().ok_or(BftError::TakeBlockFailed)?;
                self.get_block_resps
                    .entry(block_txs.get_height() + 1)
                    .or_insert_with(|| block_txs);

                let mut front_h = self.get_block_reqs.pop_front();
                while front_h.is_some() {
                    self.try_feed_bft(front_h.unwrap())?;
                    front_h = self.get_block_reqs.pop_front();
                }
            }

            routing_key!(Auth >> VerifyBlockResp) => {
                let resp = msg
                    .take_verify_block_resp()
                    .ok_or(BftError::TakeVerifyBlockRespFailed)?;
                let height = resp.get_height();
                let round = resp.get_round();
                self.check_tx_resps
                    .entry((height, round))
                    .or_insert_with(|| resp.clone());
                let block = resp.get_block();
                self.insert_verified_txs(height, block);

                let mut front_h_r = self.check_tx_reqs.front();
                while front_h_r.is_some() {
                    let (req_height, req_round) = front_h_r.unwrap();

                    let verify_resp = self
                        .check_tx_resps
                        .get(&(*req_height, *req_round))
                        .ok_or_else(|| {
                            BftError::NotYetGetResp(format!(
                                "of check_tx_resps with height {}, round {}",
                                req_height, req_round
                            ))
                        })?;

                    self.p2b
                        .check_block
                        .send(BridgeMsg::CheckBlockResp(Ok(VerifyResp {
                            is_pass: verify_resp.get_pass(),
                            round: *req_round,
                        })))
                        .map_err(|e| {
                            BftError::SendMsgFailed(format!("{:?} of verify_resp to bft_bridge", e))
                        })?;
                    self.check_tx_reqs.pop_front();

                    front_h_r = self.check_tx_reqs.front();
                }
            }

            routing_key!(Snapshot >> SnapshotReq) => {
                let req = msg
                    .take_snapshot_req()
                    .ok_or(BftError::TakeSnapshotReqFailed)?;
                match req.cmd {
                    Cmd::Snapshot => {
                        info!("Processor receives Snapshot::Snapshot: {:?}", req);
                        self.snapshot_response(Resp::SnapshotAck, true)?;
                    }
                    Cmd::Begin => {
                        info!("Processor receives Snapshot::Begin: {:?}", req);
                        self.bft_actuator.send(BftMsg::Pause).map_err(|e| {
                            BftError::SendMsgFailed(format!("{:?} of pause to bft_actuator", e))
                        })?;
                        self.snapshot_response(Resp::BeginAck, true)?;
                    }
                    Cmd::Restore => {
                        info!("Processor receives Snapshot::Restore: {:?}", req);
                        self.snapshot_response(Resp::RestoreAck, true)?;
                    }
                    Cmd::Clear => {
                        info!("Processor receives Snapshot::Clear: {:?}", req);
                        self.snapshot_response(Resp::ClearAck, true)?;
                    }
                    Cmd::End => {
                        info!("Processor receives Snapshot::End: {:?}", req);
                        let proof = to_bft_proof(&BftProof::from(req.get_proof().clone()));
                        self.bft_actuator.send(BftMsg::Clear(proof)).map_err(|e| {
                            BftError::SendMsgFailed(format!("{:?} of clear to bft_actuator", e))
                        })?;
                        self.snapshot_response(Resp::EndAck, true)?;
                    }
                }
            }

            _ => {}
        }
        Ok(())
    }

    fn process_bridge_msg(&mut self, bridge_msg: BridgeMsg) -> Result<(), BftError> {
        match bridge_msg {
            BridgeMsg::GetBlockReq(height, proof) => {
                self.proof.entry(proof.height).or_insert_with(|| proof);
                self.get_block_reqs.push_back(height);
                self.try_feed_bft(height)?;
            }

            BridgeMsg::CheckBlockReq(
                block,
                block_hash,
                signed_proposal_hash,
                height,
                round,
                _proposer,
            ) => {
                if let Err(err) = self.check_block(&block, &block_hash, height) {
                    self.p2b
                        .check_block
                        .send(BridgeMsg::CheckBlockResp(Err(err)))
                        .map_err(|e| {
                            BftError::SendMsgFailed(format!(
                                "{:?} of check_block_resp to bft_bridge",
                                e
                            ))
                        })?;
                }

                let compact_block = CompactBlock::try_from(block.as_slice())
                    .map_err(|e| BftError::TryFromFailed(format!("{:?} of CompactBlock", e)))?;
                let tx_hashes = compact_block.get_body().transaction_hashes();

                if tx_hashes.is_empty() {
                    self.p2b
                        .check_block
                        .send(BridgeMsg::CheckBlockResp(Ok(VerifyResp {
                            is_pass: true,
                            round,
                        })))
                        .map_err(|e| {
                            BftError::SendMsgFailed(format!(
                                "{:?} of check_block_resp to bft_bridge",
                                e
                            ))
                        })?;
                } else {
                    let msg =
                        self.get_block_req_msg(compact_block, &signed_proposal_hash, height, round);
                    self.p2r
                        .send((
                            routing_key!(Consensus >> VerifyBlockReq).into(),
                            msg.clone().try_into().map_err(|e| {
                                BftError::TryIntoFailed(format!("{:?} of VerifyBlockReq", e))
                            })?,
                        ))
                        .unwrap();
                    self.check_tx_reqs.push_back((height, round));
                }
            }

            BridgeMsg::SignReq(hash) => {
                self.p2b
                    .sign
                    .send(BridgeMsg::SignResp(self.sign(&hash)))
                    .map_err(|e| {
                        BftError::SendMsgFailed(format!("{:?} of sign_resp to bft_bridge", e))
                    })?;
            }

            BridgeMsg::Transmit(bft_msg) => {
                self.transmit(bft_msg)?;
            }

            BridgeMsg::CommitReq(commit) => {
                self.commit_reqs.push_back(commit.height);
                self.commit(commit)?;
            }

            _ => {}
        }
        Ok(())
    }

    pub fn new(
        p2b: P2B,
        p2r: Sender<PubType>,
        p4b: Receiver<BridgeMsg>,
        p4r: Receiver<PubType>,
        bft_actuator: BftActuator,
        pk: PrivateKey,
    ) -> Self {
        let signer = Signer::from(pk.signer);
        let address = signer.address.to_vec();
        Processor {
            p2b,
            p2r,
            p4b,
            p4r,
            bft_actuator,
            signer: pk,
            address: address.into(),
            proof: HashMap::new(),
            pre_hash: HashMap::new(),
            version: HashMap::new(),
            get_block_reqs: VecDeque::new(),
            check_tx_reqs: VecDeque::new(),
            commit_reqs: VecDeque::new(),
            get_block_resps: HashMap::new(),
            check_tx_resps: HashMap::new(),
            verified_txs: HashMap::new(),
            origins: LruCache::new(ORIGIN_N),
        }
    }

    fn check_block(
        &self,
        block: &BftBlock,
        block_hash: &BftHash,
        height: Height,
    ) -> Result<(), BridgeError> {
        if height < 1 {
            return Err(BridgeError::CheckBlockFailed(format!(
                "block height {} is less than 1",
                height
            )));
        }

        let version = self.version.get(&(height - 1));
        let pre_hash = self.pre_hash.get(&(height - 1));
        if version.is_none() || pre_hash.is_none() {
            return Err(BridgeError::CheckBlockFailed(format!(
                "self.version {:?} or self.pre_hash {:?} is null",
                version, pre_hash
            )));
        }

        let compact_block = CompactBlock::try_from(block.as_slice())
            .map_err(|e| BridgeError::TryFromFailed(format!("{:?} of CompactBlock", e)))?;
        let blk_version = compact_block.get_version();
        if version.unwrap() != &blk_version {
            return Err(BridgeError::CheckBlockFailed(format!(
                "block version {} != self.version {:?}",
                blk_version, version
            )));
        }
        let hash = compact_block.crypt_hash().to_vec();
        if hash != block_hash.to_vec() {
            return Err(BridgeError::CheckBlockFailed(format!(
                "block hash {:?} != proposal's block_hash {:?}",
                &hash, block_hash
            )));
        }

        let header = compact_block.get_header();
        if height != header.height {
            return Err(BridgeError::CheckBlockFailed(format!(
                "block height {} != proposal height {}",
                header.height, height
            )));
        }

        let blk_pre_hash = H256::from_slice(&header.prevhash);
        if pre_hash.unwrap() != &blk_pre_hash {
            return Err(BridgeError::CheckBlockFailed(format!(
                "block pre_hash {:?} != self.pre_hash {:?}",
                blk_pre_hash, pre_hash
            )));
        }

        let transactions_root = compact_block.get_body().transactions_root().to_vec();
        if header.transactions_root != transactions_root {
            return Err(BridgeError::CheckBlockFailed(format!(
                "header transactions_root {:?} != calculate result {:?} from body",
                header.transactions_root, transactions_root
            )));
        }

        Ok(())
    }

    /// A funciton to transmit messages.
    fn transmit(&self, msg: BftMsg) -> Result<(), BftError> {
        match msg {
            BftMsg::Proposal(encode) => {
                trace!("Processor sends bft_signed_proposal{:?}", encode);
                let msg: Message = encode.into();
                self.p2r
                    .send((
                        routing_key!(Consensus >> CompactSignedProposal).into(),
                        msg.try_into().map_err(|e| {
                            BftError::TryIntoFailed(format!("{:?} of RawBytes(signed_proposal)", e))
                        })?,
                    ))
                    .map_err(|e| {
                        BftError::SendMsgFailed(format!("{:?} of signed_proposal to rabbitmq", e))
                    })?;
            }

            BftMsg::Vote(encode) => {
                trace!("Processor sends bft_signed_vote{:?}", encode);
                let msg: Message = encode.into();
                self.p2r
                    .send((
                        routing_key!(Consensus >> RawBytes).into(),
                        msg.try_into().map_err(|e| {
                            BftError::TryIntoFailed(format!("{:?} of RawBytes(signed_vote)", e))
                        })?,
                    ))
                    .map_err(|e| {
                        BftError::SendMsgFailed(format!("{:?} of signed_vote to rabbitmq", e))
                    })?;
            }

            _ => warn!("Processor gets wrong msg type!"),
        }

        Ok(())
    }

    /// A function to commit the proposal.
    fn commit(&mut self, commit: Commit) -> Result<(), BftError> {
        trace!("Processor gets {:?}", commit);
        let height = commit.height;
        let proof = commit.proof;
        self.proof.entry(height).or_insert_with(|| proof.clone());
        let proof = to_cita_proof(&proof);
        let block = self.complete_block(height, commit.block)?;
        let mut block_with_proof = BlockWithProof::new();
        block_with_proof.set_blk(block);
        block_with_proof.set_proof(proof);
        trace!("Processor send {:?} to consensus", &block_with_proof);
        let msg: Message = block_with_proof.into();
        self.p2r
            .send((
                routing_key!(Consensus >> BlockWithProof).into(),
                msg.try_into()
                    .map_err(|e| BftError::TryIntoFailed(format!("{:?} of BlockWithProof", e)))?,
            ))
            .map_err(|e| {
                BftError::SendMsgFailed(format!("{:?} of block_with_proof to rabbitmq", e))
            })?;
        self.clean_cache(height - 1);
        Ok(())
    }

    fn get_block(
        &self,
        height: Height,
        block_txs: &BlockTxs,
    ) -> Result<(BftBlock, BftHash), BridgeError> {
        let version = self.version.get(&(height - 1));
        let pre_hash = self.pre_hash.get(&(height - 1));
        let mut proof = self.proof.get(&(height - 1));
        let default_proof = Proof::default();
        if height == 1 {
            proof = Some(&default_proof);
        }
        if version.is_none() || pre_hash.is_none() || proof.is_none() {
            return Err(BridgeError::GetBlockFailed(format!(
                "any of version: {:?}, pre_hash: {:?}, proof: {:?} is none",
                version, pre_hash, proof
            )));
        }
        let mut block = Block::new();
        block.set_version(*version.unwrap());
        block.set_body(block_txs.clone().take_body());
        block
            .mut_header()
            .set_prevhash(pre_hash.unwrap().0.to_vec());
        let bft_proof = to_cita_proof(proof.unwrap());
        block.mut_header().set_proof(bft_proof);
        let block_time = unix_now();
        block
            .mut_header()
            .set_timestamp(AsMillis::as_millis(&block_time));
        block.mut_header().set_height(height);
        let transactions_root = block.get_body().transactions_root();
        block
            .mut_header()
            .set_transactions_root(transactions_root.to_vec());
        block.mut_header().set_proposer(self.address.to_vec());
        let blk: CompactBlock = block.clone().compact();
        trace!("Processor get block {:?}", &blk);

        let block_hash = blk.crypt_hash().to_vec();
        let encode: Vec<u8> = blk
            .try_into()
            .map_err(|e| BridgeError::TryIntoFailed(format!("{:?} of CompactBlock", e)))?;

        Ok((encode.into(), block_hash.into()))
    }

    fn sign(&self, hash: &[u8]) -> Result<BftSig, BridgeError> {
        Signature::sign(&self.signer.signer, &H256::from(hash))
            .and_then(|signature| Ok((&signature.0).to_vec().into()))
            .map_err(|e| BridgeError::SignFailed(format!("{:?}", e)))
    }

    fn extract_status(&mut self, status: RichStatus) -> Status {
        let height = status.height;

        let pre_hash = H256::from_slice(&status.hash);
        self.pre_hash.entry(height).or_insert(pre_hash);
        self.version.entry(height).or_insert(status.version);

        let mut map = HashMap::new();
        status.get_nodes().iter().for_each(|node| {
            let counter = map.entry(node.to_vec()).or_insert(0u32);
            *counter += 1;
        });

        let authority_list: Vec<Node> = map
            .into_iter()
            .map(|(node, n)| Node {
                address: node.into(),
                proposal_weight: n,
                vote_weight: 1,
            })
            .collect();
        Status {
            height,
            interval: Some(status.interval),
            authority_list,
        }
    }

    fn get_block_req_msg(
        &mut self,
        compact_block: CompactBlock,
        signed_proposal_hash: &BftHash,
        height: Height,
        round: Round,
    ) -> Message {
        let mut verify_req = auth::VerifyBlockReq::new();
        verify_req.set_height(height);
        verify_req.set_round(round);
        verify_req.set_block(compact_block);
        let mut msg: Message = verify_req.into();
        if let Some(origin) = self.origins.get_mut(signed_proposal_hash) {
            msg.set_origin(*origin);
        } else {
            msg.set_origin(ZERO_ORIGIN);
        }
        msg
    }

    fn try_feed_bft(&self, height: Height) -> Result<(), BftError> {
        if let Some(block_txs) = self.get_block_resps.get(&height) {
            self.p2b
                .get_block
                .send(BridgeMsg::GetBlockResp(self.get_block(height, block_txs)))
                .map_err(|e| {
                    BftError::SendMsgFailed(format!("{:?} of get_block_resp to bft_bridge", e))
                })?;
            return Ok(());
        }
        Err(BftError::NotYetGetResp(format!(
            "of feed with height {}",
            height
        )))
    }

    fn snapshot_response(&self, ack: Resp, flag: bool) -> Result<(), BftError> {
        info!(
            "Processor sends snapshot_response{{ack: {:?}, flag: {}}}",
            ack, flag
        );
        let mut resp = SnapshotResp::new();
        resp.set_resp(ack);
        resp.set_flag(flag);
        let msg: Message = resp.into();
        let encode: Vec<u8> = (&msg)
            .try_into()
            .map_err(|e| BftError::TryIntoFailed(format!("{:?} of {:?}", e, msg)))?;
        self.p2r
            .send((routing_key!(Consensus >> SnapshotResp).into(), encode))
            .map_err(|e| {
                BftError::SendMsgFailed(format!("{:?} of snap_shot_resp to rabbitmq", e))
            })?;

        Ok(())
    }

    fn clean_cache(&mut self, height: Height) {
        self.proof.retain(|&hi, _| hi >= height);
        self.pre_hash.retain(|&hi, _| hi >= height);
        self.version.retain(|&hi, _| hi >= height);
        self.get_block_resps.retain(|&hi, _| hi >= height);
        self.check_tx_resps.retain(|(hi, _), _| *hi >= height);
        self.verified_txs.retain(|hi, _| *hi >= height);
    }

    fn insert_verified_txs(&mut self, height: Height, block: &Block) {
        let txs = block.get_body().get_transactions();
        if let Some(map) = self.verified_txs.get_mut(&height) {
            for tx in txs {
                let tx_hash = tx.crypt_hash();
                map.entry(tx_hash).or_insert_with(|| tx.to_owned());
            }
        } else {
            let mut map = HashMap::new();
            for tx in txs {
                let tx_hash = tx.crypt_hash();
                map.insert(tx_hash, tx.to_owned());
            }
            self.verified_txs.insert(height, map);
        }
    }

    fn complete_block(&mut self, height: Height, block: BftBlock) -> Result<Block, BftError> {
        let compact_block = CompactBlock::try_from(block.as_slice())
            .map_err(|e| BftError::TryFromFailed(format!("{:?} of CompactBlock", e)))?;
        let tx_hashes = compact_block.get_body().transaction_hashes();
        if tx_hashes.is_empty() {
            return Ok(compact_block.complete(vec![]));
        }

        // verified_txs is empty when stop and restart node, so commit will failed
        // it requires chain to send new status to bft-rs
        let map = self.verified_txs.get(&height).ok_or_else(|| {
            BftError::NotYetGetResp(format!("verified_txs of height {} is empty", height))
        })?;
        let mut signed_txs = Vec::new();
        for tx_hash in tx_hashes {
            let signed_tx = map.get(&tx_hash).ok_or_else(|| {
                BftError::NotYetGetResp(format!(
                    "verified_txs of tx_hash {} is not exist",
                    &tx_hash
                ))
            })?;
            signed_txs.push(signed_tx.to_owned());
        }

        Ok(compact_block.complete(signed_txs))
    }
}

pub struct BftBridge {
    b2p: Sender<BridgeMsg>,
    b4p_b: Receiver<BridgeMsg>,
    b4p_c: Receiver<BridgeMsg>,
    b4p_f: Receiver<BridgeMsg>,
    b4p_s: Receiver<BridgeMsg>,
}

impl BftBridge {
    pub fn new(
        b2p: Sender<BridgeMsg>,
        b4p_b: Receiver<BridgeMsg>,
        b4p_c: Receiver<BridgeMsg>,
        b4p_f: Receiver<BridgeMsg>,
        b4p_s: Receiver<BridgeMsg>,
    ) -> Self {
        BftBridge {
            b2p,
            b4p_b,
            b4p_c,
            b4p_f,
            b4p_s,
        }
    }
}

impl BftSupport for BftBridge {
    type Error = BridgeError;
    fn check_block(
        &self,
        block: &BftBlock,
        block_hash: &BftHash,
        signed_proposal_hash: &BftHash,
        height_round: (Height, Round),
        _is_lock: bool,
        proposer: &BftAddr,
    ) -> Result<VerifyResp, BridgeError> {
        self.b2p
            .send(BridgeMsg::CheckBlockReq(
                block.clone(),
                block_hash.clone(),
                signed_proposal_hash.clone(),
                height_round.0,
                height_round.1,
                proposer.clone(),
            ))
            .map_err(|e| {
                BridgeError::SendMsgFailed(format!("{:?} of check_block_req to processor", e))
            })?;
        self.b4p_b
            .recv()
            .map_err(|e| {
                BridgeError::RcvMsgFailed(format!("{:?} of check_block_resp from processor", e))
            })
            .and_then(|bft_msg| {
                if let BridgeMsg::CheckBlockResp(result) = bft_msg {
                    result
                } else {
                    Err(BridgeError::MismatchType(format!(
                        "expect CheckBlockResp found {:?}",
                        bft_msg
                    )))
                }
            })
    }
    /// A funciton to transmit messages.
    fn transmit(&self, msg: BftMsg) {
        if let Err(e) = self.b2p.send(BridgeMsg::Transmit(msg)) {
            error!("transmit proposal/vote failed {:?}", e);
        }
    }
    /// A function to commit the proposal.
    fn commit(&self, commit: Commit) -> Result<Status, BridgeError> {
        self.b2p.send(BridgeMsg::CommitReq(commit)).map_err(|e| {
            BridgeError::SendMsgFailed(format!("{:?} of commit_req to processor", e))
        })?;
        self.b4p_c
            .recv()
            .map_err(|e| {
                BridgeError::RcvMsgFailed(format!("{:?} of commit_resp from processor", e))
            })
            .and_then(|bft_msg| {
                if let BridgeMsg::CommitResp(status) = bft_msg {
                    status
                } else {
                    Err(BridgeError::MismatchType(format!(
                        "expect CommitResp found {:?}",
                        bft_msg
                    )))
                }
            })
    }

    fn get_block(&self, height: Height, proof: &Proof) -> Result<(BftBlock, BftHash), BridgeError> {
        self.b2p
            .send(BridgeMsg::GetBlockReq(height, proof.clone()))
            .map_err(|e| {
                BridgeError::SendMsgFailed(format!("{:?} of get_block_req to processor", e))
            })?;
        self.b4p_f
            .recv()
            .map_err(|e| {
                BridgeError::RcvMsgFailed(format!("{:?} of get_block_resp from processor", e))
            })
            .and_then(|bft_msg| {
                if let BridgeMsg::GetBlockResp(result) = bft_msg {
                    result
                } else {
                    Err(BridgeError::MismatchType(format!(
                        "expect GetBlockResp found {:?}",
                        bft_msg
                    )))
                }
            })
    }

    fn sign(&self, hash: &BftHash) -> Result<BftSig, BridgeError> {
        self.b2p
            .send(BridgeMsg::SignReq(hash.clone()))
            .map_err(|e| BridgeError::SendMsgFailed(format!("{:?} of sign_req to processor", e)))?;
        self.b4p_s
            .recv()
            .map_err(|e| BridgeError::RcvMsgFailed(format!("{:?} of sign_resp from processor", e)))
            .and_then(|bft_msg| {
                if let BridgeMsg::SignResp(sign) = bft_msg {
                    sign
                } else {
                    Err(BridgeError::MismatchType(format!(
                        "expect SignResp found {:?}",
                        bft_msg
                    )))
                }
            })
    }

    fn check_sig(&self, signature: &BftSig, hash: &BftHash) -> Result<BftAddr, BridgeError> {
        if signature.as_slice().len() != SIGNATURE_BYTES_LEN {
            return Err(BridgeError::CheckSigFailed(format!(
                "invalid sig_len {}",
                signature.as_slice().len()
            )));
        }
        let signature = Signature::from(signature.as_slice());
        signature
            .recover(&H256::from(hash.as_slice()))
            .map_err(|e| BridgeError::CheckSigFailed(format!("{:?}", e)))
            .and_then(|pubkey| {
                let address = pubkey_to_address(&pubkey);
                Ok(address.to_vec().into())
            })
    }

    fn crypt_hash(&self, msg: &[u8]) -> BftHash {
        msg.to_vec().crypt_hash().to_vec().into()
    }
}

fn to_cita_proof(proof: &Proof) -> ProtoProof {
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

fn to_bft_proof(proof: &BftProof) -> Proof {
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

#[derive(Clone, Debug)]
pub enum BridgeError {
    CheckBlockFailed(String),
    GetBlockFailed(String),
    SignFailed(String),
    CheckSigFailed(String),
    SendMsgFailed(String),
    RcvMsgFailed(String),
    TryIntoFailed(String),
    TryFromFailed(String),
    MismatchType(String),
}

#[derive(Clone, Debug)]
pub enum BftError {
    SendMsgFailed(String),
    TryFromFailed(String),
    TakeRawBytesFailed(String),
    TakeRichStatusFailed,
    TakeBlockFailed,
    TakeVerifyBlockRespFailed,
    TakeSnapshotReqFailed,
    NotYetGetResp(String),
    TryIntoFailed(String),
}

fn handle_error(result: Result<(), BftError>) {
    if let Err(e) = result {
        match e {
            BftError::TryFromFailed(_)
            | BftError::TakeRawBytesFailed(_)
            | BftError::TakeRichStatusFailed
            | BftError::TakeBlockFailed
            | BftError::TakeVerifyBlockRespFailed
            | BftError::TakeSnapshotReqFailed
            | BftError::NotYetGetResp(_) => warn!("Bft encounters {:?}", e),

            BftError::SendMsgFailed(_) | BftError::TryIntoFailed(_) => {
                error!("Bft encounters {:?}", e)
            }
        }
    }
}
