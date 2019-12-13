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

use super::Step;
use crate::crypto::{pubkey_to_address, Sign, Signature};
use crate::types::{Address, H256};
use bincode::{serialize, Infinite};
use hashable::Hashable;
use libproto::blockchain::{Block, CompactBlock};
use libproto::TryFrom;
use lru_cache::LruCache;
use std::collections::HashMap;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IndexProposal {
     current_proposals : BTreeMap<u32,Proposal>,
}

impl IndexProposal {
    pub fn new() -> Self {
        IndexProposal {
            current_proposals:BTreeMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.current_proposals.clear();
    }

    // Be care of sequence
    pub fn get_proposals(&self,idxs: Vec<u32>) -> Vec<Proposal> {
        let o :Vec = self.current_proposals.iter().filter(|idx| idxs.contains(idx)).collect();
        if o.len() == idxs.len() {
            return o;
        }
        Vec::new()
    }

    pub fn add_proposal(&mut self,idx : u32,proposal:Proposal) -> bool {
        if self.current_proposals.contains_key(&idx) {
            return false;
        }
        self.current_proposals.insert(&idx,proposal);
        true
    }
}

// height -> round collector
#[derive(Debug)]
pub struct VoteCollector {
    pub votes: LruCache<usize, RoundCollector>,
}

impl VoteCollector {
    pub fn new() -> Self {
        VoteCollector {
            votes: LruCache::new(16),
        }
    }

    pub fn add(
        &mut self,
        height: usize,
        round: usize,
        step: Step,
        sender: Address,
        vote: &VoteMessage,
    ) -> bool {
        if self.votes.contains_key(&height) {
            self.votes
                .get_mut(&height)
                .unwrap()
                .add(round, step, sender, vote)
        } else {
            let mut round_votes = RoundCollector::new();
            round_votes.add(round, step, sender, vote);
            self.votes.insert(height, round_votes);
            true
        }
    }

    pub fn get_voteset(&mut self, height: usize, round: usize, step: Step) -> Option<VoteSet> {
        self.votes
            .get_mut(&height)
            .and_then(|rc| rc.get_voteset(round, step))
    }
}

//round -> step collector
#[derive(Debug)]
pub struct RoundCollector {
    pub round_votes: LruCache<usize, StepCollector>,
}

impl RoundCollector {
    pub fn new() -> Self {
        RoundCollector {
            round_votes: LruCache::new(16),
        }
    }

    pub fn add(&mut self, round: usize, step: Step, sender: Address, vote: &VoteMessage) -> bool {
        if self.round_votes.contains_key(&round) {
            self.round_votes
                .get_mut(&round)
                .unwrap()
                .add(step, sender, &vote)
        } else {
            let mut step_votes = StepCollector::new();
            step_votes.add(step, sender, &vote);
            self.round_votes.insert(round, step_votes);
            true
        }
    }

    pub fn get_voteset(&mut self, round: usize, step: Step) -> Option<VoteSet> {
        self.round_votes
            .get_mut(&round)
            .and_then(|sc| sc.get_voteset(step))
    }
}

//step -> voteset
#[derive(Debug)]
pub struct StepCollector {
    pub step_votes: HashMap<Step, VoteSet>,
}

impl StepCollector {
    pub fn new() -> Self {
        StepCollector {
            step_votes: HashMap::new(),
        }
    }

    pub fn add(&mut self, step: Step, sender: Address, vote: &VoteMessage) -> bool {
        self.step_votes
            .entry(step)
            .or_insert_with(VoteSet::new)
            .add(sender, vote)
    }

    pub fn get_voteset(&self, step: Step) -> Option<VoteSet> {
        self.step_votes.get(&step).cloned()
    }
}

//1. sender's votemessage 2. proposal'hash count
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VoteSet {
    pub votes_by_sender: HashMap<Address, VoteMessage>,
    pub votes_by_proposal: HashMap<H256, usize>,
    pub count: usize,
}

impl VoteSet {
    pub fn new() -> Self {
        VoteSet {
            votes_by_sender: HashMap::new(),
            votes_by_proposal: HashMap::new(),
            count: 0,
        }
    }

    //just add ,not check
    pub fn add(&mut self, sender: Address, vote: &VoteMessage) -> bool {
        let mut added = false;
        self.votes_by_sender.entry(sender).or_insert_with(|| {
            added = true;
            vote.to_owned()
        });
        if added {
            self.count += 1;
            let hash = vote.proposal.unwrap_or_else(H256::default);
            *self.votes_by_proposal.entry(hash).or_insert(0) += 1;
        }
        added
    }

    pub fn check(
        &self,
        h: usize,
        r: usize,
        step: Step,
        authorities: &[Address],
    ) -> Result<Option<H256>, &str> {
        let mut votes_by_proposal: HashMap<H256, usize> = HashMap::new();
        for (sender, vote) in &self.votes_by_sender {
            if authorities.contains(sender) {
                let msg = serialize(&(h, r, step, sender, vote.proposal), Infinite).unwrap();
                let signature = &vote.signature;
                if let Ok(pubkey) = signature.recover(&msg.crypt_hash()) {
                    if pubkey_to_address(&pubkey) == *sender {
                        let hash = vote.proposal.unwrap_or_else(H256::default);
                        // inc the count of vote for hash
                        *votes_by_proposal.entry(hash).or_insert(0) += 1;
                    }
                }
            }
        }
        for (hash, count) in &votes_by_proposal {
            if *count * 3 > authorities.len() * 2 {
                if hash.is_zero() {
                    return Ok(None);
                } else {
                    return Ok(Some(*hash));
                }
            }
        }
        Err("vote set check error!")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VoteMessage {
    pub proposal: Option<H256>,
    pub signature: Signature,
}


#[derive(Debug)]
pub struct ProposalRoundCollector {
    pub round_proposals: LruCache<usize, Proposal>,
}

impl ProposalRoundCollector {
    pub fn new() -> Self {
        ProposalRoundCollector {
            round_proposals: LruCache::new(16),
        }
    }

    pub fn add(&mut self, round: usize, proposal: Proposal) -> bool {
        if self.round_proposals.contains_key(&round) {
            false
        } else {
            self.round_proposals.insert(round, proposal);
            true
        }
    }

    pub fn get_proposal(&mut self, round: usize) -> Option<Proposal> {
        self.round_proposals.get_mut(&round).cloned()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Proposal {
    pub block: Vec<u8>,
    pub lock_round: Option<usize>,
    pub lock_votes: Option<VoteSet>,
}

impl Proposal {
    pub fn check(&self, h: usize, authorities: &[Address]) -> bool {
        if self.lock_round.is_none() && self.lock_votes.is_none() {
            true
        } else {
            let round = self.lock_round.unwrap();

            let ret = self
                .lock_votes
                .as_ref()
                .unwrap()
                .check(h, round, Step::Prevote, authorities);

            match ret {
                Ok(Some(p)) => {
                    if let Ok(block) = CompactBlock::try_from(&self.block) {
                        block.crypt_hash() == p
                    } else if let Ok(block) = Block::try_from(&self.block) {
                        block.crypt_hash() == p
                    } else {
                        false
                    }
                }
                _ => false,
            }
        }
    }
}
