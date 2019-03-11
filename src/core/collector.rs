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

use bft_rs::algorithm::Step;
use bft_rs::Vote as BftVote;
use crypto::Signature;
use libproto::consensus::SignedProposal;
use lru_cache::LruCache;
use std::collections::HashMap;
use types::H256;

pub const CACHE_NUMBER: usize = 16;

#[derive(Debug, Clone)]
pub struct VoteCollector {
    pub votes: LruCache<usize, RoundCollector>,
}

impl VoteCollector {
    pub fn new() -> Self {
        VoteCollector {
            votes: LruCache::new(CACHE_NUMBER),
        }
    }

    pub fn add(
        &mut self,
        height: usize,
        round: usize,
        step: Step,
        bft_vote: &BftVote,
        signed_vote: &SignedVote,
    ) -> bool {
        if self.votes.contains_key(&height) {
            self.votes
                .get_mut(&height)
                .unwrap()
                .add(round, step, bft_vote, signed_vote)
        } else {
            let mut round_votes = RoundCollector::new();
            round_votes.add(round, step, bft_vote, signed_vote);
            self.votes.insert(height, round_votes);
            true
        }
    }

    pub fn get_vote_set(&mut self, height: usize, round: usize, step: Step) -> Option<VoteSet> {
        self.votes
            .get_mut(&height)
            .and_then(|rc| rc.get_vote_set(round, step))
    }
}

//round -> step collector
#[derive(Debug, Clone)]
pub struct RoundCollector {
    pub round_votes: LruCache<usize, StepCollector>,
}

impl RoundCollector {
    pub fn new() -> Self {
        RoundCollector {
            round_votes: LruCache::new(CACHE_NUMBER),
        }
    }

    pub fn add(&mut self, round: usize, step: Step, bft_vote: &BftVote, signed_vote: &SignedVote) -> bool {
        if self.round_votes.contains_key(&round) {
            self.round_votes
                .get_mut(&round)
                .unwrap()
                .add(step, bft_vote, &signed_vote)
        } else {
            let mut step_votes = StepCollector::new();
            step_votes.add(step, bft_vote, &signed_vote);
            self.round_votes.insert(round, step_votes);
            true
        }
    }

    pub fn get_vote_set(&mut self, round: usize, step: Step) -> Option<VoteSet> {
        self.round_votes
            .get_mut(&round)
            .and_then(|sc| sc.get_vote_set(step))
    }
}

//step -> voteset
#[derive(Debug, Clone)]
pub struct StepCollector {
    pub step_votes: HashMap<Step, VoteSet>,
}

impl StepCollector {
    pub fn new() -> Self {
        StepCollector {
            step_votes: HashMap::new(),
        }
    }

    pub fn add(&mut self, step: Step, bft_vote: &BftVote, signed_vote: &SignedVote) -> bool {
        self.step_votes
            .entry(step)
            .or_insert_with(VoteSet::new)
            .add(bft_vote, signed_vote)
    }

    pub fn get_vote_set(&self, step: Step) -> Option<VoteSet> {
        self.step_votes.get(&step).cloned()
    }
}

#[derive(Clone, Debug)]
pub struct VoteSet {
    pub vote_pair: HashMap<BftVote, SignedVote>,
}

impl VoteSet {
    pub fn new() -> Self {
        VoteSet {
            vote_pair: HashMap::new(),
        }
    }

    //just add ,not check
    pub fn add(&mut self, bft_vote: &BftVote, signed_vote: &SignedVote) -> bool {
        let mut added = false;
        self.vote_pair.entry(bft_vote.clone()).or_insert_with(|| {
            added = true;
            signed_vote.to_owned()
        });
        added
    }
}

#[derive(Clone, Debug)]
pub struct SignedVote {
    pub proposal: Option<H256>,
    pub signature: Signature,
}

#[derive(Clone, Debug)]
pub struct ProposalCollector {
    pub proposals: LruCache<usize, ProposalRoundCollector>,
}

impl ProposalCollector {
    pub fn new() -> Self {
        ProposalCollector {
            proposals: LruCache::new(CACHE_NUMBER),
        }
    }

    pub fn add(&mut self, height: usize, round: usize, proposal: &SignedProposal) -> bool {
        if self.proposals.contains_key(&height) {
            self.proposals
                .get_mut(&height)
                .unwrap()
                .add(round, proposal)
        } else {
            let mut round_proposals = ProposalRoundCollector::new();
            round_proposals.add(round, proposal);
            self.proposals.insert(height, round_proposals);
            true
        }
    }

    pub fn get_proposal(&mut self, height: usize, round: usize) -> Option<SignedProposal> {
        self.proposals
            .get_mut(&height)
            .and_then(|prc| prc.get_proposal(round))
    }


}

#[derive(Clone, Debug)]
pub struct ProposalRoundCollector {
    pub round_proposals: LruCache<usize, SignedProposal>,
}

impl ProposalRoundCollector {
    pub fn new() -> Self {
        ProposalRoundCollector {
            round_proposals: LruCache::new(CACHE_NUMBER),
        }
    }

    pub fn add(&mut self, round: usize, proposal: &SignedProposal) -> bool {
        if self.round_proposals.contains_key(&round) {
            false
        } else {
            self.round_proposals.insert(round, proposal.clone());
            true
        }
    }

    pub fn get_proposal(&mut self, round: usize) -> Option<SignedProposal> {
        self.round_proposals.get_mut(&round).cloned()
    }
}