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

use crate::crypto::{pubkey_to_address, Sign, Signature};
use crate::types::{Address, H256};
use bincode::{serialize, Infinite};
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

