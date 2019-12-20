use std::collections::BTreeMap;
use std::sync::Arc;
use std::{fmt, result};

use bincode;

use super::bool_multimap::BoolMultimap;
use super::bool_set::{self, BoolSet};

#[derive(Debug,Clone)]
pub struct BinaryAgreement {
    /// Binary Agreement algorithm epoch.
    round: usize,
    /// Maximum number of future epochs for which incoming messages are accepted.
    max_future_rounds: usize,
    /// Received `Conf` messages. Reset on every epoch update.
    received_aux: BTreeMap<u32, BoolSet>,
    /// Received `Term` messages. Kept throughout epoch updates. These count as `BVal`, `Aux` and
    /// `Conf` messages for all future epochs.
    received_term: BTreeMap<u32, BoolSet>,
    /// The estimate of the decision value in the current epoch.
    estimated: Option<bool>,
    /// A permanent, latching copy of the output value. This copy is required because `output` can
    /// be consumed using `ConsensusProtocol::next_output` immediately after the instance finishing to
    /// handle a message, in which case it would otherwise be unknown whether the output value was
    /// ever there at all. While the output value will still be required in a later epoch to decide
    /// the termination state.
    decision: Option<bool>,
    /// The values we found in the first _N - f_ `Aux` messages that were in `bin_values`.
    received_bval: BTreeMap<u32, BoolSet>,


}

impl BinaryAgreement {
    pub fn new() -> Self {
        BinaryAgreement {
            round:0,
            max_future_rounds:100,
            received_aux:BTreeMap::new(),
            received_term:BTreeMap::new(),
            estimated:None,
            decision:None,
            received_bval:BTreeMap::new(),
        }
    }
    pub fn set_input(&mut self,b : bool) -> bool {
        let is_empty =  self.estimated.is_none();
        if is_empty {
            self.estimated = Some(b);
            return true;
        }
        false
    }

    pub fn clear(&mut self) {
        self.round = 0;
        self.max_future_rounds = 100;
        self.received_aux.clear();
        self.received_term.clear();
        self.estimated = None;
        self.decision = None;
        self.received_bval.clear();
    }

    pub fn handle_bval(&mut self,round:usize,send_id:u32,bval:BoolSet) -> Option<(bool,BoolSet)> {
        self.received_bval.insert(send_id,bval);
        warn!("**** received_bval {:?}",self.received_bval);
        if self.received_bval.len() < 2 {
            return None;
        }
        Some((true,true.into()))
    }
    pub fn handle_aux(&mut self,round:usize,send_id:u32,aux : BoolSet) -> Option<BoolSet> {
        self.received_aux.insert(send_id,aux);
        warn!("***** received_aux {:?}",self.received_aux);
        if self.received_aux.len() < 2 {
            return None;
        }
         Some(true.into())
    }
    pub fn handle_term(&mut self,round:usize,send_id:u32,term: BoolSet) -> Option<bool> {
        self.received_term.insert(send_id,term);
        warn!("***** received_term {:?}",self.received_term);
        if self.received_term.len() < 2 {
            return None;
        }
        Some(true)
    }

    fn getRandom(&self) -> usize {
        let now = self.round;
        93*now*now + 47*now+ now
    }

    fn getCoinState(&self) ->bool {
        match self.round % 3 {
            0 => true,
            1 => false,
            2 => self.getRandom() & 0x01 == 0x01,
            _ => false,
        }
    }
}
