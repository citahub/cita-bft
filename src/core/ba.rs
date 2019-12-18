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
    received_conf: BTreeMap<u32, BoolSet>,
    /// Received `Term` messages. Kept throughout epoch updates. These count as `BVal`, `Aux` and
    /// `Conf` messages for all future epochs.
    received_term: BoolMultimap<u32>,
    /// The estimate of the decision value in the current epoch.
    estimated: Option<bool>,
    /// A permanent, latching copy of the output value. This copy is required because `output` can
    /// be consumed using `ConsensusProtocol::next_output` immediately after the instance finishing to
    /// handle a message, in which case it would otherwise be unknown whether the output value was
    /// ever there at all. While the output value will still be required in a later epoch to decide
    /// the termination state.
    decision: Option<bool>,
    /// The values we found in the first _N - f_ `Aux` messages that were in `bin_values`.
    conf_values: Option<BoolSet>,
}

impl BinaryAgreement {
    pub fn new() -> Self {
        BinaryAgreement {
            round:0,
            max_future_rounds:100,
            received_conf:BTreeMap::new(),
            received_term:BoolMultimap::default(),
            estimated:None,
            decision:None,
            conf_values:None,
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

    pub fn handle_bval(&self,round:usize,send_id:u32,bval:BoolSet) -> Option<(bool,BoolSet)> {
        Some((true,true.into()))
    }
    pub fn handle_aux(&self,round:usize,send_id:u32,aux : BoolSet) -> Option<BoolSet> {
         Some(true.into())
    }
    pub fn handle_term(&self,round:usize,send_id:u32,term: BoolSet) -> Option<bool> {
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
