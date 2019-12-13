#[derive(Debug)]
pub struct BinaryAgreement {
    /// Binary Agreement algorithm epoch.
    epoch: usize,
    /// Maximum number of future epochs for which incoming messages are accepted.
    max_future_epochs: usize,
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
    pub fn handle_bval() {

    }
    pub fn handle_aux() {

    }
    pub fn handle_conf() {

    }
    pub fn handle_perm() {

    }

    fn getCoinState(&self) ->bool {

    }
}
