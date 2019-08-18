use crate::types::H256;
use bft::{
    Address as BftAddr, BftMsg, BftSupport, Block as BftBlock, Commit, Hash as BftHash, Height,
    Proof, Round, Signature as BftSig, Status, VerifyResp,
};
use crypto::{pubkey_to_address, Sign, Signature, SIGNATURE_BYTES_LEN};
use hashable::Hashable;

use crate::core::{BftServer, BridgeError};

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

pub struct BftBridge {
    bft_server: BftServer,
}

impl BftBridge {
    pub fn new(bft_server: BftServer) -> Self {
        BftBridge { bft_server }
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
        self.bft_server
            .sender
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
        self.bft_server
            .check_block
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
        if let Err(e) = self.bft_server.sender.send(BridgeMsg::Transmit(msg)) {
            error!("transmit proposal/vote failed {:?}", e);
        }
    }
    /// A function to commit the proposal.
    fn commit(&self, commit: Commit) -> Result<Status, BridgeError> {
        self.bft_server
            .sender
            .send(BridgeMsg::CommitReq(commit))
            .map_err(|e| {
                BridgeError::SendMsgFailed(format!("{:?} of commit_req to processor", e))
            })?;
        self.bft_server
            .commit
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
        self.bft_server
            .sender
            .send(BridgeMsg::GetBlockReq(height, proof.clone()))
            .map_err(|e| {
                BridgeError::SendMsgFailed(format!("{:?} of get_block_req to processor", e))
            })?;
        self.bft_server
            .get_block
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
        self.bft_server
            .sender
            .send(BridgeMsg::SignReq(hash.clone()))
            .map_err(|e| BridgeError::SendMsgFailed(format!("{:?} of sign_req to processor", e)))?;
        self.bft_server
            .sign
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
