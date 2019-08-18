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

pub fn handle_error(result: Result<(), BftError>) {
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
