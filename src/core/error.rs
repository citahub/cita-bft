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

#[derive(Debug)]
pub enum BftError {
    InvalidSigLen,
    ObsoleteSignedProposal,
    InvalidSignature,
    EmptyAuthManage,
    InvalidProposer,
    InvalidTxTo,
    InvalidTxNonce,
    InvalidUtilBlock,
    InvalidProof,
    TransactionRootCheckFailed,
    MismatchingVoteProposal,
    InvalidVoter,
    MismatchingVoter,
    MisMatchingPreHash,
    EmptySelfPreHash,
    RepeatLockVote,
    NotEnoughVotes,
    WaitForAuthValidation,
    ObsoleteRawBytes,
    HigherRawBytes,
    HigherProposal,
    MismatchingBlockTxs,
    SelfPreHashNotReady,
    SelfProofNotReady,
    ObsoleteVerifyBlockResp,
    ObsoleteRichStatus,
    GenerateProofFailed,
    ObsoleteBftProposal,
    ObsoleteBftVote,
    ObsoleteCommit,
    ShouldNotHappen,
    SetWalHeightFailed,
    TryFromMessageFailed,
    TryIntoMessageFailed,
    SendFailed,
    TakeNoneSignedProposal,
    TakeNoneVerifyBlockResp,
    TakeNoneRawBytes,
    TakeNoneBlockTxs,
    TakeNoneRichStatus,
    ProtoProposalTryIntoFailed,
    SaveWalLogFailed,
    MessageTryIntoFailed,
    GetNoneProposal,
    GetNoneVoteSet,
    SerializeFailed,
    DeserializeFailed,
    MessageSignFailed,
    FeedBlockIsNone,
    GetNoneLockVotes,
    GetNoneSignedVote,
    SignatureRecoverFailed,
}



