use crate::core::bft_bridge::BridgeMsg;
use libproto::router::{MsgType, RoutingKey, SubModules};
use pubsub::channel::{self, Receiver, Sender};
use pubsub::start_pubsub;

pub struct RabbitMqAgent {
    pub receiver: Receiver<(String, Vec<u8>)>,
    pub sender: Sender<(String, Vec<u8>)>,
}

impl RabbitMqAgent {
    pub fn new() -> Self {
        let (rabbitmq_pub_processor, processor_sub_rabbitmq) = channel::unbounded();
        let (processor_pub_rabbitmq, rabbitmq_sub_processor) = channel::unbounded();

        start_pubsub(
            "consensus",
            routing_key!([
                Net >> CompactSignedProposal,
                Net >> RawBytes,
                Chain >> RichStatus,
                Auth >> BlockTxs,
                Auth >> VerifyBlockResp,
                Snapshot >> SnapshotReq,
            ]),
            rabbitmq_pub_processor,
            rabbitmq_sub_processor,
        );

        RabbitMqAgent {
            receiver: processor_sub_rabbitmq,
            sender: processor_pub_rabbitmq,
        }
    }
}

#[derive(Clone)]
pub struct BftServer {
    pub sender: Sender<BridgeMsg>,
    pub check_block: Receiver<BridgeMsg>,
    pub commit: Receiver<BridgeMsg>,
    pub get_block: Receiver<BridgeMsg>,
    pub sign: Receiver<BridgeMsg>,
}

#[derive(Clone)]
pub struct BftClient {
    pub receiver: Receiver<BridgeMsg>,
    pub check_block: Sender<BridgeMsg>,
    pub commit: Sender<BridgeMsg>,
    pub get_block: Sender<BridgeMsg>,
    pub sign: Sender<BridgeMsg>,
}

pub struct BftAgent {
    pub bft_server: BftServer,
    pub bft_client: BftClient,
}

impl BftAgent {
    pub fn new() -> Self {
        let (bft_pub_processor, processor_sub_bft) = channel::unbounded();
        let (processor_pub_bft_on_check_block, bft_sub_processor_on_check_block) =
            channel::unbounded();
        let (processor_pub_bft_on_commit, bft_sub_processor_on_commit) = channel::unbounded();
        let (processor_pub_bft_on_get_block, bft_sub_processor_on_get_block) = channel::unbounded();
        let (processor_pub_bft_on_sign, bft_sub_processor_on_get_sign) = channel::unbounded();

        let bft_server = BftServer {
            sender: bft_pub_processor,
            check_block: bft_sub_processor_on_check_block,
            commit: bft_sub_processor_on_commit,
            get_block: bft_sub_processor_on_get_block,
            sign: bft_sub_processor_on_get_sign,
        };

        let bft_client = BftClient {
            receiver: processor_sub_bft,
            check_block: processor_pub_bft_on_check_block,
            commit: processor_pub_bft_on_commit,
            get_block: processor_pub_bft_on_get_block,
            sign: processor_pub_bft_on_sign,
        };

        BftAgent {
            bft_server,
            bft_client,
        }
    }
}
